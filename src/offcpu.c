/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * offcpu.c - Off-CPU event collection via BPF skeleton + ring buffer
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "offcpu.h"
#include "bperf.skel.h"

/* ── Context ──────────────────────────────────────────────────────── */

struct offcpu_ctx {
	struct bperf_bpf *skel;
	struct ring_buffer *rb;
	struct offcpu_event_buf *current_buf; /* set during poll */
};

/* ── Buffer helpers ───────────────────────────────────────────────── */

void offcpu_event_buf_init(struct offcpu_event_buf *buf)
{
	memset(buf, 0, sizeof(*buf));
}

void offcpu_event_buf_free(struct offcpu_event_buf *buf)
{
	free(buf->entries);
	memset(buf, 0, sizeof(*buf));
}

static int offcpu_event_buf_append(struct offcpu_event_buf *buf,
				   const struct offcpu_event *evt)
{
	if (buf->nr >= buf->cap) {
		int newcap = buf->cap ? buf->cap * 2 : 4096;
		struct offcpu_event *tmp = realloc(buf->entries,
						   newcap * sizeof(*tmp));
		if (!tmp)
			return -ENOMEM;
		buf->entries = tmp;
		buf->cap = newcap;
	}
	buf->entries[buf->nr++] = *evt;
	return 0;
}

void resolved_stack_map_init(struct resolved_stack_map *map)
{
	memset(map, 0, sizeof(*map));
}

void resolved_stack_map_free(struct resolved_stack_map *map)
{
	free(map->stacks);
	memset(map, 0, sizeof(*map));
}

static int resolved_stack_map_append(struct resolved_stack_map *map,
				     const struct resolved_stack *s)
{
	if (map->nr >= map->cap) {
		int newcap = map->cap ? map->cap * 2 : 4096;
		struct resolved_stack *tmp = realloc(map->stacks,
						     newcap * sizeof(*tmp));
		if (!tmp)
			return -ENOMEM;
		map->stacks = tmp;
		map->cap = newcap;
	}
	map->stacks[map->nr++] = *s;
	return 0;
}

/* ── Ring buffer callback ─────────────────────────────────────────── */

static int handle_event(void *ctx, void *data, size_t size)
{
	struct offcpu_ctx *octx = ctx;
	if (size < sizeof(struct offcpu_event))
		return 0;
	struct offcpu_event *evt = data;
	offcpu_event_buf_append(octx->current_buf, evt);
	return 0;
}

/* ── Open & attach ────────────────────────────────────────────────── */

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			    va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

struct offcpu_ctx *offcpu_open(const struct offcpu_params *params)
{
	struct offcpu_ctx *ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	libbpf_set_print(libbpf_print_fn);

	/* Open BPF skeleton */
	ctx->skel = bperf_bpf__open();
	if (!ctx->skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		goto err;
	}

	/* Set ring buffer size before load */
	if (params->ringbuf_size) {
		bpf_map__set_max_entries(ctx->skel->maps.events,
					params->ringbuf_size);
	}

	/* Load BPF programs */
	int err = bperf_bpf__load(ctx->skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
		goto err;
	}

	/* Write config to BPF map */
	struct bperf_config cfg = {
		.target_tgid = params->target_tgid,
		.min_duration_ns = params->min_duration_ns,
	};
	uint32_t key = 0;
	int map_fd = bpf_map__fd(ctx->skel->maps.bperf_cfg);
	err = bpf_map_update_elem(map_fd, &key, &cfg, BPF_ANY);
	if (err) {
		fprintf(stderr, "Failed to update BPF config: %s\n",
			strerror(-err));
		goto err;
	}

	/* Attach BPF programs */
	err = bperf_bpf__attach(ctx->skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
		goto err;
	}

	/* Create ring buffer manager */
	ctx->rb = ring_buffer__new(bpf_map__fd(ctx->skel->maps.events),
				   handle_event, ctx, NULL);
	if (!ctx->rb) {
		fprintf(stderr, "Failed to create ring buffer\n");
		goto err;
	}

	return ctx;

err:
	offcpu_close(ctx);
	return NULL;
}

/* ── Ring buffer fd ───────────────────────────────────────────────── */

int offcpu_get_ring_fd(struct offcpu_ctx *ctx)
{
	return ring_buffer__epoll_fd(ctx->rb);
}

/* ── Poll ─────────────────────────────────────────────────────────── */

int offcpu_poll(struct offcpu_ctx *ctx, struct offcpu_event_buf *buf,
		int timeout_ms)
{
	ctx->current_buf = buf;
	int ret = ring_buffer__poll(ctx->rb, timeout_ms);
	ctx->current_buf = NULL;
	return ret;
}

/* ── Dump stack traces ────────────────────────────────────────────── */

int offcpu_dump_stacks(struct offcpu_ctx *ctx,
		       struct resolved_stack_map *map)
{
	int map_fd = bpf_map__fd(ctx->skel->maps.stack_traces);
	uint32_t key = 0, next_key;
	uint64_t ips[BPERF_MAX_STACK_DEPTH];

	while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
		memset(ips, 0, sizeof(ips));
		if (bpf_map_lookup_elem(map_fd, &next_key, ips) == 0) {
			struct resolved_stack s = {
				.stack_id = (int32_t)next_key,
				.nr_ips = 0,
			};
			for (int i = 0; i < BPERF_MAX_STACK_DEPTH; i++) {
				if (ips[i] == 0)
					break;
				s.ips[s.nr_ips++] = ips[i];
			}
			resolved_stack_map_append(map, &s);
		}
		key = next_key;
	}

	return 0;
}

/* ── Cleanup ──────────────────────────────────────────────────────── */

void offcpu_close(struct offcpu_ctx *ctx)
{
	if (!ctx)
		return;
	if (ctx->rb)
		ring_buffer__free(ctx->rb);
	if (ctx->skel)
		bperf_bpf__destroy(ctx->skel);
	free(ctx);
}
