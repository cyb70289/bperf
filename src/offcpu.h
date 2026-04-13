/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
#ifndef OFFCPU_H
#define OFFCPU_H

#include <stdint.h>
#include "bperf_common.h"

/*
 * Off-CPU profiling via BPF (skeleton loader + ring buffer consumer).
 */

struct offcpu_ctx;

struct offcpu_params {
	uint32_t target_tgid;     /* 0 = system-wide */
	uint64_t min_duration_ns; /* minimum off-CPU episode duration */
	uint32_t ringbuf_size;    /* ring buffer size in bytes */
};

/* Buffer of off-CPU events */
struct offcpu_event_buf {
	struct offcpu_event *entries;
	int nr;
	int cap;
};

/* Open BPF skeleton, configure, and attach. Returns context or NULL. */
struct offcpu_ctx *offcpu_open(const struct offcpu_params *params);

/* Get the ring buffer fd for epoll. */
int offcpu_get_ring_fd(struct offcpu_ctx *ctx);

/* Poll the BPF ring buffer. Appends events to buf. timeout_ms=0 for non-blocking. */
int offcpu_poll(struct offcpu_ctx *ctx, struct offcpu_event_buf *buf,
		int timeout_ms);

/*
 * Read all stack traces from the BPF stack_traces map.
 * Returns an array of resolved stacks. Caller must free.
 */
struct resolved_stack {
	int32_t  stack_id;
	int      nr_ips;
	uint64_t ips[BPERF_MAX_STACK_DEPTH];
};

struct resolved_stack_map {
	struct resolved_stack *stacks;
	int nr;
	int cap;
};

int offcpu_dump_stacks(struct offcpu_ctx *ctx,
		       struct resolved_stack_map *map);

/* Detach and free BPF resources. */
void offcpu_close(struct offcpu_ctx *ctx);

/* Buffer helpers */
void offcpu_event_buf_init(struct offcpu_event_buf *buf);
void offcpu_event_buf_free(struct offcpu_event_buf *buf);

void resolved_stack_map_init(struct resolved_stack_map *map);
void resolved_stack_map_free(struct resolved_stack_map *map);

#endif /* OFFCPU_H */
