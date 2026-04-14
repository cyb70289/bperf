/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * oncpu.c - On-CPU sample collection via perf_event_open + mmap ring buffer
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <time.h>
#include <poll.h>

#include "oncpu.h"
#include "perf_file.h"

/* ── Helpers ──────────────────────────────────────────────────────── */

static long perf_event_open(struct perf_event_attr *attr, pid_t pid,
			    int cpu, int group_fd, unsigned long flags)
{
	return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

/* ── Per-CPU mmap state ───────────────────────────────────────────── */

struct perf_mmap {
	int      fd;
	void    *base;        /* mmap'd region */
	size_t   mask;         /* data_size - 1 (for wrapping) */
	size_t   data_size;
	size_t   page_size;
};

struct oncpu_ctx {
	struct perf_event_attr attr;
	uint64_t event_id;       /* first event ID (for per-PID mode) */
	uint64_t *event_ids;     /* all event IDs (one per fd) */
	int nr_ids;
	struct perf_mmap *mmaps;
	int nr_mmaps;
	int *fds;       /* fd array for caller */
	int mmap_pages; /* pages for ring buffer (power of 2) */
};

/* ── Buffer helpers ───────────────────────────────────────────────── */

void raw_record_buf_init(struct raw_record_buf *buf)
{
	memset(buf, 0, sizeof(*buf));
}

void raw_record_buf_free(struct raw_record_buf *buf)
{
	for (int i = 0; i < buf->nr; i++)
		free(buf->entries[i].data);
	free(buf->entries);
	memset(buf, 0, sizeof(*buf));
}

int raw_record_buf_append(struct raw_record_buf *buf,
			  const struct raw_record *rec)
{
	if (buf->nr >= buf->cap) {
		int newcap = buf->cap ? buf->cap * 2 : 4096;
		struct raw_record *tmp = realloc(buf->entries,
						 newcap * sizeof(*tmp));
		if (!tmp)
			return -ENOMEM;
		buf->entries = tmp;
		buf->cap = newcap;
	}
	buf->entries[buf->nr++] = *rec;
	return 0;
}

/* ── Extract timestamp from a perf record ─────────────────────────── */

/*
 * For PERF_RECORD_SAMPLE with our sample_type, the layout is:
 *   header (8) | identifier (8) | ip (8) | pid+tid (8) | time (8) | ...
 *
 * For non-SAMPLE records with sample_id_all=1, the sample_id trailer
 * is appended at the END of the record:
 *   ... | pid+tid (8) | time (8) | cpu+res (8) | identifier (8)
 */
static uint64_t extract_timestamp(const void *record, uint32_t size,
				  uint32_t type)
{
	const uint8_t *p = record;

	if (type == PERF_RECORD_SAMPLE) {
		/* header(8) + identifier(8) + ip(8) + pid+tid(8) + time(8) */
		if (size < 40)
			return 0;
		uint64_t ts;
		memcpy(&ts, p + 32, 8);
		return ts;
	}

	/* Non-SAMPLE: sample_id trailer at end of record.
	 * Trailer: pid(4)+tid(4) + time(8) + cpu(4)+res(4) + identifier(8) = 32
	 */
	if (size < 8 + BPERF_SAMPLE_ID_SIZE)
		return 0;
	uint64_t ts;
	memcpy(&ts, p + size - 24, 8); /* time is 24 bytes from end */
	return ts;
}

/* ── Open perf events ─────────────────────────────────────────────── */

struct oncpu_ctx *oncpu_open(const struct oncpu_params *params)
{
	struct oncpu_ctx *ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->mmap_pages = params->mmap_pages ? params->mmap_pages : 64;

	/* Set up perf_event_attr */
	struct perf_event_attr *attr = &ctx->attr;
	memset(attr, 0, sizeof(*attr));
	attr->type           = PERF_TYPE_SOFTWARE;
	attr->size           = sizeof(*attr);
	attr->config         = PERF_COUNT_SW_TASK_CLOCK;
	attr->sample_type    = BPERF_SAMPLE_TYPE;
	attr->sample_freq    = params->freq;
	attr->freq           = 1;
	attr->sample_id_all  = 1;
	attr->comm           = 1;
	attr->mmap           = 1;
	attr->mmap2          = 1;
	attr->task           = 1;
	attr->exclude_kernel = params->exclude_kernel ? 1 : 0;
	attr->sample_max_stack = params->max_stack;
	attr->wakeup_events  = 1;
	attr->use_clockid    = 1;
	attr->clockid        = CLOCK_MONOTONIC;

	int nr_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	size_t page_size = sysconf(_SC_PAGESIZE);

	if (params->system_wide) {
		/* System-wide: one fd per CPU */
		ctx->nr_mmaps = nr_cpus;
		ctx->mmaps = calloc(nr_cpus, sizeof(*ctx->mmaps));
		ctx->fds = calloc(nr_cpus, sizeof(int));
		if (!ctx->mmaps || !ctx->fds)
			goto err;

		for (int cpu = 0; cpu < nr_cpus; cpu++) {
			int fd = perf_event_open(attr, -1, cpu, -1,
						 PERF_FLAG_FD_CLOEXEC);
			if (fd < 0) {
				fprintf(stderr,
					"perf_event_open(cpu=%d): %s\n",
					cpu, strerror(errno));
				ctx->nr_mmaps = cpu;
				goto err;
			}
			ctx->mmaps[cpu].fd = fd;
			ctx->fds[cpu] = fd;
		}
	} else if (params->nr_tids > 0 && params->tids) {
		/*
		 * Per-process: one fd per thread.
		 * The caller enumerated /proc/TGID/task/ and passed us
		 * the thread list.
		 */
		int nt = params->nr_tids;
		ctx->nr_mmaps = nt;
		ctx->mmaps = calloc(nt, sizeof(*ctx->mmaps));
		ctx->fds = calloc(nt, sizeof(int));
		if (!ctx->mmaps || !ctx->fds)
			goto err;

		for (int i = 0; i < nt; i++) {
			int fd = perf_event_open(attr, params->tids[i], -1, -1,
						 PERF_FLAG_FD_CLOEXEC);
			if (fd < 0) {
				fprintf(stderr,
					"perf_event_open(tid=%d): %s\n",
					params->tids[i], strerror(errno));
				ctx->nr_mmaps = i;
				goto err;
			}
			ctx->mmaps[i].fd = fd;
			ctx->fds[i] = fd;
		}
	} else {
		/* Per-PID: one fd, any CPU */
		ctx->nr_mmaps = 1;
		ctx->mmaps = calloc(1, sizeof(*ctx->mmaps));
		ctx->fds = calloc(1, sizeof(int));
		if (!ctx->mmaps || !ctx->fds)
			goto err;

		int fd = perf_event_open(attr, params->pid, -1, -1,
					 PERF_FLAG_FD_CLOEXEC);
		if (fd < 0) {
			fprintf(stderr, "perf_event_open(pid=%d): %s\n",
				params->pid, strerror(errno));
			goto err;
		}
		ctx->mmaps[0].fd = fd;
		ctx->fds[0] = fd;
	}

	/* Get event IDs from all fds */
	ctx->nr_ids = ctx->nr_mmaps;
	ctx->event_ids = calloc(ctx->nr_ids, sizeof(uint64_t));
	if (!ctx->event_ids)
		goto err;

	for (int i = 0; i < ctx->nr_ids; i++) {
		uint64_t id = 0;
		if (ioctl(ctx->mmaps[i].fd, PERF_EVENT_IOC_ID, &id) < 0) {
			fprintf(stderr, "PERF_EVENT_IOC_ID: %s\n",
				strerror(errno));
			goto err;
		}
		ctx->event_ids[i] = id;
	}
	ctx->event_id = ctx->event_ids[0];

	/* mmap each fd */
	size_t mmap_size = (1 + ctx->mmap_pages) * page_size;
	for (int i = 0; i < ctx->nr_mmaps; i++) {
		void *base = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE,
				  MAP_SHARED, ctx->mmaps[i].fd, 0);
		if (base == MAP_FAILED) {
			fprintf(stderr, "mmap perf ring: %s\n",
				strerror(errno));
			goto err;
		}
		ctx->mmaps[i].base = base;
		ctx->mmaps[i].data_size = ctx->mmap_pages * page_size;
		ctx->mmaps[i].mask = ctx->mmaps[i].data_size - 1;
		ctx->mmaps[i].page_size = page_size;
	}

	return ctx;

err:
	oncpu_close(ctx);
	return NULL;
}

/* ── Accessors ────────────────────────────────────────────────────── */

int oncpu_get_fds(struct oncpu_ctx *ctx, int **fds, int *nr_fds)
{
	*fds = ctx->fds;
	*nr_fds = ctx->nr_mmaps;
	return 0;
}

const struct perf_event_attr *oncpu_get_attr(struct oncpu_ctx *ctx)
{
	return &ctx->attr;
}

uint64_t oncpu_get_event_id(struct oncpu_ctx *ctx)
{
	return ctx->event_id;
}

int oncpu_get_event_ids(struct oncpu_ctx *ctx, const uint64_t **ids, int *nr_ids)
{
	*ids = ctx->event_ids;
	*nr_ids = ctx->nr_ids;
	return 0;
}

/* ── Read events from mmap ring ───────────────────────────────────── */

static int read_mmap(struct perf_mmap *mm, struct raw_record_buf *buf)
{
	struct perf_event_mmap_page *header = mm->base;
	uint8_t *data = (uint8_t *)mm->base + mm->page_size;

	uint64_t head = __atomic_load_n(&header->data_head, __ATOMIC_ACQUIRE);
	uint64_t tail = header->data_tail;

	while (tail < head) {
		uint64_t offset = tail & mm->mask;
		struct perf_event_header *ehdr =
			(struct perf_event_header *)(data + offset);

		/* Read the header (may wrap) */
		struct perf_event_header hdr_copy;
		if (offset + sizeof(hdr_copy) > mm->data_size) {
			/* Header wraps around */
			size_t part1 = mm->data_size - offset;
			memcpy(&hdr_copy, data + offset, part1);
			memcpy((uint8_t *)&hdr_copy + part1, data,
			       sizeof(hdr_copy) - part1);
			ehdr = &hdr_copy;
		}

		uint32_t rec_size = ehdr->size;
		if (rec_size == 0 || rec_size > mm->data_size)
			break;

		/* Copy full record (handle wrap-around) */
		void *rec_data = malloc(rec_size);
		if (!rec_data)
			break;

		if (offset + rec_size <= mm->data_size) {
			memcpy(rec_data, data + offset, rec_size);
		} else {
			size_t part1 = mm->data_size - offset;
			memcpy(rec_data, data + offset, part1);
			memcpy((uint8_t *)rec_data + part1, data,
			       rec_size - part1);
		}

		struct raw_record rec = {
			.type = ehdr->type,
			.misc = ehdr->misc,
			.size = rec_size,
			.timestamp = extract_timestamp(rec_data, rec_size,
						       ehdr->type),
			.data = rec_data,
		};

		raw_record_buf_append(buf, &rec);
		tail += rec_size;
	}

	__atomic_store_n(&header->data_tail, tail, __ATOMIC_RELEASE);
	return 0;
}

int oncpu_read(struct oncpu_ctx *ctx, struct raw_record_buf *buf)
{
	for (int i = 0; i < ctx->nr_mmaps; i++)
		read_mmap(&ctx->mmaps[i], buf);
	return 0;
}

/* ── Cleanup ──────────────────────────────────────────────────────── */

void oncpu_close(struct oncpu_ctx *ctx)
{
	if (!ctx)
		return;

	size_t page_size = sysconf(_SC_PAGESIZE);
	size_t mmap_size = (1 + ctx->mmap_pages) * page_size;

	for (int i = 0; i < ctx->nr_mmaps; i++) {
		if (ctx->mmaps[i].base && ctx->mmaps[i].base != MAP_FAILED)
			munmap(ctx->mmaps[i].base, mmap_size);
		if (ctx->mmaps[i].fd > 0)
			close(ctx->mmaps[i].fd);
	}
	free(ctx->mmaps);
	free(ctx->fds);
	free(ctx->event_ids);
	free(ctx);
}
