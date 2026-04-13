/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
#ifndef ONCPU_H
#define ONCPU_H

#include <stdint.h>
#include <linux/perf_event.h>

/*
 * On-CPU profiling via perf_event_open + mmap ring buffer.
 *
 * We open a task-clock perf event, mmap it, and read PERF_RECORD_SAMPLE
 * (and metadata) records from the ring buffer. Samples are already in
 * the correct binary format for perf.data output.
 */

/* Opaque context for on-CPU collection */
struct oncpu_ctx;

/* Parameters for oncpu_open() */
struct oncpu_params {
	pid_t    pid;             /* target PID (-1 for system-wide) */
	int      freq;            /* sampling frequency (Hz) */
	int      system_wide;     /* 1 = system-wide, 0 = per-PID */
	int      exclude_kernel;  /* 1 = exclude kernel stacks */
	int      max_stack;       /* max stack depth */
	int      mmap_pages;      /* ring buffer size in pages (power of 2) */
};

/* A buffered raw record from the perf mmap ring */
struct raw_record {
	uint32_t type;       /* PERF_RECORD_SAMPLE, MMAP2, COMM, etc. */
	uint16_t misc;
	uint32_t size;       /* total record size */
	uint64_t timestamp;  /* extracted time (for sorting) */
	void    *data;       /* malloc'd copy of the full record (incl. header) */
};

/* Dynamically sized buffer of raw records */
struct raw_record_buf {
	struct raw_record *entries;
	int nr;
	int cap;
};

/* Open perf events and mmap ring buffers. Returns context or NULL on error. */
struct oncpu_ctx *oncpu_open(const struct oncpu_params *params);

/* Get the perf fds for epoll. Returns count; fills fds[] and nr_fds. */
int oncpu_get_fds(struct oncpu_ctx *ctx, int **fds, int *nr_fds);

/* Read all available events from the mmap ring buffers into buf. */
int oncpu_read(struct oncpu_ctx *ctx, struct raw_record_buf *buf);

/* Get the perf_event_attr used (for writing to perf.data). */
const struct perf_event_attr *oncpu_get_attr(struct oncpu_ctx *ctx);

/* Get the kernel-assigned event ID for the on-CPU event. */
uint64_t oncpu_get_event_id(struct oncpu_ctx *ctx);

/* Get all kernel-assigned event IDs (one per fd/CPU). */
int oncpu_get_event_ids(struct oncpu_ctx *ctx, const uint64_t **ids,
			int *nr_ids);

/* Close perf events and free context. */
void oncpu_close(struct oncpu_ctx *ctx);

/* Initialize a raw_record_buf */
void raw_record_buf_init(struct raw_record_buf *buf);

/* Free all records in a raw_record_buf */
void raw_record_buf_free(struct raw_record_buf *buf);

/* Append a record to the buffer */
int raw_record_buf_append(struct raw_record_buf *buf,
			  const struct raw_record *rec);

#endif /* ONCPU_H */
