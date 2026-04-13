/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
#ifndef WRITER_H
#define WRITER_H

#include <stdint.h>
#include <linux/perf_event.h>
#include "oncpu.h"
#include "offcpu.h"
#include "proc.h"

/*
 * perf.data file writer.
 *
 * Writes a valid perf.data file with:
 *   - 6 event attrs (1 on-CPU + 5 off-CPU subclasses)
 *   - COMM and MMAP2 records
 *   - Merged on-CPU + off-CPU SAMPLE records (time-sorted)
 *   - Feature sections (EVENT_DESC, CMDLINE, SAMPLE_TIME)
 */

struct writer_params {
	const char              *output_path;
	const struct perf_event_attr *oncpu_attr;  /* from perf_event_open */
	uint64_t                 oncpu_event_id;   /* first kernel-assigned ID */
	const uint64_t          *oncpu_event_ids;  /* all per-CPU IDs (system-wide) */
	int                      nr_oncpu_ids;     /* count of IDs */
	int                      combined;         /* merge all events into one */
	int                      argc;             /* for HEADER_CMDLINE */
	char                   **argv;
	struct kern_sym_info     kern_info;         /* for BPF frame filtering */
};

/* Write a complete perf.data file. Returns 0 on success. */
int writer_write(const struct writer_params *params,
		 struct raw_record_buf *oncpu_records,
		 struct offcpu_event_buf *offcpu_events,
		 struct resolved_stack_map *stacks,
		 struct proc_map_list *maps,
		 struct proc_thread_list *threads);

#endif /* WRITER_H */
