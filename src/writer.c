/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * writer.c - perf.data file writer
 *
 * Writes a valid perf.data file with:
 *   - 1 "wall-clock" attr (all IDs merged)
 *   - COMM, MMAP2, and SAMPLE records (merged, time-sorted)
 *   - Feature sections (EVENT_DESC, CMDLINE, SAMPLE_TIME, CLOCKID)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <linux/perf_event.h>

#include "writer.h"
#include "perf_file.h"
#include "bperf_common.h"

/* ── Internal write helpers ───────────────────────────────────────── */

struct writer_ctx {
	int      fd;
	uint64_t offset;   /* current write position */
};

static int wr_bytes(struct writer_ctx *w, const void *buf, size_t len)
{
	ssize_t n = write(w->fd, buf, len);
	if (n < 0)
		return -errno;
	w->offset += n;
	return 0;
}

static int wr_u8(struct writer_ctx *w, uint8_t v)  { return wr_bytes(w, &v, 1); }

static int wr_u32(struct writer_ctx *w, uint32_t v) { return wr_bytes(w, &v, 4); }
static int wr_u64(struct writer_ctx *w, uint64_t v) { return wr_bytes(w, &v, 8); }

static int wr_pad(struct writer_ctx *w, size_t len)
{
	uint8_t zero = 0;
	for (size_t i = 0; i < len; i++)
		wr_u8(w, zero);
	return 0;
}


/* Seek to absolute position */
static int wr_seek(struct writer_ctx *w, uint64_t pos)
{
	off_t r = lseek(w->fd, pos, SEEK_SET);
	if (r < 0)
		return -errno;
	w->offset = pos;
	return 0;
}

/* ── Stack lookup ─────────────────────────────────────────────────── */

static const struct resolved_stack *find_stack(
	const struct resolved_stack_map *map, int32_t stack_id)
{
	if (stack_id < 0)
		return NULL;
	for (int i = 0; i < map->nr; i++) {
		if (map->stacks[i].stack_id == stack_id)
			return &map->stacks[i];
	}
	return NULL;
}

/* ── sample_id trailer (for non-SAMPLE records) ──────────────────── */

/*
 * With sample_id_all=1 and our sample_type, the trailer contains
 * only the "id" subset fields that are present in sample_type:
 *   TID (pid+tid)  [8 bytes]
 *   TIME            [8 bytes]
 *   CPU (cpu+res)  [8 bytes]
 *   IDENTIFIER     [8 bytes]
 * Total: 32 bytes
 */
static int write_sample_id(struct writer_ctx *w, uint32_t pid, uint32_t tid,
			   uint64_t time, uint32_t cpu, uint64_t id)
{
	wr_u32(w, pid);
	wr_u32(w, tid);
	wr_u64(w, time);
	wr_u32(w, cpu);
	wr_u32(w, 0);  /* reserved */
	wr_u64(w, id);
	return 0;
}

/* ── COMM record ──────────────────────────────────────────────────── */

static int write_comm_record(struct writer_ctx *w,
			     const struct proc_thread *th,
			     uint64_t time, uint64_t event_id)
{
	/*
	 * PERF_RECORD_COMM layout:
	 *   header (8) + pid (4) + tid (4) + comm (variable) + sample_id (32)
	 * comm is padded to 8-byte alignment (including NUL).
	 */
	size_t comm_len = strlen(th->comm) + 1;
	size_t padded_comm = (comm_len + 7) & ~(size_t)7;

	uint16_t size = 8 + 4 + 4 + padded_comm + BPERF_SAMPLE_ID_SIZE;

	struct perf_event_header hdr = {
		.type = PERF_RECORD_COMM,
		.misc = PERF_RECORD_MISC_COMM_EXEC,
		.size = size,
	};

	wr_bytes(w, &hdr, sizeof(hdr));
	wr_u32(w, th->pid);
	wr_u32(w, th->tid);
	wr_bytes(w, th->comm, comm_len);
	if (padded_comm > comm_len)
		wr_pad(w, padded_comm - comm_len);
	write_sample_id(w, th->pid, th->tid, time, 0, event_id);
	return 0;
}

/* ── MMAP2 record ─────────────────────────────────────────────────── */

static int write_mmap2_record(struct writer_ctx *w,
			      const struct proc_map *map,
			      uint32_t pid, uint32_t tid,
			      uint64_t time, uint64_t event_id)
{
	/*
	 * PERF_RECORD_MMAP2 layout:
	 *   header (8) + pid (4) + tid (4) + addr (8) + len (8) + pgoff (8)
	 *   + maj (4) + min (4) + ino (8) + ino_generation (8)
	 *   + prot (4) + flags (4) + filename (variable) + sample_id (32)
	 */
	int is_kernel = (strncmp(map->filename, "[kernel.", 8) == 0);
	size_t fn_len = strlen(map->filename) + 1;
	size_t padded_fn = (fn_len + 7) & ~(size_t)7;

	uint16_t size = 8 + 4 + 4 + 8 + 8 + 8 + 4 + 4 + 8 + 8 + 4 + 4
			+ padded_fn + BPERF_SAMPLE_ID_SIZE;

	struct perf_event_header hdr = {
		.type = PERF_RECORD_MMAP2,
		.misc = is_kernel ? PERF_RECORD_MISC_KERNEL
				  : PERF_RECORD_MISC_USER,
		.size = size,
	};

	wr_bytes(w, &hdr, sizeof(hdr));
	wr_u32(w, pid);
	wr_u32(w, tid);
	wr_u64(w, map->addr);
	wr_u64(w, map->len);
	wr_u64(w, map->pgoff);
	wr_u32(w, map->maj);
	wr_u32(w, map->min);
	wr_u64(w, map->ino);
	wr_u64(w, 0);          /* ino_generation */
	wr_u32(w, map->prot);
	wr_u32(w, map->flags);
	wr_bytes(w, map->filename, fn_len);
	if (padded_fn > fn_len)
		wr_pad(w, padded_fn - fn_len);
	write_sample_id(w, pid, tid, time, 0, event_id);
	return 0;
}

/* ── Off-CPU → PERF_RECORD_SAMPLE ─────────────────────────────────── */

static int write_offcpu_sample(struct writer_ctx *w,
			       const struct offcpu_event *evt,
			       const uint64_t *event_ids,
			       const struct resolved_stack_map *stacks,
			       const struct kern_sym_info *kern_info)
{
	/* Select event ID based on subclass */
	uint64_t event_id;
	switch (evt->subclass) {
	case OFFCPU_SUBCLASS_SCHED:           event_id = event_ids[1]; break;
	case OFFCPU_SUBCLASS_IOWAIT:          event_id = event_ids[2]; break;
	case OFFCPU_SUBCLASS_INTERRUPTIBLE:   event_id = event_ids[3]; break;
	case OFFCPU_SUBCLASS_UNINTERRUPTIBLE: event_id = event_ids[4]; break;
	default:                              event_id = event_ids[5]; break;
	}

	/* Resolve stacks */
	const struct resolved_stack *kstack = find_stack(stacks, evt->kern_stack_id);
	const struct resolved_stack *ustack = find_stack(stacks, evt->user_stack_id);

	int kern_nr = kstack ? kstack->nr_ips : 0;
	int user_nr = ustack ? ustack->nr_ips : 0;

	/*
	 * Filter BPF JIT frames from the kernel stack.
	 * bpf_get_stackid() captures BPF JIT return addresses at the
	 * top of the stack.  These lie outside the vmlinux core text
	 * range (_stext.._etext) and show as [unknown] in perf report.
	 * Skip them so the stack starts at a real kernel function.
	 */
	int kern_skip = 0;
	if (kern_info->text_start < kern_info->text_end) {
		while (kern_skip < kern_nr) {
			uint64_t ip = kstack->ips[kern_skip];
			if (ip < kern_info->text_start ||
			    ip >= kern_info->text_end)
				kern_skip++;
			else
				break;
		}
	}
	int valid_kern_nr = kern_nr - kern_skip;

	/* Build callchain: [CONTEXT_KERNEL, kips..., CONTEXT_USER, uips...] */
	int cc_nr = 0;
	if (valid_kern_nr > 0)
		cc_nr += 1 + valid_kern_nr; /* context marker + IPs */
	if (user_nr > 0)
		cc_nr += 1 + user_nr;

	/* Determine IP and misc */
	uint64_t ip = 0;
	uint16_t misc = 0;
	if (user_nr > 0) {
		ip = ustack->ips[0];
		misc = PERF_RECORD_MISC_USER;
	} else if (valid_kern_nr > 0) {
		ip = kstack->ips[kern_skip];
		misc = PERF_RECORD_MISC_KERNEL;
	}

	/*
	 * PERF_RECORD_SAMPLE layout with our sample_type:
	 *   header (8) + identifier (8) + ip (8) + pid+tid (8) + time (8)
	 *   + cpu+res (8) + period (8) + callchain_nr (8) + cc_nr*8
	 *   + weight (8)
	 */
	uint16_t size = 8 + 8 + 8 + 8 + 8 + 8 + 8 + 8 + cc_nr * 8 + 8;

	struct perf_event_header hdr = {
		.type = PERF_RECORD_SAMPLE,
		.misc = misc,
		.size = size,
	};

	wr_bytes(w, &hdr, sizeof(hdr));
	wr_u64(w, event_id);            /* identifier */
	wr_u64(w, ip);                  /* ip */
	wr_u32(w, evt->pid);            /* pid */
	wr_u32(w, evt->tid);            /* tid */
	wr_u64(w, evt->sched_out_ts);   /* time (when blocked) */
	wr_u32(w, evt->cpu);            /* cpu */
	wr_u32(w, 0);                   /* reserved */
	wr_u64(w, evt->duration_ns);    /* period = off-CPU duration */
	wr_u64(w, (uint64_t)cc_nr);     /* callchain nr */

	/* Callchain IPs */
	if (valid_kern_nr > 0) {
		wr_u64(w, PERF_CONTEXT_KERNEL);
		for (int i = 0; i < valid_kern_nr; i++)
			wr_u64(w, kstack->ips[kern_skip + i]);
	}
	if (user_nr > 0) {
		wr_u64(w, PERF_CONTEXT_USER);
		for (int i = 0; i < user_nr; i++)
			wr_u64(w, ustack->ips[i]);
	}

	wr_u64(w, evt->duration_ns);    /* weight */

	return 0;
}

/* ── Feature section: EVENT_DESC ──────────────────────────────────── */

static int wr_perf_string(struct writer_ctx *w, const char *str)
{
	/*
	 * perf's do_write_string format:
	 *   u32 padded_len + string zero-padded to padded_len bytes
	 * where padded_len = PERF_ALIGN(strlen+1, NAME_ALIGN=64)
	 */
	uint32_t olen = strlen(str) + 1;
	uint32_t plen = PERF_ALIGN(olen, PERF_NAME_ALIGN);

	wr_u32(w, plen);
	wr_bytes(w, str, olen);
	if (plen > olen)
		wr_pad(w, plen - olen);
	return 0;
}

struct event_id_info {
	const uint64_t *ids;
	int nr;
};

static int write_event_desc(struct writer_ctx *w,
			    const struct perf_event_attr attrs[],
			    const struct event_id_info id_info[],
			    const char * const names[],
			    int nr_events)
{
	/* nr_events (4) + attr_size (4) */
	wr_u32(w, nr_events);
	wr_u32(w, (uint32_t)attrs[0].size);

	/*
	 * Per-event layout (must match perf's write_event_desc / read_event_desc):
	 *   1. struct perf_event_attr
	 *   2. u32 nr_ids
	 *   3. perf_string (event name)
	 *   4. u64 ids[nr_ids]
	 */
	for (int i = 0; i < nr_events; i++) {
		wr_bytes(w, &attrs[i], attrs[i].size);
		wr_u32(w, id_info[i].nr);
		wr_perf_string(w, names[i]);
		for (int j = 0; j < id_info[i].nr; j++)
			wr_u64(w, id_info[i].ids[j]);
	}
	return 0;
}

/* ── Feature section: CMDLINE ─────────────────────────────────────── */

static int write_cmdline(struct writer_ctx *w, int argc, char **argv)
{
	wr_u32(w, argc);
	for (int i = 0; i < argc; i++)
		wr_perf_string(w, argv[i]);
	return 0;
}

/* ── Feature section: SAMPLE_TIME ─────────────────────────────────── */

static int write_sample_time(struct writer_ctx *w,
			     uint64_t first_time, uint64_t last_time)
{
	wr_u64(w, first_time);
	wr_u64(w, last_time);
	return 0;
}

/* ── Comparison for merge-sort ────────────────────────────────────── */

struct sample_ref {
	uint64_t timestamp;
	int      is_offcpu; /* 0 = on-CPU raw_record, 1 = offcpu_event */
	int      index;     /* index into the respective array */
};

static int cmp_sample_ref(const void *a, const void *b)
{
	const struct sample_ref *sa = a;
	const struct sample_ref *sb = b;
	if (sa->timestamp < sb->timestamp)
		return -1;
	if (sa->timestamp > sb->timestamp)
		return 1;
	return 0;
}

/* ── Main writer ──────────────────────────────────────────────────── */

int writer_write(const struct writer_params *params,
		 struct raw_record_buf *oncpu_records,
		 struct offcpu_event_buf *offcpu_events,
		 struct resolved_stack_map *stacks,
		 struct proc_map_list *maps,
		 struct proc_thread_list *threads)
{
	int fd = open(params->output_path,
		      O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		fprintf(stderr, "open %s: %s\n", params->output_path,
			strerror(errno));
		return -1;
	}

	struct writer_ctx w = { .fd = fd, .offset = 0 };

	/* ── 1. Build event attributes ─────────────────────────────── */

	struct perf_event_attr attrs[BPERF_NR_EVENTS];

	/* On-CPU IDs: use all per-CPU IDs if available, else single ID */
	int nr_oncpu_ids = params->nr_oncpu_ids;
	const uint64_t *oncpu_ids = params->oncpu_event_ids;
	uint64_t single_id;
	if (nr_oncpu_ids <= 0 || !oncpu_ids) {
		single_id = params->oncpu_event_id;
		oncpu_ids = &single_id;
		nr_oncpu_ids = 1;
	}

	/* Off-CPU IDs: 1 each */
	uint64_t offcpu_ids[5];
	for (int i = 0; i < 5; i++)
		offcpu_ids[i] = OFFCPU_EVENT_ID_BASE + i;

	/* attr[0] = on-CPU (copy from the actual perf_event_open attr) */
	memcpy(&attrs[0], params->oncpu_attr, sizeof(attrs[0]));

	/* attrs[1..5] = off-CPU subclasses (synthetic) */
	for (int i = 1; i < BPERF_NR_EVENTS; i++) {
		memset(&attrs[i], 0, sizeof(attrs[i]));
		attrs[i].type        = PERF_TYPE_SOFTWARE;
		attrs[i].size        = attrs[0].size;
		attrs[i].config      = PERF_COUNT_SW_TASK_CLOCK;
		attrs[i].sample_type = BPERF_SAMPLE_TYPE;
		attrs[i].sample_id_all = 1;
		attrs[i].freq        = 0;
		/* period=1 for synthetic attrs (actual period in samples) */
		attrs[i].sample_period = 1;
	}

	/* ── Combined mode: single "wall-clock" attr with all IDs ──── */

	int nr_events = 1;
	int nr_combined = nr_oncpu_ids + 5;
	uint64_t *combined_ids = malloc(nr_combined * sizeof(uint64_t));
	if (!combined_ids) {
		close(fd);
		return -1;
	}
	memcpy(combined_ids, oncpu_ids, nr_oncpu_ids * sizeof(uint64_t));
	for (int i = 0; i < 5; i++)
		combined_ids[nr_oncpu_ids + i] = offcpu_ids[i];

	struct event_id_info combined_id_info = {
		.ids = combined_ids,
		.nr = nr_combined,
	};
	struct event_id_info *write_id_info = &combined_id_info;

	/* Event IDs for off-CPU sample writing (indexed by subclass 0..5) */
	uint64_t event_ids[BPERF_NR_EVENTS];
	event_ids[0] = oncpu_ids[0];
	for (int i = 1; i < BPERF_NR_EVENTS; i++)
		event_ids[i] = offcpu_ids[i - 1];

	/* ── 2. Write placeholder file header ──────────────────────── */

	struct perf_file_header fhdr;
	memset(&fhdr, 0, sizeof(fhdr));
	fhdr.magic = PERF_MAGIC;
	fhdr.size = sizeof(fhdr);
	/* attr_size = sizeof(perf_event_attr) + sizeof(perf_file_section) for ids */
	fhdr.attr_size = attrs[0].size + sizeof(struct perf_file_section);
	/* Placeholder — will be patched later */
	wr_bytes(&w, &fhdr, sizeof(fhdr));

	/* ── 3. Write attrs section ────────────────────────────────── */

	uint64_t attrs_offset = w.offset;

	/*
	 * Each attr entry in the file is:
	 *   struct perf_event_attr + struct perf_file_section (ids location)
	 *
	 * IDs come right after all attr entries. Compute offsets.
	 */
	uint64_t per_attr_size = attrs[0].size + sizeof(struct perf_file_section);
	uint64_t ids_start = attrs_offset + (uint64_t)nr_events * per_attr_size;

	/* Compute per-attr ID offsets */
	uint64_t id_offset = ids_start;
	for (int i = 0; i < nr_events; i++) {
		wr_bytes(&w, &attrs[i], attrs[i].size);
		struct perf_file_section ids_sec = {
			.offset = id_offset,
			.size = write_id_info[i].nr * sizeof(uint64_t),
		};
		wr_bytes(&w, &ids_sec, sizeof(ids_sec));
		id_offset += write_id_info[i].nr * sizeof(uint64_t);
	}

	/* ── 4. Write ID arrays ────────────────────────────────────── */

	for (int i = 0; i < nr_events; i++)
		for (int j = 0; j < write_id_info[i].nr; j++)
			wr_u64(&w, write_id_info[i].ids[j]);

	/* ── 5. Data section ───────────────────────────────────────── */

	uint64_t data_offset = w.offset;

	/* 5a. Determine a base timestamp for metadata records */
	uint64_t first_time = UINT64_MAX;
	for (int i = 0; i < oncpu_records->nr; i++) {
		if (oncpu_records->entries[i].timestamp &&
		    oncpu_records->entries[i].timestamp < first_time)
			first_time = oncpu_records->entries[i].timestamp;
	}
	for (int i = 0; i < offcpu_events->nr; i++) {
		if (offcpu_events->entries[i].sched_out_ts < first_time)
			first_time = offcpu_events->entries[i].sched_out_ts;
	}
	if (first_time == UINT64_MAX)
		first_time = 0;

	/* Use a time slightly before the first sample for metadata */
	uint64_t meta_time = first_time > 1000 ? first_time - 1000 : 0;

	/* 5b. Write COMM records */
	for (int i = 0; i < threads->nr; i++)
		write_comm_record(&w, &threads->threads[i],
				  meta_time, event_ids[0]);

	/* 5c. Write MMAP2 records */
	uint32_t pid0 = (threads->nr > 0) ? threads->threads[0].pid : 0;
	uint32_t tid0 = (threads->nr > 0) ? threads->threads[0].tid : 0;
	for (int i = 0; i < maps->nr; i++)
		write_mmap2_record(&w, &maps->maps[i], pid0, tid0,
				   meta_time, event_ids[0]);

	/* 5d. Build sorted list of all SAMPLE events (on-CPU + off-CPU) */
	int nr_oncpu_samples = 0;
	for (int i = 0; i < oncpu_records->nr; i++) {
		if (oncpu_records->entries[i].type == PERF_RECORD_SAMPLE)
			nr_oncpu_samples++;
	}

	int total_samples = nr_oncpu_samples + offcpu_events->nr;
	struct sample_ref *refs = NULL;

	if (total_samples > 0) {
		refs = malloc(total_samples * sizeof(*refs));
		if (!refs)
			goto write_features;

		int idx = 0;
		for (int i = 0; i < oncpu_records->nr; i++) {
			if (oncpu_records->entries[i].type != PERF_RECORD_SAMPLE)
				continue;
			refs[idx].timestamp = oncpu_records->entries[i].timestamp;
			refs[idx].is_offcpu = 0;
			refs[idx].index = i;
			idx++;
		}
		for (int i = 0; i < offcpu_events->nr; i++) {
			refs[idx].timestamp = offcpu_events->entries[i].sched_out_ts;
			refs[idx].is_offcpu = 1;
			refs[idx].index = i;
			idx++;
		}

		qsort(refs, total_samples, sizeof(*refs), cmp_sample_ref);
	}

	/* 5e. Also write non-SAMPLE on-CPU records (MMAP2, COMM from kernel) */
	for (int i = 0; i < oncpu_records->nr; i++) {
		struct raw_record *rec = &oncpu_records->entries[i];
		if (rec->type == PERF_RECORD_SAMPLE)
			continue;
		/* Write the raw record as-is (it's already in correct format) */
		wr_bytes(&w, rec->data, rec->size);
	}

	/* 5f. Write merged SAMPLE records */
	for (int i = 0; i < total_samples; i++) {
		struct sample_ref *ref = &refs[i];
		if (!ref->is_offcpu) {
			/* On-CPU: write the raw perf record as-is */
			struct raw_record *rec =
				&oncpu_records->entries[ref->index];
			wr_bytes(&w, rec->data, rec->size);
		} else {
			/* Off-CPU: synthesize PERF_RECORD_SAMPLE */
			struct offcpu_event *evt =
				&offcpu_events->entries[ref->index];
			write_offcpu_sample(&w, evt, event_ids, stacks,
					    &params->kern_info);
		}
	}
	free(refs);

write_features:;
	uint64_t data_size = w.offset - data_offset;

	/* ── 6. Track last timestamp ───────────────────────────────── */

	uint64_t last_time = 0;
	for (int i = 0; i < oncpu_records->nr; i++) {
		if (oncpu_records->entries[i].timestamp > last_time)
			last_time = oncpu_records->entries[i].timestamp;
	}
	for (int i = 0; i < offcpu_events->nr; i++) {
		uint64_t t = offcpu_events->entries[i].sched_out_ts +
			     offcpu_events->entries[i].duration_ns;
		if (t > last_time)
			last_time = t;
	}

	/* ── 7. Write feature sections ─────────────────────────────── */

	/*
	 * Features we write: CMDLINE, EVENT_DESC, SAMPLE_TIME, CLOCKID
	 * Each feature has a perf_file_section (offset, size) entry in
	 * the feature header area, followed by the feature data.
	 *
	 * Features must be written in bit order.
	 * CMDLINE = bit 11, EVENT_DESC = bit 12, SAMPLE_TIME = bit 21,
	 * CLOCKID = bit 23
	 *
	 * Feature section headers (perf_file_section) come first (in bit
	 * order), then the actual feature data follows.
	 */

	/* Set feature bits */
	fhdr.adds_features[0] = 0;
	fhdr.adds_features[0] |= (1ULL << HEADER_CMDLINE);
	fhdr.adds_features[0] |= (1ULL << HEADER_EVENT_DESC);
	fhdr.adds_features[0] |= (1ULL << HEADER_SAMPLE_TIME);
	fhdr.adds_features[0] |= (1ULL << HEADER_CLOCKID);

	/* Feature header area: 4 perf_file_section entries (in bit order) */
	uint64_t feat_hdr_offset = w.offset;
	struct perf_file_section feat_sections[4];
	memset(feat_sections, 0, sizeof(feat_sections));

	/* Write placeholder feature section headers */
	wr_bytes(&w, feat_sections, sizeof(feat_sections));

	/* Feature 0 (bit 11): CMDLINE */
	feat_sections[0].offset = w.offset;
	if (params->argc > 0 && params->argv)
		write_cmdline(&w, params->argc, params->argv);
	else {
		char *default_argv[] = {"bperf", "record"};
		write_cmdline(&w, 2, default_argv);
	}
	feat_sections[0].size = w.offset - feat_sections[0].offset;

	/* Feature 1 (bit 12): EVENT_DESC */
	feat_sections[1].offset = w.offset;
	{
		const char * const *names = &bperf_combined_event_name;
		write_event_desc(&w, attrs, write_id_info, names,
				 nr_events);
	}
	feat_sections[1].size = w.offset - feat_sections[1].offset;

	/* Feature 2 (bit 21): SAMPLE_TIME */
	feat_sections[2].offset = w.offset;
	write_sample_time(&w, first_time, last_time);
	feat_sections[2].size = w.offset - feat_sections[2].offset;

	/* Feature 3 (bit 23): CLOCKID */
	feat_sections[3].offset = w.offset;
	{
		uint64_t clockid_val = CLOCK_MONOTONIC;
		wr_u64(&w, clockid_val);
	}
	feat_sections[3].size = w.offset - feat_sections[3].offset;

	/* Patch feature section headers */
	wr_seek(&w, feat_hdr_offset);
	wr_bytes(&w, feat_sections, sizeof(feat_sections));

	/* ── 8. Patch file header ──────────────────────────────────── */

	fhdr.attrs.offset = attrs_offset;
	fhdr.attrs.size = nr_events * per_attr_size;
	fhdr.data.offset = data_offset;
	fhdr.data.size = data_size;
	fhdr.event_types.offset = 0;
	fhdr.event_types.size = 0;

	wr_seek(&w, 0);
	wr_bytes(&w, &fhdr, sizeof(fhdr));

	free(combined_ids);
	close(fd);

	return 0;
}
