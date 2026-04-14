// SPDX-License-Identifier: GPL-2.0
/*
 * bperf.bpf.c - BPF program for off-CPU profiling
 *
 * Attaches to tp_btf/sched_switch to capture off-CPU events.
 * For each context switch:
 *   - Phase 1 (sched-out): record timestamp, stacks, and subclass for prev
 *   - Phase 2 (sched-in):  compute off-CPU duration for next, emit event
 */
#define __BPF_PROGRAM__

#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../include/bperf_common.h"

/* ── Maps ─────────────────────────────────────────────────────────── */

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_offcpu_data);
} task_storage SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
	__uint(value_size, BPERF_MAX_STACK_DEPTH * sizeof(u64));
	__uint(max_entries, BPERF_STACK_MAP_ENTRIES);
} stack_traces SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, BPERF_RINGBUF_SIZE);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct bperf_config);
} bperf_cfg SEC(".maps");

/* ── Helpers ──────────────────────────────────────────────────────── */

/*
 * Classify why a task went off-CPU based on prev_state and in_iowait.
 *
 * prev_state encoding from the sched_switch tracepoint:
 *   bit 0 (0x01): TASK_INTERRUPTIBLE
 *   bit 1 (0x02): TASK_UNINTERRUPTIBLE
 *   bit 2 (0x04): __TASK_STOPPED
 *   bit 3 (0x08): __TASK_TRACED
 *   0:            TASK_RUNNING (preempted)
 *
 * The kernel may set additional high bits (TASK_REPORT flags, etc.).
 * We mask to the low byte.
 */
static __always_inline u8 classify_offcpu(unsigned int prev_state,
					  struct task_struct *prev)
{
	unsigned int state = prev_state & 0xFF;

	if (state == 0) /* TASK_RUNNING — preempted */
		return OFFCPU_SUBCLASS_SCHED;

	/*
	 * Check in_iowait before general UNINTERRUPTIBLE.
	 * in_iowait is a bit-field, so BPF_CORE_READ() cannot be used.
	 * BPF_CORE_READ_BITFIELD() works for tp_btf where prev is trusted.
	 */
	if (BPF_CORE_READ_BITFIELD(prev, in_iowait))
		return OFFCPU_SUBCLASS_IOWAIT;

	if (state & 0x01) /* TASK_INTERRUPTIBLE */
		return OFFCPU_SUBCLASS_INTERRUPTIBLE;

	if (state & 0x02) /* TASK_UNINTERRUPTIBLE */
		return OFFCPU_SUBCLASS_UNINTERRUPTIBLE;

	return OFFCPU_SUBCLASS_OTHER;
}

/* ── Main program ─────────────────────────────────────────────────── */

SEC("tp_btf/sched_switch")
int BPF_PROG(handle_sched_switch,
	     bool preempt,
	     struct task_struct *prev,
	     struct task_struct *next)
{
	u32 zero = 0;
	struct bperf_config *cfg;
	u32 prev_tgid, next_tgid, prev_tid, next_tid, target, target_tid;

	cfg = bpf_map_lookup_elem(&bperf_cfg, &zero);
	if (!cfg)
		return 0;

	prev_tgid = BPF_CORE_READ(prev, tgid);
	next_tgid = BPF_CORE_READ(next, tgid);
	prev_tid = BPF_CORE_READ(prev, pid);
	next_tid = BPF_CORE_READ(next, pid);
	target = cfg->target_tgid;
	target_tid = cfg->target_tid;

	/*
	 * Phase 1: SCHED-OUT — record state for the outgoing task (prev).
	 *
	 * We capture stacks NOW while prev is still current and its
	 * page tables are still active, so BPF_F_USER_STACK works.
	 */
	if (target == 0 || prev_tgid == target) {
		/* If filtering by TID, skip non-matching threads */
		if (target_tid && prev_tid != target_tid)
			goto phase2;

		/* Skip kernel threads (tgid == 0) in system-wide mode */
		if (prev_tgid == 0)
			goto phase2;

		struct task_offcpu_data *data;
		data = bpf_task_storage_get(&task_storage, prev, NULL,
					    BPF_LOCAL_STORAGE_GET_F_CREATE);
		if (!data)
			goto phase2;

		data->sched_out_ts = bpf_ktime_get_ns();

		/*
		 * Get prev_state: on 6.8+ kernels with tp_btf, the
		 * sched_switch tracepoint provides prev's state via
		 * prev->__state at the point of context switch. We read
		 * it from the task_struct directly.
		 */
		unsigned int prev_state = BPF_CORE_READ(prev, __state);
		data->subclass = classify_offcpu(prev_state, prev);

		data->kern_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
		data->user_stack_id = bpf_get_stackid(ctx, &stack_traces,
						       BPF_F_USER_STACK);
	}

phase2:
	/*
	 * Phase 2: SCHED-IN — emit off-CPU event for the incoming task (next).
	 */
	if (target == 0 || next_tgid == target) {
		if (next_tgid == 0)
			return 0;

		/* If filtering by TID, skip non-matching threads */
		if (target_tid && next_tid != target_tid)
			return 0;

		struct task_offcpu_data *data;
		data = bpf_task_storage_get(&task_storage,
					    (struct task_struct *)next,
					    NULL, 0);
		if (!data || data->sched_out_ts == 0)
			return 0;

		u64 now = bpf_ktime_get_ns();
		u64 delta = now - data->sched_out_ts;

		/* Apply minimum duration filter */
		if (delta < cfg->min_duration_ns) {
			data->sched_out_ts = 0;
			return 0;
		}

		/* Emit event to ring buffer */
		struct offcpu_event *evt;
		evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
		if (!evt) {
			data->sched_out_ts = 0;
			return 0;
		}

		evt->pid = next_tgid;
		evt->tid = BPF_CORE_READ(next, pid);
		evt->sched_out_ts = data->sched_out_ts;
		evt->duration_ns = delta;
		evt->kern_stack_id = data->kern_stack_id;
		evt->user_stack_id = data->user_stack_id;
		evt->cpu = bpf_get_smp_processor_id();
		evt->subclass = data->subclass;
		evt->pad[0] = evt->pad[1] = evt->pad[2] = 0;

		bpf_ringbuf_submit(evt, 0);

		/* Reset so we don't double-count */
		data->sched_out_ts = 0;
	}

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
