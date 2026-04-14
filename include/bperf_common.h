/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * bperf_common.h - Shared data structures between BPF and userspace
 */
#ifndef BPERF_COMMON_H
#define BPERF_COMMON_H

/*
 * When included from BPF program context, basic types come from vmlinux.h.
 * When included from userspace, use standard headers.
 */
#ifndef __BPF_PROGRAM__
#include <stdint.h>
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t  s32;
typedef int64_t  s64;
#endif

/* Off-CPU subclass classification */
enum offcpu_subclass {
	OFFCPU_SUBCLASS_SCHED           = 1, /* preempted / runqueue wait */
	OFFCPU_SUBCLASS_IOWAIT          = 2, /* waiting for I/O */
	OFFCPU_SUBCLASS_INTERRUPTIBLE   = 3, /* voluntary sleep (interruptible) */
	OFFCPU_SUBCLASS_UNINTERRUPTIBLE = 4, /* uninterruptible sleep */
	OFFCPU_SUBCLASS_OTHER           = 5, /* STOPPED, TRACED, PARKED, etc. */
};

#define OFFCPU_SUBCLASS_MAX 5

/* Stored per-task in BPF_MAP_TYPE_TASK_STORAGE */
struct task_offcpu_data {
	u64 sched_out_ts;    /* bpf_ktime_get_ns() at schedule-out */
	s32 kern_stack_id;   /* kernel stack ID from bpf_get_stackid() */
	s32 user_stack_id;   /* user stack ID from bpf_get_stackid() */
	u8  subclass;        /* OFFCPU_SUBCLASS_* enum */
	u8  pad[7];
};

/* Emitted to BPF ring buffer for each off-CPU episode */
struct offcpu_event {
	u32 pid;             /* tgid (process ID) */
	u32 tid;             /* pid (thread ID, kernel nomenclature) */
	u64 sched_out_ts;    /* timestamp when task went off-CPU (ns) */
	u64 duration_ns;     /* total off-CPU duration (ns) */
	s32 kern_stack_id;   /* index into stack_traces map */
	s32 user_stack_id;   /* index into stack_traces map */
	u32 cpu;             /* CPU where the task was running before sched-out */
	u8  subclass;        /* OFFCPU_SUBCLASS_* enum */
	u8  pad[3];
};

/* Runtime configuration (written by userspace before attach) */
struct bperf_config {
	u32 target_tgid;     /* 0 = system-wide */
	u32 target_tid;      /* 0 = all threads in tgid */
	u64 min_duration_ns; /* ignore off-CPU episodes shorter than this */
};

/* Maximum stack depth for BPF stack trace map */
#define BPERF_MAX_STACK_DEPTH 127

/* Default stack trace map entries */
#define BPERF_STACK_MAP_ENTRIES 32768

/* Default ring buffer size (16 MB) */
#define BPERF_RINGBUF_SIZE (16 * 1024 * 1024)

#endif /* BPERF_COMMON_H */
