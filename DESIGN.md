# bperf: Unified On/Off-CPU Profiler — eBPF Design Document

## Table of Contents

1. [Introduction](#1-introduction)
2. [Background: Kernel bperf Changes](#2-background-kernel-bperf-changes)
3. [eBPF Replacement Architecture](#3-ebpf-replacement-architecture)
4. [BPF Program Specifications](#4-bpf-program-specifications)
5. [Userspace Tool Design](#5-userspace-tool-design)
6. [perf.data Output Format](#6-perfdata-output-format)
7. [Usage Examples](#7-usage-examples)
8. [Limitations and Trade-offs](#8-limitations-and-trade-offs)
9. [Future Work](#9-future-work)

---

## 1. Introduction

### 1.1 Problem Statement

Traditional Linux profilers force a choice between **on-CPU** and **off-CPU** analysis:

- `perf record -e task-clock` samples only while the task is running on a CPU. It
  reveals hot code paths but is blind to time spent sleeping, waiting on I/O, or
  contending for locks.
- Off-CPU profilers (e.g., `offcputime` from bcc/bpftrace) capture time spent
  blocked but miss on-CPU activity entirely.

Neither approach alone can answer the question: *"Where does my application spend
its wall-clock time?"* A database query that takes 500ms might spend 50ms on-CPU
parsing SQL and 450ms off-CPU waiting for disk I/O — a task-clock profile would
attribute 100% overhead to the parser, completely hiding the dominant bottleneck.

### 1.2 What bperf Does

**bperf** (OSDI'24, Yonsei University) solves this by introducing **blocked
samples** — a kernel extension that generates profiling samples for both on-CPU
and off-CPU time within a single unified event stream. Key innovations:

- A new software PMU event (`task-clock-plus`) that continues "ticking" while a
  task is off-CPU, generating virtual samples proportional to off-CPU duration.
- **Subclass annotations** that classify *why* a task was off-CPU (runqueue wait,
  I/O wait, interruptible sleep, uninterruptible sleep, etc.).
- All samples (on-CPU and off-CPU) appear in the same `perf.data` file with
  identical format, enabling standard `perf report` and flame graph workflows.

The original implementation requires **26 kernel patches** on Linux 6.17-rc4.

### 1.3 Goal of This Document

Design an eBPF-based reimplementation of bperf that achieves the same profiling
capability with:

- **No kernel source changes** — works on stock/unmodified kernels (6.1+)
- **No perf tool changes** — output is a standard `perf.data` file readable by
  unmodified `perf report`, `perf script`, and flame graph tools
- **A new userspace tool** (`bperf`) that orchestrates BPF programs, collects
  on-CPU samples via `perf_event_open(2)`, and writes the unified output

### 1.4 Minimum Requirements

| Requirement             | Version / Config                          |
|-------------------------|-------------------------------------------|
| Linux kernel            | 6.1+ (LTS) with BTF enabled              |
| `CONFIG_DEBUG_INFO_BTF` | `=y` (required for CO-RE and `tp_btf`)    |
| `CONFIG_BPF_SYSCALL`    | `=y`                                      |
| libbpf                  | 1.0+                                      |
| clang/llvm              | 14+ (for BPF CO-RE compilation)           |
| Frame pointers           | Recommended for user-space stack accuracy |

---

## 2. Background: Kernel bperf Changes

This section summarizes the 26 kernel commits in the `s3yonsei/linux-blocked_samples`
repository (based on Linux 6.17-rc4). Understanding these changes is essential to
designing the eBPF replacement — each kernel modification maps to an eBPF component.

### 2.1 New Software PMU: `task-clock-plus`

A new software event `PERF_COUNT_SW_TASK_CLOCK_PLUS` (ID 12) was added alongside
the existing `task-clock`. It is backed by a dedicated PMU structure
(`perf_task_clock_plus`) with its own `event_init`, `add`, `del`, `start`, `stop`,
and `read` callbacks, registered via `perf_pmu_register()` at boot.

**eBPF equivalent:** Not needed. We use the standard `task-clock` for on-CPU
samples and BPF programs for off-CPU samples.

### 2.2 Per-Task Off-CPU Storage

A new structure is added to each `task_struct`:

```c
struct perf_event_local_storage {
    u64 sched_out_timestamp;   // when the task was scheduled out
    u8  offcpu_subclass;       // WHY the task went off-CPU
    bool enabled;              // is task-clock-plus active for this task?
};
```

Allocated in `perf_event_init_task()`, freed in `perf_event_free_task()`.

**eBPF equivalent:** `BPF_MAP_TYPE_TASK_STORAGE` (per-task BPF local storage).

### 2.3 Off-CPU Subclass Classification

At schedule-out time, the kernel inspects `task->__state` and `task->in_iowait`
to classify the off-CPU reason:

| Subclass                           | Condition                                   |
|------------------------------------|---------------------------------------------|
| `PERF_EVENT_OFFCPU_SCHED` (0x1)   | `prev_state == TASK_RUNNING` (preempted)    |
| `PERF_EVENT_OFFCPU_IOWAIT` (0x2)  | `in_iowait` flag is set                     |
| `PERF_EVENT_OFFCPU_INTERRUPTIBLE` (0x4) | `TASK_INTERRUPTIBLE`                   |
| `PERF_EVENT_OFFCPU_UNINTERRUPTIBLE` (0x8) | `TASK_UNINTERRUPTIBLE`             |
| `PERF_EVENT_OFFCPU_ETC` (0x10)    | Everything else (STOPPED, TRACED, etc.)     |

**eBPF equivalent:** Read `prev_state` from the `sched_switch` tracepoint args
and `prev->in_iowait` via BTF/CO-RE.

### 2.4 Subclass Encoding in Sample Headers

Bits 3-5 of `perf_event_header::misc` encode the subclass:

```c
#define PERF_RECORD_MISC_OFFCPU_SCHED           (1 << 3)
#define PERF_RECORD_MISC_OFFCPU_IOWAIT          (2 << 3)
#define PERF_RECORD_MISC_OFFCPU_INTERRUPTIBLE    (3 << 3)
#define PERF_RECORD_MISC_OFFCPU_UNINTERRUPTIBLE  (4 << 3)
#define PERF_RECORD_MISC_OFFCPU_ETC             (5 << 3)
```

**eBPF equivalent:** We cannot write custom misc bits (that would require kernel
changes). Instead, we use **separate event attributes** — one per off-CPU
subclass — so `perf report` naturally groups and labels them.

### 2.5 Off-CPU Sample Injection

The core algorithm runs at schedule-in time (`task_clock_plus_event_add`):

```
delta = now - sched_out_timestamp
iteration = (period + delta - period_left) / period
```

If `PERF_SAMPLE_WEIGHT` is requested, the kernel emits **one** sample with
`weight = iteration - 1` (compressing N identical samples). Otherwise it loops
and emits individual samples.

**eBPF equivalent:** Computed in the BPF program at `sched_switch` (for the
incoming task). We emit one off-CPU event per blocking episode with
`period = delta`, which gives correct time accounting in `perf report`.

### 2.6 Stack Capture

The kernel uses `task_pt_regs(current)` / `current_pt_regs()` to capture both
kernel and user call chains. These regs point to the syscall entry frame, giving
the user stack that was active when the task entered the kernel (i.e., when it
decided to sleep).

**eBPF equivalent:** `bpf_get_stackid(ctx, &stack_map, 0)` for kernel stack and
`bpf_get_stackid(ctx, &stack_map, BPF_F_USER_STACK)` for user stack, called at
`sched_switch` time when `prev` is still the current task. This captures the
same stack — the user code path that led to the blocking syscall.

### 2.7 Summary of Kernel Changes → eBPF Mapping

| Kernel Change                        | eBPF Replacement                              |
|--------------------------------------|-----------------------------------------------|
| `task-clock-plus` PMU                | Standard `task-clock` + BPF off-CPU logic     |
| `perf_event_local_storage` in task   | `BPF_MAP_TYPE_TASK_STORAGE`                   |
| Subclass classification at sched-out | BPF reads `prev_state` + `in_iowait` at `sched_switch` |
| `misc` bits encoding                 | Separate perf.data event attrs per subclass   |
| Sample injection at sched-in         | BPF emits event via ring buffer at `sched_switch` |
| Stack capture via `task_pt_regs`     | `bpf_get_stackid()` at sched-out time         |
| `try_to_wake_up` hook               | `tp_btf/sched_wakeup` (optional, for future)  |
| Context switch interference guard    | Not needed (BPF is non-invasive)              |

---

## 3. eBPF Replacement Architecture

### 3.1 High-Level Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Kernel Space                                │
│                                                                     │
│  ┌──────────────────────────────────────┐                           │
│  │     tp_btf/sched_switch              │                           │
│  │                                      │                           │
│  │  prev being switched out:            │                           │
│  │    1. Capture kernel stack ID        │     ┌───────────────────┐ │
│  │    2. Capture user stack ID          │────▶│  STACK_TRACE map  │ │
│  │    3. Record timestamp + subclass    │     └───────────────────┘ │
│  │       into TASK_STORAGE              │                           │
│  │                                      │     ┌───────────────────┐ │
│  │  next being switched in:             │────▶│  TASK_STORAGE map │ │
│  │    1. Read stored timestamp          │     └───────────────────┘ │
│  │    2. Compute delta                  │                           │
│  │    3. Emit offcpu_event to ringbuf   │     ┌───────────────────┐ │
│  │                                      │────▶│  BPF RING_BUF     │ │
│  └──────────────────────────────────────┘     └────────┬──────────┘ │
│                                                        │            │
│  ┌──────────────────────────────────────┐              │            │
│  │  perf_event (task-clock)             │              │            │
│  │  ┌─────────────────────────────────┐ │              │            │
│  │  │   perf mmap ring buffer         │ │              │            │
│  │  │   (on-CPU PERF_RECORD_SAMPLE)   │ │              │            │
│  │  └──────────────┬──────────────────┘ │              │            │
│  └─────────────────┼───────────────────-┘              │            │
│                    │                                   │            │
└────────────────────┼───────────────────────────────────┼────────────┘
                     │                                   │
┌────────────────────┼───────────────────────────────────┼────────────┐
│                    ▼         User Space                 ▼            │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │                     bperf record                                ││
│  │                                                                 ││
│  │  1. Load & attach BPF programs                                  ││
│  │  2. Open perf_event_open(task-clock), mmap ring buffer          ││
│  │  3. Poll both ring buffers                                      ││
│  │  4. Merge on-CPU + off-CPU events by timestamp                  ││
│  │  5. Read /proc/<pid>/maps for MMAP2 records                     ││
│  │  6. Dump STACK_TRACE map for callchain resolution               ││
│  │  7. Write unified perf.data                                     ││
│  └──────────────────────────┬──────────────────────────────────────┘│
│                             │                                       │
│                             ▼                                       │
│                     ┌──────────────┐                                │
│                     │  perf.data   │                                │
│                     └──────┬───────┘                                │
│                            │                                        │
│               ┌────────────┼────────────┐                           │
│               ▼            ▼            ▼                           │
│         perf report   perf script   FlameGraph                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.2 Data Flow

1. **On-CPU path**: The kernel's perf subsystem samples `task-clock` at a
   configured frequency (e.g., 99 Hz). Samples — complete with IP, callchain,
   PID/TID, timestamp — land in a per-CPU perf mmap ring buffer. The userspace
   tool reads these directly.

2. **Off-CPU path**: A BPF program attached to `tp_btf/sched_switch` fires on
   every context switch. For the outgoing task (`prev`), it captures the kernel
   and user stack IDs and records the timestamp + off-CPU subclass into per-task
   BPF storage. For the incoming task (`next`), it looks up the stored state,
   computes off-CPU duration, and emits a structured event to a BPF ring buffer.

3. **Merge**: The userspace tool polls both ring buffers, collects all events in
   memory, sorts by timestamp, resolves stack IDs to IP arrays, and writes a
   unified `perf.data` file.

### 3.3 BPF Maps

| Map Name         | Type                        | Key             | Value                     | Purpose                                  |
|------------------|-----------------------------|-----------------|---------------------------|------------------------------------------|
| `task_storage`   | `BPF_MAP_TYPE_TASK_STORAGE` | (implicit task) | `struct task_offcpu_data`  | Per-task sched-out timestamp, subclass, stacks |
| `stack_traces`   | `BPF_MAP_TYPE_STACK_TRACE`  | `u32` stack ID  | `u64[PERF_MAX_STACK_DEPTH]`| Deduplicated stack traces                |
| `events`         | `BPF_MAP_TYPE_RINGBUF`      | —               | `struct offcpu_event`      | Off-CPU events sent to userspace         |
| `config`         | `BPF_MAP_TYPE_ARRAY`        | `u32` index     | `struct bperf_config`      | Runtime configuration from userspace     |

### 3.4 Filtering Strategy

The BPF program must efficiently filter which tasks to profile. Supported modes:

| Mode             | Mechanism                                           |
|------------------|-----------------------------------------------------|
| Single process   | Compare `prev->tgid` / `next->tgid` against target PID in `config` map |
| System-wide      | Profile all tasks (no filter, or exclude kernel threads via `tgid == 0` check) |
| Cgroup           | Use `bpf_current_task_under_cgroup()` helper or compare cgroup ID |
| Thread list      | Hash map of target TIDs                             |

---

## 4. BPF Program Specifications

### 4.1 Data Structures

```c
/* Stored per-task in BPF_MAP_TYPE_TASK_STORAGE */
struct task_offcpu_data {
    u64 sched_out_ts;       /* bpf_ktime_get_ns() at schedule-out */
    s32 kern_stack_id;      /* kernel stack ID from bpf_get_stackid() */
    s32 user_stack_id;      /* user stack ID from bpf_get_stackid() */
    u8  subclass;           /* OFFCPU_SUBCLASS_* enum */
    u8  pad[7];
};

/* Emitted to BPF ring buffer for each off-CPU episode */
struct offcpu_event {
    u32 pid;                /* tgid (process ID) */
    u32 tid;                /* pid (thread ID, kernel nomenclature) */
    u64 sched_out_ts;       /* timestamp when task went off-CPU (ns) */
    u64 duration_ns;        /* total off-CPU duration (ns) */
    s32 kern_stack_id;      /* index into stack_traces map */
    s32 user_stack_id;      /* index into stack_traces map */
    u32 cpu;                /* CPU where the task was running */
    u8  subclass;           /* OFFCPU_SUBCLASS_* enum */
    u8  pad[3];
};

/* Off-CPU subclass classification */
enum offcpu_subclass {
    OFFCPU_SUBCLASS_SCHED           = 1,  /* preempted / runqueue wait */
    OFFCPU_SUBCLASS_IOWAIT          = 2,  /* waiting for I/O */
    OFFCPU_SUBCLASS_INTERRUPTIBLE   = 3,  /* voluntary sleep (interruptible) */
    OFFCPU_SUBCLASS_UNINTERRUPTIBLE = 4,  /* uninterruptible sleep */
    OFFCPU_SUBCLASS_OTHER           = 5,  /* STOPPED, TRACED, PARKED, etc. */
};

/* Runtime configuration (written by userspace before attach) */
struct bperf_config {
    u32 target_tgid;        /* 0 = system-wide */
    u64 min_duration_ns;    /* ignore off-CPU episodes shorter than this */
};
```

### 4.2 Map Declarations

```c
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct task_offcpu_data);
} task_storage SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(u32));
    __uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
    __uint(max_entries, 16384);
} stack_traces SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024); /* 16 MB */
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct bperf_config);
} config SEC(".maps");
```

### 4.3 Subclass Classification Function

```c
static __always_inline u8 classify_offcpu(unsigned int prev_state,
                                          struct task_struct *prev)
{
    /*
     * prev_state encoding in sched_switch tracepoint:
     *   0 (R)  = TASK_RUNNING — task was preempted
     *   1 (S)  = TASK_INTERRUPTIBLE
     *   2 (D)  = TASK_UNINTERRUPTIBLE
     *   4 (T)  = __TASK_STOPPED
     *   8 (t)  = __TASK_TRACED
     *   etc.
     *
     * The high bit (TASK_REPORT_MAX) indicates preemption when state
     * was TASK_RUNNING. We mask it out.
     */
    unsigned int state = prev_state & 0xFF; /* mask off TASK_REPORT_MAX */

    if (state == 0 /* TASK_RUNNING */)
        return OFFCPU_SUBCLASS_SCHED;

    /* Check in_iowait before general UNINTERRUPTIBLE */
    bool iowait;
    bpf_probe_read_kernel(&iowait, sizeof(iowait), &prev->in_iowait);
    if (iowait)
        return OFFCPU_SUBCLASS_IOWAIT;

    if (state & 0x01 /* TASK_INTERRUPTIBLE */)
        return OFFCPU_SUBCLASS_INTERRUPTIBLE;

    if (state & 0x02 /* TASK_UNINTERRUPTIBLE */)
        return OFFCPU_SUBCLASS_UNINTERRUPTIBLE;

    return OFFCPU_SUBCLASS_OTHER;
}
```

> **Note on `in_iowait`:** With BTF/CO-RE, the field offset of `task_struct->in_iowait`
> is resolved at load time. No hardcoded offsets. Using `BPF_CORE_READ()` or
> `bpf_probe_read_kernel()` is required since `prev` is a trusted pointer from the
> tracepoint but field access beyond the first level needs explicit reads.

### 4.4 Main BPF Program: `sched_switch` Handler

```c
SEC("tp_btf/sched_switch")
int BPF_PROG(handle_sched_switch,
             bool preempt,
             struct task_struct *prev,
             struct task_struct *next,
             unsigned int prev_state)
{
    u32 zero = 0;
    struct bperf_config *cfg = bpf_map_lookup_elem(&config, &zero);
    if (!cfg)
        return 0;

    u32 prev_tgid = BPF_CORE_READ(prev, tgid);
    u32 next_tgid = BPF_CORE_READ(next, tgid);
    u32 target = cfg->target_tgid;

    /* ================================================================
     * Phase 1: SCHED-OUT — Record state for the outgoing task (prev)
     * ================================================================ */
    if (target == 0 || prev_tgid == target) {
        /* Skip kernel threads (tgid == 0) in system-wide mode */
        if (prev_tgid == 0)
            goto phase2;

        struct task_offcpu_data *data = bpf_task_storage_get(
            &task_storage, prev, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
        if (!data)
            goto phase2;

        data->sched_out_ts = bpf_ktime_get_ns();
        data->subclass = classify_offcpu(prev_state, prev);

        /*
         * Capture stacks NOW while prev is still current.
         * At this point, prev's page tables are still active, so
         * BPF_F_USER_STACK will correctly walk the user stack.
         */
        data->kern_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
        data->user_stack_id = bpf_get_stackid(ctx, &stack_traces,
                                               BPF_F_USER_STACK);
    }

phase2:
    /* ================================================================
     * Phase 2: SCHED-IN — Emit off-CPU event for the incoming task (next)
     * ================================================================ */
    if (target == 0 || next_tgid == target) {
        if (next_tgid == 0)
            return 0;

        struct task_offcpu_data *data = bpf_task_storage_get(
            &task_storage, (struct task_struct *)next, NULL, 0);
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

        bpf_ringbuf_submit(evt, 0);

        /* Reset so we don't double-count */
        data->sched_out_ts = 0;
    }

    return 0;
}
```

### 4.5 Verifier Considerations

| Concern                    | Mitigation                                                  |
|----------------------------|-------------------------------------------------------------|
| Loop bounds                | No loops in the BPF program (single event per sched_switch) |
| Stack size (512 bytes max) | All variables fit; `offcpu_event` is reserved from ringbuf, not on stack |
| Map access patterns        | All map lookups check for NULL returns                      |
| `bpf_get_stackid` failure  | Returns negative value; stored as-is, handled in userspace  |
| `tp_btf` arg trust         | `prev` and `next` are trusted pointers from the tracepoint  |

### 4.6 Program Attachment

```c
/* In userspace loader */
struct bpf_link *link = bpf_program__attach(skel->progs.handle_sched_switch);
```

The `tp_btf/sched_switch` attachment is automatic via libbpf skeleton when the
program section name is `SEC("tp_btf/sched_switch")`. No explicit tracepoint
perf event fd is needed.

---

## 5. Userspace Tool Design

### 5.1 CLI Interface

```
bperf — Unified on/off-CPU profiler using eBPF

USAGE:
    bperf record [OPTIONS] [-- command [args...]]
    bperf report [OPTIONS]
    bperf script [OPTIONS]

SUBCOMMANDS:
    record    Collect on-CPU and off-CPU profiling data
    report    Display profiling results (wraps perf report)
    script    Dump raw events (wraps perf script)

RECORD OPTIONS:
    -p, --pid <PID>         Profile a specific process (and all its threads)
    -a, --all-cpus          System-wide profiling (default if no -p or command)
    -F, --freq <HZ>         On-CPU sampling frequency [default: 99]
    -g, --call-graph         Record call graphs (always enabled, this is default)
    --no-kernel              Exclude kernel call chains
    --min-block <USEC>      Minimum off-CPU duration to record [default: 1]
    -d, --duration <SEC>    Recording duration in seconds [default: until Ctrl-C]
    -o, --output <FILE>     Output file [default: bperf.data]
    --stack-depth <N>       Maximum stack depth [default: 127]
    --ringbuf-size <MB>     BPF ring buffer size [default: 16]

REPORT OPTIONS:
    -i, --input <FILE>      Input file [default: bperf.data]
    --stdio                 Text mode (passed to perf report)
    --tui                   TUI mode (passed to perf report)
    Additional flags are forwarded to perf report.

SCRIPT OPTIONS:
    -i, --input <FILE>      Input file [default: bperf.data]
    Additional flags are forwarded to perf script.
```

### 5.2 Source File Organization

```
bperf/
├── DESIGN.md               # This document
├── Makefile                 # Build system
├── src/
│   ├── bperf.c             # CLI entry point, argument parsing
│   ├── record.c            # bperf record implementation
│   ├── record.h
│   ├── oncpu.c             # On-CPU: perf_event_open, mmap, sample reading
│   ├── oncpu.h
│   ├── offcpu.c            # Off-CPU: BPF loader, ringbuf reader
│   ├── offcpu.h
│   ├── writer.c            # perf.data file writer
│   ├── writer.h
│   ├── proc.c              # /proc parser (maps, comm, tasks)
│   ├── proc.h
│   └── bperf.bpf.c         # BPF program (compiled to .bpf.o)
├── include/
│   ├── bperf_common.h      # Shared structs between BPF and userspace
│   └── perf_file.h         # perf.data format definitions
└── vmlinux.h               # Generated: BTF header for CO-RE
```

### 5.3 `bperf record` Workflow

```
bperf record -p 1234 -F 99 -d 10 -o bperf.data

Phase 1: Setup
  ├─ Parse CLI arguments
  ├─ Load BPF skeleton (bperf.bpf.o)
  ├─ Write config to BPF config map (target_tgid=1234, min_duration_ns=1000)
  ├─ Attach BPF program to tp_btf/sched_switch
  ├─ Open perf_event_open(PERF_COUNT_SW_TASK_CLOCK, pid=1234, freq=99)
  │   ├─ Set sample_type (see §6.2)
  │   ├─ mmap() the perf ring buffer (per-CPU)
  │   └─ ioctl(PERF_EVENT_IOC_ID) → on_cpu_event_id
  ├─ Read /proc/1234/comm → store COMM record
  ├─ Read /proc/1234/maps → store MMAP2 records
  ├─ Enumerate /proc/1234/task/* for thread COMM records
  └─ If command mode: fork(), setup, execvp()

Phase 2: Collection (main loop, runs for --duration or until Ctrl-C)
  ├─ epoll_wait() on:
  │   ├─ perf mmap fds (on-CPU samples)
  │   └─ BPF ring buffer fd (off-CPU events)
  ├─ On perf mmap readable:
  │   ├─ Read PERF_RECORD_SAMPLE records
  │   ├─ Read PERF_RECORD_MMAP2 records (new mappings)
  │   ├─ Read PERF_RECORD_COMM records (exec)
  │   └─ Buffer into on_cpu_events[]
  ├─ On BPF ringbuf readable:
  │   ├─ ring_buffer__poll() → callback per offcpu_event
  │   └─ Buffer into off_cpu_events[]
  └─ Periodically check duration / signal

Phase 3: Finalize
  ├─ Detach BPF programs
  ├─ Drain remaining events from both ring buffers
  ├─ Dump stack_traces BPF map → stack_map[stack_id] = u64 ips[]
  ├─ Sort all events by timestamp
  └─ Call writer to produce perf.data (see §5.5)
```

### 5.4 On-CPU Sample Collection (`oncpu.c`)

The on-CPU path uses the kernel's perf subsystem directly via syscalls:

```c
/* Open perf event for task-clock sampling */
struct perf_event_attr attr = {
    .type           = PERF_TYPE_SOFTWARE,
    .size           = sizeof(attr),
    .config         = PERF_COUNT_SW_TASK_CLOCK,
    .sample_type    = BPERF_SAMPLE_TYPE,  /* see §6.2 */
    .sample_freq    = freq,
    .freq           = 1,
    .sample_id_all  = 1,
    .comm           = 1,
    .mmap           = 1,
    .mmap2          = 1,
    .task           = 1,                  /* FORK/EXIT records */
    .exclude_kernel = exclude_kernel,
    .sample_max_stack = max_stack_depth,
};

/* Per-process mode: one fd, target pid */
int fd = perf_event_open(&attr, pid, -1 /* any CPU */, -1, 0);

/* System-wide mode: one fd per CPU, pid=-1 */
for (int cpu = 0; cpu < nr_cpus; cpu++)
    fds[cpu] = perf_event_open(&attr, -1, cpu, -1, 0);

/* mmap each fd to get the ring buffer */
void *base = mmap(NULL, (1 + 2^n) * page_size,
                  PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
struct perf_event_mmap_page *header = base;
void *data = base + page_size;
```

Reading samples from the mmap ring buffer:

```c
/* Adapted from perf's mmap_read_event() */
u64 head = __atomic_load_n(&header->data_head, __ATOMIC_ACQUIRE);
u64 tail = header->data_tail;

while (tail < head) {
    struct perf_event_header *ehdr = data + (tail % data_size);

    /* Copy event (may wrap around ring buffer) */
    copy_event(ehdr, buf, data, data_size, tail);

    switch (ehdr->type) {
    case PERF_RECORD_SAMPLE:
        buffer_oncpu_sample(buf, ehdr->size);
        break;
    case PERF_RECORD_MMAP2:
        buffer_mmap2_record(buf, ehdr->size);
        break;
    case PERF_RECORD_COMM:
        buffer_comm_record(buf, ehdr->size);
        break;
    case PERF_RECORD_FORK:
    case PERF_RECORD_EXIT:
        buffer_task_record(buf, ehdr->size);
        break;
    }

    tail += ehdr->size;
}

__atomic_store_n(&header->data_tail, tail, __ATOMIC_RELEASE);
```

On-CPU PERF_RECORD_SAMPLE records are already in the correct binary format for
perf.data. We can write them directly to the output file with only one
modification: ensuring the `PERF_SAMPLE_IDENTIFIER` value matches our attr.
Since we're using the kernel-assigned event ID (obtained via `PERF_EVENT_IOC_ID`),
the samples already have the correct ID — no modification needed.

### 5.5 Off-CPU Event Collection (`offcpu.c`)

```c
/* Create ring buffer manager */
struct ring_buffer *rb = ring_buffer__new(
    bpf_map__fd(skel->maps.events),
    handle_offcpu_event,    /* callback */
    ctx,                    /* user context */
    NULL                    /* opts */
);

/* Callback for each off-CPU event */
static int handle_offcpu_event(void *ctx, void *data, size_t size)
{
    struct offcpu_event *evt = data;
    struct collection_ctx *cctx = ctx;

    /* Store in dynamic array for later sorting and writing */
    offcpu_event_buf_append(&cctx->offcpu_events, evt);
    return 0;
}

/* In main loop */
ring_buffer__poll(rb, timeout_ms);
```

### 5.6 perf.data Writer (`writer.c`)

The writer converts buffered on-CPU samples and off-CPU events into a valid
`perf.data` file. The full format specification is in §6.

```c
struct perf_data_writer {
    int fd;                         /* output file descriptor */
    u64 data_offset;                /* start of data section */
    u64 data_size;                  /* bytes written to data section */

    /* Event attributes (6 total: 1 on-CPU + 5 off-CPU subclasses) */
    struct perf_event_attr attrs[6];
    u64 event_ids[6];               /* unique IDs for each attr */

    /* Resolved stack traces from BPF map */
    struct {
        int id;
        int nr_ips;
        u64 ips[PERF_MAX_STACK_DEPTH];
    } *stacks;
    int nr_stacks;
};

/* Writing sequence */
int write_perf_data(struct perf_data_writer *w,
                    struct oncpu_sample *oncpu, int nr_oncpu,
                    struct offcpu_event *offcpu, int nr_offcpu,
                    struct mmap2_record *mmaps, int nr_mmaps,
                    struct comm_record *comms, int nr_comms)
{
    /* 1. Write placeholder header (patched at the end) */
    write_placeholder_header(w);

    /* 2. Write attrs section */
    write_attrs_section(w);

    /* 3. Write ID arrays */
    write_id_arrays(w);

    /* 4. Mark start of data section */
    w->data_offset = lseek(w->fd, 0, SEEK_CUR);

    /* 5. Write COMM records */
    for (int i = 0; i < nr_comms; i++)
        write_comm_record(w, &comms[i]);

    /* 6. Write MMAP2 records */
    for (int i = 0; i < nr_mmaps; i++)
        write_mmap2_record(w, &mmaps[i]);

    /* 7. Merge-sort on-CPU and off-CPU events by timestamp, write SAMPLE records */
    write_merged_samples(w, oncpu, nr_oncpu, offcpu, nr_offcpu);

    /* 8. Record data section size */
    w->data_size = lseek(w->fd, 0, SEEK_CUR) - w->data_offset;

    /* 9. Write feature sections (EVENT_DESC, CMDLINE, SAMPLE_TIME, etc.) */
    write_feature_sections(w);

    /* 10. Seek back and patch header with correct offsets */
    patch_header(w);

    return 0;
}
```

#### Converting Off-CPU Events to PERF_RECORD_SAMPLE

Each `offcpu_event` from the BPF ring buffer is converted to a
`PERF_RECORD_SAMPLE`:

```c
static void write_offcpu_sample(struct perf_data_writer *w,
                                struct offcpu_event *evt)
{
    /* Select the event ID based on subclass */
    u64 event_id;
    switch (evt->subclass) {
    case OFFCPU_SUBCLASS_SCHED:           event_id = w->event_ids[1]; break;
    case OFFCPU_SUBCLASS_IOWAIT:          event_id = w->event_ids[2]; break;
    case OFFCPU_SUBCLASS_INTERRUPTIBLE:   event_id = w->event_ids[3]; break;
    case OFFCPU_SUBCLASS_UNINTERRUPTIBLE: event_id = w->event_ids[4]; break;
    default:                              event_id = w->event_ids[5]; break;
    }

    /* Resolve stack IDs to IP arrays */
    int kern_nr = 0, user_nr = 0;
    u64 *kern_ips = resolve_stack(w, evt->kern_stack_id, &kern_nr);
    u64 *user_ips = resolve_stack(w, evt->user_stack_id, &user_nr);

    /* Build callchain: CONTEXT_KERNEL, kern_ips..., CONTEXT_USER, user_ips... */
    u64 callchain[2 + kern_nr + user_nr]; /* context markers + IPs */
    int cc_nr = 0;
    if (kern_nr > 0) {
        callchain[cc_nr++] = PERF_CONTEXT_KERNEL; /* 0xFFFFFFFFFFFFFF80 */
        for (int i = 0; i < kern_nr; i++)
            callchain[cc_nr++] = kern_ips[i];
    }
    if (user_nr > 0) {
        callchain[cc_nr++] = PERF_CONTEXT_USER;   /* 0xFFFFFFFFFFFFFE00 */
        for (int i = 0; i < user_nr; i++)
            callchain[cc_nr++] = user_ips[i];
    }

    /* Determine the IP (top of the most relevant stack) */
    u64 ip;
    u16 misc;
    if (user_nr > 0) {
        ip = user_ips[0];
        misc = PERF_RECORD_MISC_USER;       /* 2 */
    } else if (kern_nr > 0) {
        ip = kern_ips[0];
        misc = PERF_RECORD_MISC_KERNEL;     /* 1 */
    } else {
        ip = 0;
        misc = 0;
    }

    /* Calculate record size */
    u16 size = 8                    /* header */
             + 8                    /* PERF_SAMPLE_IDENTIFIER */
             + 8                    /* PERF_SAMPLE_IP */
             + 8                    /* PERF_SAMPLE_TID (pid + tid) */
             + 8                    /* PERF_SAMPLE_TIME */
             + 8                    /* PERF_SAMPLE_CPU (cpu + res) */
             + 8                    /* PERF_SAMPLE_PERIOD */
             + 8 + cc_nr * 8       /* PERF_SAMPLE_CALLCHAIN (nr + ips) */
             + 8;                   /* PERF_SAMPLE_WEIGHT */

    /* Ensure 8-byte alignment */
    size = (size + 7) & ~7;

    /* Write the record */
    struct perf_event_header hdr = {
        .type = PERF_RECORD_SAMPLE,
        .misc = misc,
        .size = size,
    };
    write_bytes(w, &hdr, sizeof(hdr));
    write_u64(w, event_id);                             /* identifier */
    write_u64(w, ip);                                   /* ip */
    write_u32(w, evt->pid); write_u32(w, evt->tid);    /* pid, tid */
    write_u64(w, evt->sched_out_ts);                    /* time */
    write_u32(w, evt->cpu); write_u32(w, 0);            /* cpu, res */
    write_u64(w, evt->duration_ns);                     /* period = off-CPU time */
    write_u64(w, cc_nr);                                /* callchain nr */
    write_bytes(w, callchain, cc_nr * 8);               /* callchain ips */
    write_u64(w, evt->duration_ns);                     /* weight = duration */
}
```

> **Design decision — `period = duration_ns`:** By setting the period of each
> off-CPU sample to the off-CPU duration (in nanoseconds), `perf report`'s
> overhead calculation correctly accounts for off-CPU time. The on-CPU task-clock
> samples also have period in nanoseconds. This means the total overhead reported
> by `perf report` represents **wall-clock time** — the sum of on-CPU and off-CPU
> time. This is precisely the unified view that bperf provides.

---

## 6. perf.data Output Format

### 6.1 File Layout

```
Offset 0x00:                 perf_file_header        (104 bytes)
Offset 0x68:                 attrs section start
                             ├─ attr[0] + ids_section  (on-CPU: task-clock)
                             ├─ attr[1] + ids_section  (offcpu-sched)
                             ├─ attr[2] + ids_section  (offcpu-iowait)
                             ├─ attr[3] + ids_section  (offcpu-interruptible)
                             ├─ attr[4] + ids_section  (offcpu-uninterruptible)
                             └─ attr[5] + ids_section  (offcpu-other)
Offset A:                    ID arrays (6 × u64)
Offset B:                    data section start
                             ├─ PERF_RECORD_COMM records
                             ├─ PERF_RECORD_MMAP2 records
                             └─ PERF_RECORD_SAMPLE records (merged, time-sorted)
Offset C:                    feature section headers
Offset D:                    feature data
                             ├─ HEADER_EVENT_DESC
                             ├─ HEADER_CMDLINE
                             └─ HEADER_SAMPLE_TIME
```

### 6.2 Sample Type

All six event attributes share the same `sample_type`:

```c
#define BPERF_SAMPLE_TYPE ( \
    PERF_SAMPLE_IDENTIFIER |    /* 0x010000 — event ID (first field) */ \
    PERF_SAMPLE_IP |            /* 0x000001 — instruction pointer    */ \
    PERF_SAMPLE_TID |           /* 0x000002 — pid + tid              */ \
    PERF_SAMPLE_TIME |          /* 0x000004 — timestamp              */ \
    PERF_SAMPLE_CPU |           /* 0x000080 — CPU number             */ \
    PERF_SAMPLE_PERIOD |        /* 0x000100 — sampling period        */ \
    PERF_SAMPLE_CALLCHAIN |     /* 0x000020 — call stack             */ \
    PERF_SAMPLE_WEIGHT          /* 0x004000 — sample weight          */ \
)
/* = 0x0141A7 */
```

Resulting PERF_RECORD_SAMPLE binary layout (fields appear in this order):

```
struct perf_event_header    header;         /*  8 bytes */
u64                         identifier;     /*  8 bytes — PERF_SAMPLE_IDENTIFIER */
u64                         ip;             /*  8 bytes — PERF_SAMPLE_IP */
u32                         pid, tid;       /*  8 bytes — PERF_SAMPLE_TID */
u64                         time;           /*  8 bytes — PERF_SAMPLE_TIME */
u32                         cpu, res;       /*  8 bytes — PERF_SAMPLE_CPU */
u64                         period;         /*  8 bytes — PERF_SAMPLE_PERIOD */
u64                         nr;             /*  8 bytes — PERF_SAMPLE_CALLCHAIN */
u64                         ips[nr];        /*  8*nr    — callchain IPs */
u64                         weight;         /*  8 bytes — PERF_SAMPLE_WEIGHT */
```

Total: `72 + 8*nr` bytes per sample (before 8-byte alignment padding).

### 6.3 Event Attributes

Six `perf_event_attr` entries, differentiated by their event IDs and described
by the `HEADER_EVENT_DESC` feature section:

| Index | Event Name               | Event ID | config            | Purpose              |
|-------|--------------------------|----------|-------------------|----------------------|
| 0     | `task-clock`             | (kernel) | `SW_TASK_CLOCK`   | On-CPU samples       |
| 1     | `offcpu-sched`           | 1001     | `SW_TASK_CLOCK`*  | Off-CPU: runqueue    |
| 2     | `offcpu-iowait`          | 1002     | `SW_TASK_CLOCK`*  | Off-CPU: I/O wait    |
| 3     | `offcpu-interruptible`   | 1003     | `SW_TASK_CLOCK`*  | Off-CPU: voluntary   |
| 4     | `offcpu-uninterruptible` | 1004     | `SW_TASK_CLOCK`*  | Off-CPU: involuntary |
| 5     | `offcpu-other`           | 1005     | `SW_TASK_CLOCK`*  | Off-CPU: misc        |

> \* Off-CPU attrs reuse `type=PERF_TYPE_SOFTWARE, config=PERF_COUNT_SW_TASK_CLOCK`
> since the underlying event type doesn't matter for a synthetic file — only the
> event name (from `HEADER_EVENT_DESC`) and the event ID matter for `perf report`.

The on-CPU attr (index 0) is a copy of the attr used in the actual
`perf_event_open()` call, with the kernel-assigned event ID. The off-CPU attrs
(indices 1-5) are synthetic copies with the same `sample_type` but their own
unique IDs (1001-1005).

### 6.4 File Header

```c
struct perf_file_header header = {
    .magic      = 0x32454C4946524550ULL,  /* "PERFILE2" */
    .size       = 104,
    .attr_size  = sizeof(struct perf_event_attr) + 16, /* attr + ids section */
    .attrs      = { .offset = attrs_offset, .size = 6 * attr_size },
    .data       = { .offset = data_offset,  .size = data_size },
    .event_types = { 0, 0 },              /* legacy, unused */
};
/* Set feature bits for EVENT_DESC, CMDLINE, SAMPLE_TIME */
header.adds_features[0] |= (1 << HEADER_EVENT_DESC);
header.adds_features[0] |= (1 << HEADER_CMDLINE);
header.adds_features[0] |= (1 << HEADER_SAMPLE_TIME);
```

### 6.5 HEADER_EVENT_DESC Feature

This feature maps attr indices to human-readable event names. It enables
`perf report` to display meaningful event names instead of raw `type:config`:

```
Format:
    u32 nr_events;                          /* 6 */
    for each event:
        struct perf_event_attr attr;        /* copy of the attr */
        u32 nr_ids;                         /* number of IDs for this attr */
        u64 ids[nr_ids];                    /* the event IDs */
        u32 event_string_len;              /* including NUL */
        char event_string[event_string_len]; /* e.g., "offcpu-sched" */
```

### 6.6 Non-SAMPLE Records

All non-SAMPLE records (COMM, MMAP2, FORK, EXIT) include a `sample_id` trailer
because `sample_id_all = 1`. The trailer fields match the `sample_type` bits
(excluding CALLCHAIN, WEIGHT, and other sample-only fields):

```
sample_id trailer for our sample_type:
    u32 pid, tid;       /* PERF_SAMPLE_TID */
    u64 time;           /* PERF_SAMPLE_TIME */
    u32 cpu, res;       /* PERF_SAMPLE_CPU */
    u64 id;             /* PERF_SAMPLE_IDENTIFIER */
```

Total trailer: 32 bytes.

### 6.7 MMAP2 Records

Synthesized from `/proc/<pid>/maps`:

```
/proc/<pid>/maps line:
  55a234000000-55a234020000 r-xp 00000000 08:01 1234567  /usr/bin/myapp

Becomes:
  PERF_RECORD_MMAP2 {
      .header.type = 10,
      .header.misc = PERF_RECORD_MISC_USER (2),
      .pid = <pid>, .tid = <tid>,
      .addr = 0x55a234000000,
      .len  = 0x20000,
      .pgoff = 0,
      .maj = 8, .min = 1,
      .ino = 1234567, .ino_generation = 0,
      .prot = 5 (PROT_READ|PROT_EXEC),
      .flags = 2 (MAP_PRIVATE),
      .filename = "/usr/bin/myapp",
      + sample_id trailer
  }
```

For the kernel (`[kernel.kallsyms]`), we emit a MMAP record with
`misc = PERF_RECORD_MISC_KERNEL`. The address range can be obtained from
`/proc/kallsyms` (first and last symbol addresses) or set to a conventional
range.

---

## 7. Usage Examples

### 7.1 Profile a Single Process

```bash
# Record for 30 seconds at 99 Hz
$ bperf record -p 12345 -F 99 -d 30 -o bperf.data

bperf: profiling PID 12345 at 99 Hz for 30s...
bperf: on-CPU samples: 2847
bperf: off-CPU events: 1523
bperf:   offcpu-sched: 312
bperf:   offcpu-iowait: 891
bperf:   offcpu-interruptible: 287
bperf:   offcpu-uninterruptible: 33
bperf: output written to bperf.data (4.2 MB)

# View results with standard perf report
$ perf report -i bperf.data --stdio

# Overhead  Event                    Command  Shared Object       Symbol
# ........  .......................  .......  ..................  ...................
#
    18.23%  task-clock               myapp    myapp               [.] compute_hash
    15.67%  offcpu-iowait            myapp    libc.so.6           [.] __pread64
    12.41%  offcpu-interruptible     myapp    myapp               [.] wait_for_lock
     9.88%  task-clock               myapp    myapp               [.] parse_request
     8.34%  offcpu-sched             myapp    myapp               [.] process_batch
     ...

# View results per-event
$ perf report -i bperf.data --stdio --event offcpu-iowait
```

### 7.2 Profile a Command from Launch

```bash
# Profile a command, recording both on-CPU and off-CPU
$ bperf record -- ./my_server --config server.conf

# Press Ctrl-C to stop
^C
bperf: output written to bperf.data

# Generate a flame graph (all events combined = wall-clock profile)
$ perf script -i bperf.data | stackcollapse-perf.pl | flamegraph.pl > wall.svg
```

### 7.3 System-Wide Profiling

```bash
# System-wide profiling for 60 seconds
$ sudo bperf record -a -d 60 -o system.data

# View top off-CPU waiters across the system
$ perf report -i system.data --event offcpu-iowait --stdio --sort comm,dso,sym
```

### 7.4 Filter Short Off-CPU Episodes

```bash
# Only record off-CPU episodes longer than 100 microseconds
# (reduces noise from brief scheduler preemptions)
$ bperf record -p 12345 --min-block 100 -o bperf.data
```

### 7.5 View Call Stacks for Off-CPU Events

```bash
# perf script dumps every sample with full callchains
$ perf script -i bperf.data | head -40

myapp  12345 [003] 1234567.890:     99000 task-clock:
            55a234001234 compute_hash+0x44 (/usr/bin/myapp)
            55a234003456 handle_request+0x156 (/usr/bin/myapp)
            55a234005678 main+0x78 (/usr/bin/myapp)

myapp  12345 [003] 1234567.895: 5000000 offcpu-iowait:
            ffffffff81234567 __schedule+0x2e7 ([kernel.kallsyms])
            ffffffff81234890 schedule+0x30 ([kernel.kallsyms])
            ffffffff812a1234 io_schedule+0x14 ([kernel.kallsyms])
            ffffffff81345678 blkdev_read_iter+0x88 ([kernel.kallsyms])
            55a234002345 read_block+0x25 (/usr/bin/myapp)
            55a234004567 load_data+0x67 (/usr/bin/myapp)
            55a234005678 main+0x98 (/usr/bin/myapp)

myapp  12345 [003] 1234567.900: 12000000 offcpu-interruptible:
            ffffffff81234567 __schedule+0x2e7 ([kernel.kallsyms])
            ffffffff81234890 schedule+0x30 ([kernel.kallsyms])
            ffffffff815a0123 futex_wait+0x103 ([kernel.kallsyms])
            55a234003789 mutex_lock+0x19 (/usr/bin/myapp)
            55a234004567 process_queue+0x47 (/usr/bin/myapp)
            55a234005678 main+0xb8 (/usr/bin/myapp)
```

### 7.6 Comparing Event Types in Flame Graphs

```bash
# Generate separate flame graphs per event type

# On-CPU flame graph
$ perf script -i bperf.data --event task-clock \
    | stackcollapse-perf.pl | flamegraph.pl \
      --title "On-CPU" --color hot > oncpu.svg

# Off-CPU flame graph (all subclasses combined)
$ perf script -i bperf.data \
    --event offcpu-sched,offcpu-iowait,offcpu-interruptible,offcpu-uninterruptible \
    | stackcollapse-perf.pl | flamegraph.pl \
      --title "Off-CPU" --color io > offcpu.svg

# I/O wait only
$ perf script -i bperf.data --event offcpu-iowait \
    | stackcollapse-perf.pl | flamegraph.pl \
      --title "I/O Wait" --color io > iowait.svg

# Combined wall-clock flame graph (on-CPU + all off-CPU)
$ perf script -i bperf.data \
    | stackcollapse-perf.pl | flamegraph.pl \
      --title "Wall Clock (on+off CPU)" > wall.svg
```

### 7.7 Interpreting the Output

When viewing `perf report`, the event name tells you the sample's nature:

| Event Name                | Meaning                                               |
|---------------------------|-------------------------------------------------------|
| `task-clock`              | Task was running on a CPU                             |
| `offcpu-sched`            | Task was runnable but waiting for a CPU (preempted)   |
| `offcpu-iowait`           | Task was waiting for I/O completion                   |
| `offcpu-interruptible`    | Task was in voluntary sleep (e.g., futex, poll, sleep)|
| `offcpu-uninterruptible`  | Task was in mandatory sleep (e.g., page fault, NFS)   |
| `offcpu-other`            | Task was stopped, traced, or in another state         |

The `period` field of each sample represents **time in nanoseconds**:
- On-CPU: the sampling interval (e.g., ~10 ms at 99 Hz)
- Off-CPU: the actual off-CPU duration

The `Overhead` column in `perf report` correctly reflects wall-clock contribution
because overhead is computed as `sum(period) / total_period`.

---

## 8. Limitations and Trade-offs

### 8.1 Comparison with Kernel bperf

| Aspect                         | Kernel bperf                           | eBPF bperf                                   |
|--------------------------------|----------------------------------------|----------------------------------------------|
| Kernel changes required        | 26 patches on 6.17                     | None                                         |
| Perf tool changes required     | Yes (report, script, etc.)             | None                                         |
| Minimum kernel version         | Custom kernel only                     | Stock 6.1+ with BTF                          |
| On+off CPU sample format       | Identical (same PMU, same event)       | Different event attrs, same perf.data file    |
| Subclass encoding              | `misc` bits in sample header           | Separate event attrs per subclass             |
| perf report compatibility      | Native (with patched perf)             | Native (unmodified perf)                      |
| Off-CPU overhead               | PMU callback, minimal                  | BPF on every sched_switch, slightly higher    |
| Stack accuracy                 | `task_pt_regs` — works without FP      | `bpf_get_stackid` — needs frame pointers for user stacks |
| Sample weight compression      | Kernel emits weighted samples          | One sample per off-CPU episode, period=duration |
| Sampling granularity           | Virtual samples at PMU period intervals | One aggregate sample per blocking episode     |

### 8.2 Known Limitations

**Frame Pointer Requirement:**
User-space stack unwinding via `bpf_get_stackid(BPF_F_USER_STACK)` relies on
frame pointers. Applications compiled with `-fomit-frame-pointer` (the default
in most optimized builds) will produce truncated or inaccurate user stacks. The
kernel bperf has the same limitation since it also uses the kernel's frame-pointer
based unwinder.

*Mitigation:* Compile the target application with `-fno-omit-frame-pointer`.
Major distributions are increasingly building packages with frame pointers
enabled (Fedora 38+, Ubuntu 24.04+).

**Ring Buffer Overflow:**
Under extreme context-switch rates (e.g., >100K/sec on a system with many
cores), the BPF ring buffer may drop events. The tool reports the number of
lost events.

*Mitigation:* Increase `--ringbuf-size`, use `--min-block` to filter trivial
off-CPU episodes, or profile a specific PID instead of system-wide.

**Stack Trace Map Overflow:**
The `BPF_MAP_TYPE_STACK_TRACE` has a fixed size (`max_entries = 16384` by
default). In diverse workloads with many unique call stacks, the map can fill
up, causing `bpf_get_stackid()` to return `-EEXIST`.

*Mitigation:* Increase `--stack-depth` or the internal map size. Alternatively,
use `BPF_F_REUSE_STACKID` to evict older stacks (with some risk of losing
infrequent but important stacks).

**Timestamp Correlation:**
On-CPU samples use `perf_clock()` (typically `clock_monotonic_raw` or
`local_clock`), while BPF uses `bpf_ktime_get_ns()` (which is
`clock_monotonic`). On most systems these are close but not identical. Small
timestamp ordering errors may occur at merge boundaries.

*Mitigation:* At recording start, sample both clocks to compute the offset, then
adjust BPF timestamps when writing perf.data.

**No DWARF Unwinding:**
BPF helpers cannot perform DWARF-based stack unwinding. This is a hard
limitation — the kernel's BPF verifier does not allow the complexity of DWARF
interpretation.

*Mitigation:* Use frame pointers, or use ORC unwinder for kernel stacks (which
BPF does support implicitly via the kernel's `perf_callchain_kernel` path
that `bpf_get_stackid` calls internally).

**One Sample per Blocking Episode:**
Unlike kernel bperf which generates N virtual samples proportional to off-CPU
duration (one per period), our eBPF approach emits one sample with
`period = duration`. This means off-CPU events don't have the same statistical
distribution as on-CPU events. In practice, this rarely matters — `perf report`
aggregates by overhead (sum of periods), and flame graphs scale by the same
metric.

### 8.3 Overhead Estimate

| Component                    | Approximate Cost                             |
|------------------------------|----------------------------------------------|
| BPF program per sched_switch | ~200-500 ns (stack capture dominates)         |
| Stack capture (kernel)       | ~100-200 ns                                  |
| Stack capture (user)         | ~100-400 ns (depends on stack depth)          |
| Ring buffer write            | ~50-100 ns                                   |
| perf task-clock sampling     | Same as standard `perf record -e task-clock`  |
| Total per context switch     | ~500-1200 ns (0.05-0.12% at 1M switches/sec) |

For typical server workloads (1K-50K context switches/sec), the overhead is
negligible (<0.01% CPU).

---

## 9. Future Work

### 9.1 DWARF-Based User Stack Unwinding

Linux 6.x introduced `bpf_get_stack()` with `BPF_F_USER_BUILD_ID`, which
returns `(build_id, file_offset)` pairs instead of raw IPs. Combined with
offline DWARF unwinding in userspace, this could improve stack accuracy for
applications without frame pointers. However, this only provides symbolization
help — actual unwinding still requires frame pointers in BPF context.

A more promising direction is the proposed `bpf_get_user_stack_buildid()` kfunc
and user-space SFrame-based unwinding, which would allow BPF programs to capture
user stacks using the SFrame format (a simplified, fast-to-parse alternative to
DWARF CFI). This is under active development in the kernel community.

### 9.2 Wakeup Chain Analysis

The BPF architecture easily extends to capture **wakeup chains** — who woke up
a sleeping task. By attaching to `tp_btf/sched_wakeup` or
`tp_btf/sched_waking`, we can record the waker's PID, stack, and timestamp.
This enables causality analysis: "Task A was off-CPU waiting for I/O, and was
woken by the block layer completion handler triggered by Task B's DMA
interrupt."

### 9.3 Cgroup and Container Awareness

The `bpf_get_current_cgroup_id()` helper can tag each sample with its cgroup,
enabling per-container profiling views. The perf.data `PERF_SAMPLE_CGROUP`
field could carry this information natively.

### 9.4 Differential Profiling

With the subclass annotations, bperf enables a new class of differential
analysis: compare the off-CPU profile before and after a code change to see if
blocking behavior shifted (e.g., I/O waits decreased but lock contention
increased).

### 9.5 Integration with `perf inject`

Instead of writing perf.data from scratch, an alternative architecture is:
1. Run `perf record -e task-clock` normally for on-CPU data
2. Collect off-CPU data separately via BPF into a custom format
3. Use `perf inject` to merge off-CPU samples into the existing perf.data

This would avoid reimplementing the perf.data writer but requires understanding
`perf inject`'s internal format requirements. It also allows users to use all
existing `perf record` features (e.g., `-b` for LBR, `--call-graph dwarf`).

### 9.6 Why Not sched_ext?

sched_ext (extensible scheduler) provides clean BPF hooks for scheduling
decisions (`ops.running`, `ops.stopping`, `ops.quiescent`, `ops.runnable`).
However, using sched_ext **replaces the active scheduler**, which is:

1. **Intrusive** — changes scheduling behavior of the entire system
2. **Risky** — a bug in the sched_ext program can degrade system performance
3. **Unnecessary** — `tp_btf/sched_switch` provides the same information
   without affecting scheduling

sched_ext is designed for building custom schedulers, not for passive
observation. Standard tracepoints are the correct tool for profiling.

---

## Appendix A: perf.data File Format Quick Reference

### A.1 File Header (104 bytes)

```
Offset  Size  Field
0x00    8     magic = 0x32454C4946524550 ("PERFILE2")
0x08    8     size = 104
0x10    8     attr_size = sizeof(perf_event_attr) + 16
0x18    16    attrs { offset, size }
0x28    16    data { offset, size }
0x38    16    event_types { 0, 0 }   (legacy)
0x48    32    adds_features[256 bits]
```

### A.2 PERF_RECORD_SAMPLE Field Order

Fields appear in this order when their `sample_type` bit is set:

```
IDENTIFIER → IP → TID → TIME → ADDR → ID → STREAM_ID → CPU →
PERIOD → READ → CALLCHAIN → RAW → BRANCH_STACK → REGS_USER →
STACK_USER → WEIGHT → DATA_SRC → TRANSACTION → REGS_INTR →
PHYS_ADDR → CGROUP → DATA_PAGE_SIZE → CODE_PAGE_SIZE → AUX
```

### A.3 Callchain Context Markers

```c
#define PERF_CONTEXT_HV        (u64)-32
#define PERF_CONTEXT_KERNEL    (u64)-128    /* 0xFFFFFFFFFFFFFF80 */
#define PERF_CONTEXT_USER      (u64)-512    /* 0xFFFFFFFFFFFFFE00 */
#define PERF_CONTEXT_GUEST     (u64)-2048
#define PERF_CONTEXT_GUEST_KERNEL  (u64)-2176
#define PERF_CONTEXT_GUEST_USER    (u64)-2560
```

### A.4 Key `perf_event_header::misc` Values

```c
#define PERF_RECORD_MISC_CPUMODE_MASK  0x0007
#define PERF_RECORD_MISC_CPUMODE_UNKNOWN  0
#define PERF_RECORD_MISC_KERNEL           1
#define PERF_RECORD_MISC_USER             2
#define PERF_RECORD_MISC_HYPERVISOR       3
#define PERF_RECORD_MISC_COMM_EXEC     0x2000
#define PERF_RECORD_MISC_MMAP_BUILD_ID 0x4000
```

### A.5 `sample_id` Trailer (for non-SAMPLE records when `sample_id_all = 1`)

Only includes fields that are **both** in `sample_type` **and** in this set:

```
TID → TIME → ID → STREAM_ID → CPU → IDENTIFIER
```

(Does not include IP, CALLCHAIN, PERIOD, WEIGHT, etc.)
