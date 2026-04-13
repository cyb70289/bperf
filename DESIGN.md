# bperf: Unified On/Off-CPU Profiler -- eBPF Design Document

## Table of Contents

1. [Introduction](#1-introduction)
2. [Architecture](#2-architecture)
3. [BPF Program](#3-bpf-program)
4. [Userspace Tool](#4-userspace-tool)
5. [perf.data Output Format](#5-perfdata-output-format)
6. [Usage Examples](#6-usage-examples)
7. [Limitations and Trade-offs](#7-limitations-and-trade-offs)
8. [Future Work](#8-future-work)

---

## 1. Introduction

### 1.1 Problem Statement

Traditional Linux profilers force a choice between **on-CPU** and **off-CPU**
analysis:

- `perf record -e task-clock` samples only while the task is running on a CPU.
  It reveals hot code paths but is blind to time spent sleeping, waiting on I/O,
  or contending for locks.
- Off-CPU profilers (e.g., `offcputime` from bcc/bpftrace) capture time spent
  blocked but miss on-CPU activity entirely.

Neither approach alone can answer the question: *"Where does my application
spend its wall-clock time?"* A database query that takes 500 ms might spend
50 ms on-CPU parsing SQL and 450 ms off-CPU waiting for disk I/O -- a
task-clock profile would attribute 100% overhead to the parser, completely
hiding the dominant bottleneck.

### 1.2 What bperf Does

**bperf** captures both on-CPU and off-CPU profiling data within a single
unified event stream. It classifies *why* a task was off-CPU (runqueue wait,
I/O wait, interruptible sleep, uninterruptible sleep, etc.) and writes
everything into a standard `perf.data` file.

The concept originates from the bperf paper (OSDI '24, Yonsei University),
which introduced **blocked samples** via 26 kernel patches. This
implementation achieves the same profiling capability using eBPF, requiring:

- **No kernel source changes** -- works on stock kernels (6.1+) with BTF
- **No perf tool changes** -- output is readable by unmodified `perf report`,
  `perf script`, and flame graph tools
- **A single userspace tool** (`bperf record`) that orchestrates BPF programs,
  collects on-CPU samples via `perf_event_open(2)`, and writes the unified
  output

### 1.3 Minimum Requirements

| Requirement             | Version / Config                          |
|-------------------------|-------------------------------------------|
| Linux kernel            | 6.1+ (LTS) with BTF enabled               |
| `CONFIG_DEBUG_INFO_BTF` | `=y` (required for CO-RE and `tp_btf`)    |
| `CONFIG_BPF_SYSCALL`    | `=y`                                      |
| libbpf                  | 1.0+                                      |
| clang/llvm              | 14+ (for BPF CO-RE compilation)           |
| Frame pointers          | Recommended for user-space stack accuracy |

---

## 2. Architecture

### 2.1 High-Level Overview

```
+-----------------------------------------------------------------+
|                       Kernel Space                              |
|                                                                 |
|  +--------------------------------------+                       |
|  |     tp_btf/sched_switch              |                       |
|  |                                      |                       |
|  |  prev being switched out:            |     +---------------+ |
|  |    1. Capture kernel stack ID        |---->| STACK_TRACE   | |
|  |    2. Capture user stack ID          |     | map           | |
|  |    3. Record timestamp + subclass    |     +---------------+ |
|  |       into TASK_STORAGE              |                       |
|  |                                      |     +---------------+ |
|  |  next being switched in:             |---->| TASK_STORAGE  | |
|  |    1. Read stored timestamp          |     | map           | |
|  |    2. Compute delta                  |     +---------------+ |
|  |    3. Emit offcpu_event to ringbuf   |                       |
|  |                                      |     +---------------+ |
|  |                                      |---->| BPF RING_BUF  | |
|  +--------------------------------------+     +-------+-------+ |
|                                                       |         |
|  +--------------------------------------+             |         |
|  |  perf_event (task-clock)             |             |         |
|  |  +--------------------------------+  |             |         |
|  |  | perf mmap ring buffer          |  |             |         |
|  |  | (on-CPU PERF_RECORD_SAMPLE)    |  |             |         |
|  |  +--------------+-----------------+  |             |         |
|  +-----------------|--------------------+             |         |
|                    |                                  |         |
+--------------------+----------------------------------+---------+
                     |                                  |
+--------------------+----------------------------------+---------+
|                    v         User Space               v         |
|  +-------------------------------------------------------------+|
|  |                   bperf record                               ||
|  |                                                              ||
|  |  1. Load & attach BPF programs                               ||
|  |  2. Open perf_event_open(task-clock), mmap ring buffer       ||
|  |  3. Poll both ring buffers                                   ||
|  |  4. Merge on-CPU + off-CPU events by timestamp               ||
|  |  5. Read /proc/<pid>/maps for MMAP2 records                  ||
|  |  6. Dump STACK_TRACE map for callchain resolution            ||
|  |  7. Write unified perf.data                                  ||
|  +--------------------------+-----------------------------------+|
|                             |                                    |
|                             v                                    |
|                     +------------+                               |
|                     | perf.data  |                               |
|                     +-----+------+                               |
|                           |                                      |
|              +------------+------------+                         |
|              v            v            v                          |
|        perf report   perf script   FlameGraph                    |
+-----------------------------------------------------------------+
```

### 2.2 Data Flow

1. **On-CPU path**: The kernel's perf subsystem samples `task-clock` at a
   configured frequency (e.g., 99 Hz). Samples -- complete with IP, callchain,
   PID/TID, timestamp -- land in a per-CPU perf mmap ring buffer. The userspace
   tool reads these directly. On-CPU `PERF_RECORD_SAMPLE` records are already
   in the correct binary format for perf.data and can be written verbatim.

2. **Off-CPU path**: A BPF program attached to `tp_btf/sched_switch` fires on
   every context switch. For the outgoing task (`prev`), it captures the kernel
   and user stack IDs and records the timestamp + off-CPU subclass into per-task
   BPF storage. For the incoming task (`next`), it looks up the stored state,
   computes off-CPU duration, and emits a structured event to a BPF ring buffer.

3. **Merge**: The userspace tool polls both ring buffers, collects all events in
   memory, sorts by timestamp, resolves stack IDs to IP arrays, and writes a
   unified `perf.data` file.

### 2.3 BPF Maps

| Map Name         | Type                        | Key             | Value                      | Purpose                                        |
|------------------|-----------------------------|-----------------|----------------------------|-------------------------------------------------|
| `task_storage`   | `BPF_MAP_TYPE_TASK_STORAGE` | (implicit task) | `struct task_offcpu_data`  | Per-task sched-out timestamp, subclass, stacks  |
| `stack_traces`   | `BPF_MAP_TYPE_STACK_TRACE`  | `u32` stack ID  | `u64[PERF_MAX_STACK_DEPTH]`| Deduplicated stack traces                       |
| `events`         | `BPF_MAP_TYPE_RINGBUF`      | --              | `struct offcpu_event`      | Off-CPU events sent to userspace                |
| `bperf_cfg`      | `BPF_MAP_TYPE_ARRAY`        | `u32` index     | `struct bperf_config`      | Runtime configuration from userspace            |

### 2.4 Filtering Strategy

| Mode             | Mechanism                                                                      |
|------------------|--------------------------------------------------------------------------------|
| Single process   | Compare `prev->tgid` / `next->tgid` against target PID in config map           |
| System-wide      | Profile all tasks (exclude kernel threads via `tgid == 0` check)               |

---

## 3. BPF Program

### 3.1 Shared Data Structures

These structures are defined in `include/bperf_common.h` and shared between
the BPF program and userspace:

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
    OFFCPU_SUBCLASS_INTERRUPTIBLE   = 3,  /* voluntary sleep */
    OFFCPU_SUBCLASS_UNINTERRUPTIBLE = 4,  /* uninterruptible sleep */
    OFFCPU_SUBCLASS_OTHER           = 5,  /* STOPPED, TRACED, PARKED, etc. */
};

/* Runtime configuration (written by userspace before attach) */
struct bperf_config {
    u32 target_tgid;        /* 0 = system-wide */
    u64 min_duration_ns;    /* ignore off-CPU episodes shorter than this */
};
```

### 3.2 Off-CPU Subclass Classification

At schedule-out time, the BPF program inspects `prev->__state` and
`prev->in_iowait` to classify the off-CPU reason:

| Subclass                  | Condition                                   |
|---------------------------|---------------------------------------------|
| `OFFCPU_SUBCLASS_SCHED`  | `prev_state == TASK_RUNNING` (preempted)    |
| `OFFCPU_SUBCLASS_IOWAIT` | `in_iowait` flag is set                     |
| `OFFCPU_SUBCLASS_INTERRUPTIBLE` | `TASK_INTERRUPTIBLE`               |
| `OFFCPU_SUBCLASS_UNINTERRUPTIBLE` | `TASK_UNINTERRUPTIBLE`           |
| `OFFCPU_SUBCLASS_OTHER`  | Everything else (STOPPED, TRACED, etc.)     |

**Note on `in_iowait`:** This field is a bit-field in `task_struct` and must
be read with `BPF_CORE_READ_BITFIELD()`, not `BPF_CORE_READ()`.

### 3.3 sched_switch Handler Overview

The BPF program is attached to `tp_btf/sched_switch` and has two phases:

**Phase 1 -- Sched-out (prev task):**
- Capture kernel and user stack IDs via `bpf_get_stackid()`
- Record timestamp (`bpf_ktime_get_ns()`) and subclass into task storage
- Stack capture must happen here while `prev` is still current (user page
  tables are still active)

**Phase 2 -- Sched-in (next task):**
- Look up stored state from task storage
- Compute `delta = now - sched_out_ts`
- Apply minimum duration filter
- Emit `offcpu_event` to BPF ring buffer
- Reset `sched_out_ts` to avoid double-counting

**Note on `tp_btf/sched_switch` arguments:** On kernel 6.8, the tracepoint
provides 3 arguments `(bool preempt, struct task_struct *prev,
struct task_struct *next)`. The `prev_state` must be read from
`prev->__state` via `BPF_CORE_READ`.

### 3.4 Verifier Considerations

| Concern                    | Mitigation                                                  |
|----------------------------|-------------------------------------------------------------|
| Loop bounds                | No loops in the BPF program (single event per sched_switch) |
| Stack size (512 bytes max) | `offcpu_event` is reserved from ringbuf, not on stack       |
| Map access patterns        | All map lookups check for NULL returns                      |
| `bpf_get_stackid` failure  | Returns negative value; stored as-is, handled in userspace  |
| `tp_btf` arg trust         | `prev` and `next` are trusted pointers from the tracepoint  |

---

## 4. Userspace Tool

### 4.1 CLI Interface

```
bperf record [OPTIONS] [-- command [args...]]

OPTIONS:
    -p, --pid <PID>         Profile a specific process (and all its threads)
    -a, --all-cpus          System-wide profiling
    -F, --freq <HZ>         On-CPU sampling frequency [default: 99]
    --no-kernel             Exclude kernel call chains
    --min-block <USEC>      Minimum off-CPU duration to record [default: 1]
    -d, --duration <SEC>    Recording duration [default: until Ctrl-C]
    -o, --output <FILE>     Output file [default: bperf.data]
    --stack-depth <N>       Maximum stack depth [default: 127]
    --ringbuf-size <MB>     BPF ring buffer size [default: 16]
```

### 4.2 Source File Organization

```
bperf/
+-- BUILD.md                # Build and test instructions
+-- DESIGN.md               # This document
+-- Makefile                 # Build system
+-- vmlinux.h               # Generated: BTF header for CO-RE
+-- test_workload.c          # Test program (CPU work + nanosleep cycles)
+-- include/
|   +-- bperf_common.h      # Shared structs between BPF and userspace
|   +-- perf_file.h          # perf.data format definitions
+-- src/
    +-- bperf.bpf.c          # BPF program (tp_btf/sched_switch handler)
    +-- bperf.c              # CLI entry point, argument parsing
    +-- record.c / record.h  # Recording orchestration (setup, main loop, finalize)
    +-- oncpu.c / oncpu.h    # On-CPU: perf_event_open, mmap ring buffer reader
    +-- offcpu.c / offcpu.h  # Off-CPU: BPF skeleton loader, ringbuf consumer
    +-- writer.c / writer.h  # perf.data file writer
    +-- proc.c / proc.h      # /proc parser (maps, comm, threads)
```

### 4.3 Recording Workflow

```
bperf record -p 1234 -F 99 -d 10 -o bperf.data

Phase 1: Setup
  +- Parse CLI arguments
  +- Load BPF skeleton (bperf.bpf.o)
  +- Write config to BPF config map (target_tgid, min_duration_ns)
  +- Attach BPF program to tp_btf/sched_switch
  +- Open perf_event_open(PERF_COUNT_SW_TASK_CLOCK, pid, freq)
  |   +- Set sample_type = BPERF_SAMPLE_TYPE (see S5.2)
  |   +- mmap() the perf ring buffer (per-CPU in system-wide mode)
  |   +- ioctl(PERF_EVENT_IOC_ID) -> on_cpu_event_id(s)
  +- Read /proc/<pid>/comm, maps, task/* for COMM and MMAP2 records
  +- If command mode: fork(), sync pipe, execvp()

Phase 2: Collection (main loop, epoll on both ring buffers)
  +- On perf mmap readable:
  |   +- Read all record types (SAMPLE, MMAP2, COMM, FORK, EXIT)
  |   +- Buffer raw records into on_cpu_events[]
  +- On BPF ringbuf readable:
  |   +- ring_buffer__poll() -> callback per offcpu_event
  |   +- Buffer into off_cpu_events[]
  +- Check duration / signal / child exit

Phase 3: Finalize
  +- Drain remaining events from both ring buffers
  +- Dump stack_traces BPF map -> resolved IP arrays
  +- Sort all events by timestamp
  +- Write perf.data (see S5)
```

### 4.4 Key Design Decisions

**On-CPU records written verbatim:** `PERF_RECORD_SAMPLE` from the perf mmap
ring buffer is already in the exact binary format expected by perf.data.
The kernel-assigned event ID (from `PERF_EVENT_IOC_ID`) is embedded in each
record. In system-wide mode, each per-CPU fd gets a distinct event ID; all
IDs are listed in the attrs section so perf can match them.

**Off-CPU events synthesized as PERF_RECORD_SAMPLE:** Each `offcpu_event`
from the BPF ring buffer is converted to a `PERF_RECORD_SAMPLE` with the
same `sample_type` as on-CPU samples, but assigned to one of 5 synthetic
event IDs (1001--1005) based on subclass.

**period = duration_ns:** By setting the period of each off-CPU sample to
the off-CPU duration in nanoseconds, `perf report`'s overhead calculation
correctly accounts for off-CPU time. The on-CPU `task-clock` samples also
have period in nanoseconds. The total overhead thus represents **wall-clock
time**.

---

## 5. perf.data Output Format

### 5.1 File Layout

```
Offset 0x00:                 perf_file_header        (104 bytes)
Offset 0x68:                 attrs section start
                             +- attr[0] + ids_section  (on-CPU: task-clock)
                             +- attr[1] + ids_section  (offcpu-sched)
                             +- attr[2] + ids_section  (offcpu-iowait)
                             +- attr[3] + ids_section  (offcpu-interruptible)
                             +- attr[4] + ids_section  (offcpu-uninterruptible)
                             +- attr[5] + ids_section  (offcpu-other)
Offset A:                    ID arrays
                             +- attr[0] IDs: N u64s (1 per CPU in sys-wide)
                             +- attr[1..5] IDs: 1 u64 each
Offset B:                    data section start
                             +- PERF_RECORD_COMM records
                             +- PERF_RECORD_MMAP2 records
                             +- Non-SAMPLE on-CPU records (FORK, EXIT, etc.)
                             +- PERF_RECORD_SAMPLE records (merged, time-sorted)
Offset C:                    feature section headers (3 x perf_file_section)
Offset D:                    feature data
                             +- HEADER_CMDLINE    (bit 11)
                             +- HEADER_EVENT_DESC (bit 12)
                             +- HEADER_SAMPLE_TIME (bit 21)
```

Feature sections must be written in **bit order** of their feature IDs.

### 5.2 Sample Type

All six event attributes share the same `sample_type`:

```c
#define BPERF_SAMPLE_TYPE ( \
    PERF_SAMPLE_IDENTIFIER |    /* event ID (first field in SAMPLE) */ \
    PERF_SAMPLE_IP |            /* instruction pointer              */ \
    PERF_SAMPLE_TID |           /* pid + tid                        */ \
    PERF_SAMPLE_TIME |          /* timestamp                        */ \
    PERF_SAMPLE_CPU |           /* CPU number                       */ \
    PERF_SAMPLE_PERIOD |        /* sampling period                  */ \
    PERF_SAMPLE_CALLCHAIN |     /* call stack                       */ \
    PERF_SAMPLE_WEIGHT          /* sample weight                    */ \
)
```

Resulting `PERF_RECORD_SAMPLE` binary layout:

```
struct perf_event_header    header;         /*  8 bytes */
u64                         identifier;     /*  8 bytes */
u64                         ip;             /*  8 bytes */
u32                         pid, tid;       /*  8 bytes */
u64                         time;           /*  8 bytes */
u32                         cpu, res;       /*  8 bytes */
u64                         period;         /*  8 bytes */
u64                         nr;             /*  8 bytes (callchain count) */
u64                         ips[nr];        /*  8*nr    */
u64                         weight;         /*  8 bytes */
```

### 5.3 Event Attributes

Six `perf_event_attr` entries, differentiated by event IDs and named via
`HEADER_EVENT_DESC`:

| Index | Event Name               | Event ID     | Purpose              |
|-------|--------------------------|--------------|----------------------|
| 0     | `task-clock`             | kernel-assigned (per-CPU in system-wide) | On-CPU samples |
| 1     | `offcpu-sched`           | 1001         | Off-CPU: runqueue    |
| 2     | `offcpu-iowait`          | 1002         | Off-CPU: I/O wait    |
| 3     | `offcpu-interruptible`   | 1003         | Off-CPU: voluntary   |
| 4     | `offcpu-uninterruptible` | 1004         | Off-CPU: involuntary |
| 5     | `offcpu-other`           | 1005         | Off-CPU: misc        |

Off-CPU attrs reuse `type=PERF_TYPE_SOFTWARE, config=PERF_COUNT_SW_TASK_CLOCK`
since the underlying event type doesn't matter for synthetic samples -- only
the event name (from `HEADER_EVENT_DESC`) and event ID matter for `perf report`.

### 5.4 HEADER_EVENT_DESC Format

This feature maps attrs to human-readable event names. The format per event
(matching perf's `write_event_desc` / `read_event_desc` in
`tools/perf/util/header.c`):

```
u32 nr_events
u32 attr_size
for each event:
    struct perf_event_attr  attr
    u32                     nr_ids
    perf_string             event_name    (u32 padded_len + zero-padded string)
    u64                     ids[nr_ids]
```

**String format:** perf's `do_write_string` writes strings as
`u32 PERF_ALIGN(strlen+1, 64)` followed by the string zero-padded to that
length. `HEADER_CMDLINE` uses the same format.

### 5.5 Non-SAMPLE Records

All non-SAMPLE records (COMM, MMAP2, FORK, EXIT) include a `sample_id`
trailer because `sample_id_all = 1`:

```
sample_id trailer (32 bytes):
    u32 pid, tid;       /* PERF_SAMPLE_TID */
    u64 time;           /* PERF_SAMPLE_TIME */
    u32 cpu, res;       /* PERF_SAMPLE_CPU */
    u64 id;             /* PERF_SAMPLE_IDENTIFIER */
```

### 5.6 File Header

```c
struct perf_file_header {
    u64 magic;                      /* 0x32454C4946524550 ("PERFILE2") */
    u64 size;                       /* 104 */
    u64 attr_size;                  /* sizeof(perf_event_attr) + 16 */
    struct perf_file_section attrs; /* offset, size of attrs section */
    struct perf_file_section data;  /* offset, size of data section */
    struct perf_file_section event_types; /* {0, 0} (legacy) */
    u64 adds_features[4];          /* 256-bit feature flags */
};
```

Feature bits set: `HEADER_CMDLINE` (bit 11), `HEADER_EVENT_DESC` (bit 12),
`HEADER_SAMPLE_TIME` (bit 21).

---

## 6. Usage Examples

### 6.1 Profile a Single Process

```bash
# Record for 30 seconds at 99 Hz
sudo bperf record -p 12345 -F 99 -d 30 -o bperf.data

# View results with standard perf report
perf report -i bperf.data --stdio
```

### 6.2 Profile a Command from Launch

```bash
sudo bperf record -- ./my_server --config server.conf
# Press Ctrl-C to stop

# Generate a flame graph (all events combined = wall-clock profile)
perf script -i bperf.data | stackcollapse-perf.pl | flamegraph.pl > wall.svg
```

### 6.3 System-Wide Profiling

```bash
sudo bperf record -a -d 60 -o system.data
perf report -i system.data --stdio
```

### 6.4 Filter Short Off-CPU Episodes

```bash
# Only record off-CPU episodes longer than 100 microseconds
sudo bperf record -p 12345 --min-block 100 -o bperf.data
```

### 6.5 Separate Flame Graphs per Event Type

```bash
# On-CPU flame graph
perf script -i bperf.data --event task-clock \
    | stackcollapse-perf.pl | flamegraph.pl \
      --title "On-CPU" --color hot > oncpu.svg

# Off-CPU flame graph (all subclasses)
perf script -i bperf.data \
    --event offcpu-sched,offcpu-iowait,offcpu-interruptible,offcpu-uninterruptible \
    | stackcollapse-perf.pl | flamegraph.pl \
      --title "Off-CPU" --color io > offcpu.svg

# Combined wall-clock flame graph
perf script -i bperf.data \
    | stackcollapse-perf.pl | flamegraph.pl \
      --title "Wall Clock (on+off CPU)" > wall.svg
```

### 6.6 Interpreting the Output

| Event Name                | Meaning                                               |
|---------------------------|-------------------------------------------------------|
| `task-clock`              | Task was running on a CPU                             |
| `offcpu-sched`            | Task was runnable but waiting for a CPU (preempted)   |
| `offcpu-iowait`           | Task was waiting for I/O completion                   |
| `offcpu-interruptible`    | Task was in voluntary sleep (futex, poll, sleep)      |
| `offcpu-uninterruptible`  | Task was in mandatory sleep (page fault, NFS)         |
| `offcpu-other`            | Task was stopped, traced, or in another state         |

The `period` field of each sample represents **time in nanoseconds**:
- On-CPU: the sampling interval (e.g., ~10 ms at 99 Hz)
- Off-CPU: the actual off-CPU duration

The `Overhead` column in `perf report` correctly reflects wall-clock
contribution because overhead is computed as `sum(period) / total_period`.

---

## 7. Limitations and Trade-offs

### 7.1 Known Limitations

**Frame Pointer Requirement:**
User-space stack unwinding via `bpf_get_stackid(BPF_F_USER_STACK)` relies on
frame pointers. Applications compiled with `-fomit-frame-pointer` (the default
in most optimized builds) will produce truncated stacks.
*Mitigation:* Compile with `-fno-omit-frame-pointer`. Major distributions are
increasingly building packages with frame pointers (Fedora 38+, Ubuntu 24.04+).

**Ring Buffer Overflow:**
Under extreme context-switch rates (>100K/sec system-wide), the BPF ring
buffer may drop events.
*Mitigation:* Increase `--ringbuf-size`, use `--min-block` to filter trivial
episodes, or profile a specific PID.

**Stack Trace Map Overflow:**
`BPF_MAP_TYPE_STACK_TRACE` has a fixed max_entries (16384). Diverse workloads
with many unique call stacks can fill the map, causing `bpf_get_stackid()` to
return `-EEXIST`.

**Timestamp Correlation:**
On-CPU samples use the perf clock while BPF uses `bpf_ktime_get_ns()`
(`clock_monotonic`). These are close but not identical on most systems. Small
ordering errors may occur at merge boundaries.

**No DWARF Unwinding:**
BPF helpers cannot perform DWARF-based stack unwinding. This is a hard
limitation of the BPF verifier.

**One Sample per Blocking Episode:**
Unlike the kernel bperf which generates N virtual samples proportional to
off-CPU duration, this approach emits one sample with `period = duration`.
In practice this rarely matters -- `perf report` aggregates by overhead
(sum of periods).

### 7.2 Overhead Estimate

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

## 8. Future Work

**DWARF-Based User Stack Unwinding:**
The proposed `bpf_get_user_stack_buildid()` kfunc and SFrame-based unwinding
would allow BPF to capture user stacks without frame pointers.

**Wakeup Chain Analysis:**
Attaching to `tp_btf/sched_wakeup` to record who woke up a sleeping task,
enabling causality analysis.

**Cgroup and Container Awareness:**
`bpf_get_current_cgroup_id()` can tag each sample with its cgroup for
per-container profiling views.

**Integration with `perf inject`:**
An alternative architecture: run standard `perf record` for on-CPU data,
collect off-CPU data via BPF separately, then use `perf inject` to merge.
This would allow using all `perf record` features (LBR, `--call-graph dwarf`).

---

## Appendix: perf.data Quick Reference

### PERF_RECORD_SAMPLE Field Order

Fields appear in `sample_type` bit order:

```
IDENTIFIER -> IP -> TID -> TIME -> ADDR -> ID -> STREAM_ID -> CPU ->
PERIOD -> READ -> CALLCHAIN -> RAW -> BRANCH_STACK -> REGS_USER ->
STACK_USER -> WEIGHT -> DATA_SRC -> ...
```

### Callchain Context Markers

```c
#define PERF_CONTEXT_KERNEL    (u64)-128    /* 0xFFFFFFFFFFFFFF80 */
#define PERF_CONTEXT_USER      (u64)-512    /* 0xFFFFFFFFFFFFFE00 */
```

### sample_id Trailer Field Order (when sample_id_all = 1)

Only includes fields in both `sample_type` and this set:

```
TID -> TIME -> ID -> STREAM_ID -> CPU -> IDENTIFIER
```

(Does not include IP, CALLCHAIN, PERIOD, WEIGHT, etc.)
