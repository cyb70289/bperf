# Building bperf

## Host Requirements

| Requirement | Minimum | Tested With |
|---|---|---|
| Linux kernel | 6.1+ with BTF | 6.8.0-106-generic (aarch64) |
| `CONFIG_DEBUG_INFO_BTF` | `=y` | Required for CO-RE / `tp_btf` |
| `CONFIG_BPF_SYSCALL` | `=y` | Required for BPF |
| clang/llvm | 14+ | clang-18, llvm-18 |
| libbpf | 1.0+ | 1.3.0 (libbpf-dev) |
| libelf | any | libelf-dev |
| bpftool | 5.15+ | 7.4.0 |

**Architecture:** Tested on aarch64 (ARM). Should work on x86_64 without changes
(the Makefile auto-detects `uname -m`).

## Install Build Dependencies

Ubuntu/Debian:

```bash
sudo apt-get install -y \
    clang-18 llvm-18 \
    libbpf-dev libelf-dev zlib1g-dev \
    linux-tools-common bpftool
```

If `bpftool` is not available as a package, it can be built from the kernel
source tree (`tools/bpf/bpftool`).

## Generate vmlinux.h

This header provides BTF type definitions for CO-RE. Generate it once from the
running kernel:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

This produces a large file (~180K lines). It must be regenerated if you move
to a different kernel version.

## Build

```bash
make -j$(nproc)
```

This compiles the BPF program (`src/bperf.bpf.c`), generates the BPF skeleton,
and links the userspace binary. Output: `./bperf`.

To clean:

```bash
make clean
```

## Quick Test

### 1. Build the test workload

```bash
gcc -O2 -fno-omit-frame-pointer -o test_workload test_workload.c -lm
```

### 2. Profile it

```bash
# Command-launch mode (profiles until the command exits)
sudo ./bperf record -F 99 -o bperf.data -- ./test_workload

# Or profile an existing PID
./test_workload &
sudo ./bperf record -p $! -o bperf.data
# Press Ctrl-C after a few seconds
kill %1
```

Expected output:

```
bperf: profiling command './test_workload' (pid 12345)
bperf: recording... press Ctrl-C to stop
test_workload: 10 rounds of CPU work + sleep
test_workload: done
bperf: stopping...
bperf: on-CPU samples: 48
bperf: off-CPU events: 363
bperf:   offcpu-sched: 353
bperf:   offcpu-iowait: 0
bperf:   offcpu-interruptible: 10
bperf:   offcpu-uninterruptible: 0
bperf:   offcpu-other: 0
bperf: unique stacks: 74
bperf: output written to bperf.data
```

### 3. View results with standard perf tools

```bash
# Interactive report
perf report -i bperf.data

# Text report
perf report -i bperf.data --stdio

# Raw event dump (shows event names, callchains, durations)
perf script -i bperf.data | head -40

# Verify all 6 events are recognized
perf report -i bperf.data --header-only | grep "^# event"
```

You should see all six events listed:

```
# event : name = task-clock, ...
# event : name = offcpu-sched, ...
# event : name = offcpu-iowait, ...
# event : name = offcpu-interruptible, ...
# event : name = offcpu-uninterruptible, ...
# event : name = offcpu-other, ...
```

### 4. System-wide test

```bash
sudo ./bperf record -a -F 99 -o system.data &
sleep 2
sudo kill -INT $!
wait
perf report -i system.data --stdio | head -40
```

## Notes

- **Root required**: bperf needs root (or `CAP_BPF` + `CAP_PERFMON`) for BPF
  and `perf_event_open`.
- **Frame pointers**: For accurate user-space stacks, compile your target with
  `-fno-omit-frame-pointer`. The test workload already uses this flag.
- **Kernel symbols**: If `perf report` shows `[unknown]` for kernel symbols,
  run `echo 0 | sudo tee /proc/sys/kernel/kptr_restrict`.

## Flamegraph Support

bperf can generate an SVG flamegraph directly via the `--flamegraph` flag.
This uses the bundled [FlameGraph](https://github.com/brendangregg/FlameGraph)
scripts in the `flamegraph/` directory (no separate install needed).

**Requirements:** `perl` (for the FlameGraph scripts) and `perf` (for `perf script`).

### Usage

```bash
# Command-launch mode with flamegraph
sudo ./bperf record --flamegraph -F 99 -o bperf.data -- ./test_workload

# Profile a PID with flamegraph
sudo ./bperf record --flamegraph -p 1234 -d 10 -o bperf.data

# System-wide with flamegraph
sudo ./bperf record --flamegraph -a -d 5 -o system.data
```

`--flamegraph` implies `--combined`, merging all on-CPU and off-CPU events
into a single "wall-clock" event for a unified flamegraph. The output SVG is
written next to the perf.data file (e.g. `bperf.data.svg`).

### Bundled scripts

The `flamegraph/` directory contains:

- `stackcollapse-perf.pl` — collapses `perf script` output into folded stacks
- `flamegraph.pl` — renders folded stacks as an interactive SVG

These are from Brendan Gregg's
[FlameGraph](https://github.com/brendangregg/FlameGraph) project (CDDL-1.0 license).
