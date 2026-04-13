/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * perf_file.h - perf.data format definitions for bperf writer
 */
#ifndef PERF_FILE_H
#define PERF_FILE_H

#include <stdint.h>
#include <linux/perf_event.h>

/* perf.data magic: "PERFILE2" */
#define PERF_MAGIC 0x32454C4946524550ULL

/*
 * Our sample_type — all 6 event attrs share this.
 *
 * Fields in PERF_RECORD_SAMPLE appear in bit order:
 *   IDENTIFIER(first), IP, TID, TIME, CPU, PERIOD, CALLCHAIN, WEIGHT
 */
#define BPERF_SAMPLE_TYPE ( \
	PERF_SAMPLE_IDENTIFIER | \
	PERF_SAMPLE_IP |         \
	PERF_SAMPLE_TID |        \
	PERF_SAMPLE_TIME |       \
	PERF_SAMPLE_CPU |        \
	PERF_SAMPLE_PERIOD |     \
	PERF_SAMPLE_CALLCHAIN |  \
	PERF_SAMPLE_WEIGHT       \
)

/*
 * sample_id trailer fields for non-SAMPLE records (when sample_id_all=1).
 * Only the bits in BPERF_SAMPLE_TYPE that are in the sample_id subset:
 *   TID, TIME, ID, STREAM_ID, CPU, IDENTIFIER
 * Our mask has: TID, TIME, CPU, IDENTIFIER
 * So trailer is: { pid, tid, time, cpu, res, identifier } = 32 bytes
 */
#define BPERF_SAMPLE_ID_SIZE 32

/* perf.data file header (104 bytes) */
struct perf_file_section {
	uint64_t offset;
	uint64_t size;
};

struct perf_file_header {
	uint64_t magic;                    /* PERF_MAGIC */
	uint64_t size;                     /* sizeof(this) = 104 */
	uint64_t attr_size;                /* size of each attr entry */
	struct perf_file_section attrs;    /* attrs section */
	struct perf_file_section data;     /* data section */
	struct perf_file_section event_types; /* legacy, {0,0} */
	uint64_t adds_features[4];         /* feature bit array (256 bits) */
};

/* Feature header IDs (bit positions in adds_features) */
#define HEADER_TRACING_DATA  1
#define HEADER_BUILD_ID      2  /* not used */
#define HEADER_HOSTNAME      3
#define HEADER_OSRELEASE     4
#define HEADER_VERSION       5
#define HEADER_ARCH          6
#define HEADER_NRCPUS        7
#define HEADER_CPUDESC       8
#define HEADER_CPUID         9
#define HEADER_TOTAL_MEM     10
#define HEADER_CMDLINE       11
#define HEADER_EVENT_DESC    12
#define HEADER_CPU_TOPOLOGY  13
#define HEADER_NUMA_TOPOLOGY 14
#define HEADER_BRANCH_STACK  15
#define HEADER_PMU_MAPPINGS  16
#define HEADER_GROUP_DESC    17
#define HEADER_AUXTRACE      18
#define HEADER_STAT          19
#define HEADER_CACHE         20
#define HEADER_SAMPLE_TIME   21
#define HEADER_MEM_TOPOLOGY  22
#define HEADER_CLOCKID       23
#define HEADER_DIR_FORMAT    24
#define HEADER_BPF_PROG_INFO 25
#define HEADER_BPF_BTF       26
#define HEADER_COMPRESSED    27
#define HEADER_CPU_PMU_CAPS  28
#define HEADER_CLOCK_DATA    29

/* perf string alignment (matches NAME_ALIGN in tools/perf/util/header.c) */
#define PERF_NAME_ALIGN  64
#define PERF_ALIGN(x, a) (((x) + (a) - 1) & ~((a) - 1))

/* Callchain context markers */
#ifndef PERF_CONTEXT_KERNEL
#define PERF_CONTEXT_KERNEL  ((uint64_t)-128)
#define PERF_CONTEXT_USER    ((uint64_t)-512)
#endif

/* perf_event_header misc field */
#ifndef PERF_RECORD_MISC_KERNEL
#define PERF_RECORD_MISC_KERNEL   1
#define PERF_RECORD_MISC_USER     2
#define PERF_RECORD_MISC_COMM_EXEC 0x2000
#endif

/* Record types */
#ifndef PERF_RECORD_MMAP2
#define PERF_RECORD_MMAP2     10
#endif

/* Event IDs: on-CPU uses kernel-assigned; off-CPU uses synthetic */
#define OFFCPU_EVENT_ID_BASE  1001

/* Number of event attributes (1 on-CPU + 5 off-CPU subclasses) */
#define BPERF_NR_EVENTS  6

/* Event name strings indexed by attr index (default 6-event mode) */
static const char * const bperf_event_names[BPERF_NR_EVENTS]
	__attribute__((unused)) = {
	"task-clock",
	"offcpu-sched",
	"offcpu-iowait",
	"offcpu-interruptible",
	"offcpu-uninterruptible",
	"offcpu-other",
};

/* Event name for combined (single-event) mode */
static const char * const bperf_combined_event_name
	__attribute__((unused)) = "wall-clock";

#endif /* PERF_FILE_H */
