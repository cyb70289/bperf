/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
#ifndef RECORD_H
#define RECORD_H

/*
 * bperf record — main recording orchestration.
 */

struct record_opts {
	pid_t   pid;            /* target PID, or 0 if command mode / system-wide */
	int     system_wide;    /* -a flag */
	int     freq;           /* sampling frequency (Hz) */
	int     exclude_kernel; /* --no-kernel */
	int     min_block_us;   /* --min-block (microseconds) */
	int     duration_sec;   /* -d, 0 = until Ctrl-C */
	int     max_stack;      /* --stack-depth */
	int     ringbuf_mb;     /* --ringbuf-size (MB) */
	int     combined;       /* --combined: single wall-clock event */
	int     flamegraph;     /* --flamegraph: generate SVG after recording */
	char   *output;         /* -o output file */
	int     cmd_argc;       /* command args after -- */
	char  **cmd_argv;
	int     prog_argc;      /* original full argc */
	char  **prog_argv;      /* original full argv */
};

/* Run the recording session. Returns 0 on success. */
int record_run(struct record_opts *opts);

#endif /* RECORD_H */
