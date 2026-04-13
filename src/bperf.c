/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * bperf.c - CLI entry point for the unified on/off-CPU profiler
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

#include "record.h"

static void usage(void)
{
	fprintf(stderr,
"bperf - Unified on/off-CPU profiler using eBPF\n"
"\n"
"USAGE:\n"
"    bperf record [OPTIONS] [-- command [args...]]\n"
"\n"
"RECORD OPTIONS:\n"
"    -p, --pid <PID>         Profile a specific process\n"
"    -a, --all-cpus          System-wide profiling\n"
"    -F, --freq <HZ>         On-CPU sampling frequency [default: 99]\n"
"    --no-kernel             Exclude kernel call chains\n"
"    --min-block <USEC>      Minimum off-CPU duration to record [default: 1]\n"
"    -d, --duration <SEC>    Recording duration [default: until Ctrl-C]\n"
"    -o, --output <FILE>     Output file [default: bperf.data]\n"
"    --stack-depth <N>       Maximum stack depth [default: 127]\n"
"    --ringbuf-size <MB>     BPF ring buffer size [default: 16]\n"
"    -g                      Record call graphs (always on, ignored)\n"
"    -h, --help              Show this help\n"
"\n"
"EXAMPLES:\n"
"    bperf record -p 1234 -F 99 -d 30\n"
"    bperf record -a -d 10 -o system.data\n"
"    bperf record -- ./my_program --arg1 --arg2\n"
"\n"
"ANALYSIS:\n"
"    perf report -i bperf.data\n"
"    perf script -i bperf.data\n"
	);
}

static int cmd_record(int argc, char **argv, int full_argc, char **full_argv)
{
	struct record_opts opts = {
		.pid = 0,
		.system_wide = 0,
		.freq = 99,
		.exclude_kernel = 0,
		.min_block_us = 1,
		.duration_sec = 0,
		.max_stack = 127,
		.ringbuf_mb = 16,
		.output = "bperf.data",
		.cmd_argc = 0,
		.cmd_argv = NULL,
		.prog_argc = full_argc,
		.prog_argv = full_argv,
	};

	static struct option long_options[] = {
		{"pid",          required_argument, 0, 'p'},
		{"all-cpus",     no_argument,       0, 'a'},
		{"freq",         required_argument, 0, 'F'},
		{"no-kernel",    no_argument,       0, 'K'},
		{"min-block",    required_argument, 0, 'm'},
		{"duration",     required_argument, 0, 'd'},
		{"output",       required_argument, 0, 'o'},
		{"stack-depth",  required_argument, 0, 'S'},
		{"ringbuf-size", required_argument, 0, 'R'},
		{"help",         no_argument,       0, 'h'},
		{0, 0, 0, 0}
	};

	int opt;
	while ((opt = getopt_long(argc, argv, "p:aF:gd:o:h",
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 'p':
			opts.pid = atoi(optarg);
			break;
		case 'a':
			opts.system_wide = 1;
			break;
		case 'F':
			opts.freq = atoi(optarg);
			break;
		case 'K':
			opts.exclude_kernel = 1;
			break;
		case 'm':
			opts.min_block_us = atoi(optarg);
			break;
		case 'd':
			opts.duration_sec = atoi(optarg);
			break;
		case 'o':
			opts.output = optarg;
			break;
		case 'S':
			opts.max_stack = atoi(optarg);
			break;
		case 'R':
			opts.ringbuf_mb = atoi(optarg);
			break;
		case 'g':
			/* Always on, ignore */
			break;
		case 'h':
			usage();
			return 0;
		default:
			usage();
			return 1;
		}
	}

	/* Remaining args after -- are the command to launch */
	if (optind < argc) {
		opts.cmd_argc = argc - optind;
		opts.cmd_argv = &argv[optind];
	}

	/* Validate */
	if (opts.pid <= 0 && !opts.system_wide && opts.cmd_argc == 0) {
		fprintf(stderr, "bperf: specify -p PID, -a, or -- command\n");
		usage();
		return 1;
	}

	if (opts.pid > 0 && opts.system_wide) {
		fprintf(stderr, "bperf: -p and -a are mutually exclusive\n");
		return 1;
	}

	if (opts.freq <= 0 || opts.freq > 10000) {
		fprintf(stderr, "bperf: frequency must be 1-10000 Hz\n");
		return 1;
	}

	/* Need root for BPF */
	if (geteuid() != 0) {
		fprintf(stderr, "bperf: must run as root (for BPF)\n");
		return 1;
	}

	return record_run(&opts);
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage();
		return 1;
	}

	if (strcmp(argv[1], "record") == 0) {
		return cmd_record(argc - 1, argv + 1, argc, argv);
	} else if (strcmp(argv[1], "-h") == 0 ||
		   strcmp(argv[1], "--help") == 0) {
		usage();
		return 0;
	} else {
		fprintf(stderr, "bperf: unknown subcommand '%s'\n", argv[1]);
		usage();
		return 1;
	}
}
