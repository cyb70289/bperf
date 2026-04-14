/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * record.c - bperf record: main recording orchestration
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <limits.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <time.h>

#include "record.h"
#include "oncpu.h"
#include "offcpu.h"
#include "writer.h"
#include "proc.h"
#include "perf_file.h"
#include "bperf_common.h"

static volatile sig_atomic_t g_stop = 0;
static volatile sig_atomic_t g_child_exited = 0;

static void sig_handler(int sig)
{
	if (sig == SIGCHLD)
		g_child_exited = 1;
	g_stop = 1;
}

/*
 * Generate an SVG flamegraph from the perf.data output.
 *
 * Resolves the bundled FlameGraph scripts relative to the bperf binary
 * using /proc/self/exe, then runs:
 *   perf script -i <data> | stackcollapse-perf.pl --all | flamegraph.pl > <data>.svg
 *
 * Returns 0 on success, -1 on failure (non-fatal — perf.data is already written).
 */
static int run_flamegraph_pipeline(const char *data_path)
{
	char exe_path[PATH_MAX];
	ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
	if (len < 0) {
		fprintf(stderr, "bperf: flamegraph: cannot resolve /proc/self/exe: %s\n",
			strerror(errno));
		return -1;
	}
	exe_path[len] = '\0';

	/* Strip binary name to get directory */
	char *slash = strrchr(exe_path, '/');
	if (slash)
		*(slash + 1) = '\0';
	else
		strcpy(exe_path, "./");

	/* Build paths to bundled scripts */
	char collapse_path[PATH_MAX];
	char flamegraph_path[PATH_MAX];
	snprintf(collapse_path, sizeof(collapse_path),
		 "%sflamegraph/stackcollapse-perf.pl", exe_path);
	snprintf(flamegraph_path, sizeof(flamegraph_path),
		 "%sflamegraph/flamegraph.pl", exe_path);

	/* Verify scripts exist */
	if (access(collapse_path, X_OK) != 0) {
		fprintf(stderr, "bperf: flamegraph: %s not found or not executable\n",
			collapse_path);
		return -1;
	}
	if (access(flamegraph_path, X_OK) != 0) {
		fprintf(stderr, "bperf: flamegraph: %s not found or not executable\n",
			flamegraph_path);
		return -1;
	}

	/* Build the SVG output path */
	char svg_path[PATH_MAX];
	snprintf(svg_path, sizeof(svg_path), "%s.svg", data_path);

	/* Build and run the pipeline */
	char cmd[PATH_MAX * 4];
	snprintf(cmd, sizeof(cmd),
		 "perf script -i '%s' | '%s' --all | '%s' --color=wallclock"
		 " --title='bperf Wall Clock' --countname=ns > '%s'",
		 data_path, collapse_path, flamegraph_path, svg_path);

	fprintf(stderr, "bperf: generating flamegraph...\n");
	int rc = system(cmd);
	if (rc != 0) {
		fprintf(stderr, "bperf: flamegraph pipeline failed (exit %d)\n", rc);
		/* Remove empty/partial SVG */
		unlink(svg_path);
		return -1;
	}

	fprintf(stderr, "bperf: flamegraph written to %s\n", svg_path);
	return 0;
}

int record_run(struct record_opts *opts)
{
	int ret = -1;
	struct oncpu_ctx *oncpu = NULL;
	struct offcpu_ctx *offcpu = NULL;
	int epoll_fd = -1;
	pid_t child_pid = 0;

	struct raw_record_buf oncpu_buf;
	struct offcpu_event_buf offcpu_buf;
	struct resolved_stack_map stack_map;
	struct proc_map_list map_list;
	struct proc_thread_list thread_list;

	raw_record_buf_init(&oncpu_buf);
	offcpu_event_buf_init(&offcpu_buf);
	resolved_stack_map_init(&stack_map);
	proc_map_list_init(&map_list);
	proc_thread_list_init(&thread_list);

	/* Install signal handlers */
	struct sigaction sa = {0};
	sa.sa_handler = sig_handler;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGCHLD, &sa, NULL);

	/* ── Command mode: fork + exec ─────────────────────────────── */

	if (opts->cmd_argc > 0) {
		/*
		 * We use a pipe to synchronize: the child blocks on read
		 * until the parent has set up profiling, then we close the
		 * pipe to unblock.
		 */
		int sync_pipe[2];
		if (pipe(sync_pipe) < 0) {
			perror("pipe");
			goto out;
		}

		child_pid = fork();
		if (child_pid < 0) {
			perror("fork");
			close(sync_pipe[0]);
			close(sync_pipe[1]);
			goto out;
		}

		if (child_pid == 0) {
			/* Child: wait for parent to set up profiling */
			close(sync_pipe[1]);
			char c;
			if (read(sync_pipe[0], &c, 1) < 0)
				_exit(126);
			close(sync_pipe[0]);

			execvp(opts->cmd_argv[0], opts->cmd_argv);
			perror("execvp");
			_exit(127);
		}

		/* Parent */
		close(sync_pipe[0]);
		opts->pid = child_pid;

		/* We'll close sync_pipe[1] after setup to unblock child */
		/* Store for later */
		int sync_fd = sync_pipe[1];

		/* Set up profiling for the child PID */
		fprintf(stderr, "bperf: profiling command '%s' (pid %d)\n",
			opts->cmd_argv[0], child_pid);

		/* ── Set up on-CPU collection ──────────────────────── */
		struct oncpu_params oncpu_params = {
			.pid = opts->pid,
			.freq = opts->freq,
			.system_wide = 0,
			.exclude_kernel = opts->exclude_kernel,
			.max_stack = opts->max_stack,
		};
		oncpu = oncpu_open(&oncpu_params);
		if (!oncpu) {
			fprintf(stderr, "bperf: failed to set up on-CPU profiling\n");
			kill(child_pid, SIGKILL);
			close(sync_fd);
			goto out;
		}

		/* ── Set up off-CPU collection ─────────────────────── */
		struct offcpu_params offcpu_params = {
			.target_tgid = opts->pid,
			.min_duration_ns = (uint64_t)opts->min_block_us * 1000,
			.ringbuf_size = (uint32_t)opts->ringbuf_mb * 1024 * 1024,
		};
		offcpu = offcpu_open(&offcpu_params);
		if (!offcpu) {
			fprintf(stderr, "bperf: failed to set up off-CPU profiling\n");
			kill(child_pid, SIGKILL);
			close(sync_fd);
			goto out;
		}

		/* Unblock child */
		close(sync_fd);

		goto start_collection;
	}

	/* ── PID or system-wide mode ───────────────────────────────── */

	{
		pid_t target_pid = opts->pid;
		int system_wide = opts->system_wide;

		if (target_pid > 0) {
			/*
			 * Determine if the user gave us a TGID (process leader)
			 * or a TID (specific thread).  This affects:
			 *  - on-CPU: TGID → enumerate all threads; TID → single thread
			 *  - off-CPU: always filter by real TGID, optionally by TID
			 */
			pid_t real_tgid = proc_read_tgid(target_pid);
			if (real_tgid < 0) {
				fprintf(stderr, "bperf: cannot read /proc/%d/status: "
					"process not found?\n", target_pid);
				goto out;
			}

			pid_t offcpu_tid = 0; /* 0 = all threads */
			if (real_tgid == target_pid) {
				/* User gave us the TGID — profile entire process */
				fprintf(stderr, "bperf: profiling process %d "
					"(all threads) at %d Hz\n",
					target_pid, opts->freq);
			} else {
				/* User gave us a TID — profile that thread only */
				fprintf(stderr, "bperf: profiling thread %d "
					"(process %d) at %d Hz\n",
					target_pid, real_tgid, opts->freq);
				offcpu_tid = target_pid;
			}

			/*
			 * On-CPU: if profiling the whole process, enumerate
			 * all threads and open one perf event per thread.
			 * If profiling a single thread, use the TID directly.
			 */
			struct oncpu_params oncpu_params = {
				.pid = target_pid,
				.freq = opts->freq,
				.system_wide = 0,
				.exclude_kernel = opts->exclude_kernel,
				.max_stack = opts->max_stack,
			};

			struct proc_thread_list tid_list;
			proc_thread_list_init(&tid_list);

			if (real_tgid == target_pid) {
				proc_read_threads(real_tgid, &tid_list);
				if (tid_list.nr > 0) {
					pid_t *tids = malloc(tid_list.nr * sizeof(pid_t));
					if (tids) {
						for (int i = 0; i < tid_list.nr; i++)
							tids[i] = tid_list.threads[i].tid;
						oncpu_params.tids = tids;
						oncpu_params.nr_tids = tid_list.nr;
					}
				}
			}

			oncpu = oncpu_open(&oncpu_params);
			free(oncpu_params.tids);
			if (!oncpu) {
				proc_thread_list_free(&tid_list);
				fprintf(stderr, "bperf: failed to set up on-CPU profiling\n");
				goto out;
			}

			/* Off-CPU: always use real TGID; optionally filter by TID */
			struct offcpu_params offcpu_params = {
				.target_tgid = (uint32_t)real_tgid,
				.target_tid = (uint32_t)offcpu_tid,
				.min_duration_ns = (uint64_t)opts->min_block_us * 1000,
				.ringbuf_size = (uint32_t)opts->ringbuf_mb * 1024 * 1024,
			};
			offcpu = offcpu_open(&offcpu_params);
			proc_thread_list_free(&tid_list);
			if (!offcpu) {
				fprintf(stderr, "bperf: failed to set up off-CPU profiling\n");
				goto out;
			}

			/*
			 * For /proc reads later, use the TGID so we get maps/threads
			 * for the whole process regardless of single-thread mode.
			 */
			opts->pid = real_tgid;

		} else if (system_wide) {
			fprintf(stderr, "bperf: system-wide profiling at %d Hz\n",
				opts->freq);

			struct oncpu_params oncpu_params = {
				.pid = -1,
				.freq = opts->freq,
				.system_wide = 1,
				.exclude_kernel = opts->exclude_kernel,
				.max_stack = opts->max_stack,
			};
			oncpu = oncpu_open(&oncpu_params);
			if (!oncpu) {
				fprintf(stderr, "bperf: failed to set up on-CPU profiling\n");
				goto out;
			}

			struct offcpu_params offcpu_params = {
				.target_tgid = 0,
				.target_tid = 0,
				.min_duration_ns = (uint64_t)opts->min_block_us * 1000,
				.ringbuf_size = (uint32_t)opts->ringbuf_mb * 1024 * 1024,
			};
			offcpu = offcpu_open(&offcpu_params);
			if (!offcpu) {
				fprintf(stderr, "bperf: failed to set up off-CPU profiling\n");
				goto out;
			}
		} else {
			fprintf(stderr, "bperf: no target specified, use -p PID, -a, or -- command\n");
			goto out;
		}
	}

start_collection:

	/* ── Read /proc info ───────────────────────────────────────── */

	if (opts->cmd_argc > 0) {
		/*
		 * Command mode: the child hasn't exec'd yet (it's blocked
		 * on the sync pipe that we just closed). Reading /proc now
		 * would get the parent's (bperf) comm and maps.
		 * Rely on kernel-generated COMM/MMAP2 records from the perf
		 * ring buffer instead — they arrive after exec with correct
		 * timestamps (now that we use CLOCK_MONOTONIC for perf too).
		 */
		proc_add_kernel_map(&map_list);
	} else if (opts->pid > 0 && !opts->system_wide) {
		proc_read_maps(opts->pid, &map_list);
		proc_read_threads(opts->pid, &thread_list);
		proc_add_kernel_map(&map_list);
	} else {
		/* System-wide: add kernel mapping */
		proc_add_kernel_map(&map_list);
		/* We'll rely on MMAP2/COMM records from perf for processes */
	}

	/* ── Set up epoll ──────────────────────────────────────────── */

	epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (epoll_fd < 0) {
		perror("epoll_create1");
		goto out;
	}

	/* Add on-CPU perf fds */
	int *perf_fds;
	int nr_perf_fds;
	oncpu_get_fds(oncpu, &perf_fds, &nr_perf_fds);
	for (int i = 0; i < nr_perf_fds; i++) {
		struct epoll_event ev = {
			.events = EPOLLIN,
			.data.fd = perf_fds[i],
		};
		epoll_ctl(epoll_fd, EPOLL_CTL_ADD, perf_fds[i], &ev);
	}

	/* Add BPF ring buffer fd */
	int ring_fd = offcpu_get_ring_fd(offcpu);
	{
		struct epoll_event ev = {
			.events = EPOLLIN,
			.data.fd = ring_fd,
		};
		epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ring_fd, &ev);
	}

	/* ── Main collection loop ──────────────────────────────────── */

	struct timespec start_ts;
	clock_gettime(CLOCK_MONOTONIC, &start_ts);

	if (opts->duration_sec > 0)
		fprintf(stderr, "bperf: recording for %d seconds...\n",
			opts->duration_sec);
	else
		fprintf(stderr, "bperf: recording... press Ctrl-C to stop\n");

	while (!g_stop) {
		struct epoll_event events[16];
		int nfds = epoll_wait(epoll_fd, events, 16, 100);

		if (nfds < 0) {
			if (errno == EINTR)
				continue;
			break;
		}

		/* Read on-CPU events */
		oncpu_read(oncpu, &oncpu_buf);

		/* Read off-CPU events */
		offcpu_poll(offcpu, &offcpu_buf, 0);

		/* Check duration */
		if (opts->duration_sec > 0) {
			struct timespec now;
			clock_gettime(CLOCK_MONOTONIC, &now);
			double elapsed = (now.tv_sec - start_ts.tv_sec) +
					 (now.tv_nsec - start_ts.tv_nsec) / 1e9;
			if (elapsed >= opts->duration_sec)
				break;
		}

		/* Check child exit */
		if (g_child_exited && child_pid > 0) {
			int status;
			waitpid(child_pid, &status, WNOHANG);
			break;
		}
	}

	/* ── Finalize ──────────────────────────────────────────────── */

	fprintf(stderr, "bperf: stopping...\n");

	/* Drain remaining events */
	oncpu_read(oncpu, &oncpu_buf);
	offcpu_poll(offcpu, &offcpu_buf, 0);

	/* Re-read /proc info (in case new mappings appeared) */
	if (opts->pid > 0 && !opts->system_wide && opts->cmd_argc == 0) {
		struct proc_map_list new_maps;
		proc_map_list_init(&new_maps);
		proc_read_maps(opts->pid, &new_maps);
		/* Merge (just use new list — it's more complete) */
		if (new_maps.nr > 0) {
			/* Keep kernel map from original list */
			for (int i = 0; i < map_list.nr; i++) {
				if (strncmp(map_list.maps[i].filename,
					    "[kernel.", 8) == 0) {
					proc_map_list_init(&new_maps);
					proc_read_maps(opts->pid, &new_maps);
					/* Add kernel map back */
					proc_add_kernel_map(&new_maps);
					break;
				}
			}
			proc_map_list_free(&map_list);
			map_list = new_maps;
		} else {
			proc_map_list_free(&new_maps);
		}
	}

	/* Dump stack traces from BPF map */
	offcpu_dump_stacks(offcpu, &stack_map);

	/* Count events by type */
	int oncpu_samples = 0;
	for (int i = 0; i < oncpu_buf.nr; i++) {
		if (oncpu_buf.entries[i].type == PERF_RECORD_SAMPLE)
			oncpu_samples++;
	}

	int offcpu_by_subclass[OFFCPU_SUBCLASS_MAX + 1] = {0};
	for (int i = 0; i < offcpu_buf.nr; i++) {
		int sc = offcpu_buf.entries[i].subclass;
		if (sc >= 1 && sc <= OFFCPU_SUBCLASS_MAX)
			offcpu_by_subclass[sc]++;
	}

	fprintf(stderr, "bperf: on-CPU samples: %d\n", oncpu_samples);
	fprintf(stderr, "bperf: off-CPU events: %d\n", offcpu_buf.nr);
	fprintf(stderr, "bperf:   offcpu-sched: %d\n",
		offcpu_by_subclass[OFFCPU_SUBCLASS_SCHED]);
	fprintf(stderr, "bperf:   offcpu-iowait: %d\n",
		offcpu_by_subclass[OFFCPU_SUBCLASS_IOWAIT]);
	fprintf(stderr, "bperf:   offcpu-interruptible: %d\n",
		offcpu_by_subclass[OFFCPU_SUBCLASS_INTERRUPTIBLE]);
	fprintf(stderr, "bperf:   offcpu-uninterruptible: %d\n",
		offcpu_by_subclass[OFFCPU_SUBCLASS_UNINTERRUPTIBLE]);
	fprintf(stderr, "bperf:   offcpu-other: %d\n",
		offcpu_by_subclass[OFFCPU_SUBCLASS_OTHER]);
	fprintf(stderr, "bperf: unique stacks: %d\n", stack_map.nr);

	/* ── Write perf.data ───────────────────────────────────────── */

	struct kern_sym_info kern_info;
	proc_read_kern_sym_info(&kern_info);

	struct writer_params wp = {
		.output_path = opts->output,
		.oncpu_attr = oncpu_get_attr(oncpu),
		.oncpu_event_id = oncpu_get_event_id(oncpu),
		.argc = opts->prog_argc,
		.argv = opts->prog_argv,
		.kern_info = kern_info,
	};
	oncpu_get_event_ids(oncpu, &wp.oncpu_event_ids, &wp.nr_oncpu_ids);

	ret = writer_write(&wp, &oncpu_buf, &offcpu_buf, &stack_map,
			   &map_list, &thread_list);
	if (ret == 0) {
		fprintf(stderr, "bperf: output written to %s\n", opts->output);
		if (!opts->no_flamegraph)
			run_flamegraph_pipeline(opts->output);
	} else {
		fprintf(stderr, "bperf: failed to write output\n");
	}

out:
	if (epoll_fd >= 0)
		close(epoll_fd);
	offcpu_close(offcpu);
	oncpu_close(oncpu);
	raw_record_buf_free(&oncpu_buf);
	offcpu_event_buf_free(&offcpu_buf);
	resolved_stack_map_free(&stack_map);
	proc_map_list_free(&map_list);
	proc_thread_list_free(&thread_list);

	/* Reap child */
	if (child_pid > 0) {
		int status;
		waitpid(child_pid, &status, 0);
	}

	return ret;
}
