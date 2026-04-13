/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
#ifndef PROC_H
#define PROC_H

#include <stdint.h>

/*
 * /proc parser for process memory maps, comm names, and thread enumeration.
 */

/* Parsed MMAP2 info from /proc/<pid>/maps */
struct proc_map {
	uint64_t addr;
	uint64_t len;
	uint64_t pgoff;
	uint32_t maj;
	uint32_t min;
	uint64_t ino;
	uint32_t prot;      /* PROT_READ | PROT_WRITE | PROT_EXEC */
	uint32_t flags;     /* MAP_PRIVATE | MAP_SHARED */
	char     filename[256];
};

struct proc_map_list {
	struct proc_map *maps;
	int nr;
	int cap;
};

/* Thread info */
struct proc_thread {
	pid_t pid;    /* tgid */
	pid_t tid;    /* thread tid */
	char  comm[16];
};

struct proc_thread_list {
	struct proc_thread *threads;
	int nr;
	int cap;
};

/* Parse /proc/<pid>/maps into a list of mappings. */
int proc_read_maps(pid_t pid, struct proc_map_list *list);

/* Read /proc/<pid>/comm. Returns 0 on success, fills comm (max 16). */
int proc_read_comm(pid_t pid, char *comm, int size);

/* Enumerate /proc/PID/task and read each thread's comm. */
int proc_read_threads(pid_t pid, struct proc_thread_list *list);

/* Add a kernel ([kernel.kallsyms]) mapping entry. */
int proc_add_kernel_map(struct proc_map_list *list);

/*
 * Kernel symbol info for filtering BPF infrastructure frames
 * from off-CPU kernel stacks.
 */
#define KERN_MAX_TRAMP_ADDRS 32

struct kern_sym_info {
	uint64_t text_start;   /* vmlinux text range start */
	uint64_t text_end;     /* vmlinux text range end (exclusive) */
	uint64_t tramp_addrs[KERN_MAX_TRAMP_ADDRS]; /* BPF trampoline fn addrs */
	int      nr_tramp;
};

/*
 * Read /proc/kallsyms to determine kernel text range and collect
 * addresses of BPF trampoline functions (bpf_trace_run*, __bpf_trace_*).
 */
int proc_read_kern_sym_info(struct kern_sym_info *info);

/* Free helpers */
void proc_map_list_init(struct proc_map_list *list);
void proc_map_list_free(struct proc_map_list *list);
void proc_thread_list_init(struct proc_thread_list *list);
void proc_thread_list_free(struct proc_thread_list *list);

#endif /* PROC_H */
