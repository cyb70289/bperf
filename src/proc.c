/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * proc.c - /proc parser for process maps, comm, and thread enumeration
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>

#include "proc.h"

/* ── List helpers ─────────────────────────────────────────────────── */

void proc_map_list_init(struct proc_map_list *list)
{
	memset(list, 0, sizeof(*list));
}

void proc_map_list_free(struct proc_map_list *list)
{
	free(list->maps);
	memset(list, 0, sizeof(*list));
}

static int proc_map_list_append(struct proc_map_list *list,
				const struct proc_map *map)
{
	if (list->nr >= list->cap) {
		int newcap = list->cap ? list->cap * 2 : 256;
		struct proc_map *tmp = realloc(list->maps,
					       newcap * sizeof(*tmp));
		if (!tmp)
			return -ENOMEM;
		list->maps = tmp;
		list->cap = newcap;
	}
	list->maps[list->nr++] = *map;
	return 0;
}

void proc_thread_list_init(struct proc_thread_list *list)
{
	memset(list, 0, sizeof(*list));
}

void proc_thread_list_free(struct proc_thread_list *list)
{
	free(list->threads);
	memset(list, 0, sizeof(*list));
}

static int proc_thread_list_append(struct proc_thread_list *list,
				   const struct proc_thread *th)
{
	if (list->nr >= list->cap) {
		int newcap = list->cap ? list->cap * 2 : 64;
		struct proc_thread *tmp = realloc(list->threads,
						  newcap * sizeof(*tmp));
		if (!tmp)
			return -ENOMEM;
		list->threads = tmp;
		list->cap = newcap;
	}
	list->threads[list->nr++] = *th;
	return 0;
}

/* ── /proc/<pid>/maps parser ──────────────────────────────────────── */

/*
 * Parse lines like:
 *   55a234000000-55a234020000 r-xp 00000000 08:01 1234567 /usr/bin/myapp
 *   7fff12340000-7fff12360000 rw-p 00000000 00:00 0       [stack]
 */
int proc_read_maps(pid_t pid, struct proc_map_list *list)
{
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/maps", pid);

	FILE *fp = fopen(path, "r");
	if (!fp)
		return -errno;

	char line[512];
	while (fgets(line, sizeof(line), fp)) {
		struct proc_map m = {0};
		uint64_t start, end;
		char perms[5] = {0};
		unsigned int maj, min;
		uint64_t ino;
		uint64_t pgoff;
		char filename[256] = {0};

		int n = sscanf(line, "%lx-%lx %4s %lx %x:%x %lu %255[^\n]",
			       &start, &end, perms, &pgoff, &maj, &min,
			       &ino, filename);
		if (n < 7)
			continue;

		/* Skip non-file-backed anonymous mappings unless named */
		if (n < 8 || filename[0] == '\0')
			continue;

		/* Skip [vvar] and similar non-useful mappings */
		if (strcmp(filename, "[vvar]") == 0 ||
		    strcmp(filename, "[vdso]") == 0 ||
		    strcmp(filename, "[vsyscall]") == 0)
			continue;

		m.addr = start;
		m.len = end - start;
		m.pgoff = pgoff;
		m.maj = maj;
		m.min = min;
		m.ino = ino;
		snprintf(m.filename, sizeof(m.filename), "%s", filename);

		/* Parse prot/flags from perms string (e.g., "r-xp") */
		m.prot = 0;
		if (perms[0] == 'r') m.prot |= 1; /* PROT_READ */
		if (perms[1] == 'w') m.prot |= 2; /* PROT_WRITE */
		if (perms[2] == 'x') m.prot |= 4; /* PROT_EXEC */

		m.flags = (perms[3] == 'p') ? 2 : 1; /* MAP_PRIVATE : MAP_SHARED */

		proc_map_list_append(list, &m);
	}

	fclose(fp);
	return 0;
}

/* ── /proc/<pid>/comm ─────────────────────────────────────────────── */

int proc_read_comm(pid_t pid, char *comm, int size)
{
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/comm", pid);

	FILE *fp = fopen(path, "r");
	if (!fp)
		return -errno;

	if (!fgets(comm, size, fp)) {
		fclose(fp);
		return -EIO;
	}

	/* Strip trailing newline */
	char *nl = strchr(comm, '\n');
	if (nl)
		*nl = '\0';

	fclose(fp);
	return 0;
}

/* ── /proc/PID/task enumeration ────────────────────────────────────── */

int proc_read_threads(pid_t pid, struct proc_thread_list *list)
{
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/task", pid);

	DIR *dir = opendir(path);
	if (!dir)
		return -errno;

	struct dirent *de;
	while ((de = readdir(dir)) != NULL) {
		if (de->d_name[0] == '.')
			continue;

		pid_t tid = atoi(de->d_name);
		if (tid <= 0)
			continue;

		struct proc_thread th = {
			.pid = pid,
			.tid = tid,
		};

		char tpath[64];
		snprintf(tpath, sizeof(tpath), "/proc/%d/task/%d/comm",
			 pid, tid);
		FILE *fp = fopen(tpath, "r");
		if (fp) {
			if (fgets(th.comm, sizeof(th.comm), fp)) {
				char *nl = strchr(th.comm, '\n');
				if (nl)
					*nl = '\0';
			}
			fclose(fp);
		}

		proc_thread_list_append(list, &th);
	}

	closedir(dir);
	return 0;
}

/* ── Kernel mapping ───────────────────────────────────────────────── */

int proc_add_kernel_map(struct proc_map_list *list)
{
	/*
	 * Synthesize a kernel mapping entry.
	 * The address range covers the typical kernel text range.
	 * On aarch64, the kernel is mapped in the upper VA range.
	 */
	struct proc_map m = {0};

	/* Read /proc/kallsyms to find min/max kernel addresses */
	FILE *fp = fopen("/proc/kallsyms", "r");
	if (!fp) {
		/* Fallback: use a conventional range */
		m.addr = 0xffff000000000000ULL;
		m.len  = 0x0000ffffffffffffULL;
		strncpy(m.filename, "[kernel.kallsyms]_text",
			sizeof(m.filename) - 1);
		m.prot = 5; /* r-x */
		m.flags = 0;
		return proc_map_list_append(list, &m);
	}

	uint64_t min_addr = UINT64_MAX, max_addr = 0;
	uint64_t ktext = 0;
	char line[256];
	while (fgets(line, sizeof(line), fp)) {
		uint64_t addr;
		char type;
		char name[256] = {0};
		if (sscanf(line, "%lx %c %255s", &addr, &type, name) < 2)
			continue;
		if (addr == 0)
			continue;
		if (type == 'T' || type == 't') {
			if (addr < min_addr)
				min_addr = addr;
			if (addr > max_addr)
				max_addr = addr;
		}
		if (strcmp(name, "_text") == 0 && (type == 'T' || type == 't'))
			ktext = addr;
	}
	fclose(fp);

	if (min_addr >= max_addr) {
		min_addr = 0xffff000000000000ULL;
		max_addr = 0xffffffffffffffffULL;
	}

	m.addr = min_addr;
	m.len = max_addr - min_addr + 4096;
	/*
	 * Set pgoff to the _text address.  The filename suffix "_text"
	 * tells perf the ref_reloc_sym name is "_text", and pgoff
	 * provides its address.  With pgoff matching the actual _text
	 * symbol, perf computes zero relocation and resolves kernel
	 * symbols correctly.  A zero pgoff would trigger a false
	 * "Kernel address maps were restricted" warning.
	 */
	m.pgoff = ktext ? ktext : min_addr;
	strncpy(m.filename, "[kernel.kallsyms]_text",
		sizeof(m.filename) - 1);
	m.prot = 5; /* r-x */
	m.flags = 0;

	return proc_map_list_append(list, &m);
}

/* ── Kernel symbol info for BPF JIT frame filtering ──────────────── */

int proc_read_kern_sym_info(struct kern_sym_info *info)
{
	memset(info, 0, sizeof(*info));
	info->text_start = 0;
	info->text_end = UINT64_MAX;

	FILE *fp = fopen("/proc/kallsyms", "r");
	if (!fp)
		return -errno;

	uint64_t stext = 0, etext = 0;
	char line[512];

	while (fgets(line, sizeof(line), fp)) {
		uint64_t addr;
		char type;
		char name[256];

		if (sscanf(line, "%lx %c %255s", &addr, &type, name) < 3)
			continue;
		if (addr == 0)
			continue;

		/*
		 * Use _stext and _etext to determine the vmlinux core text
		 * range.  This excludes kernel modules and BPF JIT regions
		 * which lie outside the vmlinux image.  Using min/max of
		 * all T/t symbols would include modules and accidentally
		 * encompass BPF JIT addresses.
		 */
		if (strcmp(name, "_stext") == 0 && (type == 'T' || type == 't'))
			stext = addr;
		if (strcmp(name, "_etext") == 0)
			etext = addr;
	}
	fclose(fp);

	if (stext && etext && stext < etext) {
		info->text_start = stext;
		info->text_end = etext;
	}

	return 0;
}

/* ── Read TGID from /proc/PID/status ─────────────────────────────── */

pid_t proc_read_tgid(pid_t pid)
{
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/status", pid);

	FILE *fp = fopen(path, "r");
	if (!fp)
		return -1;

	pid_t tgid = -1;
	char line[256];
	while (fgets(line, sizeof(line), fp)) {
		if (sscanf(line, "Tgid:\t%d", &tgid) == 1)
			break;
	}
	fclose(fp);
	return tgid;
}
