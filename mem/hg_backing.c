/*
 * slab allocator with elastic arenas - page backing: reserve, commit, release
 *
 * Copyright (C) 2026 Yury Kirsanov
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifdef HG_MALLOC

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/resource.h>
#ifdef __OS_linux
#include <sys/vfs.h>
#endif

#include "hg_version.h"
#include "hg_malloc.h"
#include "hg_arena.h"
#include "hg_large.h"
#include "hg_dbg.h"
#include "hg_memlimit.h"
#include "../dprint.h"
#include "../globals.h"
#include "../statistics.h"
#include "../pt_scaling.h"
#include "shm_mem.h"

#ifdef DBG_MALLOC
#include "mem_dbg_hash.h"
#endif

#include "../lib/dbg/struct_hist.h"
#include "hg_backing.h"
#include "hg_buddy.h"

/* Linux values, defined only under __OS_linux: elsewhere the same bits mean
 * something else (0x40000 is MAP_PREFAULT_READ on FreeBSD) */
#ifdef __OS_linux
#ifndef MAP_HUGETLB
#define MAP_HUGETLB 0x40000
#endif
#ifndef MADV_HUGEPAGE
#define MADV_HUGEPAGE 14
#endif
#ifndef MADV_COLLAPSE
#define MADV_COLLAPSE 25
#endif
#ifndef MADV_POPULATE_WRITE
#define MADV_POPULATE_WRITE 23
#endif
#define HG_PROC_SUPER_MAGIC 0x9fa0
#endif /* __OS_linux */

/* probed, as it is not always 2M: a wrong size breaks munmap() and THP */
#define HG_HPS_FALLBACK (2UL * 1024 * 1024)

static unsigned long hg_hps_cached;

static unsigned long hg_hps_ok(unsigned long b)
{
	/* a power of two the grid can use: a chunk fits a page, and a huge
	 * page past 32 MB (arm64 64K-page PMDs) would make every arena small */
	return b >= HG_SMALL_PAGE && b <= (32UL << 20) && !(b & (b - 1)) ? b : 0;
}

/* the page grid: the THP PMD size, which the THP tiers need; the default
 * hugetlb size may differ (default_hugepagesz=1G) */
unsigned long hg_hps(void)
{
	FILE *f;
	char line[256];
	unsigned long kb = 0, pmd = 0;

	if (hg_hps_cached)
		return hg_hps_cached;

	f = fopen("/sys/kernel/mm/transparent_hugepage/hpage_pmd_size", "r");
	if (f) {
		if (fscanf(f, "%lu", &pmd) != 1)
			pmd = 0;
		fclose(f);
	}
	if (!hg_hps_ok(pmd)) {
		f = fopen("/proc/meminfo", "r");
		if (f) {
			while (fgets(line, sizeof line, f)) {
				if (!strncmp(line, "Hugepagesize:", 13)) {
					kb = strtoul(line + 13, NULL, 10);
					break;
				}
			}
			fclose(f);
		}
		pmd = hg_hps_ok(kb * 1024UL);
	}
	hg_hps_cached = pmd ? pmd : HG_HPS_FALLBACK;
	return hg_hps_cached;
}

/* hugetlb pages of the grid's size: total, free and reserved, from sysfs
 * (the meminfo HugePages_* lines describe only the default size); 0 if
 * there is no such pool */
int hg_hugetlb_pool(long *total, long *freep, long *rsvd)
{
	static const char *names[3] = {
		"nr_hugepages", "free_hugepages", "resv_hugepages" };
	long *out[3] = { total, freep, rsvd };
	char path[160];
	FILE *f;
	int i;

	for (i = 0; i < 3; i++) {
		snprintf(path, sizeof path, "/sys/kernel/mm/hugepages/"
			"hugepages-%lukB/%s", HG_HPS >> 10, names[i]);
		*out[i] = -1;
		if ((f = fopen(path, "r"))) {
			if (fscanf(f, "%ld", out[i]) != 1)
				*out[i] = -1;
			fclose(f);
		}
	}
	if (*total < 0 || *freep < 0 || *rsvd < 0) {
		*total = *freep = *rsvd = 0;
		return 0;
	}
	return 1;
}

/* each backing tier is proven by trying it and reading /proc afterwards,
 * never inferred from the kernel version or sysfs alone */

static long hg_proc_field(const char *path, const char *key, int base)
{
	FILE *f;
	char line[256];
	size_t klen = strlen(key);
	long v = -1;

	f = fopen(path, "r");
	if (!f)
		return -1;
	while (fgets(line, sizeof line, f)) {
		if (!strncmp(line, key, klen) && line[klen] == ':') {
			v = strtol(line + klen + 1, NULL, base);
			break;
		}
	}
	fclose(f);
	return v;
}

long hg_meminfo_kb(const char *key)
{
	return hg_proc_field(hg_meminfo_file, key, 10);
}

void hg_meminfo_kb2(const char *k1, long *v1, const char *k2, long *v2)
{
	FILE *f;
	char line[256];
	size_t l1 = strlen(k1), l2 = strlen(k2);

	*v1 = *v2 = -1;
	f = fopen(hg_meminfo_file, "r");
	if (!f)
		return;
	while ((*v1 < 0 || *v2 < 0) && fgets(line, sizeof line, f)) {
		if (*v1 < 0 && !strncmp(line, k1, l1) && line[l1] == ':')
			*v1 = strtol(line + l1 + 1, NULL, 10);
		else if (*v2 < 0 && !strncmp(line, k2, l2) && line[l2] == ':')
			*v2 = strtol(line + l2 + 1, NULL, 10);
	}
	fclose(f);
}

/* a grow's mlock() gets ENOMEM both from RLIMIT_MEMLOCK (hugetlb too) and
 * from an empty hugetlb pool; the helpers below tell the two apart */
#define HG_CAP_IPC_LOCK	14	/* linux/capability.h */

static int hg_has_cap_ipc_lock(void)
{
	FILE *f;
	char line[256];
	unsigned long long eff = 0;
	int found = 0;

	f = fopen("/proc/self/status", "r");
	if (!f)
		return 0;
	while (fgets(line, sizeof line, f)) {
		if (!strncmp(line, "CapEff:", 7)) {
			eff = strtoull(line + 7, NULL, 16);
			found = 1;
			break;
		}
	}
	fclose(f);
	return found && (eff & (1ULL << HG_CAP_IPC_LOCK));
}

/* the RLIMIT_MEMLOCK soft limit in bytes, or 0 when it does not bind:
 * unlimited, unreadable, or lifted by CAP_IPC_LOCK */
unsigned long hg_memlock_limit(void)
{
	struct rlimit rl;

	if (getrlimit(RLIMIT_MEMLOCK, &rl) != 0 || rl.rlim_cur == RLIM_INFINITY)
		return 0;
	if (hg_has_cap_ipc_lock())
		return 0;
	return (unsigned long)rl.rlim_cur;
}

enum hg_grow_refusal hg_mlock_refusal_why(unsigned long lim, long locked_kb,
		unsigned long delta, int hugetlb, long free_pg, long rsvd_pg,
		long page_kb)
{
	if (locked_kb < 0)
		locked_kb = 0;
	if (lim && ((unsigned long long)locked_kb << 10) + delta > lim)
		return HG_GR_MEMLOCK;
	/* more reserved than free is an empty pool, not a huge one */
	if (hugetlb && free_pg >= 0 && rsvd_pg >= 0 && page_kb > 0 &&
	    (unsigned long long)(free_pg > rsvd_pg ? free_pg - rsvd_pg : 0) *
	    ((unsigned long long)page_kb << 10) < delta)
		return HG_GR_HUGETLB_POOL;
	return HG_GR_MLOCK;
}

static enum hg_grow_refusal hg_mlock_refusal(struct hg_block *hb,
		unsigned long delta, int err, int say)
{
	unsigned long lim = hg_memlock_limit();
	long locked_kb = hg_proc_field("/proc/self/status", "VmLck", 10);
	long free_pg = -1, rsvd_pg = -1, page_kb = -1;
	enum hg_grow_refusal why;

	if (hb->tier == HG_MEM_HUGETLB) {
		long total;

		hg_hugetlb_pool(&total, &free_pg, &rsvd_pg);
		page_kb = (long)(HG_HPS >> 10);
	}
	why = hg_mlock_refusal_why(lim, locked_kb, delta,
		hb->tier == HG_MEM_HUGETLB, free_pg, rsvd_pg, page_kb);
	if (!say)
		return why;
	if (locked_kb < 0)
		locked_kb = 0;

	if (why == HG_GR_MEMLOCK)
		LM_WARN("%s: cannot grow by %lu MB: RLIMIT_MEMLOCK is %lu KB and "
			"this process already has %ld KB locked - every grow is "
			"mlock()ed, on hugetlb as well. Set LimitMEMLOCK=infinity "
			"in the service unit (or ulimit -l unlimited).\n",
			hb->name, delta >> 20, lim >> 10, locked_kb);
	else if (why == HG_GR_HUGETLB_POOL)
		LM_WARN("%s: cannot grow by %lu MB: the hugetlb pool has %ld "
			"free pages of %ld KB, %ld of them already reserved, "
			"and the grow needs %lu. Raise vm.nr_hugepages or "
			"vm.nr_overcommit_hugepages.\n", hb->name, delta >> 20,
			free_pg, page_kb, rsvd_pg,
			delta / ((unsigned long)page_kb << 10));
	else
		LM_WARN("%s: cannot grow by %lu MB: mlock failed (%s), and "
			"neither RLIMIT_MEMLOCK (%s) nor %s accounts for it.\n",
			hb->name, delta >> 20, strerror(err),
			lim ? "set" : "not binding",
			hb->tier == HG_MEM_HUGETLB ? "the hugetlb pool" :
			"the locked-memory total");
	return why;
}

static void hg_mlock_refused(struct hg_block *hb, unsigned long delta, int err)
{
	if (!hb->grow_refuse_said || !hb->grow_refuse_mlock) {
		hb->grow_refuse_mlock = hg_mlock_refusal(hb, delta, err,
			!hb->grow_refuse_said);
		hb->grow_refuse_said = 1;
	}
	hb->grow_refuse_why = hb->grow_refuse_mlock;
}

/* an explicit MADV_COLLAPSE bypasses THP "never" in the kernel, so the
 * policy is honoured here; cached per mapping kind */
static int hg_thp_collapse_denied(int shared)
{
	static int cached[2] = { -1, -1 };
	char buf[128];
	FILE *f;

	if (cached[!!shared] >= 0)
		return cached[!!shared];
	f = fopen(shared ?
		"/sys/kernel/mm/transparent_hugepage/shmem_enabled" :
		"/sys/kernel/mm/transparent_hugepage/enabled", "r");
	if (!f || !fgets(buf, sizeof buf, f)) {
		if (f)
			fclose(f);
		cached[!!shared] = 0;      /* cannot tell - allow it */
		return 0;
	}
	fclose(f);
	cached[!!shared] = strstr(buf, "[never]") != NULL ||
	                   strstr(buf, "[deny]") != NULL;
	return cached[!!shared];
}

const char *hg_4k_reason(int shared)
{
	if (!hg_thp_collapse_denied(shared))
		return "";
	return shared ?
		" - host shmem_enabled is never/deny and this build honours "
		"it; set it to 'advise' to allow the MADV_COLLAPSE retrofit" :
		" - host transparent_hugepage/enabled is never";
}

/* LXCFS serves a container's /proc/meminfo with ShmemHugePages stuck at 0
 * (AnonHugePages too on cgroup v2): count this process's own pages there */
static int hg_meminfo_virtual(void)
{
	static int virt = -1;
#ifdef __OS_linux
	struct statfs sf;

	if (virt < 0) {
		virt = statfs("/proc/meminfo", &sf) == 0 &&
		       sf.f_type != HG_PROC_SUPER_MAGIC;
		if (virt)
			LM_INFO("/proc/meminfo is not procfs (LXCFS?): huge pages "
				"are counted from /proc/self/smaps_rollup\n");
	}
#else
	virt = 0;
#endif
	return virt;
}

/* shared anon memory shows up in ShmemHugePages, private in AnonHugePages;
 * smaps_rollup counts the shared kind mapped here as ShmemPmdMapped */
static long hg_read_huge_kb(int shared)
{
	if (hg_meminfo_virtual())
		return hg_proc_field("/proc/self/smaps_rollup",
			shared ? "ShmemPmdMapped" : "AnonHugePages", 10);
	return hg_meminfo_kb(shared ? "ShmemHugePages" : "AnonHugePages");
}

/* the counter's delta (O(1) from meminfo, unlike smaps); 90% must show, so
 * a partial populate fails */
static int hg_delta_is_huge(long before_kb, long after_kb, unsigned long len)
{
	return before_kb >= 0 && after_kb >= 0 &&
	       after_kb - before_kb >= (long)(len / 1024) * 9 / 10;
}


/* arenas are dumped like any allocator's memory, so a core holds shm and
 * pkg; HG_DUMP_ARENA=0 in the environment keeps them out (a large fixed
 * arena is in every core otherwise) */
static void hg_exclude_from_core(void *base, unsigned long size)
{
#ifdef MADV_DONTDUMP
	const char *want = getenv("HG_DUMP_ARENA");

	if (want && *want == '0')
		madvise(base, size, MADV_DONTDUMP);
#endif
}

#ifdef __OS_linux
/* MAP_HUGETLB refused @bytes although a pool exists: say why, as the tier
 * line that follows names only the THP policy */
static void hg_hugetlb_refused(unsigned long bytes, int err)
{
	long total, kb = (long)(HG_HPS >> 10), freep, rsvd, v;
	char nodes[256], path[128];
	unsigned long need;
	int n, len = 0;
	FILE *f;

	if (!hg_hugetlb_pool(&total, &freep, &rsvd) || total <= 0)
		return;
	need = bytes / ((unsigned long)kb << 10);
	if (freep - rsvd < (long)need) {
		LM_NOTICE("hugetlb pool has %ld free %ld KB pages, %ld of them "
			"reserved, and a %lu MB shared arena needs %lu: it falls "
			"back. Raise vm.nr_hugepages.\n", freep, kb, rsvd,
			bytes >> 20, need);
		return;
	}
	nodes[0] = 0;
	for (n = 0; n < 64 && len < (int)sizeof nodes - 40; n++) {
		snprintf(path, sizeof path, "/sys/devices/system/node/node%d/"
			"hugepages/hugepages-%ldkB/free_hugepages", n, kb);
		if (!(f = fopen(path, "r")))
			continue;
		if (fscanf(f, "%ld", &v) == 1)
			len += snprintf(nodes + len, sizeof nodes - len, "%snode%d %ld",
				len ? ", " : "", n, v);
		fclose(f);
	}
	LM_WARN("MAP_HUGETLB refused a %lu MB shared arena (%s) although the pool "
		"has %ld free %ld KB pages (%s): a NUMA binding (numactl, a cpuset) "
		"leaving out the nodes that hold them, or a hugetlb cgroup limit, "
		"makes the kernel refuse.\n", bytes >> 20, strerror(err),
		freep - rsvd, kb, nodes[0] ? nodes : "per node unknown");
}
#endif

/* MAP_HUGETLB of the grid's page size, not the default hugetlb size */
static inline int hg_map_huge_size(void)
{
#ifdef MAP_HUGE_SHIFT
	return __builtin_ctzl(HG_HPS) << MAP_HUGE_SHIFT;
#else
	return 0;
#endif
}

/* reserve >= @size, aligned and pinned, on huge pages where possible; NULL
 * only if mmap fails. pkg must be !@shared: each worker needs its own copy */
void *hg_mem_reserve(unsigned long size, unsigned long *cap,
		enum hg_mem_tier *tier, unsigned long *locked_b, int shared,
		unsigned long apage)
{
	unsigned long asize = hg_page_round(size, apage);
	unsigned long csize = hg_page_round(*cap < size ? size : *cap, apage);
	int vis = shared ? MAP_SHARED : MAP_PRIVATE;
	int small = apage < HG_HPS;
	char *resv, *base;
	long shmem_kb;
	void *p;

	*locked_b = 0;
	*tier = HG_MEM_4K;
	*cap = csize;

#ifndef __OS_linux
	/* no verified huge-page route outside Linux: the 4K tier */
	p = mmap(NULL, csize, PROT_READ|PROT_WRITE, vis|MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED)
		return NULL;
	hg_exclude_from_core(p, csize);
	if (mlock(p, asize) == 0)
		*locked_b = asize;
	else
		memset(p, 0, asize);
	return p;
#else

	/* tier 1: MAP_HUGETLB, shared only (a COW fault on an empty pool is a
	 * SIGBUS): the whole cap, else INIT alone to keep the huge pages */
	p = (!shared || small || config_check) ? MAP_FAILED :
	    mmap(NULL, csize, PROT_READ|PROT_WRITE,
	         vis|MAP_ANONYMOUS|MAP_HUGETLB|hg_map_huge_size(), -1, 0);
	if (p == MAP_FAILED && shared && !small && !config_check &&
	    csize > asize) {
		p = mmap(NULL, asize, PROT_READ|PROT_WRITE,
		         vis|MAP_ANONYMOUS|MAP_HUGETLB|hg_map_huge_size(), -1, 0);
		if (p != MAP_FAILED) {
			LM_NOTICE("hugetlb pool cannot back a %lu MB cap; "
				"reserving the %lu MB in use instead - the arena "
				"keeps huge pages but cannot grow. Raise "
				"vm.nr_hugepages to allow growth.\n",
				csize >> 20, asize >> 20);
			*cap = asize;
		}
		/* on total failure csize stays at the full cap for tiers 2-4:
		 * THP reservations are plain VA, which CAN hold the cap */
	}
	if (p == MAP_FAILED && shared && !small && !config_check)
		hg_hugetlb_refused(asize, errno);
	/* populated by mlock, not memset: a fault past a hugetlb cgroup limit
	 * fails the call rather than raising SIGBUS */
	if (p != MAP_FAILED && mlock(p, asize) != 0) {
		LM_WARN("hugetlb pages for the %lu MB shared arena could not be "
			"populated (%s) - falling back to THP\n", asize >> 20,
			strerror(errno));
		munmap(p, *cap);
		*cap = csize;
		p = MAP_FAILED;
	}
	if (p != MAP_FAILED) {
		hg_exclude_from_core(p, *cap);
		*tier = HG_MEM_HUGETLB;
		*locked_b = asize;
		return p;
	}

	/* tiers 2-4: an aligned anon map of the whole cap R/W */
	resv = mmap(NULL, csize + apage, PROT_NONE,
	            MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (resv == MAP_FAILED)
		return NULL;
	base = (char *)(((unsigned long)resv + apage - 1) & ~(apage - 1));
	/* NORESERVE: the cap is address space, committed as the arena grows */
	p = mmap(base, csize, PROT_READ|PROT_WRITE,
	         vis|MAP_ANONYMOUS|MAP_FIXED|MAP_NORESERVE, -1, 0);
	if (p == MAP_FAILED) {
		munmap(resv, csize + apage);
		return NULL;
	}

	hg_exclude_from_core(base, csize);

	/* a config check (-c/-C) only proves the arena can be reserved */
	if (config_check)
		return base;

	/* small mode stops here: THP cannot back a range under one huge page */
	if (small) {
		if (mlock(base, asize) == 0) {
			*locked_b = asize;
		} else {
			LM_WARN("mlock of the %lu KB HG_MALLOC arena failed "
				"(%s): continuing unpinned (swappable)\n",
				asize >> 10, strerror(errno));
			memset(base, 0, asize);        /* still pre-fault */
		}
		return base;
	}

	/* advise huge before first touch (tier 2), then pin: a cold mlock is
	 * also the pre-fault; advising the whole cap lets growth inherit it */
	madvise(base, csize, MADV_HUGEPAGE);
	shmem_kb = hg_read_huge_kb(shared);
	if (mlock(base, asize) == 0) {
		*locked_b = asize;
	} else {
		LM_WARN("mlock of the %lu MB HG_MALLOC arena failed (%s): "
			"continuing unpinned (swappable). If running under "
			"systemd, add LimitMEMLOCK=infinity to the unit.\n",
			asize >> 20, strerror(errno));
		memset(base, 0, asize);
	}

	if (hg_delta_is_huge(shmem_kb, hg_read_huge_kb(shared), asize)) {
		*tier = HG_MEM_THP_ADVISE;
	} else if (shmem_kb >= 0 && !hg_thp_collapse_denied(shared) &&
	           madvise(base, asize, MADV_COLLAPSE) == 0 &&
	           hg_read_huge_kb(shared) - shmem_kb >= (long)(asize / 1024)) {
		*tier = HG_MEM_THP_COLLAPSE;
	} else {
		*tier = HG_MEM_4K;
	}
	return base;
#endif /* __OS_linux */
}

/* 1 when now huge, 0 if host THP policy forbids it, else -errno (often a
 * transient EAGAIN, worth a retry) */
int hg_mem_collapse(struct hg_block *hb, char *base, unsigned long len)
{
#ifdef __OS_linux
	if (hg_thp_collapse_denied(hb->shared))
		return 0;
	return madvise(base, len, MADV_COLLAPSE) == 0 ? 1 : -errno;
#else
	return 0;
#endif
}

const char * const hg_cp_phase_str[HG_CP_PHASES] = {
	"meminfo", "advise", "mlock_populate", "verify", "collapse"
};

#define HG_CP_TIME(phase, stmt) do { \
		hg_ns_t _t0 = hg_now_ns(); \
		stmt; \
		cp_ns[phase] = hg_ns_ul(hg_now_ns() - _t0); \
	} while (0)

/* a failed commit gives back what mlock or a populate faulted in, or it stays
 * committed above the span, counted nowhere */
static void commit_undo(struct hg_block *hb, char *base, unsigned long len)
{
	munlock(base, len);
#ifdef __OS_linux
	madvise(base, len, hb->shared ? MADV_REMOVE : MADV_DONTNEED);
#endif
}

#ifdef __OS_linux
/* the pre-fault without the pin; memset only where the kernel lacks
 * MADV_POPULATE_WRITE (EINVAL, before 5.14) - any other error is a shortage
 * the memset would only turn into an OOM kill */
static int commit_populate(char *base, unsigned long len)
{
	if (madvise(base, len, MADV_POPULATE_WRITE) == 0)
		return 0;
	if (errno != EINVAL)
		return -1;
	memset(base, 0, len);
	return 0;
}

static int commit_populate_refused(struct hg_block *hb, char *base,
		unsigned long delta, int err)
{
	commit_undo(hb, base, delta);
	hb->grow_refuse_why = HG_GR_POPULATE;
	if (!hb->grow_refuse_said) {
		hb->grow_refuse_said = 1;
		LM_WARN("%s: cannot grow by %lu MB: the kernel could not populate "
			"the range (%s) - host or cgroup memory is short\n",
			hb->name, delta >> 20, strerror(err));
	}
	return -1;
}
#endif

/* commit [hbase+off, +delta) via mlock(), which fails with an errno rather
 * than a later SIGBUS; returns the delta's hg_mem_tier, or -1, all undone */
int hg_mem_commit(struct hg_block *hb, unsigned long off, unsigned long delta,
		unsigned long cp_ns[HG_CP_PHASES], int *collapse_later, int *pinned)
{
	char *base = hb->hbase + off;
	int mlock_rc, is_huge, collapsed, i, err;

	for (i = 0; i < HG_CP_PHASES; i++)
		cp_ns[i] = 0;
	*pinned = 0;

	if (off + delta > hb->hcap) {
		LM_BUG("%s: commit of %lu@%lu overruns the %lu byte cap\n",
			hb->name, delta, off, hb->hcap);
		hb->grow_refuse_why = HG_GR_CAP;
		return -1;
	}

	if (hb->tier == HG_MEM_HUGETLB) {
		HG_CP_TIME(HG_CP_MLOCK, mlock_rc = mlock(base, delta));
		if (mlock_rc != 0) {
			err = errno;
			commit_undo(hb, base, delta);
			hg_mlock_refused(hb, delta, err);
			return -1;
		}
		*pinned = 1;
		return HG_MEM_HUGETLB;
	}

#ifdef __OS_linux
	{
		long shmem_kb;

		HG_CP_TIME(HG_CP_MEMINFO, shmem_kb = hg_read_huge_kb(hb->shared));

		/* re-advise the delta: cheap, and a later madvise elsewhere in
		 * the VMA may have split the reserve-time advice */
		HG_CP_TIME(HG_CP_ADVISE, madvise(base, delta, MADV_HUGEPAGE));

		if (hb->unpinned) {
			HG_CP_TIME(HG_CP_MLOCK, mlock_rc = commit_populate(base, delta));
			if (mlock_rc != 0)
				return commit_populate_refused(hb, base, delta, errno);
		} else {
			HG_CP_TIME(HG_CP_MLOCK, mlock_rc = mlock(base, delta));
			err = errno;
			/* off hugetlb the pin is a latency aid, not a must: past
			 * the limit - only then - go on unpinned */
			if (mlock_rc != 0 &&
			    hg_mlock_refusal(hb, delta, err, 0) == HG_GR_MEMLOCK) {
				munlock(base, delta);
				LM_WARN("%s: RLIMIT_MEMLOCK (%lu KB) cannot pin a %lu MB "
					"grow - the arena continues unpinned (swappable). "
					"Set LimitMEMLOCK=infinity in the service unit (or "
					"ulimit -l unlimited) to keep it pinned.\n", hb->name,
					hg_memlock_limit() >> 10, delta >> 20);
				hb->unpinned = 1;
				HG_CP_TIME(HG_CP_MLOCK,
					mlock_rc = commit_populate(base, delta));
				if (mlock_rc != 0)
					return commit_populate_refused(hb, base, delta,
						errno);
			} else if (mlock_rc != 0) {
				commit_undo(hb, base, delta);
				hg_mlock_refused(hb, delta, err);
				return -1;
			} else {
				*pinned = 1;
			}
		}

		/* small mode (pages under a PMD): THP cannot back it, and a
		 * collapse of a sub-PMD range only fails */
		if (hb->hps < HG_HPS)
			return HG_MEM_4K;
		/* the init tier says nothing about this delta's backing */
		HG_CP_TIME(HG_CP_VERIFY, is_huge = hg_delta_is_huge(shmem_kb,
			hg_read_huge_kb(hb->shared), delta));
		if (is_huge)
			return HG_MEM_THP_ADVISE;
		/* a worker waits on this grow, and a collapse takes ms: defer it */
		if (collapse_later && shmem_kb >= 0 &&
		    !hg_thp_collapse_denied(hb->shared)) {
			*collapse_later = 1;
			return HG_MEM_4K;
		}
		HG_CP_TIME(HG_CP_COLLAPSE,
			collapsed = shmem_kb >= 0 &&
			    !hg_thp_collapse_denied(hb->shared) &&
			    madvise(base, delta, MADV_COLLAPSE) == 0 &&
			    hg_read_huge_kb(hb->shared) - shmem_kb >= (long)(delta / 1024));
		if (collapsed)
			return HG_MEM_THP_COLLAPSE;
		return HG_MEM_4K;
	}
#else
	(void)is_huge; (void)collapsed; (void)collapse_later;
	if (mlock(base, delta) != 0)
		memset(base, 0, delta);
	else
		*pinned = 1;
	return HG_MEM_4K;
#endif
}

int hg_mem_release(struct hg_block *hb, unsigned long off, unsigned long len)
{
	char *base = hb->hbase + off;
#ifdef __OS_linux
	int advice = hb->shared ? MADV_REMOVE : MADV_DONTNEED;
#endif

	if (off + len > hb->span_end) {
		LM_BUG("%s: release of %lu@%lu overruns the %lu byte span\n",
			hb->name, len, off, hb->span_end);
		return -1;
	}

#ifndef __OS_linux
	/* no portable release off Linux (MADV_REMOVE is Linux-only, a remap
	 * would unshare the range): the arena keeps its memory */
	(void)base;
	if (!hb->shrink_unsupported) {
		hb->shrink_unsupported = 1;
		LM_NOTICE("%s: returning memory to the OS is Linux-only - this "
			"arena grows but does not shrink here\n", hb->name);
	}
	return -1;
#else
	/* the kernel refuses these advices on locked pages, so unlock first;
	 * a refused advice must then pin the range again */
	munlock(base, len);

	if (madvise(base, len, advice) != 0) {
		int err = errno;

		hb->shrink_unsupported = 1;
		LM_WARN("%s: cannot release memory (%s of %lu MB failed: %s) "
			"- shrink disabled for this arena\n", hb->name,
			hb->shared ? "MADV_REMOVE" : "MADV_DONTNEED",
			len >> 20, strerror(err));
		if (!hb->unpinned && mlock(base, len) != 0) {
			LM_WARN("%s: could not pin the %lu MB again after the refused "
				"release (%s) - they stay committed but unpinned\n",
				hb->name, len >> 20, strerror(errno));
			return -2;
		}
		return -1;
	}
	return 0;
#endif /* __OS_linux */
}

/* re-pins in the calling process, as mlock is not inherited; -1 on hugetlb:
 * the page is gone (refuse), elsewhere it is populated but left unpinned */
int hg_mem_repin(struct hg_block *hb, unsigned long off, unsigned long len,
                 int tier)
{
	char *base = hb->hbase + off;

	if (off + len > hb->span_end) {
		LM_BUG("%s: repin of %lu@%lu is outside the %lu byte span\n",
			hb->name, len, off, hb->span_end);
		return -1;
	}

	if (hb->unpinned) {
#ifdef __OS_linux
		if (commit_populate(base, len) != 0) {
			madvise(base, len, hb->shared ? MADV_REMOVE : MADV_DONTNEED);
			return -1;
		}
#else
		memset(base, 0, len);
#endif
		return 1;
	}

	if (mlock(base, len) != 0) {
		int err = errno;

		hb->repin_failed++;
		if (tier == HG_MEM_HUGETLB) {
			if (!hb->repin_said) {
				hb->repin_said = 1;
				LM_WARN("%s: the hugetlb pool cannot back a "
					"%lu KB page released earlier (%s) - "
					"it "
					"was returned to the pool and is gone; "
					"the request is refused. Raise "
					"vm.nr_hugepages or set "
					"hg_interior_release=0.\n",
					hb->name, len >> 10, strerror(err));
			}
			return -1;           /* NOT touched: nothing is there */
		}
		if (!hb->repin_said) {
			hb->repin_said = 1;
			LM_WARN("%s: could not re-pin a %lu KB page released "
				"earlier (%s) - it is in use again but NOT "
				"pinned from swapping. Watch "
				"hg_shm_repin_failed; raise RLIMIT_MEMLOCK "
				"(LimitMEMLOCK=infinity under systemd) or set "
				"hg_interior_release=0.\n",
				hb->name, len >> 10, strerror(err));
		}
		/* still populate, so the caller gets usable memory */
#ifdef __OS_linux
		if (commit_populate(base, len) != 0) {
			munlock(base, len);
			madvise(base, len, hb->shared ? MADV_REMOVE : MADV_DONTNEED);
			return -1;
		}
#else
		memset(base, 0, len);
#endif
		return 1;
	}
	return 0;
}

/* mlock is per process: a worker's grow stays pinned only while that worker
 * lives, so the maintenance process pins every committed page too. Holes are
 * skipped, and only this process punches or trims a shared arena, so none
 * can appear under it */
void hg_mem_pin_others(struct hg_block *hb)
{
	unsigned long gen, n;

	if (!hb->shared || hb->tier == HG_MEM_HUGETLB || hb->unpinned ||
	    !hb->buddy_ready)
		return;
	/* a binding limit: its own grows need it, or they would go unpinned
	 * for good */
	if (hg_memlock_limit())
		return;
	gen = __atomic_load_n(&hb->pin_gen, __ATOMIC_ACQUIRE);
	if (gen == hb->pin_seen)
		return;
	hg_lock_enter(hb, HG_LK_POLICY);
	n = hb->npages;
	hb->pin_seen = gen;
	hg_lock_leave(hb);
	hg_mem_pin_pages(hb, n);
}

/* mlock every committed page below page @n in this process: the caller
 * owns no range op (maintenance process, or the attendant pre-fork) */
void hg_mem_pin_pages(struct hg_block *hb, unsigned long n)
{
	static int said;
	unsigned long i, j;

	for (i = 0; i < n; i = j) {
		for (j = i; j < n && !hb->pages[j].punched &&
		     !hb->pages[j].releasing; j++)
			;
		if (j > i && mlock(hb->pages[i].base, (j - i) << hb->hps_shift)) {
			if (!said++)
				LM_WARN("%s: the maintenance process cannot pin the "
					"pages workers committed (%s) - they stay "
					"pinned only while the committing worker "
					"lives\n", hb->name, strerror(errno));
			return;
		}
		if (j == i)
			j++;
	}
}

#endif /* HG_MALLOC */
