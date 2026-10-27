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
#include <sys/resource.h>    /* getrlimit(RLIMIT_MEMLOCK) */

#include "hg_version.h"
#include "hg_malloc.h"
#include "hg_arena.h"
#include "hg_large.h"
#include "hg_dbg.h"
#include "hg_memlimit.h"
#include "../dprint.h"
#include "../globals.h"
#include "../statistics.h"
#include "../pt_scaling.h"    /* profiles + counted_max_processes via pt.h */
#include "shm_mem.h"           /* shm_block, for the post-cfg attach */

#ifdef DBG_MALLOC
#include "mem_dbg_hash.h"
#endif

#include "../lib/dbg/struct_hist.h"
#include "hg_backing.h"

/*
 * Linux values, defined ONLY under __OS_linux: elsewhere the same bits mean
 * something else (0x40000 is MAP_PREFAULT_READ on FreeBSD), so mmap() would
 * succeed with unrelated semantics. Other OSes get a plain anonymous mapping.
 */
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
#endif /* __OS_linux */

/*
 * The system's default huge page size, probed once: 2M on x86_64 and on
 * arm64 with 4K pages, 32M with 16K pages, 512M with 64K pages.
 * mmap(MAP_HUGETLB) rounds the mapping up to it, so a wrong value makes the
 * munmap() fail (the arena leaks) and misaligns the THP tiers, which then
 * silently stay on 4K. Falls back to 2M only if /proc/meminfo cannot be read.
 */
#define HG_HPS_FALLBACK (2UL * 1024 * 1024)

static unsigned long hg_hps_cached;

unsigned long hg_hps(void)
{
	FILE *f;
	char line[256];
	unsigned long kb = 0;

	if (hg_hps_cached)
		return hg_hps_cached;

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

	/* must be a power of two for the alignment masks below to work */
	if (kb == 0 || (kb * 1024UL) & ((kb * 1024UL) - 1))
		hg_hps_cached = HG_HPS_FALLBACK;
	else
		hg_hps_cached = kb * 1024UL;

	return hg_hps_cached;
}

/* each backing tier is proven by trying it and reading /proc afterwards,
 * never inferred from the kernel version or sysfs alone */

/* one numeric field ("Key:   value") from a /proc file, parsed in @base;
 * -1 if the file or the field is missing */
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

/*
 * Every grow mlock()s its delta, and mlock() checks RLIMIT_MEMLOCK on
 * hugetlb mappings too. The kernel returns ENOMEM both for that limit and
 * for an empty hugetlb pool; the helpers below tell the two apart.
 */
#define HG_CAP_IPC_LOCK	14	/* linux/capability.h; mlock() ignores the
				 * limit for a process that holds it */

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
	if (hugetlb && free_pg >= 0 && rsvd_pg >= 0 && page_kb > 0 &&
	    (unsigned long long)(free_pg - rsvd_pg) *
	    ((unsigned long long)page_kb << 10) < delta)
		return HG_GR_HUGETLB_POOL;
	return HG_GR_MLOCK;
}

/* why mlock() refused @delta bytes of @hb, with the errno of the failed
 * mlock(); when @say, also the warning that names it */
static enum hg_grow_refusal hg_mlock_refusal(struct hg_block *hb,
		unsigned long delta, int err, int say)
{
	unsigned long lim = hg_memlock_limit();
	long locked_kb = hg_proc_field("/proc/self/status", "VmLck", 10);
	long free_pg = -1, rsvd_pg = -1, page_kb = -1;
	enum hg_grow_refusal why;

	if (hb->tier == HG_MEM_HUGETLB) {
		free_pg = hg_meminfo_kb("HugePages_Free");
		rsvd_pg = hg_meminfo_kb("HugePages_Rsvd");
		page_kb = hg_meminfo_kb("Hugepagesize");
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

/* a grow's mlock() was refused: the cause is classified and logged once per
 * episode (see grow_refuse_said's comment) and recorded every time */
static void hg_mlock_refused(struct hg_block *hb, unsigned long delta, int err)
{
	if (!hb->grow_refuse_said || !hb->grow_refuse_mlock) {
		hb->grow_refuse_mlock = hg_mlock_refusal(hb, delta, err,
			!hb->grow_refuse_said);
		hb->grow_refuse_said = 1;
	}
	hb->grow_refuse_why = hb->grow_refuse_mlock;
}

/*
 * Does the host's THP policy forbid MADV_COLLAPSE for this mapping kind?
 * The kernel lets an explicit MADV_COLLAPSE bypass "never", so the setting
 * is honoured here: "never" or "deny" for shmem, "never" for anon (which
 * has no deny). Read once per kind and cached - it is a host property.
 */
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

/*
 * Why a 4K arena is on 4K, for its startup line, when a host THP setting
 * is the cause: with shmem_enabled=never MADV_COLLAPSE would still give
 * shmem huge pages, so the arena is on 4K because this build honours the
 * setting, and the operator is told which knob changes it. Below Linux 6.1
 * there is no MADV_COLLAPSE at all.
 */
const char *hg_4k_reason(int shared)
{
	if (!hg_thp_collapse_denied(shared))
		return "";
	return shared ?
		" - host shmem_enabled is never/deny and this build honours "
		"it; set it to 'advise' to allow the MADV_COLLAPSE retrofit" :
		" - host transparent_hugepage/enabled is never";
}

/* shared anon memory shows up in ShmemHugePages, private in AnonHugePages */
static long hg_read_huge_kb(int shared)
{
	return hg_meminfo_kb(shared ? "ShmemHugePages" : "AnonHugePages");
}

/*
 * Did a populate of @len bytes land on huge pages? Judged from the
 * system-wide counter delta across it, not from /proc/self/smaps, which
 * walks the page tables of the whole mapping. Huge faults elsewhere can
 * over-count; 90% of the range must show so a partial fallback does not
 * read as success, and a false negative only costs a collapse retry.
 */
static int hg_delta_is_huge(long before_kb, long after_kb, unsigned long len)
{
	return before_kb >= 0 && after_kb >= 0 &&
	       after_kb - before_kb >= (long)(len / 1024) * 9 / 10;
}


/*
 * Keep the arena out of core dumps: it is all resident (pre-faulted and
 * pinned), so every crashing worker would dump the whole reservation.
 * HG_DUMP_ARENA=1 in the environment keeps it in, to debug the allocator;
 * coredump_filter cannot, VM_DONTDUMP overrides it. An environment variable
 * because it applies at allocator init, before the config is parsed.
 * Best effort (MADV_DONTDUMP is Linux 3.4+): failure only means bigger cores.
 */
static void hg_exclude_from_core(void *base, unsigned long size)
{
#ifdef MADV_DONTDUMP
	const char *want = getenv("HG_DUMP_ARENA");

	if (want && *want && *want != '0') {
		/* explicit: the mapping may have inherited VM_DONTDUMP from an
		 * earlier madvise on an overlapping range */
		madvise(base, size, MADV_DODUMP);
		return;
	}

	madvise(base, size, MADV_DONTDUMP);
#endif
}

/*
 * Reserve an aligned region of at least @size bytes, huge-page-backed where
 * possible and mlock-pinned, mapped until hg_malloc_destroy(); @cap comes
 * back as what was reserved. NULL only when mmap fails outright: a
 * huge-page miss still returns a plain 4K mapping.
 *
 * @shared: MAP_SHARED for shm, one arena for every forked worker. pkg MUST
 * be MAP_PRIVATE so each worker gets its own copy-on-write arena; shared,
 * the hg_block with its lock (a spinlock under FAST_LOCK) and free lists
 * would be common to all workers.
 */
void *hg_mem_reserve(unsigned long size, unsigned long *cap,
		enum hg_mem_tier *tier, unsigned long *locked_b, int shared,
		int inherited, unsigned long apage)
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
	*cap = csize;        /* rewritten below if a fallback shrinks it */

#ifndef __OS_linux
	/* no verified huge-page route outside Linux: a plain anonymous
	 * mapping on the 4K tier, still pinned and pre-faulted */
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

	/*
	 * tier 1: MAP_HUGETLB, unswappable without mlock(), so INIT escapes
	 * RLIMIT_MEMLOCK; a grow does not, it is an mlock() of its delta (see
	 * hg_mlock_refusal()). Try the whole cap, then INIT alone: a pool too
	 * small for the cap fails the mmap, and keeping huge pages without
	 * growth room beats dropping to THP.
	 *
	 * Skipped for the arena children inherit copy-on-write
	 * (HG_INIT_INHERITED): a child's COW fault on a hugetlb page with the
	 * pool empty is a SIGBUS, while THP's COW falls back to 4K pages.
	 */
	p = (inherited || small) ? MAP_FAILED :
	    mmap(NULL, csize, PROT_READ|PROT_WRITE,
	         vis|MAP_ANONYMOUS|MAP_HUGETLB, -1, 0);
	if (p == MAP_FAILED && !inherited && !small && csize > asize) {
		p = mmap(NULL, asize, PROT_READ|PROT_WRITE,
		         vis|MAP_ANONYMOUS|MAP_HUGETLB, -1, 0);
		if (p != MAP_FAILED) {
			LM_NOTICE("hugetlb pool cannot back a %lu MB cap; "
				"reserving the %lu MB in use instead - the arena "
				"keeps huge pages but cannot grow. Raise "
				"vm.nr_hugepages to allow growth.\n",
				csize >> 20, asize >> 20);
			*cap = asize;      /* the arena is fixed after all */
		}
		/* on total failure csize stays at the full cap for tiers 2-4:
		 * THP reservations are plain VA, which CAN hold the cap */
	}
	if (p != MAP_FAILED) {
		hg_exclude_from_core(p, *cap);
		memset(p, 0, asize);
		*tier = HG_MEM_HUGETLB;
		*locked_b = asize;
		return p;
	}

	/*
	 * tiers 2-4: an aligned anon mapping. THP on shmem needs the VA
	 * congruent with the file offset modulo the huge page size, so reserve
	 * PROT_NONE first and MAP_FIXED the real mapping at an aligned address
	 * inside it (an atomic replace); harmless for MAP_PRIVATE.
	 *
	 * The real mapping covers the whole cap R/W, though only asize is
	 * committed: made before fork, it is the one VMA every worker inherits,
	 * so a grow only faults in more of the shared object. An mmap/mprotect
	 * of the tail at grow time would change only the grower's page tables,
	 * and the other workers would SIGSEGV there. An untouched tail costs
	 * page-table entries, not memory.
	 */
	resv = mmap(NULL, csize + apage, PROT_NONE,
	            MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (resv == MAP_FAILED)
		return NULL;
	base = (char *)(((unsigned long)resv + apage - 1) & ~(apage - 1));
	p = mmap(base, csize, PROT_READ|PROT_WRITE,
	         vis|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
	if (p == MAP_FAILED) {
		munmap(resv, csize + apage);
		return NULL;
	}

	hg_exclude_from_core(base, csize);

	/* small mode stops here: THP cannot back a range under one huge
	 * page, so it is the 4K tier, pinned and pre-faulted all the same */
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

	/* advise huge before first touch (tier 2), then pin: a cold mlock
	 * populates, so it is also the pre-fault. The advice covers the whole
	 * cap so growth inherits it; each delta is still verified when grown */
	madvise(base, csize, MADV_HUGEPAGE);
	shmem_kb = hg_read_huge_kb(shared);
	if (mlock(base, asize) == 0) {
		*locked_b = asize;
	} else {
		LM_WARN("mlock of the %lu MB HG_MALLOC arena failed (%s): "
			"continuing unpinned (swappable). If running under "
			"systemd, add LimitMEMLOCK=infinity to the unit.\n",
			asize >> 20, strerror(errno));
		memset(base, 0, asize);        /* still pre-fault */
	}

	if (hg_delta_is_huge(shmem_kb, hg_read_huge_kb(shared), asize)) {
		*tier = HG_MEM_THP_ADVISE;
	} else if (shmem_kb >= 0 && !hg_thp_collapse_denied(shared) &&
	           madvise(base, asize, MADV_COLLAPSE) == 0 &&
	           hg_read_huge_kb(shared) - shmem_kb >= (long)(asize / 1024)) {
		*tier = HG_MEM_THP_COLLAPSE;
	} else {
		*tier = HG_MEM_4K;         /* reserved+pinned but 4K */
	}
	return base;
#endif /* __OS_linux */
}

/*
 * MADV_COLLAPSE one committed range, for hg_collapse_deferred() (which owns
 * the page bookkeeping): 1 when it is now on huge pages, else the negated
 * errno, or 0 if the host's THP policy forbids it. The kernel returns 0 only
 * when every huge-page-aligned part collapsed, so success needs no counter
 * check; a failure is often transient (EAGAIN) and worth a retry.
 */
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

/*
 * Commit [hbase+off, +delta): the cap is mapped R/W since reserve time, so
 * this faults the pages in, pins them and verifies their backing. mlock()
 * is the commit primitive on every tier because it fails with an errno, not
 * a later SIGBUS in whichever worker touches the shortfall: an unbackable
 * grow fails HERE, before the buddy sees the range. On tier 1 (unswappable
 * anyway) it is only the populate; a short pool gives ENOMEM, no SIGBUS
 * (hgstress exercises this). Returns the delta's hg_mem_tier, or -1 with
 * the range munlock'd (refuse, never half-commit). Reserve time already
 * excluded the whole cap from core dumps.
 */
const char * const hg_cp_phase_str[HG_CP_PHASES] = {
	"meminfo", "advise", "mlock_populate", "verify", "collapse"
};

#define HG_CP_TIME(phase, stmt) do { \
		unsigned long _t0 = hg_now_ns(); \
		stmt; \
		cp_ns[phase] = hg_now_ns() - _t0; \
	} while (0)

int hg_mem_commit(struct hg_block *hb, unsigned long off, unsigned long delta,
		unsigned long cp_ns[HG_CP_PHASES], int *collapse_later)
{
	char *base = hb->hbase + off;
	int mlock_rc, is_huge, collapsed, i;

	for (i = 0; i < HG_CP_PHASES; i++)
		cp_ns[i] = 0;

	if (off + delta > hb->hcap) {
		LM_BUG("%s: commit of %lu@%lu overruns the %lu byte cap\n",
			hb->name, delta, off, hb->hcap);
		hb->grow_refuse_why = HG_GR_CAP;
		return -1;
	}

	if (hb->tier == HG_MEM_HUGETLB) {
		HG_CP_TIME(HG_CP_MLOCK, mlock_rc = mlock(base, delta));
		if (mlock_rc != 0) {
			hg_mlock_refused(hb, delta, errno);
			munlock(base, delta);
			return -1;
		}
		__sync_fetch_and_add(&hb->locked_mb, delta >> 20);
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
			/* unpinned arena (init's mlock failed): a populating
			 * write fault is the pre-fault without the pin */
			HG_CP_TIME(HG_CP_MLOCK, {
				if (madvise(base, delta, MADV_POPULATE_WRITE) != 0)
					memset(base, 0, delta);   /* pre-5.14 kernels */
			});
			mlock_rc = 0;
		} else {
			HG_CP_TIME(HG_CP_MLOCK, mlock_rc = mlock(base, delta));
			if (mlock_rc != 0 && hg_memlock_limit()) {
				/* 4 KB/THP memory is swappable: the pin is a
				 * latency guarantee, not a requirement, so a
				 * grow the memlock limit cannot cover goes on
				 * unpinned. A failure with no binding limit
				 * still refuses below; hugetlb always needs
				 * the lock (above). */
				munlock(base, delta);
				LM_WARN("%s: RLIMIT_MEMLOCK (%lu KB) cannot pin a %lu MB "
					"grow - the arena continues unpinned (swappable). "
					"Set LimitMEMLOCK=infinity in the service unit (or "
					"ulimit -l unlimited) to keep it pinned.\n", hb->name,
					hg_memlock_limit() >> 10, delta >> 20);
				hb->unpinned = 1;
				HG_CP_TIME(HG_CP_MLOCK, {
					if (madvise(base, delta, MADV_POPULATE_WRITE) != 0)
						memset(base, 0, delta);   /* pre-5.14 kernels */
				});
				mlock_rc = 0;
			}
		}
		if (mlock_rc != 0) {
			hg_mlock_refused(hb, delta, errno);
			munlock(base, delta);
			return -1;
		}
		if (!hb->unpinned)
			__sync_fetch_and_add(&hb->locked_mb, delta >> 20);

		/* the init tier says nothing about this delta's backing: verify
		 * it from the counter delta across the populate (O(1)) */
		HG_CP_TIME(HG_CP_VERIFY, is_huge = hg_delta_is_huge(shmem_kb,
			hg_read_huge_kb(hb->shared), delta));
		if (is_huge)
			return HG_MEM_THP_ADVISE;
		/* a worker is waiting on this grow and a collapse takes
		 * milliseconds: publish on 4 KB pages now, the maintenance
		 * process collapses them later (hg_collapse_deferred) */
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
	if (mlock(base, delta) != 0) {
		memset(base, 0, delta);        /* still pre-fault */
	} else {
		__sync_fetch_and_add(&hb->locked_mb, delta >> 20);
	}
	return HG_MEM_4K;
#endif
}

/* the shrink primitive - contract on the prototype */
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
	/* no portable release off Linux: MADV_REMOVE (the only call that frees
	 * shmem pages) is Linux-only, a remap would split the range from the
	 * other processes, and MADV_DONTNEED neither frees nor zeroes on the
	 * BSDs or macOS. The arena keeps its memory and stops shrinking. */
	(void)base;
	if (!hb->shrink_unsupported) {
		hb->shrink_unsupported = 1;
		LM_NOTICE("%s: returning memory to the OS is Linux-only - this "
			"arena grows but does not shrink here\n", hb->name);
	}
	return -1;
#else
	munlock(base, len);

	if (madvise(base, len, advice) != 0) {
		/* structural, not transient: said once, and the arena never
		 * tries to shrink again */
		hb->shrink_unsupported = 1;
		LM_WARN("%s: cannot release memory (%s of %lu MB failed: %s) "
			"- shrink disabled for this arena\n", hb->name,
			hb->shared ? "MADV_REMOVE" : "MADV_DONTNEED",
			len >> 20, strerror(errno));
		return -1;
	}

	if (hb->locked_mb >= len >> 20)
		hb->locked_mb -= len >> 20;
	else
		hb->locked_mb = 0;
	return 0;
#endif /* __OS_linux */
}

/*
 * Bring a punched range back: populate it and, unless the arena runs
 * unpinned, mlock() it again IN THE CALLING PROCESS - mlock() is per VMA
 * and not inherited across fork(), so the maintenance process's munlock()
 * says nothing about a worker, and a carver that does not mlock gets the
 * page back swappable. mlock() populates as well as pins.
 * Tiers 2-4: a failure does not refuse the carve - the memory is valid,
 * only unpinned; counted in repin_failed and logged once.
 * Hugetlb: a failure MUST refuse - the punched page went back to the pool
 * unreserved, so a failed mlock() means it is gone and touching it would
 * SIGBUS; the caller refuses the request.
 */
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
		/* unpinned arena: a populating write fault is the commit
		 * without the pin */
#ifdef __OS_linux
		if (madvise(base, len, MADV_POPULATE_WRITE) != 0)
#endif
			memset(base, 0, len);
		return 0;
	}

	if (mlock(base, len) != 0) {
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
					hb->name, len >> 10, strerror(errno));
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
				hb->name, len >> 10, strerror(errno));
		}
		/* still populate, so the caller gets usable memory */
		memset(base, 0, len);
		return -1;
	}
	__sync_fetch_and_add(&hb->locked_mb, len >> 20);
	return 0;
}
#endif /* HG_MALLOC */
