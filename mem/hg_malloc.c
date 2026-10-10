/*
 * hugepage-backed slab allocator
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
#include <errno.h>
#include <sys/mman.h>
#include <sys/resource.h>    /* getrlimit(RLIMIT_MEMLOCK) */

#include "hg_version.h"
#include "hg_malloc.h"
#include "hg_arena.h"
#include "hg_large.h"
#include "../dprint.h"
#include "../globals.h"
#include "../statistics.h"
#include "../pt_scaling.h"    /* profiles + counted_max_processes via pt.h */
#include "shm_mem.h"           /* shm_block, for the post-cfg attach */

#ifdef DBG_MALLOC
#include "mem_dbg_hash.h"
#endif

#include "../lib/dbg/struct_hist.h"

/*
 * The huge-page ladder is Linux-only, and the fallback values below are
 * Linux's. They are defined ONLY under __OS_linux on purpose: the same bit
 * means something else elsewhere (0x40000 is MAP_PREFAULT_READ on FreeBSD),
 * so defining them unconditionally would make mmap() succeed with unrelated
 * semantics and this code would then report a huge-page tier it never got.
 * On every other OS the reservation is a plain anonymous mapping.
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
 * The system's default huge page size, probed once rather than assumed.
 *
 * It is 2M on x86_64 and on arm64 with 4K base pages, but 32M on arm64
 * with 16K pages and 512M with 64K pages. Getting it wrong is not
 * cosmetic: mmap(MAP_HUGETLB) without MAP_HUGE_* bits uses the system
 * default, and the kernel rounds the mapping up to it - so a hardcoded
 * 2M would (a) leave the arena's recorded extent smaller than the VMA,
 * making the matching munmap() fail with EINVAL and leak the arena, and
 * (b) align the THP tiers to 2M instead of the real PMD granularity, so
 * MADV_HUGEPAGE/MADV_COLLAPSE quietly do nothing and every arena silently
 * degrades to 4K while still reporting a huge-page tier.
 *
 * Falls back to 2M only if /proc/meminfo cannot be read at all.
 */
#define HG_HPS_FALLBACK (2UL * 1024 * 1024)

static unsigned long hg_hps_cached;

static unsigned long hg_hps(void)
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

#define HG_HPS (hg_hps())

/* round @s up to a whole number of huge pages. Used for the reservation
 * length, the alignment of the THP tiers, AND the matching munmap length -
 * they must agree exactly or the unmap fails and the arena leaks, so they
 * all go through this one macro rather than repeating the expression. */
#define HG_HPS_ROUND(s) (((s) + HG_HPS - 1) & ~(HG_HPS - 1))

/*
 * Small-arena mode: an arena whose whole reservation cannot even hold one
 * huge page has no use for the hugetlb or THP tiers (a transparent huge
 * page IS a huge page - there is nothing sub-2MB to collapse into), so its
 * page grid runs on 256 KB "pages" instead. Everything downstream - the
 * buddy layout, growth publication, shrink granularity, tier accounting -
 * already reads the per-arena hb->hps/hps_shift, so the geometry follows
 * from this one choice.
 *
 * Why 256 KB and not smaller: a buddy block never spans pages, so the page
 * IS the ceiling on any contiguous allocation - and the arena's own
 * furniture needs that ceiling high enough. The largest slab class (64 KB
 * cells) has a hard chunk floor of header + 2 cells = ~131 KB
 * (chunk_size_for()'s "least"), and core startup takes a single ~140 KB
 * large-tier object (init_pvar_support) before serving anything. A 64 KB
 * page was tried and measured failing on exactly those ("class 19 wants a
 * 98432 byte chunk, larger than the 65536 byte page"). 256 KB clears every
 * fixed cost; with the ~31 KB hg_block header on page 0, TWO pages
 * (512 KB) is the honest minimum in this mode.
 *
 * In huge-page mode the minimum is ONE system huge page, not two: the
 * reserve floor, buddy order math and metadata carve were all verified
 * fine at npages=1, and the mapping itself cannot be smaller anyway.
 */
#define HG_SMALL_PAGE_SHIFT 18
#define HG_SMALL_PAGE (1UL << HG_SMALL_PAGE_SHIFT)

/* the page unit an arena with this init/cap runs on */
static inline unsigned long hg_arena_page(unsigned long init_b,
		unsigned long cap_b)
{
	unsigned long m = cap_b > init_b ? cap_b : init_b;

	return (m && m < HG_HPS) ? HG_SMALL_PAGE : HG_HPS;
}

static inline unsigned long hg_page_round(unsigned long v, unsigned long pg)
{
	return (v + pg - 1) & ~(pg - 1);
}

/* the smallest arena that can function in this page unit */
static inline unsigned long hg_min_viable(unsigned long apage)
{
	return apage < HG_HPS ? 2 * apage : apage;
}

/* "512 KB" vs "48 MB" in one printable pair, for the error messages */
#define HG_SZ_VAL(b)  ((b) < (1UL << 20) ? (b) >> 10 : (b) >> 20)
#define HG_SZ_UNIT(b) ((b) < (1UL << 20) ? "KB" : "MB")

/* HG_ROUNDTO=2^k so the following works (same trick as f_malloc.c) */
#define ROUNDTO_MASK   (~((unsigned long)HG_ROUNDTO-1))
#define ROUNDUP_TO(s)  (((s)+(HG_ROUNDTO-1))&ROUNDTO_MASK)

/*
 * Tier ladder + verification, ported near-verbatim from the huge-page
 * reservation code of an earlier caching module: every tier
 * is proven by TRYING it and verifying the result through /proc, never
 * inferred from kernel version or sysfs config alone.
 */

/* read one "Key:  <n> kB" line; -1 if absent (old kernel, no /proc) */
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

static long hg_meminfo_kb(const char *key)
{
	return hg_proc_field("/proc/meminfo", key, 10);
}

/*
 * RLIMIT_MEMLOCK and the arena's grows.
 *
 * Every grow commits its delta with mlock() (hg_mem_commit()), and mlock()
 * checks RLIMIT_MEMLOCK for EVERY mapping, MAP_HUGETLB included - what a
 * hugetlb mapping is exempt from is only the locked-page accounting
 * AFTERWARDS, not the check. So a process left with a distribution's
 * default limit (64 KB under a systemd unit without LimitMEMLOCK) refuses
 * every 2 MB grow, while the hugetlb pool sits full of free pages. The
 * kernel reports that and a genuinely empty pool with the same ENOMEM;
 * the helpers below tell them apart so the warning names the resource that
 * actually ran out.
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
static unsigned long hg_memlock_limit(void)
{
	struct rlimit rl;

	if (getrlimit(RLIMIT_MEMLOCK, &rl) != 0 || rl.rlim_cur == RLIM_INFINITY)
		return 0;
	if (hg_has_cap_ipc_lock())
		return 0;
	return (unsigned long)rl.rlim_cur;
}

/* log why mlock() refused @delta bytes of @hb - called once per refusal
 * episode (grow_refuse_said), with the errno of the failed mlock() */
static void hg_explain_mlock_refusal(struct hg_block *hb, unsigned long delta,
		int err)
{
	unsigned long lim = hg_memlock_limit();
	long locked_kb = hg_proc_field("/proc/self/status", "VmLck", 10);
	long free_pg, rsvd_pg, page_kb;

	if (locked_kb < 0)
		locked_kb = 0;
	if (lim && ((unsigned long)locked_kb << 10) + delta > lim) {
		LM_WARN("%s: cannot grow by %lu MB: RLIMIT_MEMLOCK is %lu KB and "
			"this process already has %ld KB locked - every grow is "
			"mlock()ed, on hugetlb as well. Set LimitMEMLOCK=infinity "
			"in the service unit (or ulimit -l unlimited).\n",
			hb->name, delta >> 20, lim >> 10, locked_kb);
		return;
	}

	if (hb->tier == HG_MEM_HUGETLB) {
		free_pg = hg_meminfo_kb("HugePages_Free");
		rsvd_pg = hg_meminfo_kb("HugePages_Rsvd");
		page_kb = hg_meminfo_kb("Hugepagesize");
		if (free_pg >= 0 && rsvd_pg >= 0 && page_kb > 0 &&
		    (unsigned long)(free_pg - rsvd_pg) * (page_kb << 10) < delta) {
			LM_WARN("%s: cannot grow by %lu MB: the hugetlb pool has %ld "
				"free pages of %ld KB, %ld of them already reserved, "
				"and the grow needs %lu. Raise vm.nr_hugepages or "
				"vm.nr_overcommit_hugepages.\n", hb->name, delta >> 20,
				free_pg, page_kb, rsvd_pg,
				delta / ((unsigned long)page_kb << 10));
			return;
		}
	}

	LM_WARN("%s: cannot grow by %lu MB: mlock failed (%s), and neither "
		"RLIMIT_MEMLOCK (%s) nor %s accounts for it.\n", hb->name,
		delta >> 20, strerror(err), lim ? "set" : "not binding",
		hb->tier == HG_MEM_HUGETLB ? "the hugetlb pool" :
		"the locked-memory total");
}

/*
 * The huge-page counter a mapping shows up in: shared anonymous memory
 * is shmem (ShmemHugePages), private anonymous memory is AnonHugePages.
 */

/*
 * Does the host's THP policy forbid an explicit MADV_COLLAPSE for this
 * mapping kind? MADV_COLLAPSE deliberately bypasses "never" in the kernel
 * (it is an explicit request), so an admin who disabled THP still gets
 * collapsed arenas unless WE honor the setting: for shmem, only "deny"
 * blocks it kernel-side, but we treat "never" as the admin's intent too;
 * for anon there is no deny at all, so "never" is the only signal there
 * is. Read once per kind and cached - the setting is a host property.
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
		cached[!!shared] = 0;      /* cannot tell - keep old behavior */
		return 0;
	}
	fclose(f);
	cached[!!shared] = strstr(buf, "[never]") != NULL ||
	                   strstr(buf, "[deny]") != NULL;
	return cached[!!shared];
}

/*
 * Why a 4K arena is 4K.  "plain 4K pages" on its own sent an operator
 * hunting a kernel bug when the answer was a host setting - and, for
 * shmem, our own decision to honour it.  MEASURED 2026-09-02: on a 6.12
 * kernel with shmem_enabled=[never], MADV_HUGEPAGE on a MAP_SHARED anon
 * mapping yields nothing (+0 kB ShmemHugePages) while MADV_COLLAPSE on
 * the same mapping yields the whole 32 MB.  So the pages ARE available
 * and we are declining them on purpose; an operator deserves to be told
 * that, and told which knob changes it.  On kernels below 6.1 there is
 * no MADV_COLLAPSE at all (EINVAL, measured on 5.4) and 4K is simply the
 * truth.
 */
static const char *hg_4k_reason(int shared)
{
	if (!hg_thp_collapse_denied(shared))
		return "";
	return shared ?
		" - host shmem_enabled is never/deny and this build honours "
		"it; set it to 'advise' to allow the MADV_COLLAPSE retrofit" :
		" - host transparent_hugepage/enabled is never";
}

static long hg_read_huge_kb(int shared)
{
	return hg_meminfo_kb(shared ? "ShmemHugePages" : "AnonHugePages");
}

/*
 * Did a populate of @len bytes land on huge pages? Answered from the
 * system-wide counter delta across the populate - the same test the
 * MADV_COLLAPSE branch has always used - instead of parsing
 * /proc/self/smaps, which walks the page tables of the WHOLE mapping:
 * measured at 8-11 ms per 16 MB grow on a 3 GB arena, under the arena
 * lock (the commit-phase timings). The counter is host-wide, so concurrent huge
 * faults elsewhere can over-count; 90% of the range is demanded to keep
 * a partial fallback from reading as success, and a false negative only
 * costs the collapse retry it would have taken anyway.
 */
static int hg_delta_is_huge(long before_kb, long after_kb, unsigned long len)
{
	return before_kb >= 0 && after_kb >= 0 &&
	       after_kb - before_kb >= (long)(len / 1024) * 9 / 10;
}


/*
 * Keep the arena out of core dumps - unless someone is trying to debug the
 * allocator, in which case the arena is the only thing worth having.
 *
 * HG_MALLOC pre-faults and mlocks its whole reservation, so unlike the
 * lazily-faulted F_MALLOC/Q_MALLOC pools every page is resident - a
 * crashing worker would otherwise write the ENTIRE arena (-m plus -M, and
 * the shm_memlog_size-derived debug pool on top) into its core file. With
 * one core per worker that is multi-GB of core dumps per crash, which is
 * enough page-cache churn to push a busy box into reclaim, and it buries
 * the actually-useful stack/heap in gigabytes of allocator slab.
 *
 * The cost of that default only became clear when a core was actually needed:
 * VM_DONTDUMP wins over coredump_filter, so no filter setting can bring the
 * arena back, and every core taken during the 2026-08 crash investigation had
 * "Cannot access memory" where shm_block should be. The free lists, the class
 * counters, the cell headers - the entire state that decides whether a crash
 * was corruption or a race - are all inside the region being skipped.
 *
 * So it is opt-in: set HG_DUMP_ARENA=1 in the environment (a systemd
 * Environment= line is enough) and the arena is dumped. Sized deliberately as
 * an environment variable rather than a config parameter, because it must take
 * effect during allocator init, long before the config file is parsed.
 *
 * Best-effort: MADV_DONTDUMP is Linux 3.4+, and failure is harmless
 * (bigger cores, nothing incorrect), so the return value is ignored.
 */
static void hg_exclude_from_core(void *base, unsigned long size)
{
#ifdef MADV_DONTDUMP
	const char *want = getenv("HG_DUMP_ARENA");

	if (want && *want && *want != '0') {
		/* explicit, not merely "leave the default alone" - the mapping
		 * may have inherited VM_DONTDUMP from a previous madvise on an
		 * overlapping range */
		madvise(base, size, MADV_DODUMP);
		return;
	}

	madvise(base, size, MADV_DONTDUMP);
#endif
}

/*
 * Reserve a huge-page-aligned, huge-page-backed (best effort) region of at least
 * @size bytes, mlock-pinned against swap. Never unmapped until
 * hg_malloc_destroy(). Returns NULL on total mmap failure only - a huge-page
 * miss still returns a valid plain-4K mapping (degrade, don't fail), per
 * hg_mem_tier_str()'s HG_MEM_4K case.
 *
 * @shared picks MAP_SHARED vs MAP_PRIVATE, and it is NOT cosmetic:
 *
 *   shm  -> MAP_SHARED:  one arena visible to every forked worker, which is
 *                        the entire point of shm.
 *   pkg  -> MAP_PRIVATE: every worker must get its OWN copy-on-write arena
 *                        after fork. Mapping the pkg arena MAP_SHARED (as
 *                        this function originally did unconditionally) put
 *                        the pkg hg_block - including its embedded
 *                        gen_lock_t and its per-class gpool free lists - in
 *                        memory shared by all workers. Under FAST_LOCK that
 *                        lock is a *spinlock*, so every worker's pkg
 *                        allocations serialized on one contended spinlock,
 *                        and "process-private" pkg cells silently migrated
 *                        between processes through the shared gpool.
 */
static void *hg_mem_reserve(unsigned long size, unsigned long *cap,
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
	/* No verified huge-page route outside Linux: take a plain anonymous
	 * mapping and report the 4K tier honestly rather than claiming one we
	 * cannot check. Still pinned and pre-faulted. */
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
	 * tier 1: MAP_HUGETLB - unswappable without an mlock(), so the INIT
	 * mapping is not limited by RLIMIT_MEMLOCK. Its GROWS are: each one is
	 * an mlock() of the delta, and mlock() checks the limit on hugetlb too
	 * (see hg_explain_mlock_refusal()).
	 *
	 * Try the whole cap first, then fall back to the committed size alone.
	 * hugetlb mappings are backed by a fixed pool, so a cap larger than the
	 * pool can hold makes this mmap fail outright - and silently dropping
	 * to THP because the admin asked for growth room would be a far worse
	 * trade than simply not being able to grow. A cap-less tier-1 arena
	 * keeps its hugetlb backing and gives up only the growth room.
	 */
	/*
	 * ...except for the arena children inherit copy-on-write (the pre-fork
	 * pkg arena, HG_INIT_INHERITED): a child's write into an inherited
	 * hugetlb page needs a fresh huge page with no 4K fallback and no
	 * reservation behind it - an empty pool at that instant is a SIGBUS.
	 * That arena starts the ladder at THP, whose COW splits to 4K pages
	 * instead. See the flag's comment in hg_malloc.h.
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
	 * tiers 2-4: huge-page-aligned anon mapping. For the shmem
	 * (MAP_SHARED) case the VA and shmem *file offset* must be congruent
	 * modulo the huge page size for THP eligibility, so reserve PROT_NONE
	 * first, then MAP_FIXED the real mapping at a huge-page boundary
	 * inside it - an atomic replace, no race with other mappings.
	 * Harmless (and keeps the alignment) for MAP_PRIVATE.
	 *
	 * The real mapping covers the whole CAP, readable and writable, even
	 * though only asize of it is committed now. That is the load-bearing
	 * part of growth, not an accident: this mapping is created before
	 * fork, so it is the one VMA every worker inherits, all of them backed
	 * by the same shmem object. Growing later means faulting more of that
	 * object in - visible to every process by construction. The obvious
	 * alternative - keep the tail PROT_NONE and mmap/mprotect it live at
	 * grow time - changes only the GROWER's page tables: measured on the
	 * 5.4 kernel, the grower reads its new pages fine and a forked worker
	 * SIGSEGVs on the same addresses (userspace test rig, test A vs
	 * B). An untouched R/W tail costs a few hundred kB of page-table
	 * entries, not memory - test B: 64 MB of mapped-untouched span held
	 * RSS at 576 kB.
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

	/* a small-mode arena is done here: THP advice on a sub-huge-page
	 * range can never produce a huge page, so skip the whole detection
	 * dance and report the 4K tier it genuinely runs on - pinned and
	 * pre-faulted all the same */
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

	/* advise huge before first touch (tier 2), then pin+populate: a cold
	 * mlock populates to pin, so it doubles as the pre-fault. The advice
	 * covers the whole cap so growth deltas inherit it - each delta still
	 * gets its backing VERIFIED at grow time, never assumed from here. */
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
 * The host-RAM limb of the growth ceiling - see the prototype comment.
 *
 * The floor it defends is max(256 MB, MemTotal/20), overridable via the
 * hg_ram_floor_mb config global.
 * MemAvailable is the kernel's own estimate of what can be claimed
 * without swapping - exactly the question here. On a kernel too old to
 * export it the check PASSES: the mlock in hg_mem_commit() still refuses
 * with a clean errno when the host truly cannot back the delta, so the
 * failure mode without this limb is a later, harsher refusal, not a
 * crash.
 *
 * Reading /proc under hb->lock is deliberate, same trade as the commit
 * pre-fault: growth is once per granule of genuine demand, and the
 * mlock that follows costs orders of magnitude more than one procfs
 * read.
 */
int hg_grow_ram_refused(struct hg_block *hb, unsigned long delta)
{
	static long floor_mb = -1;          /* resolved once, per process */
	unsigned long effective = delta, nproc = 1;
	long avail_kb;

	/* tier 1 consumes no new host RAM at commit time: the whole cap was
	 * reserved from the hugetlb pool at map time, and those pages are
	 * already carved out of MemTotal. Charging them here double-counts. */
	if (hb->tier == HG_MEM_HUGETLB)
		return 0;

	if (floor_mb < 0) {
		if (hg_ram_floor_mb > 0) {
			floor_mb = hg_ram_floor_mb;      /* hg_ram_floor_mb= config */
		} else {
			long total_kb = hg_meminfo_kb("MemTotal");

			floor_mb = 256;
			if (total_kb > 0 && total_kb / 20 / 1024 > floor_mb)
				floor_mb = total_kb / 20 / 1024;
		}
	}

	avail_kb = hg_meminfo_kb("MemAvailable");
	if (avail_kb < 0)
		return 0;                   /* cannot tell - let mlock decide */

	if (!hb->shared) {
		/* pkg: every worker will grow its own arena under the same
		 * workload; the single-arena delta understates the real cost
		 * by the process count */
		nproc = counted_max_processes ? counted_max_processes : 1;
		effective = delta * nproc;
	}

	if ((unsigned long)avail_kb * 1024 <
	    effective + ((unsigned long)floor_mb << 20)) {
		/* once per episode - see grow_refuse_said's comment */
		if (!hb->grow_refuse_said) {
			hb->grow_refuse_said = 1;
			LM_WARN("%s: refusing to grow by %lu MB: %lu MB effective"
				" (x%lu processes) would leave the host under the "
				"%ld MB floor (MemAvailable %ld MB). Freeing host "
				"memory or lowering the floor lifts this.\n",
				hb->name, delta >> 20, effective >> 20, nproc,
				floor_mb, avail_kb / 1024);
		}
		return 1;
	}
	return 0;
}

/*
 * Commit [hbase+off, +delta) of the reservation: populate, pin, verify the
 * achieved backing. The range is already mapped R/W (the whole cap is, since
 * reserve time - that is what makes the commit visible to every forked
 * worker with no page-table surgery here), so the only work is faulting the
 * pages in and finding out what the kernel faulted them in AS.
 *
 * mlock() is the commit primitive for every tier, chosen for one property:
 * it populates the exact range and reports failure through errno instead of
 * raising SIGBUS in whichever worker touches the shortfall later. A grow
 * that cannot be backed must fail HERE, atomically, while the buddy still
 * considers the range nonexistent.
 *   - tiers 2-4: mlock is also the pin, same as init.
 *   - tier 1: hugetlb pages are unswappable regardless; mlock is used only
 *     as the populate-with-clean-errno vehicle. The pool-exhaustion path
 *     (mlock ENOMEM, nothing SIGBUSes, VM_LOCKED rolled back) is PROVEN by
 *     the hgstress grow harness against a deliberately undersized pool -
 *     do not take this comment's word for it, run the harness.
 *
 * Returns the achieved hg_mem_tier of the delta, or -1 with the range
 * munlock'd again (refuse, never half-commit). No hg_exclude_from_core()
 * here: reserve time already excluded the whole cap.
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
		unsigned long cp_ns[HG_CP_PHASES])
{
	char *base = hb->hbase + off;
	int mlock_rc, is_huge, collapsed, i;

	for (i = 0; i < HG_CP_PHASES; i++)
		cp_ns[i] = 0;

	if (off + delta > hb->hcap) {
		LM_BUG("%s: commit of %lu@%lu overruns the %lu byte cap\n",
			hb->name, delta, off, hb->hcap);
		return -1;
	}

	if (hb->tier == HG_MEM_HUGETLB) {
		HG_CP_TIME(HG_CP_MLOCK, mlock_rc = mlock(base, delta));
		if (mlock_rc != 0) {
			/* once per episode - see grow_refuse_said's comment */
			if (!hb->grow_refuse_said) {
				hb->grow_refuse_said = 1;
				hg_explain_mlock_refusal(hb, delta, errno);
			}
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

		/* re-advise the delta: cheap, and correct even though reserve
		 * time advised the whole cap - a later madvise elsewhere in the
		 * VMA may have split it */
		HG_CP_TIME(HG_CP_ADVISE, madvise(base, delta, MADV_HUGEPAGE));

		if (hb->unpinned) {
			/* the arena runs unpinned (init's mlock failed and it
			 * carried on) - grow the same way rather than refuse: a
			 * populating write fault is the pre-fault without the pin */
			HG_CP_TIME(HG_CP_MLOCK, {
				if (madvise(base, delta, MADV_POPULATE_WRITE) != 0)
					memset(base, 0, delta);   /* pre-5.14 kernels */
			});
			mlock_rc = 0;
		} else {
			HG_CP_TIME(HG_CP_MLOCK, mlock_rc = mlock(base, delta));
		}
		if (mlock_rc != 0) {
			/* once per episode - see grow_refuse_said's comment */
			if (!hb->grow_refuse_said) {
				hb->grow_refuse_said = 1;
				hg_explain_mlock_refusal(hb, delta, errno);
			}
			munlock(base, delta);
			return -1;
		}
		if (!hb->unpinned)
			__sync_fetch_and_add(&hb->locked_mb, delta >> 20);

		/*
		 * The delta's backing is a fresh negotiation - the arena's init
		 * tier says NOTHING about what this range just got. Verify it
		 * the same way init does: read what the kernel actually did.
		 */
		/* O(1) verification - the counter delta across the populate,
		 * not a walk of the whole VMA's page tables */
		HG_CP_TIME(HG_CP_VERIFY, is_huge = hg_delta_is_huge(shmem_kb,
			hg_read_huge_kb(hb->shared), delta));
		if (is_huge)
			return HG_MEM_THP_ADVISE;
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

/* the shrink primitive - contract and measurements on the prototype */
int hg_mem_release(struct hg_block *hb, unsigned long off, unsigned long len)
{
	char *base = hb->hbase + off;
	int advice = hb->shared ? MADV_REMOVE : MADV_DONTNEED;

	if (off + len > hb->span_end) {
		LM_BUG("%s: release of %lu@%lu overruns the %lu byte span\n",
			hb->name, len, off, hb->span_end);
		return -1;
	}

	munlock(base, len);

	if (madvise(base, len, advice) != 0) {
		/* structural, not transient: the advice either works on this
		 * mapping type + kernel or it never will. Say so once and stop
		 * trying for this arena's lifetime. */
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
}

/*
 * Bring a punched range back: fault it in and, unless the arena runs
 * deliberately unpinned, pin it AGAIN - in whichever process is calling.
 *
 * "in whichever process is calling" is the whole point, and it is measured,
 * not assumed (on kernels 5.4 and 6.12): mlock() is
 * per-vma and is NOT inherited across fork(), so a child sees the pre-fork
 * arena as entirely unlocked and the maintenance process's munlock() says
 * nothing about a worker's address space. The punch happens in the
 * maintenance process; the refill happens in whatever worker carves. If the
 * carver does not mlock, the page comes back resident and swappable -
 * measured: 2048K resident, 0K locked - and no counter would have shown it.
 *
 * mlock() populates as well as pins, so it is the whole re-commit.
 *
 * On tiers 2-4 a failure does NOT refuse the carve. The memory is valid,
 * just unpinned; refusing would turn a pinning shortfall into an allocation
 * failure under exactly the memory pressure that caused it. It is counted
 * in repin_failed and said once - which is the difference between a
 * degraded promise and a silent one.
 *
 * On the hugetlb tier a failure MUST refuse. A punched huge page went back
 * to the pool with no reservation kept (measured on 6.12: HugePages_Free
 * rises, Rsvd stays 0 - any mapping may take it), so mlock() failing means
 * the page does not exist, and touching it would be a SIGBUS in this
 * process. The hole stays a hole and the caller refuses the request the
 * way an exhausted grow does; the pool is the admin's to size.
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
		/* init could not pin and the arena went on unpinned; a
		 * populating write fault is the commit without the pin */
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

/* the pkg policy, resolved once post-parse and inherited by fork - every
 * per-child arena pt.c creates copies it in at hg_malloc_init() time */
static struct {
	int valid;
	unsigned long up_bytes, down_bytes;
	unsigned int up_pct, up_need, up_window, down_pct, down_cycles;
	unsigned short cooldown;
} hg_pkg_pol_resolved;

/*
 * Fit a profile's targets to the cap the arena ACTUALLY reserved.
 *
 * The validation in hg_autoscale_apply() judges a profile against the cap the
 * admin ASKED for, which is right: a scale-up target above it is a mistake in
 * the config and must fail loudly. But the arena may have ACHIEVED less.
 * hg_mem_reserve() rewrites the cap when the hugetlb pool cannot back it -
 * "hugetlb pool cannot back a %lu MB cap; reserving the %lu MB in use
 * instead", after which the arena keeps its huge pages and simply cannot
 * grow. Nothing re-checked the profile against that smaller number, so
 * pol.up_bytes could sit above hb->hcap; hg_buddy_grow() then sized a granule
 * past the end of the mapping on every tick and hg_mem_commit() refused it at
 * "off + delta > hb->hcap" with LM_BUG, a resource refusal and a latched
 * grow-block - once per policy tick, for the life of the process.
 *
 * Clamped rather than refused, deliberately. A target above the REQUEST is a
 * config error the admin can fix by editing a line; a reservation that came up
 * short is this boot's machine, with the configuration perfectly correct, and
 * hg_autoscale_post_cfg()'s failure path aborts startup (mem/shm_mem.c). An
 * arena that works at its initial size is worth more than a process that
 * refuses to run because the hugepage pool was short. Clamped to hcap the
 * ordinary ceiling path takes over: hg_grow_tick() returns at the profile
 * ceiling and hg_buddy_grow() reports room==0 once per episode.
 */
static void hg_pol_fit_to_cap(struct hg_block *hb, const char *which,
		const char *pname, unsigned long *up_b, unsigned long *down_b)
{
	if (*up_b <= hb->hcap)
		return;

	LM_WARN("%s profile '%s': scale-up target %lu %s is above the %lu %s "
		"this arena actually reserved - the reservation came up short "
		"at init (see the hugetlb pool notice above), the profile is "
		"not at fault. Capping the target at the reservation; growth "
		"beyond it is impossible until the pool can back the full "
		"cap.\n", which, pname, HG_SZ_VAL(*up_b), HG_SZ_UNIT(*up_b),
		HG_SZ_VAL(hb->hcap), HG_SZ_UNIT(hb->hcap));
	*up_b = hb->hcap;
	/* a scale-down target that no longer sits below the ceiling would be
	 * a floor above the roof; fall back to the arena's own initial size */
	if (*down_b > *up_b)
		*down_b = 0;
}

/*
 * Copy a profile's numbers onto an arena, translating workers->MB and
 * validating every edge against the reservation this arena actually has.
 * @hb may be NULL for the pkg case (arena does not exist yet) - then only
 * the validation against @cap/@init runs and the result lands in
 * hg_pkg_pol_resolved.
 */
static int hg_autoscale_apply(struct hg_block *hb, const char *which,
		struct scaling_profile *p, unsigned long init_bytes,
		unsigned long cap_bytes)
{
	/* profile numbers are MB, or KB when the config used a size suffix
	 * (p->mem_kb_units, set by the parser); rounding and the viability
	 * floor follow the page unit THIS arena runs on, so a small-mode
	 * arena is judged in its own 64 KB currency, not huge pages */
	int ush = p->mem_kb_units ? 10 : 20;
	unsigned long apage = hb ? hb->hps :
		hg_arena_page(init_bytes, cap_bytes);
	unsigned long up_b   =
		hg_page_round((unsigned long)p->max_procs << ush, apage);
	unsigned long down_b = p->min_procs
		? hg_page_round((unsigned long)p->min_procs << ush, apage) : 0;

	if (cap_bytes <= hg_page_round(init_bytes, apage)) {
		LM_ERR("%s profile '%s': the arena has no growth room - give "
			"the reservation on the command line (-%s INIT:CAP)\n",
			which, p->name, hb || !strcmp(which, "shm") ? "m" : "M");
		return -1;
	}
	if (up_b <= hg_page_round(init_bytes, apage)) {
		LM_ERR("%s profile '%s': scale-up target %lu %s does not exceed "
			"the initial %lu %s - the profile could never act\n",
			which, p->name, HG_SZ_VAL(up_b), HG_SZ_UNIT(up_b),
			HG_SZ_VAL(init_bytes), HG_SZ_UNIT(init_bytes));
		return -1;
	}
	if (up_b > cap_bytes) {
		LM_ERR("%s profile '%s': scale-up target %lu %s exceeds the "
			"%lu %s reservation - raise the :CAP\n",
			which, p->name, HG_SZ_VAL(up_b), HG_SZ_UNIT(up_b),
			HG_SZ_VAL(cap_bytes), HG_SZ_UNIT(cap_bytes));
		return -1;
	}
	if (down_b) {
		if (down_b < hg_min_viable(apage)) {
			LM_ERR("%s profile '%s': scale-down target %lu %s is below "
				"the %lu %s minimum viable arena\n",
				which, p->name, HG_SZ_VAL(down_b), HG_SZ_UNIT(down_b),
				HG_SZ_VAL(hg_min_viable(apage)),
				HG_SZ_UNIT(hg_min_viable(apage)));
			return -1;
		}
		if (down_b >= up_b) {
			LM_ERR("%s profile '%s': scale-down target %lu %s is not "
				"below the scale-up target %lu %s\n",
				which, p->name, HG_SZ_VAL(down_b), HG_SZ_UNIT(down_b),
				HG_SZ_VAL(up_b), HG_SZ_UNIT(up_b));
			return -1;
		}
	}

	if (hb) {
		/* every check above judged the ASKED-for cap; this one judges
		 * what the arena got. @hb is NULL only for the pre-fork pkg
		 * case, whose arenas do not exist yet - hg_malloc_init_cap()
		 * applies the same fit as each child arena is created. */
		hg_pol_fit_to_cap(hb, which, p->name, &up_b, &down_b);

		hg_lock_enter(hb, HG_LK_POLICY);
		hb->pol.active      = 1;
		hb->pol.up_bytes    = up_b;
		hb->pol.down_bytes  = down_b ? down_b : hb->committed_min;
		hb->pol.up_pct      = p->up_threshold;
		hb->pol.up_need     = p->up_cycles_needed;
		hb->pol.up_window   = p->up_cycles_tocheck;
		hb->pol.down_pct    = p->down_threshold;
		hb->pol.down_cycles = p->down_cycles_tocheck;
		hb->pol.cooldown    = p->down_cycles_delay;
		if (down_b)     /* the profile IS the ask now */
			hb->committed_min = down_b;
		hg_lock_leave(hb);
	} else {
		hg_pkg_pol_resolved.valid       = 1;
		hg_pkg_pol_resolved.up_bytes    = up_b;
		hg_pkg_pol_resolved.down_bytes  = down_b;
		hg_pkg_pol_resolved.up_pct      = p->up_threshold;
		hg_pkg_pol_resolved.up_need     = p->up_cycles_needed;
		hg_pkg_pol_resolved.up_window   = p->up_cycles_tocheck;
		hg_pkg_pol_resolved.down_pct    = p->down_threshold;
		hg_pkg_pol_resolved.down_cycles = p->down_cycles_tocheck;
		hg_pkg_pol_resolved.cooldown    = p->down_cycles_delay;
	}

	LM_NOTICE("%s auto-scaling profile '%s'%s: %lu %s..%lu %s (start "
		"%lu %s), up at %u%% for %u/%u cycles, down at %u%% for %u "
		"cycles (cooldown %u)\n", which, p->name,
		hg_autoscale_dry_run ? " [DRY RUN - advise only]" : "",
		HG_SZ_VAL(down_b ? down_b : hg_page_round(init_bytes, apage)),
		HG_SZ_UNIT(down_b ? down_b : hg_page_round(init_bytes, apage)),
		HG_SZ_VAL(up_b), HG_SZ_UNIT(up_b),
		HG_SZ_VAL(init_bytes), HG_SZ_UNIT(init_bytes),
		p->up_threshold, p->up_cycles_needed,
		p->up_cycles_tocheck, p->down_threshold, p->down_cycles_tocheck,
		p->down_cycles_delay);
	return 0;
}

int hg_autoscale_post_cfg(void)
{
	struct scaling_profile *p;
	int hg_shm = (mem_allocator_shm == MM_HG_MALLOC ||
	              mem_allocator_shm == MM_HG_MALLOC_DBG);
#ifdef PKG_MALLOC
	int hg_pkg = (mem_allocator_pkg == MM_HG_MALLOC ||
	              mem_allocator_pkg == MM_HG_MALLOC_DBG);
#else
	int hg_pkg = 0;     /* pkg memory is the system malloc */
#endif

	if (hg_shm_profile_name) {
		if (!hg_shm) {
			LM_WARN("shm_auto_scaling_profile ignored: the shm "
				"allocator is %s, not " HG_MALLOC_NAME "\n",
				mm_str(mem_allocator_shm));
		} else {
			p = get_scaling_profile(hg_shm_profile_name);
			if (!p) {
				LM_ERR("shm_auto_scaling_profile '%s' does not name "
					"an auto_scaling_profile\n", hg_shm_profile_name);
				return -1;
			}
			if (hg_autoscale_apply((struct hg_block *)shm_block, "shm",
			        p, shm_mem_size, hg_shm_cap_bytes) < 0)
				return -1;
		}
	}

	if (hg_shm_grow_granule && hg_shm && shm_block) {
		struct hg_block *hb = (struct hg_block *)shm_block;

		hg_lock_enter(hb, HG_LK_POLICY);
		hb->grow_granule = hg_page_round(hg_shm_grow_granule, hb->hps);
		hg_lock_leave(hb);
		LM_NOTICE("shm grow granule set to %lu %s per step (config)\n",
			HG_SZ_VAL(hb->grow_granule), HG_SZ_UNIT(hb->grow_granule));
	}
	if (hg_pkg_grow_granule && hg_pkg)
		LM_NOTICE("pkg grow granule %lu %s per step will apply to every "
			"worker arena (config)\n",
			HG_SZ_VAL(hg_pkg_grow_granule), HG_SZ_UNIT(hg_pkg_grow_granule));
	if (hg_shm && shm_block) {
		struct hg_block *hb = (struct hg_block *)shm_block;
		unsigned long step = hg_page_round(hg_shrink_step, hb->hps);

		if (step < hb->hps)
			step = hb->hps;
		if (step != hb->shrink_step) {
			hg_lock_enter(hb, HG_LK_POLICY);
			hb->shrink_step = step;
			hg_lock_leave(hb);
		}
		LM_NOTICE("shm shrink step %lu %s per drain tick, policy cycle "
			"%d s\n", HG_SZ_VAL(hb->shrink_step),
			HG_SZ_UNIT(hb->shrink_step), hg_scaling_cycle);
	}

	if (hg_pkg_profile_name) {
		if (!hg_pkg) {
#ifdef PKG_MALLOC
			LM_WARN("pkg_auto_scaling_profile ignored: the pkg "
				"allocator is %s, not " HG_MALLOC_NAME "\n",
				mm_str(mem_allocator_pkg));
#else
			LM_WARN("pkg_auto_scaling_profile ignored: pkg memory is "
				"the system malloc, not " HG_MALLOC_NAME "\n");
#endif
		} else {
			p = get_scaling_profile(hg_pkg_profile_name);
			if (!p) {
				LM_ERR("pkg_auto_scaling_profile '%s' does not name "
					"an auto_scaling_profile\n", hg_pkg_profile_name);
				return -1;
			}
			if (hg_autoscale_apply(NULL, "pkg", p, pkg_mem_size,
			        hg_pkg_cap_bytes) < 0)
				return -1;
		}
	}
	return 0;
}

const char *hg_mem_tier_str(enum hg_mem_tier tier)
{
	switch (tier) {
	case HG_MEM_HUGETLB:
		return "MAP_HUGETLB 2M pages";
	case HG_MEM_THP_ADVISE:
		return "THP 2M pages via MADV_HUGEPAGE (huge at fault)";
	case HG_MEM_THP_COLLAPSE:
		return "THP 2M pages via MADV_COLLAPSE (post-fill retrofit)";
	case HG_MEM_4K:
		return "plain 4K pages";
	}
	return "unknown";
}

/*
 * Registry of live arena ranges, for the ownership tests in hg_malloc.h.
 *
 * hg_owns_any() needs to answer "is this pointer from ANY of our arenas?"
 * without being handed a block, because hg_frag_size() is installed into a
 * shared function-pointer interface whose signature we do not control. A
 * fixed-size array is deliberate: this is bootstrap bookkeeping for the
 * allocator itself, so it must not be allocated THROUGH the allocator.
 *
 * Process-local, and correct under fork by construction: a child inherits the
 * parent's entries (its shm mapping is genuinely the same memory) and adds its
 * own private pkg arena when pt.c swaps one in. Keeping the parent's stale pkg
 * entry is a feature here - a parent-allocated pkg pointer freed in a child
 * still resolves to mapped memory, so it is declined rather than dereferenced.
 */
struct hg_arena_range hg_arena_reg[HG_ARENA_REG_MAX];

/*
 * How many frees this process redirected to an arena other than the one the
 * caller named. Not an error count - see hg_owner(). It is expected to be a
 * small constant per child, set at startup and never moving again; a figure
 * that climbs with traffic would mean something is handing pointers across
 * arenas at runtime, which nothing should.
 */
unsigned long hg_xarena_frees;

static void hg_arena_reg_add(struct hg_block *hb)
{
	int i;

	for (i = 0; i < HG_ARENA_REG_MAX; i++) {
		if (!hg_arena_reg[i].base) {
			hg_arena_reg[i].base = hb->hbase;
			/* the CAP, not the span: growth must not invalidate the
			 * registry entry, or a pointer into grown space would be
			 * misread as foreign and "routed" to another arena. The
			 * whole cap's VA belongs to this arena from reserve time;
			 * uncommitted ranges cannot hold live cells, so the wider
			 * range cannot misattribute anything that exists. */
			hg_arena_reg[i].size = hb->hcap;
			hg_arena_reg[i].hb   = hb;
			return;
		}
	}
	/* Not fatal: hg_owns_any() then declines pointers it cannot vouch for,
	 * which costs diagnostics, never correctness. */
	LM_WARN("%s: more than %d live HG_MALLOC arenas in one process - "
		"ownership checks will be incomplete\n", hb->name,
		HG_ARENA_REG_MAX);
}

static void hg_arena_reg_del(struct hg_block *hb)
{
	int i;

	for (i = 0; i < HG_ARENA_REG_MAX; i++) {
		if (hg_arena_reg[i].base == hb->hbase) {
			hg_arena_reg[i].base = NULL;
			hg_arena_reg[i].size = 0;
			hg_arena_reg[i].hb   = NULL;
			return;
		}
	}
}

/*
 * hg_malloc_init() reserves its own memory (unlike fm_malloc_init(), which
 * receives an already-mmap'd address from shm_getmem()) and lays the block
 * control structure out at the very start of that reservation - the same
 * "control struct lives inside the memory it manages" pattern fm_block/
 * hp_block use, chosen specifically so HG_MALLOC never needs to call
 * shm_malloc()/pkg_malloc() on itself to bootstrap its own bookkeeping
 * (it cannot: HG_MALLOC IS what those macros dispatch to when selected).
 */
struct hg_block *hg_malloc_init(unsigned long size, char *name, int shared,
		const char *proc_desc, unsigned int flags)
{
	/* the core arenas take their cap by name (below); a module arena
	 * brings its own - see hg_arena_create() */
	return hg_malloc_init_cap(size, HG_CAP_BY_NAME, name, shared, proc_desc,
		flags);
}

struct hg_block *hg_malloc_init_cap(unsigned long size, unsigned long cap_req,
		char *name, int shared, const char *proc_desc, unsigned int flags)
{
	enum hg_mem_tier tier;
	unsigned long locked_b;
	unsigned long cap, apage;
	char *base;
	struct hg_block *hb;

	/* The reservation may exceed the committed size, by admin cap.
	 * cap comes back as what was actually achieved (a hugetlb pool that
	 * cannot hold the cap degrades to a fixed arena, not to no arena).
	 * By NAME, not by @shared: shm_dbg is also shared but is a fixed-size
	 * diagnostic pool computed by hg_get_dbg_pool_size() - handing it the
	 * shm cap would reserve gigabytes of VA for a pool that must never
	 * grow past its formula.
	 *
	 * The caps arrive via -m INIT:CAP / -M INIT:CAP on the command line -
	 * they cannot come from the config, which is parsed only after this
	 * arena exists (and, for tier 1, after the pool reservation is
	 * already taken). */
	if (cap_req != HG_CAP_BY_NAME)
		cap = cap_req;
	else if (!strcmp(name, "shm"))
		cap = hg_shm_cap_bytes;
	else if (!strcmp(name, "pkg"))
		cap = hg_pkg_cap_bytes;
	else
		cap = 0;
	apage = hg_arena_page(size, cap);
	if (size < hg_min_viable(apage)) {
		LM_ERR("%s arena: %lu %s is below the %lu %s minimum viable "
			"arena\n", name, HG_SZ_VAL(size), HG_SZ_UNIT(size),
			HG_SZ_VAL(hg_min_viable(apage)),
			HG_SZ_UNIT(hg_min_viable(apage)));
		return NULL;
	}
	base = hg_mem_reserve(size, &cap, &tier, &locked_b, shared,
		(flags & HG_INIT_INHERITED) != 0, apage);
	if (!base) {
		LM_ERR("failed to reserve %lu bytes for %s HG_MALLOC arena\n",
			size, name);
		return NULL;
	}

	/* the block header itself lives inside the reservation it describes */
	if (size < ROUNDUP_TO(sizeof(struct hg_block))) {
		LM_ERR("%s arena of %lu bytes too small for the block header "
			"(%zu bytes)\n", name, size, sizeof(struct hg_block));
		munmap(base, cap);
		return NULL;
	}

	hb = (struct hg_block *)(void *)base;
	memset(hb, 0, sizeof *hb);
	hb->name = name;
	hb->size = size;
	hb->lo = ~0UL;
	hb->hbase = base;
	/* one figure assigned to both: the span and the committed count part
	 * ways only when a hole is punched, and nothing does that yet */
	hb->span_end = hg_page_round(size, apage);
	hb->committed_bytes = hb->span_end;
	hb->committed_min = hb->committed_bytes;
	hb->span_pending = hb->span_end;
	hb->hcap = cap;
	/* one committed-size step per grow: big enough that a growth spurt is
	 * a handful of commits, small enough that the pre-fault under the
	 * arena lock stays bounded. A small-mode arena steps one of its own
	 * 256 KB pages at a time - a 16 MB granule would overshoot its whole
	 * cap. Overridable by config later. */
	hb->grow_granule = apage < HG_HPS ?
		apage : HG_HPS_ROUND(16UL << 20);
	/* config override (shm_grow_granule / pkg_grow_granule): rounded to
	 * this arena's page, never below one page. The core shm arena exists
	 * before the config - hg_autoscale_post_cfg() re-applies for it; the
	 * per-child pkg arenas are created after and take it right here.
	 * Module arenas keep the default (their own sizing surface). */
	if (!shared && hg_pkg_grow_granule)
		hb->grow_granule = hg_page_round(hg_pkg_grow_granule, apage);
	else if (shared && !strcmp(name, "shm") && hg_shm_grow_granule)
		hb->grow_granule = hg_page_round(hg_shm_grow_granule, apage);
	/* the shrink step: config, page-rounded, never below one page. Like
	 * the granule, the core shm arena predates the config and takes the
	 * value again in hg_autoscale_post_cfg(). */
	hb->shrink_step = hg_page_round(hg_shrink_step, apage);
	if (hb->shrink_step < apage)
		hb->shrink_step = apage;
	/* the page unit this arena's whole grid runs on: the probed huge page
	 * size, or the small-mode 64 KB page - hg_arena_init() lays out the
	 * page grid from this, never re-probing */
	hb->hps = apage;
	hb->tier = tier;
	hb->locked_mb = locked_b >> 20;
	hb->unpinned = (tier != HG_MEM_HUGETLB && locked_b == 0);
	hb->tier_bytes[tier] = hb->committed_bytes;
	hb->shared = shared;

	/*
	 * A per-child PKG arena created after the config was parsed inherits
	 * the resolved pkg policy (the fork copied hg_pkg_pol_resolved). The
	 * pre-fork parent pkg arena and the shm arena take the other path:
	 * they exist BEFORE the config, so the shm policy is attached to the
	 * live block by hg_autoscale_post_cfg() and the parent pkg arena
	 * simply stays fixed.
	 */
	if (!shared && hg_pkg_pol_resolved.valid) {
		unsigned long up_b   = hg_pkg_pol_resolved.up_bytes;
		unsigned long down_b = hg_pkg_pol_resolved.down_bytes;

		/* the resolved policy was validated against the cap asked for
		 * on -M, before any pkg arena existed; THIS arena may have
		 * reserved less (same hugetlb path, same consequence) */
		hg_pol_fit_to_cap(hb, "pkg", "the resolved pkg policy",
			&up_b, &down_b);

		hb->pol.active      = 1;
		hb->pol.up_bytes    = up_b;
		hb->pol.down_bytes  = down_b ? down_b : hb->committed_min;
		hb->pol.up_pct      = hg_pkg_pol_resolved.up_pct;
		hb->pol.up_need     = hg_pkg_pol_resolved.up_need;
		hb->pol.up_window   = hg_pkg_pol_resolved.up_window;
		hb->pol.down_pct    = hg_pkg_pol_resolved.down_pct;
		hb->pol.down_cycles = hg_pkg_pol_resolved.down_cycles;
		hb->pol.cooldown    = hg_pkg_pol_resolved.cooldown;
		if (down_b)
			hb->committed_min = down_b;
	}

	if (!lock_init(&hb->lock)) {
		LM_ERR("failed to init the %s arena lock\n", name);
		munmap(base, hb->hcap);
		return NULL;
	}

	hg_arena_reg_add(hb);

	/* the region right after the block header is the first thing chunks
	 * bump-carve from - hg_arena_init() sets hoff past it */
	if (hg_arena_init(hb, ROUNDUP_TO(sizeof(struct hg_block))) < 0) {
		LM_ERR("failed to init the %s arena\n", name);
		lock_destroy(&hb->lock);
		munmap(base, hb->hcap);
		return NULL;
	}

	/* "pinned from swapping" is the real guarantee this reports: tier-1
	 * MAP_HUGETLB pages are non-swappable by construction (no mlock()
	 * needed or taken), tiers 2-4 rely on an explicit mlock() instead -
	 * either way, the reported MB are equally protected against swap,
	 * just via a different mechanism. Plain "pinned" reads ambiguously
	 * (looks like "an mlock() call happened") and was caught live during
	 * a real diagnosis session mid-2026-08-07 being misread that way. */
	if (proc_desc)
		LM_NOTICE("%s " HG_MALLOC_NAME " arena (%s): %lu %s on %s, %lu %s "
			"pinned from swapping%s\n",
			name, proc_desc, HG_SZ_VAL(size), HG_SZ_UNIT(size),
			hg_mem_tier_str(tier),
			HG_SZ_VAL(locked_b), HG_SZ_UNIT(locked_b),
			tier == HG_MEM_4K ? hg_4k_reason(shared) : "");
	else
		LM_NOTICE("%s " HG_MALLOC_NAME " arena: %lu %s on %s, %lu %s "
			"pinned from swapping%s%s\n",
			name, HG_SZ_VAL(size), HG_SZ_UNIT(size),
			hg_mem_tier_str(tier),
			HG_SZ_VAL(locked_b), HG_SZ_UNIT(locked_b),
			tier == HG_MEM_4K ? hg_4k_reason(shared) : "",
			(flags & HG_INIT_INHERITED) ?
			" (pre-fork arena, inherited copy-on-write by every child: "
			"hugetlb deliberately skipped, its COW cannot fall back)" : "");
	if (hb->hcap > hb->committed_bytes)
		LM_NOTICE("%s arena can grow to %lu %s (%lu %s headroom "
			"reserved, uncommitted)\n", name,
			HG_SZ_VAL(hb->hcap), HG_SZ_UNIT(hb->hcap),
			HG_SZ_VAL(hb->hcap - hb->committed_bytes),
			HG_SZ_UNIT(hb->hcap - hb->committed_bytes));

	/*
	 * An elastic arena grows by mlock()ing each delta, so a memlock
	 * limit that cannot cover the growth makes the cap a promise the
	 * arena cannot keep - and it surfaces only at the first refused grow,
	 * possibly hours into traffic. Say so now, where the operator (and a
	 * -C config check) sees it. On hugetlb the limit is checked per grow
	 * against one delta plus whatever else the process has locked; on the
	 * other tiers every committed byte counts, so the whole cap must fit.
	 */
	if (hb->hcap > hb->committed_bytes) {
		unsigned long lim = hg_memlock_limit();
		unsigned long need = (tier == HG_MEM_HUGETLB) ?
			hb->grow_granule : hb->hcap;

		if (lim && lim < need)
			LM_WARN("%s arena: RLIMIT_MEMLOCK is %lu KB, but growing "
				"needs %lu KB locked (%s) - every grow will be "
				"refused. Set LimitMEMLOCK=infinity in the service "
				"unit (or ulimit -l unlimited) before relying on the "
				"%lu %s cap.\n", name, lim >> 10, need >> 10,
				tier == HG_MEM_HUGETLB ? "one grow granule" :
				"the whole cap", HG_SZ_VAL(hb->hcap),
				HG_SZ_UNIT(hb->hcap));
	}

	return hb;
}

/* mirrors fm_get_dbg_pool_size()'s structure, HG_CELL_HDR substituted for
 * FRAG_OVERHEAD - see the "why" note on the declaration in hg_malloc.h */
unsigned long hg_get_dbg_pool_size(unsigned int hist_size)
{
	return ROUNDUP_TO(sizeof(struct hg_block)) + HG_CELL_HDR +
		HG_CELL_HDR + 56 /* sizeof(struct struct_hist_list) */ + 2 * hist_size *
		(HG_CELL_HDR + 88 /* sizeof(struct struct_hist) */ +
		HG_CELL_HDR + sizeof(struct struct_hist_action));
}

void hg_malloc_destroy(struct hg_block *hb)
{
	if (!hb)
		return;

	hg_arena_reg_del(hb);
	hg_arena_destroy(hb);
	lock_destroy(&hb->lock);
	/* munmap last: hb itself lives inside hbase. The whole cap, not just
	 * the committed part - the reservation is one mapping */
	munmap(hb->hbase, hb->hcap);
}

void hg_malloc_child_init(struct hg_block *hb)
{
	if (hb)
		hg_arena_child_init(hb);
}

/*
 * Fork reset for EVERY shared arena this process can see - the core shm
 * block, shm_dbg, and every module arena in the registry. The per-arena
 * reasoning lives in hg_arena_child_init(); what this adds is coverage:
 * a module arena that saw pre-fork traffic (a module loading its data in
 * mod_init is enough - one refill batch leaves ~31 cells in the parent's
 * private cache) would otherwise hand every child an identical COW copy of
 * the parent's cached cell list, and the children's later flushes would
 * push the same physical cells onto the shared pool repeatedly - an
 * "already has all N cells free" refusal storm.
 *
 * Private (pkg) blocks are deliberately skipped: a child's COW copy of
 * the pre-fork parent pkg arena is self-consistent private memory, and
 * the child's own fresh pkg arena - created after this runs - must not
 * have its slots cleared.
 */
void hg_malloc_child_init_all(void)
{
	int i;

	for (i = 0; i < HG_ARENA_REG_MAX; i++)
		if (hg_arena_reg[i].hb && hg_arena_reg[i].hb->shared)
			hg_arena_child_init(hg_arena_reg[i].hb);
}

#ifdef SHM_EXTRA_STATS
#include "module_info.h"
unsigned long hg_stats_get_index(void *ptr)
{
	if (!ptr)
		return GROUP_IDX_INVALID;

	return HG_STATS_IDX(ptr);
}

void hg_stats_set_index(void *ptr, unsigned long idx)
{
	if (!ptr)
		return;

	HG_STATS_IDX(ptr) = idx;
}

/* called once, pre-fork, after the statistics engine but before any worker
 * exists yet (matches hp_init_shm_statistics()'s call site) - single
 * process at this point, so walking "not on any known free list" is exact,
 * unlike hg_status_dbg()'s post-fork best-effort walk (see hg_arena.c's
 * hg_arena_walk_live() comment) */
void hg_stats_core_init(struct hg_block *hb, int core_index)
{
	hg_arena_stats_core_init(hb, core_index);
}
#endif

/* fills a malloc info structure with info about the block */
void hg_info(struct hg_block *hb, struct mem_info *info)
{
	unsigned long recycled;

	memset(info, 0, sizeof *info);
	info->total_size = hb->size;
	info->min_frag = 64; /* smallest cell class, see hg_arena.c cell_sizes */
	info->used = hg_used(hb);

	/* Report carved-but-idle cell capacity as FREE rather than USED, so
	 * real_used/free track live demand and fall again when load drops -
	 * the same thing q_malloc/f_malloc do for a fragment sitting on a free
	 * list. hb->real_used on its own is the arena's carve footprint, which
	 * never decreases and would otherwise look like a leak. */
	recycled = hg_slab_recycled(hb);
	info->real_used = hb->real_used > recycled ? hb->real_used - recycled : 0;
	/* room left to CARVE, not size minus live - see hg_get_free() */
	info->free = hb->size - hb->real_used;

	/* the peak of what real_used above actually reached - NOT the peak
	 * carve (hb->max_real_used), which only ever grows and would drift
	 * away from real_used forever */
	if (info->real_used > hb->max_live_used)
		hb->max_live_used = info->real_used;
	info->max_used = hb->max_live_used;
	info->total_frags = hg_fragments(hb);
}

void hg_status(struct hg_block *hb)
{
	unsigned int nchunks;
	unsigned long bytes;

	LM_GEN1(memdump, "hg_status (%p):\n", hb);
	if (!hb)
		return;

	hg_arena_stats(hb, &nchunks, &bytes);
	LM_GEN1(memdump, " heap size= %lu, tier=%s, pinned=%lu MB\n",
		hb->size, hg_mem_tier_str(hb->tier), hb->locked_mb);
	LM_GEN1(memdump, " chunks= %u, chunk bytes= %lu\n", nchunks, bytes);
}

#if !defined INLINE_ALLOC && defined DBG_MALLOC
struct hg_dbg_dump_ctx {
	mem_dbg_htable_t *allocd;
	unsigned long skipped_notlive;   /* see hg_dbg_dump_cb() */
};

static void hg_dbg_dump_cb(void *payload, void *ctx)
{
	struct hg_dbg_dump_ctx *c = ctx;
	char *tag = HG_HDR(payload);
	const char *file, *func;
	unsigned long line;

	/*
	 * The walker derives cell addresses from chunk bookkeeping rather than
	 * from a live-cell list, so a single corrupted chunk hands us an
	 * address that need not be mapped - and this is a DIAGNOSTIC path. A
	 * memory dump must never be the thing that kills the process, which is
	 * exactly what happened on 2026-08-09 before this check existed.
	 */
	if (!hg_owns_any(tag)) {
		hg_corrupt(NULL, HG_C_FOREIGN_PTR);
		LM_CRIT("%s: dump walker produced %p, outside every arena - "
			"skipping it\n", HG_MALLOC_NAME, payload);
		return;
	}

	/*
	 * Read the DBG fields directly from the tag region, like
	 * fm_status_dbg reads f->file/func/line straight off the frag
	 * struct - NOT via hg_frag_file()/func()/line() (hg_malloc.h),
	 * which are nested inside "#ifdef SHM_EXTRA_STATS" (they exist only
	 * to serve the shm_frag_file/func/line stats ladder). This function
	 * is gated on DBG_MALLOC alone, so it must not depend on
	 * SHM_EXTRA_STATS also being on.
	 */
	file = HG_CELL_AT(tag)->file;
	if (!file)
		return;   /* stamped before any hg_malloc_dbg() call ever ran
		           * on this cell (e.g. still on its very first carve
		           * without having been freed+realloc'd) - matches
		           * fm_status_dbg's own "if (f->file)" guard */
	func = HG_CELL_AT(tag)->func;
	line = HG_CELL_AT(tag)->line;

	/*
	 * Defence in depth, on top of the walker sizing its set exactly.
	 *
	 * The walker infers liveness by absence from that set, so anything that
	 * leaves the set incomplete turns a FREE cell into an apparently live
	 * one - and a free cell's payload holds the free-list link, so these
	 * file/func would be pointers INTO THE ARENA rather than string
	 * literals. dbg_ht_update() would then consume them as strings.
	 *
	 * hg_owns_any() is the exact discriminator: a real __FILE__ lives in the
	 * binary's rodata and can never be inside an arena; a free-list link
	 * always is. Costs nothing on a diagnostic path, and turns what was an
	 * abort into a skipped line.
	 */
	if (hg_owns_any((void *)file) || hg_owns_any((void *)func)) {
		c->skipped_notlive++;
		return;
	}

	if (dbg_ht_update(*c->allocd, file, func, line, hg_frag_size(payload)) < 0)
		LM_ERR("unable to update the %s allocation summary\n", HG_MALLOC_NAME);
}

/*
 * f_malloc-equivalent per-allocation-site summary: walk every live cell/
 * frag, aggregate by (file,func,line) via mem_dbg_hash (mem_dbg_hash.c -
 * same plain-malloc'd, allocator-independent structure fm_status_dbg
 * uses), dump, free. See hg_arena_walk_live()'s comment in hg_arena.c for
 * the one real accuracy caveat: exact pre-fork, best-effort post-fork
 * (can't see cells idling in ANOTHER worker's private free stack) - large
 * frags (hg_large_walk_live) don't share that caveat, they're always exact.
 */
void hg_status_dbg(struct hg_block *hb)
{
	mem_dbg_htable_t allocd;
	struct hg_dbg_dump_ctx ctx;
	struct mem_dbg_entry *it;
	unsigned int i;

	LM_GEN1(memdump, "hg_status_dbg (%p):\n", hb);
	if (!hb)
		return;

	hg_status(hb);

	dbg_ht_init(allocd);
	ctx.allocd = &allocd;
	ctx.skipped_notlive = 0;

	hg_arena_walk_live(hb, hg_dbg_dump_cb, &ctx);
	hg_large_walk_live(hb, hg_dbg_dump_cb, &ctx);

	LM_GEN1(memdump, " dumping summary of all alloc'ed. fragments:\n");
	LM_GEN1(memdump, "------------+---------------------------------------\n");
	LM_GEN1(memdump, "total_bytes | num_allocations x [file: func, line]\n");
	LM_GEN1(memdump, "------------+---------------------------------------\n");
	for (i = 0; i < DBG_HASH_SIZE; i++) {
		for (it = allocd[i]; it; it = it->next)
			LM_GEN1(memdump, " %10lu : %lu x [%s: %s, line %lu]\n",
				it->size, it->no_fragments, it->file, it->func, it->line);
	}
	LM_GEN1(memdump, "----------------------------------------------------\n");
	if (ctx.skipped_notlive)
		LM_GEN1(memdump, " %lu cell(s) skipped: header held free-list linkage, "
			"so the cell was free despite not being in the free set\n",
			ctx.skipped_notlive);

	dbg_ht_free(allocd);
}
#endif

/*
 * hg_cell_alloc()/hg_cell_free() (hg_arena.c, a separate translation unit)
 * have a signature fixed ONCE by hg_arena.h's *original* DBG_MALLOC state -
 * unlike f_malloc.c's internal helpers (fm_split_frag etc.), which live
 * inside f_malloc_dyn.h itself and get recompiled fresh on each pass below,
 * so their signature tracks the local #undef/#define correctly.
 * hg_malloc_dyn.h's PASS 2 (after the #undef below) must therefore NOT use
 * a bare "#ifdef DBG_MALLOC" to decide the hg_cell_alloc()/hg_cell_free()
 * call arity - that macro is locally stale during pass 2. This sentinel
 * captures the true, original state before any undef games. */
#ifdef DBG_MALLOC
#define HG_CELL_TAKES_DBG_ARGS 1
#else
#define HG_CELL_TAKES_DBG_ARGS 0
#endif

#include "hg_malloc_dyn.h"

#if !defined INLINE_ALLOC && defined DBG_MALLOC
#undef DBG_MALLOC
#include "hg_malloc_dyn.h"
#define DBG_MALLOC
#endif

/* --- module arenas ------------------------------------------------------
 *
 * A module that wants its own memory - a cache whose lifetime, class mix and
 * growth have nothing to do with transactions - asks for an arena here and
 * gets one that HG_MALLOC manages completely: the slab classes with their
 * per-process caches, block GC and re-typing, elastic growth and shrink
 * inside the module's own INIT:CAP, the maintenance process (which ticks
 * every registered shared arena), hg_stats. The arena is created BEFORE the
 * fork (mod_init), so every child inherits the one shared mapping exactly
 * as it does the shm arena; the ownership registry routes a free to the
 * arena that owns the pointer, whichever one it is. Independent of the -a
 * choice: the core allocator can be anything while the module's cells live
 * in HG.
 */
struct hg_block *hg_arena_create(char *name, unsigned long init_bytes,
		unsigned long cap_bytes)
{
	struct hg_block *hb;
	int i, free_slot = -1;

	if (!name || !*name) {
		LM_ERR("module arena needs a name\n");
		return NULL;
	}
	if (cap_bytes < init_bytes)
		cap_bytes = init_bytes;
	if (init_bytes < hg_min_viable(hg_arena_page(init_bytes, cap_bytes))) {
		unsigned long mv =
			hg_min_viable(hg_arena_page(init_bytes, cap_bytes));

		LM_ERR("module arena '%s': %lu %s is below the %lu %s minimum "
			"viable arena\n", name,
			HG_SZ_VAL(init_bytes), HG_SZ_UNIT(init_bytes),
			HG_SZ_VAL(mv), HG_SZ_UNIT(mv));
		return NULL;
	}
	for (i = 0; i < HG_ARENA_REG_MAX; i++) {
		if (hg_arena_reg[i].hb && hg_arena_reg[i].hb->name &&
		    !strcmp(hg_arena_reg[i].hb->name, name)) {
			LM_ERR("module arena '%s' already exists\n", name);
			return NULL;
		}
		if (free_slot < 0 && !hg_arena_reg[i].base)
			free_slot = i;
	}
	if (free_slot < 0) {
		LM_ERR("module arena '%s': all %d arena slots are taken\n",
			name, HG_ARENA_REG_MAX);
		return NULL;
	}

	hb = hg_malloc_init_cap(init_bytes,
		hg_page_round(cap_bytes, hg_arena_page(init_bytes, cap_bytes)),
		name, 1, NULL, 0);
	if (!hb) {
		LM_ERR("module arena '%s': could not reserve %lu %s (cap "
			"%lu %s)\n", name,
			HG_SZ_VAL(init_bytes), HG_SZ_UNIT(init_bytes),
			HG_SZ_VAL(cap_bytes), HG_SZ_UNIT(cap_bytes));
		return NULL;
	}
	LM_NOTICE("module arena '%s': %lu MB committed, can grow to %lu MB - "
		"managed by HG_MALLOC (classes, GC, growth, maintenance)\n",
		name, hb->committed_bytes >> 20, hb->hcap >> 20);
	return hb;
}

/* attach an auto_scaling_profile to a module arena (mod_init, pre-fork) */
int hg_arena_set_profile(struct hg_block *hb, const char *profile_name)
{
	struct scaling_profile *p;

	if (!hb || !profile_name)
		return -1;
	p = get_scaling_profile((char *)profile_name);
	if (!p) {
		LM_ERR("arena '%s': '%s' does not name an auto_scaling_profile\n",
			hb->name, profile_name);
		return -1;
	}
	return hg_autoscale_apply(hb, hb->name, p, hb->committed_min, hb->hcap);
}

#endif /* HG_MALLOC */
