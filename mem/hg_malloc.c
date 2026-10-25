/*
 * slab allocator with elastic arenas
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

/* round @s up to a whole number of huge pages */
#define HG_HPS_ROUND(s) (((s) + HG_HPS - 1) & ~(HG_HPS - 1))

/*
 * Small-arena mode: an arena whose whole reservation is under one huge page
 * gets nothing from hugetlb or THP, so its grid runs on 256 KB pages (all
 * geometry reads hb->hps).
 * A buddy block never spans pages, and 256 KB fits the largest class's
 * ~131 KB chunk floor (chunk_size_for()) and the ~140 KB large object core
 * startup takes. Minimum: two pages (512 KB; the hg_block header takes
 * ~31 KB of page 0) for a fixed arena, one for an elastic one; in huge-page
 * mode, one huge page.
 */
#define HG_SMALL_PAGE_SHIFT 18
#define HG_SMALL_PAGE (1UL << HG_SMALL_PAGE_SHIFT)

/* the page unit an arena with this init/cap runs on, judged by size;
 * an INIT under one huge page with a larger cap is settled by the backing
 * tier in hg_malloc_init_cap() */
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

static long hg_meminfo_kb(const char *key)
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
static unsigned long hg_memlock_limit(void)
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
static const char *hg_4k_reason(int shared)
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
 * The host-memory floor no commit may cross, in MB: hg_ram_floor_mb, else
 * MemTotal/20 but at least the smaller of 256 MB and MemTotal/8 (a flat
 * 256 MB would refuse startup on a small host). Not cached: arenas created
 * before the config is parsed must not pin the default for later grows.
 */
static long hg_ram_floor(void)
{
	long total_kb;

	if (hg_ram_floor_mb > 0)
		return hg_ram_floor_mb;
	total_kb = hg_meminfo_kb("MemTotal");
	if (total_kb <= 0)
		return 256;
	return hg_floor_mb_for(total_kb >> 10);
}

/* bytes the hugetlb pool can still hand out: free pages not already
 * promised to a mapping. 64-bit like the room (hg_memlimit.h): the pool
 * is the host's */
static unsigned long long hg_pool_free_bytes(void)
{
	long free_pg = hg_meminfo_kb("HugePages_Free");
	long rsvd_pg = hg_meminfo_kb("HugePages_Rsvd");
	long page_kb = hg_meminfo_kb("Hugepagesize");

	if (free_pg < 0 || rsvd_pg < 0 || page_kb <= 0 || free_pg <= rsvd_pg)
		return 0;
	return (unsigned long long)(free_pg - rsvd_pg) *
		((unsigned long long)page_kb << 10);
}

/* bytes of general RAM that can still be committed: the host's above its
 * floor, or the memory cgroup's above its own floor when that is tighter
 * (hg_memlimit.c); HG_ROOM_ANY when neither says. @ci, if given, describes
 * the cgroup level that binds, version 0 when the host does */
static unsigned long long hg_ram_room_why(struct hg_cg_info *ci)
{
	long avail_kb = hg_meminfo_kb("MemAvailable");
	unsigned long long floor_b = (unsigned long long)hg_ram_floor() << 20;
	unsigned long long avail_b = (unsigned long long)avail_kb << 10, room, cg;
	struct hg_cg_info c;

	if (avail_kb < 0)
		room = HG_ROOM_ANY;
	else if (avail_b <= floor_b)
		room = 0;
	else
		room = avail_b - floor_b;
	cg = hg_cgroup_room(&c);
	if (cg < room)
		room = cg;
	else
		c.version = 0;
	if (ci)
		*ci = c;
	return room;
}

static unsigned long long hg_ram_room(void)
{
	return hg_ram_room_why(NULL);
}

/*
 * Can a new arena commit @init bytes now? Tier 1 takes them from the
 * hugetlb pool (never for an inherited arena, and only on the huge-page
 * grid); tiers 2-4 take them from general RAM, which must stay above the
 * floor. Logs why not, for @what, and returns 0; 1 when it fits.
 */
static int hg_init_fits(const char *what, unsigned long init,
		unsigned long cap, int inherited)
{
	unsigned long apage = hg_arena_page(init, cap);
	int huge_grid = (apage == HG_HPS);
	/* an INIT under one huge page may be raised to one on huge pages */
	unsigned long need = hg_page_round(init, huge_grid ? HG_HPS : apage);
	struct hg_cg_info ci;
	unsigned long long room = hg_ram_room_why(&ci), pool;

	if (need <= room)
		return 1;
	pool = (huge_grid && !inherited) ? hg_pool_free_bytes() : 0;
	if (need <= pool)
		return 1;
	if (ci.version)
		LM_ERR("%s: the memory cgroup (v%d) is the tighter limit: %lu MB "
			"limit, %lu MB in use, %lu MB floor\n", what, ci.version,
			ci.limit_mb, ci.used_mb, ci.floor_mb);
	LM_ERR("%s: committing %lu %s now does not fit - %lu MB of RAM is "
		"available above the %ld MB floor (hg_ram_floor_mb) and the "
		"hugetlb pool has %lu MB free. Lower INIT (-m/-M), the number of "
		"processes, or the floor, or add memory or huge pages.\n", what,
		HG_SZ_VAL(need), HG_SZ_UNIT(need),
		room == HG_ROOM_ANY ? 0 : (unsigned long)(room >> 20), hg_ram_floor(),
		(unsigned long)(pool >> 20));
	return 0;
}

void hg_oom_report(struct hg_block *hb, unsigned long n, unsigned long max_req)
{
	LM_ERR("%s: %lu allocations failed in the last 30 s for lack of arena "
		"memory (largest %lu %s) - the arena is full; increase it or find "
		"what fills it (core:hg_stats)\n", hb->name, n,
		HG_SZ_VAL(max_req), HG_SZ_UNIT(max_req));
}

/* the shared arenas (shm, module arenas), once per sweep interval from the
 * sweep timer - every process sees them, so no per-process reporting */
void hg_oom_report_shared(void)
{
	unsigned long n, max_req;
	struct hg_block *hb;
	int i;

	for (i = 0; i < HG_ARENA_REG_MAX; i++) {
		hb = hg_arena_reg[i].hb;
		if (!hb || !hb->shared)
			continue;
		hg_lock_enter(hb, HG_LK_STATS);
		n = hg_oom_take(hb, &max_req);
		hg_lock_leave(hb);
		if (n)
			hg_oom_report(hb, n, max_req);
	}
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
 * The live peak (live_peak, shmem:max_used_size) is a high-water mark taken
 * when the figure is computed. The sweep timer calls this every second for
 * the shared arenas (O(1), lock-free), so a peak lasting a second or more
 * is kept even when no statistics read happened during it.
 */
void hg_sample_live_peaks(void)
{
#ifdef STATISTICS
	struct hg_block *hb;
	int i;

	for (i = 0; i < HG_ARENA_REG_MAX; i++) {
		hb = hg_arena_reg[i].hb;
		if (hb && hb->shared)
			(void)hg_get_real_used(hb);
	}
#endif
}

/*
 * Private arenas are per process, so their growth refusals are invisible
 * to statistics read in another process. Each process publishes its own
 * pkg arena's refusal count and GROW-BLOCKED state into its slot of this
 * shared array at every cache sweep; the hgmem: statistics sum them.
 */
struct hg_pkg_pub {
	unsigned long grow_refused;
	unsigned int grow_blocked;
};
static struct hg_pkg_pub *hg_pkg_pub;
static unsigned int hg_pkg_pub_n;

int hg_pkg_pub_init(unsigned int nproc)
{
#ifdef PKG_MALLOC
	if (mem_allocator_pkg != MM_HG_MALLOC &&
	    mem_allocator_pkg != MM_HG_MALLOC_DBG)
		return 0;
	hg_pkg_pub = shm_malloc(nproc * sizeof *hg_pkg_pub);
	if (!hg_pkg_pub) {
		LM_ERR("no shm for the pkg growth statistics\n");
		return -1;
	}
	memset(hg_pkg_pub, 0, nproc * sizeof *hg_pkg_pub);
	hg_pkg_pub_n = nproc;
#endif
	return 0;
}

void hg_pkg_publish(struct hg_block *hb)
{
	if (!hg_pkg_pub || process_no < 0 ||
	    (unsigned int)process_no >= hg_pkg_pub_n)
		return;
	hg_pkg_pub[process_no].grow_refused = hb->grow_refused;
	hg_pkg_pub[process_no].grow_blocked = hb->grow_blocked;
}

void hg_pkg_pub_reset(int proc)
{
	if (hg_pkg_pub && proc >= 0 && (unsigned int)proc < hg_pkg_pub_n)
		memset(&hg_pkg_pub[proc], 0, sizeof *hg_pkg_pub);
}

/* @ctx: 0 = refused grows summed over all processes, 1 = processes whose
 * pkg arena is GROW-BLOCKED now */
unsigned long hg_pkg_pub_stat(void *ctx)
{
	unsigned long sum = 0;
	unsigned int i;

	if (!hg_pkg_pub)
		return 0;
	for (i = 0; i < hg_pkg_pub_n; i++)
		sum += ctx ? (hg_pkg_pub[i].grow_blocked ? 1 : 0) :
		             hg_pkg_pub[i].grow_refused;
	return sum;
}

/*
 * Before forking one more process (startup or auto-scaler): can its private
 * arena commit its INIT? 0 makes the fork fail cleanly - the auto-scaler
 * keeps the processes it has - instead of an OOM kill. Logged once per
 * episode, re-armed when a fork fits again.
 */
int hg_fork_fits(void)
{
#ifdef PKG_MALLOC
	static int said;

	if (mem_allocator_pkg != MM_HG_MALLOC &&
	    mem_allocator_pkg != MM_HG_MALLOC_DBG)
		return 1;
	if (hg_ram_room() >= hg_page_round(pkg_mem_size,
	        hg_arena_page(pkg_mem_size, hg_pkg_cap_bytes) == HG_HPS ?
	        HG_HPS : HG_SMALL_PAGE) ||
	    hg_pool_free_bytes() >= hg_page_round(pkg_mem_size, HG_HPS)) {
		said = 0;
		return 1;
	}
	if (!said) {
		said = 1;
		hg_init_fits("new process's pkg arena", pkg_mem_size,
			hg_pkg_cap_bytes, 0);
		LM_ERR("not forking more processes until memory frees up\n");
	}
	return 0;
#else
	return 1;      /* pkg memory is the system malloc */
#endif
}

/*
 * Startup, before anything forks: will every child's private arena (its
 * own -M INIT) fit? Simulated against the hugetlb pool first (a child takes
 * its whole cap from it when it can, else its INIT), then RAM above the
 * floor. -1 when the processes forked at startup do not fit; only a warning
 * for the auto-scaling maximum or caps beyond MemTotal (the per-fork check
 * stops scaling there).
 */
int hg_capacity_check(unsigned int start_procs, unsigned int max_procs)
{
#ifndef PKG_MALLOC
	return 0;      /* pkg memory is the system malloc */
#else
	unsigned long init = pkg_mem_size, cap, capr, initr_huge, initr_ram;
	/* sums over every process: 64-bit, as the room they are held to */
	unsigned long long pool, pool_left, room, ram_start = 0, ram_max = 0, caps;
	long total_kb;
	unsigned int i, children;
	int huge_grid;

	if (mem_allocator_pkg != MM_HG_MALLOC &&
	    mem_allocator_pkg != MM_HG_MALLOC_DBG)
		return 0;

	cap = hg_pkg_cap_bytes > init ? hg_pkg_cap_bytes : init;
	huge_grid = (hg_arena_page(init, cap) == HG_HPS);
	capr = hg_page_round(cap, HG_HPS);
	initr_huge = hg_page_round(init, HG_HPS);
	initr_ram = hg_page_round(init, huge_grid ? HG_HPS : HG_SMALL_PAGE);
	pool = pool_left = huge_grid ? hg_pool_free_bytes() : 0;
	room = hg_ram_room();

	/* the attendant keeps its pre-fork arena; every other process
	 * creates its own */
	children = max_procs > 1 ? max_procs - 1 : 0;
	for (i = 0; i < children; i++) {
		unsigned long long *ram = (i + 1 < start_procs) ?
			&ram_start : &ram_max;

		if (pool_left >= capr)
			pool_left -= capr;
		else if (pool_left >= initr_huge)
			pool_left -= initr_huge;
		else
			*ram += initr_ram;
	}
	ram_max += ram_start;
	LM_INFO("pkg: %u processes at startup, up to %u with auto-scaling, "
		"-M INIT %lu %s: %lu MB from the hugetlb pool, %lu MB (%lu MB at "
		"the maximum) from RAM; %ld MB of RAM available above the %ld MB "
		"floor\n", start_procs, max_procs, HG_SZ_VAL(init),
		HG_SZ_UNIT(init), (unsigned long)((pool - pool_left) >> 20),
		(unsigned long)(ram_start >> 20), (unsigned long)(ram_max >> 20),
		room == HG_ROOM_ANY ? -1L : (long)(room >> 20), hg_ram_floor());

	if (room != HG_ROOM_ANY && ram_start > room) {
		LM_ERR("pkg: the %u processes started now need %lu MB of RAM for "
			"their -M INIT of %lu %s (after %lu MB from the hugetlb "
			"pool), but %lu MB is available above the %ld MB floor. "
			"Lower -M INIT or the worker counts, or add memory or huge "
			"pages.\n", start_procs, (unsigned long)(ram_start >> 20),
			HG_SZ_VAL(init), HG_SZ_UNIT(init),
			(unsigned long)((pool - pool_left) >> 20),
			(unsigned long)(room >> 20), hg_ram_floor());
		return -1;
	}
	if (room != HG_ROOM_ANY && ram_max > room)
		LM_WARN("pkg: auto-scaling up to %u processes would need %lu MB "
			"of RAM for their -M INIT, but %lu MB is available above "
			"the %ld MB floor - processes beyond what fits will not be "
			"forked. Lower the scale-up maximums or -M INIT to make "
			"them all fit.\n", max_procs, (unsigned long)(ram_max >> 20),
			(unsigned long)(room >> 20), hg_ram_floor());

	total_kb = hg_meminfo_kb("MemTotal");
	caps = (unsigned long long)children * cap;
	if ((mem_allocator_shm == MM_HG_MALLOC ||
	     mem_allocator_shm == MM_HG_MALLOC_DBG) && shm_block)
		caps += ((struct hg_block *)shm_block)->hcap;
	if (total_kb > 0 && caps > ((unsigned long long)total_kb << 10))
		LM_WARN("the -m cap plus -M cap x %u processes is %lu MB, more "
			"than the host's %ld MB of memory: those caps can never all "
			"be met, and growth will be refused at the %ld MB floor\n",
			children, (unsigned long)(caps >> 20), total_kb >> 10,
			hg_ram_floor());
	return 0;
#endif
}

/*
 * The host-RAM limb of the growth ceiling (see the prototype), defending
 * hg_ram_floor(); a limited memory cgroup is held to the same rule on its
 * own limit (hg_memlimit.c). MemAvailable is the kernel's estimate of what
 * can be claimed without swapping; a kernel without it passes the check,
 * and the mlock in hg_mem_commit() still refuses cleanly. Reading /proc
 * under hb->lock is deliberate: a grow is rare and its mlock costs far more.
 */
int hg_grow_ram_refused(struct hg_block *hb, unsigned long delta)
{
	long floor_mb;
	/* a pkg grow counts once per process: 64-bit, as the room */
	unsigned long long effective = delta, cg_room;
	unsigned long nproc = 1;
	long avail_kb;
	struct hg_cg_info ci;
	int host_short, cg_short;

	/* tier 1: the whole cap was reserved from the hugetlb pool at map
	 * time, so a commit takes no new host RAM */
	if (hb->tier == HG_MEM_HUGETLB)
		return 0;

	floor_mb = hg_ram_floor();
	avail_kb = hg_meminfo_kb("MemAvailable");
	cg_room = hg_cgroup_room(&ci);

	if (!hb->shared) {
		/* pkg: every worker grows its own arena under the same load,
		 * so the cost is the delta times the process count */
		nproc = counted_max_processes ? counted_max_processes : 1;
		effective = (unsigned long long)delta * nproc;
	}

	/* the host (unknown MemAvailable: let mlock decide), then the memory
	 * cgroup, which a container or a unit's MemoryMax hits first */
	host_short = avail_kb >= 0 && ((unsigned long long)avail_kb << 10) <
		effective + ((unsigned long long)floor_mb << 20);
	cg_short = cg_room != HG_ROOM_ANY && cg_room < effective;
	if (!host_short && !cg_short)
		return 0;
	hb->grow_refuse_why = host_short ? HG_GR_HOST_FLOOR : HG_GR_CGROUP;
	/* once per episode - see grow_refuse_said's comment */
	if (!hb->grow_refuse_said) {
		hb->grow_refuse_said = 1;
		if (host_short)
			LM_WARN("%s: refusing to grow by %lu MB: %lu MB effective"
				" (x%lu processes) would leave the host under the "
				"%ld MB floor (MemAvailable %ld MB). Freeing host "
				"memory or lowering the floor lifts this.\n",
				hb->name, delta >> 20, (unsigned long)(effective >> 20),
				nproc, floor_mb, avail_kb / 1024);
		else
			LM_WARN("%s: refusing to grow by %lu MB: %lu MB effective"
				" (x%lu processes) would leave the memory cgroup (v%d) "
				"under its %lu MB floor (limit %lu MB, %lu MB in use). "
				"Raising the cgroup's memory limit or freeing memory in "
				"it lifts this.\n", hb->name, delta >> 20,
				(unsigned long)(effective >> 20), nproc, ci.version,
				ci.floor_mb, ci.limit_mb, ci.used_mb);
	}
	return 1;
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

/* the pkg policy, resolved once post-parse and inherited by fork - every
 * per-child arena pt.c creates copies it in at hg_malloc_init() time */
static struct {
	int valid;
	unsigned long up_bytes, down_bytes;
	unsigned int up_pct, up_need, up_window, down_pct, down_cycles;
	unsigned short cooldown;
} hg_pkg_pol_resolved;

/*
 * Fit a profile's targets to the cap the arena ACTUALLY reserved:
 * hg_autoscale_apply() validates against the cap asked for, but
 * hg_mem_reserve() reserves less when the hugetlb pool cannot back it, and
 * a scale-up target above hb->hcap would have every grow tick overrun the
 * mapping. Clamped, not refused: the config is correct, only this boot's
 * pool came up short, and a refusal would abort startup. At hcap the
 * ordinary ceiling path takes over.
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
	 * (p->mem_kb_units); rounding and the viability floor use THIS
	 * arena's page unit, so a small-mode arena is judged in 256 KB pages */
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
		/* the checks above judged the cap ASKED for; this one judges
		 * what the arena got. For pkg (@hb NULL) hg_malloc_init_cap()
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

	/* tcp_threads is known now: re-derive the private-cache divisor from
	 * the real IO-pool size, pre-fork so every worker inherits it */
	if (hg_shm && shm_block)
		hg_private_caps_retune((struct hg_block *)shm_block);
	if (hg_pkg && mem_block)
		hg_private_caps_retune((struct hg_block *)mem_block);

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

const char *hg_grow_refusal_str(unsigned int why)
{
	static const char * const str[HG_GR_REASONS] = {
		[HG_GR_NONE]         = "none",
		[HG_GR_CAP]          = "cap",
		[HG_GR_PROFILE]      = "profile_ceiling",
		[HG_GR_DRY_RUN]      = "dry_run",
		[HG_GR_WAIT_TIMEOUT] = "grow_wait_timeout",
		[HG_GR_HOST_FLOOR]   = "host_ram_floor",
		[HG_GR_CGROUP]       = "cgroup_limit",
		[HG_GR_MEMLOCK]      = "memlock_limit",
		[HG_GR_HUGETLB_POOL] = "hugetlb_pool",
		[HG_GR_MLOCK]        = "mlock_failed",
		[HG_GR_HOLE_REPIN]   = "hole_repin_failed",
	};

	return why < HG_GR_REASONS ? str[why] : "?";
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
 * Registry of live arena ranges, for the ownership tests in hg_malloc.h:
 * hg_owns_any() must place a pointer in any arena without being given a
 * block (hg_frag_size() has a fixed signature). A fixed array, since the
 * allocator must not allocate its own bookkeeping. Process-local: a child
 * inherits the parent's entries and adds its own pkg arena; the parent's
 * pkg entry stays, so a parent pkg pointer freed in a child still resolves
 * to mapped memory and is declined, not dereferenced.
 */
struct hg_arena_range hg_arena_reg[HG_ARENA_REG_MAX];

/*
 * Frees this process redirected to an arena other than the one the caller
 * named (see hg_owner()); not an error count. Expected to be a small
 * constant per child, set at startup: a figure that climbs with traffic
 * means something hands pointers across arenas at runtime.
 */
unsigned long hg_xarena_frees;

static void hg_arena_reg_add(struct hg_block *hb)
{
	int i;

	for (i = 0; i < HG_ARENA_REG_MAX; i++) {
		if (!hg_arena_reg[i].base) {
			hg_arena_reg[i].base = hb->hbase;
			/* the CAP, not the span, so a pointer into grown
			 * space never looks foreign; uncommitted VA holds no
			 * live cells to misattribute */
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
 * hg_malloc_init() reserves its own memory (fm_malloc_init() is handed
 * one) and puts the block header at its start, as fm_block/hp_block do, so
 * HG_MALLOC never allocates its own bookkeeping through shm_malloc() or
 * pkg_malloc(), which dispatch to it when it is selected.
 */
struct hg_block *hg_malloc_init(unsigned long size, char *name, int shared,
		const char *proc_desc, unsigned int flags)
{
	/* the core arenas take their cap by name (below); a module arena
	 * brings its own - see hg_arena_create() */
	return hg_malloc_init_cap(size, HG_CAP_BY_NAME, name, shared, proc_desc,
		flags);
}

/* the header-checksum secret: random when the kernel gives randomness,
 * else derived from the clock and the pid - it only has to differ between
 * runs, not resist an attacker */
static void hg_hdr_secret_init(void)
{
	unsigned long long s = 0;
	int fd;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd >= 0) {
		if (read(fd, &s, sizeof s) != (ssize_t)sizeof s)
			s = 0;
		close(fd);
	}
	if (!s) {
		struct timeval tv;

		gettimeofday(&tv, NULL);
		s = ((unsigned long long)tv.tv_sec << 32) ^ (unsigned long long)tv.tv_usec
			^ ((unsigned long long)getpid() << 16)
			^ (unsigned long long)(unsigned long)&s;
	}
	hg_hdr_secret = s | 1;
}

struct hg_block *hg_malloc_init_cap(unsigned long size, unsigned long cap_req,
		char *name, int shared, const char *proc_desc, unsigned int flags)
{
	enum hg_mem_tier tier;
	unsigned long locked_b;
	unsigned long cap, apage;
	char *base;
	struct hg_block *hb;
	int tier_decides;
	unsigned long cap_asked, mv;

	/* before the first arena, so before any fork: every process then
	 * checks headers against the same secret */
	if (!hg_hdr_secret)
		hg_hdr_secret_init();

	/* The reservation may exceed INIT, up to the admin cap; cap comes back
	 * as what was achieved (a hugetlb pool short of the cap gives a fixed
	 * arena, not none). By NAME, not @shared: shm_dbg is shared too but a
	 * fixed pool sized by hg_get_dbg_pool_size(). The caps come from
	 * -m/-M INIT:CAP on the command line: the config is parsed only after
	 * this arena exists. */
	if (cap_req != HG_CAP_BY_NAME)
		cap = cap_req;
	else if (!strcmp(name, "shm"))
		cap = hg_shm_cap_bytes;
	else if (!strcmp(name, "pkg"))
		cap = hg_pkg_cap_bytes;
	else
		cap = 0;
	apage = hg_arena_page(size, cap);
	/* INIT under one huge page with a cap at or above it: the backing the
	 * arena gets decides the page unit, so the reservation is made on the
	 * page grid and INIT is settled once the tier is known (below) */
	tier_decides = (apage == HG_HPS && size < HG_HPS);
	/* a small-mode arena with room above it can start on one page: what
	 * does not fit grows the arena instead of failing */
	mv = (apage < HG_HPS && cap > hg_page_round(size, apage)) ?
		apage : hg_min_viable(apage);
	if (!tier_decides && size < mv) {
		LM_ERR("%s arena: %lu %s is below the %lu %s minimum viable "
			"arena\n", name, HG_SZ_VAL(size), HG_SZ_UNIT(size),
			HG_SZ_VAL(mv), HG_SZ_UNIT(mv));
		return NULL;
	}
	/* the INIT is committed and pinned at once: refuse one the host
	 * cannot hold rather than let the kernel's OOM killer decide */
	if (!hg_init_fits(name, size, cap, (flags & HG_INIT_INHERITED) != 0))
		return NULL;
	cap_asked = cap;
	base = hg_mem_reserve(size, &cap, &tier, &locked_b, shared,
		(flags & HG_INIT_INHERITED) != 0, apage);
	if (!base) {
		LM_ERR("failed to reserve %lu bytes for %s HG_MALLOC arena\n",
			size, name);
		return NULL;
	}

	if (tier_decides && tier != HG_MEM_4K) {
		/* huge pages come whole: INIT becomes one. Refused only when
		 * the cap ASKED for leaves no room above that page (a pool
		 * too small for the cap already made the arena fixed) */
		if (hg_page_round(cap_asked, HG_HPS) <= HG_HPS) {
			LM_ERR("%s arena: on huge pages INIT is at least one huge "
				"page (%lu %s), which leaves no room to grow under the "
				"%lu %s cap - raise the cap, or give INIT as %lu %s for "
				"a fixed arena\n", name, HG_SZ_VAL(HG_HPS),
				HG_SZ_UNIT(HG_HPS), HG_SZ_VAL(cap_asked),
				HG_SZ_UNIT(cap_asked),
				HG_SZ_VAL(HG_HPS), HG_SZ_UNIT(HG_HPS));
			munmap(base, cap);
			return NULL;
		}
		LM_NOTICE("%s arena: INIT raised from %lu %s to %lu %s - on huge "
			"pages an arena holds at least one whole page\n", name,
			HG_SZ_VAL(size), HG_SZ_UNIT(size), HG_SZ_VAL(HG_HPS),
			HG_SZ_UNIT(HG_HPS));
		size = HG_HPS;
	} else if (tier_decides) {
		/* plain 4K pages: run the grid on small pages up to the cap, and
		 * hand back the part of the first huge page the reservation
		 * pre-faulted beyond INIT */
		unsigned long keep = hg_page_round(size, HG_SMALL_PAGE);

		/* one small page is enough here: the cap is at least a huge
		 * page above it, so the first allocations that do not fit grow
		 * the arena instead of failing */
		if (locked_b > keep) {
			munlock(base + keep, locked_b - keep);
			locked_b = keep;
		}
#ifdef __OS_linux
		/* off Linux these pages simply stay committed: there is no
		 * portable release, see hg_mem_release() */
		madvise(base + keep, HG_HPS - keep,
			shared ? MADV_REMOVE : MADV_DONTNEED);
#endif
		apage = HG_SMALL_PAGE;
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
	/* one committed-size step per grow: a growth spurt is a handful of
	 * commits, and one commit's pre-fault stays bounded. A small-mode
	 * arena steps one 256 KB page (16 MB would overshoot its cap). */
	hb->grow_granule = apage < HG_HPS ?
		apage : HG_HPS_ROUND(16UL << 20);
	/* shm_grow_granule / pkg_grow_granule, rounded to this arena's page.
	 * The shm arena predates the config and takes it in
	 * hg_autoscale_post_cfg(); per-child pkg arenas take it here. Module
	 * arenas keep the default. */
	if (!shared && hg_pkg_grow_granule)
		hb->grow_granule = hg_page_round(hg_pkg_grow_granule, apage);
	else if (shared && !strcmp(name, "shm") && hg_shm_grow_granule)
		hb->grow_granule = hg_page_round(hg_shm_grow_granule, apage);
	/* the shrink step: config, page-rounded, at least one page; the shm
	 * arena takes it again in hg_autoscale_post_cfg() */
	hb->shrink_step = hg_page_round(hg_shrink_step, apage);
	if (hb->shrink_step < apage)
		hb->shrink_step = apage;
	/* the page unit of this arena's grid (the huge page or 256 KB);
	 * hg_arena_init() lays the grid out from it */
	hb->hps = apage;
	hb->tier = tier;
	hb->locked_mb = locked_b >> 20;
	hb->unpinned = (tier != HG_MEM_HUGETLB && locked_b == 0);
	hb->tier_bytes[tier] = hb->committed_bytes;
	hb->shared = shared;
	/* the debug checks follow the allocator chosen for the memory this
	 * arena serves: a shared one (shm, shm_dbg, module arenas) that of shm,
	 * a private one that of pkg. The quarantine is a thousandth of the
	 * reservation per thread, within [16 KB, 1 MB]. */
#ifdef PKG_MALLOC
	hb->dbg = shared ? mem_allocator_shm == MM_HG_MALLOC_DBG :
	                   mem_allocator_pkg == MM_HG_MALLOC_DBG;
#else
	hb->dbg = shared && mem_allocator_shm == MM_HG_MALLOC_DBG;
#endif
	hb->quar_bytes = cap >> 10;
	if (hb->quar_bytes < HG_QUAR_MIN)
		hb->quar_bytes = HG_QUAR_MIN;
	else if (hb->quar_bytes > HG_QUAR_MAX)
		hb->quar_bytes = HG_QUAR_MAX;

	/*
	 * A per-child pkg arena, created after the config was parsed, takes
	 * the resolved pkg policy (copied by fork). The shm arena and the
	 * pre-fork parent pkg arena predate the config: shm gets its policy
	 * in hg_autoscale_post_cfg(), the parent pkg arena none.
	 */
	if (!shared && hg_pkg_pol_resolved.valid) {
		unsigned long up_b   = hg_pkg_pol_resolved.up_bytes;
		unsigned long down_b = hg_pkg_pol_resolved.down_bytes;

		/* validated against the -M cap asked for; THIS arena may have
		 * reserved less */
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

	/* "pinned from swapping", not "pinned": tier 1 is unswappable
	 * without mlock(), tiers 2-4 are mlock()ed - the same guarantee */
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
	 * Warn now (where -C sees it too), not at the first refused grow, when
	 * the memlock limit cannot cover growth. On hugetlb each grow must fit
	 * one delta plus what the process has locked, or it fails; on the other
	 * tiers the whole cap must fit to stay pinned, and growth past the
	 * limit goes on unpinned (hg_mem_commit()).
	 */
	if (hb->hcap > hb->committed_bytes) {
		unsigned long lim = hg_memlock_limit();
		unsigned long need = (tier == HG_MEM_HUGETLB) ?
			hb->grow_granule : hb->hcap;

		if (lim && lim < need && tier == HG_MEM_HUGETLB)
			LM_WARN("%s arena: RLIMIT_MEMLOCK is %lu KB, but growing "
				"on hugetlb pages needs %lu KB locked (one grow "
				"granule) - grows past the limit will be refused. Set "
				"LimitMEMLOCK=infinity in the service unit (or ulimit "
				"-l unlimited) before relying on the %lu %s cap.\n",
				name, lim >> 10, need >> 10,
				HG_SZ_VAL(hb->hcap), HG_SZ_UNIT(hb->hcap));
		else if (lim && lim < need)
			LM_WARN("%s arena: RLIMIT_MEMLOCK is %lu KB, less than the "
				"%lu %s cap - %s, so the arena can be swapped. Set "
				"LimitMEMLOCK=infinity in the service unit (or ulimit "
				"-l unlimited) to keep it pinned.\n",
				name, lim >> 10, HG_SZ_VAL(hb->hcap),
				HG_SZ_UNIT(hb->hcap), hb->unpinned ? "it runs unpinned "
				"and grows without pinning" : "grows past the limit "
				"continue unpinned");
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
 * Fork reset for every SHARED arena this process can see (core shm,
 * shm_dbg, module arenas); the per-arena logic is hg_arena_child_init().
 * A module arena used before fork (e.g. loading data in mod_init) leaves
 * cells in the parent's private cache, and without the reset every child
 * would flush the same cells into the shared pool. Private (pkg) arenas
 * are skipped: the inherited copy is self-consistent private memory, and
 * the child's own pkg arena, created after this, must keep its slots.
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

/* once, pre-fork, after the statistics engine starts (the call site of
 * hp_init_shm_statistics()): with one process, the "not on any free list"
 * walk is exact, unlike post-fork (see hg_arena_walk_live()) */
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

	/* carved-but-idle cells count as free, as q_malloc/f_malloc count a
	 * fragment on a free list, so real_used follows live demand;
	 * hb->real_used alone is the carve footprint, which never decreases */
	recycled = hg_slab_recycled(hb);
	info->real_used = hb->real_used > recycled ? hb->real_used - recycled : 0;
	/* room left to CARVE, not size minus live - see hg_get_free() */
	info->free = hb->size - hb->real_used;

	/* the peak of real_used as computed above, not of the carve
	 * (hb->max_real_used), which only grows */
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
	/* the live figures this process can see - its own slot(s) plus,
	 * for shm, every other process's */
	LM_GEN1(memdump, " live: used= %lu, fragments= %lu, cell bytes= %lu\n",
		hg_used(hb), hg_fragments(hb), hg_cell_live(hb));
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

	/* the walker derives cell addresses from chunk bookkeeping, so a
	 * corrupted chunk can yield an unmapped address; a diagnostic dump
	 * must never be what kills the process */
	if (!hg_owns_any(tag)) {
		hg_corrupt(NULL, HG_C_FOREIGN_PTR);
		LM_CRIT("%s: dump walker produced %p, outside every arena - "
			"skipping it\n", HG_MALLOC_NAME, payload);
		return;
	}

	/* read the DBG fields straight from the cell, as fm_status_dbg does:
	 * hg_frag_file()/func()/line() exist only under SHM_EXTRA_STATS, and
	 * this function depends on DBG_MALLOC alone */
	file = HG_CELL_AT(tag)->file;
	if (!file)
		return;   /* not stamped by hg_malloc_dbg() yet (e.g. first
		           * carve) - as fm_status_dbg's "if (f->file)" */
	func = HG_CELL_AT(tag)->func;
	line = HG_CELL_AT(tag)->line;

	/*
	 * Defence in depth: the walker takes a cell missing from its free set
	 * as live, so an incomplete set makes a free cell look live, and its
	 * file/func would be free-list linkage INTO THE ARENA, which
	 * dbg_ht_update() would read as strings. A real __FILE__ is in
	 * rodata, never in an arena.
	 */
	if (hg_owns_any((void *)file) || hg_owns_any((void *)func)) {
		c->skipped_notlive++;
		return;
	}

	if (dbg_ht_update(*c->allocd, file, func, line, hg_frag_size(payload)) < 0)
		LM_ERR("unable to update the %s allocation summary\n", HG_MALLOC_NAME);
}

/*
 * Per-allocation-site summary, as fm_status_dbg's: walk every live cell and
 * large fragment, aggregate by (file, func, line) in mem_dbg_hash (plain
 * malloc, allocator-independent), dump, free. Exact pre-fork; post-fork it
 * cannot see cells idling in another worker's private cache (see
 * hg_arena_walk_live()). Large fragments are always exact.
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
 * hg_cell_alloc()/hg_cell_free() live in hg_arena.c, so their arity is
 * fixed by the ORIGINAL DBG_MALLOC state (f_malloc's helpers are recompiled
 * in each pass instead). hg_malloc_dyn.h's second pass, after the #undef
 * below, must NOT test DBG_MALLOC for that arity; this sentinel keeps the
 * original state.
 */
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
 * A module can get its own arena, managed by HG_MALLOC like shm: slab
 * classes and per-process caches, block GC and re-typing, growth and shrink
 * within its INIT:CAP, the maintenance process, hg_stats. Created before
 * fork (mod_init), so every child inherits the shared mapping; the
 * registry routes each free to the owning arena. Independent of -a: the
 * core allocator can be anything.
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
	/* an INIT under one huge page with a cap at or above it is settled
	 * by hg_malloc_init_cap() once the backing tier is known */
	if (!(hg_arena_page(init_bytes, cap_bytes) == HG_HPS &&
	      init_bytes < HG_HPS) &&
	    init_bytes < hg_min_viable(hg_arena_page(init_bytes, cap_bytes))) {
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
