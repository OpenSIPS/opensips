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
#include "hg_backing.h"

/* round @s up to a whole number of huge pages */
#define HG_HPS_ROUND(s) (((s) + HG_HPS - 1) & ~(HG_HPS - 1))

/* HG_ROUNDTO=2^k so the following works (same trick as f_malloc.c) */
#define ROUNDTO_MASK   (~((unsigned long)HG_ROUNDTO-1))
#define ROUNDUP_TO(s)  (((s)+(HG_ROUNDTO-1))&ROUNDTO_MASK)

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
	info->min_frag = 64; /* smallest cell class, see cell_sizes */
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
