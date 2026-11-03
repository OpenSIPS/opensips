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
#include <sys/resource.h>

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

/* once per sweep interval: every process sees a shared arena, so no
 * per-process reporting */
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

/* Samples the shared arenas' live peak every second from the sweep timer
 * (O(1), lock-free), so a peak no statistics read saw is still kept */
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

/* Fit a profile's targets to the cap the arena ACTUALLY reserved (a short
 * hugetlb pool reserves less): clamped, not refused, so startup goes on */
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

/* @hb NULL (pkg, no arena yet): validate only, into hg_pkg_pol_resolved */
static int hg_autoscale_apply(struct hg_block *hb, const char *which,
		struct scaling_profile *p, unsigned long init_bytes,
		unsigned long cap_bytes)
{
	/* profile numbers are MB (KB with a size suffix); rounding and the
	 * viability floor use THIS arena's page unit */
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
		if (down_b)
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
	int hg_pkg = 0;
#endif

	if (hg_shm && shm_block)
		hg_private_caps_retune((struct hg_block *)shm_block);
	if (hg_pkg && mem_block)
		hg_private_caps_retune((struct hg_block *)mem_block);

	/* arenas made before the config take hg_mem_check only from here on */
	{
		int i;

		for (i = 0; i < HG_ARENA_REG_MAX; i++)
			if (hg_arena_reg[i].hb)
				hg_arena_reg[i].hb->guard = !hg_arena_reg[i].hb->dbg &&
					hg_mem_check > 0;
	}
	if (hg_mem_check && !hg_shm && !hg_pkg)
		LM_WARN("hg_mem_check ignored: neither shm nor pkg is "
			HG_MALLOC_NAME "\n");

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

/* a fixed array: the allocator must not allocate its own bookkeeping */
struct hg_arena_range hg_arena_reg[HG_ARENA_REG_MAX];

/* frees redirected to another arena: a small constant per child is
 * expected, one that climbs with traffic is not */
unsigned long hg_xarena_frees;

static int hg_arena_reg_add(struct hg_block *hb)
{
	int i;

	for (i = 0; i < HG_ARENA_REG_MAX; i++) {
		if (!hg_arena_reg[i].base) {
			hg_arena_reg[i].base = hb->hbase;
			/* the CAP, not the span, so a pointer into grown space
			 * never looks foreign */
			hg_arena_reg[i].size = hb->hcap;
			hg_arena_reg[i].hb   = hb;
			return 0;
		}
	}
	/* not fatal for a private arena: only diagnostics suffer */
	LM_WARN("%s: more than %d live HG_MALLOC arenas in one process - "
		"ownership checks will be incomplete\n", hb->name,
		HG_ARENA_REG_MAX);
	return -1;
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

struct hg_block *hg_malloc_init(unsigned long size, char *name, int shared,
		const char *proc_desc, unsigned int flags)
{
	return hg_malloc_init_cap(size, HG_CAP_BY_NAME, name, shared, proc_desc,
		flags);
}

/* /dev/urandom, else clock and pid: it only has to differ between runs,
 * not resist an attacker */
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

	if (!hg_hdr_secret)
		hg_hdr_secret_init();

	/* by NAME, not @shared: shm_dbg is shared but fixed */
	if (cap_req != HG_CAP_BY_NAME)
		cap = cap_req;
	else if (!strcmp(name, "shm"))
		cap = hg_shm_cap_bytes;
	else if (!strcmp(name, "pkg"))
		cap = hg_pkg_cap_bytes;
	else
		cap = 0;
	/* every rounding below is to a page of at most HG_HPS */
	if (!hg_page_roundable(size, HG_HPS) || !hg_page_roundable(cap, HG_HPS)) {
		LM_ERR("%s arena: %lu bytes, cap %lu, cannot be rounded to a page\n",
			name, size, cap);
		return NULL;
	}
	apage = hg_arena_page(size, cap);
	/* INIT under one huge page with a cap at or above it: the backing tier
	 * decides the page unit, and INIT is settled once it is known */
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
	if (!hg_init_fits(name, size, cap, !shared))
		return NULL;
	cap_asked = cap;
	base = hg_mem_reserve(size, &cap, &tier, &locked_b, shared, apage);
	if (!base) {
		LM_ERR("failed to reserve %lu bytes for %s HG_MALLOC arena\n",
			size, name);
		return NULL;
	}

	if (tier_decides && tier != HG_MEM_4K) {
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
		/* plain 4K pages: run the grid on small pages and hand back
		 * the part of the first huge page pre-faulted beyond INIT */
		unsigned long keep = hg_page_round(size, HG_SMALL_PAGE);

		if (locked_b > keep) {
			munlock(base + keep, locked_b - keep);
			locked_b = keep;
		}
#ifdef __OS_linux
		madvise(base + keep, HG_HPS - keep,
			shared ? MADV_REMOVE : MADV_DONTNEED);
#endif
		apage = HG_SMALL_PAGE;
	}

	if (size < ROUNDUP_TO(sizeof(struct hg_block))) {
		LM_ERR("%s arena of %lu bytes too small for the block header "
			"(%zu bytes)\n", name, size, sizeof(struct hg_block));
		munmap(base, cap);
		return NULL;
	}

	hb = (struct hg_block *)(void *)base;
	memset(hb, 0, sizeof *hb);
	hb->name = name;
	hb->hbase = base;
	hb->span_end = hg_page_round(size, apage);
	/* the span, not INIT: the grid covers the page-rounded span, and every
	 * "free" figure (size - real_used) would wrap otherwise */
	hb->size = hb->span_end;
	hb->committed_bytes = hb->span_end;
	hb->committed_min = hb->committed_bytes;
	hb->span_pending = hb->span_end;
	hb->hcap = cap;
	/* a step bounds a commit's pre-fault; a small-mode arena steps one page,
	 * as 16 MB would overshoot its cap */
	hb->grow_granule = apage < HG_HPS ?
		apage : HG_HPS_ROUND(16UL << 20);
	/* the shm arena predates the config, so hg_autoscale_post_cfg() sets its
	 * granule; module arenas keep the default */
	if (!shared && hg_pkg_grow_granule)
		hb->grow_granule = hg_page_round(hg_pkg_grow_granule, apage);
	else if (shared && !strcmp(name, "shm") && hg_shm_grow_granule)
		hb->grow_granule = hg_page_round(hg_shm_grow_granule, apage);
	hb->shrink_step = hg_page_round(hg_shrink_step, apage);
	if (hb->shrink_step < apage)
		hb->shrink_step = apage;
	hb->hps = apage;
	hb->tier = tier;
	hb->locked_mb = locked_b >> 20;
	hb->unpinned = (tier != HG_MEM_HUGETLB && locked_b == 0);
	hb->tier_bytes[tier] = hb->committed_bytes;
	hb->shared = shared;
#ifdef PKG_MALLOC
	hb->dbg = shared ? mem_allocator_shm == MM_HG_MALLOC_DBG :
	                   mem_allocator_pkg == MM_HG_MALLOC_DBG;
#else
	hb->dbg = shared && mem_allocator_shm == MM_HG_MALLOC_DBG;
#endif
	hb->guard = !hb->dbg && hg_mem_check > 0;
	hb->quar_bytes = cap >> 10;
	if (hb->quar_bytes < HG_QUAR_MIN)
		hb->quar_bytes = HG_QUAR_MIN;
	else if (hb->quar_bytes > HG_QUAR_MAX)
		hb->quar_bytes = HG_QUAR_MAX;

	/* shm gets its policy in hg_autoscale_post_cfg(); the pre-fork pkg arena,
	 * made before the policy resolves, gets none */
	if (!shared && hg_pkg_pol_resolved.valid) {
		unsigned long up_b   = hg_pkg_pol_resolved.up_bytes;
		unsigned long down_b = hg_pkg_pol_resolved.down_bytes;

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

	if (hg_arena_reg_add(hb) < 0 && shared) {
		LM_ERR("%s: a shared arena must be in the arena registry, which "
			"resets its caches at fork - not creating it\n", name);
		lock_destroy(&hb->lock);
		munmap(base, hb->hcap);
		return NULL;
	}

	if (hg_arena_init(hb, ROUNDUP_TO(sizeof(struct hg_block))) < 0) {
		LM_ERR("failed to init the %s arena\n", name);
		/* or hg_owner() would route a later free into the unmapped range */
		hg_arena_reg_del(hb);
		lock_destroy(&hb->lock);
		munmap(base, hb->hcap);
		return NULL;
	}
	backed_fast_update(hb);

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
			" (pre-fork arena, inherited copy-on-write by every child)" :
			"");
	if (hb->hcap > hb->committed_bytes)
		LM_NOTICE("%s arena can grow to %lu %s (%lu %s headroom "
			"reserved, uncommitted)\n", name,
			HG_SZ_VAL(hb->hcap), HG_SZ_UNIT(hb->hcap),
			HG_SZ_VAL(hb->hcap - hb->committed_bytes),
			HG_SZ_UNIT(hb->hcap - hb->committed_bytes));

	/* warn now (-C sees it too) if the memlock limit cannot cover growth:
	 * hugetlb needs a granule, other tiers the whole cap to stay pinned */
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
	/* the whole cap, not the committed part: the reservation is one mapping */
	munmap(hb->hbase, hb->hcap);
}

void hg_malloc_child_init(struct hg_block *hb)
{
	if (hb)
		hg_arena_child_init(hb);
}

/* a SHARED arena's reset, or each child would flush the parent's cached
 * cells into the shared pool */
void hg_malloc_child_init_all(void)
{
	int i;

	for (i = 0; i < HG_ARENA_REG_MAX; i++) {
		struct hg_block *hb = hg_arena_reg[i].hb;

		if (!hb)
			continue;
		if (hb->shared)
			hg_arena_child_init(hb);
		else
			hb->inherited = 1;
	}
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

/* pre-fork: with one process the "not on any free list" walk is exact */
void hg_stats_core_init(struct hg_block *hb, int core_index)
{
	hg_arena_stats_core_init(hb, core_index);
}
#endif

void hg_info(struct hg_block *hb, struct mem_info *info)
{
	memset(info, 0, sizeof *info);
	info->total_size = hb->size;
	info->min_frag = 64; /* smallest cell class, see cell_sizes */
	info->used = hg_used(hb);
	info->real_used = hg_get_real_used(hb);
	info->free = hg_free_to_carve(hb);
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
	LM_GEN1(memdump, " live: used= %lu, fragments= %lu, cell bytes= %lu\n",
		hg_used(hb), hg_fragments(hb), hg_cell_live(hb));
}

#if !defined INLINE_ALLOC && defined DBG_MALLOC
struct hg_dbg_dump_ctx {
	mem_dbg_htable_t *allocd;
	unsigned long skipped_notlive;
};

static void hg_dbg_dump_cb(void *payload, void *ctx)
{
	struct hg_dbg_dump_ctx *c = ctx;
	char *tag = HG_HDR(payload);
	const char *file, *func;
	unsigned long line;

	/* a corrupted chunk can yield an unmapped cell address; a diagnostic
	 * dump must never be what kills the process */
	if (!hg_owns_any(tag)) {
		LM_CRIT("%s: dump walker produced %p, outside every arena - "
			"skipping it\n", HG_MALLOC_NAME, payload);
		hg_corrupt(NULL, HG_C_FOREIGN_PTR);
		return;
	}

	/* read the DBG fields straight from the cell: hg_frag_file() and co
	 * exist only under SHM_EXTRA_STATS, this needs only DBG_MALLOC */
	file = HG_CELL_AT(tag)->file;
	if (!file)
		return;   /* not stamped by hg_malloc_dbg() yet, e.g. a fresh carve */
	func = HG_CELL_AT(tag)->func;
	line = HG_CELL_AT(tag)->line;

	/* a free cell taken as live holds free-list links INTO THE ARENA where
	 * file/func should be; a real __FILE__ is in rodata, never an arena */
	if (hg_owns_any((void *)file) || hg_owns_any((void *)func)) {
		c->skipped_notlive++;
		return;
	}

	if (dbg_ht_update(*c->allocd, file, func, line, hg_frag_size(payload)) < 0)
		LM_ERR("unable to update the %s allocation summary\n", HG_MALLOC_NAME);
}

/* Per-allocation-site summary, as fm_status_dbg's: exact pre-fork, but
 * post-fork it misses cells idling in other workers' private caches */
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

/* hg_cell_alloc()/hg_cell_free() (hg_arena.c) take the ORIGINAL DBG_MALLOC's
 * arity; the second hg_malloc_dyn.h pass below tests this, not DBG_MALLOC */
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
	if (!hg_page_roundable(cap_bytes, HG_HPS)) {
		LM_ERR("module arena '%s': a %lu byte cap cannot be rounded to a "
			"page\n", name, cap_bytes);
		return NULL;
	}
	/* the tier_decides case of hg_malloc_init_cap() is settled there */
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
