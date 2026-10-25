/*
 * slab allocator with elastic arenas - statistics and lock instrumentation
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
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>   /* sysconf, for the IO-pool consumer count */

#include "hg_malloc.h"
#include "hg_arena.h"
#include "hg_buddy.h"
#include "hg_large.h"
#include "hg_dbg.h"
#include "../dprint.h"
#include "../globals.h"
#include "hg_arena_int.h"

/*
 * Slab bytes carved into chunks but not handed out - on a private free stack,
 * in the global pool, or never bumped; fully reusable. hg_get_real_used()
 * subtracts it from real_used, so free cells read as free, as a fragment on
 * a q_malloc/f_malloc free list does.
 */
unsigned long hg_slab_recycled(struct hg_block *hb)
{
	unsigned long capacity, live;

	/* no registry walk, which would need hb->lock (hg_gc_class() returns
	 * chunks to the buddy): slab_capacity is a running sum kept by
	 * carve_chunk()/hg_gc_class(), read unlocked - a torn read is at worst
	 * one chunk off, for a figure that is a sample either way */
	capacity = hb->slab_capacity;
	live = hg_cell_live(hb);
	return capacity > live ? capacity - live : 0;
}

void hg_arena_stats(struct hg_block *hb, unsigned int *nchunks,
		unsigned long *bytes)
{
	hg_lock_enter(hb, HG_LK_STATS);
	*nchunks = hb->nchunks;
	*bytes = hb->real_used;
	hg_lock_leave(hb);
}

#ifdef SHM_EXTRA_STATS
static void hg_stats_core_init_cb(void *payload, void *ctx)
{
	HG_STATS_IDX(payload) = (unsigned long)*(int *)ctx;
}

void hg_arena_stats_core_init(struct hg_block *hb, int core_index)
{
	hg_arena_walk_live(hb, hg_stats_core_init_cb, &core_index);
	hg_large_stats_core_init(hb, core_index);
}
#endif



/* =========================================================================
 * Statistics (registered by hg_register_stats() below)
 *
 * The hg_stats figures as core statistics, so a dashboard can attribute
 * huge-page use to the allocator. Named hg_shm_* under "hgmem", apart from a
 * caching module's own huge-page statistics, which describe that module's
 * own reservation - different memory.
 * ========================================================================= */

#include "../statistics.h"
#include "shm_mem.h"   /* mem_allocator_shm */
#include "mem.h"       /* mem_allocator_pkg */

/* this thread's stats slot, -1 = the process's own (see hg_pstat_mine) */
__thread int hg_pstat_slot = -1;

void hg_thread_stats_init(void)
{
	struct hg_block *hb = (struct hg_block *)shm_block;
	static unsigned int local_next = HG_STAT_SLOTS - 1;
	static int said;
	unsigned int *next, s;

	if (hg_pstat_slot >= 0)
		return;
	/* the shared counter when shm is HG_MALLOC, else a per-process one
	 * (threads exist in one process today; a second kind would collide only
	 * on a pkg arena, which is private anyway) */
	next = (hb && (mem_allocator_shm == MM_HG_MALLOC ||
	               mem_allocator_shm == MM_HG_MALLOC_DBG)) ?
	       &hb->thread_slot_next : &local_next;
	s = __atomic_fetch_sub(next, 1, __ATOMIC_ACQ_REL);
	if (s <= HG_STAT_SLOTS / 4 || s >= HG_STAT_SLOTS) {
		/* out of thread slots: share the process slot */
		if (!said) {
			said = 1;
			LM_WARN("no free per-thread stats slot (claimed %u of %u) - this "
				"thread shares its process's slot\n", s, HG_STAT_SLOTS);
		}
		return;
	}
	hg_pstat_slot = (int)s;
}

/* --- lock-stall bookkeeping (called after the release) ----------------- */
const char * const hg_lk_reason_str[HG_LK_REASONS] = {
	"refill", "return", "flush", "large", "policy", "stats", "other"
};

void hg_lock_assert_held(struct hg_block *hb, const char *where)
{
	if (hb->lk_cur != HG_LK_NONE)
		return;
	hg_corrupt(hb, HG_C_INTERNAL);
	LM_BUG("%s: %s without hb->lock held - a lock-dropping callee broke its "
		"contract (hold on entry, held again on return)", hb->name, where);
}

void hg_lock_stall_note(struct hg_block *hb, int reason, unsigned long held_ns)
{
	/* once per second per process: a stall storm must not become a log
	 * storm, the counters and the deferred event carry the magnitude */
	static unsigned long last_warn_ns;
	unsigned long now = hg_now_ns();

	if (last_warn_ns && now - last_warn_ns < 1000000000UL)
		return;
	last_warn_ns = now;
	LM_WARN("%s arena lock held for %lu us by the %s path (threshold "
		"hg_lock_stall_us=%d; %lu stalls so far, worst %lu us by %s in "
		"process %d)\n", hb->name, held_ns / 1000,
		reason >= 0 && reason < HG_LK_REASONS ? hg_lk_reason_str[reason] : "?",
		hg_lock_stall_us, hb->lk_stalls, hb->lk_worst_ns / 1000,
		hb->lk_worst_reason >= 0 && hb->lk_worst_reason < HG_LK_REASONS ?
			hg_lk_reason_str[hb->lk_worst_reason] : "?",
		hb->lk_worst_proc);
}

enum hg_stat_field {
	HGS_TIER = 0, HGS_TOTAL, HGS_PINNED_BYTES, HGS_CARVED, HGS_CARVED_PEAK,
	HGS_CHUNKS, HGS_FREE_TO_CARVE, HGS_LIVE, HGS_LIVE_PEAK, HGS_PAYLOAD,
	HGS_CELLS, HGS_SLAB_LIVE, HGS_SLAB_RECYCLED,
	/* reclaim rates: counters, not events - an EVI event per transition
	 * would cost more than the allocator it reports on */
	HGS_BLOCKS_CARVED, HGS_BLOCKS_RETURNED, HGS_GC_PASSES,
	HGS_CACHE_FLUSHES, HGS_CELLS_FLUSHED, HGS_PRESSURE_FLUSHES, HGS_PRESSURE_CELLS,
	HGS_GC_TICK_BLOCKS, HGS_GC_INLINE_BLOCKS, HGS_GC_KEPT_BLOCKS, HGS_SWEEPS_SKIPPED,
	HGS_BUDDY_SPLITS, HGS_BUDDY_MERGES, HGS_BUDDY_FREE_LEAVES,
	/* large tier footprint, and the reserve floor - without these last
	 * three the floor is invisible outside a one-shot log line */
	HGS_LARGE_BACKING, HGS_LARGE_LIVE, HGS_LARGE_RECYCLED,
	HGS_LARGE_CHUNKS_CARVED, HGS_LARGE_CHUNKS_RETURNED,
	HGS_RESERVE_FLOOR, HGS_BELOW_FLOOR, HGS_FLOOR_CROSSINGS,
	/* one number an operator can alert on; the breakdown is in hg_stats */
	HGS_CORRUPTION,
	/* elastic arena: committed vs reserved, and the grow ledger. Alert on
	 * grow_refused rising: demand hit the cap or the host */
	HGS_COMMITTED, HGS_CAP, HGS_GROWS, HGS_GROW_BYTES, HGS_GROW_REFUSED,
	HGS_SHRINKS, HGS_SHRINK_BYTES,
	HGS_PUNCHES, HGS_PUNCH_BYTES, HGS_PUNCHED_PAGES, HGS_WHOLE_FREE_PAGES,
	HGS_REPINS, HGS_REPIN_FAILED, HGS_HOLE_REGROWS,
	/* the alertable gauge: 1 while a resource refusal is latched (cap
	 * refusals never latch - an admin ceiling is policy, not incident) */
	HGS_GROW_BLOCKED,
	HGS_LOCK_STALLS, HGS_LOCK_HOLD_MAX_US,
	HGS_GROWS_PROACTIVE, HGS_GROWS_EXHAUSTION,
};

static unsigned long hg_shm_stat(void *ctx)
{
	struct hg_block *hb = (struct hg_block *)shm_block;

	if (!hb)
		return 0;
	switch ((enum hg_stat_field)(long)ctx) {
	case HGS_TIER:          return hb->tier;
	case HGS_TOTAL:         return hb->size;
	/* bytes rather than the MB the MI reports, so it composes with the
	 * other byte-valued statistics and with node_exporter's page counts */
	case HGS_PINNED_BYTES:  return (unsigned long)hb->locked_mb << 20;
	/* carved: slab blocks plus whole large-tier chunks, what free_to_carve
	 * counts down from. Not monotonic: hg_gc_class() subtracts a returned
	 * block, so carved below carved_peak means reclaim is working */
	case HGS_CARVED:        return hb->real_used;
	case HGS_CARVED_PEAK:   return hb->max_real_used;
	case HGS_CHUNKS:        return hb->nchunks;
	case HGS_FREE_TO_CARVE: return hb->size - hb->real_used;
	/* live: handed out right now. The gap to carved is free cells,
	 * reusable only within their class - slab behaviour, not a leak */
	case HGS_LIVE:          return hg_get_real_used(hb);
	case HGS_LIVE_PEAK:     return hb->max_live_used;
	case HGS_PAYLOAD:       return hg_used(hb);
	case HGS_CELLS:         return hg_fragments(hb);
	/* slab only: large allocations go to the boundary-tag tier and never
	 * appear here, so this is deliberately not comparable with payload */
	case HGS_SLAB_LIVE:     return hg_cell_live(hb);
	case HGS_SLAB_RECYCLED: return hg_slab_recycled(hb);
	/* reclaim rates: carved minus returned is the live block count, and
	 * returned/carved shows how well reclaim keeps up */
	case HGS_BLOCKS_CARVED:   return hb->blocks_carved;
	case HGS_BLOCKS_RETURNED: return hb->gc_blocks_returned;
	case HGS_GC_PASSES:       return hb->gc_passes;
	case HGS_CACHE_FLUSHES:   return hb->cache_flushes;
	case HGS_CELLS_FLUSHED:   return hb->cells_flushed;
	case HGS_PRESSURE_FLUSHES: return hb->pressure_flushes;
	case HGS_PRESSURE_CELLS:  return hb->pressure_cells;
	case HGS_GC_TICK_BLOCKS:   return hb->gc_tick_blocks;
	case HGS_GC_INLINE_BLOCKS: return hb->gc_inline_blocks;
	case HGS_SWEEPS_SKIPPED:   return hb->sweeps_skipped;
	case HGS_GC_KEPT_BLOCKS: {
		unsigned long n = 0;
		int c;

		for (c = 0; c < HG_NCLASSES; c++)
			n += hb->ndrained[c];
		return n;
	}
	case HGS_BUDDY_SPLITS:    return hb->buddy_splits;
	case HGS_BUDDY_MERGES:    return hb->buddy_merges;
	case HGS_BUDDY_FREE_LEAVES: return hb->buddy_free_leaves;
	case HGS_LARGE_BACKING:   return hb->large_backing;
	case HGS_LARGE_LIVE:      return hb->large_live;
	case HGS_LARGE_RECYCLED:  return hg_large_recycled(hb);
	case HGS_LARGE_CHUNKS_CARVED:   return hb->large_chunks_carved;
	case HGS_LARGE_CHUNKS_RETURNED: return hb->large_chunks_returned;
	case HGS_RESERVE_FLOOR:   return hb->reserve_floor;
	case HGS_BELOW_FLOOR:     return hb->below_floor;
	case HGS_FLOOR_CROSSINGS: return hb->floor_crossings;
	case HGS_CORRUPTION:      return hg_corrupt_total(hb);
	case HGS_COMMITTED:       return hb->committed_bytes;
	case HGS_CAP:             return hb->hcap;
	case HGS_GROWS:           return hb->grows;
	case HGS_GROW_BYTES:      return hb->grow_bytes;
	case HGS_GROW_REFUSED:    return hb->grow_refused;
	case HGS_GROW_BLOCKED:    return hb->grow_blocked;
	case HGS_LOCK_STALLS:     return hb->lk_stalls;
	case HGS_LOCK_HOLD_MAX_US: return hb->lk_worst_ns / 1000;
	case HGS_GROWS_PROACTIVE: return hb->grows_proactive;
	case HGS_GROWS_EXHAUSTION: return hb->grows_exhaustion;
	case HGS_SHRINKS:         return hb->shrinks;
	case HGS_SHRINK_BYTES:    return hb->shrink_bytes;
	case HGS_PUNCHES:         return hb->punches;
	case HGS_PUNCH_BYTES:     return hb->punch_bytes;
	case HGS_PUNCHED_PAGES:   return hb->punched_pages;
	case HGS_WHOLE_FREE_PAGES: return hb->nfree[hb->buddy_top];
	case HGS_REPINS:          return hb->repins;
	case HGS_REPIN_FAILED:    return hb->repin_failed;
	case HGS_HOLE_REGROWS:    return hb->hole_regrows;
	}
	return 0;
}

static const struct {
	const char *name;
	enum hg_stat_field field;
} hg_stat_defs[] = {
	{"hg_shm_tier",          HGS_TIER},
	{"hg_shm_total_size",    HGS_TOTAL},
	{"hg_shm_pinned_bytes",  HGS_PINNED_BYTES},
	{"hg_shm_carved",        HGS_CARVED},
	{"hg_shm_carved_peak",   HGS_CARVED_PEAK},
	{"hg_shm_chunks",        HGS_CHUNKS},
	{"hg_shm_free_to_carve", HGS_FREE_TO_CARVE},
	{"hg_shm_live",          HGS_LIVE},
	{"hg_shm_live_peak",     HGS_LIVE_PEAK},
	{"hg_shm_live_payload",  HGS_PAYLOAD},
	{"hg_shm_live_cells",    HGS_CELLS},
	{"hg_shm_slab_live",     HGS_SLAB_LIVE},
	{"hg_shm_slab_recycled", HGS_SLAB_RECYCLED},
	{"hg_shm_blocks_carved",   HGS_BLOCKS_CARVED},
	{"hg_shm_blocks_returned", HGS_BLOCKS_RETURNED},
	{"hg_shm_gc_passes",       HGS_GC_PASSES},
	{"hg_shm_cache_flushes",   HGS_CACHE_FLUSHES},
	{"hg_shm_cells_flushed",   HGS_CELLS_FLUSHED},
	{"hg_shm_pressure_flushes", HGS_PRESSURE_FLUSHES},
	{"hg_shm_pressure_cells",   HGS_PRESSURE_CELLS},
	{"hg_shm_gc_tick_blocks",   HGS_GC_TICK_BLOCKS},
	{"hg_shm_gc_inline_blocks", HGS_GC_INLINE_BLOCKS},
	{"hg_shm_gc_kept_blocks",   HGS_GC_KEPT_BLOCKS},
	{"hg_shm_sweeps_skipped",   HGS_SWEEPS_SKIPPED},
	{"hg_shm_buddy_splits",    HGS_BUDDY_SPLITS},
	{"hg_shm_buddy_merges",    HGS_BUDDY_MERGES},
	{"hg_shm_buddy_free_leaves", HGS_BUDDY_FREE_LEAVES},
	{"hg_shm_large_backing",   HGS_LARGE_BACKING},
	{"hg_shm_large_live",      HGS_LARGE_LIVE},
	{"hg_shm_large_recycled",  HGS_LARGE_RECYCLED},
	{"hg_shm_large_chunks_carved",   HGS_LARGE_CHUNKS_CARVED},
	{"hg_shm_large_chunks_returned", HGS_LARGE_CHUNKS_RETURNED},
	{"hg_shm_reserve_floor",   HGS_RESERVE_FLOOR},
	{"hg_shm_below_floor",     HGS_BELOW_FLOOR},
	{"hg_shm_floor_crossings", HGS_FLOOR_CROSSINGS},
	{"hg_shm_corruption",      HGS_CORRUPTION},
	{"hg_shm_committed",       HGS_COMMITTED},
	{"hg_shm_cap",             HGS_CAP},
	{"hg_shm_grows",           HGS_GROWS},
	{"hg_shm_grow_bytes",      HGS_GROW_BYTES},
	{"hg_shm_grow_refused",    HGS_GROW_REFUSED},
	{"hg_shm_grow_blocked",    HGS_GROW_BLOCKED},
	{"hg_shm_lock_stalls",     HGS_LOCK_STALLS},
	{"hg_shm_lock_hold_max_us", HGS_LOCK_HOLD_MAX_US},
	{"hg_shm_grows_proactive", HGS_GROWS_PROACTIVE},
	{"hg_shm_grows_exhaustion", HGS_GROWS_EXHAUSTION},
	{"hg_shm_shrinks",         HGS_SHRINKS},
	{"hg_shm_shrink_bytes",    HGS_SHRINK_BYTES},
	{"hg_shm_punches",         HGS_PUNCHES},
	{"hg_shm_punch_bytes",     HGS_PUNCH_BYTES},
	{"hg_shm_punched_pages",   HGS_PUNCHED_PAGES},
	{"hg_shm_whole_free_pages", HGS_WHOLE_FREE_PAGES},
	{"hg_shm_repins",          HGS_REPINS},
	{"hg_shm_repin_failed",    HGS_REPIN_FAILED},
	{"hg_shm_hole_regrows",    HGS_HOLE_REGROWS},
	{NULL, 0}
};

int hg_register_stats(void)
{
	int i;

#ifdef PKG_MALLOC
	if ((mem_allocator_pkg == MM_HG_MALLOC ||
	     mem_allocator_pkg == MM_HG_MALLOC_DBG) &&
	    (register_stat2("hgmem", "hg_pkg_grow_refused",
	        (stat_var **)hg_pkg_pub_stat, STAT_NO_RESET|STAT_IS_FUNC,
	        (void *)0L, 0) != 0 ||
	     register_stat2("hgmem", "hg_pkg_grow_blocked",
	        (stat_var **)hg_pkg_pub_stat, STAT_NO_RESET|STAT_IS_FUNC,
	        (void *)1L, 0) != 0)) {
		LM_ERR("failed to add the pkg growth statistics\n");
		return -1;
	}
#endif

	if (mem_allocator_shm != MM_HG_MALLOC &&
	        mem_allocator_shm != MM_HG_MALLOC_DBG)
		return 0;       /* another allocator is in use */

	for (i = 0; hg_stat_defs[i].name; i++) {
		if (register_stat2("hgmem", (char *)hg_stat_defs[i].name,
		        (stat_var **)hg_shm_stat, STAT_NO_RESET|STAT_IS_FUNC,
		        (void *)(long)hg_stat_defs[i].field, 0) != 0) {
			LM_ERR("failed to add the %s statistic\n", hg_stat_defs[i].name);
			return -1;
		}
	}
	return 0;
}
#endif /* HG_MALLOC, statistics included */
