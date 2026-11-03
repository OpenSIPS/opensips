/*
 * HG_MALLOC MI commands: core:hg_stats and core:hg_advise
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#ifdef HG_MALLOC

#include <string.h>
#include <time.h>

#include "../dprint.h"
#include "../globals.h"
#include "../pt.h"
#include "../mem/mem.h"
#include "../mem/shm_mem.h"
#include "../mem/hg_malloc.h"
#include "../mem/hg_advise.h"
#include "mi.h"
#include "mi_hg.h"

/* hg_stats/hg_advise: HG_MALLOC carves size-class chunks, so committed,
 * live and still-available differ - more than shmem:/pkgmem: can say */
static int hg_stats_lk(mi_item_t *parent, const char *name,
                       const struct hg_lkstat *st)
{
	mi_item_t *o, *h;
	int b;

	if (!st->n)
		return 0;
	o = add_mi_object(parent, (char *)name, strlen(name));
	if (!o)
		return -1;
	if (add_mi_number(o, MI_SSTR("n"), st->n) < 0 ||
	    add_mi_number(o, MI_SSTR("mean_us"), st->total_ns / st->n / 1000) < 0 ||
	    add_mi_number(o, MI_SSTR("max_us"), st->max_ns / 1000) < 0 ||
	    add_mi_number(o, MI_SSTR("stalls"), st->stalls) < 0)
		return -1;
	h = add_mi_array(o, MI_SSTR("hist_log2us"));
	if (!h)
		return -1;
	for (b = 0; b < HG_LK_BUCKETS; b++)
		if (add_mi_number(h, NULL, 0, st->hist[b]) < 0)
			return -1;
	return 0;
}

static int hg_stats_lock(mi_item_t *parent, struct hg_block *hb)
{
	mi_item_t *o, *ho, *wo;
	const char *r;
	int i;

	o = add_mi_object(parent, MI_SSTR("lock"));
	if (!o)
		return -1;
	if (add_mi_number(o, MI_SSTR("stall_threshold_us"), hg_lock_stall_us) < 0 ||
	    add_mi_number(o, MI_SSTR("stalls"), hb->lk_stalls) < 0 ||
	    add_mi_number(o, MI_SSTR("worst_hold_us"), hb->lk_worst_ns / 1000) < 0 ||
	    add_mi_number(o, MI_SSTR("worst_process"), hb->lk_worst_proc) < 0)
		return -1;
	r = hb->lk_worst_reason >= 0 && hb->lk_worst_reason < HG_LK_REASONS ?
	    hg_lk_reason_str[hb->lk_worst_reason] : "none";
	if (add_mi_string(o, MI_SSTR("worst_reason"), (char *)r, strlen(r)) < 0)
		return -1;
	ho = add_mi_object(o, MI_SSTR("hold"));
	wo = add_mi_object(o, MI_SSTR("wait"));
	if (!ho || !wo)
		return -1;
	for (i = 0; i < HG_LK_REASONS; i++) {
		if (hg_stats_lk(ho, hg_lk_reason_str[i], &hb->lk_hold[i]) < 0 ||
		    hg_stats_lk(wo, hg_lk_reason_str[i], &hb->lk_wait[i]) < 0)
			return -1;
	}
	if (hg_stats_lk(o, "release", &hb->lk_release) < 0 ||
	    hg_stats_lk(o, "commit", &hb->lk_commit) < 0 ||
	    hg_stats_lk(o, "gc", &hb->lk_gc) < 0 ||
	    hg_stats_lk(o, "grow_wait", &hb->lk_grow_wait) < 0)
		return -1;
	if (hb->lk_commit.n) {
		mi_item_t *cp = add_mi_object(o, MI_SSTR("commit_phases"));

		if (!cp)
			return -1;
		for (i = 0; i < HG_CP_PHASES; i++)
			if (hg_stats_lk(cp, hg_cp_phase_str[i], &hb->lk_cphase[i]) < 0)
				return -1;
	}
	return 0;
}

/* @per_process: the arena is private to the answering process (pkg), so
 * the payload names that process */
static int hg_stats_one(mi_item_t *parent, char *name, struct hg_block *hb,
                        int per_process)
{
	mi_item_t *o, *cls_arr, *cls_item;
	unsigned int chunks_of[HG_NCLASSES], cell_size_of[HG_NCLASSES];
	unsigned long cells_of[HG_NCLASSES];
	unsigned long carved, live_committed;
	const char *tier;
	int c;

	if (!hb)
		return 0;

	o = add_mi_object(parent, name, strlen(name));
	if (!o)
		return -1;

	if (per_process) {
		const char *d = (process_no >= 0 && pt) ? pt[process_no].desc : "?";

		if (add_mi_number(o, MI_SSTR("pid"), my_pid()) < 0)
			return -1;
		if (add_mi_string(o, MI_SSTR("process"), (char *)d, strlen(d)) < 0)
			return -1;
		if (add_mi_string(o, MI_SSTR("scope"),
			MI_SSTR("this process only - see pkmem: for every process")) < 0)
			return -1;
	}

	carved = hb->real_used;
	tier = hg_mem_tier_str(hb->tier);
	/* before reading max_live_used: the high-water is refreshed on read */
	live_committed = hg_live_sample(hb);

	if (add_mi_string(o, MI_SSTR("tier"), (char *)tier, strlen(tier)) < 0)
		return -1;
	{
		int nt = 0, t;
		for (t = HG_MEM_HUGETLB; t <= HG_MEM_4K; t++)
			if (hb->tier_bytes[t])
				nt++;
		if (nt > 1) {
			mi_item_t *ta = add_mi_object(o, MI_SSTR("tier_bytes"));

			if (!ta)
				return -1;
			for (t = HG_MEM_HUGETLB; t <= HG_MEM_4K; t++) {
				/* add_mi_number() wants a non-const name;
				 * it only reads these literals */
				char *ts = (char *)hg_mem_tier_str((enum hg_mem_tier)t);

				if (hb->tier_bytes[t] &&
				    add_mi_number(ta, ts, strlen(ts),
				                  hb->tier_bytes[t]) < 0)
					return -1;
			}
		}
	}
	if (add_mi_number(o, MI_SSTR("total_size"), hb->size) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("pinned_mb"), hb->locked_bytes >> 20) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("unpinned"), hb->unpinned) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("guard"), hb->guard) < 0)
		return -1;
	/* committed == cap means a fixed arena (the default) */
	if (add_mi_number(o, MI_SSTR("committed"), hb->committed_bytes) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("cap"), hb->hcap) < 0)
		return -1;
	if (hb->hcap > hb->committed_bytes &&
	    add_mi_number(o, MI_SSTR("grow_headroom"),
	                  hb->hcap - hb->committed_bytes) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("grows"), hb->grows) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("span_bytes"), hb->span_end) < 0)
		return -1;
	/* whole_free_pages, always shown: a page is reclaimable only whole, so
	 * this explains a zero punch on a mostly free arena */
	if (add_mi_number(o, MI_SSTR("shrink_step"), hb->shrink_step) < 0 ||
	    add_mi_number(o, MI_SSTR("scaling_cycle_s"),
	                  (unsigned long)hg_scaling_cycle) < 0 ||
	    add_mi_number(o, MI_SSTR("whole_free_pages"),
	                  hb->nfree[hb->buddy_top]) < 0 ||
	    add_mi_number(o, MI_SSTR("punches"), hb->punches) < 0 ||
	    add_mi_number(o, MI_SSTR("punch_bytes"), hb->punch_bytes) < 0 ||
	    add_mi_number(o, MI_SSTR("punched_pages"), hb->punched_pages) < 0 ||
	    add_mi_number(o, MI_SSTR("repins"), hb->repins) < 0 ||
	    add_mi_number(o, MI_SSTR("repin_failed"), hb->repin_failed) < 0 ||
	    add_mi_number(o, MI_SSTR("top_list_reachable"),
	                  hg_buddy_top_reachable(hb)) < 0 ||
	    add_mi_number(o, MI_SSTR("hole_regrows"), hb->hole_regrows) < 0 ||
	    add_mi_number(o, MI_SSTR("draining"), hb->draining) < 0 ||
	    add_mi_number(o, MI_SSTR("top_carves"), hb->top_carves) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("grow_bytes"), hb->grow_bytes) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("grow_refused"), hb->grow_refused) < 0)
		return -1;
	/* grow_blocked says whether this refusal is current */
	{
		const char *why = hg_grow_refusal_str(hb->grow_refuse_why);

		if (add_mi_string(o, MI_SSTR("last_grow_refusal"), (char *)why,
		                  strlen(why)) < 0)
			return -1;
	}
	if (add_mi_number(o, MI_SSTR("grows_proactive"), hb->grows_proactive) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("grows_exhaustion"), hb->grows_exhaustion) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("collapse_deferred"), hb->collapse_deferred) < 0 ||
	    add_mi_number(o, MI_SSTR("collapsed_late"), hb->collapsed_late) < 0 ||
	    add_mi_number(o, MI_SSTR("collapse_retries"), hb->collapse_retries) < 0 ||
	    add_mi_number(o, MI_SSTR("collapse_late_failed"),
	        hb->collapse_late_failed) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("grow_inflight"), hb->grow_inflight) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("grow_waits"), hb->grow_waits) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("grow_wait_timeouts"), hb->grow_wait_timeouts) < 0)
		return -1;
	/* -1 = no maintenance process (fixed arena), else its process no */
	if (add_mi_number(o, MI_SSTR("maintenance_process"),
			hb->maint_active ? hb->maint_proc : -1) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("grow_blocked"), hb->grow_blocked) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("shrinks"), hb->shrinks) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("shrink_bytes"), hb->shrink_bytes) < 0)
		return -1;

	if (add_mi_number(o, MI_SSTR("carved"), carved) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("carved_peak"), hb->max_real_used) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("chunks"), hb->nchunks) < 0)
		return -1;
	/* shmem:free_size: never-carved arena; idle carved cells are not
	 * counted, as they serve only their own size class */
	if (add_mi_number(o, MI_SSTR("free_to_carve"),
	        hb->size > carved ? hb->size - carved : 0) < 0)
		return -1;

	/* live = handed out now; live_committed, live_peak, payload, cells are
	 * shmem: real_used_size, max_used_size, used_size, fragments */
	if (add_mi_number(o, MI_SSTR("live_committed"), live_committed) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("live_peak"), hb->max_live_used) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("live_payload"), hg_used(hb)) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("live_cells"), hg_fragments(hb)) < 0)
		return -1;
	/* slab only: large allocations live in the boundary-tag tier, so this
	 * is NOT comparable with live_payload, which counts both */
	if (add_mi_number(o, MI_SSTR("slab_cell_bytes_live"),
		hg_cell_live(hb)) < 0)
		return -1;

	/* reclaim: blocks_carved - blocks_returned = live blocks; carved below
	 * carved_peak proves memory is being given back */
	if (add_mi_number(o, MI_SSTR("blocks_carved"), hb->blocks_carved) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("blocks_returned"), hb->gc_blocks_returned) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("gc_passes"), hb->gc_passes) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("cache_flushes"), hb->cache_flushes) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("cells_flushed"), hb->cells_flushed) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("pressure_flushes"), hb->pressure_flushes) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("pressure_cells"), hb->pressure_cells) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("xfer_puts"), hb->xfer_puts) < 0 ||
	    add_mi_number(o, MI_SSTR("xfer_gets"), hb->xfer_gets) < 0 ||
	    add_mi_number(o, MI_SSTR("xfer_full"), hb->xfer_full) < 0 ||
	    add_mi_number(o, MI_SSTR("xfer_drained"), hb->xfer_drained) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("gc_tick_blocks"), hb->gc_tick_blocks) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("gc_inline_blocks"), hb->gc_inline_blocks) < 0)
		return -1;
	{
		unsigned long kept = 0;
		int c;

		for (c = 0; c < HG_NCLASSES; c++)
			kept += hb->ndrained[c];
		if (add_mi_number(o, MI_SSTR("gc_kept_blocks"), kept) < 0)
			return -1;
	}
	if (add_mi_number(o, MI_SSTR("sweeps_skipped"), hb->sweeps_skipped) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("buddy_splits"), hb->buddy_splits) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("buddy_merges"), hb->buddy_merges) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("buddy_merges_init"), hb->buddy_merges_init) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("buddy_free_leaves"), hb->buddy_free_leaves) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("slab_recycled"), hg_slab_recycled(hb)) < 0)
		return -1;

	{
		static const char * const kind[HG_CORRUPT_KINDS] = {
			"class_mismatch", "double_free", "nfree_underflow",
			"bad_class", "foreign_ptr", "buddy_bad_free", "internal",
			"header", "use_after_free", "overflow"
		};
		mi_item_t *co;
		int k;

		co = add_mi_object(o, MI_SSTR("corruption"));
		if (!co)
			return -1;
		if (add_mi_number(co, MI_SSTR("total"), hg_corrupt_total(hb)) < 0)
			return -1;
		for (k = 0; k < HG_CORRUPT_KINDS; k++)
			if (add_mi_number(co, (char *)kind[k], strlen(kind[k]),
					hb->corrupt[k]) < 0)
				return -1;
	}
	if (add_mi_number(o, MI_SSTR("large_backing"), hb->large_backing) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("large_live"), hb->large_live) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("large_recycled"), hg_large_recycled(hb)) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("large_chunks_carved"),
			hb->large_chunks_carved) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("large_chunks_returned"),
			hb->large_chunks_returned) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("reserve_floor"), hb->reserve_floor) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("below_floor"), hb->below_floor) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("floor_crossings"), hb->floor_crossings) < 0)
		return -1;
	/* allocations refused for lack of memory, and whether that is ongoing */
	if (add_mi_number(o, MI_SSTR("alloc_failed"), hb->oom_fails) < 0 ||
	    add_mi_number(o, MI_SSTR("out_of_memory"), hb->oom_episode) < 0)
		return -1;
	if (hg_stats_lock(o, hb) < 0)
		return -1;

	/* per-order buddy free lists: tells one contiguous run from scattered
	 * leaves, i.e. whether a large chunk can still be served */
	{
		mi_item_t *ord_arr, *ord_item;
		unsigned int ord;

		ord_arr = add_mi_array(o, MI_SSTR("buddy_free_orders"));
		if (!ord_arr)
			return -1;
		for (ord = 0; ord <= hb->buddy_top && ord <= HG_MAX_ORDERS; ord++) {
			if (!hb->nfree[ord])
				continue;
			ord_item = add_mi_object(ord_arr, 0, 0);
			if (!ord_item)
				return -1;
			if (add_mi_number(ord_item, MI_SSTR("order"), ord) < 0)
				return -1;
			if (add_mi_number(ord_item, MI_SSTR("bytes"),
				(unsigned long)HG_LEAF_SIZE << ord) < 0)
				return -1;
			if (add_mi_number(ord_item, MI_SSTR("blocks"), hb->nfree[ord]) < 0)
				return -1;
		}
	}

	/* counters kept at carve and GC time: no chunk walk under the lock */
	hg_lock_enter(hb, HG_LK_STATS);
	for (c = 0; c < HG_NCLASSES; c++) {
		chunks_of[c] = hb->cls_chunks[c];
		cells_of[c] = hb->cls_cells[c];
		cell_size_of[c] = hg_cell_total_size((unsigned char)c);
	}
	hg_lock_leave(hb);

	cls_arr = add_mi_array(o, MI_SSTR("classes"));
	if (!cls_arr)
		return -1;
	for (c = 0; c < HG_NCLASSES; c++) {
		if (!chunks_of[c])
			continue;
		cls_item = add_mi_object(cls_arr, 0, 0);
		if (!cls_item)
			return -1;
		if (add_mi_number(cls_item, MI_SSTR("cell_size"),
			cell_size_of[c]) < 0)
			return -1;
		if (add_mi_number(cls_item, MI_SSTR("chunks"), chunks_of[c]) < 0)
			return -1;
		if (add_mi_number(cls_item, MI_SSTR("gc_keep"), hb->gc_keep[c]) < 0)
			return -1;
		if (add_mi_number(cls_item, MI_SSTR("drained"), hb->ndrained[c]) < 0)
			return -1;
		if (add_mi_number(cls_item, MI_SSTR("cells"), cells_of[c]) < 0)
			return -1;
		/* free cells in the SHARED pool (thread caches unseen), a lower
		 * bound; tells a full class from one that went idle */
		if (add_mi_number(cls_item, MI_SSTR("free_shared"),
			hb->gpool_n[c]) < 0)
			return -1;
		if (add_mi_number(cls_item, MI_SSTR("xfer_chains"),
			hb->xfer[c].n) < 0 ||
		    add_mi_number(cls_item, MI_SSTR("xfer_cap"),
			hb->xfer[c].cap) < 0)
			return -1;
	}

	return 0;
}

static int hg_advise_one(mi_item_t *parent, const char *name,
		const struct hg_advice *a)
{
	mi_item_t *o;

	o = add_mi_object(parent, (char *)name, strlen(name));
	if (!o)
		return -1;

	if (a->elastic) {
		if (add_mi_number(o, MI_SSTR("init_mb"), a->init >> 20) < 0 ||
		    add_mi_number(o, MI_SSTR("committed_mb"), a->committed >> 20) < 0 ||
		    add_mi_number(o, MI_SSTR("cap_mb"), a->cap >> 20) < 0 ||
		    add_mi_number(o, MI_SSTR("peak_bytes"), a->peak) < 0 ||
		    add_mi_number(o, MI_SSTR("peak_pct_of_cap"), a->peak_pct) < 0 ||
		    add_mi_number(o, MI_SSTR("margin_applied"), a->margin) < 0 ||
		    add_mi_number(o, MI_SSTR("recommended_init_mb"),
		        a->rec_init_mb) < 0 ||
		    add_mi_number(o, MI_SSTR("recommended_cap_mb"), a->rec_mb) < 0)
			return -1;
	} else if (add_mi_number(o, MI_SSTR("configured_mb"), a->size >> 20) < 0 ||
	    add_mi_number(o, MI_SSTR("peak_bytes"), a->peak) < 0 ||
	    add_mi_number(o, MI_SSTR("peak_pct_of_configured"), a->peak_pct) < 0 ||
	    add_mi_number(o, MI_SSTR("margin_applied"), a->margin) < 0 ||
	    add_mi_number(o, MI_SSTR("recommended_mb"), a->rec_mb) < 0)
		return -1;

	if (add_mi_string(o, MI_SSTR("verdict"), (char *)a->verdict,
	        strlen(a->verdict)) < 0 ||
	    add_mi_number(o, MI_SSTR("live_slab_bytes"), a->slab_live) < 0 ||
	    add_mi_number(o, MI_SSTR("live_large_bytes"), a->large_live) < 0 ||
	    add_mi_number(o, MI_SSTR("large_share_pct"), a->large_share_pct) < 0)
		return -1;
	if (a->caveat && add_mi_string(o, MI_SSTR("caveat"), (char *)a->caveat,
	        strlen(a->caveat)) < 0)
		return -1;

	/* pkg is per process: the set of arenas is what is pinned */
	if (a->nproc > 0 &&
	    (add_mi_number(o, MI_SSTR("processes"), a->nproc) < 0 ||
	     add_mi_number(o, MI_SSTR("pinned_total_mb"), a->pinned_total_mb) < 0 ||
	     add_mi_number(o, MI_SSTR("recommended_total_mb"), a->rec_total_mb) < 0))
		return -1;
	return 0;
}

static mi_response_t *mi_hg_advise(const mi_params_t *params,
						struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj, *notes;
	struct hg_block *hb;
	struct hg_advice a;
	unsigned long uptime = (unsigned long)(time(NULL) - startup_time);
	int reported = 0, elastic = 0, pkg_seen = 0;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if (add_mi_number(resp_obj, MI_SSTR("uptime_s"), uptime) < 0)
		goto error;

	if (mem_allocator_shm == MM_HG_MALLOC ||
	    mem_allocator_shm == MM_HG_MALLOC_DBG) {
		hb = (struct hg_block *)shm_block;
		/* the CARVE high-water, not the live one: carve is what has to
		 * fit in the arena, and it can sit well above live */
		hg_advise_arena(hb, hb->max_real_used, 0, 0, 0, &a);
		if (hg_advise_one(resp_obj, "shm", &a) < 0)
			goto error;
		elastic |= a.elastic;
		reported++;
	}

#ifdef PKG_MALLOC
	if (mem_allocator_pkg == MM_HG_MALLOC ||
	    mem_allocator_pkg == MM_HG_MALLOC_DBG) {
		struct hg_pkg_worst w;

		hb = (struct hg_block *)mem_block;
		hg_pkg_pub_worst(&w);
		/* the carve high-water again, of the worst process, with that
		 * process's live figures; none published yet: this process */
		hg_advise_arena(hb, w.nproc ? w.peak : hb->max_real_used, 1,
			w.nproc, w.committed_all, &a);
		if (w.nproc) {
			a.slab_live = w.slab_live;
			a.large_live = w.large_live;
			hg_advise_compute(&a);
		}
		if (hg_advise_one(resp_obj, "pkg", &a) < 0)
			goto error;
		elastic |= a.elastic;
		pkg_seen = 1;
		reported++;
	}
#endif

	if (!reported) {
		free_mi_response(resp);
		return init_mi_error(400,
			MI_SSTR("HG_MALLOC is not the active allocator"));
	}

	notes = add_mi_array(resp_obj, MI_SSTR("notes"));
	if (!notes)
		goto error;
	if (add_mi_string(notes, 0, 0, MI_SSTR(
		"advice is based on the high-water reached SO FAR; a longer or "
		"heavier window can only raise it")) < 0)
		goto error;
	if (uptime < 7200 && add_mi_string(notes, 0, 0, MI_SSTR(
		"uptime is under 2 hours - too short to have seen a busy period, "
		"treat the numbers as provisional")) < 0)
		goto error;
	if (pkg_seen && add_mi_string(notes, 0, 0, MI_SSTR(
		"pkg peak is the worst single process, which is the one -M has to "
		"cover, as each process published it at its last sweep; every "
		"process gets its own arena of that size")) < 0)
		goto error;
	if (elastic && add_mi_string(notes, 0, 0, MI_SSTR(
		"an elastic arena grows to just past its peak, so it is judged "
		"against its cap; recommended_init_mb is an INIT that holds the "
		"peak without growing")) < 0)
		goto error;

	return resp;

error:
	LM_ERR("failed to add mi item\n");
	free_mi_response(resp);
	return 0;
}

static mi_response_t *mi_hg_stats(const mi_params_t *params,
						struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	int reported = 0;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if (mem_allocator_shm == MM_HG_MALLOC ||
	    mem_allocator_shm == MM_HG_MALLOC_DBG) {
		if (hg_stats_one(resp_obj, "shm", (struct hg_block *)shm_block, 0) < 0)
			goto error;
		reported++;
	}

#ifdef PKG_MALLOC
	if (mem_allocator_pkg == MM_HG_MALLOC ||
	    mem_allocator_pkg == MM_HG_MALLOC_DBG) {
		if (hg_stats_one(resp_obj, "pkg", (struct hg_block *)mem_block, 1) < 0)
			goto error;
		reported++;
	}
#endif

	/* module arenas (hg_arena_create()) exist whatever -a says */
	{
		int i;

		for (i = 0; i < HG_ARENA_REG_MAX; i++) {
			struct hg_block *hb = hg_arena_reg[i].hb;

			if (!hb || !hb->shared || (void *)hb == shm_block ||
			    !hb->name || !strcmp(hb->name, "shm_dbg"))
				continue;
			if (hg_stats_one(resp_obj, hb->name, hb, 0) < 0)
				goto error;
			reported++;
		}
	}

	if (!reported) {
		free_mi_response(resp);
		return init_mi_error(400,
			MI_SSTR("HG_MALLOC is not the active allocator"));
	}

	/* this process's frees into an arena other than the named one; over
	 * mi_fifo that is the idle FIFO listener, so a zero proves nothing */
	if (add_mi_number(resp_obj, MI_SSTR("cross_arena_frees_this_proc"),
			hg_xarena_frees) < 0)
		goto error;

	return resp;

error:
	LM_ERR("failed to add mi item\n");
	free_mi_response(resp);
	return 0;
}

const mi_export_t mi_hg_cmds[] = {
	{ "hg_stats", "HG_MALLOC arena internals: how much of the arena is "
		"carved into size-class chunks, how much of that is live versus "
		"recycled, and the per-class chunk breakdown", 0, 0, {
		{mi_hg_stats, {0}},
		{EMPTY_MI_RECIPE}}, {0}
	},
	{ "hg_advise", "what -m and -M should be set to, derived from the "
		"high-water each arena has actually reached; pkg advice covers the "
		"worst single process, not the one answering", 0, 0, {
		{mi_hg_advise, {0}},
		{EMPTY_MI_RECIPE}}, {0}
	},
	{EMPTY_MI_EXPORT}
};

#endif /* HG_MALLOC */
