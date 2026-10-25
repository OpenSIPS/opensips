/*
 * buddy allocator over the HG_MALLOC page grid
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
#include <stdlib.h>
#include <unistd.h>

#include "hg_version.h"
#include "hg_malloc.h"
#include "hg_buddy.h"
#include "hg_arena.h"
#include "../dprint.h"
#include "../globals.h"

/*
 * Two records per page tree make split and merge O(1). leaforder[leaf] is the
 * order of the block CONTAINING the leaf, kept in every leaf of the block, so
 * an interior address (a cell being freed) finds its block with a mask;
 * HG_LEAF_NONE = not buddy space (e.g. part of a multi-page run). bitmap[node]
 * is 1 iff the node is a WHOLE free block, i.e. on a free list - a split node
 * is 0 even if both halves are free - which is the merge test "is my buddy
 * free AND entire".
 */

/* node id in the per-page tree: level 0 is the whole page, level `top`
 * the leaves; 2^(top+1)-1 nodes (511, a 64 byte bitmap, for 8 KB leaves
 * in a 2 MB page) */
static inline unsigned long node_id(unsigned int top, unsigned int order,
                                    unsigned long leaf)
{
	unsigned int level = top - order;

	return (1UL << level) - 1 + (leaf >> order);
}

static inline unsigned long nodes_per_page(unsigned int top)
{
	return (1UL << (top + 1)) - 1;
}

static inline int bit_test(const unsigned long *bm, unsigned long n)
{
	return (bm[n / (sizeof(long) * 8)] >> (n % (sizeof(long) * 8))) & 1UL;
}

static inline void bit_set(unsigned long *bm, unsigned long n)
{
	bm[n / (sizeof(long) * 8)] |= 1UL << (n % (sizeof(long) * 8));
}

static inline void bit_clear(unsigned long *bm, unsigned long n)
{
	bm[n / (sizeof(long) * 8)] &= ~(1UL << (n % (sizeof(long) * 8)));
}

/*
 * The top order IS the page, so its free list is a bitmap (hb->wfree), one bit
 * per page with nothing stored in the page. Find-first-set serves the lowest
 * page, so carves stay low and the top pages drain for the trim.
 */
#define HG_WF_BITS (sizeof(long) * 8)

static inline int wf_test(const struct hg_block *hb, unsigned long idx)
{
	return (hb->wfree[idx / HG_WF_BITS] >> (idx % HG_WF_BITS)) & 1UL;
}

static inline void wf_set(struct hg_block *hb, unsigned long idx)
{
	if (wf_test(hb, idx)) {
		hg_corrupt(hb, HG_C_INTERNAL);
		LM_CRIT("%s: page %lu published as whole-free twice\n", hb->name, idx);
		return;
	}
	hb->wfree[idx / HG_WF_BITS] |= 1UL << (idx % HG_WF_BITS);
	hb->nfree[hb->buddy_top]++;
}

static inline void wf_clear(struct hg_block *hb, unsigned long idx)
{
	if (!wf_test(hb, idx)) {
		hg_corrupt(hb, HG_C_INTERNAL);
		LM_CRIT("%s: page %lu taken off offer but was not on it\n", hb->name, idx);
		return;
	}
	hb->wfree[idx / HG_WF_BITS] &= ~(1UL << (idx % HG_WF_BITS));
	hb->nfree[hb->buddy_top]--;
}

/* the lowest whole-free page on offer, or -1 */
static inline long wf_first(const struct hg_block *hb)
{
	unsigned long w;

	for (w = 0; w < hb->wfree_words; w++)
		if (hb->wfree[w])
			return (long)(w * HG_WF_BITS + __builtin_ctzl(hb->wfree[w]));
	return -1;
}

static inline unsigned long wf_count(const struct hg_block *hb)
{
	unsigned long w, n = 0;

	for (w = 0; w < hb->wfree_words; w++)
		n += (unsigned long)__builtin_popcountl(hb->wfree[w]);
	return n;
}

/* --- free lists ------------------------------------------------------- */

static inline void fl_push(struct hg_block *hb, void *p, unsigned int order)
{
	struct hg_free_blk *b = (struct hg_free_blk *)p;

	/* the top order lives in the bitmap. Lower orders stay LIFO: inside
	 * carved pages the cell-level policy owns placement, and ordering
	 * these long lists would cost a walk */
	if (order == hb->buddy_top) {
		wf_set(hb, hg_page_of(hb, p));
		return;
	}
	b->prev = NULL;
	b->next = hb->bfree[order];
	if (b->next)
		b->next->prev = b;
	hb->bfree[order] = b;
	hb->nfree[order]++;
}

static inline void fl_unlink(struct hg_block *hb, void *p, unsigned int order)
{
	struct hg_free_blk *b = (struct hg_free_blk *)p;

	if (order == hb->buddy_top) {
		wf_clear(hb, hg_page_of(hb, p));
		return;
	}
	if (b->prev)
		b->prev->next = b->next;
	else
		hb->bfree[order] = b->next;
	if (b->next)
		b->next->prev = b->prev;
	hb->nfree[order]--;
}


/* --- geometry --------------------------------------------------------- */

static inline struct hg_page *page_of(struct hg_block *hb, const void *p)
{
	return &hb->pages[hg_page_of(hb, p)];
}

/* --- init ------------------------------------------------------------- */

/* publish a whole page, nothing carved from it, as one top-order free block */
static void page_publish_whole(struct hg_block *hb, struct hg_page *pg)
{
	unsigned int top = hb->buddy_top;

	memset(pg->leaforder, (int)top, (size_t)hg_leaves_per_page(hb));
	bit_set(pg->bitmap, node_id(top, top, 0));
	fl_push(hb, pg->base, top);
	pg->free_leaves = (unsigned int)hg_leaves_per_page(hb);
	hb->buddy_free_leaves += pg->free_leaves;
}

/*
 * Release the leaves [from, to) of the one page the block header and the buddy
 * metadata partly occupy, leaf by leaf through the ordinary free path so the
 * merges follow the ordinary rules. Skipping the page instead would waste up
 * to a huge page, 25% of an 8 MB pkg arena.
 */
static void page_release_range(struct hg_block *hb, struct hg_page *pg,
                               unsigned long from, unsigned long to)
{
	unsigned long leaf;

	for (leaf = from; leaf < to; leaf++) {
		/* hand it to the free path as a legitimately allocated leaf */
		pg->leaforder[leaf] = 0;
		hg_buddy_free(hb, pg->base + (leaf << HG_LEAF_SHIFT), 0);
	}
}

int hg_buddy_init(struct hg_block *hb)
{
	unsigned long i, lpp, bmwords, meta, consumed_leaves, wfwords;
	unsigned int top;
	char *meta_base, *cur;
	struct hg_page *pg;

	if (hb->npages == 0) {
		LM_INFO("%s: no whole pages, buddy reclaim inactive\n", hb->name);
		return 0;
	}

	top = hg_buddy_top_order(hb);
	if (top > HG_MAX_ORDERS) {
		LM_ERR("%s: %u buddy orders exceeds the %d the free-list array "
			"holds\n", hb->name, top, HG_MAX_ORDERS);
		return -1;
	}
	hb->buddy_top = top;

	lpp = hg_leaves_per_page(hb);
	bmwords = (nodes_per_page(top) + sizeof(long) * 8 - 1) /
	          (sizeof(long) * 8);

	/*
	 * One metadata carve for all pages, from the FRONT of the arena
	 * via the bump allocator: it inherits the arena's tier and
	 * sharing and costs no extra huge page. Sized for npages_cap, so
	 * a grow only publishes descriptors and never needs room for
	 * metadata in a full arena.
	 */
	wfwords = (hb->npages_cap + HG_WF_BITS - 1) / HG_WF_BITS;
	meta = hb->npages_cap * (sizeof(struct hg_page) + lpp +
	                         bmwords * sizeof(long)) + wfwords * sizeof(long);
	meta_base = hg_chunk_backing(hb, meta);
	if (!meta_base) {
		LM_ERR("%s: cannot carve %lu bytes of buddy metadata for %lu "
			"pages (%lu committed)\n", hb->name, meta,
			hb->npages_cap, hb->npages);
		return -1;
	}
	memset(meta_base, 0, meta);

	hb->pages = (struct hg_page *)(void *)meta_base;
	cur = meta_base + hb->npages_cap * sizeof(struct hg_page);
	/* the whole-free-page bitmap, ahead of the per-page arrays */
	hb->wfree = (unsigned long *)(void *)cur;
	hb->wfree_words = wfwords;
	cur += wfwords * sizeof(long);
	for (i = 0; i < hb->npages_cap; i++) {
		pg = &hb->pages[i];
		pg->idx = (unsigned int)i;
		pg->base = hb->pbase + (i << hb->hps_shift);
		pg->leaforder = (unsigned char *)cur;
		cur += lpp;
		pg->bitmap = (unsigned long *)(void *)cur;
		cur += bmwords * sizeof(long);
		memset(pg->leaforder, HG_LEAF_NONE, lpp);
		/* init's achieved tier; a grow stamps the pages it commits */
		pg->tier = (unsigned char)hb->tier;
		/* starts wholly reserved; pages < npages are published below,
		 * pages beyond wait for hg_buddy_grow_unlocks() */
	}

	/*
	 * Everything below hoff (block header, then the metadata) is spoken
	 * for. hoff is leaf aligned (hg_arena_init); round up anyway, so a
	 * change to the bump allocator cannot hand out a partly used leaf.
	 */
	consumed_leaves = 0;
	{
		unsigned long hoff = hb->hoff;
		const char *cend = hb->hbase + ((hoff + HG_LEAF_SIZE - 1) &
		                               ~(HG_LEAF_SIZE - 1));

		if (cend > hb->pbase)
			consumed_leaves = (unsigned long)(cend - hb->pbase) >>
			                  HG_LEAF_SHIFT;
	}

	for (i = 0; i < hb->npages; i++) {
		unsigned long first = i * lpp, last = first + lpp;

		pg = &hb->pages[i];
		if (consumed_leaves >= last)
			continue;                       /* wholly consumed */
		if (consumed_leaves <= first) {
			page_publish_whole(hb, pg);     /* wholly free */
			continue;
		}
		/* the single straddling page */
		page_release_range(hb, pg, consumed_leaves - first, lpp);
	}

	/*
	 * Rebase the coalesce counters: the straddling page's merges above say
	 * nothing about fragmentation. Keep their total and restart from zero,
	 * so buddy_splits and buddy_merges share a zero point.
	 */
	hb->buddy_merges_init = hb->buddy_merges;
	hb->buddy_merges = 0;
	hb->buddy_splits = 0;   /* init allocates nothing; make that explicit */

	hb->buddy_ready = 1;
	/*
	 * Reserve floor at 1/16 of the grid: a fraction, not a constant,
	 * because arenas range from 8 MB pkg to 5 GB shm.
	 */
	hb->reserve_floor = (hb->npages * hg_leaves_per_page(hb)) / 16;
	LM_DBG("%s buddy: %lu pages, orders 0..%u (%lu B..%lu B), %lu B metadata "
		"(%lu B/page, %.3f%%), %lu of %lu leaves free after reserving %lu\n",
		hb->name, hb->npages, top, HG_LEAF_SIZE, HG_LEAF_SIZE << top,
		meta, meta / hb->npages,
		100.0 * (double)meta / (double)hb->committed_bytes,
		hb->buddy_free_leaves, hb->npages * lpp, consumed_leaves);
	return 0;
}

/*
 * A punched page keeps its address in the span but its bytes are no longer
 * committed, so the invariant is:
 *
 *     committed_bytes + punched_pages * hps == span_end
 *
 * Re-checked wherever either side moves (grow, trim, punch, re-commit). A
 * mismatch is an accounting slip in this file, not damaged memory: it is
 * counted as an internal inconsistency and the arena carries on.
 */
static void span_check(struct hg_block *hb, const char *after)
{
	unsigned long holes = hb->punched_pages << hb->hps_shift;

	if (hb->committed_bytes + holes == hb->span_end)
		return;
	hg_corrupt(hb, HG_C_INTERNAL);
	LM_CRIT("%s: after %s committed_bytes %lu + %lu punched != span_end "
		"%lu\n", hb->name, after, hb->committed_bytes, holes,
		hb->span_end);
}

/*
 * Reserve floor at 1/16 of the pages the allocator can carve - committed
 * pages, not the span. Counting holes would inflate the floor by what the
 * drain gave back, and the drain would then throttle itself on its own holes.
 */
static inline void floor_recompute(struct hg_block *hb)
{
	hb->reserve_floor = ((hb->npages - hb->punched_pages) *
	                     hg_leaves_per_page(hb)) / 16;
}

/* --- grow ------------------------------------------------------------- */

/*
 * A RESOURCE refusal - the host, not the admin, said no: count it and run the
 * two-step latch (see grow_blocked's declaration). The event is raised by the
 * sweep timer via grow_event_due, never here under hb->lock.
 */
static int grow_resource_refused(struct hg_block *hb)
{
	hb->grow_refused++;

	if (hb->grow_blocked)
		return -1;

	if (!hb->grow_blocked_mark) {
		/* the mark doubles as the "armed" flag: gc_passes + 1
		 * is never 0, and is the count gc_passes reaches once a
		 * GC pass has run */
		hb->grow_blocked_mark = hb->gc_passes + 1;
		hb->grow_blocked_refuse0 = hb->grow_refused;
	} else if (hb->gc_passes >= hb->grow_blocked_mark) {
		hb->grow_blocked = 1;
		hb->grow_event_due = 1;
		LM_WARN("%s: GROW-BLOCKED latched - the arena cannot grow and "
			"a GC pass did not change that (%lu refusals so far). "
			"Alert on %s; details precede this line.\n", hb->name,
			hb->grow_refused, hb->shared ? "hg_shm_grow_blocked" :
			"hg_pkg_grow_blocked");
	}
	return -1;
}

/* end the episode, if any, and re-arm the once-per-episode messages */
void hg_grow_unblock(struct hg_block *hb, const char *how)
{
	if (hb->grow_blocked)
		LM_NOTICE("%s: GROW-BLOCKED cleared - %s\n", hb->name, how);
	hb->grow_blocked = 0;
	hb->grow_blocked_mark = 0;
	hb->grow_blocked_refuse0 = 0;
	hb->grow_event_due = 0;
	hb->grow_refuse_said = 0;
	hb->grow_refuse_mlock = 0;
}

/*
 * The sweep timer's half of the latch (see grow_blocked_refuse0), once per
 * sweep interval with hb->lock held.
 */
void hg_grow_blocked_tick(struct hg_block *hb)
{
	if (hb->grow_blocked || !hb->grow_blocked_mark)
		return;
	if (hb->grow_refused > hb->grow_blocked_refuse0) {
		hb->grow_blocked = 1;
		hb->grow_event_due = 1;
		LM_WARN("%s: GROW-BLOCKED latched - the arena cannot grow and "
			"a full sweep interval did not change that (%lu refusals "
			"so far). Alert on %s; details precede this line.\n",
			hb->name, hb->grow_refused,
			hb->shared ? "hg_shm_grow_blocked" : "hg_pkg_grow_blocked");
	} else {
		/* armed but quiet for a whole interval: the spike passed */
		hb->grow_blocked_mark = 0;
		hb->grow_blocked_refuse0 = 0;
	}
}

/* how long an exhausted worker waits, lock released, for a grow another worker
 * has in flight; past it the request is refused and counted */
#define HG_GROW_WAIT_MAX_NS  2000000000UL
#define HG_GROW_WAIT_SLICE_US 100

static int hg_buddy_regrow_holes_unlocks(struct hg_block *hb, unsigned long need,
                                         unsigned long room);

/*
 * Deferred collapse. A worker's exhaustion grow publishes a delta that did not
 * fault in huge on 4 KB pages, flagged want_collapse (hg_mem_commit()), so the
 * worker does not wait for the MADV_COLLAPSE retrofit. The maintenance process
 * calls this every tick: at most one pass over the pages, each flagged page
 * collapsed with the arena lock released, until HG_COLLAPSE_BUDGET_NS is
 * spent. Failures are usually transient (a page just faulted cannot be
 * isolated yet), so a page gets HG_COLLAPSE_TRIES attempts over later ticks
 * before it is left on 4 KB. Pages are only released by this same process, so
 * a page picked here cannot be released under it; the flag is re-checked
 * once the lock is back all the same.
 */
#define HG_COLLAPSE_BUDGET_NS	(100UL * 1000000UL)

void hg_collapse_deferred(struct hg_block *hb)
{
	unsigned long start = hg_now_ns(), i;
	struct hg_page *pg;
	int rc;

	if (!__atomic_load_n(&hb->collapse_pending, __ATOMIC_ACQUIRE))
		return;
	while (hg_now_ns() - start < HG_COLLAPSE_BUDGET_NS) {
		hg_lock_enter(hb, HG_LK_POLICY);
		pg = NULL;
		for (i = hb->collapse_scan; i < hb->npages; i++)
			if (hb->pages[i].want_collapse && !hb->pages[i].releasing &&
			    !hb->pages[i].punched) {
				pg = &hb->pages[i];
				break;
			}
		if (!pg) {
			/* end of this tick's pass; the next tick starts over */
			hb->collapse_scan = 0;
			if (!hb->collapse_wanting)
				hb->collapse_pending = 0;
			hg_lock_leave(hb);
			return;
		}
		hb->collapse_scan = i + 1;
		hg_lock_leave(hb);

		rc = hg_mem_collapse(hb, pg->base, hb->hps);

		hg_lock_enter(hb, HG_LK_POLICY);
		if (!pg->want_collapse) {
			/* released meanwhile: not counted either way */
		} else if (rc > 0) {
			if (pg->tier == HG_MEM_4K) {
				if (hb->tier_bytes[HG_MEM_4K] >= hb->hps)
					hb->tier_bytes[HG_MEM_4K] -= hb->hps;
				hb->tier_bytes[HG_MEM_THP_COLLAPSE] += hb->hps;
				pg->tier = HG_MEM_THP_COLLAPSE;
			}
			pg->want_collapse = 0;
			hb->collapse_wanting--;
			hb->collapsed_late++;
		} else if (rc < 0 && --pg->want_collapse) {
			hb->collapse_retries++;
			if (!hb->collapse_fail_said) {
				hb->collapse_fail_said = 1;
				LM_INFO("%s: deferred collapse of a 2 MB page failed (%s) "
					"- retrying it on later ticks\n", hb->name,
					strerror(-rc));
			}
		} else {
			/* tries used up, or the host forbids collapse now */
			pg->want_collapse = 0;
			hb->collapse_wanting--;
			hb->collapse_late_failed++;
			LM_NOTICE("%s: a 2 MB page stays on 4 KB pages - %s\n",
				hb->name, rc < 0 ? strerror(-rc) :
				"the host no longer allows collapse");
		}
		hg_lock_leave(hb);
	}
}

/*
 * Grow in three phases: RESERVE the range under hb->lock, POPULATE it with
 * hg_mem_commit() with the lock released (faulting, pinning and verifying the
 * backing are slow and must not stall the arena), PUBLISH under the lock.
 * grow_inflight keeps every other grow, trim and punch out meanwhile. Reached
 * on buddy exhaustion (carve_chunk, the large tier) and from the proactive
 * ticks, never on the fast path.
 */
static int buddy_grow_body(struct hg_block *hb, unsigned long need, enum hg_grow_why why)
{
	unsigned long delta, room, old_pages, i, limit, t0, off, commit_ns;
	unsigned long cp_ns[HG_CP_PHASES];
	int tier, reason, later;

	if (!hb->buddy_ready)
		return -1;

	/* advise-only mode: report what growth WOULD have done, act never -
	 * the arena behaves exactly like a fixed one, with evidence */
	if (hg_autoscale_dry_run) {
		hb->grow_refused++;
		hb->grow_refuse_why = HG_GR_DRY_RUN;
		if (!hb->pol_dry_said) {
			hb->pol_dry_said = 1;
			LM_WARN("%s: DRY RUN - would grow for a %lu byte request "
				"(committed %lu MB); counting further suppressed "
				"grows in hg_shm_grow_refused\n",
				hb->name, need, hb->committed_bytes >> 20);
		}
		return -1;
	}

	/*
	 * Another grow is in flight: wait for its publish WITHOUT the lock and
	 * report "grew", so the caller retries its carve on the new pages.
	 */
	if (hb->grow_inflight) {
		unsigned long gen = hb->grow_gen, waited = 0;

		hb->grow_waits++;
		reason = hb->lk_cur;
		t0 = hg_now_ns();
		/*
		 * The token can be re-taken between the poll seeing it
		 * clear and the lock coming back (a grow after a refused
		 * one, the drain's punch after its trim). That is no
		 * timeout: keep waiting, within the same budget, until it
		 * is clear UNDER the lock.
		 */
		do {
			hg_lock_leave(hb);
			do {
				usleep(HG_GROW_WAIT_SLICE_US);
				waited = hg_now_ns() - t0;
			} while (__atomic_load_n(&hb->grow_inflight, __ATOMIC_ACQUIRE) &&
			         waited < HG_GROW_WAIT_MAX_NS);
			hg_lock_enter(hb, (enum hg_lock_reason)reason);
			/* a grow or a hole re-grow published pages: retry the
			 * carve. A trim or a punch also holds the token; after
			 * one of those, try this caller's own grow below */
			if (hb->grow_gen != gen) {
				hg_lkstat_add(&hb->lk_grow_wait, waited);
				return 0;
			}
		} while (hb->grow_inflight && waited < HG_GROW_WAIT_MAX_NS);
		hg_lkstat_add(&hb->lk_grow_wait, waited);
		if (hb->grow_inflight) {
			hb->grow_wait_timeouts++; /* still populating - give up */
			hb->grow_refused++;
			hb->grow_refuse_why = HG_GR_WAIT_TIMEOUT;
			return -1;
		}
		/* the in-flight operation went away; fall through and grow */
	}

	/* the ceiling: the profile's scale-up target (within the -m INIT:CAP
	 * reservation), else the reservation */
	limit = (hb->pol.active && hb->pol.up_bytes) ? hb->pol.up_bytes
	                                             : hb->hcap;
	/* room is counted in committed bytes: the ceiling bounds what is
	 * backed, not the span. Holes are refilled first (below); an append
	 * past the reservation is refused by hg_mem_commit() */
	room = limit > hb->committed_bytes ? limit - hb->committed_bytes : 0;
	if (room == 0) {
		hb->grow_refused++;
		hb->grow_refuse_why = limit == hb->hcap ? HG_GR_CAP
		                                        : HG_GR_PROFILE;
		/* a ceiling doing its job is a notice, not an alarm; an arena
		 * with no cap lives here silently. grows > 0 tells them apart:
		 * a growable arena reaches room == 0 only by growing. Once per
		 * episode; grow_refused counts. */
		if (hb->grows && !hb->grow_refuse_said) {
			hb->grow_refuse_said = 1;
			LM_NOTICE("%s: at the %lu MB growth ceiling (%s), "
				"a %lu byte request must fail - counting further "
				"refusals in hg_shm_grow_refused\n",
				hb->name, limit >> 20,
				limit == hb->hcap ? "the -m/-M reservation"
				                  : "the profile scale-up target",
				need);
		}
		return -1;
	}

	/* holes first: re-committing one costs a pin and no new span, and
	 * keeps a punched arena from growing past its own free space */
	{
		int r = hg_buddy_regrow_holes_unlocks(hb, need, room);

		if (r > 0)
			return 0;       /* served: the caller retries */
		if (r < 0)
			return -1;           /* the RAM limb refused */
	}

	delta = hb->grow_granule;
	if (need > delta)
		delta = (need + hb->grow_granule - 1) /
		        hb->grow_granule * hb->grow_granule;
	if (delta > room)
		delta = room;

	/* the host-RAM limb of the ceiling, before any work is done */
	if (hg_grow_ram_refused(hb, delta))
		return grow_resource_refused(hb);

	/* phase 1 - RESERVE the range under the lock, taking grow_inflight */
	off = hb->span_end;
	hb->grow_inflight = 1;
	hb->span_pending = off + delta;
	reason = hb->lk_cur;
	hg_lock_leave(hb);

	/* phase 2 - POPULATE with the lock released */
	t0 = hg_now_ns();
	later = 0;
	tier = hg_mem_commit(hb, off, delta, cp_ns,
		(why == HG_GROW_EXHAUSTION && hb->shared &&
		 __atomic_load_n(&hb->maint_active, __ATOMIC_ACQUIRE)) ?
		&later : NULL);
	commit_ns = hg_now_ns() - t0;

	/* phase 3 - PUBLISH under the lock */
	hg_lock_enter(hb, (enum hg_lock_reason)reason);
	hg_lkstat_add(&hb->lk_commit, commit_ns);
	for (i = 0; i < HG_CP_PHASES; i++)
		if (cp_ns[i])
			hg_lkstat_add(&hb->lk_cphase[i], cp_ns[i]);
	__atomic_store_n(&hb->grow_inflight, 0, __ATOMIC_RELEASE);
	if (tier < 0) {
		/* the commit rolled itself back; give the reservation back */
		hb->span_pending = hb->span_end;
		return grow_resource_refused(hb);
	}

	hb->tier_bytes[tier] += delta;
	/* hb->size feeds every "total/free" report and free_to_carve
	 * (size - real_used), which underflows if size lags. The per-thread
	 * cache budget and chunk_max keep their init values, so the cell
	 * caches do not change behaviour mid-flight. */
	hb->size += delta;
	old_pages = hb->npages;
	hb->npages = (unsigned long)(hb->hbase + off + delta - hb->pbase)
	             >> hb->hps_shift;

	for (i = old_pages; i < hb->npages; i++) {
		hb->pages[i].tier = (unsigned char)tier;
		hb->pages[i].want_collapse = later ? HG_COLLAPSE_TRIES : 0;
		page_publish_whole(hb, &hb->pages[i]);
	}
	if (later) {
		hb->collapse_deferred += hb->npages - old_pages;
		hb->collapse_wanting += hb->npages - old_pages;
		__atomic_store_n(&hb->collapse_pending, 1, __ATOMIC_RELEASE);
	}
	/* the published sizes move last, with release semantics: nothing that
	 * reads them lock-free may see the new figure before the pages exist */
	__atomic_store_n(&hb->span_end, off + delta, __ATOMIC_RELEASE);
	__atomic_store_n(&hb->committed_bytes, hb->committed_bytes + delta,
	                 __ATOMIC_RELEASE);
	hb->span_pending = hb->span_end;
	span_check(hb, "a grow");

	/* keep the floor at 1/16 of the grid it now guards */
	floor_recompute(hb);

	hb->grows++;
	hb->grow_gen++;
	hb->grow_bytes += delta;
	if (why == HG_GROW_PROACTIVE)
		hb->grows_proactive++;
	else
		hb->grows_exhaustion++;
	hb->shrink_quiet = 0;    /* fresh demand voids any quiet window */
	hb->draining = 0;
	hb->pol_cooldown = hb->pol.active ? hb->pol.cooldown : 0;
	hb->pol_dry_said = 0;
	hg_grow_unblock(hb, "the arena grew, the resource came back");

	LM_NOTICE("%s arena grew %s by %lu MB to %lu MB (%lu new pages on %s; "
		"commit %lu us with the lock released; %lu MB headroom left)\n",
		hb->name, why == HG_GROW_PROACTIVE ? "proactively" : "on exhaustion",
		delta >> 20, hb->committed_bytes >> 20, hb->npages - old_pages,
		hg_mem_tier_str((enum hg_mem_tier)tier),
		commit_ns / 1000, (hb->hcap - hb->committed_bytes) >> 20);
	return 0;
}

int hg_buddy_grow_unlocks(struct hg_block *hb, unsigned long need, enum hg_grow_why why)
{
	int r;

	hg_lock_assert_held(hb, "hg_buddy_grow_unlocks entry");
	r = buddy_grow_body(hb, need, why);
	hg_lock_assert_held(hb, "hg_buddy_grow_unlocks return");
	return r;
}

/* --- shrink ----------------------------------------------------------- */

/* defined with the run machinery below; shrink shares its eligibility test */
static inline int page_is_whole_free(const struct hg_block *hb,
                                     const struct hg_page *pg);

/*
 * Trim: release whole-free pages from the TOP of the span, retracting it,
 * never below committed_min (-m/-M). Top-only keeps hg_owns() one contiguous
 * test and the registry entry valid. Whole-free needs no cross-process
 * coordination: a cell in any thread's private cache still counts in its
 * block's live count, so its page is never whole-free. The pages leave the
 * free list under hb->lock, out of every carve's reach, and grow_inflight
 * keeps other range operations out; the release runs with the lock RELEASED
 * and the bookkeeping finishes under it. A kernel refusal puts the pages back.
 * Returns the number of pages released.
 */
static unsigned long buddy_shrink_body(struct hg_block *hb)
{
	unsigned long lpp = hg_leaves_per_page(hb);
	unsigned long limit = hb->shrink_step >> hb->hps_shift;
	unsigned long n = 0, i, off, len, backed = 0, t0, rel_ns;
	unsigned int top = hb->buddy_top;
	int reason, rc;

	/*
	 * Only still-backed pages ("backed") count against committed_min: a
	 * punched page's bytes left committed_bytes at the punch. The test
	 * cannot wrap: backed never exceeds committed_bytes - committed_min.
	 */
	while (n < limit) {
		struct hg_page *pg = &hb->pages[hb->npages - 1 - n];
		unsigned long cost = pg->punched ? 0 : hb->hps;
		unsigned long bpages = (backed + cost) >> hb->hps_shift;
		unsigned long floor_after, free_after;

		if (pg->releasing || !page_is_whole_free(hb, pg))
			break;
		if (hb->committed_bytes - backed < hb->committed_min + cost)
			break;
		/* stay above the headroom rule's line (free leaves after this
		 * page >= 2x the floor after it), or the next tick regrows
		 * what this one released */
		if (hb->buddy_free_leaves < bpages * lpp)
			break;
		free_after = hb->buddy_free_leaves - bpages * lpp;
		floor_after = ((hb->npages - hb->punched_pages - bpages) * lpp)
		              / 16;
		if (free_after < 2 * floor_after)
			break;
		backed += cost;
		n++;
	}
	if (!n)
		return 0;

	len = n << hb->hps_shift;
	off = (unsigned long)(hb->pages[hb->npages - n].base - hb->hbase);
	if (off + len != hb->span_end) {
		/* the grid does not end at the span end (an unaligned
		 * non-Linux base): decline rather than approximate */
		return 0;
	}

	/* phase 1 - off the free set under the lock, out of every carve's
	 * reach: the release below runs with the lock dropped. A punched
	 * page is already off. */
	for (i = hb->npages - n; i < hb->npages; i++) {
		struct hg_page *pg = &hb->pages[i];

		if (!pg->punched)
			fl_unlink(hb, pg->base, top);
		pg->releasing = 1;
	}
	hb->grow_inflight = 1;
	reason = hb->lk_cur;
	hg_lock_leave(hb);

	/* phase 2 - the syscalls, lock released */
	t0 = hg_now_ns();
	rc = hg_mem_release(hb, off, len);
	rel_ns = hg_now_ns() - t0;

	/* phase 3 - publish, or put back */
	hg_lock_enter(hb, (enum hg_lock_reason)reason);
	hg_lkstat_add(&hb->lk_release, rel_ns);
	__atomic_store_n(&hb->grow_inflight, 0, __ATOMIC_RELEASE);
	if (rc != 0) {
		for (i = hb->npages - n; i < hb->npages; i++) {
			struct hg_page *pg = &hb->pages[i];

			pg->releasing = 0;
			if (!pg->punched)
				fl_push(hb, pg->base, top);
		}
		return 0;
	}

	for (i = hb->npages - n; i < hb->npages; i++) {
		struct hg_page *pg = &hb->pages[i];

		pg->releasing = 0;
		bit_clear(pg->bitmap, node_id(top, top, 0));
		memset(pg->leaforder, HG_LEAF_NONE, (size_t)lpp);
		pg->free_leaves = 0;
		pg->run_len = 0;
		if (pg->punched) {
			/* the hole leaves the span with its page; its bytes and
			 * its leaves left the counts at the punch */
			pg->punched = 0;
			if (hb->punched_pages)
				hb->punched_pages--;
		} else {
			hb->buddy_free_leaves -= lpp;
			if (hb->tier_bytes[pg->tier] >= hb->hps)
				hb->tier_bytes[pg->tier] -= hb->hps;
		}
		if (pg->want_collapse) {   /* released: nothing left to collapse */
			pg->want_collapse = 0;
			hb->collapse_wanting--;
		}
	}
	hb->npages -= n;
	hb->span_end -= len;
	hb->committed_bytes -= backed;
	hb->span_pending = hb->span_end;
	hb->size -= len;
	hb->shrinks++;
	hb->shrink_bytes += backed;
	floor_recompute(hb);
	span_check(hb, "a shrink");

	LM_NOTICE("%s arena shrank by %lu MB to %lu MB (%lu pages released "
		"to the %s in %lu us with the lock released; %lu MB of growth "
		"still held)\n", hb->name, len >> 20, hb->committed_bytes >> 20,
		n, hb->tier == HG_MEM_HUGETLB ? "hugetlb pool" : "host",
		rel_ns / 1000, (hb->committed_bytes - hb->committed_min) >> 20);
	return n;
}

static unsigned long hg_buddy_shrink_unlocks(struct hg_block *hb)
{
	unsigned long r;

	hg_lock_assert_held(hb, "hg_buddy_shrink_unlocks entry");
	r = buddy_shrink_body(hb);
	hg_lock_assert_held(hb, "hg_buddy_shrink_unlocks return");
	return r;
}

/*
 * Interior release (punch): give back a whole-free page from ANYWHERE in the
 * span, so one live cell at the top no longer pins the free pages below it
 * (MADV_REMOVE is valid at any offset of a shared mapping). The page stays in
 * the span as a hole; its bytes leave committed_bytes and its leaves
 * buddy_free_leaves, which counts CARVABLE leaves only.
 *
 * The page is unlinked first, so no carve can take it while it is released
 * with the lock dropped, and stays off until
 * hg_buddy_regrow_holes_unlocks() re-commits it. Its bitmap and leaforder
 * (metadata region) are untouched, so page_is_whole_free() stays true.
 *
 * Phases as in the trim: choose and unlink under hb->lock, release unlocked
 * (one syscall pair per page), publish under it. A refusal latches
 * shrink_unsupported and puts the rest back. Called from the drain after the
 * trim; returns the pages punched.
 */
#define HG_PAGES_PER_EVENT 128   /* per release or re-commit event */
static unsigned long buddy_punch_body(struct hg_block *hb)
{
	unsigned long sel[HG_PAGES_PER_EVENT];
	unsigned long limit = hb->shrink_step >> hb->hps_shift;
	unsigned long lpp = hg_leaves_per_page(hb);
	unsigned long i, got = 0, ok, t0, rel_ns, free_after, floor_after;
	unsigned int top = hb->buddy_top;
	int reason;

	if (!hg_interior_release || hb->shrink_unsupported || !limit)
		return 0;
	if (limit > HG_PAGES_PER_EVENT)
		limit = HG_PAGES_PER_EVENT;

	/* phase 1 - choose from the bottom, where the re-commit refills
	 * too, and unlink each page so no carve can take it. The
	 * floor is in COMMITTED bytes (a hole is not usable memory); the
	 * span never moves */
	for (i = 0; i + 1 < hb->npages && got < limit; i++) {
		struct hg_page *pg = &hb->pages[i];

		if (pg->punched || pg->releasing || !page_is_whole_free(hb, pg))
			continue;
		if (hb->committed_bytes <
		    hb->committed_min + ((got + 1) << hb->hps_shift))
			break;
		/* the headroom rule's line, as in the trim */
		if (hb->buddy_free_leaves < (got + 1) * lpp)
			break;
		free_after = hb->buddy_free_leaves - (got + 1) * lpp;
		floor_after = ((hb->npages - hb->punched_pages - got - 1) * lpp)
		              / 16;
		if (free_after < 2 * floor_after)
			break;
		fl_unlink(hb, pg->base, top);
		pg->releasing = 1;
		sel[got++] = i;
	}
	if (!got)
		return 0;
	hb->grow_inflight = 1;
	reason = hb->lk_cur;
	hg_lock_leave(hb);

	/* phase 2 - the syscalls, lock released; stop at the first refusal */
	t0 = hg_now_ns();
	for (ok = 0; ok < got; ok++) {
		struct hg_page *pg = &hb->pages[sel[ok]];

		if (hg_mem_release(hb, (unsigned long)(pg->base - hb->hbase),
		                   hb->hps) != 0)
			break;
	}
	rel_ns = hg_now_ns() - t0;

	/* phase 3 - publish what went, put back what did not */
	hg_lock_enter(hb, (enum hg_lock_reason)reason);
	hg_lkstat_add(&hb->lk_release, rel_ns);
	__atomic_store_n(&hb->grow_inflight, 0, __ATOMIC_RELEASE);
	for (i = 0; i < got; i++) {
		struct hg_page *pg = &hb->pages[sel[i]];

		pg->releasing = 0;
		if (i >= ok) {
			fl_push(hb, pg->base, top);      /* still backed */
			continue;
		}
		pg->punched = 1;
		hb->buddy_free_leaves -= lpp;
		hb->committed_bytes -= hb->hps;
		hb->punches++;
		hb->punch_bytes += hb->hps;
		hb->punched_pages++;
		if (hb->tier_bytes[pg->tier] >= hb->hps)
			hb->tier_bytes[pg->tier] -= hb->hps;
		if (pg->want_collapse) {   /* punched: nothing left to collapse */
			pg->want_collapse = 0;
			hb->collapse_wanting--;
		}
	}
	if (ok) {
		floor_recompute(hb);
		span_check(hb, "a punch");
		LM_NOTICE("%s arena punched %lu interior page%s (%lu MB) back "
			"to the %s in %lu us with the lock released; %lu MB "
			"committed of a %lu MB span, %lu page%s held as "
			"holes\n", hb->name, ok, ok == 1 ? "" : "s",
			(ok << hb->hps_shift) >> 20,
			hb->tier == HG_MEM_HUGETLB ? "hugetlb pool" : "host",
			rel_ns / 1000, hb->committed_bytes >> 20,
			hb->span_end >> 20, hb->punched_pages,
			hb->punched_pages == 1 ? "" : "s");
	}
	return ok;
}

static unsigned long hg_buddy_punch_unlocks(struct hg_block *hb)
{
	unsigned long r;

	hg_lock_assert_held(hb, "hg_buddy_punch_unlocks entry");
	r = buddy_punch_body(hb);
	hg_lock_assert_held(hb, "hg_buddy_punch_unlocks return");
	return r;
}

/*
 * Re-commit holes, from hg_buddy_grow_unlocks() before it extends the span. A
 * hole is faulted back in AND re-pinned in THIS process before it can be
 * carved again: mlock() is per-vma and does not survive fork. Phases as in the
 * grow: select under hb->lock (holes are off the free list, so no carve
 * reaches them; grow_inflight keeps trim and punch out), pin with the lock
 * released, publish under it. Returns 1 if it served the request, 0 if no hole
 * could serve it, -1 if the RAM limb or every re-pin refused.
 */
static int buddy_regrow_holes_body(struct hg_block *hb, unsigned long need,
                                   unsigned long room)
{
	unsigned long sel[HG_PAGES_PER_EVENT];
	unsigned long want, i, got = 0, ok, t0, pin_ns;
	unsigned long lpp = hg_leaves_per_page(hb);
	unsigned int top = hb->buddy_top;
	int reason;

	if (!hb->punched_pages)
		return 0;

	/* at least a granule, like a span grow, and at least what the
	 * request needs - one round trip, not one per page */
	want = (need + hb->hps - 1) >> hb->hps_shift;
	if (want < hb->grow_granule >> hb->hps_shift)
		want = hb->grow_granule >> hb->hps_shift;
	if (want < 1)
		want = 1;
	if (want > hb->punched_pages)
		want = hb->punched_pages;
	if (want > room >> hb->hps_shift)
		want = room >> hb->hps_shift;
	if (want > HG_PAGES_PER_EVENT)
		want = HG_PAGES_PER_EVENT;
	if (!want)
		return 0;
	if (hg_grow_ram_refused(hb, want << hb->hps_shift))
		return grow_resource_refused(hb);

	/* phase 1 - select, lowest first */
	for (i = 0; i < hb->npages && got < want; i++)
		if (hb->pages[i].punched && !hb->pages[i].releasing)
			sel[got++] = i;
	hb->grow_inflight = 1;
	reason = hb->lk_cur;
	hg_lock_leave(hb);

	/* phase 2 - pin, in this process, lock released. On hugetlb a hole's
	 * pages went back to the pool for anyone to take, so the re-commit can
	 * fail and those pages stay holes. The other tiers populate even when
	 * they cannot pin (hg_mem_repin() counts that). */
	t0 = hg_now_ns();
	for (i = 0, ok = 0; i < got; i++) {
		struct hg_page *pg = &hb->pages[sel[i]];

		if (hg_mem_repin(hb, (unsigned long)(pg->base - hb->hbase),
		                 hb->hps, pg->tier) == 0 ||
		    pg->tier != HG_MEM_HUGETLB)
			sel[ok++] = sel[i];
	}
	got = ok;
	pin_ns = hg_now_ns() - t0;

	/* phase 3 - publish what came back */
	hg_lock_enter(hb, (enum hg_lock_reason)reason);
	hg_lkstat_add(&hb->lk_commit, pin_ns);
	if (!got) {
		__atomic_store_n(&hb->grow_inflight, 0, __ATOMIC_RELEASE);
		hb->grow_refuse_why = HG_GR_HOLE_REPIN;
		return grow_resource_refused(hb);
	}
	for (i = 0; i < got; i++) {
		struct hg_page *pg = &hb->pages[sel[i]];

		pg->punched = 0;
		fl_push(hb, pg->base, top);
		hb->buddy_free_leaves += lpp;
		hb->tier_bytes[pg->tier] += hb->hps;
		if (hb->punched_pages)
			hb->punched_pages--;
	}
	/* the count moves last, with release semantics: a waiter polling it
	 * lock-free must not see it before the pages are back on the list */
	__atomic_store_n(&hb->committed_bytes,
	                 hb->committed_bytes + (got << hb->hps_shift),
	                 __ATOMIC_RELEASE);
	__atomic_store_n(&hb->grow_inflight, 0, __ATOMIC_RELEASE);
	hb->repins += got;
	hb->repin_bytes += got << hb->hps_shift;
	hb->hole_regrows++;
	hb->grow_gen++;
	floor_recompute(hb);
	hb->shrink_quiet = 0;    /* fresh demand voids any quiet window */
	hb->draining = 0;
	hb->pol_cooldown = hb->pol.active ? hb->pol.cooldown : 0;
	span_check(hb, "a re-commit");

	LM_NOTICE("%s arena re-committed %lu hole%s (%lu MB) instead of "
		"growing the span; pin %lu us with the lock released; %lu MB "
		"committed of a %lu MB span, %lu hole%s left\n", hb->name, got,
		got == 1 ? "" : "s", (got << hb->hps_shift) >> 20,
		pin_ns / 1000, hb->committed_bytes >> 20, hb->span_end >> 20,
		hb->punched_pages, hb->punched_pages == 1 ? "" : "s");
	return 1;
}

static int hg_buddy_regrow_holes_unlocks(struct hg_block *hb, unsigned long need,
                                         unsigned long room)
{
	int r;

	hg_lock_assert_held(hb, "hg_buddy_regrow_holes_unlocks entry");
	r = buddy_regrow_holes_body(hb, need, room);
	hg_lock_assert_held(hb, "hg_buddy_regrow_holes_unlocks return");
	return r;
}


/* no-profile default: consecutive quiet sweep ticks before a drain starts (two
 * minutes at the 30 s sweep); a profile sets its own cycle count */
#define HG_SHRINK_QUIET_TICKS 4

/*
 * The shrink decision, once per sweep interval, hb->lock held. A tick is quiet
 * only if elastic bytes exist, nothing is starved (below the floor,
 * grow-blocked) and free space stays well clear of the floor even after a
 * granule goes back, so a shrink never re-triggers pressure. Any failed
 * condition, and any grow, resets the window.
 */
static void shrink_tick_body(struct hg_block *hb)
{
	unsigned long granule_leaves;
	unsigned int need_ticks;

	if (!hb->buddy_ready || hb->shrink_unsupported)
		return;
	if (hb->committed_bytes <= hb->committed_min) {
		hb->shrink_quiet = 0;
		return;
	}
	/* never move the top while a grow is populating above it */
	if (hb->grow_inflight) {
		hb->shrink_quiet = 0;
		return;
	}
	/* post-grow cool-off: the profile grammar's 10x-cycles hold, so an
	 * arena that just grew cannot immediately give the growth back */
	if (hb->pol_cooldown) {
		hb->pol_cooldown--;
		hb->shrink_quiet = 0;
		return;
	}
	/* never shrink an arena that is starved or latched, policy or not. A
	 * busy top page ends the tick only without interior release: it
	 * blocks just the trim (which re-tests it), and it is the very case
	 * the punch exists for */
	if (hb->below_floor || hb->grow_blocked ||
	    (!hg_interior_release &&
	     !page_is_whole_free(hb, &hb->pages[hb->npages - 1]))) {
		hb->shrink_quiet = 0;
		return;
	}
	if (hb->pol.active) {
		/* the profile's quiet test: usage at or below its
		 * down-threshold, and free space of at least a granule plus
		 * twice the floor */
		if (hg_get_real_used(hb) * 100 > (unsigned long)hb->pol.down_pct *
		                          hb->committed_bytes ||
		    hb->buddy_free_leaves <
		        (hb->grow_granule >> HG_LEAF_SHIFT) +
		        hb->reserve_floor * 2) {
			hb->shrink_quiet = 0;
			return;
		}
		need_ticks = hb->pol.down_cycles ? hb->pol.down_cycles : 1;
	} else {
		granule_leaves = hb->grow_granule >> HG_LEAF_SHIFT;
		if (hb->buddy_free_leaves <
		        granule_leaves + hb->reserve_floor * 4) {
			hb->shrink_quiet = 0;
			return;
		}
		need_ticks = HG_SHRINK_QUIET_TICKS;
	}
	if (++hb->shrink_quiet < need_ticks)
		return;
	hb->shrink_quiet = 0;
	if (hg_autoscale_dry_run) {
		if (!hb->pol_dry_said) {
			hb->pol_dry_said = 1;
			LM_NOTICE("%s: DRY RUN - would shrink (committed %lu MB, "
				"usage %lu%%)\n", hb->name,
				hb->committed_bytes >> 20,
				hg_get_real_used(hb) * 100 /
				hb->committed_bytes);
		}
		return;
	}
	/* decided once per cycle; from here the drain releases one step per
	 * maintenance tick until a gate fails or nothing is left */
	hb->draining = 1;
	hg_drain_tick(hb);
}

void hg_shrink_tick(struct hg_block *hb)
{
	hg_lock_assert_held(hb, "hg_shrink_tick entry");
	shrink_tick_body(hb);
	hg_lock_assert_held(hb, "hg_shrink_tick return");
}

/*
 * One drain step, hb->lock held: the top trim, then the interior punch. Every
 * maintenance tick (1 s) while draining, and once from the sweep fallback. The
 * gates are re-tested each step, since one tick of demand withdraws the
 * decision; free space must exceed the headroom line (2x the floor with a
 * profile, 4x without) by a page, so a drain never trips the regrow.
 */
void hg_drain_tick(struct hg_block *hb)
{
	unsigned long lpp = hg_leaves_per_page(hb), released;

	if (!hb->draining || !hb->buddy_ready)
		return;
	if (hb->shrink_unsupported || hb->below_floor || hb->grow_blocked ||
	    hb->committed_bytes <= hb->committed_min) {
		hb->draining = 0;
		return;
	}
	if (hb->grow_inflight)
		return;               /* a release or a grow is in flight */
	if (hb->pol.active) {
		if (hg_get_real_used(hb) * 100 >
		    (unsigned long)hb->pol.down_pct * hb->committed_bytes ||
		    hb->buddy_free_leaves < 2 * hb->reserve_floor + lpp) {
			hb->draining = 0;
			return;
		}
	} else if (hb->buddy_free_leaves < 4 * hb->reserve_floor + lpp) {
		hb->draining = 0;
		return;
	}

	released = hg_buddy_shrink_unlocks(hb);
	/* the trim reaches only the top of the span; the punch also frees what
	 * sits below a long-lived allocation at the top */
	released += hg_buddy_punch_unlocks(hb);
	if (!released)
		hb->draining = 0;
}

/*
 * The always-on headroom rule, profile or not: keep the free grid above twice
 * the floor while the reservation allows, so the arena does not sit at its
 * floor flushing caches every sweep. Ticked every second by the maintenance
 * process, else once per sweep interval. Returns 1 if it grew.
 */
static int grow_headroom_tick_body(struct hg_block *hb)
{
	if (!hb->buddy_ready || !hg_grow_ahead)
		return 0;
	if (hb->span_end < hb->hcap && !hb->grow_inflight &&
	    hb->buddy_free_leaves < 2 * hb->reserve_floor)
		return hg_buddy_grow_unlocks(hb, hb->grow_granule, HG_GROW_PROACTIVE) == 0;
	return 0;
}

int hg_grow_headroom_tick(struct hg_block *hb)
{
	int r;

	hg_lock_assert_held(hb, "hg_grow_headroom_tick entry");
	r = grow_headroom_tick_body(hb);
	hg_lock_assert_held(hb, "hg_grow_headroom_tick return");
	return r;
}

/*
 * The profile's proactive grow: grow BEFORE exhaustion when usage crossed the
 * up-threshold often enough. Same call sites and lock contract as
 * hg_shrink_tick(). Exhaustion growth stays armed with a profile too: a burst
 * between ticks must not fail allocations.
 */
static void grow_tick_body(struct hg_block *hb)
{
	int hit;

	if (!hb->buddy_ready)
		return;
	if (!hb->maint_active && hg_grow_headroom_tick(hb))
		return;
	if (!hb->pol.active)
		return;
	if (hb->committed_bytes >= hb->pol.up_bytes)
		return;                          /* at the profile ceiling */

	hb->pol_up_ticks++;
	if (hg_get_real_used(hb) * 100 >=
	    (unsigned long)hb->pol.up_pct * hb->committed_bytes)
		hb->pol_up_hits++;

	if (hb->pol_up_ticks <
	    (hb->pol.up_window ? hb->pol.up_window : 1))
		return;
	hit = hb->pol_up_hits >= (hb->pol.up_need ? hb->pol.up_need : 1);
	hb->pol_up_ticks = 0;
	hb->pol_up_hits = 0;
	if (!hit)
		return;

	if (hg_autoscale_dry_run) {
		if (!hb->pol_dry_said) {
			hb->pol_dry_said = 1;
			LM_NOTICE("%s: DRY RUN - would grow (committed %lu MB, "
				"usage %lu%%, profile ceiling %lu MB)\n",
				hb->name, hb->committed_bytes >> 20,
				hg_get_real_used(hb) * 100 /
				hb->committed_bytes,
				hb->pol.up_bytes >> 20);
		}
		return;
	}
	hg_buddy_grow_unlocks(hb, hb->grow_granule, HG_GROW_PROACTIVE);
}

void hg_grow_tick(struct hg_block *hb)
{
	hg_lock_assert_held(hb, "hg_grow_tick entry");
	grow_tick_body(hb);
	hg_lock_assert_held(hb, "hg_grow_tick return");
}

/* top-order free pages per the wfree bitmap, to check against nfree[top] */
unsigned long hg_buddy_top_reachable(struct hg_block *hb)
{
	return wf_count(hb);
}

/*
 * Rebuild one order's free list from the per-page bitmaps, skipping punched
 * pages (hg_buddy_regrow_holes_unlocks() republishes those). Corruption path
 * only - reached when a list head is on a punched page - and a full walk.
 */
static void fl_rebuild(struct hg_block *hb, unsigned int o)
{
	unsigned int top = hb->buddy_top;
	unsigned long i, leaf, lpp = hg_leaves_per_page(hb), step = 1UL << o;
	unsigned long before = hb->nfree[o];

	if (o == top)
		memset(hb->wfree, 0, hb->wfree_words * sizeof(long));
	else
		hb->bfree[o] = NULL;
	hb->nfree[o] = 0;
	for (i = 0; i < hb->npages; i++) {
		struct hg_page *pg = &hb->pages[i];

		/* a page being released is off every free list on purpose and
		 * its memory may be going away right now */
		if (pg->punched || pg->releasing)
			continue;
		for (leaf = 0; leaf < lpp; leaf += step)
			if (bit_test(pg->bitmap, node_id(top, o, leaf)))
				fl_push(hb, pg->base + (leaf << HG_LEAF_SHIFT), o);
	}
	LM_WARN("%s: free list order %u rebuilt from the bitmaps: %lu blocks "
		"before, %lu now, %lu page%s punched\n", hb->name, o, before,
		hb->nfree[o], hb->punched_pages, hb->punched_pages == 1 ? "" : "s");
}

/* --- allocate --------------------------------------------------------- */

void *hg_buddy_alloc(struct hg_block *hb, unsigned int order)
{
	unsigned int o, top = hb->buddy_top;
	struct hg_page *pg;
	unsigned long leaf;
	char *blk;

	if (!hb->buddy_ready || order > top)
		return NULL;

	/* smallest free block that fits - the first non-empty list scanning up
	 * from the requested order - so large free blocks are preserved */
	for (o = order; o <= top; o++) {
		if (o == top) {
			long idx = wf_first(hb);

			if (idx < 0)
				continue;
			pg = &hb->pages[idx];
		} else {
			if (!hb->bfree[o])
				continue;
			pg = page_of(hb, hb->bfree[o]);
		}
		if (!pg->punched)
			break;
		/*
		 * The list head is on a punched page: its descriptor (metadata
		 * region) is readable, the page is not - on hugetlb a touch
		 * can SIGBUS, elsewhere it reads as zeros and an unlink would
		 * orphan the list. So check BEFORE the unlink, never touch the
		 * page, and rebuild the list from the bitmaps (which skip
		 * punched pages), then serve from it or move up an order.
		 */
		hg_corrupt(hb, HG_C_INTERNAL);
		LM_CRIT("%s: free list order %u heads at punched page %u - the "
			"list and the page descriptor disagree; rebuilding the list "
			"from the bitmaps\n", hb->name, o, pg->idx);
		fl_rebuild(hb, o);
		if (o == top ? wf_first(hb) >= 0 : hb->bfree[o] != NULL)
			break;
	}
	if (o > top)
		return NULL;

	if (o == top) {
		pg = &hb->pages[wf_first(hb)];
		blk = pg->base;
	} else {
		blk = (char *)hb->bfree[o];
		pg = page_of(hb, blk);
	}
	if (o == top)
		hb->top_carves++;
	fl_unlink(hb, blk, o);
	leaf = hg_leaf_of(hb, blk);
	bit_clear(pg->bitmap, node_id(top, o, leaf));

	/* split down, publishing the upper half at each step. The lower half
	 * stays in hand, so the returned address never moves. */
	while (o > order) {
		unsigned long bleaf;
		char *buddy;

		o--;
		bleaf = leaf + (1UL << o);
		buddy = pg->base + (bleaf << HG_LEAF_SHIFT);
		memset(pg->leaforder + bleaf, (int)o, (size_t)1UL << o);
		bit_set(pg->bitmap, node_id(top, o, bleaf));
		fl_push(hb, buddy, o);
		hb->buddy_splits++;
	}

	memset(pg->leaforder + leaf, (int)order, (size_t)1UL << order);
	pg->free_leaves -= 1U << order;
	hb->buddy_free_leaves -= 1UL << order;
	hg_extent_note(hb, blk, (unsigned long)HG_LEAF_SIZE << order);
	hg_reserve_floor_check(hb);
	return blk;
}

/* --- free ------------------------------------------------------------- */

void hg_buddy_free(struct hg_block *hb, void *p, unsigned int order)
{
	unsigned int o = order, top = hb->buddy_top;
	struct hg_page *pg;
	unsigned long leaf;
	char *blk = p;

	if (!hg_in_pages(hb, p)) {
		hg_corrupt(hb, HG_C_BUDDY_BAD_FREE);
		LM_CRIT("%s: buddy free of %p, which is outside the page grid - "
			"ignoring\n", hb->name, p);
		return;
	}
	pg = page_of(hb, p);
	leaf = hg_leaf_of(hb, p);

	if (((unsigned long)p & ((HG_LEAF_SIZE << order) - 1)) !=
	    ((unsigned long)pg->base & ((HG_LEAF_SIZE << order) - 1))) {
		hg_corrupt(hb, HG_C_BUDDY_BAD_FREE);
		LM_CRIT("%s: buddy free of %p at order %u, which is not aligned to "
			"its own size - ignoring\n", hb->name, p, order);
		return;
	}
	if (leaf & ((1UL << order) - 1)) {
		hg_corrupt(hb, HG_C_BUDDY_BAD_FREE);
		LM_CRIT("%s: buddy free of %p as order %u, but leaf %lu does not "
			"start a block of that order - ignoring\n",
			hb->name, p, order, leaf);
		return;
	}
	if (pg->leaforder[leaf] != order) {
		hg_corrupt(hb, HG_C_BUDDY_BAD_FREE);
		LM_CRIT("%s: buddy free of %p as order %u, but leaf %lu records "
			"order %u - ignoring\n", hb->name, p, order, leaf,
			pg->leaforder[leaf]);
		return;
	}
	/*
	 * Double free: the leaforder check above passes it (a free block that
	 * did not merge still records its order), and a second push would hand
	 * the address out twice. The bitmap knows "already free and entire".
	 */
	if (bit_test(pg->bitmap, node_id(top, order, leaf))) {
		hg_corrupt(hb, HG_C_DOUBLE_FREE);
		LM_CRIT("%s: double buddy free of %p at order %u - ignoring\n",
			hb->name, p, order);
		return;
	}

	pg->free_leaves += 1U << order;
	hb->buddy_free_leaves += 1UL << order;

	/*
	 * Merge up while the buddy (leaf ^ (1 << o)) is free and entire: O(1)
	 * per step, at most `top` steps, ending at the page.
	 */
	while (o < top) {
		unsigned long bleaf = leaf ^ (1UL << o);
		char *buddy = pg->base + (bleaf << HG_LEAF_SHIFT);

		if (!bit_test(pg->bitmap, node_id(top, o, bleaf)))
			break;                    /* allocated, or split */
		if (pg->leaforder[bleaf] != o)
			break;                    /* free but not at this order */

		fl_unlink(hb, buddy, o);
		bit_clear(pg->bitmap, node_id(top, o, bleaf));
		hb->buddy_merges++;
		pg->leaforder[bleaf] = HG_LEAF_NONE;

		if (bleaf < leaf) {           /* the upper half: move down */
			leaf = bleaf;
			blk = buddy;
		}
		o++;
	}

	memset(pg->leaforder + leaf, (int)o, (size_t)1UL << o);
	bit_set(pg->bitmap, node_id(top, o, leaf));
	fl_push(hb, blk, o);
	hg_reserve_floor_check(hb);
}

/* --- multi-page runs -------------------------------------------------- */

/* is this whole page free and unsplit, i.e. available to a run? */
static inline int page_is_whole_free(const struct hg_block *hb,
                                     const struct hg_page *pg)
{
	unsigned int top = hb->buddy_top;

	return pg->run_len == 0 && bit_test(pg->bitmap, node_id(top, top, 0)) &&
	       pg->leaforder[0] == top;
}

void *hg_buddy_alloc_run(struct hg_block *hb, unsigned long npages)
{
	unsigned int top = hb->buddy_top;
	unsigned long i, start, run = 0;

	if (!hb->buddy_ready || npages == 0)
		return NULL;
	if (npages == 1)
		return hg_buddy_alloc(hb, top);

	for (i = 0, start = 0; i < hb->npages; i++) {
		/* a punched page is whole-free by its bitmap but unbacked
		 * and off the list; a run must not take it (a grow
		 * re-commits it) */
		if (hb->pages[i].punched || hb->pages[i].releasing ||
		    !page_is_whole_free(hb, &hb->pages[i])) {
			run = 0;
			start = i + 1;
			continue;
		}
		if (++run == npages)
			break;
	}
	if (run < npages)
		return NULL;

	for (i = start; i < start + npages; i++) {
		struct hg_page *pg = &hb->pages[i];

		fl_unlink(hb, pg->base, top);
		bit_clear(pg->bitmap, node_id(top, top, 0));
		memset(pg->leaforder, HG_LEAF_NONE,
		       (size_t)hg_leaves_per_page(hb));
		pg->free_leaves = 0;
		pg->run_len = (i == start) ? (unsigned int)npages : HG_RUN_MEMBER;
		hb->buddy_free_leaves -= hg_leaves_per_page(hb);
	}
	hg_extent_note(hb, hb->pages[start].base, npages << hb->hps_shift);
	hg_reserve_floor_check(hb);
	LM_DBG("%s: run of %lu pages at page %lu\n", hb->name, npages, start);
	return hb->pages[start].base;
}

unsigned long hg_buddy_run_len(const struct hg_block *hb, const void *p)
{
	const struct hg_page *pg;

	if (!hb->buddy_ready || !hg_in_pages(hb, p))
		return 0;
	pg = &hb->pages[hg_page_of(hb, p)];
	if (pg->base != p || pg->run_len == 0 || pg->run_len == HG_RUN_MEMBER)
		return 0;
	return pg->run_len;
}

void hg_buddy_free_run(struct hg_block *hb, void *p)
{
	unsigned long n, i, start;
	struct hg_page *pg;

	n = hg_buddy_run_len(hb, p);
	if (n == 0) {
		hg_corrupt(hb, HG_C_BUDDY_BAD_FREE);
		LM_CRIT("%s: run free of %p, which heads no run - ignoring\n",
			hb->name, p);
		return;
	}
	start = hg_page_of(hb, p);
	for (i = start; i < start + n; i++) {
		pg = &hb->pages[i];
		pg->run_len = 0;
		page_publish_whole(hb, pg);
	}
	hg_reserve_floor_check(hb);
}

int hg_buddy_order_of(const struct hg_block *hb, const void *p)
{
	const struct hg_page *pg;
	unsigned long leaf;

	if (!hb->buddy_ready || !hg_in_pages(hb, p))
		return -1;
	pg = &hb->pages[hg_page_of(hb, p)];
	leaf = hg_leaf_of(hb, p);
	if (pg->leaforder[leaf] == HG_LEAF_NONE)
		return -1;
	return pg->leaforder[leaf];
}

#endif /* HG_MALLOC */
