/*
 * buddy allocator over the HG_MALLOC huge-page grid
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
 * Two records describe the same tree, because they answer different
 * questions and neither answers both cheaply:
 *
 *   leaforder[leaf]  the order of the block CONTAINING that leaf - every leaf
 *                    of a block carries it, not just the first. That is what
 *                    turns any interior address into its block with a mask,
 *                    which the layers above need: a cell being freed sits
 *                    somewhere in the middle of its block, and finding the
 *                    block is how the live count gets decremented at all.
 *                    Filling the range costs a memset of 2^order bytes on the
 *                    slow path (256 B for a whole 2 MB page) and buys an O(1)
 *                    lookup on a path that would otherwise need a search.
 *                    HG_LEAF_NONE means the leaf is not buddy space - it
 *                    belongs to a multi-page run.
 *
 *   bitmap[node]     1 iff that tree node is a WHOLE FREE block, i.e. it is
 *                    sitting in a free list right now. Not "free" in the
 *                    sense of "contains free space": a split node is 0 even
 *                    though both its halves may be free. That is exactly the
 *                    predicate the merge step needs - "is my buddy free AND
 *                    entire" - and it answers it in one bit test.
 *
 * Keeping both is what makes split and merge O(1) instead of a search.
 */

/* node id in the per-page tree. Level 0 is the whole page (one node), level
 * `top` is the leaves; a complete tree over 2^top leaves has 2^(top+1)-1
 * nodes - 511 for a 2 MB page with 8 KB leaves, which is the 64 byte bitmap
 * the design budgets. */
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
 * The whole-free-page bitmap (hb->wfree). The top order IS the page,
 * so "a top-order free block" and "a whole-free page on offer" are the same
 * thing, and a bit per page describes it with nothing stored in the page.
 * prefer-low - serve the LOWEST free page, so carves concentrate at the
 * bottom and the top pages drain for the top-only shrink - is find-first-set.
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

	/* the top order lives in the bitmap; lower orders stay LIFO -
	 * their blocks live inside pages already carved, where the cell-level
	 * concentration policy owns placement, and their lists are the long
	 * ones where an ordered walk would cost */
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

/*
 * Publish one whole page as a single top-order free block. Only valid for a
 * page nothing has been carved out of yet.
 */
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
 * Release the leaves [from, to) of a page that started out wholly reserved.
 *
 * Used for the one page that the block header and the buddy's own metadata
 * partly occupy. Done leaf by leaf through the ordinary free path so the
 * merges happen by the ordinary rules: freeing 24 consecutive leaves yields
 * whatever mix of orders the alignment actually permits, which is fiddly to
 * compute directly and trivial to get by construction.
 *
 * The alternative - refusing to use a partly-occupied page at all - would
 * throw away up to a whole huge page. That is 0.8% of a 256 MB shm arena but
 * 25% of an 8 MB pkg arena, which is not affordable.
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
	 * One contiguous metadata carve for all pages, from the FRONT of the
	 * arena via the ordinary bump allocator - so it inherits whatever tier
	 * the reservation achieved, is shared for shm and private for pkg with
	 * no decision to make, and costs no extra huge pages. A dedicated page
	 * would be 25% overhead on an 8 MB pkg arena, and 30 workers each
	 * wanting one would burn 60 MB to hold 45 KB.
	 *
	 * Sized for npages_cap, not npages: descriptors for pages the arena
	 * could GROW into are laid out now, from committed memory, so a later
	 * grow only publishes them - it never has to find room for metadata
	 * in an arena that is, by definition of why it is growing, full. The
	 * overhead is ~0.05% of each never-committed page, paid up front.
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
		/* the committed pages carry init's achieved tier; pages beyond
		 * get theirs stamped by the grow that commits them */
		pg->tier = (unsigned char)hb->tier;
		/* starts wholly reserved; pages < npages are published below,
		 * pages beyond wait for hg_buddy_grow() */
	}

	/*
	 * Everything below hoff is spoken for - the block header, then the
	 * metadata just carved. hoff is leaf aligned (hg_arena_init), so the
	 * boundary lands on a leaf and no partially-consumed leaf can be handed
	 * out. Round UP anyway: it costs at most one leaf and it means a future
	 * change to the bump allocator cannot silently start handing out memory
	 * that is already in use.
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
	 * Rebase the coalesce counter.  Publishing the straddling page above
	 * goes through the ordinary free path on purpose - so the tree is built
	 * by the same rules it will be maintained by - but that means every one
	 * of those coalesces has just been counted, and they say nothing about
	 * fragmentation.  Keep the total for the record and restart from zero,
	 * so buddy_splits and buddy_merges finally share a zero point: without
	 * this an idle 8 MB pkg arena reports 7 splits against 244 merges.
	 */
	hb->buddy_merges_init = hb->buddy_merges;
	hb->buddy_merges = 0;
	hb->buddy_splits = 0;   /* init allocates nothing; make that explicit */

	hb->buddy_ready = 1;
	/*
	 * Reserve floor at 1/16 of the grid. A fraction rather than a constant
	 * because the arenas differ by three orders of magnitude - 8 MB pkg to
	 * 5 GB shm - and a fixed page count would be either meaningless on one
	 * or most of the other.
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
 * span_end and committed_bytes (struct hg_block) differ once a page is
 * punched: it keeps its address inside the span while its bytes stop
 * being committed. So the invariant is
 * not equality, it is that every byte of the span is either committed or
 * accounted for as a hole:
 *
 *     committed_bytes + punched_pages * hps == span_end
 *
 * Re-checked at every point that moves either number - grow, trim, punch and
 * the re-commit on carve. A mismatch is an accounting slip in this file, not
 * damaged memory; it is counted where every other internal inconsistency is
 * and the arena carries on.
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
 * Reserve floor at 1/16 of the grid the allocator can actually CARVE - the
 * committed pages, not the span. A hole is an address the arena keeps and
 * memory it does not have; counting it in the floor inflates the floor by
 * exactly what the drain gave back, and the drain then throttles itself on
 * its own holes (measured: a 2 GB arena that had punched 375 pages parked at
 * 274 MB with 3 MB live, the headroom rule holding 258 MB free on a floor
 * computed over a 1 GB span it could no longer use).
 */
static inline void floor_recompute(struct hg_block *hb)
{
	hb->reserve_floor = ((hb->npages - hb->punched_pages) *
	                     hg_leaves_per_page(hb)) / 16;
}

/* --- grow ------------------------------------------------------------- */

/*
 * Commit more of the reservation and publish the new whole pages. Called
 * with hb->lock HELD, from the two places an allocation can die of buddy
 * exhaustion (carve_chunk and the large tier), which also bounds how often
 * it runs: once per granule of genuine demand, never on the fast path.
 *
 * Three phases: the granule's range is RESERVED under the lock, POPULATED
 * by hg_mem_commit() with the lock released (the page faults, the pin and
 * the backing verification take tens of ms per 16 MB and must not stall
 * every other slow path in the arena), then PUBLISHED under the lock.
 * grow_inflight keeps a second grow or a shrink off the range meanwhile.
 *
 * Returns 0 if new pages were published (caller retries its allocation),
 * -1 if the arena cannot grow (at cap, cap never set, or the commit was
 * refused by the host). The caller's existing failure path then reports
 * exhaustion exactly as a fixed arena would.
 */
/*
 * A RESOURCE refusal - the host, not the admin, said no. Counts, and runs
 * the two-step latch described on grow_blocked's declaration: arm on the
 * first refusal, latch only if the arena is refused again after a full GC
 * pass ran - a spike that reclaim absorbs never alerts. The latch WARNs
 * once and hands the event raise to the sweep timer via grow_event_due;
 * nothing is raised from here, hb->lock is held.
 */
static int grow_resource_refused(struct hg_block *hb)
{
	hb->grow_refused++;

	if (hb->grow_blocked)
		return -1;

	if (!hb->grow_blocked_mark) {
		/* gc_passes + 1 doubles as the "armed" flag: it can never be
		 * 0, and it is exactly the count a pass must push gc_passes
		 * PAST for the refusal to have survived one */
		hb->grow_blocked_mark = hb->gc_passes + 1;
		hb->grow_blocked_refuse0 = hb->grow_refused;
	} else if (hb->gc_passes >= hb->grow_blocked_mark) {
		hb->grow_blocked = 1;
		hb->grow_event_due = 1;
		LM_WARN("%s: GROW-BLOCKED latched - the arena cannot grow and "
			"a GC pass did not change that (%lu refusals so far). "
			"Alert on hg_shm_grow_blocked; details precede this "
			"line.\n", hb->name, hb->grow_refused);
	}
	return -1;
}

/* the blocked state ends two ways; both say so if there is anything to
 * end, and both re-arm the once-per-episode messages */
void hg_grow_unblock(struct hg_block *hb, const char *how)
{
	if (hb->grow_blocked)
		LM_NOTICE("%s: GROW-BLOCKED cleared - %s\n", hb->name, how);
	hb->grow_blocked = 0;
	hb->grow_blocked_mark = 0;
	hb->grow_blocked_refuse0 = 0;
	hb->grow_event_due = 0;
	hb->grow_refuse_said = 0;
}

/*
 * The sweep timer's half of the latch - see grow_blocked_refuse0's
 * declaration for why the GC route alone cannot be trusted. Called once
 * per sweep interval with hb->lock HELD; latches if an armed episode is
 * still accumulating refusals a full interval later.
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
			"so far). Alert on hg_shm_grow_blocked; details precede "
			"this line.\n", hb->name, hb->grow_refused);
	} else {
		/* armed but quiet for a whole interval: the spike passed */
		hb->grow_blocked_mark = 0;
		hb->grow_blocked_refuse0 = 0;
	}
}

/* how long an exhausted worker waits, lock released, for a grow that
 * another worker has in flight: a populate takes tens of ms, the collapse
 * retrofit up to ~200 ms; past this the request is refused and counted */
#define HG_GROW_WAIT_MAX_NS  2000000000UL
#define HG_GROW_WAIT_SLICE_US 100

static int hg_buddy_regrow_holes(struct hg_block *hb, unsigned long need,
                                 unsigned long room);

int hg_buddy_grow(struct hg_block *hb, unsigned long need, enum hg_grow_why why)
{
	unsigned long delta, room, old_pages, i, limit, t0, off, commit_ns;
	unsigned long cp_ns[HG_CP_PHASES];
	int tier, reason;

	if (!hb->buddy_ready)
		return -1;

	/* advise-only mode: report what growth WOULD have done, act never -
	 * the arena behaves exactly like a fixed one, with evidence */
	if (hg_autoscale_dry_run) {
		hb->grow_refused++;
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
	 * Another worker is populating a granule right now. Its publish
	 * is what this caller needs, so wait for it WITHOUT the lock - every
	 * other slow path keeps running meanwhile - and report "grew" so the
	 * caller retries its carve against the fresh pages.
	 */
	if (hb->grow_inflight) {
		unsigned long seen = hb->committed_bytes, waited;

		hb->grow_waits++;
		reason = hb->lk_cur;
		hg_lock_leave(hb);
		t0 = hg_now_ns();
		do {
			usleep(HG_GROW_WAIT_SLICE_US);
			waited = hg_now_ns() - t0;
		} while (__atomic_load_n(&hb->grow_inflight, __ATOMIC_ACQUIRE) &&
		         __atomic_load_n(&hb->committed_bytes,
		                         __ATOMIC_ACQUIRE) == seen &&
		         waited < HG_GROW_WAIT_MAX_NS);
		hg_lock_enter(hb, (enum hg_lock_reason)reason);
		hg_lkstat_add(&hb->lk_grow_wait, waited);
		if (hb->committed_bytes != seen)
			return 0;                 /* it landed: retry the carve */
		if (hb->grow_inflight) {
			hb->grow_wait_timeouts++; /* still populating - give up */
			hb->grow_refused++;
			return -1;
		}
		/* the in-flight grow was refused; fall through and try ours */
	}

	/* the profile's scale-up target is the admin ceiling WITHIN the
	 * -m INIT:CAP reservation; without a profile the reservation is the
	 * ceiling */
	limit = (hb->pol.active && hb->pol.up_bytes) ? hb->pol.up_bytes
	                                             : hb->hcap;
	/* The room is counted in committed bytes: the ceiling bounds what is
	 * backed. With interior release a punched hole leaves committed_bytes
	 * below span_end; holes are refilled first (below), and an append that
	 * would run past the reservation is refused by hg_mem_commit(). */
	room = limit > hb->committed_bytes ? limit - hb->committed_bytes : 0;
	if (room == 0) {
		hb->grow_refused++;
		/* an admin-set ceiling doing its job is not an alarm; growth
		 * being impossible because no cap was ever set is not even
		 * noteworthy - a fixed arena lives its whole life there. The
		 * two are told apart by history, not arithmetic: a growable
		 * arena can only reach room==0 by having grown (committed_bytes
		 * starts below hcap and moves only in grows), so grows>0 here
		 * means "the headroom existed and is spent", while grows==0
		 * means the arena never had any. Said once per episode -
		 * grow_refused carries the magnitude. */
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

	/* holes first: RAM the arena already holds the address of costs a
	 * pin and no virtual memory to take back, and refilling them is
	 * what keeps a punched arena from growing past its own free space */
	{
		int r = hg_buddy_regrow_holes(hb, need, room);

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

	/*
	 * Phase 1 - RESERVE under the lock: the granule's range is fixed
	 * now, nobody else grows or shrinks until it is published or given
	 * back (shrink checks grow_inflight; a second exhausted worker waits
	 * above).
	 */
	off = hb->span_end;
	hb->grow_inflight = 1;
	hb->span_pending = off + delta;
	reason = hb->lk_cur;
	hg_lock_leave(hb);

	/* phase 2 - POPULATE with the lock released: the page faults, the
	 * pin and the backing verification (tens of ms for 16 MB) no longer
	 * stall every other slow path in the arena */
	t0 = hg_now_ns();
	tier = hg_mem_commit(hb, off, delta, cp_ns);
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
	/* hb->size is the figure every "total/free" surface reports (shmem
	 * statistics, hg_info, hg_advise's configured_mb) and free_to_carve
	 * is literally size - real_used: leave it behind and that subtraction
	 * underflows once carving passes the original size. The per-thread
	 * cache budget and chunk_max stay on their init-time derivation -
	 * conservative, and re-deriving them per grow would change cell-cache
	 * behaviour mid-flight for a marginal win. */
	hb->size += delta;
	old_pages = hb->npages;
	hb->npages = (unsigned long)(hb->hbase + off + delta - hb->pbase)
	             >> hb->hps_shift;

	for (i = old_pages; i < hb->npages; i++) {
		hb->pages[i].tier = (unsigned char)tier;
		page_publish_whole(hb, &hb->pages[i]);
	}
	/* the published sizes move last, with release semantics: a waiter
	 * polling committed_bytes lock-free, or hg_owns() reading span_end on
	 * a free path, must not see the new figure before the pages exist */
	__atomic_store_n(&hb->span_end, off + delta, __ATOMIC_RELEASE);
	__atomic_store_n(&hb->committed_bytes, hb->committed_bytes + delta,
	                 __ATOMIC_RELEASE);
	hb->span_pending = hb->span_end;
	span_check(hb, "a grow");

	/* keep the floor at 1/16 of the grid it now guards */
	floor_recompute(hb);

	hb->grows++;
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

/* --- shrink ----------------------------------------------------------- */

/* defined with the run machinery below; shrink shares its eligibility test */
static inline int page_is_whole_free(const struct hg_block *hb,
                                     const struct hg_page *pg);

/*
 * Release whole-free pages from the TOP of the span, retracting it. Top-only
 * is what keeps every address invariant intact: hg_owns() stays one
 * contiguous test, the registry entry stays valid, and a page below the new
 * top is untouched. Whole-free is what makes it SAFE with no cross-process
 * coordination: eager merging guarantees a whole-free page is one top-order
 * block on the free list, and a cell parked in some thread's private cache
 * has NOT decremented its block's live count - so its page is not whole-free
 * and can never be picked here.
 *
 * Never below committed_min: the admin asked for -m/-M; only growth is
 * elastic.
 *
 * Two-phase, like the grow. The pages are chosen and taken off the
 * free list under hb->lock - from then on no carve can reach them, and
 * grow_inflight keeps every other grow, trim and punch out - then the
 * release syscall runs with the lock RELEASED, and the bookkeeping is
 * finished under it. Measured on kernel 6.12: a 4K-backed release is
 * ~400 us per 2 MB page, so a 256 MB trim under the lock held it 52-67 ms
 * and stalled every allocator; unlocked, the hold is microseconds and the
 * step is bounded by the grow_inflight window instead. If the kernel
 * refuses, the pages are still backed and go straight back on the list.
 *
 * Returns the number of pages released.
 */
static unsigned long hg_buddy_shrink(struct hg_block *hb)
{
	unsigned long lpp = hg_leaves_per_page(hb);
	unsigned long limit = hb->shrink_step >> hb->hps_shift;
	unsigned long n = 0, i, off, len, backed = 0, t0, rel_ns;
	unsigned int top = hb->buddy_top;
	int reason, rc;

	/*
	 * A page the punch already gave back costs the committed floor nothing
	 * when the trim retracts the span over it: its bytes left
	 * committed_bytes at the punch, and all the trim does is take the hole
	 * out of the span with the page. So the floor is charged only for
	 * pages that are still backed ("backed"), in the form that cannot
	 * wrap: backed never exceeds committed_bytes - committed_min, because
	 * that is the very test.
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
		/* never below the headroom rule's own line, or the next tick
		 * regrows what this one released: carvable leaves after this
		 * page against twice the floor after it */
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
		/* a platform where the grid does not end exactly at the span
		 * end (unaligned non-Linux base) - decline rather than
		 * approximate */
		return 0;
	}

	/* phase 1 - off the free list, invisible to every carve, under the
	 * lock. The list is intrusive (a node is the first bytes of the free
	 * page it describes) and the release discards those bytes, so this
	 * MUST come first. A punched page is already off. */
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

/*
 * Interior release: give back a whole-free page from ANYWHERE in the span.
 *
 * The reach failure the task exists to fix is that one live cell in the top
 * page pins every free page beneath it - measured at 1,010 free pages of
 * 1,024 held behind a single startup-lifetime resident, and again on the
 * bench with the tick fixed: the trim stopped at 1,616 MB with 793 pages
 * free behind it; the punch took them. The kernel side already worked -
 * hg_mem_release() is munlock() + MADV_REMOVE(), a hole punch valid at any
 * offset in a shared mapping; only the arena's arithmetic refused, because
 * hsize was both the span and the committed count. Step 1 split those.
 *
 * What a punch does to the buddy, and why, was learned from measurement
 * rather than assumed. The node of a top-order free block is the first
 * bytes of the page itself (struct hg_free_blk), and MADV_REMOVE discards
 * them - so a punched page CANNOT stay on the free list. Left there, the
 * first fl_unlink() through its zeroed node nulled the list head and
 * orphaned every page behind it (28 reachable before, 0 after). So the page
 * is unlinked FIRST, while its node can still be read, and stays off the
 * list until hg_buddy_regrow_holes() re-commits it. Its bitmap and leaforder
 * live in the metadata region and are untouched: page_is_whole_free() still
 * describes it truthfully, the extent stays a power of two and the
 * double-free detector keeps the bitmap as its authority.
 * buddy_free_leaves counts CARVABLE leaves, so a hole leaves it and the
 * reserve floor and headroom rules keep meaning what they say.
 *
 * Two-phase like the trim: choose and unlink under the lock, release with
 * it dropped (one syscall pair per page - interior pages are scattered),
 * publish under it; a refusal latches shrink_unsupported and puts the
 * remaining pages back. Called with hb->lock held, from the drain, after
 * the top trim has taken what it could. Returns the pages punched.
 */
#define HG_PAGES_PER_EVENT 128   /* per release or re-commit event */
static unsigned long hg_buddy_punch(struct hg_block *hb)
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

	/* phase 1 - choose from the bottom (the order the re-commit refills
	 * holes, so what the arena uses stays packed low) and take each page
	 * off the free list before its node is discarded. A COMMITTED-bytes
	 * floor: the admin asked for -m/-M of usable memory and a hole is
	 * memory they do not have; the span never moves here. */
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

/*
 * The other half of the punch, and the one that carries the correctness
 * risk: a hole is re-committed - faulted back in AND re-pinned - before it
 * can be carved again, in THIS process, because mlock() is per-vma and does
 * not survive fork (measured). It runs from
 * hg_buddy_grow(), i.e. in whatever process hit exhaustion or in the
 * maintenance process growing ahead, and it runs BEFORE the span is
 * extended: a hole is committed RAM the arena already owns the address of,
 * and taking it back costs a pin and no virtual memory.
 *
 * Two-phase like a span grow: select under the lock (the pages are already
 * off the free list, so nothing can carve them, and grow_inflight keeps the
 * tick's trim and punch away), pin with the lock released, publish under
 * it. Returns 1 if it served the request, 0 if there were no holes to
 * serve it from, -1 if the RAM limb refused.
 */
static int hg_buddy_regrow_holes(struct hg_block *hb, unsigned long need,
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

	/* phase 2 - pin, in this process, lock released. On the hugetlb
	 * rung a hole's pages went back to the pool for anyone to take
	 * (measured: HugePages_Free up, Rsvd unchanged), so the re-commit can
	 * genuinely fail; those pages stay holes and are compacted out of
	 * the list here. On the other rungs hg_mem_repin() populates even
	 * when it cannot pin, and counts that. */
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


/* the no-policy default: consecutive quiet sweep ticks per released
 * granule (two minutes at the 30 s sweep) - deliberately down-slow. A
 * profile replaces this with its own "for N cycles". */
#define HG_SHRINK_QUIET_TICKS 4

/*
 * The down-slow policy gate, one call per sweep interval, hb->lock held.
 * Counts a tick as "quiet" only while ALL of it holds: elastic bytes
 * exist, nothing is starved (not below the floor, not grow-blocked), the
 * top page is already whole-free, and free space would stay generously
 * clear of the floor's recovery threshold even after giving a granule
 * back - so a shrink can never be the thing that re-triggers pressure.
 * Any failed condition resets the window; so does any grow.
 *
 * These thresholds are the hardcoded seed of the scale-down half of the
 * auto_scaling_profile surface; the profile replaces the constants, not
 * the shape.
 */
void hg_shrink_tick(struct hg_block *hb)
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
	/* the hard SAFETY conditions hold with or without a policy: never
	 * shrink an arena that is starved or latched.
	 *
	 * The top page being in use is a THIRD condition, and it belongs to
	 * the trim alone: retracting the span can only ever take the topmost
	 * pages, so a live cell up there ends the matter. An interior punch
	 * does not care where the free page sits - and a pinned top page is
	 * precisely the case interior release exists for, so keeping this test in
	 * front of the whole tick would return before the punch ever ran and
	 * make the feature a no-op exactly where it is needed.
	 * hg_buddy_shrink() re-tests the top itself and does nothing when it
	 * is busy, so dropping the test here costs the trim nothing. */
	if (hb->below_floor || hb->grow_blocked ||
	    (!hg_interior_release &&
	     !page_is_whole_free(hb, &hb->pages[hb->npages - 1]))) {
		hb->shrink_quiet = 0;
		return;
	}
	if (hb->pol.active) {
		/* the profile's own quiet test: usage at or below its
		 * down-threshold, plus the giving-a-granule-back-stays-safe
		 * floor guard */
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
	/* the decision is made once per cycle; the RELEASE runs once per
	 * maintenance tick from here on, one step at a time, until a gate
	 * fails or there is nothing left to take */
	hb->draining = 1;
	hg_drain_tick(hb);
}

/*
 * One step of the drain, hb->lock held: the top trim, then the interior
 * punch. Called every maintenance tick (1 s) while draining is set - and
 * once from the sweep fallback, which has no faster clock. The gates are
 * re-tested per tick, cheaply: the quiet window was the DECISION, and a
 * single tick's worth of demand is enough to withdraw it. Abundance is
 * tested one page beyond the headroom rule's own line (2x the floor with a
 * profile, 4x without - the down-slow default), so a drain can never be the
 * thing that trips the rule that regrows.
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

	released = hg_buddy_shrink(hb);
	/* the trim can only ever reach the top of the span; this reaches the
	 * rest, and is the only thing that returns memory once a
	 * startup-lifetime allocation has landed above the free space */
	released += hg_buddy_punch(hb);
	if (!released)
		hb->draining = 0;
}

/*
 * The proactive half of the profile: grow BEFORE exhaustion when usage
 * has crossed the up-threshold often enough. Same call sites and lock
 * contract as hg_shrink_tick(); a profile-less arena never enters (its
 * growth remains exhaustion-triggered, the emergency path, which
 * also stays armed WITH a profile - a burst between ticks must not fail
 * allocations while the timer catches up).
 */
/*
 * The always-on headroom rule, profile or not. The warm-path tail
 * was measured to be "arena at its reserve floor" (every sweep flushing
 * caches to stay above it); with the commit off the hot path a
 * proactive granule costs the data path nothing, so keep the free grid
 * above twice the floor whenever the reservation allows it. Ticked every
 * second by the maintenance process when there is one, else once per
 * sweep interval. Returns 1 if it grew.
 */
int hg_grow_headroom_tick(struct hg_block *hb)
{
	if (!hb->buddy_ready || !hg_grow_ahead)
		return 0;
	if (hb->span_end < hb->hcap && !hb->grow_inflight &&
	    hb->buddy_free_leaves < 2 * hb->reserve_floor)
		return hg_buddy_grow(hb, hb->grow_granule, HG_GROW_PROACTIVE) == 0;
	return 0;
}

void hg_grow_tick(struct hg_block *hb)
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
	hg_buddy_grow(hb, hb->grow_granule, HG_GROW_PROACTIVE);
}

/*
 * How many whole-free pages can actually be REACHED from the top list's
 * head, against nfree[top]'s claim. (The top order is a bitmap now;
 * the walk became a population count, the check keeps its meaning.) Each node lives
 * in the first bytes of the free block it describes - so anything that
 * discards a free page's contents (a punch) severs the list there while the
 * count stays put. Bounded by the count, so a cycle cannot spin it.
 */
unsigned long hg_buddy_top_reachable(struct hg_block *hb)
{
	/* the bitmap's population, to compare with nfree[top]'s count */
	return wf_count(hb);
}

/*
 * Rebuild one order's free list from the per-page bitmaps - the
 * authority for "free, whole, not split" - skipping punched
 * pages, whose blocks belong to hg_buddy_regrow_holes() and are republished
 * when it re-commits them. Corruption path only: it is reached when a list
 * head is found on a punched page (below), and it walks every page's every
 * block of the order, so it is not for routine use.
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

		if (pg->punched)
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

	/*
	 * Smallest free block that fits, so large free blocks are preserved by
	 * construction (design, "allocation policy"). Scanning UP from the
	 * requested order is exactly that: the first non-empty list is the
	 * smallest one that can serve it.
	 */
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
		 * The head of this list is on a punched page. The descriptor
		 * lives in the metadata region and is always readable; the page is
		 * not: on hugetlb its node faults (a SIGBUS once the pool is
		 * empty), on the other tiers it reads as zeros and the unlink would
		 * null the list head and orphan every block behind it. The
		 * check therefore sits BEFORE the unlink: after it, and
		 * ignoring the re-pin result, it could also hand out a hugetlb
		 * page whose first touch is a SIGBUS. Refuse without touching
		 * the page: rebuild this order's list from the bitmaps, which skip
		 * punched pages, and serve from the result or move up an order.
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
	 * Double free. The leaforder check above does NOT catch it: a block that
	 * failed to merge still records its own order, so freeing it twice would
	 * look entirely legitimate and push it onto the free list a second time,
	 * after which two callers get the same address. The bitmap is the
	 * authority on "already free and entire", which is precisely this.
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
	 * Merge upwards while the buddy is free and entire. The buddy's address
	 * is this block's with one bit flipped, which is what keeps each step
	 * O(1); the loop runs at most `top` times.
	 *
	 * Note the merge stops at the page. The top order IS the page, so there
	 * is no cross-page merging to implement and a wholly free top block is
	 * exactly one huge page - which is the unit a reclaim hands back.
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

		if (bleaf < leaf) {           /* we are the upper half - move down */
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
		/* a punched page is whole-free by its bitmap but off the list
		 * and unbacked; a run must not take it (hg_buddy_grow will
		 * re-commit it if the arena needs it) */
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
