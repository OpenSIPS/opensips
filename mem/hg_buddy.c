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

/* --- free lists ------------------------------------------------------- */

static inline void fl_push(struct hg_block *hb, void *p, unsigned int order)
{
	struct hg_free_blk *b = (struct hg_free_blk *)p;

	/*
	 * v3: the TOP-order list is kept in ascending address order, so the
	 * list head - what hg_buddy_alloc() serves whole pages from - is
	 * always the LOWEST free page. That is the whole prefer-low policy:
	 * new carves concentrate at the bottom, the top pages drain, and
	 * shrink (top-only by design) finds them whole-free. Lower orders
	 * stay LIFO - their blocks live inside pages already carved, where
	 * the cell-level concentration policy owns placement, and their
	 * lists are the long ones where an ordered walk would cost.
	 *
	 * The walk is bounded by the whole-free page count and runs on the
	 * buddy slow path only (a page reaches top order when it drains
	 * fully - GC and shrink territory, not the cell fast path).
	 */
	if (order == hb->buddy_top && hb->bfree[order]) {
		struct hg_free_blk *cur = hb->bfree[order], *prev = NULL;

		while (cur && (void *)cur < p) {
			prev = cur;
			cur = cur->next;
		}
		b->prev = prev;
		b->next = cur;
		if (cur)
			cur->prev = b;
		if (prev)
			prev->next = b;
		else
			hb->bfree[order] = b;
		hb->nfree[order]++;
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
	unsigned long i, lpp, bmwords, meta, consumed_leaves;
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
	meta = hb->npages_cap * (sizeof(struct hg_page) + lpp +
	                         bmwords * sizeof(long));
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
		100.0 * (double)meta / (double)hb->hsize,
		hb->buddy_free_leaves, hb->npages * lpp, consumed_leaves);
	return 0;
}

/* --- grow (v3) -------------------------------------------------------- */

/*
 * Commit more of the reservation and publish the new whole pages. Called
 * with hb->lock HELD, from the two places an allocation can die of buddy
 * exhaustion (carve_chunk and the large tier), which also bounds how often
 * it runs: once per granule of genuine demand, never on the fast path.
 *
 * The pre-fault inside hg_mem_commit() happens under the arena lock - a
 * deliberate trade. Growth is rare (once per granule, ratcheting), the
 * granule is sized to keep the stall in the low milliseconds, and the
 * alternative - dropping the lock to fault, then re-taking it - opens a
 * publish race for no benefit: every other worker in here is ALSO out of
 * memory and would only queue on the same growth.
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

int hg_buddy_grow(struct hg_block *hb, unsigned long need)
{
	unsigned long delta, room, old_pages, i, limit;
	int tier;

	if (!hb->buddy_ready)
		return -1;

	/* advise-only mode: report what growth WOULD have done, act never -
	 * the arena behaves exactly like a fixed v2 one, with evidence */
	if (hg_autoscale_dry_run) {
		hb->grow_refused++;
		if (!hb->pol_dry_said) {
			hb->pol_dry_said = 1;
			LM_WARN("%s: DRY RUN - would grow for a %lu byte request "
				"(committed %lu MB); counting further suppressed "
				"grows in hg_shm_grow_refused\n",
				hb->name, need, hb->hsize >> 20);
		}
		return -1;
	}

	/* the profile's scale-up target is the admin ceiling WITHIN the
	 * -m INIT:CAP reservation; without a profile the reservation is the
	 * ceiling */
	limit = (hb->pol.active && hb->pol.up_bytes) ? hb->pol.up_bytes
	                                             : hb->hcap;
	room = limit > hb->hsize ? limit - hb->hsize : 0;
	if (room == 0) {
		hb->grow_refused++;
		/* an admin-set ceiling doing its job is not an alarm; growth
		 * being impossible because no cap was ever set is not even
		 * noteworthy - v2 arenas live their whole lives there. The two
		 * are told apart by history, not arithmetic: a growable arena
		 * can only reach room==0 by having grown (hsize starts below
		 * hcap and moves only in grows), so grows>0 here means "the
		 * headroom existed and is spent", while grows==0 means the
		 * arena never had any. Said once per episode - grow_refused
		 * carries the magnitude. */
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

	delta = hb->grow_granule;
	if (need > delta)
		delta = (need + hb->grow_granule - 1) /
		        hb->grow_granule * hb->grow_granule;
	if (delta > room)
		delta = room;

	/* the host-RAM limb of the ceiling, before any work is done */
	if (hg_grow_ram_refused(hb, delta))
		return grow_resource_refused(hb);

	tier = hg_mem_commit(hb, hb->hsize, delta);
	if (tier < 0) {
		/* the commit rolled itself back; nothing was published */
		return grow_resource_refused(hb);
	}

	hb->tier_bytes[tier] += delta;
	hb->hsize += delta;
	/* hb->size is the figure every "total/free" surface reports (shmem
	 * statistics, hg_info, hg_advise's configured_mb) and free_to_carve
	 * is literally size - real_used: leave it behind and that subtraction
	 * underflows once carving passes the original size. The per-thread
	 * cache budget and chunk_max stay on their init-time derivation -
	 * conservative, and re-deriving them per grow would change cell-cache
	 * behaviour mid-flight for a marginal win. */
	hb->size += delta;
	old_pages = hb->npages;
	hb->npages = (unsigned long)(hb->hbase + hb->hsize - hb->pbase)
	             >> hb->hps_shift;

	for (i = old_pages; i < hb->npages; i++) {
		hb->pages[i].tier = (unsigned char)tier;
		page_publish_whole(hb, &hb->pages[i]);
	}

	/* keep the floor at 1/16 of the grid it now guards */
	hb->reserve_floor = (hb->npages * hg_leaves_per_page(hb)) / 16;

	hb->grows++;
	hb->grow_bytes += delta;
	hb->shrink_quiet = 0;    /* fresh demand voids any quiet window */
	hb->pol_cooldown = hb->pol.active ? hb->pol.cooldown : 0;
	hb->pol_dry_said = 0;
	hg_grow_unblock(hb, "the arena grew, the resource came back");

	LM_NOTICE("%s arena grew by %lu MB to %lu MB (%lu new pages on %s; "
		"%lu MB headroom left)\n", hb->name, delta >> 20,
		hb->hsize >> 20, hb->npages - old_pages,
		hg_mem_tier_str((enum hg_mem_tier)tier),
		(hb->hcap - hb->hsize) >> 20);
	return 0;
}

/* --- shrink (v3) ------------------------------------------------------ */

/* defined with the run machinery below; shrink shares its eligibility test */
static inline int page_is_whole_free(const struct hg_block *hb,
                                     const struct hg_page *pg);

/*
 * Release up to one granule of whole-free pages from the TOP of the
 * committed range. Top-only is what keeps every address invariant intact:
 * hg_owns() stays one contiguous test, the registry entry stays valid, and
 * a page below the new top is untouched. Whole-free is what makes it SAFE
 * with no cross-process coordination: eager merging guarantees a
 * whole-free page is one top-order block on the free list, and a cell
 * parked in some thread's private cache has NOT decremented its block's
 * live count - so its page is not whole-free and can never be picked here.
 *
 * Never below hsize_min: the admin asked for -m/-M; only growth is
 * elastic. The release syscall runs BEFORE any bookkeeping, while
 * hb->lock (held by the caller) keeps every allocator out of the pages
 * being punched - if the kernel refuses, nothing has changed.
 */
static void hg_buddy_shrink(struct hg_block *hb)
{
	unsigned long lpp = hg_leaves_per_page(hb);
	unsigned long limit = hb->grow_granule >> hb->hps_shift;
	unsigned long n = 0, i, off, len;
	unsigned int top = hb->buddy_top;

	while (n < limit &&
	       hb->hsize - ((n + 1UL) << hb->hps_shift) >= hb->hsize_min &&
	       page_is_whole_free(hb, &hb->pages[hb->npages - 1 - n]))
		n++;
	if (!n)
		return;

	len = n << hb->hps_shift;
	off = (unsigned long)(hb->pages[hb->npages - n].base - hb->hbase);
	if (off + len != hb->hsize) {
		/* a platform where the grid does not end exactly at the
		 * committed end (unaligned non-Linux base). Shrinking a
		 * mid-range is correct for the punch but wrong for the
		 * hsize arithmetic - decline rather than approximate. */
		return;
	}

	if (hg_mem_release(hb, off, len) != 0)
		return;

	for (i = hb->npages - n; i < hb->npages; i++) {
		struct hg_page *pg = &hb->pages[i];

		fl_unlink(hb, pg->base, top);
		bit_clear(pg->bitmap, node_id(top, top, 0));
		memset(pg->leaforder, HG_LEAF_NONE, (size_t)lpp);
		pg->free_leaves = 0;
		pg->run_len = 0;
		hb->buddy_free_leaves -= lpp;
		if (hb->tier_bytes[pg->tier] >= hb->hps)
			hb->tier_bytes[pg->tier] -= hb->hps;
	}
	hb->npages -= n;
	hb->hsize -= len;
	hb->size -= len;
	hb->shrinks++;
	hb->shrink_bytes += len;
	hb->reserve_floor = (hb->npages * lpp) / 16;

	LM_NOTICE("%s arena shrank by %lu MB to %lu MB (%lu pages released "
		"to the %s; %lu MB of growth still held)\n", hb->name,
		len >> 20, hb->hsize >> 20, n,
		hb->tier == HG_MEM_HUGETLB ? "hugetlb pool" : "host",
		(hb->hsize - hb->hsize_min) >> 20);
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
	if (hb->hsize <= hb->hsize_min) {
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
	 * shrink an arena that is starved, latched, or whose top page is
	 * still in use */
	if (hb->below_floor || hb->grow_blocked ||
	    !page_is_whole_free(hb, &hb->pages[hb->npages - 1])) {
		hb->shrink_quiet = 0;
		return;
	}
	if (hb->pol.active) {
		/* the profile's own quiet test: usage at or below its
		 * down-threshold, plus the giving-a-granule-back-stays-safe
		 * floor guard */
		if (hb->real_used * 100 > (unsigned long)hb->pol.down_pct *
		                          hb->hsize ||
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
				"usage %lu%%)\n", hb->name, hb->hsize >> 20,
				hb->real_used * 100 / hb->hsize);
		}
		return;
	}
	hg_buddy_shrink(hb);
}

/*
 * The proactive half of the profile: grow BEFORE exhaustion when usage
 * has crossed the up-threshold often enough. Same call sites and lock
 * contract as hg_shrink_tick(); a profile-less arena never enters (its
 * growth remains exhaustion-triggered, the step-1 emergency path, which
 * also stays armed WITH a profile - a burst between ticks must not fail
 * allocations while the timer catches up).
 */
void hg_grow_tick(struct hg_block *hb)
{
	int hit;

	if (!hb->buddy_ready || !hb->pol.active)
		return;
	if (hb->hsize >= hb->pol.up_bytes)
		return;                          /* at the profile ceiling */

	hb->pol_up_ticks++;
	if (hb->real_used * 100 >= (unsigned long)hb->pol.up_pct * hb->hsize)
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
				hb->name, hb->hsize >> 20,
				hb->real_used * 100 / hb->hsize,
				hb->pol.up_bytes >> 20);
		}
		return;
	}
	hg_buddy_grow(hb, hb->grow_granule);
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
	for (o = order; o <= top; o++)
		if (hb->bfree[o])
			break;
	if (o > top)
		return NULL;

	blk = (char *)hb->bfree[o];
	fl_unlink(hb, blk, o);
	pg = page_of(hb, blk);
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
	 * exactly one huge page - which is the unit the reclaim in task #57 will
	 * hand back.
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
		if (!page_is_whole_free(hb, &hb->pages[i])) {
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
