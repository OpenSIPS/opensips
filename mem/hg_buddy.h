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

/*
 * One buddy tree per huge page (geometry in hg_malloc.h, HG_LEAF_SHIFT).
 * Order 0 is the leaf (HG_LEAF_SIZE, 8 KB), the top order the whole page,
 * so there is no cross-page merging. Splitting and merging only change
 * records; merging is the only defragmentation, since callers hold raw
 * pointers and nothing live can move. Everything here runs under hb->lock,
 * on the slow path; the cell fast path never calls into this file.
 */

#ifndef HG_BUDDY_H
#define HG_BUDDY_H

#include "hg_malloc.h"

/* HG_MAX_ORDERS is in hg_malloc.h: struct hg_block needs it */

/* A free block keeps its list linkage in its own first bytes, so the free
 * lists need no external metadata. No magic in the block: hg_buddy_free()
 * catches a double free by the bitmap, which sits in the metadata region and
 * cannot be forged by a write to freed memory, and a wild pointer by its
 * alignment, order and bounds checks. */
struct hg_free_blk {
	struct hg_free_blk *next;
	struct hg_free_blk *prev;
};

/*
 * Per-page descriptor, in the metadata region at the front of the arena, NOT
 * in the page it describes, so that the page can become wholly free.
 */
/* deferred-collapse attempts per page before it is left on 4 KB pages */
#define HG_COLLAPSE_TRIES 16

struct hg_page {
	char          *base;       /* first byte of this page */
	unsigned char *leaforder;  /* per leaf: order of the block it starts */
	unsigned long *bitmap;     /* per node: 1 = free, whole, not split */

	/* fullness lists, unused until a page-preference allocation policy
	 * lands; they fit the descriptor's 64 byte budget */
	struct hg_page *next;
	struct hg_page *prev;

	unsigned int idx;          /* page index within the arena */
	unsigned int free_leaves;  /* leaves not currently allocated */
	/* >0 on the FIRST page of a multi-page run, giving its length; the
	 * other pages carry HG_RUN_MEMBER (see hg_buddy_alloc_run()) */
	unsigned int run_len;
	/* the byte fields below fit existing padding: the descriptor stays
	 * 56 bytes on 64-bit builds */
	/* the backing tier achieved by the commit that brought this page in
	 * (enum hg_mem_tier): each growth delta negotiates its own and shrink
	 * takes pages from any delta, so tier_bytes is decremented by this */
	unsigned char tier;
	/* backing punched out with MADV_REMOVE while whole-free. The buddy
	 * tree is untouched (free block, bitmap, leaforder all kept); the
	 * next carve from this page must re-commit and re-pin it first */
	unsigned char punched;
	/* set while a trim or a punch holds the arena lock RELEASED between
	 * taking the page off the free list and finishing its bookkeeping;
	 * every scan that reads the bitmap rather than the list must skip it */
	unsigned char releasing;
	/* collapse attempts left for a page a worker's grow published on 4 KB
	 * pages (HG_COLLAPSE_TRIES at publish, 0 = none); worked off by the
	 * maintenance process (hg_collapse_deferred) */
	unsigned char want_collapse;
};

/* run_len marker for a page that belongs to a run but does not head it */
#define HG_RUN_MEMBER  0xffffffffu
/* no per-order free count per page: that array would more than double the
 * descriptor; per-order counts are global, on hg_block */

/* leaforder[] value for a leaf that does not START a block (it is in the
 * middle of a larger one, or its block is allocated and recorded elsewhere) */
#define HG_LEAF_NONE  0xff

/*
 * Set up the buddy state: carve the per-page metadata from the front of the
 * arena, mark the block header and that metadata allocated, publish the rest
 * as free. Once, from hg_arena_init(), after pages_init(). 0, or -1 if the
 * metadata cannot be carved.
 */
int hg_buddy_init(struct hg_block *hb);

/* Allocate one block of exactly (HG_LEAF_SIZE << order) bytes, naturally
 * aligned. hb->lock must be held. Returns NULL when no page can serve it. */
void *hg_buddy_alloc(struct hg_block *hb, unsigned int order);

/* the *_unlocks functions and the three ticks DROP hb->lock inside (reserve
 * locked, populate unlocked, publish locked) and re-take it: held on entry
 * and on return, but nothing read before the call is valid after it. Each
 * asserts both ends (hg_lock_assert_held). */
/* commit up to max(granule, @need) more of the reservation and publish the
 * new whole pages as free. 0 = grew (retry the allocation), -1 = cannot (at
 * cap / no cap / host refused the commit) */
int hg_buddy_grow_unlocks(struct hg_block *hb, unsigned long need, enum hg_grow_why why);
/* the always-on headroom rule on its own (the maintenance process ticks it
 * every second); hb->lock held; 1 = grew */
int hg_grow_headroom_tick(struct hg_block *hb);

/* end a grow-blocked episode (logged if one was latched) and re-arm its
 * once-per-episode report; hb->lock held. Called by a successful grow and
 * the reserve floor's recovery. @how ends "GROW-BLOCKED cleared - ". */
void hg_grow_unblock(struct hg_block *hb, const char *how);

/* the sweep's promoter for an armed grow-blocked episode (the GC pass
 * cannot latch where nothing is reclaimable); also disarms one that went
 * quiet. hb->lock held */
void hg_grow_blocked_tick(struct hg_block *hb);

/* the down-slow shrink gate, once per sweep interval per arena, hb->lock
 * held. After HG_SHRINK_QUIET_TICKS consecutive quiet ticks it releases up
 * to a granule of whole-free top pages to the host (tier 1: the hugetlb
 * pool), never below the initial -m/-M size. For shm from the sweep timer
 * (or the maintenance process when it runs); for pkg from its owner's flush
 * path, as only the owner can shrink a private arena. */
void hg_shrink_tick(struct hg_block *hb);
/* one drain step (trim + punch) if the quiet window is open; every
 * maintenance tick, hb->lock held */
void hg_drain_tick(struct hg_block *hb);

/* the profile's proactive grow gate - same cadence, call sites
 * and lock contract as hg_shrink_tick(). No-op without a policy. */
void hg_grow_tick(struct hg_block *hb);

/* Return a block previously handed out by hg_buddy_alloc(), merging it with
 * its buddy as far up as it will go. hb->lock must be held. */
void hg_buddy_free(struct hg_block *hb, void *p, unsigned int order);

/* Order of the block containing @p, or -1 if @p is not in buddy space. */
int hg_buddy_order_of(const struct hg_block *hb, const void *p);

/*
 * The block CONTAINING @p, from any address inside it, without a search: a
 * freed cell reaches its block's live count this way, which is how an empty
 * block is recognised and reclaimed. NULL if @p is outside the page grid or
 * in a multi-page run.
 */
static inline void *hg_buddy_block_of(const struct hg_block *hb, const void *p)
{
	const struct hg_page *pg;
	unsigned long leaf;
	unsigned char o;

	if (!hb->buddy_ready || !hg_in_pages(hb, p))
		return NULL;
	pg = &hb->pages[hg_page_of(hb, p)];
	leaf = hg_leaf_of(hb, p);
	o = pg->leaforder[leaf];
	if (o == HG_LEAF_NONE)
		return NULL;
	return pg->base + ((leaf & ~((1UL << o) - 1)) << HG_LEAF_SHIFT);
}

/*
 * A run of @npages CONTIGUOUS whole pages, for a large-tier allocation
 * bigger than a huge page (a dialog or usrloc hash table). A linear scan
 * over page descriptors, not an index: it runs only when the large tier
 * grows past a page. hb->lock must be held. The run's first byte, or NULL.
 */
void *hg_buddy_alloc_run(struct hg_block *hb, unsigned long npages);

/* Release a run obtained from hg_buddy_alloc_run(). hb->lock must be held. */
void hg_buddy_free_run(struct hg_block *hb, void *p);

/* Length in pages of the run starting at @p, or 0 if @p heads no run. */
unsigned long hg_buddy_run_len(const struct hg_block *hb, const void *p);

/* Highest order this arena can serve, i.e. the whole-page order. */
static inline unsigned int hg_buddy_top_order(const struct hg_block *hb)
{
	return hb->hps_shift - HG_LEAF_SHIFT;
}

/* Smallest order whose block is at least @bytes. Returns -1 if @bytes exceeds
 * a whole page, which the caller must route to the large tier instead. */
static inline int hg_buddy_order_for(const struct hg_block *hb,
                                     unsigned long bytes)
{
	unsigned int o = 0;

	while ((HG_LEAF_SIZE << o) < bytes) {
		if (o >= hg_buddy_top_order(hb))
			return -1;
		o++;
	}
	return (int)o;
}

#endif /* HG_BUDDY_H */
