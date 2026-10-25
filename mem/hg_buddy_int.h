/*
 * buddy allocator over the HG_MALLOC page grid - shared helpers
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

#ifndef HG_BUDDY_INT_H
#define HG_BUDDY_INT_H

/* internal to hg_buddy.c, hg_grow.c and hg_shrink.c: the bitmap, free-list
 * and page helpers they share; include after their headers */


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
		LM_CRIT("%s: page %lu published as whole-free twice\n", hb->name, idx);
		hg_corrupt(hb, HG_C_INTERNAL);
		return;
	}
	hb->wfree[idx / HG_WF_BITS] |= 1UL << (idx % HG_WF_BITS);
	hb->nfree[hb->buddy_top]++;
}

static inline void wf_clear(struct hg_block *hb, unsigned long idx)
{
	if (!wf_test(hb, idx)) {
		LM_CRIT("%s: page %lu taken off offer but was not on it\n", hb->name, idx);
		hg_corrupt(hb, HG_C_INTERNAL);
		return;
	}
	hb->wfree[idx / HG_WF_BITS] &= ~(1UL << (idx % HG_WF_BITS));
	hb->nfree[hb->buddy_top]--;
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
static inline void page_publish_whole(struct hg_block *hb, struct hg_page *pg)
{
	unsigned int top = hb->buddy_top;

	memset(pg->leaforder, (int)top, (size_t)hg_leaves_per_page(hb));
	bit_set(pg->bitmap, node_id(top, top, 0));
	fl_push(hb, pg->base, top);
	pg->free_leaves = (unsigned int)hg_leaves_per_page(hb);
	hb->buddy_free_leaves += pg->free_leaves;
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
static inline void span_check(struct hg_block *hb, const char *after)
{
	unsigned long holes = hb->punched_pages << hb->hps_shift;

	if (hb->committed_bytes + holes == hb->span_end)
		return;
	LM_CRIT("%s: after %s committed_bytes %lu + %lu punched != span_end "
		"%lu\n", hb->name, after, hb->committed_bytes, holes,
		hb->span_end);
	hg_corrupt(hb, HG_C_INTERNAL);
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

/* --- multi-page runs -------------------------------------------------- */

/* is this whole page free and unsplit, i.e. available to a run? */
static inline int page_is_whole_free(const struct hg_block *hb,
                                     const struct hg_page *pg)
{
	unsigned int top = hb->buddy_top;

	return pg->run_len == 0 && bit_test(pg->bitmap, node_id(top, top, 0)) &&
	       pg->leaforder[0] == top;
}

#endif /* HG_BUDDY_INT_H */
