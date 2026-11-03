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

/* One buddy tree per huge page, no cross-page merging, and nothing live
 * moves. All of it runs under hb->lock; the cell fast path never calls it. */

#ifndef HG_BUDDY_H
#define HG_BUDDY_H

#include "hg_malloc.h"

/* A free block keeps its list links in its own first bytes, with no magic:
 * a double free is caught by the bitmap, out of reach of freed memory. */
struct hg_free_blk {
	struct hg_free_blk *next;
	struct hg_free_blk *prev;
};

/* deferred-collapse attempts per page before it is left on 4 KB pages */
#define HG_COLLAPSE_TRIES 16

/* Per-page descriptor, in the metadata region at the front of the arena, NOT
 * in the page it describes, so that the page can become wholly free. */
struct hg_page {
	char          *base;
	unsigned char *leaforder;  /* per leaf: order of the block holding it */
	unsigned long *bitmap;     /* per node: 1 = free, whole, not split */

	/* unused, reserved for page fullness lists */
	struct hg_page *next;
	struct hg_page *prev;

	unsigned int idx;
	unsigned int free_leaves;
	/* pages in the run this page heads; HG_RUN_MEMBER on its other pages */
	unsigned int run_len;
	/* the byte fields below fit existing padding: the descriptor stays
	 * 56 bytes on 64-bit builds */
	/* backing tier (enum hg_mem_tier) of the commit that brought this
	 * page in: shrink takes from any delta, so it debits tier_bytes */
	unsigned char tier;
	/* MADV_REMOVEd while whole-free, tree kept: a carve re-commits it and
	 * the CARVING process re-pins it, as mlock is not inherited */
	unsigned char punched;
	/* set while a trim or punch has the arena lock dropped mid-release:
	 * every scan that reads the bitmap rather than the list must skip it */
	unsigned char releasing;
	/* collapse attempts left for a page a worker's grow published on 4 KB
	 * pages (0 = none); worked off by hg_collapse_deferred */
	unsigned char want_collapse;
};

#define HG_RUN_MEMBER  0xffffffffu
/* no per-page per-order free counts: they would double the descriptor */

/* leaforder[] of a leaf in no buddy block: a page past npages, or a run */
#define HG_LEAF_NONE  0xff

/* Carve the per-page metadata from the arena front, publish the rest as
 * free. Once, from hg_arena_init() after pages_init(). */
int hg_buddy_init(struct hg_block *hb);

/* one block of HG_LEAF_SIZE << @order bytes, naturally aligned, or NULL */
void *hg_buddy_alloc(struct hg_block *hb, unsigned int order);

/* *_unlocks, hg_grow_headroom_tick(), hg_grow_tick() and hg_drain_tick() DROP
 * hb->lock: held on entry and return, but nothing read before stays valid */
/* commit up to max(granule, @need) more and publish the new whole pages
 * as free; 0 = grew (retry the allocation), -1 = cannot */
int hg_buddy_grow_unlocks(struct hg_block *hb, unsigned long need, enum hg_grow_why why);
/* the always-on headroom rule alone (the maintenance process ticks it every
 * second); 1 = grew */
int hg_grow_headroom_tick(struct hg_block *hb);

/* end a grow-blocked episode (logged if one was latched) and re-arm its
 * report; @how ends "GROW-BLOCKED cleared - " */
void hg_grow_unblock(struct hg_block *hb, const char *how);

/* once per sweep interval: latch an armed grow-blocked episode whose
 * refusals rose (see grow_blocked_refuse0), disarm a quiet one */
void hg_grow_blocked_tick(struct hg_block *hb);

/* the down-slow shrink gate, once per sweep interval, never below
 * committed_min; a pkg arena only from its owner's flush path */
void hg_shrink_tick(struct hg_block *hb);
/* one drain step (trim, then punch) while the quiet window is open; every
 * maintenance tick */
void hg_drain_tick(struct hg_block *hb);

/* the profile's proactive grow gate, with hg_shrink_tick()'s cadence and call
 * sites; no-op without a policy */
void hg_grow_tick(struct hg_block *hb);

void hg_buddy_free(struct hg_block *hb, void *p, unsigned int order);

/* Order of the block containing @p, or -1 if @p is not in buddy space. */
int hg_buddy_order_of(const struct hg_block *hb, const void *p);

/* The block CONTAINING @p, from any address inside it, without a search;
 * NULL if @p is outside the page grid or in a multi-page run. */
static inline void *hg_buddy_block_of(const struct hg_block *hb, const void *p)
{
	const struct hg_page *pg;
	unsigned long leaf;
	unsigned char o;

	if (!hb->buddy_ready || !hg_in_pages(hb, p))
		return NULL;
	pg = &hb->pages[hg_page_of(hb, p)];
	/* a punched page keeps its leaf orders but not its memory: a block
	 * there is a stale pointer's, and its header must not be read */
	if (pg->punched || pg->releasing)
		return NULL;
	leaf = hg_leaf_of(hb, p);
	o = pg->leaforder[leaf];
	/* a damaged order is not shifted by */
	if (o == HG_LEAF_NONE || o > hb->buddy_top)
		return NULL;
	return pg->base + ((leaf & ~((1UL << o) - 1)) << HG_LEAF_SHIFT);
}

/* A run of @npages CONTIGUOUS whole pages, for a large-tier allocation
 * over a huge page; a linear scan */
void *hg_buddy_alloc_run(struct hg_block *hb, unsigned long npages);

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
