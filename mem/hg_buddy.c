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
#include "hg_buddy_int.h"

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

/* Free the leaves [from, to) of the page the header and metadata share:
 * skipping that page would waste up to a huge page, 25% of an 8 MB arena */
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
		pg->tier = (unsigned char)hb->tier;
		/* pages < npages are published below, the rest by a grow */
	}

	/* everything below hoff (header, then metadata) is spoken for; rounded
	 * up, so a bump allocator change cannot hand out a partly used leaf */
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
			page_publish_whole(hb, pg);
			continue;
		}
		/* the single straddling page */
		page_release_range(hb, pg, consumed_leaves - first, lpp);
	}

	hb->buddy_merges_init = hb->buddy_merges;
	hb->buddy_merges = 0;
	hb->buddy_splits = 0;

	hb->buddy_ready = 1;
	hb->reserve_floor = (hb->npages * hg_leaves_per_page(hb)) / 16;
	LM_DBG("%s buddy: %lu pages, orders 0..%u (%lu B..%lu B), %lu B metadata "
		"(%lu B/page, %.3f%%), %lu of %lu leaves free after reserving %lu\n",
		hb->name, hb->npages, top, HG_LEAF_SIZE, HG_LEAF_SIZE << top,
		meta, meta / hb->npages,
		100.0 * (double)meta / (double)hb->committed_bytes,
		hb->buddy_free_leaves, hb->npages * lpp, consumed_leaves);
	return 0;
}

/* top-order free pages per the wfree bitmap, to check against nfree[top] */
unsigned long hg_buddy_top_reachable(struct hg_block *hb)
{
	return wf_count(hb);
}

/* corruption path only (a list head on a punched page): a full walk */
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

void *hg_buddy_alloc(struct hg_block *hb, unsigned int order)
{
	unsigned int o, top = hb->buddy_top;
	struct hg_page *pg;
	unsigned long leaf;
	char *blk;

	if (!hb->buddy_ready || order > top)
		return NULL;

	/* the smallest free block that fits, so large ones are preserved */
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
		/* the list head is on a punched page, which must not be
		 * touched (SIGBUS on hugetlb): rebuild from the bitmaps */
		LM_CRIT("%s: free list order %u heads at punched page %u - the "
			"list and the page descriptor disagree; rebuilding the list "
			"from the bitmaps\n", hb->name, o, pg->idx);
		hg_corrupt(hb, HG_C_INTERNAL);
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

	/* split down, freeing each upper half: blk, the lower, never moves */
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
	hg_reserve_floor_check(hb);
	return blk;
}

void hg_buddy_free(struct hg_block *hb, void *p, unsigned int order)
{
	unsigned int o = order, top = hb->buddy_top;
	struct hg_page *pg;
	unsigned long leaf;
	char *blk = p;

	if (!hg_in_pages(hb, p)) {
		LM_CRIT("%s: buddy free of %p, which is outside the page grid - "
			"ignoring\n", hb->name, p);
		hg_corrupt(hb, HG_C_BUDDY_BAD_FREE);
		return;
	}
	/* before any shift by it */
	if (order > top) {
		LM_CRIT("%s: buddy free of %p at order %u, above the page's %u - "
			"ignoring\n", hb->name, p, order, top);
		hg_corrupt(hb, HG_C_BUDDY_BAD_FREE);
		return;
	}
	pg = page_of(hb, p);
	leaf = hg_leaf_of(hb, p);

	if (((unsigned long)p & ((HG_LEAF_SIZE << order) - 1)) !=
	    ((unsigned long)pg->base & ((HG_LEAF_SIZE << order) - 1))) {
		LM_CRIT("%s: buddy free of %p at order %u, which is not aligned to "
			"its own size - ignoring\n", hb->name, p, order);
		hg_corrupt(hb, HG_C_BUDDY_BAD_FREE);
		return;
	}
	if (leaf & ((1UL << order) - 1)) {
		LM_CRIT("%s: buddy free of %p as order %u, but leaf %lu does not "
			"start a block of that order - ignoring\n",
			hb->name, p, order, leaf);
		hg_corrupt(hb, HG_C_BUDDY_BAD_FREE);
		return;
	}
	if (pg->leaforder[leaf] != order) {
		LM_CRIT("%s: buddy free of %p as order %u, but leaf %lu records "
			"order %u - ignoring\n", hb->name, p, order, leaf,
			pg->leaforder[leaf]);
		hg_corrupt(hb, HG_C_BUDDY_BAD_FREE);
		return;
	}
	/* double free: leaforder passes it (an unmerged free block still
	 * records its order); the bitmap knows "already free and entire" */
	if (bit_test(pg->bitmap, node_id(top, order, leaf))) {
		LM_CRIT("%s: double buddy free of %p at order %u - ignoring\n",
			hb->name, p, order);
		hg_corrupt(hb, HG_C_DOUBLE_FREE);
		return;
	}

	pg->free_leaves += 1U << order;
	hb->buddy_free_leaves += 1UL << order;

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

void *hg_buddy_alloc_run(struct hg_block *hb, unsigned long npages)
{
	unsigned int top = hb->buddy_top;
	unsigned long i, start, run = 0;

	/* run_len is an unsigned int with HG_RUN_MEMBER reserved */
	if (!hb->buddy_ready || npages == 0 || npages >= HG_RUN_MEMBER ||
	    npages > hb->npages)
		return NULL;
	if (npages == 1)
		return hg_buddy_alloc(hb, top);

	for (i = 0, start = 0; i < hb->npages; i++) {
		/* a punched page is whole-free by its bitmap but unbacked and
		 * off the list: a run must not take it */
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
		LM_CRIT("%s: run free of %p, which heads no run - ignoring\n",
			hb->name, p);
		hg_corrupt(hb, HG_C_BUDDY_BAD_FREE);
		return;
	}
	start = hg_page_of(hb, p);
	if (n > hb->npages - start) {
		LM_CRIT("%s: run free of %p, whose recorded %lu pages run past the "
			"%lu-page grid - ignoring\n", hb->name, p, n, hb->npages);
		hg_corrupt(hb, HG_C_BUDDY_BAD_FREE);
		return;
	}
	for (i = start + 1; i < start + n; i++)
		if (hb->pages[i].run_len != HG_RUN_MEMBER) {
			LM_CRIT("%s: run free of %p, whose page %lu of %lu is not "
				"a member of it - ignoring\n", hb->name, p,
				i - start, n);
			hg_corrupt(hb, HG_C_BUDDY_BAD_FREE);
			return;
		}
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
	if (pg->leaforder[leaf] == HG_LEAF_NONE ||
	    pg->leaforder[leaf] > hb->buddy_top)
		return -1;
	return pg->leaforder[leaf];
}

int hg_backed_slow(const struct hg_block *hb, const void *p)
{
	const struct hg_page *pg;

	if ((unsigned long)((const char *)p - hb->hbase) >=
	    __atomic_load_n(&hb->span_end, __ATOMIC_RELAXED))
		return 0;
	if (!hb->buddy_ready || !hg_in_pages(hb, p))
		return 1;
	pg = &hb->pages[hg_page_of(hb, p)];
	return !pg->punched && !pg->releasing;
}

#endif /* HG_MALLOC */
