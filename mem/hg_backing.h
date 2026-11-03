/*
 * slab allocator with elastic arenas - page-size and backing helpers
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

#ifndef HG_BACKING_H
#define HG_BACKING_H

/* internal to hg_malloc.c, hg_backing.c and hg_capacity.c: page-size,
 * backing and capacity helpers; include after their headers */

unsigned long hg_hps(void);

long hg_meminfo_kb(const char *key);
/* two fields in one pass of the file; each -1 if missing */
void hg_meminfo_kb2(const char *k1, long *v1, const char *k2, long *v2);

unsigned long hg_memlock_limit(void);

const char *hg_4k_reason(int shared);

void *hg_mem_reserve(unsigned long size, unsigned long *cap,
		enum hg_mem_tier *tier, unsigned long *locked_b, int shared,
		unsigned long apage);

/* @no_pool: a private arena, which never takes hugetlb pages */
int hg_init_fits(const char *what, unsigned long init,
		unsigned long cap, int no_pool);


#define HG_HPS (hg_hps())

/* small-arena mode: an arena under one huge page gains nothing from huge
 * pages, so it runs on 256 KB pages (fits the largest class's chunk floor) */
#define HG_SMALL_PAGE_SHIFT 18
#define HG_SMALL_PAGE (1UL << HG_SMALL_PAGE_SHIFT)

/* by size alone: hg_malloc_init_cap() may settle another (tier_decides) */
static inline unsigned long hg_arena_page(unsigned long init_b,
		unsigned long cap_b)
{
	unsigned long m = cap_b > init_b ? cap_b : init_b;

	return (m && m < HG_HPS) ? HG_SMALL_PAGE : HG_HPS;
}

static inline unsigned long hg_page_round(unsigned long v, unsigned long pg)
{
	return (v + pg - 1) & ~(pg - 1);
}

/* can @v be rounded up to a page of @pg bytes, or it wraps to a small one */
static inline int hg_page_roundable(unsigned long v, unsigned long pg)
{
	return v <= ~0UL - (pg - 1);
}

static inline unsigned long hg_min_viable(unsigned long apage)
{
	return apage < HG_HPS ? 2 * apage : apage;
}

#define HG_SZ_VAL(b)  ((b) < (1UL << 20) ? (b) >> 10 : (b) >> 20)
#define HG_SZ_UNIT(b) ((b) < (1UL << 20) ? "KB" : "MB")

#endif /* HG_BACKING_H */
