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

/* internal to hg_malloc.c, hg_backing.c and hg_capacity.c: the
 * page-size helpers and the backing and capacity calls they share; include
 * after their headers */

unsigned long hg_hps(void);

long hg_meminfo_kb(const char *key);

unsigned long hg_memlock_limit(void);

const char *hg_4k_reason(int shared);

void *hg_mem_reserve(unsigned long size, unsigned long *cap,
		enum hg_mem_tier *tier, unsigned long *locked_b, int shared,
		int inherited, unsigned long apage);

int hg_init_fits(const char *what, unsigned long init,
		unsigned long cap, int inherited);


#define HG_HPS (hg_hps())

/*
 * Small-arena mode: an arena whose whole reservation is under one huge page
 * gets nothing from hugetlb or THP, so its grid runs on 256 KB pages (all
 * geometry reads hb->hps).
 * A buddy block never spans pages, and 256 KB fits the largest class's
 * ~131 KB chunk floor (chunk_size_for()) and the ~140 KB large object core
 * startup takes. Minimum: two pages (512 KB; the hg_block header takes
 * ~31 KB of page 0) for a fixed arena, one for an elastic one; in huge-page
 * mode, one huge page.
 */
#define HG_SMALL_PAGE_SHIFT 18
#define HG_SMALL_PAGE (1UL << HG_SMALL_PAGE_SHIFT)

/* the page unit an arena with this init/cap runs on, judged by size;
 * an INIT under one huge page with a larger cap is settled by the backing
 * tier in hg_malloc_init_cap() */
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

/* the smallest arena that can function in this page unit */
static inline unsigned long hg_min_viable(unsigned long apage)
{
	return apage < HG_HPS ? 2 * apage : apage;
}

/* "512 KB" vs "48 MB" in one printable pair, for the error messages */
#define HG_SZ_VAL(b)  ((b) < (1UL << 20) ? (b) >> 10 : (b) >> 20)
#define HG_SZ_UNIT(b) ((b) < (1UL << 20) ? "KB" : "MB")

#endif /* HG_BACKING_H */
