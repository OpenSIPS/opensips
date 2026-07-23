/*
 * cachedb_perf - high-performance local memory cache
 *
 * Copyright (C) 2026 Yury Kirsanov
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef _PCACHE_MEM_H_
#define _PCACHE_MEM_H_

/* the four-tier huge-page ladder (DESIGN 2.6.1 / CP-20), best first */
enum pcache_mem_tier {
	PCACHE_MEM_HUGETLB = 1,   /* mmap MAP_HUGETLB - best, 1.42x on chases */
	PCACHE_MEM_THP_ADVISE,    /* shmem THP via MADV_HUGEPAGE, huge at fault */
	PCACHE_MEM_THP_COLLAPSE,  /* shmem THP via MADV_COLLAPSE, post-fill */
	PCACHE_MEM_4K,            /* plain pages - always works */
};

struct pcache_mem_info {
	enum pcache_mem_tier tier;
	int huge_static;          /* vm.nr_hugepages at probe time, -1 unknown */
	int huge_overcommit;      /* vm.nr_overcommit_hugepages, -1 unknown */
};

extern struct pcache_mem_info pcache_mem;

/* probe the ladder by trying each route on a scratch mapping; pre-fork only */
void pcache_mem_probe(void);
const char *pcache_mem_tier_str(enum pcache_mem_tier tier);

#endif /* _PCACHE_MEM_H_ */
