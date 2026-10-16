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

#ifndef _CACHEDB_PERF_H_
#define _CACHEDB_PERF_H_

#include "../../cachedb/cachedb.h"
#include "../../cachedb/cachedb_cap.h"

/* log2 of a collection's initial bucket count, clamped to [MIN, MAX];
 * tables grow at runtime */
#define PCACHE_SIZE_MIN      4
#define PCACHE_SIZE_MAX     24
#define PCACHE_SIZE_DEFAULT 14

#define PCACHE_DEFAULT_COLLECTION "default"

struct pcache_htable;

typedef struct pcache_col {
	str col_name;
	unsigned int size_log2;
	struct pcache_htable *htable;
	int raise_expired;              /* raise E_CACHEDB_PERF_EXPIRED */
	int persist;                    /* load on start, save on stop */
	int replicate;                  /* may be pulled by other nodes */
	/* last sync times (ticks) for perf_stats; not a consistency signal */
	unsigned int last_sync_out;
	unsigned int last_sync_in;
	int last_sync_src;
	/* per-collection pull counters, updated with __sync_fetch_and_add */
	unsigned long pulled_in;
	unsigned long served_out;
	struct pcache_col *next;
} pcache_col_t;

/* the first 3 fields must mirror cachedb_pool_con (cachedb/cachedb_pool.h) */
typedef struct {
	struct cachedb_id *id;
	unsigned int ref;
	struct cachedb_pool_con_t *next;

	pcache_col_t *col;
} pcache_con;

typedef struct pcache_url {
	str url;
	struct pcache_url *next;
} pcache_url_t;

extern pcache_col_t *pcache_collection;

#endif /* _CACHEDB_PERF_H_ */
