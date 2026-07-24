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

/* log2 of a collection's initial bucket count.  Growth (CP-09) resizes at
 * runtime, so this only sets the starting point.  Configured values are
 * clamped to [PCACHE_SIZE_MIN, PCACHE_SIZE_MAX]: an unbounded "1 << size"
 * is undefined behaviour at 32 and a zero-size table at 64. */
#define PCACHE_SIZE_MIN      4
#define PCACHE_SIZE_MAX     24
#define PCACHE_SIZE_DEFAULT 14

#define PCACHE_DEFAULT_COLLECTION "default"

struct pcache_htable;

typedef struct pcache_col {
	str col_name;
	unsigned int size_log2;         /* initial table size (log2 buckets) */
	struct pcache_htable *htable;
	int raise_expired;              /* CP-11: emit E_CACHEDB_PERF_EXPIRED */
	int persist;                    /* CP-19: load-on-start / save-on-stop */
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
