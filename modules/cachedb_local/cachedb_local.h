/*
 * memory cache system module
 *
 * Copyright (C) 2009 Anca Vamanu
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * --------
 *  2009-01-30  initial version (Anca Vamanu)
 */

#ifndef _MEMCACHE_
#define _MEMCACHE_

#include "../../cachedb/cachedb.h"
#include "../../cachedb/cachedb_cap.h"
#include "hash.h"

#define HASH_SIZE_DEFAULT 9 /* power of two */
#define DEFAULT_COLLECTION_NAME "default"

extern int cache_htable_size;
extern int local_exec_threshold;

typedef struct {
	struct cachedb_id *id;
	unsigned int ref;
	struct cachedb_pool_con_t *next;

	/* local cache hash structure */
	struct lcache_col* col;
} lcache_con;

typedef struct lcache_col {
	str col_name;

	lcache_t* col_htable;
	int size;

	/* we need to know somehow if this collection is used or not;
	 * if not used we'll need to throw an error */
	int is_used;

	struct lcache_col* next;
} lcache_col_t;

typedef struct url_lst {
	str url;
	struct url_lst* next;
} url_lst_t;

int _lcache_htable_insert(lcache_col_t *cache_col, str* attr, str* value,
	int expires, int isrepl);
int _lcache_htable_remove(lcache_col_t *cache_col ,str* attr, int isrepl);

extern lcache_col_t* lcache_collection;
extern url_lst_t* url_list;

#endif
