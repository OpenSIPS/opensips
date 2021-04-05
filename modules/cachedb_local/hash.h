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
 *  2009-01-29  initial version (Anca Vamanu)
 */


#ifndef _MEMCACHE_HASH_
#define _MEMCACHE_HASH_

#include "../../str.h"
#include "../../lock_ops.h"
#include "../../cachedb/cachedb.h"

typedef struct lcache_entry
{
	str attr;
	str value;
	unsigned int expires;
	unsigned int ttl;
	int synced;
	struct lcache_entry* next;
}lcache_entry_t;


typedef struct lcache
{
	lcache_entry_t* entries;
	gen_lock_t lock;
}lcache_t;

typedef struct lcache_htable {
	lcache_t *htable;
	int size;
} lcache_htable_t;

struct lcache_col;

int lcache_htable_init(struct lcache_col *col);
void lcache_htable_destroy(lcache_htable_t *htable, osips_free_f free_f);
int lcache_htable_insert(cachedb_con *con,str* attr, str* value, int expires);
int lcache_htable_remove(cachedb_con *con,str* attr);
int lcache_htable_fetch(cachedb_con *con,str* attr, str* val);
int lcache_htable_add(cachedb_con *con,str *attr,int val,int expires,int *new_val);
int lcache_htable_sub(cachedb_con *con,str *attr,int val,int expires,int *new_val);
int lcache_htable_fetch_counter(cachedb_con* con,str* attr,int *val);
int lcache_htable_iter_keys(cachedb_con *con, int (*kv_func)(const str *, const str *));

#endif
