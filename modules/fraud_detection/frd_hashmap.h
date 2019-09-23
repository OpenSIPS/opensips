/**
 * Fraud Detection Module
 *
 * Copyright (C) 2014 OpenSIPS Foundation
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
 * History
 * -------
 *  2014-09-26  initial version (Andrei Datcu)
*/

#ifndef __FRD_HASHMAP_H__
#define __FRD_HASHMAP_H__

#include "../../map.h"
#include "../../rw_locking.h"

typedef struct {
	map_t items;
	gen_lock_t   *lock;
} hash_bucket_t;

typedef struct {
	hash_bucket_t *buckets;
	size_t size;
} hash_map_t;



int init_hash_map(hash_map_t* hm);
static inline void **get_item(hash_map_t *hm, str key, unsigned int hash)
{
	return map_get(hm->buckets[hash].items, key);
}

void free_hash_map(hash_map_t* hm, void (*value_destroy_func)(void *));

#endif
