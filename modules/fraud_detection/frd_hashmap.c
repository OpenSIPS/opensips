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

#include "frd_hashmap.h"

#include "../../hash_func.h"
#include "../../str.h"
#include "../../locking.h"

int init_hash_map(hash_map_t *hm)
{
	unsigned int i;

	hm->buckets = shm_malloc(hm->size * sizeof(hash_bucket_t));
	if (hm->buckets == NULL) {
		LM_ERR("No more shm memory\n");
		return -1;
	}

	for (i = 0; i < hm->size; ++i) {
		hm->buckets[i].items = map_create(AVLMAP_SHARED);
		if (!hm->buckets[i].items) {
			LM_ERR("oom\n");
			return -1;
		}

		hm->buckets[i].lock = lock_alloc();
		if (!hm->buckets[i].lock) {
			LM_ERR("cannot init lock\n");
			shm_free(hm->buckets);
			return -1;
		}

		if (!lock_init(hm->buckets[i].lock)) {
			lock_dealloc(hm->buckets[i].lock);
			shm_free(hm->buckets);
			LM_ERR("faled to init lock\n");
			return -1;
		}
	}

	return 0;
}

void free_hash_map(hash_map_t* hm, void (*value_destroy_func)(void *))
{
	unsigned int i;

	/* no need for locking; if there were, any readers would die afterwards */
	for (i = 0; i < hm->size; ++i) {
		map_destroy(hm->buckets[i].items, value_destroy_func);
		lock_dealloc(hm->buckets[i].lock);
	}

	shm_free(hm->buckets);
}
