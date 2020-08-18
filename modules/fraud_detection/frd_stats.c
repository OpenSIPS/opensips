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

#include <string.h>
#include "frd_stats.h"
#include "frd_hashmap.h"
#include "../../ut.h"


/* Struct used for the first level of the hashmap
 * the user is kept in shm for two reasons :
 *     a) to keep using core's map
 *     b) to pass it for the dialog_end callback
*/

typedef struct {

	hash_map_t numbers_hm;
	str user;
} frd_users_map_item_t;

static hash_map_t stats_table;
static void destroy_stats_entry(void *e);

/*
 * Function to init the stats hash table
*/

int init_stats_table(void)
{
	stats_table.size = FRD_USER_HASH_SIZE;
	return init_hash_map(&stats_table);
}


frd_stats_entry_t* get_stats(str user, str prefix, str *shm_user)
{
	unsigned int hash = core_hash(&user, NULL, FRD_USER_HASH_SIZE);

	lock_get(stats_table.buckets[hash].lock);

	/* First go one level below using the user key */
	frd_users_map_item_t **hm =
		(frd_users_map_item_t **)get_item(&stats_table, user, hash);

	if (*hm == NULL) {
		/* First time the user is seen, we must create a hashmap */
		*hm = shm_malloc(sizeof(frd_users_map_item_t));
		if (*hm == NULL) {
			lock_release(stats_table.buckets[hash].lock);
			LM_ERR("no more shm memory\n");
			return NULL;
		}

		(*hm)->numbers_hm.size = FRD_PREFIX_HASH_SIZE;
		if (init_hash_map(&(*hm)->numbers_hm) != 0) {
			shm_free(*hm); *hm = NULL;
			lock_release(stats_table.buckets[hash].lock);
			LM_ERR("cannot init hashmap\n");
			return NULL;
		}

		if (shm_str_dup(&(*hm)->user, &user) != 0) {
			free_hash_map(&(*hm)->numbers_hm, destroy_stats_entry);
			shm_free(*hm); *hm = NULL;
			lock_release(stats_table.buckets[hash].lock);
			LM_ERR("oom\n");
			return NULL;
		}
	}

	lock_release(stats_table.buckets[hash].lock);

	if (shm_user)
		*shm_user = (*hm)->user;

	hash = core_hash(&prefix, NULL, FRD_PREFIX_HASH_SIZE);
	lock_get((*hm)->numbers_hm.buckets[hash].lock);

	frd_stats_entry_t **stats_entry =
		(frd_stats_entry_t**)get_item(&(*hm)->numbers_hm, prefix, hash);
	if (*stats_entry == NULL) {
		/* First time the prefix is seen for this user */
		*stats_entry = shm_malloc(sizeof(frd_stats_entry_t));
		if (*stats_entry == NULL) {
			lock_release((*hm)->numbers_hm.buckets[hash].lock);
			LM_ERR("no more shm memory\n");
			return NULL;
		}

		/* Now init the auxiliary info for a stats structure */
		if (!lock_init(&(*stats_entry)->lock)) {
			shm_free(*stats_entry); *stats_entry = NULL;
			lock_release((*hm)->numbers_hm.buckets[hash].lock);
			LM_ERR ("cannot init lock\n");
			return NULL;
		}

		(*stats_entry)->interval_id = 0;
		memset(&(*stats_entry)->stats, 0, sizeof(frd_stats_t));
	}

	lock_release((*hm)->numbers_hm.buckets[hash].lock);

	return *stats_entry;
}


int stats_exist(str user, str prefix)
{
	unsigned int hash = core_hash(&user, NULL, FRD_USER_HASH_SIZE);

	lock_get(stats_table.buckets[hash].lock);

	/* First go one level below using the user key */
	frd_users_map_item_t **hm =
		(frd_users_map_item_t **)get_item(&stats_table, user, hash);

	if (*hm == NULL) {
		lock_release(stats_table.buckets[hash].lock);
		return 0;
	}

	lock_release(stats_table.buckets[hash].lock);

	hash = core_hash(&prefix, NULL, FRD_PREFIX_HASH_SIZE);
	lock_get((*hm)->numbers_hm.buckets[hash].lock);

	frd_stats_entry_t **stats_entry =
		(frd_stats_entry_t**)get_item(&(*hm)->numbers_hm, prefix, hash);
	if (*stats_entry == NULL) {
		lock_release((*hm)->numbers_hm.buckets[hash].lock);
		return 0;
	}

	lock_release((*hm)->numbers_hm.buckets[hash].lock);
	return 1;
}

/*
 * Functions for freeing the stats hash table
*/

static void destroy_stats_entry(void *e)
{
	frd_stats_entry_t *se = (frd_stats_entry_t *)e;

	lock_destroy(&se->lock);
	shm_free(se->stats.last_dial.s);
	shm_free(se);
}

static void destroy_users(void *u)
{
	frd_users_map_item_t *hm = (frd_users_map_item_t*)u;
	free_hash_map(&hm->numbers_hm, destroy_stats_entry);
	shm_free(hm->user.s);
	shm_free(u);
}

void free_stats_table(void)
{
	free_hash_map(&stats_table, destroy_users);
}
