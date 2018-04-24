/**
 *
 * Copyright (C) 2015 OpenSIPS Foundation
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History
 * -------
 *  2015-02-18  initial version (Ionut Ionita)
*/
#include "nh_table.h"
#include "nh_locks.h"
#include "../usrloc/usrloc.h"

static struct nh_table* n_table=0;

extern int ping_checker_interval;
extern int ping_threshold;
extern usrloc_api_t ul;

void lock_hash(int i)
{
	lock(&n_table->entries[i].mutex);
}

void unlock_hash(int i)
{
	unlock(&n_table->entries[i].mutex);
}


struct nh_table* init_hash_table(void)
{
	int i;

	n_table = shm_malloc(sizeof(struct nh_table));
	if (n_table==NULL) {
		LM_ERR("no more shared memory\n");
		goto error;
	}

	memset(n_table, 0, sizeof(struct nh_table));
	for ( i=0; i < NH_TABLE_ENTRIES; i++)
	{
		lock_init(&n_table->entries[i].mutex);
		n_table->entries[i].next_via_label = rand();
		n_table->entries[i].first = n_table->entries[i].last = 0;
	}

	lock_init(&n_table->timer_list.mutex);
	INIT_LIST_HEAD(&n_table->timer_list.wt_timer);
	INIT_LIST_HEAD(&n_table->timer_list.pg_timer);

	return n_table;

error:
	return 0;
}

void free_hash_table(void)
{
	struct ping_cell *cell,*next_cell;
	int i;

	for (i=0; i < NH_TABLE_ENTRIES; i++) {
		cell=n_table->entries[i].first;
		while(cell) {
			next_cell = cell->next;
			shm_free(cell);
			cell = next_cell;
		}
		lock_destroy(&n_table->entries[i].mutex);
	}

	lock_destroy(&n_table->timer_list.mutex);

	shm_free(n_table);
}

struct nh_table* get_htable(void)
{
	return n_table;
}

struct ping_cell *build_p_cell(int hash_id, udomain_t* d,
                               ucontact_coords ct_coords)
{
	struct ping_cell *cell;

	cell = shm_malloc(sizeof(struct ping_cell));
	if (0 == cell) {
		LM_ERR("no more memory\n");
		return 0;
	}

	memset(cell, 0, sizeof(struct ping_cell));

	cell->hash_id   = hash_id;
	cell->timestamp = now;
	cell->d         = d;
	cell->ct_coords = ct_coords;

	return cell;
}

void insert_into_hash( struct ping_cell* p_cell)
{
	struct nh_entry* entry;
	struct ping_cell* cell;

	entry = &n_table->entries[p_cell->hash_id];
	cell = entry->first;

	if (!cell) {
		entry->first = entry->last = p_cell;
		return;
	}

	p_cell->next = cell;
	cell->prev = p_cell;

	entry->first = p_cell;
}

struct ping_cell *get_cell(int hash_id, ucontact_coords coords)
{
	struct nh_entry *entry;
	struct ping_cell *cell;

	entry = &n_table->entries[hash_id];
	cell = entry->first;

	for (cell=entry->first; cell; cell = cell->next) {
		if (!ul.ucontact_coords_cmp(cell->ct_coords, coords))
			return cell;
	}

	return NULL;
}

/* must be called under lock */
void remove_from_hash(struct ping_cell *cell)
{
	struct nh_entry *entry;

	entry = &n_table->entries[cell->hash_id];

	if (cell == entry->first && cell == entry->last) {
		entry->first = entry->last = 0;
	} else if (cell == entry->first) {
		entry->first = cell->next;
		cell->next->prev = 0;
	} else if (cell == entry->last) {
		entry->last = cell->prev;
		cell->prev->next = 0;
	} else {
		cell->prev->next = cell->next;
		cell->next->prev = cell->prev;
	}
}
