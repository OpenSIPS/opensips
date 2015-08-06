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
		n_table->entries[i].next_label = rand();
		n_table->entries[i].first = n_table->entries[i].last = 0;
	}


	return n_table;

error:
	return 0;
}

void free_hash_table(void)
{
	int i;

	for (i=0; i < NH_TABLE_ENTRIES; i++)
		lock_destroy(&n_table->entries[i].mutext);

	shm_free(n_table);
}

struct nh_table* get_htable(void)
{
	return n_table;
}

struct ping_cell *build_p_cell(udomain_t* d, uint64_t contact_id)
{
	struct ping_cell *cell;

	cell = shm_malloc(sizeof(struct ping_cell));
	if (0 == cell) {
		LM_ERR("no more memory\n");
		return 0;
	}

	cell->timestamp = now;
	cell->d         = d;
	cell->contact_id = contact_id;

	cell->next      = 0;

	return cell;
}

void insert_into_hash( struct ping_cell* p_cell, unsigned int hash_idx)
{
	struct nh_entry* entry;

	lock_hash(hash_idx);

	entry = &n_table->entries[hash_idx];
	p_cell->label = n_table->entries[hash_idx].next_label++;

	if (!entry->first)
		entry->first = entry->last = p_cell;
	else {
		entry->last->next = p_cell;
		entry->last = p_cell;
	}

	unlock_hash(hash_idx);
}


/*
 * this function remove the cell with the given index and
 * label and also all the cells that has timestamps previous
 * to this one
 */
void remove_older_cells(unsigned int hash_idx, int label)
{
	struct nh_entry *entry;
	struct ping_cell* cell=NULL;
	struct ping_cell* prev=NULL;

	unsigned int max_ts;
	uint64_t cid;

	lock_hash(hash_idx);

	entry = &n_table->entries[hash_idx];
	cell = entry->first;

	for (cell=entry->first; cell; cell = cell->next) {
		if (cell->label == label)
			break;
	}

	if (cell == 0) {
		LM_DBG("cannot find cell for this ping; most probably ping came"
				"later than another one for this contact\n");
		return;
	}

	/* cell may be removed during the process so we save its timestamp
	 * and contact id */
	cid = cell->contact_id;
	max_ts = cell->timestamp;

	cell = entry->first;
	prev = NULL;

	/* remove all pings previous to this one; we just want to know
	 * if the contact is alive */
	while (cell) {
		if (cell->contact_id == cid && cell->timestamp <= max_ts) {
			remove_given_cell(hash_idx, cell, prev, entry);
			if (prev)
				cell = prev->next;
			else
				cell = entry->first;
		} else {
			cell = cell->next;
			prev = cell;
		}
	}

	unlock_hash(hash_idx);
}

/*
 * needs to be called under lock
 * only removes cell from hash
 * also frees the cell
 */
void remove_given_cell(int hash_idx, struct ping_cell *cell,
		struct ping_cell *prev, struct nh_entry *entry)
{
	if (cell == entry->first && cell == entry->last) {
		entry->first = entry->last = 0;
	} else if (cell == entry->first) {
		entry->first = cell->next;
	} else if (cell == entry->last) {
		entry->last = prev;
	} else {
		prev->next = cell->next;
	}

	shm_free(cell);
}


