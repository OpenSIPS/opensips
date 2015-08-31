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

#ifndef _NH_TABLE_H
#define _NH_TABLE_H

#include <stdio.h>
#include <stdlib.h>

#include "../../parser/msg_parser.h"
#include "../../locking.h"
#include "../usrloc/udomain.h"


/* size of hash table */
#define NH_TABLE_ENTRIES	(1<<16)

/* current time */
#define now (time(NULL))

struct ping_cell {
	int hash_id;

	udomain_t* d;

	uint64_t contact_id;

	unsigned int timestamp; /* !< timestamp when ping was sent */
	char not_responded; /* !< number of pings not responded to */

	/* hash table links */
	struct ping_cell* next;
	struct ping_cell* prev;

	/* timer list link */
	struct ping_cell* tnext;
};

struct nh_entry
{
	struct ping_cell* first;
	struct ping_cell* last;

	unsigned int next_via_label; /* !< label to make the via unique */

	gen_lock_t mutex;

};

/* timer list */
typedef struct nh_tlist
{
	struct ping_cell *first;
	struct ping_cell *last;

	gen_lock_t mutex;
} nh_tlist;


struct nh_table
{
	/* the queue and its mutex */
	nh_tlist   timer_list;

	/* the hash table */
	struct nh_entry entries[NH_TABLE_ENTRIES];
};


void lock_hash(int i);
void unlock_hash(int i);

struct nh_table* init_hash_table(void);
struct nh_table* get_htable(void);
void free_hash_table();
struct ping_cell *build_p_cell(int hash_id, udomain_t* d, uint64_t contact_id);
void insert_into_hash( struct ping_cell* p_cell);
struct ping_cell *get_cell(int hash_id, uint64_t contact_id);
void remove_given_cell(struct ping_cell *cell, struct nh_entry *entry);


#endif
