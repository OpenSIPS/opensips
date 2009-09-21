/*
 * $Id: records.c $
 *
 * back-to-back logic module
 *
 * Copyright (C) 2009 Free Software Fundation
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
 * History:
 * --------
 *  2009-08-03  initial version (Anca Vamanu)
 */

#ifndef _B2BL_RECORDS_H
#define _B2BL_RECORDS_H

#include <libxml/parser.h>
#include <stdlib.h>
#include "../../str.h"
#include "../../lock_ops.h"
#include "b2b_logic.h"

typedef struct b2bl_entity_id
{
	str scenario_id;
	str key;
	str to_uri;
	str from_uri;
	enum b2b_entity_type type;
	struct b2bl_entity_id* next;
	struct b2bl_entity_id* peer;
}b2bl_entity_id_t;

typedef struct b2bl_tuple
{
	unsigned int id;
	str* key;
	b2b_scenario_t* scenario;  /* if scenario is NULL it means that the simple Topology Hiding Scenary must be applied*/
	str scenario_params[5];
	int scenario_state;
	int next_scenario_state;
	b2bl_entity_id_t* server;
	b2bl_entity_id_t* clients;
	b2bl_entity_id_t* bridge_entities[2];
	int to_del;
	struct b2bl_tuple* next;
	struct b2bl_tuple* prev;
	unsigned int lifetime;
}b2bl_tuple_t;

typedef struct b2bl_entry
{
	b2bl_tuple_t* first;
	gen_lock_t lock;
}b2bl_entry_t;

typedef b2bl_entry_t* b2bl_table_t;

b2bl_tuple_t* b2bl_insert_new(unsigned int hash_index, b2b_scenario_t* scenario,
		str* args[], str** b2bl_key_s);

str* b2bl_generate_key(unsigned int hash_index, unsigned int local_index);

int b2bl_parse_key(str* key, unsigned int* hash_index,
		unsigned int* local_index);

b2bl_tuple_t* b2bl_search_tuple_safe(unsigned int hash_index,
		unsigned int local_index);

void b2bl_delete(b2bl_tuple_t* tuple, unsigned int hash_index);

int init_b2bl_htable(void);

extern b2bl_table_t b2bl_htable;
extern unsigned int b2bl_hsize;

int process_bridge_action(b2bl_tuple_t* tuple, xmlNodePtr bridge_node);

void destroy_b2bl_htable(void);

#endif
