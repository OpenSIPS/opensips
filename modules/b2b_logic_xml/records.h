/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
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
#include "b2b_load.h"

typedef struct b2bl_entity_id
{
	str scenario_id;
	str key;
	str to_uri;
	str from_uri;
	str from_dname;
	str hdrs;
	b2b_dlginfo_t* dlginfo;
	int rejected;
	int disconnected;
	int state;
	unsigned short no;
	unsigned short sdp_type;
	enum b2b_entity_type type;
	b2bl_dlg_stat_t stats;
	struct b2bl_entity_id* peer;
	struct b2bl_entity_id* prev;
	struct b2bl_entity_id* next;
}b2bl_entity_id_t;

#define B2BL_SDP_NORMAL     0
#define B2BL_SDP_LATE       1
#define B2BL_SDP_RENEW      2

#define NO_UPDATEDB_FLAG    0
#define UPDATEDB_FLAG       1
#define INSERTDB_FLAG       2

#define MAX_B2BL_ENT		3
#define MAX_BRIDGE_ENT		3

struct b2b_ctx_val {
	unsigned int id;
	str name;
	str val;
	struct b2b_ctx_val *next;
};

typedef struct b2bl_tuple
{
	unsigned int id;
	unsigned int hash_index;
	str* key;
	b2b_scenario_t* scenario;  /* if scenario is NULL it means that the simple Topology Hiding Scenary must be applied*/
	str scenario_params[MAX_SCENARIO_PARAMS];
	int scenario_state;
	int next_scenario_state;
	b2bl_entity_id_t* servers[MAX_B2BL_ENT];
	b2bl_entity_id_t* clients[MAX_B2BL_ENT];
	b2bl_entity_id_t* bridge_entities[MAX_BRIDGE_ENT];
	int to_del;
	str* extra_headers;
	struct b2bl_tuple* next;
	struct b2bl_tuple* prev;
	unsigned int lifetime;
	str local_contact;
	str sdp;
	str b1_sdp; /* used for multiple attempts to bridge the first entity */
	int db_flag;
	int repl_flag;  /* sent/received through entities replication */
	struct b2b_ctx_val *vals;
	b2bl_cback_f cbf;
	unsigned int cb_mask;
	void* cb_param;
}b2bl_tuple_t;

typedef struct b2bl_entry
{
	b2bl_tuple_t* first;
	gen_lock_t lock;
	int locked_by;
	int flags;
}b2bl_entry_t;

typedef b2bl_entry_t* b2bl_table_t;


#define PREP_REQ_DATA(entity) do{		\
	req_data.et =(entity)->type;		\
	req_data.b2b_key =&(entity)->key;	\
	req_data.dlginfo =(entity)->dlginfo;	\
}while(0)

#define PREP_RPL_DATA(entity) do{		\
	rpl_data.et =(entity)->type;		\
	rpl_data.b2b_key =&(entity)->key;	\
	rpl_data.dlginfo =(entity)->dlginfo;	\
}while(0)

static inline int bridge_get_entityno(b2bl_tuple_t* tuple, b2bl_entity_id_t* entity)
{
	int i;

	/*check to which entity the reply belongs to */
	for(i = 0; i< 3; i++)
	{
		if(tuple->bridge_entities[i]== entity)
				return i;
	}
	return -1;
}

void b2bl_print_tuple(b2bl_tuple_t* tuple, int log_level);

b2bl_tuple_t* b2bl_insert_new(struct sip_msg* msg,
		unsigned int hash_index, b2b_scenario_t* scenario,
		str* args[], str* body, str* custom_hdrs, int local_index,
		str** b2bl_key_s, int db_flag, int repl_flag);

str* b2bl_generate_key(unsigned int hash_index, unsigned int local_index);

int b2bl_parse_key(str* key, unsigned int* hash_index,
		unsigned int* local_index);

b2bl_tuple_t* b2bl_search_tuple_safe(unsigned int hash_index,
		unsigned int local_index);

void b2bl_delete(b2bl_tuple_t* tuple, unsigned int hash_index,
		int db_del, int del_entities);

int init_b2bl_htable(void);

extern b2bl_table_t b2bl_htable;
extern unsigned int b2bl_hsize;

int process_bridge_action(struct sip_msg* msg, b2bl_entity_id_t* curr_entity,
		b2bl_tuple_t* tuple, unsigned int hash_index, xmlNodePtr bridge_node);

void destroy_b2bl_htable(void);

b2bl_entity_id_t* b2bl_create_new_entity(enum b2b_entity_type type, str* entity_id,
		str* to_uri,str* from_uri,str* from_dname,str* ssid,str* hdrs,struct sip_msg* msg);

void unchain_ent(b2bl_entity_id_t *ent, b2bl_entity_id_t **head);
void b2bl_remove_single_entity(b2bl_entity_id_t *entity, b2bl_entity_id_t **head,
	unsigned int hash_index);
int b2bl_drop_entity(b2bl_entity_id_t* entity, b2bl_tuple_t* tuple);
void b2bl_delete_entity(b2bl_entity_id_t* entity, b2bl_tuple_t* tuple,
	unsigned int hash_index, int b2be_del1);

int b2b_extra_headers(struct sip_msg* msg, str* b2bl_key, str* custom_hdrs, str* extra_headers);

int b2bl_add_client(b2bl_tuple_t* tuple, b2bl_entity_id_t* entity);
int b2bl_add_server(b2bl_tuple_t* tuple, b2bl_entity_id_t* entity);

b2bl_entity_id_t* b2bl_search_entity(b2bl_tuple_t* tuple, str* key, int src,
	b2bl_entity_id_t*** head);

void b2bl_db_delete(b2bl_tuple_t* tuple);

int store_ctx_value(struct b2b_ctx_val **vals, str *name, str *new_val);

#endif
