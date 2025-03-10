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

#include <stdlib.h>
#include "../../str.h"
#include "../../lock_ops.h"
#include "b2b_logic.h"
#include "b2b_load.h"

/* flags used for terminating an entity after it's peer
 * has already been terminated from b2b_entities; see B2B_NOTIFY_FL_TERM_BYE */
#define ENTITY_FL_TERM_BYE       (1<<0)
#define ENTITY_FL_REPLY_RECEIVED (1<<1)

typedef struct b2bl_entity_id
{
	str scenario_id;
	str key;
	str to_uri;
	str proxy;
	str from_uri;
	str from_dname;
	str hdrs;
	str adv_contact;
	str in_sdp;
	str out_sdp;
	b2b_dlginfo_t* dlginfo;
	int rejected;
	int disconnected;
	int state;
	int init_maxfwd;
	unsigned int flags;
	unsigned int last_rcv_code;
	unsigned short no;
	unsigned short sdp_type;
	enum b2b_entity_type type;
	b2bl_dlg_stat_t stats;
	struct b2bl_entity_id* peer;
	struct b2bl_entity_id* prev;
	struct b2bl_entity_id* next;
}b2bl_entity_id_t;

struct b2bl_new_entity {
	enum b2b_entity_type type;
	str id;
	str dest_uri;
	str proxy;
	str from_dname;
	str adv_contact;
	int avp_hdrs;
	int avp_hdr_vals;
};

#define B2BL_SDP_NORMAL     0
#define B2BL_SDP_LATE       1

#define NO_UPDATEDB_FLAG    0
#define UPDATEDB_FLAG       1
#define INSERTDB_FLAG       2

#define MAX_B2BL_ENT		3
#define MAX_BRIDGE_ENT		3
#define MAX_B2BL_KEY		16

#define B2BL_RT_REQ_CTX 1
#define B2BL_RT_RPL_CTX 2
#define B2BL_RT_DO_UPDATE 4
#define B2BL_RT_ENTITY_TERM 8

struct b2b_ctx_val {
	unsigned int id;
	str name;
	str val;
	struct b2b_ctx_val *next;
};

struct b2bl_cback {
	b2bl_cback_f f;
	void *param;
	unsigned int mask;
};

typedef struct b2bl_tuple
{
	unsigned int id;
	unsigned int hash_index;
	str* key;
	str *scenario_id;
	enum b2b_tuple_state state;
	struct script_route_ref *req_route;
	struct script_route_ref *reply_route;
	b2bl_entity_id_t* servers[MAX_B2BL_ENT];
	b2bl_entity_id_t* clients[MAX_B2BL_ENT];
	b2bl_entity_id_t* bridge_entities[MAX_BRIDGE_ENT];
	b2bl_entity_id_t* bridge_initiator;
	int bridge_flags;
	int to_del;
	str* extra_headers;
	struct b2bl_tuple* next;
	struct b2bl_tuple* prev;
	unsigned int lifetime;
	str local_contact;
	int db_flag;
	int repl_flag;  /* sent/received through entities replication */
	struct b2b_ctx_val *vals;
	struct b2b_tracer tracer;
	struct b2bl_cback cb;
}b2bl_tuple_t;

typedef struct b2bl_entry
{
	b2bl_tuple_t* first;
	gen_lock_t lock;
	int locked_by;
	int flags;
}b2bl_entry_t;

typedef b2bl_entry_t* b2bl_table_t;

struct b2bl_route_ctx {
	unsigned int hash_index;
	unsigned int local_index;
	str entity_key;
	int entity_type;
	str peer_key;
	int peer_type;
	str *extra_headers;
	str *body;
	int flags;
};

struct b2b_term_t_list {
	b2bl_entity_id_t *entity;
	volatile unsigned int timeout;
	struct b2b_term_t_list *next;
};

struct b2b_term_timer {
	gen_lock_t *lock;
	struct b2b_term_t_list *first;
	struct b2b_term_t_list *last;
};

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

b2bl_tuple_t* b2bl_insert_new(struct sip_msg* msg, unsigned int hash_index,
	struct b2b_params *init_params, str* custom_hdrs, int local_index,
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

void destroy_b2bl_htable(void);

b2bl_entity_id_t* b2bl_create_new_entity(enum b2b_entity_type type, str* entity_id,
		str* to_uri, str *proxy, str* from_uri,str*from_dname, str* ssid, str* hdrs,
		str *adv_ct, struct sip_msg* msg);

void unchain_ent(b2bl_entity_id_t *ent, b2bl_entity_id_t **head);
void b2bl_remove_single_entity(b2bl_entity_id_t *entity, b2bl_entity_id_t **head,
	unsigned int hash_index);
int b2bl_drop_entity(b2bl_entity_id_t* entity, b2bl_tuple_t* tuple);
void b2bl_delete_entity(b2bl_entity_id_t* entity, b2bl_tuple_t* tuple,
	unsigned int hash_index, int b2be_del1);
void b2bl_free_entity(b2bl_entity_id_t *entity);

int b2b_extra_headers(struct sip_msg* msg, str* b2bl_key, str* custom_hdrs, str* extra_headers);

int b2bl_add_client(b2bl_tuple_t* tuple, b2bl_entity_id_t* entity);
int b2bl_add_server(b2bl_tuple_t* tuple, b2bl_entity_id_t* entity);

b2bl_entity_id_t* b2bl_search_entity(b2bl_tuple_t* tuple, str* key, int src,
	b2bl_entity_id_t*** head);

void b2bl_db_delete(b2bl_tuple_t* tuple);

int store_ctx_value(struct b2b_ctx_val **vals, str *name, str *new_val);

int b2bl_register_set_tracer_cb( b2bl_set_tracer_f f, unsigned int msg_flag_filter );

int b2bl_register_new_tuple_cb(b2bl_cback_f f, void *param);

int b2bl_run_new_tuple_cb(str *key);

b2bl_tuple_t *b2bl_get_tuple(str *key);

int get_new_entities(struct b2bl_new_entity **entity1,
	struct b2bl_new_entity **entity2);

#endif
