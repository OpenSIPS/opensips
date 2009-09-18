/*
 * $Id: dlg.h $
 *
 * back-to-back entities modules
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

#ifndef _B2B_DLG_H_
#define _B2B_DLG_H_

#include "../../str.h"
#include "../../lock_ops.h"
#include "../tm/h_table.h"
#include "../tm/dlg.h"
#include "../dialog/dlg_load.h"
//#include "../b2b_logic/records.h"

#define CALLER_LEG   0
#define CALLEE_LEG   1

#define B2B_REQUEST   0
#define B2B_REPLY     1

#define DLG_ESTABLISHED   1

enum b2b_entity_type {B2B_SERVER, B2B_CLIENT};

typedef int (*b2b_notify_t)(struct sip_msg* , str* , int , void* );

/*
 * Dialog state
 */
typedef enum b2b_state {
	B2B_UNDEFINED = 0, /* New dialog, no reply received yet */
	B2B_NEW,        /* New dialog, no reply received yet */
	B2B_EARLY,      /* Early dialog, provisional response received */
	B2B_CONFIRMED,  /* Confirmed dialog, 2xx received */
	B2B_ESTABLISHED,/* Established dialog, sent or received ACK received */
	B2B_MODIFIED,   /* ReInvite inside dialog */
	B2B_DESTROYED,  /* Destroyed dialog */
	B2B_TERMINATED, /* Terminated dialog */
	B2B_LAST_STATE  /* Just to know the number of states */
} b2b_state_t;

typedef struct b2b_dlg_leg {
	int id;
	str tag;
	unsigned int cseq;
	str route_set;
	str contact;
	struct socket_info *bind_addr;
	struct b2b_dlg_leg* next;
}dlg_leg_t;


/** Definitions for structures used for storing dialogs */
typedef struct b2b_dlg
{
	unsigned int         id;
	b2b_state_t          state;

	str                  callid;
	str                  from_uri;
	str                  to_uri;
	str                  tag[2];
	unsigned int         cseq[2];
	unsigned int         last_invite_cseq;
	str                  route_set[2];
	str                  contact[2];
	struct socket_info*  bind_addr[2];
	str                  sdp;
	enum request_method  last_method;
	struct b2b_dlg      *next;
	struct b2b_dlg      *prev;
	b2b_notify_t         b2b_cback;
	void*                param;
	struct cell*         tm_tran;
	struct cell*         cancel_tm_tran;
	dlg_leg_t*           legs;
	unsigned int         last_reply_code;
}b2b_dlg_t;

typedef struct b2b_entry
{
	b2b_dlg_t* first;
	gen_lock_t lock;
}b2b_entry_t;

typedef b2b_entry_t* b2b_table;

/** Hash table declaration: for client and server dialogs */
b2b_table server_htable;
b2b_table client_htable;

str* b2b_htable_insert(b2b_table table, b2b_dlg_t* dlg, int hash_index, int src);

b2b_dlg_t* b2b_htable_search_safe(str callid, str to_tag, str from_tag);

int b2b_parse_key(str* key, unsigned int* hash_index,
		unsigned int* local_index);

str* b2b_generate_key(unsigned int hash_index, unsigned int local_index);

b2b_dlg_t* b2b_dlg_copy(b2b_dlg_t* dlg);

int init_b2b_htables(void);
void destroy_b2b_htables();
b2b_dlg_t* b2b_new_dlg(struct sip_msg* msg, int flag);

int b2b_prescript_f(struct sip_msg *msg, void *param);

typedef str* (*b2b_server_new_t) (struct sip_msg* ,b2b_notify_t , void* param);
typedef str* (*b2b_client_new_t) (str* method, str* to_uri, str* from_uri,
		str* extra_headers, str* body, b2b_notify_t b2b_cback, void* param);

int b2b_send_reply(enum b2b_entity_type et, str* b2b_key, int code, str* text,
		str* body, str* extra_headers);

typedef int (*b2b_send_reply_t)(enum b2b_entity_type et, str* b2b_key, int code, str* text,
		str* body, str* extra_headers);

typedef int (*b2b_send_request_t)(enum b2b_entity_type , str* , str* ,str* , str* );

int b2b_send_request(enum b2b_entity_type et, str* b2b_key, str* method,
		str* extra_headers, str* body);

void b2b_delete_record(b2b_dlg_t* dlg, b2b_table* htable, unsigned int hash_index);

typedef dlg_t* (*build_dlg_f)(b2b_dlg_t* dlg);

str* b2b_key_copy_shm(str* b2b_key);

void shm_free_param(void* param);

void b2b_entity_delete(enum b2b_entity_type et, str* b2b_key);

typedef void (*b2b_entity_delete_t)(enum b2b_entity_type et, str* b2b_key);

b2b_dlg_t* b2b_search_htable(b2b_table table, 
		unsigned int hash_index, unsigned int local_index);

void b2b_tm_cback(b2b_table htable, struct tmcb_params *ps);

#endif
