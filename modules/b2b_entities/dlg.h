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
 *  2011-06-27  added authentication support (Ovidiu Sas)
 */

#ifndef _B2B_DLG_H_
#define _B2B_DLG_H_

#include "../../str.h"
#include "../../lock_ops.h"
#include "../tm/h_table.h"
#include "../tm/dlg.h"
#include "../dialog/dlg_load.h"
#include "b2b_common.h"

#define CALLER_LEG   0
#define CALLEE_LEG   1

#define B2B_REQUEST   0
#define B2B_REPLY     1

#define DLG_ESTABLISHED   1

#define B2B_MAX_KEY_SIZE	(B2B_MAX_PREFIX_LEN + 5*3 + 40)


enum b2b_entity_type {B2B_SERVER=0, B2B_CLIENT, B2B_NONE};

typedef struct b2b_dlginfo
{
	str callid;
	str fromtag;
	str totag;
}b2b_dlginfo_t;

typedef int (*b2b_notify_t)(struct sip_msg* , str* , int , void* );
typedef int (*b2b_add_dlginfo_t)(str* key, str* entity_key, int src,
	 b2b_dlginfo_t* info);

/*
 * Dialog state
 */
typedef enum b2b_state {
	B2B_UNDEFINED = 0, /* New dialog, no reply received yet */
	B2B_NEW,        /* New dialog, no reply received yet */
	B2B_NEW_AUTH,   /* New dialog with auth info, no reply received yet */
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
	struct b2b_dlg_leg* next;
}dlg_leg_t;


#define NO_UPDATEDB_FLAG    0
#define UPDATEDB_FLAG       1
#define INSERTDB_FLAG       2


/** Definitions for structures used for storing dialogs */
typedef struct b2b_dlg
{
	unsigned int         id;
	b2b_state_t          state;
	str                  ruri;
	str                  callid;
	str                  from_uri;
	str                  from_dname;
	str                  to_uri;
	str                  to_dname;
	str                  tag[2];
	unsigned int         cseq[2];
	unsigned int         last_invite_cseq;
	str                  route_set[2];
	str                  contact[2];
	enum request_method  last_method;
	struct b2b_dlg      *next;
	struct b2b_dlg      *prev;
	b2b_notify_t         b2b_cback;
	b2b_add_dlginfo_t    add_dlginfo;
	str                  param;
	str                  ack_sdp;
	struct cell*         uac_tran;
	struct cell*         uas_tran;
	struct cell*         update_tran;
	struct cell*         cancel_tm_tran;
	dlg_leg_t*           legs;
	struct socket_info*  send_sock;
	unsigned int         last_reply_code;
	int                  db_flag;
}b2b_dlg_t;

typedef struct client_info
{
	str method;
	str from_uri;
	str from_dname;
	str req_uri;
	str dst_uri;
	str to_uri;
	str to_dname;
	str* extra_headers;
	str* body;
	str* from_tag;
	str local_contact;
	unsigned int cseq;
	struct socket_info* send_sock;
}client_info_t;

typedef struct b2b_entry
{
	b2b_dlg_t* first;
	gen_lock_t lock;
	int checked;
}b2b_entry_t;

typedef b2b_entry_t* b2b_table;


typedef struct b2b_req_data
{
	enum b2b_entity_type et;
	str* b2b_key;
	str* method;
	str* extra_headers;
	str* body;
	b2b_dlginfo_t* dlginfo;
	unsigned int no_cb;
}b2b_req_data_t;

typedef struct b2b_rpl_data
{
	enum b2b_entity_type et;
	str* b2b_key;
	int method;
	int code;
	str* text;
	str* body;
	str* extra_headers;
	b2b_dlginfo_t* dlginfo;
}b2b_rpl_data_t;


/** Hash table declaration: for client and server dialogs */
b2b_table server_htable;
b2b_table client_htable;


void print_b2b_dlg(b2b_dlg_t *dlg);

str* b2b_htable_insert(b2b_table table, b2b_dlg_t* dlg, int hash_index,
		int src, int reload);

b2b_dlg_t* b2b_htable_search_safe(str callid, str to_tag, str from_tag);

int b2b_parse_key(str* key, unsigned int* hash_index,
		unsigned int* local_index);

str* b2b_generate_key(unsigned int hash_index, unsigned int local_index);

b2b_dlg_t* b2b_dlg_copy(b2b_dlg_t* dlg);

int init_b2b_htables(void);
void destroy_b2b_htables();
b2b_dlg_t* b2b_new_dlg(struct sip_msg* msg, str* local_contact,
		b2b_dlg_t* init_dlg, str* param);

int b2b_prescript_f(struct sip_msg *msg, void* param);

typedef str* (*b2b_server_new_t) (struct sip_msg* , str* local_contact,
		b2b_notify_t , str* param);
typedef str* (*b2b_client_new_t) (client_info_t* , b2b_notify_t b2b_cback,
		b2b_add_dlginfo_t add_dlginfo_f, str* param);

int b2b_send_reply(b2b_rpl_data_t*);

typedef int (*b2b_send_reply_t)(b2b_rpl_data_t*);

typedef int (*b2b_send_request_t)(b2b_req_data_t*);

int b2b_send_request(b2b_req_data_t*);

void b2b_delete_record(b2b_dlg_t* dlg, b2b_table htable, unsigned int hash_index);

typedef dlg_t* (*build_dlg_f)(b2b_dlg_t* dlg);

str* b2b_key_copy_shm(str* b2b_key);

void shm_free_param(void* param);

void b2b_entity_delete(enum b2b_entity_type et, str* b2b_key,
	 b2b_dlginfo_t* dlginfo, int db_del);

typedef void (*b2b_entity_delete_t)(enum b2b_entity_type et, str* b2b_key,
	 b2b_dlginfo_t* dlginfo, int db_del);
b2b_dlg_t* b2b_search_htable(b2b_table table, 
		unsigned int hash_index, unsigned int local_index);

void b2b_tm_cback(struct cell* t, b2b_table htable, struct tmcb_params *ps);

void print_b2b_entities(void);

int b2breq_complete_ehdr(str* extra_headers, str* ehdr_out, str* body,
		str* contact);

b2b_dlg_t* b2b_search_htable_dlg(b2b_table table, unsigned int hash_index,
		unsigned int local_index, str* to_tag, str* from_tag, str* callid);

#endif
