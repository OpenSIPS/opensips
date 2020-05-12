/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
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
#include "../../bin_interface.h"
#include "../../context.h"
#include "b2b_common.h"
#include "b2be_load.h"

#define CALLER_LEG   0
#define CALLEE_LEG   1

#define DLG_ESTABLISHED   1

#define B2B_MAX_KEY_SIZE	(B2B_MAX_PREFIX_LEN+4+10+10+INT2STR_MAX_LEN)

#define B2BE_STORAGE_BIN_TYPE 1
#define B2BE_STORAGE_BIN_VERS 1

#define B2BE_SERIALIZE_STORAGE() (serialize_backend != 0)

/*
 * Dialog state
 */
typedef enum b2b_state {
	B2B_UNDEFINED = 0,
	B2B_NEW,        /* New dialog, no reply received yet */
	B2B_NEW_AUTH,   /* New dialog with auth info, no reply received yet */
	B2B_EARLY,      /* Early dialog, provisional response received */
	B2B_CONFIRMED,  /* Confirmed dialog, 2xx received */
	B2B_ESTABLISHED,/* Established dialog, sent or received ACK received */
	B2B_MODIFIED,   /* ReInvite inside dialog */
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
	str                  storage;
	str                  mod_name;
	str                  ack_sdp;
	struct cell*         uac_tran;
	struct cell*         uas_tran;
	struct cell*         update_tran;
	struct cell*         cancel_tm_tran;
	dlg_leg_t*           legs;
	struct socket_info*  send_sock;
	unsigned int         last_reply_code;
	int                  db_flag;
	int                  replicated;
}b2b_dlg_t;

typedef struct b2b_entry
{
	b2b_dlg_t* first;
	gen_lock_t lock;
	int locked_by;
	int checked;
}b2b_entry_t;

typedef b2b_entry_t* b2b_table;

struct b2b_callback {
	b2b_cb_t cbf;
	str mod_name;
	struct b2b_callback *next;
};


/** Hash table declaration: for client and server dialogs */
extern b2b_table server_htable;
extern b2b_table client_htable;

void print_b2b_dlg(b2b_dlg_t *dlg);

str* b2b_htable_insert(b2b_table table, b2b_dlg_t* dlg, int hash_index,
		time_t timestamp, int src, int safe, int db_insert);

b2b_dlg_t* b2b_htable_search_safe(str callid, str to_tag, str from_tag);

int b2b_parse_key(str* key, unsigned int* hash_index,
		unsigned int* local_index, uint64_t *timestamp);

str* b2b_generate_key(unsigned int hash_index, unsigned int local_index, time_t timestamp);

b2b_dlg_t* b2b_dlg_copy(b2b_dlg_t* dlg);

int init_b2b_htables(void);
void destroy_b2b_htables();
b2b_dlg_t* b2b_new_dlg(struct sip_msg* msg, str* local_contact,
	b2b_dlg_t* init_dlg, str* param, str *mod_name);

int b2b_prescript_f(struct sip_msg *msg, void* param);

int b2b_send_reply(b2b_rpl_data_t*);

int b2b_send_request(b2b_req_data_t*);

void b2b_delete_record(b2b_dlg_t* dlg, b2b_table htable, unsigned int hash_index);

typedef dlg_t* (*build_dlg_f)(b2b_dlg_t* dlg);

str* b2b_key_copy_shm(str* b2b_key);

void shm_free_param(void* param);

void b2b_entity_delete(enum b2b_entity_type et, str* b2b_key,
	 b2b_dlginfo_t* dlginfo, int db_del, int replicate);

b2b_dlg_t* b2b_search_htable(b2b_table table,
		unsigned int hash_index, unsigned int local_index);

void b2b_tm_cback(struct cell* t, b2b_table htable, struct tmcb_params *ps);

void print_b2b_entities(void);

int b2breq_complete_ehdr(str* extra_headers, str *client_headers,
		str* ehdr_out, str* body, str* contact);

b2b_dlg_t* b2b_search_htable_dlg(b2b_table table, unsigned int hash_index,
		unsigned int local_index, str* to_tag, str* from_tag, str* callid);

int b2b_apply_lumps(struct sip_msg* msg);

int b2b_register_cb(b2b_cb_t cb, int cb_type, str *mod_name);

void b2b_run_cb(b2b_dlg_t *dlg, unsigned int hash_index, int entity_type,
	int cbs_type, int event_type, bin_packet_t *storage, int backend);

dlg_leg_t* b2b_dup_leg(dlg_leg_t* leg, int mem_type);

#endif
