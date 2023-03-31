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

#ifndef _B2B_LOGIC_H_
#define _B2B_LOGIC_H_

#include "../../str.h"
#include "../../db/db.h"
#include "../../cachedb/cachedb.h"
#include "../../timer.h"
#include "../b2b_entities/b2be_load.h"

enum b2b_tuple_state {
	/* initial bridge state */
	B2B_INIT_BRIDGING_STATE,

	/* tmp state when bridging with B2BL_BR_FLAG_HOLD */
	B2B_BRIDGING_HOLD_STATE,
	/* tmp state when bridging with B2BL_BR_FLAG_RENEW_SDP */
	B2B_BRIDGING_INIT_SDP_STATE,
	/* main bridging state */
	B2B_BRIDGING_STATE,

	B2B_BRIDGED_STATE,

	B2B_CANCEL_STATE
};

#define IS_BRIDGING_STATE(state) \
	(state>=B2B_BRIDGING_HOLD_STATE && state <=B2B_BRIDGING_STATE)

#define B2B_TOP_HIDING_SCENARY "top hiding"
#define B2B_TOP_HIDING_SCENARY_LEN  strlen("top hiding")

#define B2BL_ENT_NEW		0
#define B2BL_ENT_CONFIRMED	1
#define B2BL_ENT_CANCELING	2


#define b2b_peer(type) ((type+1)%2)

#define HDR_LST_LEN       32
#define HDR_DEFAULT_LEN   9

/* B2BL_FLAGS constants */
#define		B2BL_FLAG_TRANSPARENT_AUTH	0x01
#define		B2BL_FLAG_TRANSPARENT_TO	0x02

/* tuple bridge flags */
#define B2BL_BR_FLAG_NOTIFY                        (1<<0)
#define B2BL_BR_FLAG_RETURN_AFTER_FAILURE          (1<<1)
#define B2BL_BR_FLAG_DONT_DELETE_BRIDGE_INITIATOR  (1<<2)
#define B2BL_BR_FLAG_HOLD                          (1<<3)
#define B2BL_BR_FLAG_RENEW_SDP                     (1<<4)
#define B2BL_BR_FLAG_PROV_MEDIA                    (1<<5)
#define B2BL_BR_FLAG_NO_OLD_ENT                    (1<<6)


/* modes to write in db */
#define NO_DB         0
#define WRITE_THROUGH 1
#define WRITE_BACK    2

extern b2b_api_t b2b_api;

enum {
	B2B_INVITE,
	B2B_ACK,
	B2B_BYE,
	B2B_MESSAGE,
	B2B_SUBSCRIBE,
	B2B_NOTIFY,
	B2B_REFER,
	B2B_CANCEL,
	B2B_UPDATE,
	B2B_INFO,
	B2B_METHODS_NO
};

struct b2b_params
{
	unsigned int flags;
	unsigned int init_timeout;
	int req_routeid;
	int reply_routeid;
	str *id;
};

struct b2b_bridge_params
{
	unsigned int flags;
	unsigned int lifetime;
	str *remote_entity;
	unsigned int remote_entity_party;
};

enum pv_entity_field {
	PV_ENTITY_KEY,
	PV_ENTITY_CALLID,
	PV_ENTITY_ID,
	PV_ENTITIY_FROMTAG,
	PV_ENTITIY_TOTAG
};

extern str custom_headers_lst[HDR_LST_LEN];
extern regex_t* custom_headers_re;
extern int custom_headers_lst_len;
extern int contact_user;
extern str server_address;
extern pv_elem_t *server_address_pve;
extern unsigned int max_duration;
extern str init_callid_hdr;
extern str db_url;
extern str cdb_url;
extern str cdb_key_prefix;
extern db_con_t *b2bl_db ;
extern db_func_t b2bl_dbf;
extern cachedb_funcs b2bl_cdbf;
extern cachedb_con *b2bl_cdb;
extern str b2bl_dbtable;
extern char* b2bl_db_buf;
extern int b2bl_db_mode;
extern unsigned int b2bl_th_init_timeout;
extern int global_req_rtid;
extern int global_reply_rtid;
extern int b2b_early_update;

extern str top_hiding_scen_s;
extern str internal_scen_s;

extern struct b2bl_route_ctx cur_route_ctx;

extern str b2bl_mod_name;

extern str requestTerminated;

#define B2B_TOP_HIDING_ID_PTR &top_hiding_scen_s
#define B2B_INTERNAL_ID_PTR &internal_scen_s

static inline int b2b_get_request_id(str* request)
{
	if(request->len ==INVITE_LEN&&strncasecmp(request->s,INVITE,INVITE_LEN)==0)
		return B2B_INVITE;

	if(request->len ==ACK_LEN && strncasecmp(request->s,ACK,ACK_LEN)==0)
		return B2B_ACK;

	if(request->len ==BYE_LEN && strncasecmp(request->s,BYE,BYE_LEN)==0)
		return B2B_BYE;

	if(request->len==REFER_LEN &&strncasecmp(request->s, REFER, REFER_LEN)==0)
		return B2B_REFER;

	if(request->len==CANCEL_LEN &&strncasecmp(request->s, CANCEL, CANCEL_LEN)==0)
		return B2B_CANCEL;

	if(request->len==SUBSCRIBE_LEN &&strncasecmp(request->s, SUBSCRIBE, SUBSCRIBE_LEN)==0)
		return B2B_SUBSCRIBE;

	if(request->len==NOTIFY_LEN &&strncasecmp(request->s, NOTIFY, NOTIFY_LEN)==0)
		return B2B_NOTIFY;

	if(request->len==MESSAGE_LEN &&strncasecmp(request->s, MESSAGE, MESSAGE_LEN)==0)
		return B2B_MESSAGE;

	if(request->len==UPDATE_LEN &&strncasecmp(request->s, UPDATE, UPDATE_LEN)==0)
		return B2B_UPDATE;

	if(request->len==INFO_LEN &&strncasecmp(request->s, INFO, INFO_LEN)==0)
		return B2B_INFO;

	return -1;
}

#define get_tracer(_tuple) \
	( (_tuple)->tracer.f ? &((_tuple)->tracer) : NULL )

int b2b_add_dlginfo(str* key, str* entity_key,int src, b2b_dlginfo_t* info, void *param);
int b2b_server_notify(struct sip_msg* msg, str* key, int type,
		str *logic_key, void* param, int flags);
int b2b_client_notify(struct sip_msg* msg, str* key, int type,
		str *logic_key, void* param, int flags);
void b2bl_db_init(void);

int b2b_get_local_contact(struct sip_msg *msg, str *from_uri, str *local_contact);

#endif
