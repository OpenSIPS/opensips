/*
 * Copyright (C) 2020 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 *
 */

#ifndef _B2BE_LOAD_H_
#define _B2BE_LOAD_H_

#include "../../bin_interface.h"
#include "../../parser/parse_from.h"

#define B2BCB_TRIGGER_EVENT    (1<<0)
#define B2BCB_RECV_EVENT       (1<<1)

#define B2BCB_BACKEND_DB       (1<<0)
#define B2BCB_BACKEND_CLUSTER  (1<<1)

#define B2B_REQUEST   0
#define B2B_REPLY     1

#define B2B_NOTIFY_FL_TERMINATED (1<<0)
#define B2B_NOTIFY_FL_ACK_NEG    (1<<1)
/* entity has been terminated on the spot when receiving a BYE request
 * while another transaction was ongoing(no final reply sent) */
#define B2B_NOTIFY_FL_TERM_BYE   (1<<2)

#define B2B_MAX_PREFIX_LEN    5
#define B2B_MAX_KEY_SIZE	(B2B_MAX_PREFIX_LEN+5+10+10+INT2STR_MAX_LEN+10)

enum b2b_entity_type {B2B_SERVER=0, B2B_CLIENT, B2B_NONE};

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
	str* client_headers;
	str* body;
	str* from_tag;
	str local_contact;
	unsigned int cseq;
	unsigned int maxfwd;
	struct socket_info* send_sock;
	struct socket_info* pref_sock;
	struct usr_avp *avps;
}client_info_t;

typedef struct b2b_dlginfo
{
	str callid;
	str fromtag;
	str totag;
}b2b_dlginfo_t;

typedef struct b2b_req_data
{
	enum b2b_entity_type et;
	str* b2b_key;
	str* method;
	str* extra_headers;
	str* client_headers;
	str* body;
	b2b_dlginfo_t* dlginfo;
	unsigned int maxfwd;
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


typedef int (*b2b_tracer_cb)(struct sip_msg *msg, void *trans, void* param);
typedef void (*b2b_tracer_freep_cb)( void *param);

struct b2b_tracer {
	b2b_tracer_cb f;
	void *param;
	b2b_tracer_freep_cb f_freep;
};


enum b2b_event_type {B2B_EVENT_CREATE, B2B_EVENT_ACK, B2B_EVENT_UPDATE,
	B2B_EVENT_DELETE};

typedef void (*b2b_cb_t)(enum b2b_entity_type entity_type, str* entity_key,
	str *logic_param, void *param, enum b2b_event_type event_type, bin_packet_t *storage,
	int backend);

typedef int (*b2b_notify_t)(struct sip_msg* msg, str* key, int type,
		str *logic_key, void* param, int flags);
typedef int (*b2b_add_dlginfo_t)(str* key, str* entity_key, int src,
	 b2b_dlginfo_t* info, void *);


typedef void (*b2b_param_free_cb)(void *param);
typedef str* (*b2b_server_new_t) (struct sip_msg* , str* local_contact,
		b2b_notify_t , str *mod_name, str* logic_key, struct b2b_tracer *tracer,
		void *param, b2b_param_free_cb free_param);
typedef str* (*b2b_client_new_t) (client_info_t* , b2b_notify_t b2b_cback,
		b2b_add_dlginfo_t add_dlginfo_f, str *mod_name, str* logic_key,
		struct b2b_tracer *tracer, void *param, b2b_param_free_cb free_param);

typedef int (*b2b_send_request_t)(b2b_req_data_t*);
typedef int (*b2b_send_reply_t)(b2b_rpl_data_t*);

typedef void (*b2b_entity_delete_t)(enum b2b_entity_type et, str* b2b_key,
	 b2b_dlginfo_t* dlginfo, int db_del, int replicate);
typedef int (*b2b_entity_exists_t)(enum b2b_entity_type et, str* b2b_key);
typedef void (*b2b_db_delete_t)(str param);

typedef int (*b2b_restore_linfo_t)(enum b2b_entity_type type, str* key,
		b2b_notify_t cback, void *param, b2b_param_free_cb free_param);

typedef int (*b2b_reg_cb_t) (b2b_cb_t cb, int cb_type, str *mod_name);

typedef int (*b2b_update_b2bl_param_t)(enum b2b_entity_type type, str* key,
		str* param, int replicate);
typedef str *(*b2b_get_b2bl_key_t)(str* callid, str* from_tag, str* to_tag,
		str* entity_key);

typedef int (*b2b_apply_lumps_t)(struct sip_msg* msg);

typedef void* (*b2b_get_context_t)(void);

typedef struct b2b_api
{
	b2b_server_new_t          server_new;
	b2b_client_new_t          client_new;
	b2b_send_request_t        send_request;
	b2b_send_reply_t          send_reply;
	b2b_entity_delete_t       entity_delete;
	b2b_entity_exists_t       entity_exists;
	b2b_db_delete_t           entities_db_delete;
	b2b_restore_linfo_t       restore_logic_info;
	b2b_reg_cb_t       		  register_cb;
	b2b_update_b2bl_param_t   update_b2bl_param;
	b2b_get_b2bl_key_t        get_b2bl_key;
	b2b_apply_lumps_t         apply_lumps;
	b2b_get_context_t		  get_context;
}b2b_api_t;

typedef int(*load_b2b_f) (b2b_api_t* api);

static inline int load_b2b_api( struct b2b_api *b2b_api)
{
	load_b2b_f load_b2b;

	/* import the b2b_entities auto-loading function */
	if ( !(load_b2b=(load_b2b_f)find_export("load_b2b", 0))) {
		LM_ERR("can't import load_b2b\n");
		return -1;
	}

	/* let the auto-loading function load all B2B entities stuff */
	return load_b2b( b2b_api );
}

static inline b2b_dlginfo_t *b2b_new_dlginfo(str *callid, str *fromtag, str *totag)
{
	b2b_dlginfo_t* dlg = NULL;
	int size;

	size = sizeof(b2b_dlginfo_t) + callid->len;
	if (totag && totag->s)
		size += totag->len;
	if (fromtag && fromtag->s)
		size += fromtag->len;
	dlg = shm_malloc(size);
	if (!dlg)
		return NULL;
	memset(dlg, 0, size);

	dlg->callid.s = (char *)(dlg + 1);
	dlg->callid.len = callid->len;
	memcpy(dlg->callid.s, callid->s, callid->len);
	if (totag->s) {
		dlg->totag.len = totag->len;
		dlg->totag.s = dlg->callid.s + dlg->callid.len;
		memcpy(dlg->totag.s, totag->s, totag->len);
	}
	if (fromtag->s) {
		dlg->fromtag.len = fromtag->len;
		dlg->fromtag.s = dlg->callid.s + dlg->callid.len + dlg->totag.len;
		memcpy(dlg->fromtag.s, fromtag->s, fromtag->len);
	}
	return dlg;
}

static inline b2b_dlginfo_t *b2b_dup_dlginfo(b2b_dlginfo_t *info)
{
	return b2b_new_dlginfo(&info->callid, &info->fromtag, &info->totag);
}

static inline b2b_dlginfo_t *b2b_fill_dlginfo(struct sip_msg *msg, str *b2b_key)
{
	static b2b_dlginfo_t dlginfo;
	str callid, fromtag;

	if (msg->callid==NULL || msg->callid->body.s==NULL)
	{
		LM_ERR("failed to parse callid header\n");
		return NULL;
	}
	callid = msg->callid->body;

	if (msg->from->parsed == NULL)
	{
		if (parse_from_header(msg) < 0) {
			LM_ERR("cannot parse From header\n");
			return NULL;
		}
	}
	fromtag = ((struct to_body*)msg->from->parsed)->tag_value;

	dlginfo.totag  = *b2b_key;
	dlginfo.callid = callid;
	dlginfo.fromtag= fromtag;
	return &dlginfo;
}

#endif
