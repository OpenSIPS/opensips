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

#include <stdio.h>
#include <stdlib.h>
#include "../../dprint.h"
#include "../../dset.h"
#include "../../error.h"
#include "../../parser/parse_from.h"
#include "../../parser/parse_to.h"
#include "../../parser/parse_content.h"
#include "../../parser/parse_methods.h"
#include "../../parser/parse_hname2.h"
#include "../../parser/parse_refer_to.h"
#include "../../parser/parse_replaces.h"
#include "../../parser/parse_uri.h"
#include "../../strcommon.h"
#include "../../ut.h"
#include "../../pt.h"
#include "../../trim.h"
#include "../../mem/shm_mem.h"
#include "../../mem/mem.h"
#include "../../msg_translator.h"
#include "../b2b_entities/b2be_load.h"
#include "../presence/hash.h"
#include "../presence/utils_func.h"
#include "../../lib/csv.h"

#include "records.h"
#include "b2b_logic.h"
#include "b2bl_db.h"
#include "entity_storage.h"
#include "bridging.h"

static str cancel_reason_hdr=
	{"Reason: SIP;cause=200;text=\"Call completed elsewhere\"\r\n", 55};
extern int b2bl_key_avp_name;
extern unsigned short b2bl_key_avp_type;

extern b2bl_tuple_t *local_ctx_tuple;
extern struct b2b_ctx_val *local_ctx_vals;

extern int req_routeid;
extern int reply_routeid;

struct b2bl_route_ctx cur_route_ctx;

struct to_body* get_b2bl_from(struct sip_msg* msg);

int post_cb_sanity_check(b2bl_tuple_t **tuple, unsigned int hash_index, unsigned int local_index,
			b2bl_entity_id_t **entity, int etype, str *ekey);
int udh_to_uri(str user, str host, str port, str* uri);

static str method_invite= {INVITE, INVITE_LEN};
static str method_bye   = {BYE, BYE_LEN};
static str method_cancel= {CANCEL, CANCEL_LEN};

static str ok = str_init("OK");
static str notAcceptable = str_init("Not Acceptable");
str requestTerminated = str_init("Request Terminated");

int get_new_entities(struct b2bl_new_entity **entity1,
	struct b2bl_new_entity **entity2)
{
	if (!current_processing_ctx) {
		LM_ERR("no current processing ctx!\n");
		*entity1 = NULL;
		*entity2 = NULL;
		return -1;
	}

	*entity1 = context_get_ptr(CONTEXT_GLOBAL, current_processing_ctx,
		new_ent_1_ctx_idx);
	*entity2 = context_get_ptr(CONTEXT_GLOBAL, current_processing_ctx,
		new_ent_2_ctx_idx);

	return 0;
}

void new_ent_ctx_destroy(void *e)
{
	pkg_free(e);
}

int entity_add_dlginfo(b2bl_entity_id_t* entity, b2b_dlginfo_t* dlginfo)
{
	b2b_dlginfo_t* new_dlginfo= NULL;
	int size;

	size = sizeof(b2b_dlginfo_t)+ dlginfo->callid.len;
	if( dlginfo->totag.s)
		size += dlginfo->totag.len;
	if(dlginfo->fromtag.s)
		size+= dlginfo->fromtag.len;
	new_dlginfo = (b2b_dlginfo_t*)shm_malloc(size);
	if(new_dlginfo == NULL)
	{
		LM_ERR("No more shared memory\n");
		return -1;
	}
	memset(new_dlginfo, 0, size);
	size = sizeof(b2b_dlginfo_t);

	if( dlginfo->totag.s)
		CONT_COPY(new_dlginfo, new_dlginfo->totag, dlginfo->totag);
	if(dlginfo->fromtag.s)
		CONT_COPY(new_dlginfo, new_dlginfo->fromtag, dlginfo->fromtag);
	CONT_COPY(new_dlginfo, new_dlginfo->callid, dlginfo->callid);

	entity->dlginfo = new_dlginfo;

	return 0;
}

int b2b_add_dlginfo(str* key, str* entity_key, int src, b2b_dlginfo_t* dlginfo, void *param)
{
	b2bl_tuple_t* tuple;
	b2bl_entity_id_t* entity = NULL;
	b2bl_entity_id_t** ent_head = NULL;
	unsigned int hash_index, local_index;

	if(b2bl_parse_key(key, &hash_index, &local_index) < 0)
	{
		LM_ERR("Failed to parse key\n");
		return -1;
	}

	B2BL_LOCK_GET(hash_index);

	tuple = b2bl_search_tuple_safe(hash_index, local_index);
	if(tuple == NULL)
	{
		LM_ERR("No entity found\n");
		B2BL_LOCK_RELEASE(hash_index);
		return -1;
	}
	/* a connected call */
	if(max_duration)
		tuple->lifetime = get_ticks() + max_duration;
	else
		tuple->lifetime = 0;
	entity = b2bl_search_entity(tuple, entity_key, src, &ent_head);
	if(entity == NULL)
	{
		LM_ERR("No b2b_key match found\n");
		B2BL_LOCK_RELEASE(hash_index);
		return -1;
	}

	if(entity->dlginfo)
	{
		shm_free(entity->dlginfo);
		entity->dlginfo = NULL;
	}
	if(entity_add_dlginfo(entity, dlginfo) < 0)
	{
		LM_ERR("Failed to add dialoginfo\n");
		B2BL_LOCK_RELEASE(hash_index);
		return -1;
	}

	/* log the dialog pair */
	if(entity->peer && entity->peer->dlginfo)
	{
		LM_INFO("Dialog pair: [%.*s] - [%.*s]\n",
				entity->peer->dlginfo->callid.len, entity->peer->dlginfo->callid.s,
				dlginfo->callid.len, dlginfo->callid.s);
	}

	B2BL_LOCK_RELEASE(hash_index);

	return 0;
}

int msg_add_dlginfo(b2bl_entity_id_t* entity, struct sip_msg* msg, str* totag)
{
	b2b_dlginfo_t *dlginfo = b2b_fill_dlginfo(msg, totag);
	if (!dlginfo)
	{
		LM_ERR("cannot fill dlginfo!\n");
		return -1;
	}

	if(entity_add_dlginfo(entity, dlginfo) < 0)
	{
		LM_ERR("Failed to add dialoginfo\n");
		return -1;
	}

	return 0;
}

int b2b_msg_get_to(struct sip_msg* msg, str* to_uri, int flags)
{
	struct to_body *pto;

	if (flags & B2BL_FLAG_TRANSPARENT_TO)
	{
		if (!msg || !msg->to || !msg->to->body.s)
		{
			LM_ERR("cannot find 'to' header!\n");
			return -1;
		}
		if (msg->to->parsed == NULL)
		{
			if (parse_to_uri( msg ) == NULL)
			{
				LM_ERR("cannot parse To header\n");
				return -1;
			}
		}
		pto = (struct to_body*)msg->to->parsed;
		pkg_str_dup(to_uri, &pto->uri);
	} else {
		if(!msg || parse_sip_msg_uri(msg)< 0)
		{
			LM_ERR("failed to parse R-URI\n");
			return -1;
		}

		if(udh_to_uri(msg->parsed_uri.user, msg->parsed_uri.host,
			msg->parsed_uri.port, to_uri)< 0)
		{
			LM_ERR("failed to construct uri from user and domain\n");
			return -1;
		}
	}
	return 0;
}

int b2b_msg_get_from(struct sip_msg* msg, str* from_uri, str* from_dname)
{
	struct to_body *pfrom;

	pfrom = get_b2bl_from(msg);
	if (pfrom)
	{
		*from_uri = pfrom->uri;
		*from_dname = pfrom->display;
		return 0;
	}

	/* examine the from header */
	if (!msg || !msg->from || !msg->from->body.s)
	{
		LM_ERR("cannot find 'from' header!\n");
		return -1;
	}
	if (msg->from->parsed == NULL)
	{
		if ( parse_from_header( msg )<0 )
		{
			LM_ERR("cannot parse From header\n");
			return -1;
		}
	}
	pfrom = (struct to_body*)msg->from->parsed;
	*from_uri = pfrom->uri;
	*from_dname = pfrom->display;

	return 0;
}

int b2b_msg_get_maxfwd(struct sip_msg *msg)
{
	str vals;
	unsigned int valn;

	if (!msg->maxforwards) {
		if (parse_headers(msg, HDR_MAXFORWARDS_F, 0) == -1) {
			LM_ERR("parsing MAX_FORWARD header failed!\n");
			return -1;
		}
		if (!msg->maxforwards) {
			LM_DBG("max_forwards header not found!\n");
			return -1;
		}
	}

	trim_len(vals.len, vals.s, msg->maxforwards->body);
	if (str2int(&vals, &valn) < 0) {
		LM_ERR("Failed to parse Max-Forwards value\n");
		return -1;
	}

	return valn;
}

b2bl_entity_id_t* b2bl_create_new_entity(enum b2b_entity_type type, str* entity_id,
		str* to_uri, str *proxy, str* from_uri,str*from_dname, str* ssid, str* hdrs,
		str *adv_ct, struct sip_msg* msg)
{
	unsigned int size;
	b2bl_entity_id_t* entity;

	size = sizeof(b2bl_entity_id_t) + ((ssid!=NULL)?ssid->len:0) +
		((entity_id!=NULL)?entity_id->len:0)+ ((to_uri !=NULL)?to_uri->len:0)
		+ ((from_uri!=NULL)?from_uri->len:0)+ ((from_dname!=NULL)?from_dname->len:0)
		+ ((proxy!=NULL)?proxy->len:0)+ ((hdrs!=NULL)?hdrs->len:0)
		+ ((adv_ct!=NULL)?adv_ct->len:0);

	entity = (b2bl_entity_id_t*)shm_malloc(size);
	if(entity == NULL)
	{
		LM_ERR("No more shared memory\n");
		return NULL;
	}
	memset(entity, 0, size);

	size = sizeof(b2bl_entity_id_t);

	if(entity_id)
	{
		entity->key.s= (char*)entity+ size;
		memcpy(entity->key.s, entity_id->s, entity_id->len);
		entity->key.len= entity_id->len;
		size+= entity_id->len;
	}
	//CONT_COPY_P(entity, entity->key, entity_id);

	if(ssid)
	{
		entity->scenario_id.s= (char*)entity+ size;
		memcpy(entity->scenario_id.s, ssid->s, ssid->len);
		entity->scenario_id.len= ssid->len;
		size+= ssid->len;
	}

	//CONT_COPY_P(entity, entity->scenario_id, ssid);
	if(to_uri)
	{
		entity->to_uri.s= (char*)entity+ size;
		memcpy(entity->to_uri.s, to_uri->s, to_uri->len);
		entity->to_uri.len= to_uri->len;
		size+= to_uri->len;
	}

	if(proxy)
	{
		entity->proxy.s= (char*)entity+ size;
		memcpy(entity->proxy.s, proxy->s, proxy->len);
		entity->proxy.len= proxy->len;
		size+= proxy->len;
	}

	//CONT_COPY_P(entity, entity->to_uri, to_uri);
	if(from_uri)
	{
		entity->from_uri.s= (char*)entity+ size;
		memcpy(entity->from_uri.s, from_uri->s, from_uri->len);
		entity->from_uri.len= from_uri->len;
		size+= from_uri->len;
	}
//		CONT_COPY_P(entity, entity->from_uri, from_uri);

	if(from_dname)
	{
		entity->from_dname.s= (char*)entity+ size;
		memcpy(entity->from_dname.s, from_dname->s, from_dname->len);
		entity->from_dname.len= from_dname->len;
		size+= from_dname->len;
	}

	if(hdrs)
	{
		entity->hdrs.s= (char*)entity+ size;
		memcpy(entity->hdrs.s, hdrs->s, hdrs->len);
		entity->hdrs.len= hdrs->len;
		size+= hdrs->len;
	}

	if(adv_ct)
	{
		entity->adv_contact.s= (char*)entity+ size;
		memcpy(entity->adv_contact.s, adv_ct->s, adv_ct->len);
		entity->adv_contact.len= adv_ct->len;
		size+= adv_ct->len;
	}

	entity->type = type;

	if(type == B2B_SERVER && msg)
	{
		if( msg_add_dlginfo(entity, msg, entity_id)< 0 )
		{
			LM_ERR("Failed to add dialog information to b2b_logic entity\n");
			shm_free(entity);
			return NULL;
		}
	}
	entity->stats.start_time = get_ticks();
	entity->stats.call_time = 0;

	LM_DBG("new entity type [%d] [%p]->[%.*s]\n",
		entity->type, entity, entity->key.len, entity->key.s);

	return entity;
}

void b2b_end_dialog(b2bl_entity_id_t* bentity, b2bl_tuple_t* tuple,
	unsigned int hash_index)
{
	str *method;
	b2b_req_data_t req_data;

	if(!bentity)
		return;

	if (bentity->next || bentity->prev)
	{
		LM_ERR("Inconsistent state for entity [%p]\n", bentity);
		b2bl_print_tuple(tuple, L_ERR);
		return;
	}
	if(bentity->key.s)
	{
		if(!bentity->disconnected && !bentity->rejected)
		{
			if(bentity->state == B2BL_ENT_CONFIRMED)
			{
				method = &method_bye;
			}
			else
			{
				method = &method_cancel;
			}

			memset(&req_data, 0, sizeof(b2b_req_data_t));
			PREP_REQ_DATA(bentity);
			req_data.method =method;
			b2b_api.send_request(&req_data);

			bentity->disconnected = 1;
		}
	}
	else
	{
		LM_DBG("It is not connected yet - delete\n");
		b2bl_delete_entity(bentity, tuple, hash_index, 1);
	}

}

void b2b_mark_todel( b2bl_tuple_t* tuple)
{
	tuple->to_del = 1;
	tuple->lifetime = 30 + get_ticks();
	tuple->state = B2B_CANCEL_STATE;
	LM_DBG("%p\n", tuple);
}

int b2b_get_local_contact(struct sip_msg *msg, str *from_uri, str *local_contact)
{
	struct sip_uri ct_uri;
	struct socket_info *send_sock = msg ?
		(msg->force_send_socket?msg->force_send_socket:msg->rcv.bind_address):NULL;

	if (server_address.len) {
		if (pv_printf_s(msg, server_address_pve, local_contact) != 0) {
			LM_WARN("Failed to print format string from 'server_address'\n");

			if (msg) {
				get_local_contact(send_sock, NULL, local_contact);
			} else {
				LM_ERR("No current SIP message, "
					"failed to build Contact from send socket\n");
				return -1;
			}
		}
	} else {
		if (msg) {
			memset(&ct_uri, 0, sizeof(struct sip_uri));
			if (contact_user && parse_uri(from_uri->s, from_uri->len, &ct_uri) < 0) {
				LM_ERR("Not a valid sip uri [%.*s]\n", from_uri->len, from_uri->s);
				return -1;
			}

			get_local_contact(send_sock, &ct_uri.user, local_contact);
		} else {
			LM_ERR("'server_address' not defined and no current SIP message\n");
			return -1;
		}
	}

	return 0;
}

b2bl_entity_id_t *b2bl_new_client(client_info_t *ci, b2bl_tuple_t *tuple,
	str *ssid, str *adv_ct, struct sip_msg *msg)
{
	str* client_id;
	b2bl_entity_id_t* entity;

	ci->method = method_invite;
	ci->send_sock = msg ? msg->force_send_socket : NULL;
	ci->pref_sock = msg ? msg->rcv.bind_address : NULL;

	if (adv_ct) {
		ci->local_contact = *adv_ct;
	} else if (b2b_get_local_contact(msg, &ci->from_uri, &ci->local_contact) < 0) {
		LM_ERR("Failed to build Contact\n");
		return NULL;
	}

	if(msg)
	{
		if (str2int( &(get_cseq(msg)->number), &ci->cseq)!=0 )
		{
			LM_ERR("cannot parse cseq number\n");
			return NULL;
		}
	}

	client_id = b2b_api.client_new(ci, b2b_client_notify, b2b_add_dlginfo,
			&b2bl_mod_name, tuple->key, get_tracer(tuple), NULL, NULL);

	if(client_id == NULL)
	{
		LM_ERR("Failed to create client id\n");
		return NULL;
	}
	/* save the client_id in the structure */
	entity = b2bl_create_new_entity(B2B_CLIENT, client_id, &ci->to_uri, 0,
		&ci->from_uri, 0, ssid, ci->client_headers, adv_ct, 0);
	if(entity == NULL)
	{
		LM_ERR("failed to create new client entity\n");
		pkg_free(client_id);
		return NULL;
	}
	pkg_free(client_id);

	return entity;
}

int post_cb_sanity_check(b2bl_tuple_t **tuple, unsigned int hash_index, unsigned int local_index,
			b2bl_entity_id_t **entity, int etype, str *ekey)
{
	int index;
	int not_found = 1;
	b2bl_entity_id_t *e;

	*tuple = b2bl_search_tuple_safe(hash_index, local_index);
	if(*tuple == NULL)
	{
		LM_DBG("B2B logic record doesn't exist after B2B_BYE_CB\n");
		return -1;
	}
	if(ekey == NULL)
	{
		LM_DBG("entity key does not exist!\n");
		return -1;
	}
	if(etype == B2B_SERVER)
	{
		for (index = 0; index < MAX_B2BL_ENT && not_found; index++)
		{
			e = (*tuple)->servers[index];
			while (e)
			{
				if(e == *entity && e->key.len == ekey->len &&
					strncmp(e->key.s, ekey->s, ekey->len)==0)
				{
					not_found = 0;
					break;
				}
				e = e->next;
			}
		}
		if(not_found)
		{
			LM_DBG("Server Entity does not exist anymore\n");
			return -2;
		}
		else
		{
			return 0;
		}
	}
	else
	if(etype == B2B_CLIENT)
	{
		for (index = 0; index < MAX_B2BL_ENT && not_found; index++)
		{
			e = (*tuple)->clients[index];
			while (e)
			{
				LM_DBG("[%p] vs [%p]\n", e, *entity);
				LM_DBG("[%.*s] vs [%.*s]\n", e->key.len, e->key.s, ekey->len, ekey->s);
				if(e == *entity && e->key.len == ekey->len &&
					strncmp(e->key.s, ekey->s, ekey->len)==0)
				{
					not_found = 0;
					break;
				}
				e = e->next;
			}
		}
		if(not_found)
		{
			LM_DBG("Client Entity does not exist anymore\n");
			return -3;
		}
		else
		{
			return 0;
		}
	}
	else
	{
		LM_ERR("Unexpected entity type [%d]\n", etype);
		return -4;
	}
	return -5;
}

int run_init_negreply_cb(struct sip_msg *msg, b2bl_tuple_t *tuple,
	b2bl_entity_id_t *entity)
{
	b2bl_cback_f cbf = NULL;
	str ekey= {NULL, 0};
	b2bl_cb_params_t cb_params;
	b2bl_dlg_stat_t stats;
	int ret;
	int entity_no;
	int etype;

	/* call the callback for brigding failure  */
	cbf = tuple->cb.f;
	if(cbf && (tuple->cb.mask&B2B_REJECT_CB))
	{
		etype = entity->type;
		entity_no = bridge_get_entityno(tuple, entity);

		memset(&cb_params, 0, sizeof(b2bl_cb_params_t));
		cb_params.param = tuple->cb.param;
		stats.start_time =  entity->stats.start_time;
		stats.setup_time = get_ticks() - entity->stats.start_time;
		stats.key.s = NULL; stats.key.len = 0;
		cb_params.stat = &stats;
		ekey.s = (char*)pkg_malloc(entity->key.len);
		if(ekey.s == NULL)
		{
			LM_ERR("No more memory\n");
			return -1;
		}
		memcpy(ekey.s, entity->key.s, entity->key.len);
		ekey.len = entity->key.len;
		cb_params.msg = msg;
		cb_params.entity = entity_no;
		cb_params.key = tuple->key;

		B2BL_LOCK_RELEASE(cur_route_ctx.hash_index);

		ret = cbf(&cb_params, B2B_REJECT_CB);
		LM_DBG("ret = %d\n", ret);

		B2BL_LOCK_GET(cur_route_ctx.hash_index);
		/* must search the tuple again
		 * you can't know what might have happened with it */
		if (0!=post_cb_sanity_check(&tuple, cur_route_ctx.hash_index,
			cur_route_ctx.local_index, &entity, etype, &ekey))
		{
			pkg_free(ekey.s);
			return 1;
		}
		pkg_free(ekey.s);

		if(ret == B2B_DROP_MSG_CB_RET)
		{
			/* drop the negative reply */
			if(entity_no == 1)
				b2bl_delete_entity(entity, tuple, cur_route_ctx.hash_index, 1);
			return 1;
		}
	}

	return 0;
}

str *b2b_scenario_hdrs(struct b2bl_new_entity *entity);

int retry_init_bridge(struct sip_msg *msg, b2bl_tuple_t* tuple,
	b2bl_entity_id_t *entity, struct b2bl_new_entity *new_entity)
{
	str *client_id= NULL;
	str method = {INVITE, INVITE_LEN};
	b2bl_entity_id_t* client_entity = NULL;
	client_info_t ci;
	str *hdrs;
	struct sip_uri ct_uri;

	b2bl_delete_entity(entity, tuple, tuple->hash_index, 1);

	hdrs = b2b_scenario_hdrs(new_entity);

	memset(&ci, 0, sizeof(client_info_t));
	ci.method        = method;
	ci.req_uri       = new_entity->dest_uri;
	ci.to_uri        = tuple->bridge_entities[0]->to_uri;
	ci.dst_uri       = new_entity->proxy;
	ci.from_uri      = tuple->bridge_entities[0]->from_uri;
	ci.from_dname    = tuple->bridge_entities[0]->from_dname;
	ci.extra_headers = tuple->extra_headers;
	ci.client_headers= hdrs;
	ci.body          = &tuple->bridge_entities[0]->in_sdp;
	ci.send_sock     = msg ? msg->force_send_socket : NULL;
	ci.pref_sock     = msg ? msg->rcv.bind_address : NULL;

	ci.maxfwd = tuple->bridge_entities[0]->init_maxfwd;

	if (new_entity->adv_contact.s) {
		ci.local_contact = new_entity->adv_contact;
	} else {
		if (ci.send_sock) {
			memset(&ct_uri, 0, sizeof(struct sip_uri));
			if (contact_user && parse_uri(ci.from_uri.s, ci.from_uri.len, &ct_uri) < 0)
			{
				LM_ERR("Not a valid sip uri [%.*s]\n", ci.from_uri.len, ci.from_uri.s);
				goto error;
			}
			get_local_contact(ci.send_sock, &ct_uri.user, &ci.local_contact);
		} else {
			ci.local_contact = tuple->local_contact;
		}
	}

	client_id = b2b_api.client_new(&ci, b2b_client_notify, b2b_add_dlginfo,
			&b2bl_mod_name, tuple->key, get_tracer(tuple), NULL, NULL);

	if(client_id == NULL)
	{
		LM_ERR("failed to create new b2b client instance\n");
		goto error;
	}

	client_entity = b2bl_create_new_entity(B2B_CLIENT, client_id,
		&new_entity->dest_uri, 0, &tuple->bridge_entities[0]->from_uri, 0,
		new_entity->id.s ? &new_entity->id : NULL, hdrs,
		new_entity->adv_contact.s ? &new_entity->adv_contact : NULL, 0);
	if(client_entity == NULL)
	{
		LM_ERR("failed to create new client entity\n");
		pkg_free(client_id);
		goto error;
	}
	pkg_free(client_id);

	if (0 != b2bl_add_client(tuple, client_entity))
		goto error;
	client_entity->no = 1;
	tuple->bridge_entities[1] = tuple->clients[0];

	if (shm_str_dup(&client_entity->out_sdp,
		&tuple->bridge_entities[0]->in_sdp) < 0) {
		LM_ERR("Failed to save SDP\n");
		goto error;
	}

	tuple->bridge_entities[0]->peer = tuple->bridge_entities[1];
	tuple->bridge_entities[1]->peer = tuple->bridge_entities[0];

	return 0;
error:
	return -1;
}

#define SEND_REPLY_TO_PEER_OR_GOTO_DONE				\
do{								\
	memset(&rpl_data, 0, sizeof(b2b_rpl_data_t));		\
	rpl_data.et =peer->type;				\
	rpl_data.b2b_key =&peer->key;				\
	rpl_data.method =method_value;				\
	rpl_data.code =statuscode;				\
	rpl_data.text =&msg->first_line.u.reply.reason;		\
	rpl_data.body = cur_route_ctx.body->s?cur_route_ctx.body:NULL;	\
	rpl_data.extra_headers =	\
		cur_route_ctx.extra_headers->s?cur_route_ctx.extra_headers:NULL;\
	rpl_data.dlginfo =peer->dlginfo;			\
	if(b2b_api.send_reply(&rpl_data) < 0)			\
	{							\
		LM_ERR("Sending reply failed - %d, [%.*s]\n",	\
			statuscode, peer->key.len, peer->key.s);\
		goto done;					\
	}							\
}while(0)

static int ack_and_term_entity(b2bl_tuple_t *tuple, b2bl_entity_id_t *entity,
	unsigned int statuscode)
{
	b2b_req_data_t req_data;

	if (statuscode >= 200 && statuscode < 300) {
		memset(&req_data, 0, sizeof(b2b_req_data_t));
		PREP_REQ_DATA(entity);
		req_data.method = &str_init("ACK");
		b2b_api.send_request(&req_data);
	}

	memset(&req_data, 0, sizeof(b2b_req_data_t));
	PREP_REQ_DATA(entity);
	req_data.method = &str_init("BYE");
	b2b_api.send_request(&req_data);

	entity->disconnected = 1;

	return 0;
}

int _b2b_handle_reply(struct sip_msg *msg, b2bl_tuple_t *tuple,
	b2bl_entity_id_t *entity, b2bl_entity_id_t **entity_head)
{
	str method;
	b2bl_entity_id_t *peer, *e, *ent;
	int statuscode;
	int ret;
	unsigned int method_value;
	b2bl_cback_f cbf = NULL;
	str ekey= {NULL, 0};
	b2bl_cb_params_t cb_params;
	b2b_rpl_data_t rpl_data;
	b2b_req_data_t req_data;
	b2b_dlginfo_t dlginfo;
	int do_unlock = 0;
	static str method_ack = {ACK, ACK_LEN};

	if (!tuple) {
		B2BL_LOCK_GET(cur_route_ctx.hash_index);
		do_unlock = 1;
		tuple = b2bl_search_tuple_safe(cur_route_ctx.hash_index,
			cur_route_ctx.local_index);
		if(tuple == NULL)
		{
			LM_ERR("B2B logic record not found\n");
			goto error;
		}

		entity = b2bl_search_entity(tuple, &cur_route_ctx.entity_key,
			cur_route_ctx.entity_type, &entity_head);
		if(entity == NULL)
		{
			LM_ERR("No b2b_key match found [%.*s], src=%d\n",
				cur_route_ctx.entity_key.len, cur_route_ctx.entity_key.s,
				cur_route_ctx.entity_type);
			goto error;
		}
		if (entity->no > 1)
		{
			LM_ERR("unexpected entity->no [%d] for tuple [%p]\n", entity->no, tuple);
			goto error;
		}

		LM_DBG("b2b_entity key = %.*s\n",
			cur_route_ctx.entity_key.len, cur_route_ctx.entity_key.s);
	}

	method = get_cseq(msg)->method;
	if(parse_method(method.s, method.s+method.len, &method_value) == NULL)
	{
		LM_ERR("Failed to parse method\n");
		goto error;
	}

	statuscode = msg->first_line.u.reply.statuscode;

	peer = entity->peer;

	if (IS_BRIDGING_STATE(tuple->state)) {
		LM_DBG("Received a reply [%d] while in BRIDGING scenario\n",
			statuscode);

		/* if the scenario state is B2B_BRIDGING_STATE -> we should have a reply for INVITE */
		if(method_value != METHOD_INVITE)
		{
			LM_ERR("Wrong scenario state [B2B_BRIDGING_STATE] for this"
				" reply(for method %d)\n", method_value);
			goto error;
		}

		/* Reply from new bridge entity */
		if(statuscode >= 200 &&
			entity == (tuple->bridge_entities[2]?tuple->bridge_entities[2]:tuple->bridge_entities[1]) &&
			tuple->bridge_flags & B2BL_BR_FLAG_NOTIFY && tuple->bridge_initiator != 0)
		{
			send_bridge_notify(tuple->bridge_initiator, cur_route_ctx.hash_index, msg);
			if(statuscode == 200 || !(tuple->bridge_flags & B2BL_BR_FLAG_RETURN_AFTER_FAILURE))
			{
				if (!(tuple->bridge_flags & B2BL_BR_FLAG_DONT_DELETE_BRIDGE_INITIATOR)) {
					b2b_end_dialog(tuple->bridge_initiator, tuple, tuple->hash_index);
					tuple->bridge_initiator = 0;
				}
			}
		}

		/* if a negative reply */
		if(statuscode >= 300)
		{
			if ((tuple->bridge_flags & B2BL_BR_FLAG_RENEW_SDP) && statuscode == 491) {
				/* it is very likely that the new entity is trying to send itself a re-INVITE
				 * to lock down the codecs, therefore we no longer need this step - thus, for now,
				 * we simply ACK the ongoing bridging entity, and arm a re-negociation attempt
				 */
				memset(&req_data, 0, sizeof(b2b_req_data_t));
				req_data.et = tuple->bridge_entities[0]->type;
				req_data.b2b_key = &tuple->bridge_entities[0]->key;
				req_data.method = &method_ack;
				req_data.body = &tuple->bridge_entities[1]->in_sdp;
				req_data.dlginfo = tuple->bridge_entities[0]->dlginfo;
				b2b_api.send_request(&req_data);

				if (b2bl_push_bridge_retry(tuple) == 0) {
					tuple->bridge_flags |= B2BL_BR_FLAG_PENDING_SDP;
					tuple->state = B2B_BRIDGED_STATE;
					goto done;
				}
				/* else, fallback to rejecting the call */
			}
			entity->rejected = 1;
			ret = process_bridge_negreply(tuple, tuple->hash_index, entity, msg);

			if(ret < 0)
			{
				LM_ERR("Failed to process negative reply while in bridging state\n");
				goto error;
			}
			else
			if(ret == 1)
				goto done1;

			if(!entity->peer || !entity->peer->key.s)
			{
				LM_DBG("Delete this b2bl record\n");
				b2bl_delete(tuple, tuple->hash_index, 1, 1);
				tuple = 0;
			}
			goto done;
		}
		else
		if(statuscode < 200)
		{
			goto done;
		}

		if(process_bridge_200OK(msg, tuple->extra_headers,
					(cur_route_ctx.body->s?cur_route_ctx.body:0), tuple,
					tuple->hash_index, entity)< 0)
		{
			LM_ERR("Failed to process bridging 200OK for Invite\n");
			goto error;
		}

		goto done;
	}

	if(!peer)
	{
		LM_DBG("No peer found\n");
		goto done;
	}

	if (peer->flags & ENTITY_FL_TERM_BYE) {
		/* if not already terminated in BYE processing */
		if (!entity->disconnected) {
			ack_and_term_entity(tuple, entity, statuscode);
			b2b_mark_todel(tuple);
		}

		goto done;
	}

	switch (method_value)
	{
	case METHOD_BYE:
		/* if no other scenario rules defined and this is the reply for BYE */
		SEND_REPLY_TO_PEER_OR_GOTO_DONE;
		LM_DBG("Received reply for BYE - delete\n");
		b2bl_delete(tuple, tuple->hash_index, 1, 1);
		tuple = 0;
		goto done;
		break;

	case METHOD_INVITE:
		if(entity->state!=B2BL_ENT_CONFIRMED)
		{
			if(statuscode >= 300)
			{
				b2bl_print_tuple(tuple, L_DBG);
				if (entity->prev || entity->next)
				{
					LM_DBG("detaching entity[%p] from tuple[%p]\n",
							entity, tuple);
					b2bl_remove_single_entity(entity, entity_head, tuple->hash_index);
					peer->peer = *entity_head;
					tuple->bridge_entities[0] = tuple->servers[0];
					tuple->bridge_entities[1] = tuple->clients[0];
				}
				else
				{
					ret = run_init_negreply_cb(msg, tuple, entity);
					if (ret == -1) {
						goto error;
					} else if (ret == 0) {
						SEND_REPLY_TO_PEER_OR_GOTO_DONE;
						LM_DBG("Negative reply [%d] - delete[%p]\n",
							statuscode, tuple);
						b2b_mark_todel(tuple);
					}
				}
				b2bl_print_tuple(tuple, L_DBG);
			}
			else
			if(statuscode >= 200)
			{
				b2bl_print_tuple(tuple, L_DBG);
				if (entity->prev || entity->next)
				{
					unchain_ent(entity, entity_head);
					/* send CANCEL to all other entities in the list */
					e = *entity_head;
					while (e)
					{
						LM_DBG("Send request [%.*s]"
							" to entity [%.*s]\n",
							method_cancel.len, method_cancel.s,
							e->key.len, e->key.s);
						memset(&req_data, 0, sizeof(b2b_req_data_t));
						PREP_REQ_DATA(e);
						req_data.method =&method_cancel;
						req_data.extra_headers = &cancel_reason_hdr;
						if(b2b_api.send_request(&req_data) < 0)
						{
							LM_ERR("Sending request"
								" failed [%.*s]\n",
								e->key.len, e->key.s);
						}
						b2b_api.entity_delete(e->type, &e->key,
									e->dlginfo, 0, 1);
						LM_DBG("destroying dlginfo=[%p]\n",
								e->dlginfo);
						ent = e->next;
						b2bl_free_entity(e);
						e = ent;
					}
					*entity_head = entity;
					peer->peer = entity;
					tuple->bridge_entities[0] = tuple->servers[0];
					tuple->bridge_entities[1] = tuple->clients[0];
				}

				if (cur_route_ctx.flags & B2BL_RT_ENTITY_TERM) {
					memset(&rpl_data, 0, sizeof(b2b_rpl_data_t));
					PREP_RPL_DATA(peer);
					rpl_data.method = METHOD_INVITE;
					rpl_data.code = 487;
					rpl_data.text = &requestTerminated;
					rpl_data.body = NULL;

					if(b2b_api.send_reply(&rpl_data) < 0) {
						LM_ERR("Sending reply failed - %d, [%.*s]\n",
							rpl_data.code, peer->key.len, peer->key.s);
						goto done;
					}

					LM_DBG("Sent 487 reply to peer after terminating entity "
						"[%.*s]\n", entity->key.len, entity->key.s);
					b2b_mark_todel(tuple);
					goto done;
				}

				if (shm_str_sync(&entity->in_sdp, cur_route_ctx.body) < 0) {
					LM_ERR("Failed to save SDP\n");
					goto error;
				}
				if (shm_str_sync(&peer->out_sdp, cur_route_ctx.body) < 0) {
					LM_ERR("Failed to save SDP\n");
					goto error;
				}

				/* initial bridging is done */
				tuple->state = B2B_BRIDGED_STATE;

				entity->state = B2BL_ENT_CONFIRMED;
				peer->state = B2BL_ENT_CONFIRMED;
				entity->stats.setup_time = get_ticks() - entity->stats.start_time;
				entity->stats.start_time = get_ticks();
				SEND_REPLY_TO_PEER_OR_GOTO_DONE;
				b2bl_print_tuple(tuple, L_DBG);
				cbf = tuple->cb.f;
				if(cbf && (tuple->cb.mask&B2B_CONFIRMED_CB))
				{
					/* saving the entity key for later sanity check */
					ekey.s = (char*)pkg_malloc(entity->key.len);
					if(ekey.s == NULL)
					{
						LM_ERR("No more memory\n");
						goto error;
					}
					ekey.len = entity->key.len;
					memcpy(ekey.s, entity->key.s, entity->key.len);
					/* preparing the cb params */
					memset(&cb_params, 0, sizeof(b2bl_cb_params_t));
					cb_params.param = tuple->cb.param;
					cb_params.stat = NULL;
					cb_params.msg = msg;
					cb_params.entity = entity->no;
					cb_params.key = tuple->key;

					B2BL_LOCK_RELEASE(tuple->hash_index);

					ret = cbf(&cb_params, B2B_CONFIRMED_CB);

					B2BL_LOCK_GET(tuple->hash_index);

					/* must search the tuple again
					 * you can't know what might have happened with it */
					if (0!=post_cb_sanity_check(&tuple, tuple->hash_index, tuple->id,
						&entity, entity->type, &ekey))
					{
						pkg_free(ekey.s);
						goto error;
					}
					pkg_free(ekey.s);

					peer = entity->peer;
				}
			}
			else
			{	/* Provisional replies end up here */
				if((entity->dlginfo) && !entity->dlginfo->fromtag.s)
				{
					if( msg->callid==NULL || msg->callid->body.s==NULL)
					{
						LM_ERR("failed to parse callid header\n");
						goto error;
					}
					dlginfo.callid = msg->callid->body;

					if (msg->from->parsed == NULL)
					{
						if ( parse_from_header( msg )<0 )
						{
							LM_ERR("cannot parse From header\n");
							goto error;
						}
					}
					dlginfo.totag =
					((struct to_body*)msg->from->parsed)->tag_value;

					dlginfo.fromtag = get_to(msg)->tag_value;

					shm_free(entity->dlginfo);
					entity->dlginfo = NULL;
					if(entity_add_dlginfo(entity, &dlginfo) < 0)
					{
						LM_ERR("Failed to add dialoginfo\n");
						goto error;
					}
				}
				SEND_REPLY_TO_PEER_OR_GOTO_DONE;
			}
		}
		else
		{
			if (statuscode>=200 && statuscode < 300) {
				if (shm_str_sync(&entity->in_sdp, cur_route_ctx.body) < 0) {
					LM_ERR("Failed to save SDP\n");
					goto error;
				}
				if (shm_str_sync(&peer->out_sdp, cur_route_ctx.body) < 0) {
					LM_ERR("Failed to save SDP\n");
					goto error;
				}
				tuple->bridge_flags &= ~B2BL_BR_FLAG_PENDING_SDP;
			}

			/* if reINVITE and 481 or 408 reply */
			SEND_REPLY_TO_PEER_OR_GOTO_DONE;
			if(statuscode==481 || statuscode==408)
			{
				LM_DBG("Received terminate dialog reply for reINVITE\n");
				tuple->lifetime = 30 + get_ticks();
			}
		}
		break;

	default:
		SEND_REPLY_TO_PEER_OR_GOTO_DONE;
	}

done:

	if (tuple)
		cur_route_ctx.flags |= B2BL_RT_DO_UPDATE;
done1:
	if (do_unlock) {
		B2BL_LOCK_RELEASE(cur_route_ctx.hash_index);
	}
	return 0;
error:
	if (do_unlock) {
		B2BL_LOCK_RELEASE(cur_route_ctx.hash_index);
	}
	return -1;
}

int b2b_logic_notify_reply(int src, struct sip_msg* msg, str* key, str* body, str* extra_headers,
		str* b2bl_key, unsigned int hash_index, unsigned int local_index, int flags)
{
	b2bl_tuple_t* tuple;
	b2bl_entity_id_t *entity;
	b2bl_entity_id_t** entity_head = NULL;
	int_str avp_val;
	int locked = 0;
	int routeid;

	if (parse_headers(msg, HDR_EOH_F, 0) < 0)
	{
		LM_ERR("failed to parse message\n");
		return -1;
	}

	B2BL_LOCK_GET(hash_index);
	locked = 1;

	tuple = b2bl_search_tuple_safe(hash_index, local_index);
	if(tuple == NULL)
	{
		LM_ERR("B2B logic record not found\n");
		goto error;
	}

	entity = b2bl_search_entity(tuple, key, src, &entity_head);
	if(entity == NULL)
	{
		LM_ERR("No b2b_key match found [%.*s], src=%d\n", key->len, key->s, src);
		goto error;
	}
	if (entity->no > 1)
	{
		LM_ERR("unexpected entity->no [%d] for tuple [%p]\n", entity->no, tuple);
		goto error;
	}

	LM_DBG("b2b_entity key = %.*s\n", key->len, key->s);

	if (b2bl_key_avp_name >= 0)
	{
		destroy_avps( b2bl_key_avp_type, b2bl_key_avp_name, 1);
		avp_val.s = *b2bl_key;
		if(add_avp(AVP_VAL_STR|b2bl_key_avp_type, b2bl_key_avp_name, avp_val)!=0)
		{
			LM_ERR("failed to build b2bl_key avp\n");
			return -1;
		}
	}

	if (msg->first_line.u.reply.statuscode >= 200) {
		entity->flags |= ENTITY_FL_REPLY_RECEIVED;
		entity->last_rcv_code = msg->first_line.u.reply.statuscode;
	}

	/* if a disconnected entity -> do nothing */
	if(entity->disconnected)
	{
		LM_DBG("entity [%.*s] is disconnected\n", key->len, key->s);
		b2bl_delete_entity(entity, tuple, hash_index, 1);

		if(tuple->to_del && tuple->clients[0]==NULL && tuple->clients[1]==NULL &&
					tuple->servers[0]==NULL && tuple->servers[1]==NULL)
		{
			LM_DBG("Received reply and there are no more entities-> delete\n");
			b2bl_delete(tuple, hash_index, 1, 1);
			tuple = 0;
		}
		goto done;
	}

	/* if a reply from the client side was received,
	* tell the server side to send a reply also */

	cur_route_ctx.hash_index = hash_index;
	cur_route_ctx.local_index = local_index;
	cur_route_ctx.body = body;
	cur_route_ctx.extra_headers = extra_headers;
	cur_route_ctx.flags = (flags & B2B_NOTIFY_FL_TERMINATED) ?
		B2BL_RT_ENTITY_TERM : 0;

	if (!ref_script_route_check_and_update(tuple->reply_route)
	|| tuple->scenario_id == B2B_TOP_HIDING_ID_PTR) {
		if (_b2b_handle_reply(msg, tuple, entity, entity_head) < 0)
			goto error;
	} else {
		cur_route_ctx.entity_type = src;
		if (pkg_str_dup(&cur_route_ctx.entity_key, key) < 0) {
			LM_ERR("Out of pkg memory!\n");
			goto error;
		}

		routeid = tuple->reply_route->idx;

		B2BL_LOCK_RELEASE(hash_index);
		locked = 0;

		cur_route_ctx.flags |= B2BL_RT_RPL_CTX;
		run_top_route(sroutes->request[routeid], msg);
		cur_route_ctx.flags &= ~B2BL_RT_RPL_CTX;

		pkg_free(cur_route_ctx.entity_key.s);
	}

done:
	if (tuple && cur_route_ctx.flags & B2BL_RT_DO_UPDATE) {
		if (b2bl_db_mode != NO_DB && !locked) {
			B2BL_LOCK_GET(hash_index);
			locked = 1;

			tuple = b2bl_search_tuple_safe(hash_index, local_index);
			if(!tuple) {
				LM_DBG("B2B logic record not found anymore\n");
				B2BL_LOCK_RELEASE(hash_index);
				return 0;
			}
		}

		if(b2bl_db_mode == WRITE_THROUGH)
			b2bl_db_update(tuple);
		else if (b2bl_db_mode == WRITE_BACK)
			UPDATE_DBFLAG(tuple);
	}
	if (locked)
		B2BL_LOCK_RELEASE(hash_index);
	return 0;
error:
	B2BL_LOCK_RELEASE(hash_index);
	return -1;
}

int _b2b_pass_request(struct sip_msg *msg, b2bl_tuple_t *tuple,
	b2bl_entity_id_t *entity)
{
	str method;
	int request_id;
	b2bl_entity_id_t *peer;
	b2bl_entity_id_t** entity_head = NULL;
	b2b_req_data_t req_data;
	b2b_rpl_data_t rpl_data;
	int do_unlock = 0;
	int maxfwd;

	if (!tuple) {
		B2BL_LOCK_GET(cur_route_ctx.hash_index);
		do_unlock = 1;
		tuple = b2bl_search_tuple_safe(cur_route_ctx.hash_index,
			cur_route_ctx.local_index);
		if(tuple == NULL)
		{
			LM_ERR("B2B logic record not found\n");
			goto error;
		}

		entity = b2bl_search_entity(tuple, &cur_route_ctx.entity_key,
			cur_route_ctx.entity_type, &entity_head);
		if(entity == NULL)
		{
			LM_ERR("No b2b_key match found [%.*s], src=%d\n", cur_route_ctx.entity_key.len,
				cur_route_ctx.entity_key.s, cur_route_ctx.entity_type);
			goto error;
		}
		if (entity->no > 1)
		{
			LM_ERR("unexpected entity->no [%d] for tuple [%p]\n", entity->no, tuple);
			goto error;
		}

	}

	peer = entity->peer;

	method = msg->first_line.u.request.method;
	request_id = b2b_get_request_id(&method);

	switch (request_id)
	{
	case B2B_CANCEL:
		tuple->state = B2B_CANCEL_STATE;
		break;

	case B2B_BYE:
		if(!peer || !peer->key.s)
		{
			memset(&rpl_data, 0, sizeof(b2b_rpl_data_t));
			PREP_RPL_DATA(entity);
			rpl_data.method =METHOD_BYE;
			rpl_data.code =200;
			rpl_data.text =&ok;
			b2b_api.send_reply(&rpl_data);
			b2bl_delete(tuple, cur_route_ctx.hash_index, 1, 1);
			tuple = 0;
			goto done;
		}
		else
			b2b_mark_todel(tuple);
		break;
	}

	while (peer && peer->key.s)
	{
		LM_DBG("Send request [%.*s] to peer [%.*s]\n",
			method.len, method.s, peer->key.len, peer->key.s);
		memset(&req_data, 0, sizeof(b2b_req_data_t));
		PREP_REQ_DATA(peer);
		req_data.method =&method;
		req_data.extra_headers =
			cur_route_ctx.extra_headers->len?cur_route_ctx.extra_headers:NULL;
		req_data.body =cur_route_ctx.body->len?cur_route_ctx.body:NULL;
		/* Decrement Max-Forwards value */
		if ((maxfwd = b2b_msg_get_maxfwd(msg)) > 0)
			req_data.maxfwd = maxfwd;
		if(b2b_api.send_request(&req_data) < 0)
		{
			LM_ERR("Sending request failed [%.*s]\n", peer->key.len, peer->key.s);
		}
		if (request_id != B2B_ACK)
			peer->flags &= ~ENTITY_FL_REPLY_RECEIVED;
		peer = peer->next;
	}

done:
	if (tuple)
		cur_route_ctx.flags |= B2BL_RT_DO_UPDATE;
	if (do_unlock)
		B2BL_LOCK_RELEASE(cur_route_ctx.hash_index);
	return 0;
error:
	if (do_unlock)
		B2BL_LOCK_RELEASE(cur_route_ctx.hash_index);
	return -1;
}

int b2b_logic_notify_request(int src, struct sip_msg* msg, str* key, str* body, str* extra_headers,
		str* b2bl_key, unsigned int hash_index, unsigned int local_index, int flags)
{
	b2bl_tuple_t* tuple;
	str method;
	b2bl_entity_id_t* entity, *peer;
	b2bl_entity_id_t** entity_head = NULL;
	int ret;
	unsigned int method_value;
	int_str avp_val;
	b2bl_cback_f cbf = NULL;
	str ekey= {NULL, 0};
	int request_id;
	b2bl_cb_params_t cb_params;
	b2bl_dlg_stat_t stats;
	b2b_rpl_data_t rpl_data;
	int locked = 0;
	int routeid;

	B2BL_LOCK_GET(hash_index);
	locked = 1;

	tuple = b2bl_search_tuple_safe(hash_index, local_index);
	if(tuple == NULL)
	{
		LM_ERR("B2B logic record not found\n");
		goto error;
	}

	entity = b2bl_search_entity(tuple, key, src, &entity_head);
	if(entity == NULL)
	{
		LM_ERR("No b2b_key match found [%.*s], src=%d\n", key->len, key->s, src);
		goto error;
	}
	if (entity->no > 1)
	{
		LM_ERR("unexpected entity->no [%d] for tuple [%p]\n", entity->no, tuple);
		goto error;
	}
	peer = entity->peer;

	LM_DBG("b2b_entity key = %.*s\n", key->len, key->s);

	if (b2bl_key_avp_name >= 0)
	{
		destroy_avps( b2bl_key_avp_type, b2bl_key_avp_name, 1);
		avp_val.s = *b2bl_key;
		if(add_avp(AVP_VAL_STR|b2bl_key_avp_type, b2bl_key_avp_name, avp_val)!=0)
		{
			B2BL_LOCK_RELEASE(hash_index);
			LM_ERR("failed to build b2bl_key avp\n");
			return -1;
		}
	}

	method = msg->first_line.u.request.method;
	method_value = msg->first_line.u.request.method_value;

	cur_route_ctx.hash_index = hash_index;
	cur_route_ctx.local_index = local_index;
	cur_route_ctx.extra_headers = extra_headers;
	cur_route_ctx.body = body;
	cur_route_ctx.flags = 0;

	LM_DBG("request received for tuple[%p]->[%.*s]\n", tuple, tuple->key->len, tuple->key->s);
	request_id = b2b_get_request_id(&method);
	if(request_id < 0)
	{
		LM_DBG("Not a recognized request [%d]\n", request_id);
		goto send_usual_request;
	}
	/* if the request is an ACK and the tuple is marked to_del -> then delete the record and return */
	if(tuple->to_del)
	{
		switch (request_id)
		{
			case B2B_ACK:
				LM_DBG("ACK for a negative reply\n");
				break;
			case B2B_BYE:
				if (flags & B2B_NOTIFY_FL_TERM_BYE)
					break;

				/* BYE already sent to this entity but we got no reply */
				memset(&rpl_data, 0, sizeof(b2b_rpl_data_t));
				PREP_RPL_DATA(entity);
				rpl_data.method =METHOD_BYE;
				rpl_data.code =200;
				rpl_data.text =&ok;
				b2b_api.send_reply(&rpl_data);
				if(entity->peer)
				{
					memset(&rpl_data, 0, sizeof(b2b_rpl_data_t));
					PREP_RPL_DATA(entity->peer);
					rpl_data.method =METHOD_BYE;
					rpl_data.code =200;
					rpl_data.text =&ok;
					b2b_api.send_reply(&rpl_data);
				}
				break;
			default:
				memset(&rpl_data, 0, sizeof(b2b_rpl_data_t));
				PREP_RPL_DATA(entity);
				rpl_data.method =method_value;
				rpl_data.code =400;
				rpl_data.text =&notAcceptable;
				b2b_api.send_reply(&rpl_data);
		}
		b2bl_delete(tuple, hash_index, 1, 1);
		tuple = 0;
		goto done;
	}

	cbf = tuple->cb.f;

	switch (request_id) {
	case B2B_BYE:
		if (flags & B2B_NOTIFY_FL_TERM_BYE) {
			entity->flags |= ENTITY_FL_TERM_BYE;

			/* if peer has already received a reply, terminate entity here */
			if (peer && !peer->disconnected &&
				(peer->flags & ENTITY_FL_REPLY_RECEIVED)) {
				ack_and_term_entity(tuple, peer, peer->last_rcv_code);
				b2b_mark_todel(tuple);
			}

			goto done;
		}

		entity->disconnected = 1;
		if(cbf && (tuple->cb.mask&B2B_BYE_CB))
		{
			memset(&cb_params, 0, sizeof(b2bl_cb_params_t));
			cb_params.param = tuple->cb.param;
			if(!IS_BRIDGING_STATE(tuple->state))
				entity->stats.call_time = get_ticks() - entity->stats.start_time;
			else
				entity->stats.call_time = 0;
			memcpy(&stats, &entity->stats, sizeof(b2bl_dlg_stat_t));
			stats.key.s = (char*)pkg_malloc(tuple->key->len);
			if(stats.key.s == NULL)
			{
				LM_ERR("No more memory\n");
				goto error;
			}
			memcpy(stats.key.s, tuple->key->s, tuple->key->len);
			stats.key.len = tuple->key->len;
			ekey.s = (char*)pkg_malloc(entity->key.len);
			if(ekey.s == NULL)
			{
				LM_ERR("No more memory\n");
				pkg_free(stats.key.s);
				goto error;
			}
			memcpy(ekey.s, entity->key.s, entity->key.len);
			ekey.len = entity->key.len;
			cb_params.stat = &stats;
			cb_params.msg = msg;
			cb_params.entity = entity->no;
			cb_params.key = tuple->key;

			B2BL_LOCK_RELEASE(hash_index);
			LM_DBG("entity->no = %d\n", entity->no);
			ret = cbf(&cb_params, B2B_BYE_CB);
			LM_DBG("ret = %d, peer= %p\n", ret, peer);

			pkg_free(stats.key.s);
			B2BL_LOCK_GET(hash_index);
			/* must search the tuple again
			 * you can't know what might have happened with it */
			if (0!=post_cb_sanity_check(&tuple, hash_index, local_index,
						&entity, entity->type, &ekey))
			{
				pkg_free(ekey.s);
				goto error;
			}
			pkg_free(ekey.s);

			peer = entity->peer;
			if(ret< B2B_DROP_MSG_CB_RET )
			{
				LM_ERR("The callback function was unsuccessful\n");
				goto send_usual_request;
			}
			else
			if(ret == B2B_DROP_MSG_CB_RET)
			{
				entity->peer = 0;
				/* send 200 OK for BYE */
				memset(&rpl_data, 0, sizeof(b2b_rpl_data_t));
				PREP_RPL_DATA(entity);
				rpl_data.method =METHOD_BYE;
				rpl_data.code =200;
				rpl_data.text =&ok;
				b2b_api.send_reply(&rpl_data);
				b2bl_delete_entity(entity, tuple, hash_index, 1);
				entity = NULL;
				goto done;
			}
			else
			if(ret == B2B_SEND_MSG_CB_RET)
				goto send_usual_request;
		}

		if(IS_BRIDGING_STATE(tuple->state))
		{
			LM_DBG("Scenario is in bridging state\n");
			if(process_bridge_bye(msg, tuple, hash_index, entity) < 0)
			{
				LM_ERR("Failed to process BYE received in bridging state\n");
				goto error;
			}

			if(tuple->to_del && entity->peer==NULL)
			{
				LM_DBG("Delete this b2bl record after process_bridge_bye\n");
				b2bl_delete(tuple, hash_index, 1, 1);
				tuple = 0;
			}

			goto done;
		}
		break;

	case B2B_CANCEL:
		entity->state = B2BL_ENT_CANCELING;
		break;

	case B2B_INVITE:
		if(cbf)
		{
			/* saving the entity key for later sanity check */
			ekey.s = (char*)pkg_malloc(entity->key.len);
			if(ekey.s == NULL)
			{
				LM_ERR("No more memory\n");
				goto error;
			}
			ekey.len = entity->key.len;
			memcpy(ekey.s, entity->key.s, entity->key.len);
			LM_DBG("ekey [%p]->[%.*s]\n", &ekey, ekey.len, ekey.s);
			/* preparing the cb params */
			memset(&cb_params, 0, sizeof(b2bl_cb_params_t));
			cb_params.param = tuple->cb.param;
			cb_params.stat = NULL;
			cb_params.msg = msg;
			cb_params.entity = entity->no;
			cb_params.key = tuple->key;
			B2BL_LOCK_RELEASE(hash_index);

			LM_DBG("entity->no = %d\n", entity->no);
			ret = cbf(&cb_params, B2B_RE_INVITE_CB);
			LM_DBG("ret = %d, peer= %p\n", ret, peer);

			B2BL_LOCK_GET(hash_index);
			/* must search the tuple again
			 * you can't know what might have happened with it */
			if (0!=post_cb_sanity_check(&tuple, hash_index, local_index,
						&entity, entity->type, &ekey))
			{
				pkg_free(ekey.s);
				goto error;
			}
			pkg_free(ekey.s);

			peer = entity->peer;
			switch (ret) {
			case B2B_DROP_MSG_CB_RET:
				/* send 400 Not Acceptable for INVITE */
				memset(&rpl_data, 0, sizeof(b2b_rpl_data_t));
				PREP_RPL_DATA(entity);
				rpl_data.method =METHOD_INVITE;
				rpl_data.code =400;
				rpl_data.text =&notAcceptable;
				b2b_api.send_reply(&rpl_data);
				goto done;
				break;
			case B2B_SEND_MSG_CB_RET:
				goto send_usual_request;
				break;
			case B2B_FOLLOW_SCENARIO_CB_RET:
				/* just continue with normal processing */
				break;
			case B2B_ERROR_CB_RET:
				LM_ERR("The callback function was unsuccessful\n");
				goto send_usual_request;
				break;
			default:
				LM_ERR("Unexpected return code [%d]\n", ret);
				goto send_usual_request;
			}

		}

		if (shm_str_sync(&entity->in_sdp, body) < 0) {
			LM_ERR("Failed to save SDP\n");
			goto error;
		}
		if (peer && shm_str_sync(&peer->out_sdp, body) < 0) {
			LM_ERR("Failed to save SDP\n");
			goto error;
		}

		break;

	case B2B_ACK:
		if (flags & B2B_NOTIFY_FL_ACK_NEG) {
			LM_DBG("ACK for a negative reply\n");
			goto done;
		}

		break;
	}

	if (!ref_script_route_check_and_update(tuple->req_route)
	|| tuple->scenario_id == B2B_TOP_HIDING_ID_PTR) {
		if(request_id == B2B_BYE)
		{
			/* even though I don;t receive a reply,
			I should delete this record*/
			tuple->lifetime = 30 + get_ticks();
		}
		goto send_usual_request;
	} else {
		if(tuple->state == B2B_BRIDGED_STATE && peer && request_id == B2B_INVITE)
			peer->sdp_type = body->len ? B2BL_SDP_NORMAL : B2BL_SDP_LATE;

		cur_route_ctx.entity_type = src;
		if (pkg_str_dup(&cur_route_ctx.entity_key, key) < 0) {
			LM_ERR("Out of pkg memory!\n");
			goto error;
		}

		if (peer) {
			cur_route_ctx.peer_type = peer->type;
			if (pkg_str_dup(&cur_route_ctx.peer_key, &peer->key) < 0) {
				LM_ERR("Out of pkg memory!\n");
				goto error;
			}
		}

		routeid = tuple->req_route->idx;

		B2BL_LOCK_RELEASE(hash_index);
		locked = 0;

		cur_route_ctx.flags = B2BL_RT_REQ_CTX;
		run_top_route(sroutes->request[routeid], msg);
		cur_route_ctx.flags &= ~B2BL_RT_REQ_CTX;

		pkg_free(cur_route_ctx.entity_key.s);
		if (peer)
			pkg_free(cur_route_ctx.peer_key.s);
	}

	goto done;

send_usual_request:
	if (_b2b_pass_request(msg, tuple, entity) < 0)
		goto error;

done:
	if(tuple && cur_route_ctx.flags & B2BL_RT_DO_UPDATE)
	{
		if (b2bl_db_mode != NO_DB && !locked) {
			B2BL_LOCK_GET(hash_index);
			locked = 1;

			tuple = b2bl_search_tuple_safe(hash_index, local_index);
			if(!tuple) {
				LM_DBG("B2B logic record not found anymore\n");
				B2BL_LOCK_RELEASE(hash_index);
				return 0;
			}
		}
		if(b2bl_db_mode == WRITE_THROUGH)
			b2bl_db_update(tuple);
		else if (b2bl_db_mode == WRITE_BACK)
			UPDATE_DBFLAG(tuple);
	}
	if (locked)
		B2BL_LOCK_RELEASE(hash_index);
	return 0;

error:
	B2BL_LOCK_RELEASE(hash_index);
	return -1;
}

int b2b_handle_reply(struct sip_msg *msg)
{
	if (!(cur_route_ctx.flags & B2BL_RT_RPL_CTX)) {
		LM_ERR("The 'b2b_handle_reply' function can only be used from the "
			"b2b_logic dedicated reply routes\n");
		return -1;
	}

	return _b2b_handle_reply(msg, NULL, NULL, NULL) ? -1 : 1;
}

int b2b_pass_request(struct sip_msg *msg)
{
	if (!(cur_route_ctx.flags & B2BL_RT_REQ_CTX)) {
		LM_ERR("The 'b2b_pass_request' function can only be used from the "
			"b2b_logic dedicated request routes\n");
		return -1;
	}

	return _b2b_pass_request(msg, NULL, NULL) ? -1 : 1;
}

int b2b_send_reply(struct sip_msg *msg, int *code, str *reason, str *headers, str *body)
{
	b2bl_tuple_t *tuple;
	b2bl_entity_id_t *entity;
	b2bl_entity_id_t** entity_head = NULL;
	b2b_rpl_data_t rpl_data;
	unsigned int method_value;

	if (!(cur_route_ctx.flags & B2BL_RT_REQ_CTX)) {
		LM_ERR("The 'b2b_send_reply' function can only be used from the "
			"b2b_logic dedicated request routes\n");
		return -1;
	}

	B2BL_LOCK_GET(cur_route_ctx.hash_index);
	tuple = b2bl_search_tuple_safe(cur_route_ctx.hash_index,
		cur_route_ctx.local_index);
	if(tuple == NULL)
	{
		LM_ERR("B2B logic record not found\n");
		goto error;
	}

	entity = b2bl_search_entity(tuple, &cur_route_ctx.entity_key,
		cur_route_ctx.entity_type, &entity_head);
	if(entity == NULL)
	{
		LM_ERR("No b2b_key match found [%.*s], src=%d\n", cur_route_ctx.entity_key.len,
			cur_route_ctx.entity_key.s, cur_route_ctx.entity_type);
		goto error;
	}
	if (entity->no > 1)
	{
		LM_ERR("unexpected entity->no [%d] for tuple [%p]\n", entity->no, tuple);
		goto error;
	}

	method_value = msg->first_line.u.request.method_value;

	memset(&rpl_data, 0, sizeof(b2b_rpl_data_t));
	PREP_RPL_DATA(entity);
	rpl_data.method =method_value;
	rpl_data.code =*code;
	rpl_data.text =reason;
	rpl_data.extra_headers = headers;
	rpl_data.body = body;

	b2b_api.send_reply(&rpl_data);
	LM_DBG("Send reply with code [%d] and text [%.*s]\n", *code,
		reason->len, reason->s);

	B2BL_LOCK_RELEASE(cur_route_ctx.hash_index);
	return 1;
error:
	B2BL_LOCK_RELEASE(cur_route_ctx.hash_index);
	return -1;
}

int b2b_delete_entity(struct sip_msg *msg)
{
	b2bl_tuple_t *tuple;
	b2bl_entity_id_t *entity;
	b2bl_entity_id_t** entity_head = NULL;

	if (!(cur_route_ctx.flags & B2BL_RT_REQ_CTX)) {
		LM_ERR("The 'b2b_delete_entity' function can only be used from the "
			"b2b_logic dedicated request routes\n");
		return -1;
	}

	B2BL_LOCK_GET(cur_route_ctx.hash_index);
	tuple = b2bl_search_tuple_safe(cur_route_ctx.hash_index,
		cur_route_ctx.local_index);
	if(tuple == NULL)
	{
		LM_ERR("B2B logic record not found\n");
		goto error;
	}

	entity = b2bl_search_entity(tuple, &cur_route_ctx.entity_key,
		cur_route_ctx.entity_type, &entity_head);
	if(entity == NULL)
	{
		LM_ERR("No b2b_key match found [%.*s], src=%d\n", cur_route_ctx.entity_key.len,
			cur_route_ctx.entity_key.s, cur_route_ctx.entity_type);
		goto error;
	}
	if (entity->no > 1)
	{
		LM_ERR("unexpected entity->no [%d] for tuple [%p]\n", entity->no, tuple);
		goto error;
	}

	if(entity->peer)
		entity->peer->peer = 0;
	b2bl_delete_entity(entity, tuple, cur_route_ctx.hash_index, 1);

	cur_route_ctx.flags |= B2BL_RT_DO_UPDATE;

	B2BL_LOCK_RELEASE(cur_route_ctx.hash_index);
	return 1;
error:
	B2BL_LOCK_RELEASE(cur_route_ctx.hash_index);
	return -1;
}

int b2b_end_dlg_leg(struct sip_msg *msg)
{
	b2bl_tuple_t *tuple;
	b2bl_entity_id_t *entity;
	b2b_req_data_t req_data;
	b2bl_entity_id_t** entity_head = NULL;

	if (!(cur_route_ctx.flags & (B2BL_RT_REQ_CTX|B2BL_RT_RPL_CTX))) {
		LM_ERR("The 'b2b_end_dlg_leg' function can only be used from the "
			"b2b_logic dedicated request or reply routes\n");
		return -1;
	}

	B2BL_LOCK_GET(cur_route_ctx.hash_index);
	tuple = b2bl_search_tuple_safe(cur_route_ctx.hash_index,
		cur_route_ctx.local_index);
	if(tuple == NULL)
	{
		LM_ERR("B2B logic record not found\n");
		goto error;
	}

	entity = b2bl_search_entity(tuple, &cur_route_ctx.entity_key,
		cur_route_ctx.entity_type, &entity_head);
	if(entity == NULL)
	{
		LM_ERR("No b2b_key match found [%.*s], src=%d\n", cur_route_ctx.entity_key.len,
			cur_route_ctx.entity_key.s, cur_route_ctx.entity_type);
		goto error;
	}
	if (entity->no > 1)
	{
		LM_ERR("unexpected entity->no [%d] for tuple [%p]\n", entity->no, tuple);
		goto error;
	}

	LM_DBG("End dialog\n");

	entity->disconnected = 1;
	memset(&req_data, 0, sizeof(b2b_req_data_t));
	PREP_REQ_DATA(entity);
	req_data.method =&method_bye;
	b2b_api.send_request(&req_data);
	if(entity->peer)
		entity->peer->peer = NULL;
	entity->peer = NULL;

	cur_route_ctx.flags |= B2BL_RT_DO_UPDATE;

	B2BL_LOCK_RELEASE(cur_route_ctx.hash_index);
	return 1;
error:
	B2BL_LOCK_RELEASE(cur_route_ctx.hash_index);
	return -1;
}

static inline int get_b2b_dialog_by_replace(str *replaces, str *u_replaces,
			str *entity_key, unsigned int *hash_idx, unsigned int *local_idx )
{
	struct replaces_body replaces_b;
	str *tuple_key;

	//LM_DBG("Replaces=[%.*s]\n",replaces->len,replaces->s);
	if(unescape_param(replaces,u_replaces)!=0)
	{
		LM_ERR("unable to escape [%.*s]\n",
			replaces->len, replaces->s);
		return -1;
	}
	//LM_DBG("[%.*s]\n", u_replaces->len, u_replaces->s);
	if(parse_replaces_body(u_replaces->s, u_replaces->len,
		&replaces_b)<0 ||
		!replaces_b.callid_val.s ||
		!replaces_b.to_tag_val.s ||
		!replaces_b.from_tag_val.s)
	{
		LM_ERR("unable to parse replaces header [%.*s]\n",
			u_replaces->len, u_replaces->s);
		return -1;
	}
	tuple_key = b2b_api.get_b2bl_key(&replaces_b.callid_val,
		&replaces_b.from_tag_val,
		&replaces_b.to_tag_val,
		entity_key);
	if(!tuple_key)
	{
		LM_ERR("no b2bl key for [%.*s][%.*s][%.*s]\n",
			replaces_b.callid_val.len,
			replaces_b.callid_val.s,
			replaces_b.to_tag_val.len,
			replaces_b.to_tag_val.s,
			replaces_b.from_tag_val.len,
			replaces_b.from_tag_val.s);
		return -1;
	}
	if(b2bl_parse_key(tuple_key, hash_idx, local_idx)< 0)
	{
		LM_ERR("Failed to parse b2b logic key [%.*s]\n",
			tuple_key->len, tuple_key->s);
		pkg_free(tuple_key);
		return -1;
	}
	LM_DBG("Need to replace callid=[%.*s] to-tag=[%.*s] and "
		"from-tag=[%.*s] from b2b_logic [%.*s]\n",
		replaces_b.callid_val.len, replaces_b.callid_val.s,
		replaces_b.to_tag_val.len, replaces_b.to_tag_val.s,
		replaces_b.from_tag_val.len, replaces_b.from_tag_val.s,
		tuple_key->len, tuple_key->s);
	pkg_free(tuple_key);

	return 0;
}

int b2b_logic_notify(int src, struct sip_msg* msg, str* key, int type, str* b2bl_key,
	int flags)
{
	#define U_REPLACES_BUF_LEN 512
	char u_replaces_buf[U_REPLACES_BUF_LEN];
	str u_replaces = { u_replaces_buf, U_REPLACES_BUF_LEN};
	unsigned int hash_index, local_index;
	unsigned int hash_idx, local_idx;
	str entity_key = {NULL, 0};
	b2bl_tuple_t* tuple;
	str body= {NULL, 0};
	str extra_headers = {NULL, 0};
	str new_body={NULL, 0};
	int ret = -1;
	#define H_SIZE 2
	str h_name[H_SIZE];
	str h_val[H_SIZE];
	str rt_header;
	str auth_header;
	str* cust_headers;
	str* replaces = NULL;
	#define RT_BUF_LEN 1024
	char rt_buf[RT_BUF_LEN];
	str rt;
	struct b2bl_entity_id* r_peer = NULL;
	int i;

	if(b2bl_key == NULL)
	{
		LM_ERR("'param' argument NULL\n");
		return -1;
	}
	if(key == NULL)
	{
		LM_ERR("'key' argument NULL\n");
		return -1;
	}

	if(b2bl_parse_key(b2bl_key, &hash_index, &local_index)< 0)
	{
		LM_ERR("Failed to parse b2b logic key [%.*s]\n", b2bl_key->len, b2bl_key->s);
		return -1;
	}

	if (parse_headers(msg, HDR_EOH_F, 0) < 0)
	{
		LM_ERR("failed to parse message\n");
		return -1;
	}

	/* extract body if it has one */
	/* process the body */
	if(msg->content_length)
	{
		if ( get_body(msg, &body)!=0 )
		{
			LM_ERR("cannot extract body\n");
			return -1;
		}
	}

	LM_DBG("b2b_entities notification cb for [%.*s] with entity [%.*s]\n",
			b2bl_key->len, b2bl_key->s, key->len, key->s);

	if(type == B2B_REPLY)
	{
		cust_headers = NULL;
		if (b2bl_htable[hash_index].flags & B2BL_FLAG_TRANSPARENT_AUTH)
		{
			if (msg->first_line.u.reply.statuscode == 401 && msg->www_authenticate)
			{
				auth_header.s = msg->www_authenticate->name.s;
				auth_header.len = msg->www_authenticate->len;
				cust_headers = &auth_header;
			}
			if (msg->first_line.u.reply.statuscode == 407 && msg->proxy_authenticate)
			{
				auth_header.s = msg->proxy_authenticate->name.s;
				auth_header.len = msg->proxy_authenticate->len;
				cust_headers = &auth_header;
			}
		}

		/* build extra headers */
		if(b2b_extra_headers(msg, NULL, cust_headers, &extra_headers)< 0)
		{
			LM_ERR("Failed to construct extra headers\n");
			goto done;
		}
		ret = b2b_logic_notify_reply(src, msg, key, &body, &extra_headers,
						b2bl_key, hash_index, local_index, flags);
	}
	else
	if(type == B2B_REQUEST)
	{
		if(msg->first_line.u.request.method_value==METHOD_REFER &&
			parse_refer_to_header(msg)==0 && msg->refer_to!=NULL &&
			get_refer_to(msg)!=NULL && parse_uri(get_refer_to(msg)->uri.s,
							get_refer_to(msg)->uri.len,
							&(get_refer_to(msg)->parsed_uri))==0)
		{
			/* We have a Refer-To header */
			if(get_refer_to(msg)->parsed_uri.headers.s &&
				parse_uri_headers(get_refer_to(msg)->parsed_uri.headers,
								h_name,h_val,H_SIZE)==0)
			{
				for(i=0; i<H_SIZE && h_name[i].s && h_name[i].len; i++)
					if(strncmp("Replaces",h_name[i].s,h_name[i].len)==0)
					{
						replaces = &h_val[i];
						break;
					}
			}
			if ( replaces && get_b2b_dialog_by_replace(replaces, &u_replaces,
			&entity_key, &hash_idx, &local_idx)==0 )
			{
				/* There is a "replaces" info and it matches a local dialog */
				B2BL_LOCK_GET(hash_idx);
				tuple=b2bl_search_tuple_safe(hash_idx, local_idx);
				if(tuple == NULL)
				{
					LM_ERR("B2B logic record not found\n");
					B2BL_LOCK_RELEASE(hash_idx);
					goto done;
				}
				b2bl_print_tuple(tuple, L_ERR);
				for(i=0;i<MAX_B2BL_ENT;i++)
				{
					if(tuple->servers[i] &&
						tuple->servers[i]->key.len==entity_key.len &&
						strncmp(tuple->servers[i]->key.s,
							entity_key.s, entity_key.len)==0)
					{
						r_peer = tuple->servers[i]->peer;
						break;
					}
				}
				B2BL_LOCK_RELEASE(hash_idx);

				if(!r_peer)
				{
					LM_ERR("no replaces peer\n");
					goto done;
				}
				LM_DBG("got replacement callid=[%.*s] "
					"to-tag=[%.*s] and from-tag=[%.*s]\n",
					r_peer->dlginfo->callid.len, r_peer->dlginfo->callid.s,
					r_peer->dlginfo->totag.len, r_peer->dlginfo->totag.s,
					r_peer->dlginfo->fromtag.len, r_peer->dlginfo->fromtag.s);

				/* build the escaped Replaces URI header
				 * Note: dlginfo->totag becomes from-tag in Replaces URI header
				 *       dlginfo->fromtag becomes to-tag in Replaces URI header
				 */
				i = r_peer->dlginfo->callid.len + r_peer->dlginfo->fromtag.len +
					r_peer->dlginfo->totag.len + 18 /* 2x'=' + 2x'=' + ft */;
				if (U_REPLACES_BUF_LEN < i)
				{
					LM_ERR("not enough space in the buffer: "
						"U_REPLACES_BUF_LEN < %d\n", i);
				}
				memcpy(u_replaces.s,
					r_peer->dlginfo->callid.s, r_peer->dlginfo->callid.len);
				i = r_peer->dlginfo->callid.len;
				u_replaces_buf[i] = ';';
				i++;
				memcpy(u_replaces.s + i, "from-tag", strlen("from-tag"));
				i += strlen("from-tag");
				u_replaces_buf[i] = '=';
				i++;
				memcpy(u_replaces.s + i,
					r_peer->dlginfo->totag.s, r_peer->dlginfo->totag.len);
				i += r_peer->dlginfo->totag.len;
				u_replaces_buf[i] = ';';
				i++;
				memcpy(u_replaces.s + i, "to-tag", strlen("to-tag"));
				i += strlen("to-tag");
				u_replaces_buf[i] = '=';
				i++;
				memcpy(u_replaces.s + i,
					r_peer->dlginfo->fromtag.s, r_peer->dlginfo->fromtag.len);
				i += r_peer->dlginfo->fromtag.len;
				u_replaces.len = i;

				/* build the new Refer-To header
				 * Note: for now, we ignore the "early-only" parameter
				 */
				i = (int)(replaces->s - msg->refer_to->name.s);
				if(i>=RT_BUF_LEN)
				{
					LM_ERR("Not enough space to build Refer-To: "
								"%d>=RT_BUF_LEN\n", i);
					goto done;
				}
				memcpy(&rt_buf[0], msg->refer_to->name.s, i);
				rt.s = &rt_buf[i];
				rt.len = RT_BUF_LEN - i;
				if(escape_param(&u_replaces, &rt)!=0)
				{
					LM_ERR("Unable to escape [%.*s] with len [%d] in char[%d]\n",
						u_replaces.len,u_replaces.s, u_replaces.len, rt.len);
					goto done;
				}
				//LM_DBG("escaped replaces [%.*s]\n", rt.len, rt.s);
				i = (int)(msg->refer_to->name.s + msg->refer_to->len -
						replaces->s - replaces->len);
				if(RT_BUF_LEN<=(int)(rt.s - &rt_buf[0] + rt.len + i))
				{
					LM_ERR("Not enough space to build Refer-To: "
						"RT_BUF_LEN<=[%d]\n",
						(int)(rt.s - &rt_buf[0] + rt.len + i));
					goto done;
				}
				memcpy(rt.s + rt.len, replaces->s + replaces->len, i);
				rt.len = (int)(rt.s + rt.len + i - &rt_buf[0]);
				rt.s = &rt_buf[0];
				LM_DBG("New Refer-To: [%.*s]\n", rt.len, rt.s);

				/* build extra headers */
				if(b2b_extra_headers(msg, NULL, &rt, &extra_headers)< 0)
				{
					LM_ERR("Failed to construct extra headers\n");
					goto done;
				}
			}
			else
			{	/* build extra headers */
				rt_header.s = msg->refer_to->name.s;
				rt_header.len = msg->refer_to->len;
				if(b2b_extra_headers(msg, NULL, &rt_header, &extra_headers)< 0)
				{
					LM_ERR("Failed to construct extra headers\n");
					goto done;
				}
			}
		}
		else
		{	/* build extra headers */
			if(b2b_extra_headers(msg, NULL, NULL, &extra_headers)< 0)
			{
				LM_ERR("Failed to construct extra headers\n");
				goto done;
			}
		}
		ret = b2b_logic_notify_request(src, msg, key, &body, &extra_headers,
						b2bl_key, hash_index, local_index, flags);
	}
	else
	{
		LM_ERR("got notification for [%.*s] from [%.*s] with unknown event type [%d]\n",
			b2bl_key->len, b2bl_key->s, key->len, key->s, type);
	}
done:
	if(new_body.s)
		pkg_free(new_body.s);
	if(extra_headers.s)
		pkg_free(extra_headers.s);
	return ret;
}

int b2b_server_notify(struct sip_msg* msg, str* key, int type,
		str *logic_key, void* param, int flags)
{
	return b2b_logic_notify(B2B_SERVER, msg, key, type, logic_key, flags);
}


int b2b_client_notify(struct sip_msg* msg, str* key, int type,
		str *logic_key, void* param, int flags)
{
	return b2b_logic_notify(B2B_CLIENT, msg, key, type, logic_key, flags);
}

static char fromtag_buf[MD5_LEN];
static void gen_fromtag(str* callid, str* fromtag, str* uri, struct sip_msg* msg, str* from_tag_uac)
{
	int i = 0;
	str src[4];

	from_tag_uac->len = MD5_LEN;
	from_tag_uac->s = fromtag_buf;

	src[i++] = *callid;
	src[i++] = *fromtag;
	src[i++] = *uri;
	if(msg)
	{
		if (msg->via1->branch) {
			src[i++] = msg->via1->branch->value;
		}
		else
		{
			src[i++] = msg->callid->body;
		}
	}
	MD5StringArray(from_tag_uac->s, src, i);
	LM_DBG("Gen from_tag= %s\n", fromtag_buf);
}


str* create_top_hiding_entities(struct sip_msg* msg, b2bl_cback_f cbf,
	void* cb_param, unsigned int cb_mask, str* custom_hdrs, struct b2b_params *params)
{
	str* server_id = NULL;
	str* client_id = NULL;
	str body = {NULL, 0};
	str extra_headers = {NULL, 0};
	str* b2bl_key;
	b2bl_tuple_t* tuple;
	struct b2b_context *ctx;
	unsigned int hash_index;
	b2b_dlginfo_t* dlginfo, dlginfo_s;
	client_info_t ci;
	str to_uri={NULL, 0}, from_uri, from_dname;
	b2bl_entity_id_t* client_entity = NULL;
	int idx;
	str uri;
	qvalue_t q;
	str from_tag_gen= {0, 0};
	str new_body={0, 0};
	struct sip_uri ct_uri;
	int maxfwd;

	if (!str_match((_str("INVITE")), &msg->first_line.u.request.method)) {
		LM_ERR("Scenario must be initialized on INVITE but got method: %.*s\n",
			msg->first_line.u.request.method.len,
			msg->first_line.u.request.method.s);
		return NULL;
	}

	if(b2b_msg_get_from(msg, &from_uri, &from_dname)< 0 ||  b2b_msg_get_to(msg, &to_uri, params->flags)< 0)
	{
		LM_ERR("Failed to get to or from from the message\n");
		return NULL;
	}

	/* process the body */
	if(msg->content_length)
	{
		if ( get_body(msg, &body)!=0 )
		{
			LM_ERR("cannot extract body\n");
			return NULL;
		}
	}

	hash_index = core_hash(&to_uri, &from_uri, b2bl_hsize);
	b2bl_htable[hash_index].flags = params->flags;
	tuple = b2bl_insert_new(msg, hash_index, params,
				custom_hdrs, -1, &b2bl_key, INSERTDB_FLAG, TUPLE_NO_REPL);
	if(tuple== NULL)
	{
		LM_ERR("Failed to insert new scenario instance record\n");
		goto error;
	}
	tuple->cb.f = cbf;
	tuple->cb.mask = cb_mask;
	tuple->cb.param = cb_param;

	/* save tuple in global variable for accesss from local routes */
	local_ctx_tuple = tuple;

	/* set the context values already written in the request route */
	tuple->vals = local_ctx_vals;
	local_ctx_vals = NULL;

	/* save tuple in context for access in the request route */
	ctx = b2b_api.get_context();
	if (!ctx) {
		LM_ERR("Failed to get b2b context\n");
		goto error;
	}
	ctx->init = 1;
	ctx->hash_index = hash_index;
	ctx->local_index = tuple->id;

	/* if it will not be confirmed -> delete */
	if (params->init_timeout == 0)
		tuple->lifetime = max_duration + get_ticks();
	else
		tuple->lifetime = params->init_timeout + get_ticks();

	/* create new server */
	server_id = b2b_api.server_new(msg, &tuple->local_contact, b2b_server_notify,
			&b2bl_mod_name, b2bl_key, get_tracer(tuple), NULL, NULL);
	if(server_id == NULL)
	{
		LM_ERR("failed to create new b2b server instance\n");
		goto error;
	}

	tuple->servers[0] = b2bl_create_new_entity(B2B_SERVER, server_id, &to_uri,
		0, &from_uri, 0,0,0,0, msg);
	if(tuple->servers[0] == NULL)
	{
		LM_ERR("Failed to create server entity\n");
		goto error;
	}
	tuple->servers[0]->type = B2B_SERVER;
	tuple->servers[0]->no = 0;

	if (shm_str_dup(&tuple->servers[0]->in_sdp, &body) < 0) {
		LM_ERR("Failed to save SDP\n");
		goto error;
	}

	if(b2b_extra_headers(msg, b2bl_key, custom_hdrs, &extra_headers)< 0)
	{
		LM_ERR("Failed to create extra headers\n");
		goto error;
	}
	/* create new client */
	memset(&ci, 0, sizeof(client_info_t));
	ci.method        = msg->first_line.u.request.method;
	ci.req_uri       = *(GET_RURI(msg));
	ci.to_uri        = to_uri;
	ci.from_uri      = from_uri;
	ci.from_dname    = from_dname;
	ci.dst_uri       = msg->dst_uri;
	ci.extra_headers = &extra_headers;
	ci.body          = (body.s?&body:NULL);
	ci.send_sock     = msg->force_send_socket;
	ci.pref_sock     = msg->rcv.bind_address;

	memset(&ct_uri, 0, sizeof(struct sip_uri));
	if (contact_user && parse_uri(ci.from_uri.s, ci.from_uri.len, &ct_uri) < 0) {
		LM_ERR("Not a valid sip uri [%.*s]\n", ci.from_uri.len, ci.from_uri.s);
		goto error;
	}
	get_local_contact((ci.send_sock?ci.send_sock:ci.pref_sock), &ct_uri.user, &ci.local_contact);

	/* grab all AVPs from the server side and push them into the client */
	ci.avps = clone_avp_list( *get_avp_list() );

	dlginfo = tuple->servers[0]->dlginfo;
	gen_fromtag(&dlginfo->callid, &dlginfo->fromtag, &ci.req_uri, msg, &from_tag_gen);
	ci.from_tag = &from_tag_gen;

	if (str2int( &(get_cseq(msg)->number), &ci.cseq)!=0 )
	{
		LM_ERR("cannot parse cseq number\n");
		goto error;
	}

	/* Decrement Max-Forwards value */
	if ((maxfwd = b2b_msg_get_maxfwd(msg)) > 0)
		ci.maxfwd = maxfwd;

	client_id = b2b_api.client_new(&ci, b2b_client_notify, b2b_add_dlginfo,
			&b2bl_mod_name, b2bl_key, get_tracer(tuple), NULL, NULL);

	if(client_id == NULL)
	{
		LM_ERR("failed to create new b2b client instance\n");
		goto error;
	}

	client_entity = b2bl_create_new_entity(B2B_CLIENT, client_id, &to_uri, 0,
		&from_uri, 0, 0, 0, 0, 0);
	if(client_entity == NULL)
	{
		LM_ERR("Failed to create server entity\n");
		goto error;
	}

	memset(&dlginfo_s, 0, sizeof(b2b_dlginfo_t));
	dlginfo_s.callid = *client_id;
	dlginfo_s.totag = from_tag_gen;
	if(entity_add_dlginfo(client_entity, &dlginfo_s)< 0)
	{
		LM_ERR("Failed to add dialoginfo\n");
		goto error;
	}

	client_entity->no = 1;
	client_entity->peer = tuple->servers[0];
	tuple->clients[0] = client_entity;

	if (shm_str_dup(&client_entity->out_sdp, &body) < 0) {
		LM_ERR("Failed to save SDP\n");
		goto error;
	}

	for( idx=0 ; (uri.s=get_branch(idx,&uri.len,&q,0,0,0,0))!=0 ; idx++ )
	{
		LM_DBG("got branch ruri [%.*s]\n", uri.len, uri.s);
		gen_fromtag(&dlginfo->callid, &dlginfo->fromtag, &uri, msg, &from_tag_gen);
		ci.from_tag = &from_tag_gen;
		ci.req_uri = uri;
		ci.avps = clone_avp_list( *get_avp_list() );

		client_id = b2b_api.client_new(&ci, b2b_client_notify, b2b_add_dlginfo,
				&b2bl_mod_name, b2bl_key, get_tracer(tuple), NULL, NULL);

		if(client_id == NULL)
		{
			LM_ERR("failed to create new b2b client instance\n");
			goto error;
		}
		client_entity = b2bl_create_new_entity(B2B_CLIENT, client_id, &to_uri, 0,
			&from_uri, 0, 0, 0, 0, 0);
		if (client_entity == NULL)
		{
			LM_ERR("Failed to create client entity\n");
			goto error;
		}
		client_entity->no = 1;
		client_entity->peer = tuple->servers[0];

		memset(&dlginfo_s, 0, sizeof(b2b_dlginfo_t));
		dlginfo_s.callid = *client_id;
		dlginfo_s.totag = from_tag_gen;
		if(entity_add_dlginfo(client_entity, &dlginfo_s)< 0)
		{
			LM_ERR("Failed to add dialoginfo\n");
			goto error;
		}

		/* Add the client entity to the list */
		tuple->clients[0]->prev = client_entity;
		client_entity->next = tuple->clients[0];
		tuple->clients[0] = client_entity;
	}

	tuple->servers[0]->peer = tuple->clients[0];
	tuple->bridge_entities[0] = tuple->servers[0];
	tuple->bridge_entities[1] = tuple->clients[0];
	b2bl_print_tuple(tuple, L_DBG);

	if(b2bl_db_mode == WRITE_THROUGH)
	{
		b2bl_db_insert(tuple);
	}

	B2BL_LOCK_RELEASE(hash_index);

	local_ctx_tuple = NULL;

	pkg_free(to_uri.s);
	pkg_free(server_id);
	pkg_free(client_id);
	if(extra_headers.s)
		pkg_free(extra_headers.s);
	if(new_body.s)
		pkg_free(new_body.s);
	return b2bl_key;
error:
	B2BL_LOCK_RELEASE(hash_index);
	if(server_id)
		pkg_free(server_id);
	if(client_id)
		pkg_free(client_id);
	if(to_uri.s)
		pkg_free(to_uri.s);
	if(extra_headers.s)
		pkg_free(extra_headers.s);
	if(new_body.s)
		pkg_free(new_body.s);
	local_ctx_tuple = NULL;
	return NULL;
}

str *b2b_scenario_hdrs(struct b2bl_new_entity *entity)
{
	static int b2b_hdrs_buf_len;
	static str b2b_hdrs_buf = {0, 0};
	unsigned int len;
	char *tmp_buf;
	int_str name_value, body_value;
	struct usr_avp *avp_hdrs = NULL, *avp_hdr_vals = NULL;

	/* reset the buffer to fill in with new information */
	b2b_hdrs_buf.len = 0;

	avp_hdrs = search_first_avp(0, entity->avp_hdrs, &name_value, NULL);
	avp_hdr_vals = search_first_avp(0, entity->avp_hdr_vals, &body_value, NULL);

	for (; avp_hdrs; avp_hdrs = search_next_avp(avp_hdrs, &name_value),
		avp_hdr_vals = search_next_avp(avp_hdr_vals, &body_value)) {
		if (!avp_hdr_vals) {
			LM_ERR("Mismatch in the number of AVP values for the header names "
				"and header bodies\n");
			break;
		}

		if (!is_avp_str_val(avp_hdrs)) {
			LM_ERR("Header name must be a string\n");
			continue;
		}
		if (!is_avp_str_val(avp_hdr_vals))
			body_value.s.s = int2str(body_value.n, &body_value.s.len);

		trim(&name_value.s);
		trim(&body_value.s);
		LM_DBG("added header: <%.*s: %.*s>\n", name_value.s.len, name_value.s.s,
			body_value.s.len, body_value.s.s);

		len = name_value.s.len + 2 /* ': ' */ + body_value.s.len + 2 /* '\r\n' */;
		if (b2b_hdrs_buf.len + len > b2b_hdrs_buf_len) {
			tmp_buf = pkg_realloc(b2b_hdrs_buf.s, b2b_hdrs_buf.len + len);
			if (!tmp_buf) {
				LM_ERR("not enough memory to add header <%.*s: %.*s>\n",
					name_value.s.len, name_value.s.s,
					body_value.s.len, body_value.s.s);
				continue;
			}
			b2b_hdrs_buf.s = tmp_buf;
			b2b_hdrs_buf_len = b2b_hdrs_buf.len + len;
		}
		memcpy(b2b_hdrs_buf.s + b2b_hdrs_buf.len, name_value.s.s, name_value.s.len);
		b2b_hdrs_buf.len += name_value.s.len;
		memcpy(b2b_hdrs_buf.s + b2b_hdrs_buf.len, ": ", 2);
		b2b_hdrs_buf.len += 2;
		memcpy(b2b_hdrs_buf.s + b2b_hdrs_buf.len, body_value.s.s, body_value.s.len);
		b2b_hdrs_buf.len += body_value.s.len;
		memcpy(b2b_hdrs_buf.s + b2b_hdrs_buf.len, "\r\n", 2);
		b2b_hdrs_buf.len += 2;
	}

	return b2b_hdrs_buf.len ? &b2b_hdrs_buf : NULL;
}

int udh_to_uri(str user, str host, str port, str* uri)
{
	int size;

	if(uri==0)
		return -1;
	size = user.len + host.len + port.len+7;
	LM_DBG("user:host:port [%.*s][%.*s][%.*s]\n",
		user.len, user.s, host.len, host.s, port.len, port.s);
	uri->s = (char*)pkg_malloc(size);
	if(uri->s == NULL)
	{
		LM_ERR("No more memory [%d]\n", size);
		return -1;
	}

	uri->len = sprintf(uri->s, "sip:%.*s%.*s%.*s", user.len, user.s,
			user.len?1:0,"@",host.len, host.s);
	if(port.s)
	{
		uri->len += sprintf(uri->s+uri->len, ":%.*s", port.len, port.s);
	}
	return 0;
}

str* b2bl_init_extern(struct b2b_params *init_params,
	b2bl_init_params_t *scen_params, str *e1_id, str *e2_id,
	b2bl_cback_f cbf, void* cb_param, unsigned int cb_mask)
{
	unsigned int hash_index;
	b2bl_tuple_t* tuple= NULL;
	str* b2bl_key;
	struct b2bl_new_entity e1, e2;
	struct b2bl_new_entity *new_br_ent[2] = {&e1, &e2};

	hash_index = core_hash(&scen_params->e1_to, &scen_params->e2_to, b2bl_hsize);

	LM_DBG("start: bridge [%.*s] with [%.*s]\n", scen_params->e1_to.len,
		scen_params->e1_to.s, scen_params->e2_to.len, scen_params->e2_to.s);

	tuple = b2bl_insert_new(NULL, hash_index, init_params,
		NULL, -1, &b2bl_key, INSERTDB_FLAG, TUPLE_NO_REPL);
	if(tuple== NULL)
	{
		LM_ERR("Failed to insert new scenario instance record\n");
		return 0;
	}
	tuple->cb.f = cbf;
	tuple->cb.mask = cb_mask;
	tuple->cb.param = cb_param;
	tuple->lifetime = 60 + get_ticks();

	local_ctx_tuple = tuple;

	/* set the context values given in the b2b_trigger_scenario MI cmd */
	tuple->vals = local_ctx_vals;
	local_ctx_vals = NULL;
	if (scen_params->ctx_key.len)
		store_ctx_value(&tuple->vals, &scen_params->ctx_key, &scen_params->ctx_val);

	memset(&e1, 0, sizeof e1);
	memset(&e2, 0, sizeof e1);

	e1.type = scen_params->e1_type;
	e1.dest_uri = scen_params->e1_to;
	e1.from_dname = scen_params->e1_from_dname;
	if (e1_id)
		e1.id = *e1_id;

	e2.type = scen_params->e2_type;
	e2.dest_uri = scen_params->e2_to;
	e2.from_dname = scen_params->e2_from_dname;
	if (e2_id)
		e2.id = *e2_id;

	if (b2bl_bridge(NULL, tuple, hash_index, NULL, new_br_ent,
		NULL, 0) < 0) {
		LM_ERR("Failed to process bridge action\n");
		goto error;
	}

	local_ctx_tuple = NULL;

	B2BL_LOCK_RELEASE(hash_index);

	return b2bl_key;

error:
	if(tuple) {
		B2BL_LOCK_RELEASE(hash_index);
	}
	local_ctx_tuple = NULL;
	return 0;
}

str* b2b_process_scenario_init(struct sip_msg* msg, b2bl_cback_f cbf,
	void* cb_param, unsigned int cb_mask, str* custom_hdrs,
	struct b2b_params *init_params)
{
	str* server_id= NULL, *client_id= NULL;
	str body= {NULL, 0};
	str method = {INVITE, INVITE_LEN};
	str* b2bl_key = NULL;
	b2bl_tuple_t* tuple= NULL;
	struct b2b_context *ctx;
	b2bl_entity_id_t* client_entity = NULL;
	client_info_t ci;
	unsigned int hash_index;
	str to_uri={NULL, 0}, from_uri, from_dname;
	int eno = 0;
	str *hdrs;
	struct b2bl_new_entity *new_entity;
	struct b2bl_new_entity *e1, *e2;
	int maxfwd;

	if(msg == NULL)
	{
		LM_ERR("NO SIP message\n");
		goto error;
	}

	if (!str_match(&method, &msg->first_line.u.request.method)) {
		LM_ERR("Scenario must be initialized on INVITE but got method: %.*s\n",
			msg->first_line.u.request.method.len,
			msg->first_line.u.request.method.s);
		goto error;
	}

	if(b2b_msg_get_from(msg, &from_uri, &from_dname)< 0 ||
	b2b_msg_get_to(msg, &to_uri, init_params->flags)< 0)
	{
		LM_ERR("Failed to get to or from from the message\n");
		goto error;
	}
	hash_index = core_hash(&to_uri, &from_uri, b2bl_hsize);

	method = msg->first_line.u.request.method;

	if(msg->content_length)
	{
		if ( get_body(msg, &body)!=0 )
		{
			LM_ERR("cannot extract body\n");
			goto error;
		}
	}

	/* create new scenario instance record */
	tuple = b2bl_insert_new(msg, hash_index, init_params,
		custom_hdrs, -1, &b2bl_key, INSERTDB_FLAG, TUPLE_NO_REPL);
	if(tuple== NULL)
	{
		LM_ERR("Failed to insert new scenario instance record\n");
		goto error;
	}
	if (init_params->init_timeout == 0)
		tuple->lifetime = max_duration + get_ticks();
	else
		tuple->lifetime = init_params->init_timeout + get_ticks();

	/* save tuple in global variable for accesss from local routes */
	local_ctx_tuple = tuple;

	/* set the context values already written in the request route */
	tuple->vals = local_ctx_vals;
	local_ctx_vals = NULL;

	/* save tuple in context for access in the request route */
	ctx = b2b_api.get_context();
	if (!ctx) {
		LM_ERR("Failed to get b2b context\n");
		goto error;
	}
	ctx->init = 1;
	ctx->hash_index = hash_index;
	ctx->local_index = tuple->id;

	if (get_new_entities(&e1, &e2) < 0) {
		LM_ERR("Failed to get new bridging entities from context\n");
		goto error;
	}

	if (!e1 && !e2) {
		LM_ERR("Two bridge entities required!\n");
		goto error;
	}

	if (e1->type == B2B_SERVER)
		new_entity = e1;
	else if (e2->type == B2B_SERVER)
		new_entity = e2;
	else {
		LM_ERR("Server entity required\n");
		goto error;
	}

	/* create new server entity */
	server_id = b2b_api.server_new(msg, new_entity->adv_contact.s ?
		&new_entity->adv_contact : &tuple->local_contact,
		b2b_server_notify, &b2bl_mod_name, b2bl_key,
		get_tracer(tuple), NULL, NULL);
	if(server_id == NULL)
	{
		LM_ERR("failed to create new b2b server instance\n");
		goto error;
	}
	hdrs = b2b_scenario_hdrs(new_entity);
	tuple->servers[0] = b2bl_create_new_entity(B2B_SERVER, server_id, &to_uri, 0,
		&from_uri, 0, new_entity->id.s ? &new_entity->id : NULL, hdrs,
		new_entity->adv_contact.s ? &new_entity->adv_contact : NULL, msg);
	tuple->servers[0]->no = eno++;
	tuple->bridge_entities[0] = tuple->servers[0];
	if(tuple->servers[0] == NULL)
	{
		LM_ERR("failed to create new server entity\n");
		pkg_free(server_id);
		goto error;
	}
	pkg_free(server_id);
	tuple->servers[0]->type = B2B_SERVER;

	if (shm_str_dup(&tuple->servers[0]->in_sdp, &body) < 0) {
		LM_ERR("Failed to save SDP\n");
		goto error;
	}

	new_entity = NULL;

	if (e1->type == B2B_CLIENT)
		new_entity = e1;
	else if (e2->type == B2B_CLIENT)
		new_entity = e2;
	else {
		LM_ERR("Client entity required\n");
		goto error;
	}

	hdrs = b2b_scenario_hdrs(new_entity);

	memset(&ci, 0, sizeof(client_info_t));
	ci.method        = method;
	ci.to_uri        = new_entity->dest_uri;
	ci.dst_uri       = new_entity->proxy;
	ci.from_uri      = from_uri;
	ci.from_dname    = from_dname;
	ci.extra_headers = tuple->extra_headers;
	ci.client_headers= hdrs;
	ci.body          = (body.s?&body:NULL);
	ci.send_sock     = msg->force_send_socket;
	ci.pref_sock     = msg->rcv.bind_address;

	/* Decrement Max-Forwards value */
	if ((maxfwd = b2b_msg_get_maxfwd(msg)) > 0) {
		ci.maxfwd = maxfwd;
		tuple->servers[0]->init_maxfwd = maxfwd;
	}

	if (new_entity->adv_contact.s) {
		ci.local_contact = new_entity->adv_contact;
	} else if (b2b_get_local_contact(msg, &ci.from_uri, &ci.local_contact) < 0) {
		LM_ERR("Failed to get local contact\n");
		goto error;
	}

	/* grab all AVPs from the server side */
	ci.avps = clone_avp_list( *get_avp_list() );
	if (str2int( &(get_cseq(msg)->number), &ci.cseq)!=0 ) {
		LM_ERR("cannot parse cseq number\n");
		goto error;
	}

	client_id = b2b_api.client_new(&ci, b2b_client_notify, b2b_add_dlginfo,
			&b2bl_mod_name, b2bl_key, get_tracer(tuple), NULL, NULL);

	pkg_free(to_uri.s);
	to_uri.s = 0;

	if(client_id == NULL)
	{
		LM_ERR("failed to create new b2b client instance\n");
		goto error;
	}

	client_entity = b2bl_create_new_entity(B2B_CLIENT, client_id,
		&new_entity->dest_uri, 0, &from_uri, 0,
		new_entity->id.s ? &new_entity->id : NULL, hdrs,
		new_entity->adv_contact.s ? &new_entity->adv_contact : NULL, 0);
	if(client_entity == NULL)
	{
		LM_ERR("failed to create new client entity\n");
		pkg_free(client_id);
		goto error;
	}
	pkg_free(client_id);

	if (0 != b2bl_add_client(tuple, client_entity))
		goto error;
	client_entity->no = eno++;
	tuple->bridge_entities[1] = tuple->clients[0];

	if (shm_str_dup(&client_entity->out_sdp, &body) < 0) {
		LM_ERR("Failed to save SDP\n");
		goto error;
	}

	tuple->bridge_entities[0]->peer = tuple->bridge_entities[1];
	tuple->bridge_entities[1]->peer = tuple->bridge_entities[0];

	tuple->cb.f = cbf;
	tuple->cb.mask = cb_mask;
	tuple->cb.param = cb_param;

	if(b2bl_db_mode == WRITE_THROUGH)
		b2bl_db_insert(tuple);

	local_ctx_tuple = NULL;

	b2bl_htable[hash_index].flags = init_params->flags;

	B2BL_LOCK_RELEASE(hash_index);

	return b2bl_key;

error:
	if(tuple)
	{
		b2bl_delete(tuple, hash_index, 1, 1);
		B2BL_LOCK_RELEASE(hash_index);
	}
	if(to_uri.s)
		pkg_free(to_uri.s);

	local_ctx_tuple = NULL;

	return NULL;
}


str *b2bl_init_request(struct sip_msg *msg, struct b2b_params *init_params,
	b2bl_cback_f cbf, void* cb_param, unsigned int cb_mask, str* custom_hdrs)
{
	str* key;
	int_str avp_val;

	/* parse message to extract needed info */
	if (parse_headers(msg, HDR_EOH_F, 0) < 0)
	{
		LM_ERR("failed to parse message\n");
		return NULL;
	}

	if(init_params->id == B2B_TOP_HIDING_ID_PTR)
		key = create_top_hiding_entities(msg, cbf, cb_param, cb_mask,
			custom_hdrs, init_params);
	else
		key = b2b_process_scenario_init(msg, cbf, cb_param, cb_mask,
			custom_hdrs, init_params);

	if(key)
	{
		if (b2bl_key_avp_name >= 0)
		{
			avp_val.s = *key;
			if ( add_avp(AVP_VAL_STR|b2bl_key_avp_type, b2bl_key_avp_name,
			avp_val)!=0)
			{
				LM_ERR("failed to build b2bl_key avp\n");
			}
		}
	}

	return key;
}

str* b2bl_api_init(struct sip_msg* msg, str *scen_name,
	b2bl_init_params_t *scen_params, b2bl_cback_f cbf, void* cb_param,
	unsigned int cb_mask, str* custom_hdrs)
{
	struct b2b_params init_params;
	struct b2bl_new_entity *new_ent;

	if (b2bl_key_avp_name >= 0)
		destroy_avps( b2bl_key_avp_type, b2bl_key_avp_name, 1);

	memset(&init_params, 0, sizeof init_params);
	init_params.init_timeout = b2bl_th_init_timeout;

	if (scen_name->len == B2B_TOP_HIDING_SCENARY_LEN &&
		!memcmp(B2B_TOP_HIDING_SCENARY, scen_name->s, scen_name->len))
		init_params.id = B2B_TOP_HIDING_ID_PTR;
	else
		init_params.id = B2B_INTERNAL_ID_PTR;

	if (init_params.id == B2B_TOP_HIDING_ID_PTR ||
		scen_params->e1_type == B2B_SERVER || scen_params->e2_type == B2B_SERVER) {
		if (!msg) {
			LM_ERR("No SIP message for server entity\n");
			goto error;
		}

		if (init_params.id == B2B_INTERNAL_ID_PTR) {
			new_ent = pkg_malloc(sizeof(struct b2bl_new_entity));
			if (!new_ent) {
				LM_ERR("No more pkg memory!\n");
				goto error;
			}
			memset(new_ent, 0, sizeof(struct b2bl_new_entity));

			new_ent->type = scen_params->e1_type;
			new_ent->dest_uri = scen_params->e1_to;
			new_ent->from_dname = scen_params->e1_from_dname;

			context_put_ptr(CONTEXT_GLOBAL, current_processing_ctx,
				new_ent_1_ctx_idx, new_ent);

			new_ent = pkg_malloc(sizeof(struct b2bl_new_entity));
			if (!new_ent) {
				LM_ERR("No more pkg memory!\n");
				goto error;
			}
			memset(new_ent, 0, sizeof(struct b2bl_new_entity));

			new_ent->type = scen_params->e2_type;
			new_ent->dest_uri = scen_params->e2_to;
			new_ent->from_dname = scen_params->e2_from_dname;

			context_put_ptr(CONTEXT_GLOBAL, current_processing_ctx,
				new_ent_2_ctx_idx, new_ent);
		}

		return b2bl_init_request(msg, &init_params, cbf, cb_param, cb_mask, custom_hdrs);
	} else {
		return b2bl_init_extern(&init_params, scen_params, NULL, NULL,
			cbf, cb_param, cb_mask);
	}

error:
	return NULL;
}


int b2bl_script_init_request(struct sip_msg *msg, str *id, struct b2b_params *init_params,
	void *req_route_ref, void *reply_route_ref)
{
	str* key;
	str auth_header;
	str* cust_headers;
	int ret = -1;

	if (cur_route_ctx.flags & (B2BL_RT_REQ_CTX|B2BL_RT_RPL_CTX)) {
		LM_ERR("The 'b2b_init_request' function cannot be used from the "
			"b2b_logic dedicated routes\n");
		return -1;
	}

	if (b2bl_key_avp_name >= 0)
		destroy_avps( b2bl_key_avp_type, b2bl_key_avp_name, 1);

	b2b_api.apply_lumps(msg);

	cust_headers = NULL;
	if (init_params->flags & B2BL_FLAG_TRANSPARENT_AUTH)
	{
		if (msg->authorization)
		{
			auth_header.s = msg->authorization->name.s;
			auth_header.len = msg->authorization->len;
			cust_headers = &auth_header;
		}
		if (msg->proxy_auth)
		{
			auth_header.s = msg->proxy_auth->name.s;
			auth_header.len = msg->proxy_auth->len;
			cust_headers = &auth_header;
		}
	}

	init_params->id = id;
	init_params->req_route = req_route_ref ?
		(struct script_route_ref *)req_route_ref : global_req_rt_ref;
	init_params->reply_route = reply_route_ref ?
		(struct script_route_ref *)reply_route_ref : global_reply_rt_ref;

	/* call the scenario init processing function */
	key = b2bl_init_request(msg, init_params, 0, NULL, 0, cust_headers);
	if(key) ret = 1;

	return ret;
}

static struct b2bl_new_entity *tmp_client_new(struct sip_msg *msg, str *id,
	str *dest_uri, str *proxy, pv_spec_t *hnames, pv_spec_t *hvals, str *from_dname)
{
	unsigned short type;
	struct b2bl_new_entity *entity;
	struct sip_uri sip_uri;

	if (hnames && !hvals) {
		LM_ERR("header names without values!\n");
		return NULL;
	}
	if (!hnames && hvals) {
		LM_ERR("header values without names!\n");
		return NULL;
	}

	entity = pkg_malloc(sizeof *entity + id->len + (dest_uri?dest_uri->len:0) +
		(from_dname?from_dname->len:0)+ (proxy?proxy->len:0));
	if (!entity) {
		LM_ERR("out of pkg memory!\n");
		return NULL;
	}
	memset(entity, 0, sizeof *entity);

	if (hnames && pv_get_avp_name(msg, &hnames->pvp, &entity->avp_hdrs,
		&type) < 0) {
		LM_ERR("cannot resolve header names AVP\n");
		goto error;
	}
	if (hvals && pv_get_avp_name(msg, &hvals->pvp, &entity->avp_hdr_vals,
		&type) < 0) {
		LM_ERR("cannot resolve header values AVP\n");
		goto error;
	}

	entity->id.s = (char *)(entity + 1);
	entity->id.len = id->len;
	memcpy(entity->id.s, id->s, id->len);

	if (dest_uri) {
		entity->dest_uri.s = (char *)(entity + 1) + id->len;
		entity->dest_uri.len = dest_uri->len;
		memcpy(entity->dest_uri.s, dest_uri->s, dest_uri->len);

		trim(&entity->dest_uri);
		if (entity->dest_uri.s[0] == '<') {
			entity->dest_uri.s++;
			entity->dest_uri.len-=2;
		}
		if (parse_uri(entity->dest_uri.s, entity->dest_uri.len,
			&sip_uri) < 0) {
			LM_ERR("Not a valid sip uri [%.*s]\n",
				entity->dest_uri.len, entity->dest_uri.s);
			goto error;
		}
	}

	if (proxy) {
		entity->proxy.s = (char *)(entity + 1) + id->len + dest_uri->len;
		entity->proxy.len = proxy->len;
		memcpy(entity->proxy.s, proxy->s, proxy->len);

		trim(&entity->proxy);
		if (entity->proxy.s[0] == '<') {
			entity->proxy.s++;
			entity->proxy.len-=2;
		}
		if (parse_uri(entity->proxy.s, entity->proxy.len,
			&sip_uri) < 0) {
			LM_ERR("Not a valid sip uri [%.*s]\n",
				entity->proxy.len, entity->proxy.s);
			goto error;
		}
	}

	if (from_dname) {
		entity->from_dname.s = (char *)(entity + 1) + id->len + dest_uri->len +
			proxy->len;
		entity->from_dname.len = from_dname->len;
		memcpy(entity->from_dname.s, from_dname->s, from_dname->len);
	}

	entity->type = B2B_CLIENT;

	return entity;
error:
	pkg_free(entity);
	return NULL;
}

int script_trigger_scenario(struct sip_msg* msg, str *id, str * params,
	str *ent1, pv_spec_t *ent1_hnames, pv_spec_t *ent1_hvals,
	str *ent2, pv_spec_t *ent2_hnames, pv_spec_t *ent2_hvals)
{
	csv_record *list1 = NULL, *list2 = NULL, *param_list = NULL;
	int rc = -1;
	int ret;
	str *s;
	str *e1_id = NULL, *e2_id = NULL;
	str *e1_to = NULL, *e2_to = NULL;
	str *e1_proxy = NULL, *e2_proxy = NULL;
	str *e1_dname = NULL, *e2_dname = NULL;
	unsigned int hash_index, local_index, remote_tuple_hash_index;
	b2bl_tuple_t* tuple= NULL;
	b2bl_tuple_t* cur_tuple= NULL;
	str* b2bl_key;
	struct b2bl_new_entity *new_br_ent[2] = {NULL, NULL};
	struct b2b_params init_params;
	b2bl_entity_id_t *entity;
	b2bl_entity_id_t** entity_head = NULL;

	str * remote_tuple = NULL;
	int remote_tuple_party = 0;

	memset(&init_params, 0, sizeof init_params);
	init_params.id = id;
	init_params.req_route = global_req_rt_ref;
	init_params.reply_route = global_reply_rt_ref;

	list1 = parse_csv_record(ent1);
	if (!list1) {
		LM_ERR("Failed to parse CSV record for entitity 1: %.*s\n", ent1->len, ent1->s);
		rc = -1;
		goto end;
	}

	s = &list1->s;
	if (!s->s || !s->len) {
		LM_ERR("Failed to parse CSV record for entitity 1: %.*s - no entity name (first parameter)\n", ent1->len, ent1->s);
		rc = -1;
		goto end;
	}
	e1_id = s;

	s = list1->next ? &list1->next->s : NULL;
	if (!s || !s->s || !s->len) {
		LM_ERR("Failed to parse CSV record for entitity 1: %.*s - no to_uri (second parameter)\n", ent1->len, ent1->s);
		rc = -1;
		goto end;
	}
	e1_to = s;

	s = list1->next->next ? &list1->next->next->s : NULL;
	if (s && s->s && s->len) {
		e1_proxy = s;
		s = list1->next->next->next ? &list1->next->next->next->s : NULL;
		if (s && s->s && s->len) {
			e1_dname = s;
		}
	}
	LM_DBG("First entity [%.*s]: To %.*s (Proxy %.*s, Displayname %.*s)\n",
		e1_id->len, e1_id->s, e1_to->len, e1_to->s,
		(e1_proxy ? e1_proxy->len : 0), 
		(e1_proxy ? e1_proxy->s : 0),
		(e1_dname ? e1_dname->len : 0), 
		(e1_dname ? e1_dname->s : 0)
		);

	new_br_ent[0] = tmp_client_new(msg, e1_id, e1_to, e1_proxy, ent1_hnames, ent1_hvals, e1_dname);
	if (!new_br_ent[0]) {
		LM_ERR("Failed to create entity 1\n");
		rc = -1;
		goto end;
	}

	list2 = parse_csv_record(ent2);
	if (!list2) {
		LM_ERR("Failed to parse CSV record for entitity 2: %.*s\n", ent2->len, ent2->s);
		rc = -1;
		goto end;
	}

	s = &list2->s;
	if (!s->s || !s->len) {
		LM_ERR("Failed to parse CSV record for entitity 2: %.*s - no entity name (first parameter)\n", ent2->len, ent2->s);
		rc = -1;
		goto end;
	}
	e2_id = s;

	s = list2->next ? &list2->next->s : NULL;
	if (!s || !s->s || !s->len) {
		LM_ERR("Failed to parse CSV record for entitity 1: %.*s - no to_uri (second parameter)\n", ent2->len, ent2->s);
		rc = -1;
		goto end;
	}
	e2_to = s;

	s = list2->next->next ? &list2->next->next->s : NULL;
	if (s && s->s && s->len) {
		e2_proxy = s;
		s = list2->next->next->next ? &list1->next->next->next->s : NULL;
		if (s && s->s && s->len) {
			e2_dname = s;
		}
	}
	LM_DBG("Second entity [%.*s]: To %.*s (Proxy %.*s, Displayname %.*s)\n",
		e2_id->len, e2_id->s, e2_to->len, e2_to->s,
		(e2_proxy ? e2_proxy->len : 0), 
		(e2_proxy ? e2_proxy->s : 0),
		(e2_dname ? e2_dname->len : 0), 
		(e2_dname ? e2_dname->s : 0)
		);


	new_br_ent[1] = tmp_client_new(msg, e2_id, e2_to, e2_proxy, ent2_hnames, ent2_hvals, e2_dname);
	if (!new_br_ent[1]) {
		LM_ERR("Failed to create entity 2\n");
		rc = -1;
		goto end;
	}

	hash_index = core_hash(e1_to, e2_to, b2bl_hsize);

	tuple = b2bl_insert_new(msg, hash_index, &init_params,
		NULL, -1, &b2bl_key, INSERTDB_FLAG, TUPLE_NO_REPL);
	if(tuple== NULL)
	{
		LM_ERR("Failed to insert new scenario instance record\n");
		rc = -1;
		goto end;
	}
	tuple->lifetime = 60 + get_ticks();
	LM_DBG("Key: %.*s (%p)\n", b2bl_key->len, b2bl_key->s, tuple);

	if (params && params->s && params->len > 0) {
		param_list = parse_csv_record(params);
		if (!param_list) {
			LM_ERR("Failed to parse CSV record for Params: %.*s\n", params->len, params->s);
			rc = -1;
			goto end;
		}
		s = &param_list->s;
		if (!s->s || !s->len) {
			LM_ERR("Failed to parse CSV record for params: %.*s - no first parameter\n", params->len, params->s);
			rc = -1;
			goto end;
		}
		if (s->s[0] == 'n') {
			tuple->bridge_flags = B2BL_BR_FLAG_NOTIFY | B2BL_BR_FLAG_DONT_DELETE_BRIDGE_INITIATOR;
			s = param_list->next ? &param_list->next->s : NULL;
			if (s && s->s && s->len) {
				remote_tuple = s;
				s = param_list->next->next ? &param_list->next->next->s : NULL;
				if (s && s->s && s->len) {
					if (s->s[0] == '1') remote_tuple_party = 1;
				}
			}
		}
	}

	LM_DBG("Flags: %u (NOTIFY: %u)\n", tuple->bridge_flags, B2BL_BR_FLAG_NOTIFY);
	if (remote_tuple) LM_DBG("Remote tuple: %.*s (Party %i)\n", remote_tuple->len, remote_tuple->s, remote_tuple_party);

	if (tuple->bridge_flags & B2BL_BR_FLAG_NOTIFY) {
		if (remote_tuple) {
			ret = b2bl_get_tuple_key(remote_tuple, &remote_tuple_hash_index, &local_index);
			if(ret < 0)
			{
				if (ret == -1)
					LM_ERR("Failed to parse key or find an entity [%.*s]\n",
							remote_tuple->len, remote_tuple->s);
				else
					LM_ERR("Could not find entity [%.*s]\n",
							remote_tuple->len, remote_tuple->s);
				tuple->bridge_flags = 0;
			} else {
				/* extract the entity and delete the tuple */
				B2BL_LOCK_GET(remote_tuple_hash_index);

				cur_tuple = b2bl_search_tuple_safe(remote_tuple_hash_index, local_index);
				if(cur_tuple == NULL)
				{
					LM_ERR("No entity found\n");
					tuple->bridge_flags = 0;
				} else {
					LM_DBG("Found tuple\n");
					if (!cur_tuple->bridge_entities[remote_tuple_party] ||
					cur_tuple->bridge_entities[remote_tuple_party]->disconnected)
					{
						LM_ERR("Can not notify requested entity [%p]\n",
							cur_tuple->bridge_entities[remote_tuple_party]);
						tuple->bridge_flags = 0;
					} else {
						LM_DBG("Found entity\n");
						tuple->bridge_flags = B2BL_BR_FLAG_NOTIFY | B2BL_BR_FLAG_DONT_DELETE_BRIDGE_INITIATOR;
						tuple->bridge_initiator = cur_tuple->bridge_entities[remote_tuple_party];
						send_bridge_notify(cur_tuple->bridge_entities[remote_tuple_party], remote_tuple_hash_index, NULL);
					}
				}
				B2BL_LOCK_RELEASE(remote_tuple_hash_index);
			}
		} else {
			B2BL_LOCK_GET(cur_route_ctx.hash_index);
			cur_tuple = b2bl_search_tuple_safe(cur_route_ctx.hash_index,
				cur_route_ctx.local_index);
			if(cur_tuple == NULL) {
				LM_ERR("B2B logic record not found\n");
			} else {
				LM_DBG("Found tuple\n");
				entity = b2bl_search_entity(cur_tuple, &cur_route_ctx.entity_key,
					cur_route_ctx.entity_type, &entity_head);
				if (entity) {
					LM_DBG("Found entity\n");
					tuple->bridge_flags = B2BL_BR_FLAG_NOTIFY | B2BL_BR_FLAG_DONT_DELETE_BRIDGE_INITIATOR;
					tuple->bridge_initiator = entity;
					send_bridge_notify(entity, cur_route_ctx.hash_index, NULL);
				}
			}
			B2BL_LOCK_RELEASE(cur_route_ctx.hash_index);
		}
	}
	LM_DBG("Flags: %u (NOTIFY: %u)\n", tuple->bridge_flags, B2BL_BR_FLAG_NOTIFY);

	if (b2bl_bridge(msg, tuple, hash_index, NULL, new_br_ent,
		NULL, 0) < 0) {
		LM_ERR("Failed to process bridge action\n");
		goto error;
	}

	B2BL_LOCK_RELEASE(hash_index);

	rc = 1;
	goto end;
error:
	if(tuple) {
		B2BL_LOCK_RELEASE(hash_index);
	}
	local_ctx_tuple = NULL;
end:
	if (new_br_ent[0]) {
		pkg_free(new_br_ent[0]);
		new_br_ent[0] = NULL;
	}
	if (new_br_ent[1]) {
		pkg_free(new_br_ent[1]);
		new_br_ent[1] = NULL;
	}
	if (list1)
		free_csv_record(list1);
	if (list2)
		free_csv_record(list2);
	if (param_list)
		free_csv_record(param_list);

	return rc;
}

int b2bl_entity_new(struct sip_msg *msg, str *id, str *dest_uri, str *proxy,
	int etype, pv_spec_t *hnames, pv_spec_t *hvals, str *from_dname,
	str *adv_contact)
{
	unsigned short type;
	struct b2bl_new_entity *entity, *e1, *e2;
	struct sip_uri sip_uri;
	unsigned int size;

	if (get_new_entities(&e1, &e2) < 0) {
		LM_ERR("Failed to get new bridging entities from context\n");
		return -1;
	}

	if (e1 && e2) {
		LM_ERR("New bridge entities already created!\n");
		return -1;
	}

	if (hnames && !hvals) {
		LM_ERR("header names without values!\n");
		return -1;
	}
	if (!hnames && hvals) {
		LM_ERR("header values without names!\n");
		return -1;
	}

	size = sizeof *entity + id->len + (dest_uri?dest_uri->len:0) +
		(from_dname?from_dname->len:0)+ (proxy?proxy->len:0) +
		(adv_contact?adv_contact->len:0);

	entity = pkg_malloc(size);
	if (!entity) {
		LM_ERR("out of pkg memory!\n");
		return -1;
	}
	memset(entity, 0, sizeof *entity);

	if (hnames && pv_get_avp_name(msg, &hnames->pvp, &entity->avp_hdrs,
		&type) < 0) {
		LM_ERR("cannot resolve header names AVP\n");
		goto error;
	}
	if (hvals && pv_get_avp_name(msg, &hvals->pvp, &entity->avp_hdr_vals,
		&type) < 0) {
		LM_ERR("cannot resolve header values AVP\n");
		goto error;
	}

	size = sizeof *entity;

	entity->id.s = (char *)(entity + 1);
	entity->id.len = id->len;
	memcpy(entity->id.s, id->s, id->len);
	size += id->len;

	if (dest_uri) {
		entity->dest_uri.s = (char *)entity + size;
		entity->dest_uri.len = dest_uri->len;
		memcpy(entity->dest_uri.s, dest_uri->s, dest_uri->len);
		size += dest_uri->len;

		trim(&entity->dest_uri);
		if (entity->dest_uri.s[0] == '<') {
			entity->dest_uri.s++;
			entity->dest_uri.len-=2;
		}
		if (parse_uri(entity->dest_uri.s, entity->dest_uri.len,
			&sip_uri) < 0) {
			LM_ERR("Not a valid sip uri [%.*s]\n",
				entity->dest_uri.len, entity->dest_uri.s);
			goto error;
		}
	}

	if (proxy) {
		entity->proxy.s = (char *)entity + size;
		entity->proxy.len = proxy->len;
		memcpy(entity->proxy.s, proxy->s, proxy->len);
		size += proxy->len;

		trim(&entity->proxy);
		if (entity->proxy.s[0] == '<') {
			entity->proxy.s++;
			entity->proxy.len-=2;
		}
		if (parse_uri(entity->proxy.s, entity->proxy.len,
			&sip_uri) < 0) {
			LM_ERR("Not a valid sip uri [%.*s]\n",
				entity->proxy.len, entity->proxy.s);
			goto error;
		}
	}

	if (from_dname) {
		entity->from_dname.s = (char *)entity + size;
		entity->from_dname.len = from_dname->len;
		memcpy(entity->from_dname.s, from_dname->s, from_dname->len);
		size += from_dname->len;
	}

	if (adv_contact) {
		entity->adv_contact.s = (char *)entity + size;
		entity->adv_contact.len = adv_contact->len;
		memcpy(entity->adv_contact.s, adv_contact->s, adv_contact->len);
		size += adv_contact->len;
	}

	entity->type = etype;

	if (!e1) {
		context_put_ptr(CONTEXT_GLOBAL, current_processing_ctx,
			new_ent_1_ctx_idx, entity);
		LM_DBG("First new entity [%.*s] saved in context\n", id->len, id->s);
	} else {
		context_put_ptr(CONTEXT_GLOBAL, current_processing_ctx,
			new_ent_2_ctx_idx, entity);
		LM_DBG("Second new entity [%.*s] saved in context\n", id->len, id->s);
	}

	return 1;
error:
	pkg_free(entity);
	return -1;
}

int b2bl_server_new(struct sip_msg *msg, str *id, str *adv_contact,
	pv_spec_t *hnames, pv_spec_t *hvals)
{
	if (cur_route_ctx.flags & (B2BL_RT_REQ_CTX|B2BL_RT_RPL_CTX)) {
		LM_ERR("The 'b2b_server_new' function cannot be used from the "
			"b2b_logic dedicated routes\n");
		return -1;
	}

	return b2bl_entity_new(msg, id, NULL, NULL, B2B_SERVER, hnames, hvals, NULL,
		adv_contact);
}

int b2bl_client_new(struct sip_msg *msg, str *id, str *dest_uri, str *proxy,
	 str *from_dname, str *adv_contact, pv_spec_t *hnames, pv_spec_t *hvals)
{
	return b2bl_entity_new(msg, id, dest_uri, proxy, B2B_CLIENT,
		hnames, hvals, from_dname, adv_contact);
}

int b2bl_terminate_call(str* key)
{
	unsigned int hash_index, local_index;
	b2bl_tuple_t* tuple;

	if(b2bl_parse_key(key, &hash_index, &local_index) < 0)
	{
		LM_ERR("Failed to parse key\n");
		return -1;
	}

	B2BL_LOCK_GET(hash_index);

	tuple = b2bl_search_tuple_safe(hash_index, local_index);
	if(tuple == NULL)
	{
		LM_DBG("No entity found [%.*s]\n", key->len, key->s);
		B2BL_LOCK_RELEASE(hash_index);
		return -1;
	}

	local_ctx_tuple = tuple;

	b2b_end_dialog(tuple->bridge_entities[0], tuple, hash_index);
	b2b_end_dialog(tuple->bridge_entities[1], tuple, hash_index);

	b2b_mark_todel(tuple);

	local_ctx_tuple = NULL;

	B2BL_LOCK_RELEASE(hash_index);

	return 0;
}

int b2bl_get_stats(str* key, b2bl_dlg_stat_t* stat)
{
	unsigned int hash_index, local_index;
	b2bl_tuple_t* tuple;

	if(b2bl_parse_key(key, &hash_index, &local_index) < 0)
	{
		LM_ERR("Failed to parse key\n");
		return -1;
	}

	B2BL_LOCK_GET(hash_index);

	tuple = b2bl_search_tuple_safe(hash_index, local_index);
	if(tuple == NULL)
	{
		LM_ERR("No entity found\n");
		B2BL_LOCK_RELEASE(hash_index);
		return -1;
	}

	if(stat && tuple->bridge_entities[0])
	{
		stat->start_time = tuple->bridge_entities[0]->stats.start_time;
		stat->setup_time = tuple->bridge_entities[0]->stats.setup_time;
		stat->call_time  = get_ticks() - stat->start_time;
		stat->key.s = NULL; stat->key.len = 0;
	}

	B2BL_LOCK_RELEASE(hash_index);

	return 0;
}

int b2bl_get_tuple_key(str *key, unsigned int *hash_index,
		unsigned int *local_index)
{
	int ret;
	str callid, from_tag, to_tag, *tuple;

	/* check to see if the key is specified as callid;from_tag;to_tag */
	from_tag.s = q_memchr(key->s, ';', key->len);
	if (!from_tag.s) {
		LM_DBG("there's no tuple separator: must be plain key: %.*s\n",
				key->len, key->s);
		tuple = key;
		goto end;
	}
	callid.s = key->s;
	callid.len = from_tag.s - callid.s;
	from_tag.s++;
	to_tag.s = q_memchr(from_tag.s, ';', key->len - callid.len - 1);
	if (!to_tag.s) {
		LM_DBG("invalid key format: %.*s\n", key->len, key->s);
		return -1;
	}
	from_tag.len = to_tag.s - from_tag.s;
	to_tag.s++;
	to_tag.len = key->s + key->len - to_tag.s;

	/* we've got the entity's coordinates, try to find the entity now */
	tuple = b2b_api.get_b2bl_key(&callid, &from_tag, &to_tag, NULL);
	if(!tuple) {
		LM_DBG("cannot find entity [%.*s]\n", key->len, key->s);
		return -2;
	}
end:
	ret = b2bl_parse_key(tuple, hash_index, local_index);
	if (key != tuple)
		pkg_free(tuple);
	return ret;
}
