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
#include <libxml/parser.h>
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

#include "records.h"
#include "pidf.h"
#include "b2b_logic.h"
#include "b2bl_db.h"
#include "entity_storage.h"

#define BUF_LEN  128

static str cancel_reason_hdr=
	{"Reason: SIP;cause=200;text=\"Call completed elsewhere\"\r\n", 55};
extern b2b_scenario_t* script_scenarios;
extern int b2bl_key_avp_name;
extern unsigned short b2bl_key_avp_type;

extern str b2bl_mod_name;

extern b2bl_tuple_t *local_ctx_tuple;
extern struct b2b_ctx_val *local_ctx_vals;

struct to_body* get_b2bl_from(struct sip_msg* msg);

int b2b_scenario_parse_uri(xmlNodePtr value_node, char* value_content,
		b2bl_tuple_t* tuple, struct sip_msg* msg, str* client_to);
str *b2b_scenario_hdrs(xmlNodePtr client_node, b2bl_tuple_t* tuple);

int post_cb_sanity_check(b2bl_tuple_t **tuple, unsigned int hash_index, unsigned int local_index,
			b2bl_entity_id_t **entity, int etype, str *ekey);
int udh_to_uri(str user, str host, str port, str* uri);
static str method_invite= {INVITE, INVITE_LEN};
static str method_ack   = {ACK, ACK_LEN};
static str method_bye   = {BYE, BYE_LEN};
static str method_cancel= {CANCEL, CANCEL_LEN};

static str ok = str_init("OK");
static str notAcceptable = str_init("Not Acceptable");
str requestTerminated = str_init("Request Terminated");

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

int b2b_add_dlginfo(str* key, str* entity_key, int src, b2b_dlginfo_t* dlginfo)
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
	lock_get(&b2bl_htable[hash_index].lock);

	tuple = b2bl_search_tuple_safe(hash_index, local_index);
	if(tuple == NULL)
	{
		LM_ERR("No entity found\n");
		lock_release(&b2bl_htable[hash_index].lock);
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
		lock_release(&b2bl_htable[hash_index].lock);
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
		lock_release(&b2bl_htable[hash_index].lock);
		return -1;
	}

	/* log the dialog pair */
	if(entity->peer && entity->peer->dlginfo)
	{
		LM_INFO("Dialog pair: [%.*s] - [%.*s]\n",
				entity->peer->dlginfo->callid.len, entity->peer->dlginfo->callid.s,
				dlginfo->callid.len, dlginfo->callid.s);
	}

	lock_release(&b2bl_htable[hash_index].lock);

	return 0;
}

int msg_add_dlginfo(b2bl_entity_id_t* entity, struct sip_msg* msg, str* totag)
{
	str callid, fromtag;
	b2b_dlginfo_t dlginfo;

	if( msg->callid==NULL || msg->callid->body.s==NULL)
	{
		LM_ERR("failed to parse callid header\n");
		return -1;
	}
	callid = msg->callid->body;

	if (msg->from->parsed == NULL)
	{
		if ( parse_from_header( msg )<0 )
		{
			LM_ERR("cannot parse From header\n");
			return -1;
		}
	}
	fromtag = ((struct to_body*)msg->from->parsed)->tag_value;

	if (totag)
		dlginfo.totag  = *totag;
	else {
		dlginfo.totag.s = 0;
		dlginfo.totag.len = 0;
	}
	dlginfo.callid = callid;
	dlginfo.fromtag= fromtag;

	if(entity_add_dlginfo(entity, &dlginfo) < 0)
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


b2bl_entity_id_t* b2bl_create_new_entity(enum b2b_entity_type type, str* entity_id,
		str* to_uri,str* from_uri,str*from_dname, str* ssid, str* hdrs, struct sip_msg* msg)
{
	unsigned int size;
	b2bl_entity_id_t* entity;

	size = sizeof(b2bl_entity_id_t) + ((ssid!=NULL)?ssid->len:0) +
		((entity_id!=NULL)?entity_id->len:0)+ ((to_uri !=NULL)?to_uri->len:0)
		+ ((from_uri!=NULL)?from_uri->len:0)+ ((from_dname!=NULL)?from_dname->len:0)
		+ ((hdrs!=NULL)?hdrs->len:0);

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
			b2bl_htable[hash_index].locked_by = process_no;
			b2b_api.send_request(&req_data);
			b2bl_htable[hash_index].locked_by = -1;

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
	tuple->scenario_state = B2B_CANCEL_STATE;
	LM_DBG("%p\n", tuple);
}

int process_bridge_dialog_end(b2bl_tuple_t* tuple, unsigned int hash_index,
	int entity_no, b2bl_entity_id_t* bentity)
{
	if(entity_no == 0) /* if a negative reply received from the server */
	{
		/* send cancel or bye to the peers */
		b2b_end_dialog(tuple->bridge_entities[1], tuple, hash_index);
		b2b_end_dialog(tuple->bridge_entities[2], tuple, hash_index);
		b2b_mark_todel(tuple);
	}
	else
	if(entity_no == 1)
	{
		/* if the media server in 2 stage connecting did not reply */
		if(tuple->bridge_entities[2])
		{
			/* media server did not reply with success */
			b2bl_delete_entity(bentity, tuple, hash_index, 1);

			tuple->bridge_entities[1] = tuple->bridge_entities[0];
			tuple->bridge_entities[0] = tuple->bridge_entities[2];
			tuple->bridge_entities[2] = NULL;

			tuple->bridge_entities[1]->peer = tuple->bridge_entities[0];
			tuple->bridge_entities[0]->peer = tuple->bridge_entities[1];
		}
		else
		{
			/* the entity to connect replied with negative reply */
			b2b_end_dialog(tuple->bridge_entities[0], tuple, hash_index);
			b2b_mark_todel(tuple);
		}
	}
	else
	{
		/* if the final destination replied with negative reply */
		b2b_end_dialog(tuple->bridge_entities[0], tuple, hash_index);
		b2b_end_dialog(tuple->bridge_entities[1], tuple, hash_index);
		b2b_mark_todel(tuple);
	}

	return 0;
}

int process_bridge_bye(struct sip_msg* msg,  b2bl_tuple_t* tuple,
	unsigned int hash_index, b2bl_entity_id_t* entity)
{
	int entity_no;
	b2b_rpl_data_t rpl_data;

	entity_no = bridge_get_entityno(tuple, entity);
	if(entity_no < 0)
	{
		LM_ERR("No match found\n");
		return -1;
	}

	memset(&rpl_data, 0, sizeof(b2b_rpl_data_t));
	PREP_RPL_DATA(entity);
	rpl_data.method =METHOD_BYE;
	rpl_data.code =200;
	rpl_data.text =&ok;
	b2b_api.send_reply(&rpl_data);

	return process_bridge_dialog_end(tuple, hash_index, entity_no, entity);
}


int process_bridge_negreply(b2bl_tuple_t* tuple,
		unsigned int hash_index, b2bl_entity_id_t* entity, struct sip_msg* msg)
{
	int entity_no;
	int ret;
	unsigned int local_index;
	b2bl_cback_f cbf = NULL;
	str ekey={NULL, 0};
	b2bl_cb_params_t cb_params;
	b2bl_dlg_stat_t stats;

	entity_no = bridge_get_entityno(tuple, entity);
	switch (entity_no)
	{
		case 0:
			/* mark that the first step of the bridging failed */
			tuple->scenario_state = B2B_NONE;
			break;
		case 1: break;
		default:
			LM_ERR("unexpected entity_no [%d] for tuple [%p]\n",
				entity_no, tuple);
			return -1;
	}

	/* call the callback for brigding failure  */
	cbf = tuple->cbf;
	if(cbf && (tuple->cb_mask&B2B_REJECT_CB))
	{
		memset(&cb_params, 0, sizeof(b2bl_cb_params_t));
		cb_params.param = tuple->cb_param;
		local_index = tuple->id;
		stats.start_time =  entity->stats.start_time;
		stats.setup_time = get_ticks() - entity->stats.start_time;
		stats.key.s = NULL; stats.key.len = 0;
		ekey.s = (char*)pkg_malloc(entity->key.len);
		if(ekey.s == NULL)
		{
			LM_ERR("No more memory\n");
			return -1;
		}
		memcpy(ekey.s, entity->key.s, entity->key.len);
		ekey.len = entity->key.len;
		cb_params.stat = &stats;
		cb_params.msg = msg;
		cb_params.entity = entity_no;

		lock_release(&b2bl_htable[hash_index].lock);

		ret = cbf(&cb_params, B2B_REJECT_CB);
		LM_DBG("ret = %d\n", ret);

		lock_get(&b2bl_htable[hash_index].lock);
		/* must search the tuple again
		 * you can't know what might have happened with it */
		if (0!=post_cb_sanity_check(&tuple, hash_index, local_index,
					&entity, entity->type, &ekey))
		{
			pkg_free(ekey.s);
			return 1;
		}
		pkg_free(ekey.s);

		if(ret == B2B_DROP_MSG_CB_RET)
		{
			/* drop the negative reply */
			if(entity_no == 1)
				b2bl_delete_entity(entity, tuple, hash_index, 1);
			return 1;
		}
	}
	return process_bridge_dialog_end(tuple, hash_index, entity_no, entity);
}

static b2bl_entity_id_t* b2bl_new_client(str* to_uri, str* from_uri,
		b2bl_tuple_t* tuple, str* ssid, str* hdrs, struct sip_msg* msg)
{
	client_info_t ci;
	str* client_id;
	b2bl_entity_id_t* entity;

	memset(&ci, 0, sizeof(client_info_t));
	ci.method        = method_invite;
	ci.to_uri        = *to_uri;
	ci.from_uri      = *from_uri;
	ci.extra_headers = tuple->extra_headers;
	ci.client_headers= hdrs;
	ci.body          = (tuple->sdp.s?&tuple->sdp:NULL);
	ci.from_tag      = NULL;
	ci.send_sock     = msg?(msg->force_send_socket?msg->force_send_socket:msg->rcv.bind_address):NULL;
	if (ci.send_sock) get_local_contact(ci.send_sock, NULL, &ci.local_contact);
	else ci.local_contact = server_address;

	if(msg)
	{
		if (str2int( &(get_cseq(msg)->number), &ci.cseq)!=0 )
		{
			LM_ERR("cannot parse cseq number\n");
			return NULL;
		}
	}

	LM_DBG("Send Invite without a body to a new client entity\n");

	b2bl_htable[tuple->hash_index].locked_by = process_no;

	client_id = b2b_api.client_new(&ci, b2b_client_notify,
			b2b_add_dlginfo, &b2bl_mod_name, tuple->key);

	b2bl_htable[tuple->hash_index].locked_by = -1;

	if(client_id == NULL)
	{
		LM_ERR("Failed to create client id\n");
		return NULL;
	}
	/* save the client_id in the structure */
	entity = b2bl_create_new_entity(B2B_CLIENT, client_id, &ci.to_uri,
			&ci.from_uri, 0, ssid, hdrs, 0);
	if(entity == NULL)
	{
		LM_ERR("failed to create new client entity\n");
		pkg_free(client_id);
		return NULL;
	}
	pkg_free(client_id);

	return entity;
}
int process_bridge_200OK(struct sip_msg* msg, str* extra_headers,
		str* body, b2bl_tuple_t* tuple, unsigned int hash_index,
		b2bl_entity_id_t* entity)
{
	str* client_id;
	b2bl_entity_id_t* bentity0, *bentity1;
	client_info_t ci;
	int entity_no;
	b2b_req_data_t req_data;

	bentity0 = tuple->bridge_entities[0];
	bentity1 = tuple->bridge_entities[1];

	if(bentity0 == NULL)
	{
		LM_ERR("Bridge entities 0 is NULL\n");
		b2b_mark_todel(tuple);
		return -1;
	}

	entity_no = bridge_get_entityno(tuple, entity);
	if(entity_no < 0)
	{
		LM_ERR("No match found\n");
		return -1;
	}
	LM_DBG("entity_no = %d, entity=%p, be[0]= %p\n", entity_no, entity, tuple->bridge_entities[0]);

	if(entity_no == 0) /* the first reply -> must send INVITE on the other side  */
	{
		if(bentity1->key.s && bentity1->state < B2BL_ENT_CONFIRMED) /* already been in this step*/
		{
			LM_ERR("A retransmission of the reply from the first leg\n");
			return -1;
		} else if (bentity1->state == B2BL_ENT_CONFIRMED && bentity0->sdp_type == B2BL_SDP_NORMAL) {
		/*
		 * if there is a 200 OK, from the first entity, and the second entity
		 * is already confirmed, then this means that it was a reply from the
		 * last re-invite, used to fix his SDP - simply ACK it
		 */
			/* send ACK without a body to the first entity */
			memset(&req_data, 0, sizeof(b2b_req_data_t));
			req_data.et =bentity0->type;
			req_data.b2b_key =&bentity0->key;
			req_data.method =&method_ack;
			req_data.dlginfo =bentity0->dlginfo;
			b2bl_htable[hash_index].locked_by = process_no;
			if(b2b_api.send_request(&req_data) < 0)
			{
				LM_ERR("Failed to send second ACK in bridging scenario\n");
				b2bl_htable[hash_index].locked_by = -1;
				return -1;
			}
			b2bl_htable[hash_index].locked_by = -1;
			/* mark the scenario as completed */
			if(tuple->next_scenario_state>= 0)
			{
				tuple->scenario_state = tuple->next_scenario_state;
				tuple->next_scenario_state = 0;
				LM_DBG("Updated tuple state = %d\n", tuple->scenario_state);
			}
			else
				tuple->scenario_state = B2B_NOTDEF_STATE;
			LM_DBG("Finished the bridging\n");
		} else if(bentity1->type == B2B_CLIENT && bentity1->state!=B2BL_ENT_CONFIRMED)
		{
			LM_DBG("Send invite to %.*s\n", bentity1->to_uri.len, bentity1->to_uri.s);
			memset(&ci, 0, sizeof(client_info_t));
			ci.method        = method_invite;
			ci.to_uri        = bentity1->to_uri;

			/* it matters if the entity is server or client */
			if(bentity0->type == B2B_CLIENT)
			{
				ci.from_uri      = bentity0->to_uri;
			}
			else
			if(bentity0->type == B2B_SERVER)
			{
				if(bentity1->from_uri.s)
					ci.from_uri = bentity1->from_uri;
				else
					ci.from_uri      = bentity0->from_uri;
				if(bentity1->from_dname.s)
					ci.from_dname = bentity1->from_dname;
				else
					ci.from_dname    = bentity0->from_dname;
				LM_DBG("From dname: %.*s\n", ci.from_dname.len, ci.from_dname.s);
			}

			ci.client_headers= &bentity1->hdrs;
			ci.extra_headers = extra_headers;
			ci.body          = body;
			ci.from_tag      = NULL;
			ci.send_sock     = msg->force_send_socket?msg->force_send_socket:msg->rcv.bind_address;
			get_local_contact(ci.send_sock, NULL, &ci.local_contact);

			if (str2int( &(get_cseq(msg)->number), &ci.cseq)!=0 )
			{
				LM_ERR("cannot parse cseq number\n");
				return -1;
			}
			bentity0->state = B2BL_ENT_CONFIRMED;

			b2bl_htable[hash_index].locked_by = process_no;

			client_id = b2b_api.client_new(&ci, b2b_client_notify,
					b2b_add_dlginfo, &b2bl_mod_name, tuple->key);

			b2bl_htable[hash_index].locked_by = -1;

			if(client_id == NULL)
			{
				LM_ERR("Failed to create new client entity\n");
				return -1;
			}

			/* save the client_id in the structure */
			entity = b2bl_create_new_entity(B2B_CLIENT, client_id, &ci.to_uri,
					&ci.from_uri, 0, &bentity1->scenario_id, &bentity1->hdrs, 0);
			if(entity == NULL)
			{
				LM_ERR("failed to create new client entity\n");
				pkg_free(client_id);
				return -1;
			}
			entity->no =1;
			pkg_free(client_id);
			b2bl_delete_entity(bentity1, tuple, hash_index, 1);

			tuple->bridge_entities[1] = entity;
			if (0 != b2bl_add_client(tuple, entity))
				return -1;
		}
		else
		{
			/* send reInvite */
			bentity1->stats.start_time = get_ticks();
			bentity1->stats.call_time = 0;

			memset(&req_data, 0, sizeof(b2b_req_data_t));
			req_data.et =bentity1->type;
			req_data.b2b_key =&bentity1->key;
			req_data.method =&method_invite;
			req_data.client_headers=&bentity1->hdrs;;
			req_data.extra_headers =extra_headers;
			req_data.body =body;
			req_data.dlginfo =bentity1->dlginfo;
			b2bl_htable[hash_index].locked_by = process_no;
			if(b2b_api.send_request(&req_data) < 0)
			{
				LM_ERR("Failed to send second INVITE in bridging scenario\n");
				b2bl_htable[hash_index].locked_by = -1;
				return -1;
			}
			b2bl_htable[hash_index].locked_by = -1;
			bentity1->sdp_type = body ? B2BL_SDP_NORMAL : B2BL_SDP_LATE;
			bentity1->state = B2BL_ENT_NEW;
		}
		tuple->bridge_entities[1]->peer = tuple->bridge_entities[0];
		tuple->bridge_entities[0]->peer = tuple->bridge_entities[1];
		/* store this sdp */
		if(tuple->b1_sdp.s)
			shm_free(tuple->b1_sdp.s);
		if (tuple->b1_sdp.s==tuple->sdp.s)
			tuple->sdp.s = 0;
		tuple->b1_sdp.s = 0;
		if(body)
		{
			tuple->b1_sdp.s	= (char*)shm_malloc(body->len);
			if(tuple->b1_sdp.s == NULL)
			{
				LM_ERR("No more memory\n");
				return -1;
			}
			memcpy(tuple->b1_sdp.s, body->s, body->len);
			tuple->b1_sdp.len = body->len;

			/* XXX: make sure this is safe */
			if (tuple->sdp.s && tuple->b1_sdp.s != tuple->sdp.s)
				shm_free(tuple->sdp.s);
			tuple->sdp = tuple->b1_sdp;
		}
	}
	else
	if(entity_no == 1) /* from provisional media server or from final destination */
	{
		/* the second -> send ACK with body to the first entity
		and ACK without a body to the second entity*/

		bentity1->state = B2BL_ENT_CONFIRMED;

		bentity1->stats.setup_time = get_ticks() - bentity1->stats.start_time;
		bentity1->stats.start_time = get_ticks();
		bentity0->stats.setup_time = get_ticks() - bentity0->stats.start_time;
		bentity0->stats.start_time = get_ticks();

		memset(&req_data, 0, sizeof(b2b_req_data_t));
		req_data.et =bentity0->type;
		req_data.b2b_key =&bentity0->key;
		req_data.method =&method_ack;
		req_data.extra_headers =extra_headers;
		req_data.body = (bentity0->sdp_type == B2BL_SDP_LATE) ? body : 0;
		req_data.dlginfo =bentity0->dlginfo;
		b2bl_htable[hash_index].locked_by = process_no;
		if(b2b_api.send_request(&req_data) < 0)
		{
			LM_ERR("Failed to send first ACK in bridging scenario\n");
			b2bl_htable[hash_index].locked_by = -1;
			return -1;
		}

		/* send ACK without a body to the second entity */
		memset(&req_data, 0, sizeof(b2b_req_data_t));
		req_data.et =bentity1->type;
		req_data.b2b_key =&bentity1->key;
		req_data.method =&method_ack;
		req_data.dlginfo =bentity1->dlginfo;
		if(b2b_api.send_request(&req_data) < 0)
		{
			LM_ERR("Failed to send second ACK in bridging scenario\n");
			b2bl_htable[hash_index].locked_by = -1;
			return -1;
		}
		b2bl_htable[hash_index].locked_by = -1;

		tuple->bridge_entities[1]->peer = tuple->bridge_entities[0];
		tuple->bridge_entities[0]->peer = tuple->bridge_entities[1];
		/* now I have finnished the BRIDGING scenario -> mark this in the record */
		if(tuple->bridge_entities[2] == NULL)
		{

			/* if there was a renew SDP type, we have to challenge the first
			 * entity again with an invite, just to update its SDP info */
			if (bentity0->sdp_type == B2BL_SDP_RENEW)
			{
				memset(&req_data, 0, sizeof(b2b_req_data_t));
				req_data.et =bentity0->type;
				req_data.b2b_key =&bentity0->key;
				req_data.method =&method_invite;
				req_data.client_headers=&bentity0->hdrs;
				req_data.extra_headers = extra_headers;
				req_data.body = body;
				req_data.dlginfo =bentity0->dlginfo;
				b2bl_htable[hash_index].locked_by = process_no;
				if(b2b_api.send_request(&req_data) < 0)
				{
					LM_ERR("Failed to send re-invite in bridging scenario\n");
					b2bl_htable[hash_index].locked_by = -1;
					return -1;
				}
				b2bl_htable[hash_index].locked_by = -1;
				/* after sending this invite, the first endpoint should have
				 * the proper SDP used */
				bentity0->sdp_type = B2BL_SDP_NORMAL;
			} else {
				/* bridging scenario should be done */

				if(tuple->next_scenario_state>= 0)
				{
					tuple->scenario_state = tuple->next_scenario_state;
					tuple->next_scenario_state = 0;
					LM_DBG("Updated tuple state = %d\n", tuple->scenario_state);
				}
				else
					tuple->scenario_state = B2B_NOTDEF_STATE;
				LM_DBG("Finished the bridging\n");
			}
		}
		else
		{
			/* contact the real destination */
			entity =  b2bl_new_client(&tuple->bridge_entities[2]->to_uri, &bentity0->from_uri,
					tuple, &tuple->bridge_entities[2]->scenario_id, &tuple->bridge_entities[2]->hdrs, msg);
			if(entity == NULL)
			{
				LM_ERR("Failed to generate new client\n");
				return -1;
			}
			entity->no = 1;
			b2bl_delete_entity(tuple->bridge_entities[2], tuple, hash_index, 1);
			if (0 != b2bl_add_client(tuple, entity))
				return -1;
			/* original destination connected in the second step */
			tuple->bridge_entities[2]= entity;
		}
	}
	else /* if a 200 OK from the final destination */
	{
		b2b_end_dialog(bentity1, tuple, hash_index);

		/* send reinvite to the initial server*/
		bentity0->stats.setup_time = get_ticks() - bentity0->stats.start_time;
		bentity0->stats.start_time = get_ticks();
		bentity0->sdp_type = B2BL_SDP_NORMAL;

		memset(&req_data, 0, sizeof(b2b_req_data_t));
		req_data.et =bentity0->type;
		req_data.b2b_key =&bentity0->key;
		req_data.method =&method_invite;
		req_data.client_headers=&bentity0->hdrs;
		req_data.extra_headers =extra_headers;
		req_data.body =body;
		req_data.dlginfo =bentity0->dlginfo;
		b2bl_htable[hash_index].locked_by = process_no;
		if(b2b_api.send_request(&req_data) < 0)
		{
			LM_ERR("Failed to send second Invite in bridging scenario\n");
			b2bl_htable[hash_index].locked_by = -1;
			return -1;
		}
		b2bl_htable[hash_index].locked_by = -1;
		bentity0->state = 0;

		tuple->bridge_entities[1] = tuple->bridge_entities[0];
		tuple->bridge_entities[0] = tuple->bridge_entities[2];
		tuple->bridge_entities[2] = NULL;

		tuple->bridge_entities[1]->peer = tuple->bridge_entities[0];
		tuple->bridge_entities[0]->peer = tuple->bridge_entities[1];
	}
	return 0;
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


#define SEND_REPLY_TO_PEER_OR_GOTO_DONE				\
do{								\
	memset(&rpl_data, 0, sizeof(b2b_rpl_data_t));		\
	rpl_data.et =peer->type;				\
	rpl_data.b2b_key =&peer->key;				\
	rpl_data.method =method_value;				\
	rpl_data.code =statuscode;				\
	rpl_data.text =&msg->first_line.u.reply.reason;		\
	rpl_data.body = body->s?body:NULL;			\
	rpl_data.extra_headers = extra_headers->s?extra_headers:NULL;\
	rpl_data.dlginfo =peer->dlginfo;			\
	b2bl_htable[hash_index].locked_by = process_no;	\
	if(b2b_api.send_reply(&rpl_data) < 0)			\
	{							\
		b2bl_htable[hash_index].locked_by = -1;	\
		LM_ERR("Sending reply failed - %d, [%.*s]\n",	\
			statuscode, peer->key.len, peer->key.s);\
		goto done;					\
	}							\
	b2bl_htable[hash_index].locked_by = -1;	\
}while(0)

int b2b_logic_notify_reply(int src, struct sip_msg* msg, str* key, str* body, str* extra_headers,
		str* b2bl_key, unsigned int hash_index, unsigned int local_index, int flags)
{
	b2bl_tuple_t* tuple;
	str method;
	b2b_scenario_t* scenario;
	b2bl_entity_id_t *entity, *peer, *e, *ent;
	b2bl_entity_id_t** entity_head = NULL;
	int statuscode;
	int ret;
	unsigned int method_value;
	int_str avp_val;
	b2bl_cback_f cbf = NULL;
	str ekey= {NULL, 0};
	b2bl_cb_params_t cb_params;
	b2b_req_data_t req_data;
	b2b_rpl_data_t rpl_data;
	b2b_dlginfo_t dlginfo;

	if (parse_headers(msg, HDR_EOH_F, 0) < 0)
	{
		LM_ERR("failed to parse message\n");
		return -1;
	}

	lock_get(&b2bl_htable[hash_index].lock);
	tuple = b2bl_search_tuple_safe(hash_index, local_index);
	if(tuple == NULL)
	{
		LM_ERR("B2B logic record not found\n");
		goto error;
	}
	scenario = tuple->scenario;

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
			LM_ERR("failed to build b2bl_key avp\n");
			return -1;
		}
	}

	method = get_cseq(msg)->method;
	if(parse_method(method.s, method.s+method.len, &method_value) == NULL)
	{
		LM_ERR("Failed to parse method\n");
		goto error;
	}

	statuscode = msg->first_line.u.reply.statuscode;

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

	if((scenario &&
			scenario->reply_rules) || tuple->scenario_state == B2B_BRIDGING_STATE)
	{
		if(tuple->scenario_state == B2B_BRIDGING_STATE) /* if in a predefined state */
		{
			LM_DBG("Received a reply [%d] while in BRIDGING scenario\n",
				statuscode);
			/* if the scenario state is B2B_BRIDGING_STATE -> we should have a reply for INVITE */
			/* extract the method from Cseq header */

			if(method_value != METHOD_INVITE)
			{
				LM_ERR("Wrong scenario state [B2B_BRIDGING_STATE] for this"
					" reply(for method %d)\n", method_value);
				goto error;
			}
			/* if a negative reply */
			if(statuscode >= 300)
			{
				entity->rejected = 1;
				ret = process_bridge_negreply(tuple, hash_index, entity, msg);

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
					b2bl_delete(tuple, hash_index, 1, 1);
					tuple = 0;
				}
				goto done;
			}
			else
			if(statuscode < 200)
			{
				goto done;
			}

			/* if a reply with 200 OK -> we have two possibilities- either the first 200OK or the final */
			if(process_bridge_200OK(msg, tuple->extra_headers,
						(body->s?body:0), tuple, hash_index, entity)< 0)
			{
				LM_ERR("Failed to process bridging 200OK for Invite\n");
				goto error;
			}
		}
		if(scenario && scenario->reply_rules)
		{
			/* TODO -> process and apply reply rules */
		}
		if(statuscode >= 300)
		{
			tuple->to_del = 1;
			tuple->lifetime = 30 + get_ticks();
		}
	}
	else
	{
		if(!peer)
		{
			LM_DBG("No peer found\n");
			goto done;
		}

		switch (method_value)
		{
		case METHOD_BYE:
			/* if no other scenario rules defined and this is the reply for BYE */
			SEND_REPLY_TO_PEER_OR_GOTO_DONE;
			LM_DBG("Received reply for BYE - delete\n");
			b2bl_delete(tuple, hash_index, 1, 1);
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
						b2bl_remove_single_entity(entity, entity_head, hash_index);
						peer->peer = *entity_head;
						tuple->bridge_entities[0] = tuple->servers[0];
						tuple->bridge_entities[1] = tuple->clients[0];
					}
					else
					{
						SEND_REPLY_TO_PEER_OR_GOTO_DONE;
						LM_DBG("Negative reply [%d] - delete[%p]\n",
							statuscode, tuple);
						b2b_mark_todel(tuple);
					}
					b2bl_print_tuple(tuple, L_DBG);
				}
				else
				if(statuscode >= 200 && statuscode < 300)
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
							b2bl_htable[hash_index].locked_by = process_no;
							if(b2b_api.send_request(&req_data) < 0)
							{
								LM_ERR("Sending request"
									" failed [%.*s]\n",
									e->key.len, e->key.s);
							}
							b2b_api.entity_delete(e->type, &e->key,
										e->dlginfo, 0, 1);
							b2bl_htable[hash_index].locked_by = -1;
							LM_DBG("destroying dlginfo=[%p]\n",
									e->dlginfo);
							if(e->dlginfo)
								shm_free(e->dlginfo);
							ent = e->next;
							shm_free(e);
							e = ent;
						}
						*entity_head = entity;
						peer->peer = entity;
						tuple->bridge_entities[0] = tuple->servers[0];
						tuple->bridge_entities[1] = tuple->clients[0];
					}

					if (flags & B2B_NOTIFY_FL_TERMINATED) {
						memset(&rpl_data, 0, sizeof(b2b_rpl_data_t));
						PREP_RPL_DATA(peer);
						rpl_data.method = METHOD_INVITE;
						rpl_data.code = 487;
						rpl_data.text = &requestTerminated;
						rpl_data.body = NULL;

						b2bl_htable[hash_index].locked_by = process_no;
						if(b2b_api.send_reply(&rpl_data) < 0) {
							b2bl_htable[hash_index].locked_by = -1;
							LM_ERR("Sending reply failed - %d, [%.*s]\n",
								rpl_data.code, peer->key.len, peer->key.s);
							goto done;
						}
						b2bl_htable[hash_index].locked_by = -1;

						LM_DBG("Sent 487 reply to peer after terminating entity "
							"[%.*s]\n", entity->key.len, entity->key.s);
						b2b_mark_todel(tuple);
						goto done;
					}

					entity->state = B2BL_ENT_CONFIRMED;
					peer->state = B2BL_ENT_CONFIRMED;
					entity->stats.setup_time = get_ticks() - entity->stats.start_time;
					entity->stats.start_time = get_ticks();
					SEND_REPLY_TO_PEER_OR_GOTO_DONE;
					b2bl_print_tuple(tuple, L_DBG);
					cbf = tuple->cbf;
					if(cbf && (tuple->cb_mask&B2B_CONFIRMED_CB))
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
						cb_params.param = tuple->cb_param;
						cb_params.stat = NULL;
						cb_params.msg = msg;
						cb_params.entity = entity->no;

						lock_release(&b2bl_htable[hash_index].lock);
						ret = cbf(&cb_params, B2B_CONFIRMED_CB);
						lock_get(&b2bl_htable[hash_index].lock);

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
								return -1;
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
			{	/* if reINVITE and 481 or 408 reply */
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
	}

done:
	if(tuple)
	{
		if(b2bl_db_mode == WRITE_THROUGH)
			b2bl_db_update(tuple);
		else
			UPDATE_DBFLAG(tuple);
	}
done1:
	lock_release(&b2bl_htable[hash_index].lock);
	return 0;
error:
	lock_release(&b2bl_htable[hash_index].lock);
	return -1;
}


int b2b_logic_notify_request(int src, struct sip_msg* msg, str* key, str* body, str* extra_headers,
		str* b2bl_key, unsigned int hash_index, unsigned int local_index, int flags)
{
	b2bl_tuple_t* tuple;
	str method;
	b2b_scenario_t* scenario;
	b2b_rule_t* rule;
	b2bl_entity_id_t* entity, *peer;
	b2bl_entity_id_t** entity_head = NULL;
	xmlNodePtr bridge_node, node;
	int state = -1;
	str attr;
	int ret;
	unsigned int method_value;
	int_str avp_val;
	b2bl_cback_f cbf = NULL;
	str ekey= {NULL, 0};
	int request_id;
	b2bl_cb_params_t cb_params;
	b2bl_dlg_stat_t stats;
	b2b_req_data_t req_data;
	b2b_rpl_data_t rpl_data;

	lock_get(&b2bl_htable[hash_index].lock);
	tuple = b2bl_search_tuple_safe(hash_index, local_index);
	if(tuple == NULL)
	{
		LM_ERR("B2B logic record not found\n");
		goto error;
	}
	scenario = tuple->scenario;

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
			LM_ERR("failed to build b2bl_key avp\n");
			return -1;
		}
	}

	method = msg->first_line.u.request.method;
	method_value = msg->first_line.u.request.method_value;
	/* extract body if it has a body */

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

	cbf = tuple->cbf;

	switch (request_id) {
	case B2B_BYE:
		entity->disconnected = 1;
		if(cbf && (tuple->cb_mask&B2B_BYE_CB))
		{
			memset(&cb_params, 0, sizeof(b2bl_cb_params_t));
			cb_params.param = tuple->cb_param;
			if(tuple->scenario_state != B2B_BRIDGING_STATE)
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

			lock_release(&b2bl_htable[hash_index].lock);
			LM_DBG("entity->no = %d\n", entity->no);
			ret = cbf(&cb_params, B2B_BYE_CB);
			LM_DBG("ret = %d, peer= %p\n", ret, peer);

			pkg_free(stats.key.s);
			lock_get(&b2bl_htable[hash_index].lock);
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

		if(tuple->scenario_state == B2B_BRIDGING_STATE)
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
			cb_params.param = tuple->cb_param;
			cb_params.stat = NULL;
			cb_params.msg = msg;
			cb_params.entity = entity->no;
			lock_release(&b2bl_htable[hash_index].lock);

			LM_DBG("entity->no = %d\n", entity->no);
			ret = cbf(&cb_params, B2B_RE_INVITE_CB);
			LM_DBG("ret = %d, peer= %p\n", ret, peer);

			lock_get(&b2bl_htable[hash_index].lock);
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
		break;

	case B2B_ACK:
		if (flags & B2B_NOTIFY_FL_ACK_NEG) {
			LM_DBG("ACK for a negative reply\n");
			goto done;
		}

		break;
	}

	if(!scenario || !scenario->request_rules[request_id])
	{
		if(request_id == B2B_BYE)
		{
			/* even though I don;t receive a reply,
			I should delete this record*/
			tuple->lifetime = 30 + get_ticks();
		}
		goto send_usual_request;
	}
	else
	{
		rule = scenario->request_rules[request_id];
		if(tuple->scenario_state != B2B_NOTDEF_STATE)
		{
			while(rule)
			{
				if(tuple->scenario_state == rule->cond_state)
				{
					break;
				}
				else
				{
					LM_DBG("State does not match found [%d], required [%d]\n",
							tuple->scenario_state, rule->cond_state);
				}
				rule = rule->next;
			}
			peer->sdp_type = body->len ? B2BL_SDP_NORMAL : B2BL_SDP_LATE;
		}
		if(!rule)
		{
			LM_DBG("Did not find a rule to apply for this request -> do normal pass through\n");
			goto send_usual_request;
		}
		else
		{
			LM_DBG("Found rule with id [%d]\n", rule->id);
		}
		/* if a match was found -> check the condition part */
		if(rule->cond_node)
		{
			node = xmlNodeGetChildByName(rule->cond_node, "sender");
			if(node)
			{
				LM_DBG("Found a sender condition\n");
				/* get the sender type */

				attr.s = (char*)xmlNodeGetNodeContentByName(node, "type", NULL);
				if(attr.s == NULL)
				{
					LM_ERR("Bad scenario document - sender condition node"
							" without a type child\n");
					goto error;
				}

				if(xmlStrcasecmp((unsigned char*)attr.s,(unsigned char*) "server") == 0)
				{
					/* check if it is a server request */
					if(src != B2B_SERVER)
					{
						xmlFree(attr.s);
						goto send_usual_request;
					}
				}
				else
				if(xmlStrcasecmp((unsigned char*) attr.s, (unsigned char*)"client") == 0)
				{
					if(src != B2B_CLIENT)
					{
						xmlFree(attr.s);
						goto send_usual_request;
					}
				}
				else
				{
					LM_ERR("Bad scenario document - sender condition type not"
							" known\n");
					xmlFree(attr.s);
					goto error;
				}
				xmlFree(attr.s);

				/* check the id */
				attr.s = xmlNodeGetNodeContentByName(node, "id", NULL);
				if(attr.s)
				{
					attr.len = strlen(attr.s);
					if((attr.len != entity->scenario_id.len ||
							strncmp(attr.s, entity->scenario_id.s, attr.len) != 0))
					{
						LM_DBG("Scenary id did not match - do not apply the rule"
								" found [%.*s] , required [%s]\n",
								entity->scenario_id.len, entity->scenario_id.s, attr.s);
						xmlFree(attr.s);
						goto send_usual_request;
					}
					xmlFree(attr.s);
				}
				LM_DBG("Sender condition match\n");
			}
			/* TODO - process other conditions */
		}

		/* apply actions */

		/* get next state */
		node = xmlNodeGetChildByName(rule->action_node, "state");
		if(node)
		{
			attr.s = (char*)xmlNodeGetContent(node);
			if(attr.s == NULL)
			{
				LM_ERR("No state node content found\n");
				goto error;
			}
			attr.len = strlen(attr.s);

			if(str2int(&attr, (unsigned int*)&state)< 0)
			{
				LM_ERR("Bad scenario. Scenary state not an integer\n");
				xmlFree(attr.s);
				goto error;
			}
			LM_DBG("Next scenario state is [%d]\n", state);
			xmlFree(attr.s);
		}

		/* handle bridge action */

		bridge_node = xmlNodeGetChildByName(rule->action_node, "bridge");
		if(bridge_node)
		{
			LM_DBG("Found a bridge node\n");

			if(process_bridge_action(msg, entity, tuple, hash_index, bridge_node) < 0)
			{
				LM_ERR("Failed to process bridge action\n");
				goto send_usual_request;
			}
			/* save next state */
			tuple->next_scenario_state = state;
		}
		else
		{
			/* set the next state now because the action has only one step */
			if(state >= 0)
				tuple->scenario_state = state;
		}

		node = xmlNodeGetChildByName(rule->action_node, "send_reply");
		if(node)
		{
			unsigned int code;

			LM_DBG("Found a send reply node\n");
			/* get code and text */
			attr.s = xmlNodeGetNodeContentByName(node, "code", NULL);
			if(attr.s == NULL)
			{
				LM_ERR("Bad scenario document - No code defined for send_reply node\n");
				goto error;
			}
			attr.len = strlen(attr.s);
			if(str2int(&attr, &code) < 0)
			{
				LM_ERR("Bad scenario - wrong reply code, not an integer\n");
				xmlFree(attr.s);
				goto error;
			}
			xmlFree(attr.s);

			attr.s = xmlNodeGetNodeContentByName(node, "reason", NULL);
			if(attr.s == NULL)
			{
				LM_ERR("Bad scenario document - No code defined for send_reply node\n");
				goto error;
			}
			attr.len = strlen(attr.s);

			memset(&rpl_data, 0, sizeof(b2b_rpl_data_t));
			PREP_RPL_DATA(entity);
			rpl_data.method =method_value;
			rpl_data.code =code;
			rpl_data.text =&attr;

			b2bl_htable[hash_index].locked_by = process_no;
			b2b_api.send_reply(&rpl_data);
			b2bl_htable[hash_index].locked_by = -1;
			LM_DBG("Send reply with code [%d] and text [%s]\n", code, attr.s);

			xmlFree(attr.s);
		}
		/* end_dialog_leg option */
		node = xmlNodeGetChildByName(rule->action_node, "end_dialog_leg");
		if(node)
		{
			LM_DBG("End dialog\n");
			entity->disconnected = 1;
			memset(&req_data, 0, sizeof(b2b_req_data_t));
			PREP_REQ_DATA(entity);
			req_data.method =&method_bye;
			b2bl_htable[hash_index].locked_by = process_no;
			b2b_api.send_request(&req_data);
			b2bl_htable[hash_index].locked_by = -1;
			if(entity->peer)
				entity->peer->peer = NULL;
			peer = entity->peer = NULL;
		}

		node = xmlNodeGetChildByName(rule->action_node, "delete_entity");
		if(node)
		{
			if(entity->peer)
				entity->peer->peer = 0;
			b2bl_delete_entity(entity, tuple, hash_index, 1);
			entity = NULL;
			LM_DBG("Deleted current entity\n");
		}
	}

	goto done;

send_usual_request:
		switch (request_id)
		{
		case B2B_CANCEL:
			tuple->scenario_state = B2B_CANCEL_STATE;
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
				b2bl_delete(tuple, hash_index, 1, 1);
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
			req_data.extra_headers =extra_headers->len?extra_headers:NULL;
			req_data.body =body->len?body:NULL;
			b2bl_htable[hash_index].locked_by = process_no;
			if(b2b_api.send_request(&req_data) < 0)
			{
				LM_ERR("Sending request failed [%.*s]\n", peer->key.len, peer->key.s);
			}
			b2bl_htable[hash_index].locked_by = -1;
			peer = peer->next;
		}

done:
	if(tuple)
	{
		if(b2bl_db_mode == WRITE_THROUGH)
			b2bl_db_update(tuple);
		else
			UPDATE_DBFLAG(tuple);
	}

	lock_release(&b2bl_htable[hash_index].lock);
	return 0;

error:
	lock_release(&b2bl_htable[hash_index].lock);
	return -1;
}


static inline int get_b2b_dialog_by_replace(str *replaces, str *u_replaces,
			str *entity_key, unsigned int *hash_idx, unsigned int *local_idx )
{
	struct replaces_body replaces_b;
	char tuple_buf[B2BL_MAX_KEY_LEN];
	str tuple_key;

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
	tuple_key.s = tuple_buf;
	tuple_key.len = B2BL_MAX_KEY_LEN;
	if(b2b_api.get_b2bl_key(&replaces_b.callid_val,
		&replaces_b.from_tag_val,
		&replaces_b.to_tag_val,
		entity_key,
		&tuple_key)!=0)
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
	if(b2bl_parse_key(&tuple_key, hash_idx, local_idx)< 0)
	{
		LM_ERR("Failed to parse b2b logic key [%.*s]\n",
			tuple_key.len, tuple_key.s);
		return -1;
	}
	LM_DBG("Need to replace callid=[%.*s] to-tag=[%.*s] and "
		"from-tag=[%.*s] from b2b_logic [%.*s]\n",
		replaces_b.callid_val.len, replaces_b.callid_val.s,
		replaces_b.to_tag_val.len, replaces_b.to_tag_val.s,
		replaces_b.from_tag_val.len, replaces_b.from_tag_val.s,
		tuple_key.len, tuple_key.s);

	return 0;
}

int b2b_logic_notify(int src, struct sip_msg* msg, str* key, int type, void* param,
	int flags)
{
	#define U_REPLACES_BUF_LEN 512
	char u_replaces_buf[U_REPLACES_BUF_LEN];
	str u_replaces = { u_replaces_buf, U_REPLACES_BUF_LEN};
	unsigned int hash_index, local_index;
	unsigned int hash_idx, local_idx;
	str entity_key = {NULL, 0};
	b2bl_tuple_t* tuple;
	str* b2bl_key = (str*)param;
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
				lock_get(&b2bl_htable[hash_idx].lock);
				tuple=b2bl_search_tuple_safe(hash_idx, local_idx);
				if(tuple == NULL)
				{
					LM_ERR("B2B logic record not found\n");
					lock_release(&b2bl_htable[hash_idx].lock);
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
				lock_release(&b2bl_htable[hash_idx].lock);

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


/* This function does the following actions:
 *	- extract the entities description from the scenario document
 *	- send invite or reInvite to one of the parties
 *	 - mark in the scenario instantiation which are the bridged entities and
 *	 that this scenario is currently taking place
 *	*/

int process_bridge_action(struct sip_msg* msg, b2bl_entity_id_t* curr_entity,
		b2bl_tuple_t* tuple, unsigned hash_index, xmlNodePtr bridge_node)
{

	b2bl_entity_id_t* bridge_entities[3];
	b2bl_entity_id_t* entity = NULL;
	b2bl_entity_id_t* old_entity= NULL;
	b2bl_entity_id_t* e;
	int count = 0;
	int index = 0;
	str attr= {NULL, 0};
	str entity_dest;
	xmlNodePtr clientid_node;
	xmlNodePtr dest_node;
	xmlNodePtr client_node;
	xmlNodePtr lft_node;
	xmlNodePtr node;
	str provmedia_uri={NULL,0};
	client_info_t ci;
	str* client_id;
	char* fdname_content= 0;
	str from_dname= {NULL, 0};
	xmlNodePtr value_node;
	char* value_content= 0;
	b2b_req_data_t req_data;
	str *hdrs;

	/* extract provisional media uri if exists */
	node = xmlNodeGetChildByName(bridge_node, "provisional_media");
	if(node)
	{
		provmedia_uri.s = (char*)xmlNodeGetContent(node);
		if(provmedia_uri.s)
			provmedia_uri.len = strlen(provmedia_uri.s);
	}
	memset(bridge_entities, 0, 3*sizeof(b2bl_entity_id_t*));

	for(client_node= bridge_node->children; client_node;
			client_node=client_node->next)
	{
		if(xmlStrcasecmp(client_node->name, (unsigned char*)"client")!=0 &&
			xmlStrcasecmp(client_node->name, (unsigned char*)"server") !=0)
			continue;

		if(count == 2)
		{
			LM_ERR("Bad scenario document. Too many entities defined for"
				" bridge node. Only two entities should be defined\n");
			break;
		}
		entity = NULL;
		/* there are 3 ways to identify a client: "this", "peer" or "id" */
		clientid_node = xmlNodeGetChildByName(client_node, "this");
		if(clientid_node)
		{
			LM_DBG("Selected current entity\n");
			if(curr_entity == NULL)
			{
				LM_DBG("You are not allowed to use a 'this' client "
						"specification for this type of route\n");
				goto error;
			}
			entity = curr_entity;
			goto entity_search_done;
		}

		clientid_node = xmlNodeGetChildByName(client_node, "peer");
		if(clientid_node)
		{
			LM_DBG("Selected peer entity\n");
			if(curr_entity == NULL)
			{
				LM_DBG("You are not allowed to use a 'this' client "
						"specification for this type of route\n");
				goto error;
			}

			if(curr_entity->peer == NULL)
			{
				LM_ERR("Requested for the peer entity of the current entity, but it is NULL.\n");
				goto error;
			}
			entity = curr_entity->peer;
			goto entity_search_done;
		}

		/* extract entity id */
		attr.s = (char*)xmlNodeGetNodeContentByName(client_node, "id", NULL);
		if(attr.s == NULL)
		{
			LM_ERR("Entity specification not valid. Accepted values:"
					" this, peer or id\n");
			goto error;
		}
		attr.len = strlen(attr.s);

		/* search through the entities */
		for (index = 0; index < MAX_B2BL_ENT; index++)
		{
			e = tuple->servers[index];
			if(e)
			{
				if(e->next || e->prev)
				{
					LM_ERR("Inconsistent entity [%p]\n", old_entity);
					b2bl_print_tuple(tuple, L_ERR);
					goto error;
				}
				if (e->scenario_id.len == attr.len &&
					strncmp(e->scenario_id.s, attr.s, attr.len)== 0)
				{
					entity = e;
					LM_DBG("Found entity server [%d]\n", count);
					break;
				}
			}
			e = tuple->clients[index];
			if(e)
			{
				if(e->next || e->prev)
				{
					LM_ERR("Inconsistent entity [%p]\n", old_entity);
					b2bl_print_tuple(tuple, L_ERR);
					goto error;
				}
				if (e && e->scenario_id.len == attr.len &&
					strncmp(e->scenario_id.s, attr.s, attr.len)== 0)
				{
					entity = e;
					LM_DBG("Found entity client [%d]\n", count);
					break;
				}
			}
		}
		/* if I have the 'new' child -> alter the scenario id for the old entity */
		if ((xmlNodeGetChildByName(client_node, "destination")
					|| xmlNodeGetChildByName(client_node, "new")) && entity)
		{
			/* write '<' everywhere - it's safe since it's not accepted in xml */
			memset(entity->scenario_id.s, '<', entity->scenario_id.len);
			entity = NULL;
		}

entity_search_done:

		/* must create a new client entity */
		if(entity == NULL)
		{
			/* get the destination */
			LM_DBG("Entity %d for bridge - new client entity\n", count);
			dest_node = xmlNodeGetChildByName(client_node, "destination");
			if(dest_node == NULL)
			{
				LM_ERR("Bad format for b2b scenario. New entity without a destination\n");
				goto error;
			}
			value_node = xmlNodeGetChildByName(dest_node, "value");
			if(value_node == NULL)
			{
				LM_ERR("Bad format for b2b scenario. New entity without a destination\n");
				goto error;
			}
			value_content = (char*)xmlNodeGetContent(value_node);
			if(value_content == NULL)
			{
				LM_ERR("Bad formatted scenario document. URI value empty\n");
				goto error;
			}
			if(b2b_scenario_parse_uri(value_node, value_content, tuple, msg,
						&entity_dest) < 0)
			{
				LM_ERR("Failed to parse entity destination specification\n");
				xmlFree(value_content);
				goto error;
			}
			node = xmlNodeGetChildByName(client_node, "from_dname");
			if(node)
			{
				value_node = xmlNodeGetChildByName(node, "value");
				if(value_node == NULL)
				{
					LM_ERR("Bad format for b2b scenario. New entity without a destination\n");
					xmlFree(value_content);
					goto error;
				}
				fdname_content = (char*)xmlNodeGetContent(value_node);
				if(fdname_content == NULL)
				{
					LM_ERR("Bad formatted scenario document. URI value empty\n");
					xmlFree(value_content);
					goto error;
				}
				if(b2b_scenario_parse_uri(value_node, fdname_content, tuple, msg,
						&from_dname) < 0)
				{
					LM_DBG("Failed to parse entity destination specification\n");
					xmlFree(value_content);
					goto error;
				}

			}

			hdrs = b2b_scenario_hdrs(client_node, tuple);

			LM_DBG("New entity, dest = [%.*s]\n", entity_dest.len, entity_dest.s);
			entity = b2bl_create_new_entity(B2B_CLIENT, 0, &entity_dest, 0,
					from_dname.s?&from_dname:0, &attr, hdrs, 0);

			if(fdname_content)
				xmlFree(fdname_content);
			fdname_content = 0;
			from_dname.s=0;
			xmlFree(value_content);
			if(entity == NULL)
			{
				LM_ERR("Failed to create new b2b entity\n");
				goto error;
			}
		}
		else
			old_entity = entity;

		if(attr.s)
			xmlFree(attr.s);
		attr.s = NULL;
		bridge_entities[count++] = entity;
	}

	if(bridge_entities[1] == bridge_entities[0])
	{
		LM_ERR("The scenario tells to bridge the same entity\n");
		goto error;
	}

	/* arrange the entities in vector to have the old first */
	if(old_entity && bridge_entities[0]!= old_entity)
	{
		bridge_entities[1] = bridge_entities[0];
		bridge_entities[0] = old_entity;
	}

	/* I have the two entities ->  now do the first step of the bridging scenario
	 * -> send reInvite or Invite to one of the parties */
	if(old_entity)
	{
		LM_DBG("Sent reInvite without a body to old entity\n");
		tuple->bridge_entities[0]= bridge_entities[0];
		tuple->bridge_entities[1]= bridge_entities[1];

		if(provmedia_uri.s)
		{
			tuple->bridge_entities[2]= bridge_entities[1];

			tuple->bridge_entities[1] = b2bl_create_new_entity(B2B_CLIENT, 0, &provmedia_uri, 0, 0,0,0,0);
			if(tuple->bridge_entities[1] == NULL)
			{
				LM_ERR("Failed to create new b2b entity\n");
				goto error;
			}
		}
		old_entity->stats.start_time = get_ticks();
		old_entity->stats.call_time = 0;
		/* TODO -> Do I need some other info here? */
		memset(&req_data, 0, sizeof(b2b_req_data_t));
		PREP_REQ_DATA(old_entity);
		req_data.method =&method_invite;
		req_data.extra_headers = NULL;
		req_data.client_headers = &old_entity->hdrs;
		b2bl_htable[hash_index].locked_by = process_no;
		b2b_api.send_request(&req_data);
		b2bl_htable[hash_index].locked_by = -1;
		old_entity->state = 0;
		old_entity->sdp_type = B2BL_SDP_LATE;
	}
	else
	{
		str from_uri   = bridge_entities[1]->to_uri;
		str to_uri     = bridge_entities[0]->to_uri;
		str from_dname = bridge_entities[0]->from_dname;
		str hdrs = bridge_entities[0]->hdrs;

		memset(&ci, 0, sizeof(client_info_t));
		ci.method        = method_invite;
		ci.to_uri        = to_uri;
		ci.from_uri      = from_uri;
		ci.from_dname    = from_dname;
		ci.extra_headers = tuple->extra_headers;
		ci.client_headers= &hdrs;
		/* if we use init sdp and we have it, just use it */
		if (tuple->scenario && tuple->scenario->use_init_sdp && tuple->scenario->body.len) {
			ci.body          = &tuple->scenario->body;
		} else {
			ci.body          = 0;
		}
		ci.from_tag      = 0;
		ci.send_sock     = msg?(msg->force_send_socket?msg->force_send_socket:msg->rcv.bind_address):0;
		if (ci.send_sock) get_local_contact(ci.send_sock, NULL, &ci.local_contact);
		else ci.local_contact = server_address;

		if(msg)
		{
			if (str2int( &(get_cseq(msg)->number), &ci.cseq)!=0 )
			{
				LM_ERR("cannot parse cseq number\n");
				goto error1;
			}
		}

		LM_DBG("Send Invite without a body to a new client entity\n");

		b2bl_htable[hash_index].locked_by = process_no;

		client_id = b2b_api.client_new(&ci, b2b_client_notify,
				b2b_add_dlginfo, &b2bl_mod_name, tuple->key);

		b2bl_htable[hash_index].locked_by = -1;

		if(client_id == NULL)
		{
			LM_ERR("Failed to create new client entity\n");
			goto error1;
		}

		/* save the client_id in the structure */
		entity = b2bl_create_new_entity(B2B_CLIENT, client_id, &to_uri,
				&from_uri,0,&bridge_entities[0]->scenario_id, &hdrs, 0);
		if(entity == NULL)
		{
			LM_ERR("failed to create new client entity\n");
			pkg_free(client_id);
			goto error1;
		}
		pkg_free(client_id);
		entity->stats.call_time = get_ticks();
		entity->type = B2B_CLIENT;
		entity->peer = bridge_entities[1];
		entity->sdp_type = ci.body ? B2BL_SDP_RENEW : B2BL_SDP_LATE;
		shm_free(bridge_entities[0]);

		tuple->bridge_entities[0] = entity;
		tuple->bridge_entities[1]= bridge_entities[1];

		if (0 != b2bl_add_client(tuple, entity))
			goto error1;
	}
	/* save the pointers to the bridged entities ;
	 * the first (index 0) is the one we sent the first message ( reInvite or Invite)*/
	tuple->scenario_state = B2B_BRIDGING_STATE;

	/* extract the lifetime if one is defined */
	lft_node = xmlNodeGetChildByName(bridge_node, "lifetime");
	if(lft_node)
	{
		attr.s = (char*)xmlNodeGetContent(lft_node);
		if(attr.s == NULL)
		{
			LM_ERR("Failed to extract node content\n");
			goto error;
		}
		attr.len = strlen(attr.s);
		if(str2int(&attr, &tuple->lifetime)< 0)
		{
			LM_ERR("Wrong scenario document. The lifetime value is not an integer\n");
			xmlFree(attr.s);
			goto error;
		}
		xmlFree(attr.s);
		attr.s = NULL;
		LM_DBG("Lifetime defined = [%d]\n", tuple->lifetime);
		tuple->lifetime+= get_ticks();
	}
	else
		tuple->lifetime = -1;

	LM_DBG("be[0]= %p, be1=[%p]\n", tuple->bridge_entities[0], tuple->bridge_entities[1]);
	return 0;

error1:
	shm_free(bridge_entities[0]);
	shm_free(bridge_entities[1]);

error:
	if(attr.s)
		xmlFree(attr.s);
	return -1;
}

int b2b_server_notify(struct sip_msg* msg, str* key, int type, void* param,
	int flags)
{
	return b2b_logic_notify(B2B_SERVER, msg, key, type, param, flags);
}


int b2b_client_notify(struct sip_msg* msg, str* key, int type, void* param,
	int flags)
{
	return b2b_logic_notify(B2B_CLIENT, msg, key, type, param, flags);
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
	tuple = b2bl_insert_new(msg, hash_index, NULL, NULL, NULL,
				custom_hdrs, -1, &b2bl_key, INSERTDB_FLAG, TUPLE_NO_REPL);
	if(tuple== NULL)
	{
		LM_ERR("Failed to insert new scenario instance record\n");
		goto error;
	}
	tuple->cbf = cbf;
	tuple->cb_mask = cb_mask;
	tuple->cb_param = cb_param;

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
	ctx->data = tuple;

	/* if it will not be confirmed -> delete */
	tuple->lifetime = params->init_timeout + get_ticks();

	/* create new server */
	server_id = b2b_api.server_new(msg, &tuple->local_contact,
			b2b_server_notify, &b2bl_mod_name, b2bl_key);
	if(server_id == NULL)
	{
		LM_ERR("failed to create new b2b server instance\n");
		goto error;
	}

	tuple->servers[0] = b2bl_create_new_entity(B2B_SERVER, server_id, &to_uri, &from_uri,
			0,0,0, msg);
	if(tuple->servers[0] == NULL)
	{
		LM_ERR("Failed to create server entity\n");
		goto error;
	}
	tuple->servers[0]->type = B2B_SERVER;
	tuple->servers[0]->no = 0;

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
	ci.send_sock     = msg->force_send_socket?msg->force_send_socket:msg->rcv.bind_address;
	get_local_contact(ci.send_sock, NULL, &ci.local_contact);
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

	b2bl_htable[hash_index].locked_by = process_no;

	client_id = b2b_api.client_new(&ci, b2b_client_notify,
			b2b_add_dlginfo, &b2bl_mod_name, b2bl_key);

	b2bl_htable[hash_index].locked_by = -1;

	if(client_id == NULL)
	{
		LM_ERR("failed to create new b2b client instance\n");
		goto error;
	}

	client_entity = b2bl_create_new_entity(B2B_CLIENT, client_id, &to_uri, &from_uri,
			0, 0, 0, 0);
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

	for( idx=0 ; (uri.s=get_branch(idx,&uri.len,&q,0,0,0,0))!=0 ; idx++ )
	{
		LM_DBG("got branch ruri [%.*s]\n", uri.len, uri.s);
		gen_fromtag(&dlginfo->callid, &dlginfo->fromtag, &uri, msg, &from_tag_gen);
		ci.from_tag = &from_tag_gen;
		ci.req_uri = uri;
		ci.avps = clone_avp_list( *get_avp_list() );

		b2bl_htable[hash_index].locked_by = process_no;

		client_id = b2b_api.client_new(&ci, b2b_client_notify,
			b2b_add_dlginfo, &b2bl_mod_name, b2bl_key);

		b2bl_htable[hash_index].locked_by = -1;

		if(client_id == NULL)
		{
			LM_ERR("failed to create new b2b client instance\n");
			goto error;
		}
		client_entity = b2bl_create_new_entity(B2B_CLIENT, client_id, &to_uri, &from_uri,
			0, 0, 0, 0);
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

	lock_release(&b2bl_htable[hash_index].lock);

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
	lock_release(&b2bl_htable[hash_index].lock);
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

/* Function that processes destination node.
 * Accepted value types:
 *	uri: specified inline
 *	param: specified as a parameter
 *	initial: the initial destination(from the initial message)
 *	header: a header field value
 **/

int b2b_scenario_parse_uri(xmlNodePtr value_node, char* value_content,
		b2bl_tuple_t* tuple, struct sip_msg* msg, str* client_to)
{

	str value= {value_content, strlen(value_content)};
	unsigned char* value_type= NULL;
	unsigned int param_no;

	value_type = xmlNodeGetAttrContentByName(value_node, "type");
	if(value_type == NULL)
	{
		LM_ERR("Scenary document not well formed. To type param not defined\n");
		return -1;
	}

	if(xmlStrcasecmp(value_type, (unsigned char*)"uri") == 0)
	{
		LM_DBG("URI of type uri\n");
		*client_to = value;
	}
	else
	if(xmlStrcasecmp(value_type, (unsigned char*)"param") == 0)
	{
		LM_DBG("URI of type param\n");

		if(str2int(&value, &param_no)< 0)
		{
			LM_ERR("Scenary document not well formed. Client to param not a number\n");
			goto error;
		}

		if(param_no > MAX_SCENARIO_PARAMS || param_no < 1)
		{
			LM_ERR("Scenary document not well formed. Client to param not valid [%d]\n", param_no);
			goto error;
		}
		*client_to = tuple->scenario_params[param_no-1];
		LM_DBG("URI value taken from a parameter [%.*s]\n",
				client_to->len, client_to->s);
	}
	else
	if(xmlStrcasecmp(value_type, (unsigned char*)"initial") == 0)
	{
		LM_DBG("URI of type initial\n");
		// FIXME: this may not exist after a transfer that will leave us with two clients
		if (tuple->servers[0])
			*client_to = tuple->servers[0]->to_uri;
	}
	else
	if(xmlStrcasecmp(value_type, (unsigned char*)"header") == 0)
	{
		struct hdr_field* sip_hdr, hdr;
		char buf[BUF_LEN];
		struct sip_uri sip_uri;
		struct to_body to;

		LM_DBG("URI of type header value\n");
		if(msg == NULL)
		{
			LM_DBG("You are not allowed to use a header specification for this type of scenario\n");
			goto error;
		}
		if(BUF_LEN < value.len + 1)
		{
			LM_ERR("Buffer overflow\n");
			goto error;
		}
		memcpy(buf, value.s, value.len);
		buf[value.len] = ':';

		if(parse_hname2(buf, buf + value.len+1, &hdr) == 0)
		{
			LM_ERR("Failed to parse header name\n");
			goto error;
		}
		if(hdr.type == HDR_OTHER_T)
		{
			LM_DBG("Header other\n");
			sip_hdr = get_header_by_name(msg, value.s, value.len);
			if(sip_hdr == NULL)
			{
				LM_DBG("No header with the name [%.*s] found\n", value.len, value.s);
				goto error;
			}
		}
		else
		if(hdr.type == HDR_ERROR_T)
		{
			LM_DBG("Failed to parse header name\n");
			goto error;
		}
		else
		{
			sip_hdr = msg->headers;
			while(sip_hdr && sip_hdr->type != hdr.type)
				sip_hdr = sip_hdr->next;
			if(sip_hdr == NULL)
			{
				LM_DBG("Did not find header\n");
				goto error;
			}
		}

		/* as the hdr body is part of a SIP msg, we can to a +1 in len
		 * without the risk of overlowing the buffer. */
		if ( parse_to(sip_hdr->body.s, sip_hdr->body.s+sip_hdr->body.len+1,
		&to)<0 || to.error == PARSE_ERROR) {
			LM_ERR("hdr '%.*s' does not follow a name_addr SIP format\n",
					sip_hdr->name.len, sip_hdr->name.s);
			goto error;
		}
		/* we can safely free the to-hdr params now, as we do not need them,
		 * we need only the URI. */
		free_to_params(&to);

		if(parse_uri(to.uri.s, to.uri.len, &sip_uri)< 0)
		{
			LM_ERR("Not a valid sip uri [%.*s]\n", to.uri.len, to.uri.s);
			goto error;
		}
		*client_to = to.uri;
	}
	else
	{
		LM_ERR("Scenary document not well formed. Client to type not valid\n");
		goto error;
	}

	LM_DBG("URI value = [%.*s]\n", client_to->len, client_to->s);

	xmlFree(value_type);

	return 0;

error:
	if(value_type)
		xmlFree(value_type);
	return -1;
}
str *b2b_scenario_hdrs(xmlNodePtr client_node, b2bl_tuple_t* tuple)
{
	static int b2b_hdrs_buf_len;
	static str b2b_hdrs_buf = {0, 0};
	xmlNodePtr hdr_node, node;
	unsigned char *type;
	unsigned int param_no, len;
	unsigned char *body_s, *name_s;
	str value, name_value, body_value;
	char *tmp_buf;

	/* reset the buffer to fill in with new information */
	b2b_hdrs_buf.len = 0;

	for (hdr_node = client_node->children; hdr_node; hdr_node = hdr_node->next)
	{
		if (xmlStrcasecmp(hdr_node->name, (unsigned char *)"header") != 0)
			continue;

		node = xmlNodeGetChildByName(hdr_node, "name");
		if(node == NULL)
		{
			LM_WARN("header without a name... ignoring it\n");
			continue;
		}

		body_s = name_s = NULL;
		type = xmlNodeGetAttrContentByName(node, "type");
		if(type == NULL || (xmlStrcasecmp(type, (unsigned char*)"text") == 0))
		{
			/* no type, use plain name */
			name_s = xmlNodeGetContent(node);
			name_value.s = (char *)name_s;
			name_value.len = strlen(name_value.s);
		} else
			if (type && (xmlStrcasecmp(type, (unsigned char*)"param") == 0))
			{
				value.s = (char *)xmlNodeGetContent(node);
				value.len = strlen(value.s);
				if(str2int(&value, &param_no)< 0)
				{
					LM_ERR("non-int parameter index for header name\n");
					xmlFree(value.s);
					goto next;
				}
				xmlFree(value.s);

				if(param_no > MAX_SCENARIO_PARAMS || param_no < 1)
				{
					LM_ERR("bad parameter index for header name\n");
					goto next;
				}
				name_value = tuple->scenario_params[param_no-1];
			} else {
				LM_WARN("unknown header type <%s>\n", type);
				goto next;
			}
		trim(&name_value);

		LM_DBG("header name: <%.*s>\n", name_value.len, name_value.s);

		node = xmlNodeGetChildByName(hdr_node, "value");
		if(node == NULL)
		{
			LM_WARN("header %.*s without a value... ignoring it\n",
					name_value.len, name_value.s);
			goto next;
		}

		if (type)
			xmlFree(type);
		type = xmlNodeGetAttrContentByName(node, "type");
		if(type == NULL || (xmlStrcasecmp(type, (unsigned char*)"text") == 0))
		{
			/* no type, use plain name */
			body_s = xmlNodeGetContent(node);
			body_value.s = (char *)body_s;
			body_value.len = strlen(body_value.s);
		} else
			if (type && (xmlStrcasecmp(type, (unsigned char*)"param") == 0))
			{
				value.s = (char *)xmlNodeGetContent(node);
				value.len = strlen(value.s);
				if(str2int(&value, &param_no)< 0)
				{
					LM_ERR("non-int parameter index for header <%.*s>\n",
						name_value.len, name_value.s);
					xmlFree(value.s);
					goto next;
				}
				xmlFree(value.s);

				if(param_no > MAX_SCENARIO_PARAMS || param_no < 1)
				{
					LM_ERR("bad parameter index for header <%.*s>\n",
							name_value.len, name_value.s);
					goto next;
				}
				body_value = tuple->scenario_params[param_no-1];
			} else {
				LM_WARN("unknown header type <%s> for <%.*s>\n", type,
						name_value.len, name_value.s);
				goto next;
			}
		trim(&body_value);
		LM_DBG("header value: <%.*s>\n", body_value.len, body_value.s);

		len = name_value.len + 2 /* ': ' */ + body_value.len + 2 /* '\r\n' */;
		if (b2b_hdrs_buf.len + len > b2b_hdrs_buf_len) {
			tmp_buf = pkg_realloc(b2b_hdrs_buf.s, b2b_hdrs_buf.len + len);
			if (!tmp_buf) {
				LM_ERR("not enough memory to add header <%.*s: %.*s>\n",
						name_value.len, name_value.s, body_value.len, body_value.s);
				goto next;
			}
			b2b_hdrs_buf.s = tmp_buf;
			b2b_hdrs_buf_len += len;
		}
		memcpy(b2b_hdrs_buf.s + b2b_hdrs_buf.len, name_value.s, name_value.len);
		b2b_hdrs_buf.len += name_value.len;
		memcpy(b2b_hdrs_buf.s + b2b_hdrs_buf.len, ": ", 2);
		b2b_hdrs_buf.len += 2;
		memcpy(b2b_hdrs_buf.s + b2b_hdrs_buf.len, body_value.s, body_value.len);
		b2b_hdrs_buf.len += body_value.len;
		memcpy(b2b_hdrs_buf.s + b2b_hdrs_buf.len, "\r\n", 2);
		b2b_hdrs_buf.len += 2;

next:
		if (body_s)
			xmlFree(body_s);
		if (name_s)
			xmlFree(name_s);
		if (type)
			xmlFree(type);
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


str* b2b_process_scenario_init(b2b_scenario_t* scenario_struct,
	struct sip_msg* msg, str* args[], b2bl_cback_f cbf, void* cb_param,
	unsigned int cb_mask, str* custom_hdrs, struct b2b_params *params)
{
	str* server_id= NULL, *client_id= NULL;
	str body= {NULL, 0};
	str method = {INVITE, INVITE_LEN};
	str* b2bl_key = NULL;
	b2bl_tuple_t* tuple= NULL;
	struct b2b_context *ctx;
	xmlNodePtr node, init_node, node_aux;
	xmlNodePtr server_node = NULL, clients_node= NULL;
	str entity_sid;
	char* type= NULL;
	str client_to;
	b2bl_entity_id_t* client_entity = NULL;
	unsigned int scenario_state = B2B_NOTDEF_STATE;
	client_info_t ci;
	int clients_no = 0;
	unsigned int hash_index;
	unsigned int index;
	str to_uri={NULL, 0}, from_uri, from_dname;
	int eno = 0;
	str new_body={0, 0};
	str *hdrs;

	if(b2b_msg_get_from(msg, &from_uri, &from_dname)< 0 ||
	b2b_msg_get_to(msg, &to_uri, params->flags)< 0)
	{
		LM_ERR("Failed to get to or from from the message\n");
		return NULL;
	}
	hash_index = core_hash(&to_uri, &from_uri, b2bl_hsize);

	if(msg)
	{
		method = msg->first_line.u.request.method;

		/* extract info from the message in case there is a client entity
		 * with type message */
		/* process the body */
		if(msg->content_length)
		{
			if ( get_body(msg, &body)!=0 )
			{
				LM_ERR("cannot extract body\n");
				goto error;
			}
		}
	}

	/* examine the init part in the scenario XML document */
	init_node = xmlNodeGetChildByName(scenario_struct->init_node, "bridge");
	if(init_node == NULL)
	{
		LM_ERR("Wrong format for b2b scenario document. No bridging node"
				" inside init node\n");
		goto error;
	}

	server_node = xmlNodeGetChildByName(init_node, "server");

	clients_node = xmlNodeGetChildByName(init_node, "client");
	if(server_node == NULL && clients_node == NULL)
	{
		LM_ERR("There must be at least one client or one server entity\n");
		goto error;
	}

	/* create new scenario instance record */
	tuple = b2bl_insert_new(msg, hash_index, scenario_struct,
			args, body.s?&body:NULL, custom_hdrs, -1,
			&b2bl_key, INSERTDB_FLAG, TUPLE_NO_REPL);
	if(tuple== NULL)
	{
		LM_ERR("Failed to insert new scenario instance record\n");
		goto error;
	}
	tuple->lifetime = 60 + get_ticks();

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
	ctx->data = tuple;

	/* set the state of the scenario after the init section */
	node = xmlNodeGetChildByName(scenario_struct->init_node, "state");
	if(node)
	{
		str state_attr;
		state_attr.s = (char*)xmlNodeGetContent(node);
		state_attr.len = strlen(state_attr.s);

		if(str2int(&state_attr, &scenario_state)< 0)
		{
			LM_ERR("Scenary state after init section not an integer\n");
			xmlFree(state_attr.s);
			goto error;
		}
		xmlFree(state_attr.s);

		tuple->scenario_state = scenario_state;
		tuple->next_scenario_state = scenario_state;
	}

	/* go through the document and create the described entities */
	if(server_node)
	{
		if(msg == NULL)
		{
			LM_ERR("A request for a server entity and no message\n");
			goto error;
		}
		/* a server entity can only deal with a message and there can
		 * only be one server entity */
		/* extract the id */
		entity_sid.s = (char*)xmlNodeGetNodeContentByName(server_node,
			"id", NULL);
		if(entity_sid.s == NULL)
		{
			LM_ERR("Wrong formatted xml document. Server node without "
				"id parameter\n");
			goto error;
		}
		entity_sid.len = strlen(entity_sid.s);

		/* create new server entity */
		server_id = b2b_api.server_new(msg, &tuple->local_contact,
				b2b_server_notify, &b2bl_mod_name, b2bl_key);
		if(server_id == NULL)
		{
			LM_ERR("failed to create new b2b server instance\n");
			xmlFree(entity_sid.s);
			goto error;
		}
		hdrs = b2b_scenario_hdrs(server_node, tuple);
		tuple->servers[0] = b2bl_create_new_entity(B2B_SERVER, server_id,
			&to_uri, &from_uri,0,&entity_sid,hdrs,msg);
		tuple->servers[0]->no = eno++;
		tuple->bridge_entities[0] = tuple->servers[0];
		if(tuple->servers[0] == NULL)
		{
			LM_ERR("failed to create new server entity\n");
			xmlFree(entity_sid.s);
			pkg_free(server_id);
			goto error;
		}
		xmlFree(entity_sid.s);
		pkg_free(server_id);
		tuple->servers[0]->type = B2B_SERVER;
	}
	pkg_free(to_uri.s);
	to_uri.s = 0;

	/* create client entities */
	for(node = clients_node; node; node=node->next)
	{
		char* value_content;

		if(xmlStrcasecmp(node->name, (unsigned char*)"client") !=0 )
			continue;

		entity_sid.s = (char*)xmlNodeGetNodeContentByName(node, "id", NULL);
		if(entity_sid.s == NULL)
		{
			LM_ERR("Wrong formatted xml document. Client node without "
				"id parameter\n");
			goto error;
		}
		entity_sid.len = strlen(entity_sid.s);

		/* get type*/
		type = xmlNodeGetNodeContentByName(node, "type", NULL);
		if(type == NULL)
		{
			LM_ERR("Scenary document not well formed. Client Type "
				"node not found\n");
			goto error1;
		}
		/* extract destination */
		node_aux = xmlNodeGetChildByName(node, "destination");
		if(node_aux == NULL)
		{
			LM_ERR("Scenary document not well formed. No client 'to' "
				"node defined\n");
			goto error2;
		}

		node_aux = xmlNodeGetChildByName(node_aux, "value");
		if(node_aux == NULL)
		{
			LM_ERR("Bad format for b2b scenario. New entity without a "
				"destination\n");
			goto error2;
		}
		value_content = (char*)xmlNodeGetContent(node_aux);
		if(value_content == NULL)
		{
			LM_ERR("Bad formatted scenario document. URI value empty\n");
			goto error2;
		}

		if(b2b_scenario_parse_uri(node_aux, value_content, tuple, msg,
					&client_to) < 0 || !client_to.s)
		{
			LM_ERR("Failed to get the value for the b2b client ruri\n");
			xmlFree(value_content);
			goto error2;
		}
		xmlFree(value_content);
		hdrs = b2b_scenario_hdrs(node, tuple);

		if(xmlStrcasecmp((unsigned char*)type, (unsigned char*)"message") == 0)
		{
			memset(&ci, 0, sizeof(client_info_t));
			ci.method        = method;
			ci.to_uri        = client_to;
			ci.from_uri      = from_uri;
			ci.from_dname    = from_dname;
			ci.extra_headers = tuple->extra_headers;
			ci.client_headers= hdrs;
			ci.body          = (body.s?&body:NULL);
			ci.send_sock     = msg->force_send_socket?
				msg->force_send_socket:msg->rcv.bind_address;
			get_local_contact(ci.send_sock, NULL, &ci.local_contact);
			/* grab all AVPs from the server side */
			ci.avps = clone_avp_list( *get_avp_list() );
			if (str2int( &(get_cseq(msg)->number), &ci.cseq)!=0 ) {
				LM_ERR("cannot parse cseq number\n");
				goto error;
			}

			b2bl_htable[hash_index].locked_by = process_no;

			client_id = b2b_api.client_new(&ci, b2b_client_notify,
					b2b_add_dlginfo, &b2bl_mod_name, b2bl_key);

			b2bl_htable[hash_index].locked_by = -1;

			if(client_id == NULL)
			{
				LM_ERR("failed to create new b2b client instance\n");
				goto error2;
			}

			client_entity = b2bl_create_new_entity(B2B_CLIENT, client_id,
				&client_to, &from_uri,0,&entity_sid,hdrs, 0);
			if(client_entity == NULL)
			{
				LM_ERR("failed to create new client entity\n");
				xmlFree(entity_sid.s);
				pkg_free(client_id);
				goto error2;
			}
			pkg_free(client_id);

			if (0 != b2bl_add_client(tuple, client_entity))
				goto error2;
			client_entity->no = eno++;
			clients_no++;
		}
		xmlFree(type);
		xmlFree(entity_sid.s);
	}

	/* If I have a server entity I consider it peer for all client entities,
	 * and its peer is the first client */
	if(tuple->servers[0])
	{
		if(tuple->clients[0] == NULL)
		{
			LM_ERR("You have to create at least 2 entities in init part\n");
			goto error;
		}
		for (index = 0; index < MAX_B2BL_ENT; index++)
		{
			if (tuple->clients[index])
				tuple->clients[index]->peer = tuple->servers[0];

		}
		tuple->bridge_entities[0] = tuple->servers[0];
		tuple->bridge_entities[1] = tuple->clients[0];
	}
	else
	{
		if(clients_no >= 2) /* make the first 2 peers */
		{
			tuple->bridge_entities[0]= tuple->clients[0];
			tuple->bridge_entities[1]= tuple->clients[1];
		}
		else
		{
			LM_ERR("You have to create at least 2 entities in init part\n");
			goto error;
		}
	}
	tuple->bridge_entities[0]->peer = tuple->bridge_entities[1];
	tuple->bridge_entities[1]->peer = tuple->bridge_entities[0];

	tuple->cbf = cbf;
	tuple->cb_mask = cb_mask;
	tuple->cb_param = cb_param;

	if(b2bl_db_mode == WRITE_THROUGH)
		b2bl_db_insert(tuple);

	local_ctx_tuple = NULL;

	b2bl_htable[hash_index].flags = params->flags;

	lock_release(&b2bl_htable[hash_index].lock);

	if(new_body.s)
		pkg_free(new_body.s);

	return b2bl_key;

error2:
	xmlFree(type);
error1:
	xmlFree(entity_sid.s);
error:
	if(tuple)
	{
		b2bl_delete(tuple, hash_index, 1, 1);
		lock_release(&b2bl_htable[hash_index].lock);
	}
	if(to_uri.s)
		pkg_free(to_uri.s);
	if(new_body.s)
		pkg_free(new_body.s);
	local_ctx_tuple = NULL;
	return NULL;
}


str* init_request(struct sip_msg* msg, struct b2b_scen_fl *scf, str* args[],
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

	if(scf->scenario == NULL)
		key = create_top_hiding_entities(msg, cbf, cb_param, cb_mask,
			custom_hdrs, &scf->params);
	else
		key = b2b_process_scenario_init(scf->scenario, msg, args,
			cbf, cb_param, cb_mask, custom_hdrs, &scf->params);

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

str* internal_init_scenario(struct sip_msg* msg, str* name,
		str* args[MAX_SCENARIO_PARAMS], b2bl_cback_f cbf, void* cb_param,
		unsigned int cb_mask, str* custom_hdrs)
{
	struct b2b_scen_fl *scf;

	if (b2bl_key_avp_name >= 0)
		destroy_avps( b2bl_key_avp_type, b2bl_key_avp_name, 1);

	scf = prepare_b2b_scen_fl_struct();
	if (scf == NULL)
	{
		LM_ERR("no more pkg memory\n");
		return NULL;
	}
	scf->params.init_timeout = b2bl_th_init_timeout;

	if(name->len == B2B_TOP_HIDING_SCENARY_LEN &&
		strncmp(name->s,B2B_TOP_HIDING_SCENARY,B2B_TOP_HIDING_SCENARY_LEN)==0)
	{
		scf->scenario = NULL;
	}
	else
	{
		scf->scenario = get_scenario_id_list(name, script_scenarios);
		if(!scf->scenario)
		{
			LM_ERR("No scenario found with id [%s]\n", name->s);
			return NULL;
		}
	}
	return init_request(msg, scf, args, cbf, cb_param, cb_mask, custom_hdrs);
}


int b2b_init_request(struct sip_msg* msg, struct b2b_scen_fl *scf,
				str* arg2, str* arg3, str* arg4, str* arg5, str* arg6)
{
	str* args[MAX_SCENARIO_PARAMS];
	str* key;
	str auth_header;
	str* cust_headers;
	int ret = -1;

	if (b2bl_key_avp_name >= 0)
		destroy_avps( b2bl_key_avp_type, b2bl_key_avp_name, 1);

	/* find the scenario with the corresponding id */

	/* process the arguments */
	args[0] = arg2;
	args[1] = arg3;
	args[2] = arg4;
	args[3] = arg5;
	args[4] = arg6;

	b2b_api.apply_lumps(msg);

	cust_headers = NULL;
	if (scf->params.flags & B2BL_FLAG_TRANSPARENT_AUTH)
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

	/* call the scenario init processing function */
	key = init_request(msg, scf, args, 0, NULL, 0, cust_headers);
	if(key) ret = 1;

	return ret;
}

int b2bl_bridge(str* key, str* new_dst, str* new_from_dname, int entity_no)
{
	b2bl_tuple_t* tuple;
	b2bl_entity_id_t* entity = NULL, *old_entity;
	struct sip_uri uri;
	unsigned int hash_index, local_index;
	str* client_id;
	client_info_t ci;
	b2b_req_data_t req_data;
	b2b_rpl_data_t rpl_data;

	if(!key || !new_dst)
	{
		LM_ERR("Wrong arguments\n");
		return -1;
	}

	if(entity_no == 1)
	{
		LM_WARN("Not implemented yet.\n");
		return 0;
	}

	if(parse_uri(new_dst->s, new_dst->len, &uri)< 0)
	{
		LM_ERR("Bad argument. Not a valid uri [%.*s]\n",
			new_dst->len, new_dst->s);
		return -1;
	}

	if(b2bl_parse_key(key, &hash_index, &local_index) < 0)
	{
		LM_ERR("Failed to parse key\n");
		return -1;
	}

	lock_get(&b2bl_htable[hash_index].lock);

	tuple = b2bl_search_tuple_safe(hash_index, local_index);
	if(tuple == NULL)
	{
		LM_ERR("No entity found\n");
		goto error;
	}

	local_ctx_tuple = tuple;

	// FIXME: we may have no server at some point in time
	if(tuple->servers[0] == NULL)
	{
		LM_ERR("Wrong usage - no server entity present\n");
		goto error;
	}
	LM_DBG("Bridge server %.*s\n",tuple->servers[0]->dlginfo->callid.len,
			tuple->servers[0]->dlginfo->callid.s);
	old_entity = tuple->servers[0]->peer;
	if(old_entity)
	{
		if(old_entity->next || old_entity->prev)
		{
			LM_ERR("Inconsistent entity [%p]\n", old_entity);
			b2bl_print_tuple(tuple, L_ERR);
			goto error;
		}
		LM_DBG("End peer dialog [%p]\n", old_entity);
		old_entity->peer = NULL;
		if(old_entity->disconnected && old_entity->state==B2BL_ENT_CONFIRMED)
		{
			memset(&rpl_data, 0, sizeof(b2b_rpl_data_t));
			PREP_RPL_DATA(old_entity);
			rpl_data.method =METHOD_BYE;
			rpl_data.code =200;
			rpl_data.text =&ok;
			b2b_api.send_reply(&rpl_data);
			b2bl_delete_entity(old_entity, tuple, hash_index, 1);
		}
		else
			b2b_end_dialog(old_entity, tuple, hash_index);
	}
	else
		LM_DBG("No peer found\n");

	if(tuple->scenario_state == B2B_BRIDGING_STATE &&
			tuple->bridge_entities[0]== tuple->servers[0] &&
			tuple->servers[0]->state== B2BL_ENT_CONFIRMED)
	{
		LM_DBG("Do the second step of the bridging\n");
		/* do the second step of bridging */
		memset(&ci, 0, sizeof(client_info_t));
		ci.method        = method_invite;
		ci.to_uri        = *new_dst;
		ci.from_uri      = tuple->servers[0]->to_uri;
		ci.from_dname    = *new_from_dname;
		ci.extra_headers = tuple->extra_headers;
		ci.client_headers= &tuple->servers[0]->hdrs;
		ci.body          = tuple->b1_sdp.s?&tuple->b1_sdp:0;
		ci.cseq          = 1;
		ci.local_contact = tuple->local_contact;

		b2bl_htable[hash_index].locked_by = process_no;

		client_id = b2b_api.client_new(&ci, b2b_client_notify,
				b2b_add_dlginfo, &b2bl_mod_name, tuple->key);

		b2bl_htable[hash_index].locked_by = -1;

		if(client_id == NULL)
		{
			LM_ERR("Failed to create new client entity\n");
			goto error;
		}
		/* save the client_id in the structure */
		entity = b2bl_create_new_entity(B2B_CLIENT, client_id, &ci.to_uri,
				&ci.from_uri, 0, 0, &tuple->servers[0]->hdrs, 0);
		if(entity == NULL)
		{
			LM_ERR("failed to create new client entity\n");
			pkg_free(client_id);
			goto error;
		}
		pkg_free(client_id);
		LM_DBG("Created new client entity [%.*s]\n", new_dst->len, new_dst->s);

		if (0 != b2bl_add_client(tuple, entity))
			goto error;
	}
	else
	{
		entity = b2bl_create_new_entity( B2B_CLIENT, 0, new_dst, 0,
			new_from_dname,0,0,0);
		if(entity == NULL)
		{
			LM_ERR("Failed to create new b2b entity\n");
			goto error;
		}
		LM_DBG("Created new client entity [%.*s]\n", new_dst->len, new_dst->s);

		tuple->scenario_state = B2B_BRIDGING_STATE;
		memset(&req_data, 0, sizeof(b2b_req_data_t));
		PREP_REQ_DATA(tuple->servers[0]);
		req_data.method =&method_invite;
		req_data.client_headers =&tuple->servers[0]->hdrs;;
		b2bl_htable[hash_index].locked_by = process_no;
		if(b2b_api.send_request(&req_data) < 0)
		{
			LM_ERR("Failed to send INVITE request\n");
			goto error;
		}
		b2bl_htable[hash_index].locked_by = -1;
		tuple->servers[0]->sdp_type = B2BL_SDP_LATE;
		tuple->servers[0]->state = 0; /* mark it not as CONFIRMED */
	}

	tuple->bridge_entities[0]= tuple->servers[0];
	tuple->bridge_entities[1]= entity;
	tuple->servers[0]->no = 0;
	entity->no = 1;

	tuple->servers[0]->peer = entity;
	entity->peer = tuple->servers[0];

	tuple->servers[0]->stats.start_time = get_ticks();
	tuple->servers[0]->stats.call_time = 0;

	local_ctx_tuple = NULL;

	lock_release(&b2bl_htable[hash_index].lock);

	return 0;

error:
	if(entity)
		shm_free(entity);
	local_ctx_tuple = NULL;
	lock_release(&b2bl_htable[hash_index].lock);
	return -1;
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

	lock_get(&b2bl_htable[hash_index].lock);

	tuple = b2bl_search_tuple_safe(hash_index, local_index);
	if(tuple == NULL)
	{
		LM_DBG("No entity found [%.*s]\n", key->len, key->s);
		lock_release(&b2bl_htable[hash_index].lock);
		return -1;
	}

	local_ctx_tuple = tuple;

	b2b_end_dialog(tuple->bridge_entities[0], tuple, hash_index);
	b2b_end_dialog(tuple->bridge_entities[1], tuple, hash_index);

	b2b_mark_todel(tuple);

	local_ctx_tuple = NULL;

	lock_release(&b2bl_htable[hash_index].lock);

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

	lock_get(&b2bl_htable[hash_index].lock);

	tuple = b2bl_search_tuple_safe(hash_index, local_index);
	if(tuple == NULL)
	{
		LM_ERR("No entity found\n");
		lock_release(&b2bl_htable[hash_index].lock);
		return -1;
	}

	if(stat && tuple->bridge_entities[0])
	{
		stat->start_time = tuple->bridge_entities[0]->stats.start_time;
		stat->setup_time = tuple->bridge_entities[0]->stats.setup_time;
		stat->call_time  = get_ticks() - stat->start_time;
		stat->key.s = NULL; stat->key.len = 0;
	}

	lock_release(&b2bl_htable[hash_index].lock);

	return 0;
}

int b2bl_set_state(str* key, int state)
{
	unsigned int hash_index, local_index;
	b2bl_tuple_t* tuple;

	if(b2bl_parse_key(key, &hash_index, &local_index) < 0)
	{
		LM_ERR("Failed to parse key\n");
		return -1;
	}

	lock_get(&b2bl_htable[hash_index].lock);

	tuple = b2bl_search_tuple_safe(hash_index, local_index);
	if(tuple == NULL)
	{
		LM_ERR("No entity found\n");
		lock_release(&b2bl_htable[hash_index].lock);
		return -1;
	}

	if(tuple->scenario_state == B2B_BRIDGING_STATE)
		tuple->next_scenario_state = state;
	else
		tuple->scenario_state = state;

	lock_release(&b2bl_htable[hash_index].lock);

	return 0;
}

int b2bl_bridge_2calls(str* key1, str* key2)
{
	b2bl_tuple_t* tuple;
	unsigned int hash_index, local_index;
	b2bl_entity_id_t *e2= 0, *e1= 0;
	b2bl_entity_id_t *e= 0;
	b2b_req_data_t req_data;
	b2b_rpl_data_t rpl_data;

	if(!key1 || !key2)
	{
		LM_ERR("Wrong arguments [%p] [%p]\n", key1, key2);
		return -1;
	}

	if(b2bl_parse_key(key2, &hash_index, &local_index) < 0)
	{
		LM_ERR("Failed to parse key [%.*s]\n", key2->len, key2->s);
		return -1;
	}

	/* extract the entity and delete the tuple */
	lock_get(&b2bl_htable[hash_index].lock);

	tuple = b2bl_search_tuple_safe(hash_index, local_index);
	if(tuple == NULL)
	{
		LM_ERR("No entity found\n");
		goto error;
	}

	local_ctx_tuple = tuple;

	if(tuple->bridge_entities[0] && !tuple->bridge_entities[0]->disconnected)
	{
		e2 = tuple->bridge_entities[0];
		e = tuple->bridge_entities[1];
	}
	else
	if(tuple->bridge_entities[1] && !tuple->bridge_entities[1]->disconnected)
	{
		e2 = tuple->bridge_entities[1];
		e = tuple->bridge_entities[0];
	}
	tuple->cbf = 0;
	if(e2 == NULL)
	{
		LM_ERR("entity not found for key 2 [%.*s]\n", key2->len, key2->s);
		goto error;
	}
	if(e2->state != B2BL_ENT_CONFIRMED)
	{
		LM_ERR("Wrong state for entity ek= [%.*s], tk=[%.*s]\n",e2->key.len,
				e2->key.s, key2->len, key2->s);
		goto error;
	}

	if(e)
	{
		if(e->disconnected && e->state==B2BL_ENT_CONFIRMED)
		{
			memset(&rpl_data, 0, sizeof(b2b_rpl_data_t));
			PREP_RPL_DATA(e);
			rpl_data.method =METHOD_BYE;
			rpl_data.code =200;
			rpl_data.text =&ok;
			b2b_api.send_reply(&rpl_data);
		}
		else
		{
			b2b_end_dialog(e, tuple, hash_index);
		}
		e->peer = NULL;
	}

	// FIXME: this logic may need to be updated
	if(e2->type == B2B_SERVER)
	{
		if(e2 == tuple->servers[0])
		{
			tuple->servers[0] = tuple->servers[1];
			tuple->servers[1] = NULL;
		}
		else if(e2 == tuple->servers[1])
			tuple->servers[1] = NULL;
		else
		{
			LM_ERR("BUG: server entity [%.*s] not found\n",
				e2->key.len, e2->key.s);
			goto error;
		}
	}
	else if (e2->type == B2B_CLIENT)
	{
		if(e2 == tuple->clients[0])
		{
			tuple->clients[0] = tuple->clients[1];
			tuple->clients[1] = NULL;
		}
		else if(e2 == tuple->clients[1])
			tuple->clients[1] = NULL;
		else
		{
			LM_ERR("BUG: client entity [%.*s] not found\n",
				e2->key.len, e2->key.s);
			goto error;
		}
	}
	else
	{
		LM_ERR("BUG: unexpected entity type [%d] for [%.*s]\n",
				e2->type, e2->key.len, e2->key.s);
		goto error;
	}
	b2bl_delete(tuple, hash_index, 1, 1);

	lock_release(&b2bl_htable[hash_index].lock);

	/* must restore the b2bl_key for this entity in b2b_entities */

	local_ctx_tuple = NULL;

	if(b2bl_parse_key(key1, &hash_index, &local_index) < 0)
	{
		LM_ERR("Failed to parse key [%.*s]\n", key1->len, key1->s);
		return -1;
	}

	/* extract the entity and delete the tuple */
	lock_get(&b2bl_htable[hash_index].lock);

	tuple = b2bl_search_tuple_safe(hash_index, local_index);
	if(tuple == NULL)
	{
		LM_ERR("No entity found\n");
		goto error;
	}

	local_ctx_tuple = tuple;

	e1 = tuple->bridge_entities[0];
	if(e1 == NULL || e1->disconnected)
	{
		LM_ERR("entity not found for key 1 [%.*s]\n", key1->len, key1->s);
		goto error;
	}

	e = tuple->bridge_entities[1];
	if(e)
	{
		if(e->disconnected && e->state==B2BL_ENT_CONFIRMED)
		{
			memset(&rpl_data, 0, sizeof(b2b_rpl_data_t));
			PREP_RPL_DATA(e);
			rpl_data.method =METHOD_BYE;
			rpl_data.code =200;
			rpl_data.text =&ok;
			b2b_api.send_reply(&rpl_data);
		}
		b2b_end_dialog(e, tuple, hash_index);
		e->peer = NULL;
	}

	/* put it in clients list */
	e2->type = B2B_CLIENT;
	if (tuple->clients[0])
		tuple->clients[1] = e2;
	else
		tuple->clients[0] = e2;
	tuple->bridge_entities[1]= e2;

	e1->peer = e2;
	e2->peer = e1;
	e1->no = 0;
	e2->no = 1;

	if(b2b_api.update_b2bl_param(e2->type, &e2->key, tuple->key, 1) < 0)
	{
		LM_ERR("Failed to update b2bl parameter in b2b_entities\n");
		goto error;
	}
	LM_DBG("Updated b2bl param for entity [%.*s]\n", e2->key.len, e2->key.s);
	e1->stats.start_time = get_ticks();
	e1->stats.call_time = 0;
	memset(&req_data, 0, sizeof(b2b_req_data_t));
	PREP_REQ_DATA(e1);
	req_data.method =&method_invite;
	req_data.extra_headers = NULL;
	req_data.client_headers = &e1->hdrs;
	b2bl_htable[hash_index].locked_by = process_no;
	if(b2b_api.send_request(&req_data) < 0)
	{
		b2bl_htable[hash_index].locked_by = -1;
		LM_ERR("Failed to send reInvite\n");
		goto error;
	}
	b2bl_htable[hash_index].locked_by = -1;
	e1->sdp_type = B2BL_SDP_LATE;
	e1->state = 0;
	tuple->scenario_state = B2B_BRIDGING_STATE;
	if(max_duration)
		tuple->lifetime = get_ticks() + max_duration;
	else
		tuple->lifetime = 0;

	lock_release(&b2bl_htable[hash_index].lock);

	local_ctx_tuple = NULL;

	return 0;

error:
	if(tuple)
		b2b_mark_todel(tuple);
	lock_release(&b2bl_htable[hash_index].lock);
	local_ctx_tuple = NULL;
	return -1;
}

int b2bl_get_tuple_key(str *key, unsigned int *hash_index,
		unsigned int *local_index)
{
	char tuple_buffer[B2BL_MAX_KEY_LEN];
	str callid, from_tag, to_tag, tuple;

	/* check to see if the key is specified as callid;from_tag;to_tag */
	from_tag.s = q_memchr(key->s, ';', key->len);
	if (!from_tag.s) {
		LM_DBG("there's no tuple separator: must be plain key: %.*s\n",
				key->len, key->s);
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
	tuple.s = tuple_buffer;
	tuple.len = B2BL_MAX_KEY_LEN;
	if(b2b_api.get_b2bl_key(&callid, &from_tag, &to_tag, NULL, &tuple)) {
		LM_DBG("cannot find entity [%.*s]\n", key->len, key->s);
		return -2;
	}
	key = &tuple;
end:
	return b2bl_parse_key(key, hash_index, local_index);
}


/* Bridge an initial Invite with an existing dialog */
/* key and entity_no identity the existing call and the which entity from the call
 * to bridge (0 or 1) */
int b2bl_bridge_msg(struct sip_msg* msg, str* key, int entity_no)
{
	b2bl_tuple_t* tuple;
	struct b2b_context *ctx;
	struct b2b_ctx_val *v, *v_old;
	unsigned int hash_index, local_index;
	b2bl_entity_id_t *bridging_entity= NULL;
	b2bl_entity_id_t *old_entity;
	b2bl_entity_id_t *entity;
	str* server_id;
	str body, new_body = {0, 0};
	str to_uri={NULL,0}, from_uri, from_dname;
	b2b_req_data_t req_data;
	b2b_rpl_data_t rpl_data;
	int ret;

	if(!msg || !key)
	{
		LM_ERR("Wrong arguments [%p] [%p]\n", msg, key);
		return -1;
	}

	ret = b2bl_get_tuple_key(key, &hash_index, &local_index);
	if(ret < 0)
	{
		if (ret == -1)
			LM_ERR("Failed to parse key or find an entity [%.*s]\n",
					key->len, key->s);
		else
			LM_ERR("Could not find entity [%.*s]\n",
					key->len, key->s);
		return -1;
	}

	/* extract the entity and delete the tuple */
	lock_get(&b2bl_htable[hash_index].lock);

	tuple = b2bl_search_tuple_safe(hash_index, local_index);
	if(tuple == NULL)
	{
		LM_ERR("No entity found\n");
		goto error;
	}

	/* save tuple in global variable for accesss from local routes */
	local_ctx_tuple = tuple;

	/* update tuple context values with the new ones set in request route */
	for (v = local_ctx_vals; v; v = v->next) {
		for (v_old = tuple->vals; v_old; v_old = v_old->next)
			if (!str_strcmp(&v->name, &v_old->name)) {
				if (store_ctx_value(&tuple->vals, &v->name, &v->val) < 0)
					LM_ERR("Failed to store context value [%.*s]\n",
						v->name.len, v->name.s);

				break;
			}

		if (!v_old) {
			v->next = tuple->vals;
			tuple->vals = v;
		}
	}

	local_ctx_vals = NULL;

	/* save tuple in context for access in the request route */
	ctx = b2b_api.get_context();
	if (!ctx) {
		LM_ERR("Failed to get b2b context\n");
		goto error;
	}
	ctx->data = tuple;

	if(entity_no!=0 && entity_no!=1)
	{
		LM_ERR("entity_no param can take only 0 or 1 value, got [%d]\n",
			entity_no);
		goto error;
	}

	if (!tuple->bridge_entities[entity_no] ||
	tuple->bridge_entities[entity_no]->disconnected)
	{
		LM_ERR("Can not bridge requested entity [%p]\n",
			tuple->bridge_entities[entity_no]);
		goto error;
	}
	bridging_entity = tuple->bridge_entities[entity_no];
	old_entity = tuple->bridge_entities[(entity_no?0:1)];

	if(!old_entity || old_entity->next || old_entity->prev)
	{
		LM_ERR("Can not disconnect multiple entities\n");
		goto error;
	}

	if(bridging_entity->state != B2BL_ENT_CONFIRMED)
	{
		LM_ERR("Wrong state for entity ek=[%.*s], tk=[%.*s] state=%d\n",
			bridging_entity->key.len,bridging_entity->key.s, key->len, key->s,
			bridging_entity->state);
		goto error;
	}

	b2bl_print_tuple(tuple, L_DBG);

	LM_DBG("terminating b2bl_entity [%p]->[%.*s] type [%d]\n",
				old_entity, old_entity->key.len, old_entity->key.s,
				old_entity->type);
	if(old_entity->disconnected)
	{
		memset(&rpl_data, 0, sizeof(b2b_rpl_data_t));
		PREP_RPL_DATA(old_entity);
		rpl_data.method =METHOD_BYE;
		rpl_data.code =200;
		rpl_data.text =&ok;
		b2b_api.send_reply(&rpl_data);
	}
	else
	{
		memset(&req_data, 0, sizeof(b2b_req_data_t));
		PREP_REQ_DATA(old_entity);
		req_data.method =&method_bye;
		req_data.no_cb = 1;
		b2bl_htable[hash_index].locked_by = process_no;
		b2b_api.send_request(&req_data);
		b2bl_htable[hash_index].locked_by = -1;
		old_entity->disconnected = 1;
	}
	if (old_entity->peer->peer == old_entity)
		old_entity->peer->peer = NULL;
	else
	{
		LM_ERR("Unexpected chain: old_entity=[%p] and "
			"old_entity->peer->peer=[%p]\n",
			old_entity, old_entity->peer->peer);
		goto error;
	}
	old_entity->peer = NULL;

	/* remove the disconected entity from the tuple */
	if(0 == b2bl_drop_entity(old_entity, tuple))
	{
		LM_ERR("Inconsistent entity [%p] on tuple [%p]\n", old_entity, tuple);
		b2bl_print_tuple(tuple, L_ERR);
		goto error;
	}

	/* destroy the old_entity */
	b2b_api.entity_delete(old_entity->type, &old_entity->key,
		old_entity->dlginfo, 1, 1);
	if(old_entity->dlginfo)
		shm_free(old_entity->dlginfo);
	shm_free(old_entity);
	old_entity = NULL;

	b2bl_print_tuple(tuple, L_DBG);

	b2b_api.apply_lumps(msg);

	/* create server entity from Invite */
	if (b2b_msg_get_from(msg, &from_uri, &from_dname)< 0 ||
	b2b_msg_get_to(msg, &to_uri, b2bl_htable[hash_index].flags)< 0)
	{
		LM_ERR("Failed to get to or from from the message\n");
		goto error;
	}
	server_id = b2b_api.server_new(msg, &tuple->local_contact,
			b2b_server_notify, &b2bl_mod_name, tuple->key);
	if(server_id == NULL)
	{
		LM_ERR("failed to create new b2b server instance\n");
		pkg_free(to_uri.s);
		goto error;
	}

	entity = b2bl_create_new_entity(B2B_SERVER, server_id, &to_uri, &from_uri,
			0,0,0, msg);
	if(entity == NULL)
	{
		LM_ERR("Failed to create server entity\n");
		pkg_free(to_uri.s);
		goto error;
	}
	pkg_free(to_uri.s);

	if (0 != b2bl_add_server(tuple, entity))
		goto error;

	entity->peer = bridging_entity;
	bridging_entity->peer = entity;

	entity->stats.start_time = get_ticks();
	entity->stats.call_time = 0;

	bridging_entity->no = 0;
	entity->no = 1;

	/* send reInvite to the old entity*/
	if(msg->content_length)
	{
		if ( get_body(msg, &body)!=0 )
		{
			LM_ERR("cannot extract body\n");
			return -1;
		}
	}

	memset(&req_data, 0, sizeof(b2b_req_data_t));
	PREP_REQ_DATA(bridging_entity);
	req_data.method =&method_invite;
	req_data.client_headers =&bridging_entity->hdrs;
	req_data.body = &body;
	b2bl_htable[hash_index].locked_by = process_no;
	if(b2b_api.send_request(&req_data) < 0)
	{
		b2bl_htable[hash_index].locked_by = -1;
		LM_ERR("Failed to send reInvite\n");
		goto error;
	}
	b2bl_htable[hash_index].locked_by = -1;
	bridging_entity->sdp_type = B2BL_SDP_NORMAL;
	bridging_entity->state = 0;
	if(max_duration)
		tuple->lifetime = get_ticks() + max_duration;
	else
		tuple->lifetime = 0;

	tuple->bridge_entities[0] = bridging_entity;
	tuple->bridge_entities[1] = entity;

	b2bl_print_tuple(tuple, L_DBG);

	local_ctx_tuple = NULL;

	lock_release(&b2bl_htable[hash_index].lock);

	if(new_body.s)
		pkg_free(new_body.s);
	return 0;

error:
	if(tuple)
		b2b_mark_todel(tuple);
	lock_release(&b2bl_htable[hash_index].lock);
	if(new_body.s)
		pkg_free(new_body.s);
	local_ctx_tuple = NULL;
	return -1;
}
