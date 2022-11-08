/*
 * Copyright (C) 2022 OpenSIPS Solutions
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
 */

#include "../../parser/parse_uri.h"
#include "../presence/utils_func.h"

#include "entity_storage.h"
#include "records.h"
#include "b2b_logic.h"
#include "b2b_load.h"
#include "bridging.h"

extern b2bl_tuple_t *local_ctx_tuple;
extern struct b2b_ctx_val *local_ctx_vals;
extern struct b2bl_new_entity *new_entities[MAX_BRIDGE_ENT-1];
extern int new_entities_no;

static str method_bye   = {BYE, BYE_LEN};
static str method_notify= {NOTIFY, NOTIFY_LEN};
static str method_invite= {INVITE, INVITE_LEN};
static str method_ack   = {ACK, ACK_LEN};
static str method_update= {UPDATE, UPDATE_LEN};
static str ok = str_init("OK");
static str notTemporarilyUnavailable =
	str_init("Termporarily Unavailable - answered elsewhere");

void b2b_mark_todel( b2bl_tuple_t* tuple);
void b2b_end_dialog(b2bl_entity_id_t* bentity, b2bl_tuple_t* tuple,
	unsigned int hash_index);
b2bl_entity_id_t* b2bl_new_client(str* to_uri, str *proxy, str* from_uri,
	b2bl_tuple_t* tuple, str* ssid, str* hdrs, str *adv_ct, struct sip_msg* msg);
str *b2b_scenario_hdrs(struct b2bl_new_entity *entity);
int post_cb_sanity_check(b2bl_tuple_t **tuple, unsigned int hash_index,
	unsigned int local_index, b2bl_entity_id_t **entity, int etype, str *ekey);
int b2b_msg_get_from(struct sip_msg* msg, str* from_uri, str* from_dname);
int b2b_msg_get_to(struct sip_msg* msg, str* to_uri, int flags);
int b2b_msg_get_maxfwd(struct sip_msg *msg);

mi_response_t *mi_b2b_bridge(const mi_params_t *params,
							int entity_no, str *prov_media)
{
	str key;
	b2bl_tuple_t* tuple;
	str new_dest;
	b2bl_entity_id_t* entity, *old_entity, *bridging_entity, *prov_entity = 0;
	struct sip_uri uri;
	str meth_inv = {INVITE, INVITE_LEN};
	str meth_bye = {BYE, BYE_LEN};
	unsigned int hash_index, local_index;
	str ok= str_init("ok");
	b2b_req_data_t req_data;
	b2b_rpl_data_t rpl_data;
	int ret;

	if (get_mi_string_param(params, "dialog_id", &key.s, &key.len) < 0)
		return init_mi_param_error();

	if (get_mi_string_param(params, "new_uri", &new_dest.s, &new_dest.len) < 0)
		return init_mi_param_error();

	if(parse_uri(new_dest.s, new_dest.len, &uri)< 0)
	{
		LM_ERR("Bad argument. Not a valid uri [%.*s]\n", new_dest.len, new_dest.s);
		return init_mi_error(404, MI_SSTR("Invalid uri for the new destination"));
	}

	/* if 'flag' parameter is 1 - >
	 * means that destination from the current call must be
	 * bridged to the new destination */
	if (entity_no != 0 && entity_no != 1)
		return init_mi_error(404, MI_SSTR("Invalid 'flag' parameter"));

	if (prov_media) {
		/* parse new uri */
		if(parse_uri(prov_media->s, prov_media->len, &uri)< 0)
		{
			LM_ERR("Bad argument. Not a valid provisional media uri [%.*s]\n",
				   new_dest.len, new_dest.s);
			return init_mi_error(404, MI_SSTR("Bad 'prov_media_uri' parameter"));
		}
		prov_entity = b2bl_create_new_entity(B2B_CLIENT,
						0, prov_media, 0, 0, 0, 0, 0, 0, 0);
		if (!prov_entity) {
			LM_ERR("Failed to create new b2b entity\n");
			goto free;
		}
	}

	ret = b2bl_get_tuple_key(&key, &hash_index, &local_index);
	if(ret < 0)
	{
		if (ret == -1)
			LM_ERR("Failed to parse key or find an entity [%.*s]\n",
					key.len, key.s);
		else
			LM_ERR("Could not find entity [%.*s]\n",
					key.len, key.s);
		goto free;
	}

	entity = b2bl_create_new_entity(B2B_CLIENT, 0, &new_dest, 0, 0, 0, 0, 0, 0, 0);
	if(entity == NULL)
	{
		LM_ERR("Failed to create new b2b entity\n");
		goto free;
	}

	lock_get(&b2bl_htable[hash_index].lock);
	b2bl_htable[hash_index].locked_by = process_no;

	tuple = b2bl_search_tuple_safe(hash_index, local_index);
	if(tuple == NULL)
	{
		LM_ERR("No entity found\n");
		goto error;
	}

	local_ctx_tuple = tuple;

	if (!tuple->bridge_entities[entity_no] ||
	tuple->bridge_entities[entity_no]->disconnected)
	{
		LM_ERR("Can not bridge requested entity [%p]\n",
			tuple->bridge_entities[entity_no]);
		goto error;
	}

	bridging_entity = tuple->bridge_entities[entity_no];
	old_entity = tuple->bridge_entities[(entity_no?0:1)];

	if(old_entity == NULL || bridging_entity == NULL)
	{
		LM_ERR("Wrong dialog id\n");
		goto error;
	}

	if(old_entity->next || old_entity->prev)
	{
		LM_ERR("Can not disconnect entity [%p]\n", old_entity);
		b2bl_print_tuple(tuple, L_ERR);
		goto error;
	}

	if(bridging_entity->state != B2BL_ENT_CONFIRMED)
	{
		LM_ERR("Wrong state for entity ek= [%.*s], tk=[%.*s]\n",
			bridging_entity->key.len,bridging_entity->key.s,
			tuple->key->len, tuple->key->s);
		goto error;
	}

	b2bl_print_tuple(tuple, L_DBG);

	/* send BYE to old client */
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
		old_entity->disconnected = 1;
		memset(&req_data, 0, sizeof(b2b_req_data_t));
		PREP_REQ_DATA(old_entity);
		req_data.method =&meth_bye;
		b2b_api.send_request(&req_data);
	}

	if (0 == b2bl_drop_entity(old_entity, tuple))
	{
		LM_ERR("Inconsistent tuple [%p]\n", tuple);
		b2bl_print_tuple(tuple, L_ERR);
		goto error;
	}

	if (old_entity->peer->peer == old_entity)
		old_entity->peer->peer = NULL;
	else
	{
		LM_ERR("Unexpected chain: old_entity=[%p] and old_entity->peer->peer=[%p]\n",
			old_entity, old_entity->peer->peer);
		goto error;
	}
	old_entity->peer = NULL;

	tuple->bridge_entities[0]= bridging_entity;
	if (prov_entity) {
		tuple->bridge_entities[1]= prov_entity;
		tuple->bridge_entities[2]= entity;
		/* we don't have to free it anymore */
		prov_entity = 0;
	} else {
		tuple->bridge_entities[1]= entity;
		bridging_entity->peer = entity;
		entity->peer = bridging_entity;
	}

	tuple->state = B2B_BRIDGING_STATE;
	bridging_entity->state = 0;
	bridging_entity->sdp_type = B2BL_SDP_LATE;

	memset(&req_data, 0, sizeof(b2b_req_data_t));
	PREP_REQ_DATA(bridging_entity);
	req_data.method =&meth_inv;
	b2bl_htable[hash_index].locked_by = process_no;
	b2b_api.send_request(&req_data);
	b2bl_htable[hash_index].locked_by = -1;

	local_ctx_tuple = NULL;

	b2bl_htable[hash_index].locked_by = -1;;
	lock_release(&b2bl_htable[hash_index].lock);

	return init_mi_result_ok();

error:
	if(tuple)
		b2b_mark_todel(tuple);
	local_ctx_tuple = NULL;
	b2bl_htable[hash_index].locked_by = -1;
	lock_release(&b2bl_htable[hash_index].lock);
free:
	if (prov_entity)
		shm_free(prov_entity);
	return 0;
}

int process_bridge_dialog_end(b2bl_tuple_t* tuple, unsigned int hash_index,
	int entity_no, b2bl_entity_id_t* bentity)
{
	b2bl_entity_id_t* entity;

	if(entity_no == 0) /* if a negative reply received from the server */
	{
		/* send cancel or bye to the peers */
		b2b_end_dialog(tuple->bridge_entities[1], tuple, hash_index);
		b2b_end_dialog(tuple->bridge_entities[2], tuple, hash_index);
		b2b_mark_todel(tuple);
	}
	else
	if(entity_no == 1)  /* if a negative reply received from client or media server */
	{
		/* if the media server in 2 stage connecting did not reply */
		if(tuple->bridge_entities[2])
		{
			/* media server did not reply with success */
			b2bl_delete_entity(bentity, tuple, hash_index, 1);

			/* anyway contact the real destination */
			entity =  b2bl_new_client(&tuple->bridge_entities[2]->to_uri,
				&tuple->bridge_entities[2]->proxy, &tuple->bridge_entities[0]->from_uri, tuple,
				&tuple->bridge_entities[2]->scenario_id, &tuple->bridge_entities[2]->hdrs, NULL, NULL);

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

			return 1; // Don't delete tuple
		}
		else
		{
			if(tuple->bridge_flags & B2BL_BR_FLAG_RETURN_AFTER_FAILURE &&
				tuple->bridge_initiator != 0 && tuple->bridge_initiator->peer)
			{
				/* Delete failed entity */
				b2bl_delete_entity(bentity, tuple, hash_index, 1);

				/* Restore initial bridge */
				tuple->bridge_entities[1] = tuple->bridge_entities[0];
				tuple->bridge_entities[0] = tuple->bridge_initiator;

				tuple->bridge_entities[1]->peer = tuple->bridge_entities[0];
				tuple->bridge_entities[0]->peer = tuple->bridge_entities[1];

				/* Disable bridging state */
				tuple->state = B2B_NOTDEF_STATE;
				tuple->bridge_initiator = 0;

				return 1; // Don't delete tuple
			} else {
				/* the entity to connect replied with negative reply */
				b2b_end_dialog(tuple->bridge_entities[0], tuple, hash_index);
				b2b_mark_todel(tuple);
			}
		}
	}
	if(entity_no == 2) /* if a negative reply received from real destination in case of media server used */
	{
		if(tuple->bridge_flags & B2BL_BR_FLAG_RETURN_AFTER_FAILURE &&
			tuple->bridge_initiator != 0 && tuple->bridge_initiator->peer)
		{
			/* Delete failed entity */
			b2bl_delete_entity(bentity, tuple, hash_index, 1);

			/* End media entity */
			b2b_end_dialog(tuple->bridge_entities[1], tuple, hash_index);

			tuple->bridge_entities[2] = NULL;
			tuple->bridge_entities[1] = tuple->bridge_entities[0];
			tuple->bridge_entities[0] = tuple->bridge_initiator;

			tuple->bridge_entities[1]->peer = tuple->bridge_entities[0];
			tuple->bridge_entities[0]->peer = tuple->bridge_entities[1];

			/* Disable bridging state */
			tuple->state = B2B_NOTDEF_STATE;
			tuple->bridge_initiator = 0;

			return 1; // Don't delete tuple
		} else {
			/* if the final destination replied with negative reply */
			b2b_end_dialog(tuple->bridge_entities[0], tuple, hash_index);
			b2b_end_dialog(tuple->bridge_entities[1], tuple, hash_index);
			b2b_mark_todel(tuple);
		}
	}
	else /* if a negative reply received from bridge initiator */
	{
		/* send cancel or bye to the peers */
		b2b_end_dialog(tuple->bridge_entities[0], tuple, hash_index);
		b2b_end_dialog(tuple->bridge_entities[1], tuple, hash_index);
		b2b_end_dialog(tuple->bridge_entities[2], tuple, hash_index);
		b2b_mark_todel(tuple);
	}

	return 0;
}

int process_bridge_bye(struct sip_msg* msg,  b2bl_tuple_t* tuple,
	unsigned int hash_index, b2bl_entity_id_t* entity)
{
	int entity_no;
	b2b_rpl_data_t rpl_data;

	if (tuple->bridge_flags & B2BL_BR_FLAG_RETURN_AFTER_FAILURE &&
		entity && tuple->bridge_initiator == entity)
	{
		entity_no = 3; // Bridge initiator
	} else {
		entity_no = bridge_get_entityno(tuple, entity);
		if(entity_no < 0)
		{
			LM_ERR("No match found\n");
			return -1;
		}
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
			tuple->state = B2B_NONE;
			break;
		case 1: break;
		case 2: break;
		default:
			LM_ERR("unexpected entity_no [%d] for tuple [%p]\n",
				entity_no, tuple);
			return -1;
	}

	/* call the callback for brigding failure  */
	cbf = tuple->cb.f;
	if(cbf && (tuple->cb.mask&B2B_REJECT_CB))
	{
		memset(&cb_params, 0, sizeof(b2bl_cb_params_t));
		cb_params.param = tuple->cb.param;
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
		cb_params.key = tuple->key;

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

int process_bridge_200OK(struct sip_msg* msg, str* extra_headers,
		str* body, b2bl_tuple_t* tuple, unsigned int hash_index,
		b2bl_entity_id_t* entity)
{
	str* client_id;
	b2bl_entity_id_t* bentity0, *bentity1;
	client_info_t ci;
	int entity_no;
	b2b_req_data_t req_data;
	struct sip_uri ct_uri;

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
		} else if(bentity1->type == B2B_CLIENT && bentity1->state!=B2BL_ENT_CONFIRMED) {
			LM_DBG("Send invite to %.*s Proxy %.*s\n", bentity1->to_uri.len,
				bentity1->to_uri.s, bentity1->proxy.len, bentity1->proxy.s);
			memset(&ci, 0, sizeof(client_info_t));
			ci.method        = method_invite;
			ci.to_uri        = bentity1->to_uri;
			ci.dst_uri       = bentity1->proxy;

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
			ci.maxfwd = bentity0->init_maxfwd;

			if (bentity1->adv_contact.s) {
				ci.local_contact = bentity1->adv_contact;
			} else {
				memset(&ct_uri, 0, sizeof(struct sip_uri));
				if (contact_user && parse_uri(ci.from_uri.s, ci.from_uri.len, &ct_uri) < 0) {
					LM_ERR("Not a valid sip uri [%.*s]\n", ci.from_uri.len, ci.from_uri.s);
					return -1;
				}
				get_local_contact(ci.send_sock, &ct_uri.user, &ci.local_contact);
			}

			if (str2int( &(get_cseq(msg)->number), &ci.cseq)!=0 )
			{
				LM_ERR("cannot parse cseq number\n");
				return -1;
			}
			bentity0->state = B2BL_ENT_CONFIRMED;

			b2bl_htable[hash_index].locked_by = process_no;

			client_id = b2b_api.client_new(&ci, b2b_client_notify,
					b2b_add_dlginfo, &b2bl_mod_name, tuple->key,
					get_tracer(tuple), NULL, NULL);

			b2bl_htable[hash_index].locked_by = -1;

			if(client_id == NULL)
			{
				LM_ERR("Failed to create new client entity\n");
				return -1;
			}

			/* save the client_id in the structure */
			entity = b2bl_create_new_entity(B2B_CLIENT, client_id, &ci.to_uri, 0,
				&ci.from_uri, 0, &bentity1->scenario_id, &bentity1->hdrs,
				bentity1->adv_contact.s ? &bentity1->adv_contact : NULL, 0);
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
			/* bridging scenario should be done */
			tuple->state = B2B_NOTDEF_STATE;
			LM_DBG("Finished the bridging\n");
		}
		else
		{
			/* contact the real destination */
			entity =  b2bl_new_client(&tuple->bridge_entities[2]->to_uri,
				&tuple->bridge_entities[2]->proxy, &bentity0->from_uri, tuple,
				&tuple->bridge_entities[2]->scenario_id,
				&tuple->bridge_entities[2]->hdrs,
				tuple->bridge_entities[2]->adv_contact.s ?
				&tuple->bridge_entities[2]->adv_contact : NULL, msg);
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

#define BUF_LEN  128

int send_bridge_notify(b2bl_entity_id_t *entity, unsigned int hash_index,
	struct sip_msg* msg)
{
	b2b_req_data_t req_data;
	static char def_hdrs[] = "Event: refer\r\nContent-Type: message/sipfrag\r\nSubscription-State: ";
	static char buf[BUF_LEN];
	static str trying_s = str_init("SIP/2.0 100 Trying");
	str body;
	static str hdrs = {buf, 0};

	if (msg && msg->first_line.type != SIP_REPLY) {
		LM_ERR("send_bridge_notify works only with replies!\n");
		return -1;
	}

	memset(&req_data, 0, sizeof(b2b_req_data_t));
	PREP_REQ_DATA(entity);
	req_data.method = &method_notify;
	req_data.client_headers = &entity->hdrs;
	req_data.body = 0;
	if (!msg) {
		body = trying_s;
		hdrs.len = snprintf(buf, BUF_LEN, "%sactive;expires=%d\r\n", def_hdrs, 60);
	} else {
		body.s = msg->first_line.u.reply.version.s;
		body.len = msg->first_line.u.reply.version.len +
				msg->first_line.u.reply.status.len +
				msg->first_line.u.reply.reason.len + 2;
		hdrs.len = snprintf(buf, BUF_LEN, "%sterminated;reason=noresource\r\n", def_hdrs);
	}
	LM_DBG("Sending notify [%.*s]\n", body.len, body.s);
	if ((unsigned)hdrs.len >= BUF_LEN) {
		LM_ERR("Buffer is too small\n");
		return -1;
	}
	req_data.extra_headers = &hdrs;
	req_data.body = &body;
	b2bl_htable[hash_index].locked_by = process_no;
	if (b2b_api.send_request(&req_data) < 0) {
		LM_ERR("Failed to send NOTIFY\n");
		b2bl_htable[hash_index].locked_by = -1;
		return -1;
	}
	b2bl_htable[hash_index].locked_by = -1;

	return 0;
}

static struct b2bl_new_entity *get_ent_to_bridge(b2bl_tuple_t *tuple,
	b2bl_entity_id_t *cur_entity, str *ent_str, b2bl_entity_id_t **old_ent)
{
	struct b2bl_new_entity *new_br_ent = NULL;
	b2bl_entity_id_t** entity_head = NULL;
	b2bl_entity_id_t *e;
	int i;

	if (cur_entity && !str_strcmp(ent_str, const_str("this"))) {
		*old_ent = cur_entity;
	} else if (cur_entity && !str_strcmp(ent_str, const_str("peer"))) {
		*old_ent = b2bl_search_entity(tuple, &cur_route_ctx.peer_key,
			cur_route_ctx.peer_type, &entity_head);
		if(*old_ent == NULL)
		{
			LM_DBG("Peer not found [%.*s], src=%d\n", cur_route_ctx.peer_key.len,
				cur_route_ctx.peer_key.s, cur_route_ctx.peer_type);
		}
	} else {
		/* search through existing entities */
		for (i = 0; i < MAX_B2BL_ENT; i++) {
			e = tuple->servers[i];
			if (e) {
				if (e->next || e->prev) {
					LM_ERR("Inconsistent entity [%p]\n", e);
					b2bl_print_tuple(tuple, L_ERR);
					return NULL;
				}
				if (!str_strcmp(ent_str, &e->scenario_id)) {
					*old_ent = e;
					break;
				}
			}
			e = tuple->clients[i];
			if (e) {
				if (e->next || e->prev)
				{
					LM_ERR("Inconsistent entity [%p]\n", e);
					b2bl_print_tuple(tuple, L_ERR);
					return NULL;
				}
				if (!str_strcmp(ent_str, &e->scenario_id)) {
					*old_ent = e;
					break;
				}
			}
		}
		if (!*old_ent) {
			/* must be a new entity created with b2b_client_new() */
			if (new_entities[0] && new_entities[0]->type == B2B_CLIENT &&
				!str_strcmp(ent_str, &new_entities[0]->id))
				new_br_ent = new_entities[0];
			else if (new_entities[1] && new_entities[1]->type == B2B_CLIENT &&
				!str_strcmp(ent_str, &new_entities[1]->id))
				new_br_ent = new_entities[1];
			else
				LM_ERR("Unknown bridge entity: %.*s\n", ent_str->len, ent_str->s);
		}
	}

	return new_br_ent;
}

int b2b_script_bridge(struct sip_msg *msg, str *br_ent1_str, str *br_ent2_str,
	str *provmedia_uri, struct b2b_bridge_params *params)
{
	b2bl_tuple_t *tuple;
	b2bl_entity_id_t *entity, *e = NULL, *old_entity = NULL;
	b2bl_entity_id_t** entity_head = NULL;
	struct b2bl_new_entity *new_br_ent[2];
	int rc = -1;

	if (!(cur_route_ctx.flags & B2BL_RT_REQ_CTX)) {
		LM_ERR("The 'b2b_bridge' function can only be used from the "
			"b2b_logic dedicated request routes\n");
		return -1;
	}

	lock_get(&b2bl_htable[cur_route_ctx.hash_index].lock);
	tuple = b2bl_search_tuple_safe(cur_route_ctx.hash_index,
		cur_route_ctx.local_index);
	if(tuple == NULL)
	{
		LM_ERR("B2B logic record not found\n");
		goto done;
	}

	tuple->bridge_flags = params->flags;

	entity = b2bl_search_entity(tuple, &cur_route_ctx.entity_key,
		cur_route_ctx.entity_type, &entity_head);
	if(entity == NULL)
	{
		LM_DBG("No b2b_key match found [%.*s], src=%d\n", cur_route_ctx.entity_key.len,
			cur_route_ctx.entity_key.s, cur_route_ctx.entity_type);
	} else {
		if (entity->no > 1)
		{
			LM_ERR("unexpected entity->no [%d] for tuple [%p]\n", entity->no, tuple);
			goto done;
		}
	}

	if (new_entities_no == 0) {
		LM_ERR("At least one new client entity required for bridging\n");
		goto done;
	}

	new_br_ent[0] = get_ent_to_bridge(tuple, entity, br_ent1_str, &e);


	if (e)
		old_entity = e;
	else if (!new_br_ent[0])
		goto done;

	e = NULL;
	new_br_ent[1] = get_ent_to_bridge(tuple, entity, br_ent2_str, &e);

	if (e) {
		if (old_entity)
			LM_ERR("At least one new client entity required for bridging\n");
		else
			old_entity = e;
	} else if (!new_br_ent[1])
		goto done;

	if (params->flags & B2BL_BR_FLAG_NOTIFY && entity)
		send_bridge_notify(entity, cur_route_ctx.hash_index, NULL);

	if (b2bl_bridge(msg, tuple, cur_route_ctx.hash_index,
		old_entity, new_br_ent, provmedia_uri, params->lifetime) < 0) {
		LM_ERR("Failed to process bridge action\n");
		goto done;
	}

	if ((params->flags & B2BL_BR_FLAG_NOTIFY ||
		params->flags & B2BL_BR_FLAG_RETURN_AFTER_FAILURE) && entity)
		tuple->bridge_initiator = entity;

	cur_route_ctx.flags |= B2BL_RT_DO_UPDATE;

	rc = 1;

done:
	lock_release(&b2bl_htable[cur_route_ctx.hash_index].lock);

	if (new_entities[0]) {
		pkg_free(new_entities[0]);
		new_entities[0] = NULL;
	}
	if (new_entities[1]) {
		pkg_free(new_entities[1]);
		new_entities[1] = NULL;
	}
	new_entities_no = 0;

	return rc;
}

/* This function does the following actions:
 *	- extract the entities description from the scenario document
 *	- send invite or reInvite to one of the parties
 *	 - mark in the scenario instantiation which are the bridged entities and
 *	 that this scenario is currently taking place
 *	*/

int b2bl_bridge(struct sip_msg* msg, b2bl_tuple_t* tuple,
	unsigned hash_index, b2bl_entity_id_t *old_entity,
	struct b2bl_new_entity *new_br_ent[2], str *provmedia_uri, int lifetime)
{
	b2bl_entity_id_t* bridge_entities[3];
	b2bl_entity_id_t* entity = NULL;
	int count = 0;
	client_info_t ci;
	str* client_id;
	b2b_req_data_t req_data;
	str *hdrs;
	int i;
	struct sip_uri ct_uri;

	memset(bridge_entities, 0, 2*sizeof(b2bl_entity_id_t*));

	for (i = 0; i < 2; i++) {
		/* must create a new client entity */
		if (new_br_ent[i]) {
			hdrs = b2b_scenario_hdrs(new_br_ent[i]);

			LM_DBG("New entity, dest = [%.*s]\n",
				new_br_ent[i]->dest_uri.len, new_br_ent[i]->dest_uri.s);

			entity = b2bl_create_new_entity(B2B_CLIENT, 0, &new_br_ent[i]->dest_uri,
				new_br_ent[i]->proxy.s?&new_br_ent[i]->proxy:0,
				new_br_ent[i]->from_dname.s?&new_br_ent[i]->from_dname:0, 0,
				new_br_ent[i]->id.s ? &new_br_ent[i]->id : NULL, hdrs,
				new_br_ent[i]->adv_contact.s ? &new_br_ent[i]->adv_contact : NULL, 0);
			if(entity == NULL)
			{
				LM_ERR("Failed to create new b2b entity\n");
				goto error;
			}
		} else
			entity = old_entity;

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

		if(provmedia_uri)
		{
			tuple->bridge_entities[2]= bridge_entities[1];

			tuple->bridge_entities[1] = b2bl_create_new_entity(B2B_CLIENT, 0,
				provmedia_uri, 0, 0, 0,0,0,0,0);
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
		str proxy      = bridge_entities[0]->proxy;
		str from_dname = bridge_entities[0]->from_dname;
		str hdrs = bridge_entities[0]->hdrs;

		memset(&ci, 0, sizeof(client_info_t));
		ci.method        = method_invite;
		ci.to_uri        = to_uri;
		ci.dst_uri       = proxy;
		ci.from_uri      = from_uri;
		ci.from_dname    = from_dname;
		ci.extra_headers = tuple->extra_headers;
		ci.client_headers= &hdrs;
		ci.from_tag      = 0;
		ci.send_sock     = msg?(msg->force_send_socket?msg->force_send_socket:msg->rcv.bind_address):0;

		if (bridge_entities[0]->adv_contact.len) {
			ci.local_contact = bridge_entities[0]->adv_contact;
		} else if (ci.send_sock) {
			memset(&ct_uri, 0, sizeof(struct sip_uri));
			if (contact_user && parse_uri(ci.from_uri.s, ci.from_uri.len, &ct_uri) < 0) {
				LM_ERR("Not a valid sip uri [%.*s]\n", ci.from_uri.len, ci.from_uri.s);
				goto error1;
			}
			get_local_contact(ci.send_sock, &ct_uri.user, &ci.local_contact);
		} else if (server_address.s) {
			 ci.local_contact = server_address;
		} else {
			LM_ERR("'server_address' modparam required in order to to set Contact\n");
			goto error1;
		}

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

		client_id = b2b_api.client_new(&ci, b2b_client_notify, b2b_add_dlginfo,
				&b2bl_mod_name, tuple->key, get_tracer(tuple), NULL, NULL);

		b2bl_htable[hash_index].locked_by = -1;

		if(client_id == NULL)
		{
			LM_ERR("Failed to create new client entity\n");
			goto error1;
		}

		/* save the client_id in the structure */
		entity = b2bl_create_new_entity(B2B_CLIENT, client_id, &to_uri, 0,
			&from_uri,0, bridge_entities[0]->scenario_id.s ?
			&bridge_entities[0]->scenario_id : NULL, &hdrs,
			bridge_entities[0]->adv_contact.s ? &bridge_entities[0]->adv_contact :
			NULL, 0);
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
		entity->sdp_type = B2BL_SDP_LATE;
		shm_free(bridge_entities[0]);

		tuple->bridge_entities[0] = entity;
		tuple->bridge_entities[1]= bridge_entities[1];

		if (0 != b2bl_add_client(tuple, entity))
			goto error1;
	}
	/* save the pointers to the bridged entities ;
	 * the first (index 0) is the one we sent the first message ( reInvite or Invite)*/
	tuple->state = B2B_BRIDGING_STATE;

	if (lifetime)
	{
		tuple->lifetime = lifetime + get_ticks();
		LM_DBG("Lifetime defined = [%d]\n", tuple->lifetime);
	}
	else
		tuple->lifetime = -1;

	LM_DBG("be[0] = [%p], be[1] = [%p]\n", tuple->bridge_entities[0], tuple->bridge_entities[1]);
	return 0;

error1:
	shm_free(bridge_entities[0]);
	shm_free(bridge_entities[1]);

error:
	return -1;
}

int b2bl_api_bridge(str* key, str* new_dst, str *new_proxy, str* new_from_dname,
	int entity_no)
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

	if(tuple->state == B2B_BRIDGING_STATE &&
			tuple->bridge_entities[0]== tuple->servers[0] &&
			tuple->servers[0]->state== B2BL_ENT_CONFIRMED)
	{
		LM_DBG("Do the second step of the bridging\n");
		/* do the second step of bridging */
		memset(&ci, 0, sizeof(client_info_t));
		ci.method        = method_invite;
		ci.to_uri        = *new_dst;
		ci.dst_uri       = *new_proxy;
		ci.from_uri      = tuple->servers[0]->to_uri;
		ci.from_dname    = *new_from_dname;
		ci.extra_headers = tuple->extra_headers;
		ci.client_headers= &tuple->servers[0]->hdrs;
		ci.body          = tuple->b1_sdp.s?&tuple->b1_sdp:0;
		ci.cseq          = 1;
		ci.local_contact = tuple->local_contact;
		ci.maxfwd = tuple->servers[0]->init_maxfwd;

		b2bl_htable[hash_index].locked_by = process_no;

		client_id = b2b_api.client_new(&ci, b2b_client_notify, b2b_add_dlginfo,
				&b2bl_mod_name, tuple->key, get_tracer(tuple), NULL, NULL);

		b2bl_htable[hash_index].locked_by = -1;

		if(client_id == NULL)
		{
			LM_ERR("Failed to create new client entity\n");
			goto error;
		}
		/* save the client_id in the structure */
		entity = b2bl_create_new_entity(B2B_CLIENT, client_id, &ci.to_uri, 0,
			&ci.from_uri, 0, 0, &tuple->servers[0]->hdrs,
			tuple->servers[0]->adv_contact.s ?
			&tuple->servers[0]->adv_contact : NULL, 0);
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
		entity = b2bl_create_new_entity( B2B_CLIENT, 0, new_dst, new_proxy, 0,
			new_from_dname,0,0,0,0);
		if(entity == NULL)
		{
			LM_ERR("Failed to create new b2b entity\n");
			goto error;
		}
		LM_DBG("Created new client entity [%.*s]\n", new_dst->len, new_dst->s);

		tuple->state = B2B_BRIDGING_STATE;
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
	tuple->cb.f = 0;
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
	tuple->state = B2B_BRIDGING_STATE;
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

/* Bridge an initial Invite with an existing dialog */
/* key and entity_no identity the existing call and the which entity from the call
 * to bridge (0 or 1) */
int b2bl_bridge_msg(struct sip_msg* msg, str* key, int entity_no, str *adv_ct)
{
	b2bl_tuple_t* tuple;
	struct b2b_context *ctx;
	struct b2b_ctx_val *v, *v_old;
	unsigned int hash_index, local_index;
	b2bl_entity_id_t *bridging_entity= NULL;
	b2bl_entity_id_t *old_entity;
	b2bl_entity_id_t *entity;
	str* server_id;
	str body = {0, 0}, new_body = {0, 0}, contact = {0, 0};
	str to_uri={NULL,0}, from_uri, from_dname;
	b2b_req_data_t req_data;
	b2b_rpl_data_t rpl_data;
	int update = 0;
	int ret;
	struct sip_uri ct_uri;
	str local_contact;
	int maxfwd;

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
	ctx->init = 1;
	ctx->hash_index = hash_index;
	ctx->local_index = local_index;

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

	if(!b2b_early_update && bridging_entity->state != B2BL_ENT_CONFIRMED)
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
		if(old_entity->state == B2BL_ENT_CONFIRMED)
		{		
			memset(&req_data, 0, sizeof(b2b_req_data_t));
			PREP_REQ_DATA(old_entity);
			req_data.method =&method_bye;
			req_data.no_cb = 1;
			b2bl_htable[hash_index].locked_by = process_no;
			b2b_api.send_request(&req_data);
			b2bl_htable[hash_index].locked_by = -1;
		}
		else
		{
			memset(&rpl_data, 0, sizeof(b2b_rpl_data_t));
			PREP_RPL_DATA(old_entity);
			rpl_data.method = METHOD_INVITE;
			rpl_data.code =480;
			rpl_data.text =&notTemporarilyUnavailable;
			b2b_api.send_reply(&rpl_data);
			
			update = 1;			
		}
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
	b2bl_htable[hash_index].locked_by = process_no;
	b2b_api.entity_delete(old_entity->type, &old_entity->key,
		old_entity->dlginfo, 1, 1);
	b2bl_htable[hash_index].locked_by = -1;
	if(old_entity->dlginfo)
		shm_free(old_entity->dlginfo);
	shm_free(old_entity);
	old_entity = NULL;

	b2bl_print_tuple(tuple, L_DBG);

	b2b_api.apply_lumps(msg);

	if (!adv_ct) {
		memset(&ct_uri, 0, sizeof(struct sip_uri));
		if (contact_user && parse_uri(to_uri.s, to_uri.len, &ct_uri) < 0) {
			LM_ERR("Not a valid sip uri [%.*s]\n", to_uri.len, to_uri.s);
			goto error;
		}

		if (get_local_contact(msg->rcv.bind_address, &ct_uri.user, &local_contact) < 0)
		{
			LM_ERR("Failed to get received address\n");
			local_contact = tuple->local_contact;
		}
	}

	if (server_address.len > 0)
	{
		if (pv_printf_s(msg, server_address_pve, &contact) != 0)
		{
			LM_WARN("Failed to build contact from server address\n");
			if (!msg || get_local_contact(msg->rcv.bind_address, NULL, &contact) < 0)
			{
				LM_ERR("Failed to build contact from received address\n");
				goto error;
			}
		}
	}
	else
	{
		if(msg)
		{
			if (get_local_contact(msg->rcv.bind_address, NULL, &contact) < 0)
			{
				LM_ERR("Failed to build contact from received address\n");
				goto error;
			}
		}
	}
	if (contact.len <= 0)
	{
		LM_ERR("Unable to define contact\n");
		goto error;
	}
	LM_DBG("Contact: %.*s\n", contact.len, contact.s);

	/* create server entity from Invite */
	if (b2b_msg_get_from(msg, &from_uri, &from_dname)< 0 ||
	b2b_msg_get_to(msg, &to_uri, b2bl_htable[hash_index].flags)< 0)
	{
		LM_ERR("Failed to get to or from from the message\n");
		goto error;
	}
	server_id = b2b_api.server_new(msg, adv_ct ? adv_ct : &local_contact,
			b2b_server_notify, &b2bl_mod_name, tuple->key,
			get_tracer(tuple), NULL, NULL);
	if(server_id == NULL)
	{
		LM_ERR("failed to create new b2b server instance\n");
		pkg_free(to_uri.s);
		goto error;
	}

	entity = b2bl_create_new_entity(B2B_SERVER, server_id, &to_uri, 0, &from_uri,
			0,0,0, adv_ct, msg);
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
	if (update) {
		req_data.method =&method_update;
	}
	else
	{
		req_data.method =&method_invite;
	}
	req_data.client_headers =&bridging_entity->hdrs;
	req_data.body = &body;
	/* Decrement Max-Forwards value */
	if ((maxfwd = b2b_msg_get_maxfwd(msg)) > 0)
		req_data.maxfwd = maxfwd;
	b2bl_htable[hash_index].locked_by = process_no;
	if(b2b_api.send_request(&req_data) < 0)
	{
		b2bl_htable[hash_index].locked_by = -1;
		LM_ERR("Failed to send Update/reInvite\n");
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
