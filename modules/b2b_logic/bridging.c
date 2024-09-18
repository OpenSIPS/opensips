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
#include "../../parser/sdp/sdp.h"
#include "../../parser/parse_methods.h"

#include "entity_storage.h"
#include "records.h"
#include "b2b_logic.h"
#include "b2b_load.h"
#include "bridging.h"

extern b2bl_tuple_t *local_ctx_tuple;
extern struct b2b_ctx_val *local_ctx_vals;

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
b2bl_entity_id_t *b2bl_new_client(client_info_t *ci, b2bl_tuple_t *tuple,
	str *ssid, str *adv_ct, struct sip_msg *msg);
str *b2b_scenario_hdrs(struct b2bl_new_entity *entity);
int post_cb_sanity_check(b2bl_tuple_t **tuple, unsigned int hash_index,
	unsigned int local_index, b2bl_entity_id_t **entity, int etype, str *ekey);
int b2b_msg_get_from(struct sip_msg* msg, str* from_uri, str* from_dname);
int b2b_msg_get_to(struct sip_msg* msg, str* to_uri, int flags);
int b2b_msg_get_maxfwd(struct sip_msg *msg);

static int bridging_start_new_ent(b2bl_tuple_t* tuple, b2bl_entity_id_t *old_entity,
	b2bl_entity_id_t *new_entity, str *body, struct sip_msg* msg, int replace);
static b2bl_entity_id_t *bridging_new_client(b2bl_tuple_t* tuple,
	b2bl_entity_id_t *peer_ent, b2bl_entity_id_t *new_ent,
	str *body, struct sip_msg *msg, int set_maxfwd);
static int bridging_start_old_ent(b2bl_tuple_t* tuple, b2bl_entity_id_t *old_entity,
	b2bl_entity_id_t *new_entity, str *provmedia_uri, str *body);

int retry_init_bridge(struct sip_msg *msg, b2bl_tuple_t* tuple,
	b2bl_entity_id_t *entity, struct b2bl_new_entity *new_entity);

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

	B2BL_LOCK_GET(hash_index);

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

	if (old_entity->peer) {
		if (old_entity->peer->peer == old_entity)
			old_entity->peer->peer = NULL;
		else
		{
			LM_ERR("Unexpected chain: old_entity=[%p] and old_entity->peer->peer=[%p]\n",
				old_entity, old_entity->peer->peer);
			goto error;
		}
		old_entity->peer = NULL;
	}

	tuple->bridge_entities[0]= bridging_entity;

	if (prov_entity) {
		tuple->bridge_entities[1]= prov_entity;
		tuple->bridge_entities[2]= entity;
		/* we don't have to free it anymore */
		prov_entity = 0;

		bridging_entity->state = B2BL_ENT_NEW;
		bridging_entity->sdp_type = B2BL_SDP_LATE;

		memset(&req_data, 0, sizeof(b2b_req_data_t));
		PREP_REQ_DATA(bridging_entity);
		req_data.method =&meth_inv;
		b2b_api.send_request(&req_data);
	} else {
		if (bridging_start_new_ent(tuple, bridging_entity, entity, NULL, NULL, 0) < 0) {
			LM_ERR("Failed to start bridging with new entity\n");
			goto error;
		}

		shm_free(entity);
	}

	tuple->state = B2B_BRIDGING_STATE;

	local_ctx_tuple = NULL;

	B2BL_LOCK_RELEASE(hash_index);

	return init_mi_result_ok();

error:
	if(tuple)
		b2b_mark_todel(tuple);
	local_ctx_tuple = NULL;
	B2BL_LOCK_RELEASE(hash_index);
free:
	if (prov_entity)
		shm_free(prov_entity);
	return 0;
}

int process_bridge_dialog_end(b2bl_tuple_t* tuple, unsigned int hash_index,
	int entity_no, b2bl_entity_id_t* bentity)
{
	b2bl_entity_id_t* entity;
	str *body;

	if(entity_no == 0) /* if a negative reply received from the first entity */
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

			body = (tuple->bridge_flags & B2BL_BR_FLAG_RENEW_SDP) ?
				&tuple->bridge_entities[0]->in_sdp : NULL;

			/* anyway contact the real destination */
			entity = bridging_new_client(tuple, tuple->bridge_entities[0],
				tuple->bridge_entities[2], body, NULL, 1);
			if (!entity)
				return -1;

			entity->sdp_type = body ? B2BL_SDP_NORMAL : B2BL_SDP_LATE;
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
				tuple->state = B2B_BRIDGED_STATE;
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

			/* renegotiate the SDP between the remainging entites */
			if (bridging_start_old_ent(tuple, tuple->bridge_entities[0],
				tuple->bridge_entities[1], NULL, NULL) < 0) {
				LM_ERR("Failed to start bridging with old entity\n");
				return -1;
			}

			tuple->state = B2B_BRIDGING_STATE;
			tuple->bridge_initiator = 0;

			return 1; // Don't delete tuple
		} else {
			/* if the final destination replied with negative reply */
			b2b_end_dialog(tuple->bridge_entities[0], tuple, hash_index);
			b2b_end_dialog(tuple->bridge_entities[1], tuple, hash_index);
			b2b_mark_todel(tuple);
		}
	}
	else /* if rollback feature is used and BYE received from bridge initiator */
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
			tuple->state = B2B_CANCEL_STATE;
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

		B2BL_LOCK_RELEASE(hash_index);

		ret = cbf(&cb_params, B2B_REJECT_CB);
		LM_DBG("ret = %d\n", ret);

		B2BL_LOCK_GET(hash_index);
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
	b2bl_entity_id_t* bentity0, *bentity1;
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
	LM_DBG("entity_no = %d, entity=%p, be[0]= %p\n",
		entity_no, entity, tuple->bridge_entities[0]);

	switch (tuple->state) {
	case B2B_BRIDGING_HOLD_STATE:
		if (entity_no != 0) {
			LM_ERR("Unexpected 200 OK reply from entity: %d "
				"in bridging state [%d]\n", entity_no, tuple->state);
			return -1;
		}

		bentity0->state = B2BL_ENT_CONFIRMED;

		/* send ACK to first entity */
		memset(&req_data, 0, sizeof(b2b_req_data_t));
		req_data.et =bentity0->type;
		req_data.b2b_key =&bentity0->key;
		req_data.method =&method_ack;
		req_data.dlginfo =bentity0->dlginfo;
		if(b2b_api.send_request(&req_data) < 0)
		{
			LM_ERR("Failed to send ACK in bridging state [%d]\n", tuple->state);
			return -1;
		}

		if (tuple->bridge_flags & B2BL_BR_FLAG_RENEW_SDP) {
			if (tuple->bridge_entities[2]) {
				/* connect the old entity with the prov media server */
				if (bridging_start_old_ent(tuple, bentity0, bentity1,
					NULL, NULL) < 0) {
					LM_ERR("Failed to start bridging with provisional media\n");
					return -1;
				}

				tuple->state = B2B_BRIDGING_STATE;
			} else {
				/* connect the new entity but using the initial SDP from
				 * the old entity for now */
				if (bridging_start_new_ent(tuple, bentity0, bentity1,
					&bentity0->in_sdp, msg, 1) < 0) {
					LM_ERR("Failed to start bridging with new entity\n");
					return -1;
				}

				tuple->state = B2B_BRIDGING_INIT_SDP_STATE;
			}
		} else {
			if (tuple->bridge_entities[2]) {
				/* connect the old entity with the prov media server */
				if (bridging_start_old_ent(tuple, bentity0, bentity1,
					NULL, NULL) < 0) {
					LM_ERR("Failed to start bridging with provisional media\n");
					return -1;
				}

				tuple->state = B2B_BRIDGING_STATE;
			} else {
				/* connect the new entity with late sdp */
				if (bridging_start_new_ent(tuple, bentity0, bentity1,
					NULL, msg, 1) < 0) {
					LM_ERR("Failed to start bridging with new entity\n");
					return -1;
				}

				tuple->state = B2B_BRIDGING_STATE;
			}
		}

		return 0;
	case B2B_BRIDGING_INIT_SDP_STATE:
		if (entity_no != 1) {
			LM_ERR("Unexpected 200 OK reply from entity: %d "
				"in bridging state [%d]\n", entity_no, tuple->state);
			return -1;
		}

		bentity1->state = B2BL_ENT_CONFIRMED;

		bentity1->stats.setup_time = get_ticks() - bentity1->stats.start_time;
		bentity1->stats.start_time = get_ticks();

		/* send ACK to second entity */
		memset(&req_data, 0, sizeof(b2b_req_data_t));
		req_data.et =bentity1->type;
		req_data.b2b_key =&bentity1->key;
		req_data.method =&method_ack;
		req_data.dlginfo =bentity1->dlginfo;
		if(b2b_api.send_request(&req_data) < 0)
		{
			LM_ERR("Failed to send second ACK in bridging scenario\n");
			return -1;
		}
		if (shm_str_sync(&bentity1->in_sdp, body) < 0)
			LM_ERR("Failed to save SDP\n");

		if (bridging_start_old_ent(tuple, bentity0, bentity1,
			NULL, NULL) < 0) {
			LM_ERR("Failed to start bridging with old entity\n");
			return -1;
		}

		tuple->state = B2B_BRIDGING_STATE;

		return 0;
	case B2B_BRIDGING_STATE:
		break;
	default:
		LM_ERR("Unexpected bridging state: %d\n", tuple->state);
		return -1;
	}

	/* main bridging steps */
	if(entity_no == 0)
	{
		if (bentity0->sdp_type == B2BL_SDP_NORMAL) {
			/* second 200 OK reply */

			bentity0->state = B2BL_ENT_CONFIRMED;

			bentity1->stats.setup_time = get_ticks() - bentity1->stats.start_time;
			bentity1->stats.start_time = get_ticks();
			bentity0->stats.setup_time = get_ticks() - bentity0->stats.start_time;
			bentity0->stats.start_time = get_ticks();

			/* send ACK with body to the second entity */
			memset(&req_data, 0, sizeof(b2b_req_data_t));
			req_data.et = bentity1->type;
			req_data.b2b_key =&bentity1->key;
			req_data.method =&method_ack;
			req_data.extra_headers =extra_headers;
			req_data.body = body;
			req_data.dlginfo =bentity1->dlginfo;
			if(b2b_api.send_request(&req_data) < 0)
			{
				LM_ERR("Failed to send first ACK in bridging scenario\n");
				return -1;
			}

			/* send ACK without a body to the first entity */
			memset(&req_data, 0, sizeof(b2b_req_data_t));
			req_data.et =bentity0->type;
			req_data.b2b_key =&bentity0->key;
			req_data.method =&method_ack;
			req_data.dlginfo =bentity0->dlginfo;
			if(b2b_api.send_request(&req_data) < 0)
			{
				LM_ERR("Failed to send second ACK in bridging scenario\n");
				return -1;
			}

			if (shm_str_sync(&bentity0->in_sdp, body) < 0) {
				LM_ERR("Failed to save SDP\n");
				return -1;
			}
			if (shm_str_sync(&bentity1->out_sdp, body) < 0) {
				LM_ERR("Failed to save SDP\n");
				return -1;
			}

			tuple->bridge_entities[1]->peer = tuple->bridge_entities[0];
			tuple->bridge_entities[0]->peer = tuple->bridge_entities[1];

			tuple->state = B2B_BRIDGED_STATE;
			LM_DBG("Finished the bridging\n");

			return 0;
		}

		/* first 200 OK reply */
		if(bentity1->key.s && bentity1->state < B2BL_ENT_CONFIRMED) /* already been in this step*/
		{
			LM_ERR("A retransmission of the reply from the first leg\n");
			return -1;
		} else if(bentity1->type == B2B_CLIENT && bentity1->state!=B2BL_ENT_CONFIRMED) {
			LM_DBG("Send invite to [%.*s] Proxy [%.*s]\n", bentity1->to_uri.len,
				bentity1->to_uri.s, bentity1->proxy.len, bentity1->proxy.s);

			bentity0->state = B2BL_ENT_CONFIRMED;

			entity = bridging_new_client(tuple, bentity0, bentity1, body, msg, 1);
			if (!entity)
				return -1;

			b2bl_delete_entity(bentity1, tuple, hash_index, 1);

			entity->sdp_type = B2BL_SDP_NORMAL;
			entity->no =1;
			tuple->bridge_entities[1] = entity;
			bentity1 = entity;
			if (0 != b2bl_add_client(tuple, entity))
				return -1;
		} else if (bentity1->type == B2B_CLIENT &&
			bentity1->state==B2BL_ENT_CONFIRMED) {
			/* send reInvite to second entity as it is already connected
			 * (after the B2B_BRIDGING_INIT_SDP_STATE state or after
			   a SDP renewal was triggered because of a rollback) */

			bentity0->state = B2BL_ENT_CONFIRMED;

			bentity1->stats.start_time = get_ticks();
			bentity1->stats.call_time = 0;

			memset(&req_data, 0, sizeof(b2b_req_data_t));
			req_data.et =bentity1->type;
			req_data.b2b_key =&bentity1->key;
			req_data.method =&method_invite;
			req_data.client_headers=&bentity1->hdrs;;
			req_data.extra_headers =extra_headers;
			req_data.body = body;
			req_data.dlginfo =bentity1->dlginfo;
			if(b2b_api.send_request(&req_data) < 0)
			{
				LM_ERR("Failed to send reINVITE in bridging state [%d]\n",
					tuple->state);
				return -1;
			}
			bentity1->sdp_type = B2BL_SDP_NORMAL;
			bentity1->state = B2BL_ENT_NEW;
		} else if (bentity1->type == B2B_SERVER) {
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
			if(b2b_api.send_request(&req_data) < 0)
			{
				LM_ERR("Failed to send second INVITE in bridging scenario\n");
				return -1;
			}
			bentity1->sdp_type = B2BL_SDP_NORMAL;
			bentity1->state = B2BL_ENT_NEW;
		} else {
			LM_ERR("Unexpected entity state [%d]\n", bentity1->state);
			return -1;
		}

		tuple->bridge_entities[1]->peer = tuple->bridge_entities[0];
		tuple->bridge_entities[0]->peer = tuple->bridge_entities[1];

		if (tuple->bridge_entities[2] == NULL) {
			if (shm_str_sync(&bentity0->in_sdp, body) < 0) {
				LM_ERR("Failed to save SDP\n");
				return -1;
			}
			if (shm_str_sync(&bentity1->out_sdp, body) < 0) {
				LM_ERR("Failed to save SDP\n");
				return -1;
			}
		}
	}
	else
	if(entity_no == 1) /* from provisional media server or from final destination */
	{
		if (bentity1->sdp_type == B2BL_SDP_LATE) {
			/* first 200 OK reply -> send reInvite to first entity */

			bentity1->state = B2BL_ENT_CONFIRMED;

			bentity0->stats.start_time = get_ticks();
			bentity0->stats.call_time = 0;
			memset(&req_data, 0, sizeof(b2b_req_data_t));
			PREP_REQ_DATA(bentity0);
			req_data.method =&method_invite;
			req_data.extra_headers = NULL;
			req_data.client_headers = &bentity0->hdrs;
			req_data.body = body;
			b2b_api.send_request(&req_data);
			bentity0->state = B2BL_ENT_NEW;
			bentity0->sdp_type = B2BL_SDP_NORMAL;

			if (shm_str_sync(&bentity1->in_sdp, body) < 0) {
				LM_ERR("Failed to save SDP\n");
				return -1;
			}
			if (shm_str_sync(&bentity0->out_sdp, body) < 0) {
				LM_ERR("Failed to save SDP\n");
				return -1;
			}

			tuple->bridge_entities[1]->peer = tuple->bridge_entities[0];
			tuple->bridge_entities[0]->peer = tuple->bridge_entities[1];

			return 0;
		}

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
		if(b2b_api.send_request(&req_data) < 0)
		{
			LM_ERR("Failed to send first ACK in bridging scenario\n");
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
			return -1;
		}

		tuple->bridge_entities[1]->peer = tuple->bridge_entities[0];
		tuple->bridge_entities[0]->peer = tuple->bridge_entities[1];

		if(tuple->bridge_entities[2] == NULL)
		{
			if (shm_str_sync(&bentity1->in_sdp, body) < 0) {
				LM_ERR("Failed to save SDP\n");
				return -1;
			}
			if (shm_str_sync(&bentity0->out_sdp, body) < 0) {
				LM_ERR("Failed to save SDP\n");
				return -1;
			}

			/* bridging scenario should be done */
			tuple->state = B2B_BRIDGED_STATE;
			LM_DBG("Finished the bridging\n");
			tuple->bridge_flags &= ~B2BL_BR_FLAG_PENDING_SDP;
		}
		else
		{
			body = (tuple->bridge_flags & B2BL_BR_FLAG_RENEW_SDP) ?
				&bentity0->in_sdp : NULL;

			/* contact the real destination */
			entity = bridging_new_client(tuple, bentity0,
				tuple->bridge_entities[2], body, msg, 1);
			if (!entity)
				return -1;

			entity->sdp_type = body ? B2BL_SDP_NORMAL : B2BL_SDP_LATE;
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
		if(b2b_api.send_request(&req_data) < 0)
		{
			LM_ERR("Failed to send second Invite in bridging scenario\n");
			return -1;
		}
		bentity0->state = B2BL_ENT_NEW;

		if (shm_str_sync(&bentity1->in_sdp, body) < 0) {
			LM_ERR("Failed to save SDP\n");
			return -1;
		}
		if (shm_str_sync(&bentity0->out_sdp, body) < 0) {
			LM_ERR("Failed to save SDP\n");
			return -1;
		}

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
	req_data.no_cb = 1;
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
	if (b2b_api.send_request(&req_data) < 0) {
		LM_ERR("Failed to send NOTIFY\n");
		return -1;
	}

	return 0;
}

static struct b2bl_new_entity *get_ent_to_bridge(b2bl_tuple_t *tuple,
	b2bl_entity_id_t *cur_entity, str *ent_str, b2bl_entity_id_t **old_ent)
{
	struct b2bl_new_entity *new_br_ent = NULL, *e1, *e2;
	b2bl_entity_id_t** entity_head = NULL;
	b2bl_entity_id_t *e;
	int i;

	if (!str_strcmp(ent_str, const_str("this"))) {
		if (!cur_entity) {
			LM_ERR("Current entity not found anymore\n");
			return NULL;
		}
		*old_ent = cur_entity;
	} else if (!str_strcmp(ent_str, const_str("peer"))) {
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
			if (get_new_entities(&e1, &e2) < 0) {
				LM_ERR("Failed to get new bridging entities from context\n");
				return NULL;
			}

			/* must be a new entity created with b2b_client_new() */
			if (e1 && e1->type == B2B_CLIENT && !str_strcmp(ent_str, &e1->id))
				new_br_ent = e1;
			else if (e2 && e2->type == B2B_CLIENT && !str_strcmp(ent_str, &e2->id))
				new_br_ent = e2;
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

	B2BL_LOCK_GET(cur_route_ctx.hash_index);

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

	if (get_new_entities(&new_br_ent[0], &new_br_ent[1]) < 0) {
		LM_ERR("Failed to get new bridging entities from context\n");
		goto done;
	}
	if (!new_br_ent[0] && !new_br_ent[1]) {
		LM_ERR("At least one new client entity required for bridging\n");
		goto done;
	}

	new_br_ent[0] = get_ent_to_bridge(tuple, entity, br_ent1_str, &e);

	if (e)
		old_entity = e;
	else if (!new_br_ent[0]) {
		LM_ERR("Failed to get entity to bridge: %.*s\n", br_ent1_str->len,
			br_ent1_str->s);
		goto done;
	}

	e = NULL;
	new_br_ent[1] = get_ent_to_bridge(tuple, entity, br_ent2_str, &e);

	if (e) {
		if (old_entity)
			LM_ERR("both entities are already bridged - trying the first one\n");
		else
			old_entity = e;
	} else if (!new_br_ent[1]) {
		LM_ERR("Failed to get entity to bridge: %.*s\n", br_ent2_str->len,
			br_ent2_str->s);
		goto done;
	}

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
	B2BL_LOCK_RELEASE(cur_route_ctx.hash_index);

	return rc;
}

int b2b_script_bridge_retry(struct sip_msg *msg, str *new_ent_str)
{
	b2bl_tuple_t *tuple;
	b2bl_entity_id_t *entity;
	str method;
	int statuscode;
	unsigned int method_value;
	b2bl_entity_id_t** entity_head = NULL;
	struct b2bl_new_entity *e1, *e2;

	if (!(cur_route_ctx.flags & B2BL_RT_RPL_CTX)) {
		LM_ERR("The 'b2b_bridge_retry' function can only be used from the "
			"b2b_logic dedicated reply route\n");
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
		LM_ERR("No b2b_key match found [%.*s], src=%d\n",
			cur_route_ctx.entity_key.len, cur_route_ctx.entity_key.s,
			cur_route_ctx.entity_type);
		goto error;
	}

	LM_DBG("b2b_entity key = %.*s\n",
		cur_route_ctx.entity_key.len, cur_route_ctx.entity_key.s);

	method = get_cseq(msg)->method;
	if(parse_method(method.s, method.s+method.len, &method_value) == NULL)
	{
		LM_ERR("Failed to parse method\n");
		goto error;
	}
	if (method_value != METHOD_INVITE) {
		LM_ERR("The 'b2b_bridge_retry' function can only be used for"
			"replies to INVITES\n");
		goto error;
	}

	statuscode = msg->first_line.u.reply.statuscode;
	if (statuscode <= 300) {
		LM_ERR("The 'b2b_bridge_retry' function can only be used for"
			"negative replies\n");
		goto error;
	}

	if (entity != tuple->bridge_entities[1]) {
		LM_ERR("The 'b2b_bridge_retry' function can only be used for"
			"negative replies from the second entity\n");
		goto error;
	}

	if (get_new_entities(&e1, &e2) < 0) {
		LM_ERR("Failed to get new bridging entities from context\n");
		goto error;
	}
	if (!e1) {
		LM_ERR("A new client entity is required for bridge retry\n");
		goto error;
	}

	if (str_strcmp(new_ent_str, &e1->id)) {
		LM_ERR("Unknown client entity %.*s\n", new_ent_str->len, new_ent_str->s);
		goto error;
	}

	local_ctx_tuple = tuple;

	if (IS_BRIDGING_STATE(tuple->state)) {
		b2bl_delete_entity(entity, tuple, tuple->hash_index, 1);

		entity = b2bl_create_new_entity( B2B_CLIENT, 0, &e1->dest_uri,
			&e1->proxy, 0, &e1->from_dname,
			0,0,0,0);
		if(entity == NULL)
		{
			LM_ERR("Failed to create new b2b entity\n");
			goto error;
		}
		LM_DBG("Created new client entity [%.*s]\n",
			e1->dest_uri.len, e1->dest_uri.s);

		if (bridging_start_new_ent(tuple, tuple->bridge_entities[0], entity,
			NULL, msg, 0) < 0) {
			LM_ERR("Failed to start bridging with new entity\n");
			goto error;
		}

		tuple->state = B2B_BRIDGING_STATE;
	} else if (tuple->state == B2B_INIT_BRIDGING_STATE) {
		if (retry_init_bridge(msg, tuple, entity, e1) < 0) {
			LM_ERR("Failed to retry initial bridge\n");
			goto error;
		}
	} else {
		LM_ERR("Unable to retry bridge for tuple in state: %d\n", tuple->state);
		goto error;
	}

	local_ctx_tuple = NULL;

	B2BL_LOCK_RELEASE(cur_route_ctx.hash_index);

	return 1;

error:
	local_ctx_tuple = NULL;
	B2BL_LOCK_RELEASE(cur_route_ctx.hash_index);
	return -1;
}

static b2bl_entity_id_t *bridging_new_client(b2bl_tuple_t* tuple,
	b2bl_entity_id_t *peer_ent, b2bl_entity_id_t *new_ent,
	str *body, struct sip_msg *msg, int set_maxfwd)
{
	client_info_t ci;
	b2bl_entity_id_t *entity;

	memset(&ci, 0, sizeof(client_info_t));

	ci.to_uri = new_ent->to_uri;
	ci.dst_uri = new_ent->proxy;
	if (peer_ent->type == B2B_CLIENT) {
		ci.from_uri = peer_ent->to_uri;

		if (new_ent->from_dname.s)
			ci.from_dname = new_ent->from_dname;
		else
			ci.from_dname = peer_ent->from_dname;
	} else {
		if (new_ent->from_uri.s)
			ci.from_uri = new_ent->from_uri;
		else
			ci.from_uri = peer_ent->from_uri;

		if (new_ent->from_dname.s)
			ci.from_dname = new_ent->from_dname;
		else
			ci.from_dname = peer_ent->from_dname;
	}

	ci.client_headers = &new_ent->hdrs;
	ci.body = body;
	if (set_maxfwd)
		ci.maxfwd = peer_ent->init_maxfwd;
	ci.extra_headers = tuple->extra_headers;

	entity = b2bl_new_client(&ci, tuple, &new_ent->scenario_id,
		new_ent->adv_contact.s ? &new_ent->adv_contact : NULL, msg);
	if(entity == NULL)
	{
		LM_ERR("Failed to generate new client\n");
		return NULL;
	}

	return entity;
}

static int bridging_start_new_ent(b2bl_tuple_t* tuple, b2bl_entity_id_t *old_entity,
	b2bl_entity_id_t *new_entity, str *body, struct sip_msg* msg, int replace)
{
	b2bl_entity_id_t *entity;

	LM_DBG("Send Invite to new entity\n");

	entity = bridging_new_client(tuple, old_entity, new_entity, body, msg, 1);
	if (!entity)
		return -1;

	if (replace)
		b2bl_delete_entity(new_entity, tuple, tuple->hash_index, 1);

	if (0 != b2bl_add_client(tuple, entity))
		goto error;

	if (body) {
		if (!body->s) {
			LM_ERR("SDP not found\n");
			goto error;
		}
		entity->sdp_type = B2BL_SDP_NORMAL;
	} else {
		entity->sdp_type = B2BL_SDP_LATE;
	}

	entity->no = 1;
	tuple->bridge_entities[1] = entity;

	return 0;
error:
	shm_free(entity);
	return -1;
}

static int bridging_start_old_ent(b2bl_tuple_t* tuple, b2bl_entity_id_t *old_entity,
	b2bl_entity_id_t *new_entity, str *provmedia_uri, str *body)
{
	b2b_req_data_t req_data;

	LM_DBG("Send reInvite to old entity\n");

	tuple->bridge_entities[1] = new_entity;

	if(provmedia_uri)
	{
		tuple->bridge_entities[2]= new_entity;

		tuple->bridge_entities[1] = b2bl_create_new_entity(B2B_CLIENT, 0,
			provmedia_uri, 0, 0, 0,0,0,0,0);
		if(tuple->bridge_entities[1] == NULL)
		{
			LM_ERR("Failed to create new b2b entity\n");
			return -1;
		}
	}

	old_entity->stats.start_time = get_ticks();
	old_entity->stats.call_time = 0;
	memset(&req_data, 0, sizeof(b2b_req_data_t));
	PREP_REQ_DATA(old_entity);
	req_data.method =&method_invite;
	req_data.extra_headers = NULL;
	req_data.client_headers = &old_entity->hdrs;
	req_data.body = body;
	b2b_api.send_request(&req_data);
	old_entity->state = B2BL_ENT_NEW;
	if (body) {
		if (!body->s) {
			LM_ERR("SDP not found\n");
			return -1;
		}
		old_entity->sdp_type = B2BL_SDP_NORMAL;
	} else {
		old_entity->sdp_type = B2BL_SDP_LATE;
	}

	return 0;
}

static int sdp_get_hold_body(str *body, str *new_body)
{
	static sdp_info_t sdp;
	sdp_session_cell_t *session;
	sdp_stream_cell_t *stream;
	str session_hdr;
	int attr_to_add = 0;
	int len, streamnum;

	new_body->len = 0;

	if (parse_sdp_session(body, 0, NULL, &sdp) < 0) {
		LM_ERR("could not parse SDP\n");
		return -1;
	}

	/* we only have one session, so there's no need to iterate */
	streamnum = 0;
	session = sdp.sessions;
	session_hdr.s = session->body.s;
	session_hdr.len = session->body.len;
	for (stream = session->streams; stream; stream = stream->next) {
		/* first stream indicates where session header ends */
		if (session_hdr.len > stream->body.s - session->body.s)
			session_hdr.len = stream->body.s - session->body.s;
		if (stream->sendrecv_mode.len == 0)
			attr_to_add++;
		else if (strncasecmp(stream->sendrecv_mode.s, "inactive", 8) == 0)
			continue; /* do not disable already disabled stream */
		streamnum++;
	}
	if (!streamnum)
		return 0; /* nothing to change */

	new_body->s = pkg_malloc(body->len + attr_to_add * 12 /* a=inactive\r\n */);
	if (!new_body->s) {
		LM_ERR("oom for new body!\n");
		return -1;
	}

	/* copy everything untill the first stream */
	memcpy(new_body->s, session_hdr.s, session_hdr.len);
	new_body->len = session_hdr.len;
	for (streamnum = 0; streamnum < session->streams_num; streamnum++) {
		for (stream = session->streams; stream; stream = stream->next) {
			/* make sure the streams are in the same order */
			if (stream->stream_num != streamnum)
				continue;
			if (stream->sendrecv_mode.len) {
				len = stream->sendrecv_mode.s - stream->body.s;
				memcpy(new_body->s + new_body->len, stream->body.s,
						stream->sendrecv_mode.s - stream->body.s);
				new_body->len += len;
				memcpy(new_body->s + new_body->len, "inactive", 8);
				new_body->len += 8;
				len += stream->sendrecv_mode.len;
				memcpy(new_body->s + new_body->len, stream->sendrecv_mode.s +
						stream->sendrecv_mode.len, stream->body.len - len);
				new_body->len += stream->body.len - len;
			} else {
				memcpy(new_body->s + new_body->len, stream->body.s, stream->body.len);
				new_body->len += stream->body.len;
				memcpy(new_body->s + new_body->len, "a=inactive\r\n", 12);
				new_body->len += 12;
			}
		}
	}

	return 1;
}

int bridging_start_hold(b2bl_tuple_t* tuple, b2bl_entity_id_t *old_entity,
	b2bl_entity_id_t *new_entity, str *provmedia_uri)
{
	str hold_body;
	int rc;

	rc = sdp_get_hold_body(&old_entity->out_sdp, &hold_body);
	if (rc < 0) {
		LM_ERR("Failed to build hold SDP body\n");
		return -1;
	} else if (rc == 0 || hold_body.len == 0) {
		LM_DBG("First entity already on hold\n");

		tuple->bridge_entities[1] = new_entity;

		if(provmedia_uri)
		{
			tuple->bridge_entities[2]= new_entity;

			tuple->bridge_entities[1] = b2bl_create_new_entity(B2B_CLIENT, 0,
				provmedia_uri, 0, 0, 0,0,0,0,0);
			if(tuple->bridge_entities[1] == NULL)
			{
				LM_ERR("Failed to create new b2b entity\n");
				return -1;
			}
		}

		return 0;
	} else {
		rc = bridging_start_old_ent(tuple, old_entity, new_entity, provmedia_uri,
			&hold_body);

		pkg_free(hold_body.s);
		return rc;
	}
}

int b2bl_bridge(struct sip_msg* msg, b2bl_tuple_t* tuple,
	unsigned hash_index, b2bl_entity_id_t *old_entity,
	struct b2bl_new_entity *new_br_ent[2], str *provmedia_uri, int lifetime)
{
	b2bl_entity_id_t* bridge_entities[2];
	b2bl_entity_id_t* entity = NULL;
	str *hdrs;
	int i;

	memset(bridge_entities, 0, 2*sizeof(b2bl_entity_id_t*));

	for (i = 0; i < 2; i++) {
		/* must create at least one new client entity */
		if (new_br_ent[i]) {
			hdrs = b2b_scenario_hdrs(new_br_ent[i]);

			LM_DBG("New entity, dest = [%.*s]\n",
				new_br_ent[i]->dest_uri.len, new_br_ent[i]->dest_uri.s);

			entity = b2bl_create_new_entity(B2B_CLIENT, 0, &new_br_ent[i]->dest_uri,
				new_br_ent[i]->proxy.s?&new_br_ent[i]->proxy:0, NULL,
				new_br_ent[i]->from_dname.s?&new_br_ent[i]->from_dname:0,
				new_br_ent[i]->id.s ? &new_br_ent[i]->id : NULL, hdrs,
				new_br_ent[i]->adv_contact.s ? &new_br_ent[i]->adv_contact : NULL, 0);
			if(entity == NULL)
			{
				LM_ERR("Failed to create new b2b entity\n");
				goto error;
			}
		} else
			entity = old_entity;

		bridge_entities[i] = entity;
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

	if (provmedia_uri)
		tuple->bridge_flags |= B2BL_BR_FLAG_PROV_MEDIA;

	/* I have the two entities ->  now do the first step of the bridging scenario
	 * -> send reInvite or Invite to one of the parties */
	if(old_entity)
	{
		tuple->bridge_entities[0] = old_entity;

		if (tuple->bridge_flags & B2BL_BR_FLAG_HOLD) {
			/* put the old entity on hold first */
			if (bridging_start_hold(tuple, old_entity, bridge_entities[1],
				provmedia_uri) < 0) {
				LM_ERR("Failed to put old entity on hold\n");
				goto error;
			}

			tuple->state = B2B_BRIDGING_HOLD_STATE;
		} else if (tuple->bridge_flags & B2BL_BR_FLAG_RENEW_SDP) {
			if (provmedia_uri) {
				/* connect the old entity with the prov media server */
				if (bridging_start_old_ent(tuple, old_entity, bridge_entities[1],
					provmedia_uri, NULL) < 0) {
					LM_ERR("Failed to start bridging with provisional media\n");
					goto error;
				}

				tuple->state = B2B_BRIDGING_STATE;
			} else {
				/* connect the new entity but using the initial SDP from
				 * the old entity for now */
				if (bridging_start_new_ent(tuple, old_entity, bridge_entities[1],
					&old_entity->in_sdp, msg, 0) < 0) {
					LM_ERR("Failed to start bridging with new entity\n");
					goto error;
				}

				tuple->state = B2B_BRIDGING_INIT_SDP_STATE;
				shm_free(bridge_entities[1]);
			}
		} else {
			if (provmedia_uri) {
				/* connect the old entity with the prov media server */
				if (bridging_start_old_ent(tuple, old_entity, bridge_entities[1],
					provmedia_uri, NULL) < 0) {
					LM_ERR("Failed to start bridging with provisional media\n");
					goto error;
				}

				tuple->state = B2B_BRIDGING_STATE;
			} else {
				/* connect the new entity with late sdp */
				if (bridging_start_new_ent(tuple, old_entity, bridge_entities[1],
					NULL, msg, 0) < 0) {
					LM_ERR("Failed to start bridging with new entity\n");
					goto error;
				}

				tuple->state = B2B_BRIDGING_STATE;
				shm_free(bridge_entities[1]);
			}
		}
	}
	else
	{
		entity = bridging_new_client(tuple, bridge_entities[1],
			bridge_entities[0], NULL, msg, 0);
		if (!entity)
			goto error1;

		if (0 != b2bl_add_client(tuple, entity))
			goto error;

		entity->peer = bridge_entities[1];
		entity->sdp_type = B2BL_SDP_LATE;
		shm_free(bridge_entities[0]);

		tuple->bridge_entities[0] = entity;
		tuple->bridge_entities[1]= bridge_entities[1];

		tuple->state = B2B_BRIDGING_STATE;
		tuple->bridge_flags |= B2BL_BR_FLAG_NO_OLD_ENT;
	}

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
	b2b_rpl_data_t rpl_data;
	struct b2bl_new_entity new_ent;

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

	B2BL_LOCK_GET(hash_index);

	tuple = b2bl_search_tuple_safe(hash_index, local_index);
	if(tuple == NULL)
	{
		LM_ERR("No entity found\n");
		goto error;
	}

	local_ctx_tuple = tuple;

	if (tuple->state == B2B_INIT_BRIDGING_STATE) {
		memset(&new_ent, 0, sizeof new_ent);
		new_ent.dest_uri = *new_dst;
		new_ent.proxy = *new_proxy;
		new_ent.from_dname = *new_from_dname;

		if (retry_init_bridge(NULL, tuple, tuple->bridge_entities[1],
			&new_ent) < 0) {
			LM_ERR("Failed to retry initial bridge\n");
			goto error;
		}

		local_ctx_tuple = NULL;
		B2BL_LOCK_RELEASE(hash_index);

		return 0;
	}

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

	entity = b2bl_create_new_entity( B2B_CLIENT, 0, new_dst, new_proxy, 0,
		new_from_dname,0,0,0,0);
	if(entity == NULL)
	{
		LM_ERR("Failed to create new b2b entity\n");
		goto error;
	}
	LM_DBG("Created new client entity [%.*s]\n", new_dst->len, new_dst->s);

	if (bridging_start_new_ent(tuple, tuple->servers[0], entity,
		NULL, NULL, 0) < 0) {
		LM_ERR("Failed to start bridging with new entity\n");
		goto error;
	}

	tuple->state = B2B_BRIDGING_STATE;

	tuple->bridge_entities[0]= tuple->servers[0];
	tuple->servers[0]->no = 0;

	local_ctx_tuple = NULL;

	B2BL_LOCK_RELEASE(hash_index);

	return 0;

error:
	if(entity)
		shm_free(entity);
	local_ctx_tuple = NULL;
	B2BL_LOCK_RELEASE(hash_index);
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
	B2BL_LOCK_GET(hash_index);

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

	B2BL_LOCK_RELEASE(hash_index);

	/* must restore the b2bl_key for this entity in b2b_entities */

	local_ctx_tuple = NULL;

	if(b2bl_parse_key(key1, &hash_index, &local_index) < 0)
	{
		LM_ERR("Failed to parse key [%.*s]\n", key1->len, key1->s);
		return -1;
	}

	/* extract the entity and delete the tuple */
	B2BL_LOCK_GET(hash_index);

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
	if(b2b_api.send_request(&req_data) < 0)
	{
		LM_ERR("Failed to send reInvite\n");
		goto error;
	}
	e1->sdp_type = B2BL_SDP_LATE;
	e1->state = 0;
	tuple->state = B2B_BRIDGING_STATE;
	if(max_duration)
		tuple->lifetime = get_ticks() + max_duration;
	else
		tuple->lifetime = 0;

	B2BL_LOCK_RELEASE(hash_index);

	local_ctx_tuple = NULL;

	return 0;

error:
	if(tuple)
		b2b_mark_todel(tuple);
	B2BL_LOCK_RELEASE(hash_index);
	local_ctx_tuple = NULL;
	return -1;
}


int bridge_msg_term_entity(b2bl_entity_id_t *old_entity,
													unsigned int *hash_index)
{
	b2b_req_data_t req_data;
	b2b_rpl_data_t rpl_data;

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
			if (hash_index)
				b2bl_htable[*hash_index].locked_by = process_no;
			b2b_api.send_request(&req_data);
			if (hash_index)
				b2bl_htable[*hash_index].locked_by = -1;
		}
		else
		{
			memset(&rpl_data, 0, sizeof(b2b_rpl_data_t));
			PREP_RPL_DATA(old_entity);
			rpl_data.method = METHOD_INVITE;
			rpl_data.code =480;
			rpl_data.text =&notTemporarilyUnavailable;
			b2b_api.send_reply(&rpl_data);
		}
		old_entity->disconnected = 1;
	}

	/* destroy the old_entity */
	if (hash_index)
		b2bl_htable[*hash_index].locked_by = process_no;
	b2b_api.entity_delete(old_entity->type, &old_entity->key,
		old_entity->dlginfo, 1, 1);
	if (hash_index)
		b2bl_htable[*hash_index].locked_by = -1;
	if(old_entity->dlginfo)
		shm_free(old_entity->dlginfo);
	shm_free(old_entity);

	return 0;
}

int insert_entity_term_tl(b2bl_entity_id_t *entity)
{
	struct b2b_term_t_list *tl;

	tl = shm_malloc(sizeof *tl);
	if (!tl) {
		LM_ERR("no more shm memory\n");
		return -1;
	}
	memset(tl, 0, sizeof *tl);

	tl->entity = entity;
	tl->timeout = get_ticks() + ent_term_interval;

	lock_get(ent_term_timer->lock);

	if (!ent_term_timer->first)
		ent_term_timer->first = tl;
	else
		ent_term_timer->last->next = tl;

	ent_term_timer->last = tl;

	lock_release(ent_term_timer->lock);

	return 0;
}

struct b2b_term_t_list *get_entities_term_tl(unsigned int now)
{
	struct b2b_term_t_list *ret = NULL, *tl = NULL;

	lock_get(ent_term_timer->lock);

	/* empty list */
	if (!ent_term_timer->first) {
		lock_release(ent_term_timer->lock);
		return NULL;
	}

	if (ent_term_timer->first->timeout > now) {
		/* no expired entities in list at all */
		lock_release(ent_term_timer->lock);
		return NULL;
	}

	for (tl = ent_term_timer->first; tl->next && tl->next->timeout <= now;
		tl = tl->next) ;

	ret = ent_term_timer->first;

	ent_term_timer->first = tl->next;
	if (!ent_term_timer->first)
		ent_term_timer->last = NULL;

	tl->next = NULL;

	lock_release(ent_term_timer->lock);

	return ret;
}

void b2bl_term_entities_timer(unsigned int ticks, void* param)
{
	struct b2b_term_t_list *tl, *tmp;

	tl = get_entities_term_tl(ticks);

	while (tl) {
		if (bridge_msg_term_entity(tl->entity, NULL) < 0)
			LM_ERR("Failed to terminate entity\n");

		tmp = tl;
		tl = tl->next;
		shm_free(tmp);
	}

	return;
}

/* Bridge an initial Invite with an existing dialog */
/* key and entity_no identity the existing call and the which entity from the call
 * to bridge (0 or 1) */
int b2bl_bridge_msg(struct sip_msg* msg, str* key, int entity_no,
											unsigned int flags, str *adv_ct)
{
	b2bl_tuple_t* tuple;
	struct b2b_context *ctx;
	struct b2b_ctx_val *v, *v_old;
	unsigned int hash_index, local_index;
	b2bl_entity_id_t *bridging_entity= NULL;
	b2bl_entity_id_t *old_entity;
	b2bl_entity_id_t *entity;
	str* server_id;
	str body = {0, 0}, new_body = {0, 0};
	str to_uri={NULL,0}, from_uri, from_dname;
	b2b_req_data_t req_data;
	int ret;
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
	B2BL_LOCK_GET(hash_index);

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

	if (old_entity->peer->peer != old_entity)
		LM_WARN("Unexpected chain: old_entity=[%p] and "
			"old_entity->peer->peer=[%p]\n",
			old_entity, old_entity->peer->peer);

	if (flags&B2BL_BR_FLAG_BR_MSG_LATE_BYE) {
		tuple->bridge_flags = flags;
		tuple->bridge_entities[2] = old_entity;
		old_entity->peer = NULL;
	} else {
		b2bl_print_tuple(tuple, L_DBG);
		tuple->bridge_entities[(entity_no?0:1)] = NULL;
		/* remove the disconected entity from the tuple */
		if(0 == b2bl_drop_entity(old_entity, tuple))
		{
			LM_ERR("Inconsistent entity [%p] on tuple [%p]\n",
				old_entity, tuple);
			b2bl_print_tuple(tuple, L_ERR);
			goto error;
		}

		if (bridge_msg_term_entity(old_entity, &hash_index) < 0) {
			LM_ERR("Failed to terminate old entity\n");
			goto error;
		}
	}

	b2b_api.apply_lumps(msg);

	if (b2b_msg_get_from(msg, &from_uri, &from_dname)< 0 ||
	b2b_msg_get_to(msg, &to_uri, b2bl_htable[hash_index].flags)< 0)
	{
		LM_ERR("Failed to get to or from from the message\n");
		goto error;
	}

	if (!adv_ct && b2b_get_local_contact(msg, &to_uri, &local_contact) < 0) {
		LM_ERR("Failed to get local contact\n");
		goto error;
	}

	/* create server entity from Invite */
	server_id = b2b_api.server_new(msg, adv_ct ? adv_ct : &local_contact,
			b2b_server_notify, &b2bl_mod_name, tuple->key,
			get_tracer(tuple), NULL, NULL);
	if(server_id == NULL)
	{
		LM_ERR("failed to create new b2b server instance\n");
		pkg_free(to_uri.s);
		goto error;
	}

	entity = b2bl_create_new_entity(B2B_SERVER, server_id, &to_uri, 0,
		&from_uri, 0, 0, 0, adv_ct, msg);
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

		if (shm_str_dup(&entity->in_sdp, &body) < 0) {
			LM_ERR("Failed to save SDP\n");
			return -1;
		}

		if (shm_str_sync(&bridging_entity->out_sdp, &body) < 0) {
			LM_ERR("Failed to save SDP\n");
			goto error;
		}
	}

	memset(&req_data, 0, sizeof(b2b_req_data_t));
	PREP_REQ_DATA(bridging_entity);
	if (bridging_entity->state != B2BL_ENT_CONFIRMED) {
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
	if(b2b_api.send_request(&req_data) < 0)
	{
		LM_ERR("Failed to send Update/reInvite\n");
		goto error;
	}
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

	B2BL_LOCK_RELEASE(hash_index);

	if(new_body.s)
		pkg_free(new_body.s);
	return 0;

error:
	if(tuple)
		b2b_mark_todel(tuple);
	B2BL_LOCK_RELEASE(hash_index);
	if(new_body.s)
		pkg_free(new_body.s);
	local_ctx_tuple = NULL;
	return -1;
}

/* RFC 3261 says we can retry anytime between 2.1s and 4s
 * so we are trying as soon as possible, provided that our timer
 * ticked and the 2.1s have elapsed */
#define B2BL_BRIDGE_RETRY_TIMEOUT 2100000 /* ms */
#define B2BL_BRIDGE_RETRY_MAX 4000000 /* ms */

struct b2bl_bridge_retry_t {
	utime_t time;
	unsigned int hash_index, local_index;
	struct b2bl_bridge_retry_t *next;
} **b2bl_bridge_retry_head, **b2bl_bridge_retry_last;
gen_lock_t *b2bl_bridge_retry_lock;

int b2bl_init_bridge_retry(void)
{
	b2bl_bridge_retry_lock = lock_alloc();
	if (!b2bl_bridge_retry_lock) {
		LM_ERR("cannot allocate bridge retry lock\n");
		return -1;
	}
	if (!lock_init(b2bl_bridge_retry_lock)) {
		LM_ERR("cannot initialize bridge retry lock\n");
		return -1;
	}
	b2bl_bridge_retry_head = shm_malloc(sizeof(struct b2bl_bridge_retry_t *));
	if (!b2bl_bridge_retry_head) {
		LM_ERR("cannot allocate bridge retry head\n");
		return -1;
	}
	*b2bl_bridge_retry_head = NULL;
	b2bl_bridge_retry_last = shm_malloc(sizeof(struct b2bl_bridge_retry_t *));
	if (!b2bl_bridge_retry_last) {
		LM_ERR("cannot allocate bridge retry last\n");
		return -1;
	}
	*b2bl_bridge_retry_last = NULL;
	return 0;
}

void b2bl_free_bridge_retry(void)
{
	struct b2bl_bridge_retry_t *it, *next;
	for (it = *b2bl_bridge_retry_head; it; it = next) {
		next = it->next;
		shm_free(it);
	}
	lock_destroy(b2bl_bridge_retry_lock);
	lock_dealloc(b2bl_bridge_retry_lock);
	shm_free(b2bl_bridge_retry_head);
	shm_free(b2bl_bridge_retry_last);
}

int b2bl_push_bridge_retry(b2bl_tuple_t *tuple)
{
	struct b2bl_bridge_retry_t *retry = shm_malloc(sizeof *retry);
	if (!retry)
		return -1;
	memset(retry, 0, sizeof *retry);
	retry->hash_index = tuple->hash_index;
	retry->local_index = tuple->id;

	/* always adding at the end, because we know they will be added in the
	 * order they appear */
	lock_get(b2bl_bridge_retry_lock);
	retry->time = get_uticks();
	retry->next = *b2bl_bridge_retry_head;
	if (*b2bl_bridge_retry_last)
		(*b2bl_bridge_retry_last)->next = retry;
	else
		*b2bl_bridge_retry_head = retry;
	*b2bl_bridge_retry_last = retry;
	lock_release(b2bl_bridge_retry_lock);
	return 0;
}

void b2bl_timer_bridge_retry(unsigned int ticks, void* param)
{
	b2bl_tuple_t *tuple;
	struct b2bl_bridge_retry_t *it, *last, *next;
	/* we only evaluate the list under lock, and detach it */
	lock_get(b2bl_bridge_retry_lock);
	it = *b2bl_bridge_retry_head;
	last = it;
	if (it) {
		LM_DBG("going through list %p->%p\n", it, *b2bl_bridge_retry_last);
		for (last = it; last; last = last->next) {
			LM_DBG("detaching %p(%u.%u) after %.2fs\n", it, it->hash_index, it->local_index,
					((float)(get_uticks() - it->time))/1000000);
			if (get_uticks() - last->time < B2BL_BRIDGE_RETRY_TIMEOUT) {
				LM_DBG("stopping %p(%u.%u) after %.2fs\n", it, it->hash_index, it->local_index,
						((float)(get_uticks() - it->time))/1000000);
				break;
			}
		}
		if (it != last) {
			LM_DBG("detaching from %p->%p\n", it, last);
			/* detach the list */
			*b2bl_bridge_retry_head = last;
			if (!last)
				*b2bl_bridge_retry_last = NULL;
		}
	}
	lock_release(b2bl_bridge_retry_lock);

	while (it != last) {

		B2BL_LOCK_GET(it->hash_index);
		tuple = b2bl_search_tuple_safe(it->hash_index, it->local_index);
		if (tuple) {
			if (tuple->bridge_flags & B2BL_BR_FLAG_PENDING_SDP) {
				if (get_uticks() - it->time > B2BL_BRIDGE_RETRY_MAX)
					LM_WARN("bridge retrying for %.*s after > %ds\n",
							tuple->key->len, tuple->key->s,
							B2BL_BRIDGE_RETRY_MAX/1000000);
				else
					LM_DBG("bridge retrying for %.*s after %.2fs\n",
							tuple->key->len, tuple->key->s,
							((float)(get_uticks() - it->time))/1000000);
				tuple->bridge_entities[1]->state = B2BL_ENT_CONFIRMED;
				if (bridging_start_old_ent(tuple, tuple->bridge_entities[0],
						tuple->bridge_entities[1], NULL, NULL) < 0)
					LM_ERR("Failed to start bridging with old entity\n");
				else
					tuple->state = B2B_BRIDGING_STATE;
			} else {
				LM_DBG("bridge retrying for %.*s aborted after %.2fs\n",
						tuple->key->len, tuple->key->s,
						((float)(get_uticks() - it->time))/1000000);
			}
		}
		B2BL_LOCK_RELEASE(it->hash_index);

		next = it->next;
		shm_free(it);
		it = next;
	}
}
