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

#include "../../pt.h"
#include "../../bin_interface.h"
#include "entity_storage.h"
#include "b2bl_db.h"
#include "records.h"
#include "b2b_logic.h"

int entity_add_dlginfo(b2bl_entity_id_t* entity, b2b_dlginfo_t* dlginfo);

static void pack_context_vals(b2bl_tuple_t* tuple, bin_packet_t *storage)
{
	int no_vals;
	struct b2b_ctx_val *v;

	for (v = tuple->vals, no_vals = 0; v; v = v->next, no_vals++) ;
	bin_push_int(storage, no_vals);

	for (v = tuple->vals; v; v = v->next) {
		bin_push_str(storage, &v->name);
		bin_push_str(storage, &v->val);
	}
}

static int unpack_context_vals(b2bl_tuple_t* tuple, bin_packet_t *storage)
{
	int no_vals;
	int i;
	str name, val;
	struct b2b_ctx_val *v;

	/* clear existing values; this way, the values should always
	 * be consistent between instances */
	while (tuple->vals) {
		v = tuple->vals;
		tuple->vals = tuple->vals->next;
		shm_free(v);
	}

	bin_pop_int(storage, &no_vals);
	for (i = 0; i < no_vals; i++) {
		bin_pop_str(storage, &name);
		bin_pop_str(storage, &val);

		if (store_ctx_value(&tuple->vals, &name, &val) < 0) {
			LM_ERR("Failed to store context value [%.*s]\n", name.len,name.s);
			return -1;
		}
	}

	return 0;
}

static void pack_tuple(b2bl_tuple_t* tuple, bin_packet_t *storage, int repl_new)
{
	if (repl_new) {
		bin_push_int(storage, REPL_TUPLE_NEW);

		if (tuple->scenario)
			bin_push_str(storage, &tuple->scenario->id);
		else
			bin_push_str(storage, NULL);

		bin_push_str(storage, &tuple->scenario_params[0]);
		bin_push_str(storage, &tuple->scenario_params[1]);
		bin_push_str(storage, &tuple->scenario_params[2]);
		bin_push_str(storage, &tuple->scenario_params[3]);
		bin_push_str(storage, &tuple->scenario_params[4]);

		bin_push_str(storage, &tuple->sdp);
		bin_push_str(storage, tuple->extra_headers);
	} else
		bin_push_int(storage, REPL_TUPLE_UPDATE);

	bin_push_int(storage, tuple->scenario_state);
	bin_push_int(storage, tuple->next_scenario_state);

	bin_push_int(storage, tuple->lifetime > 0 ?
		(tuple->lifetime - get_ticks()) : 0);

	pack_context_vals(tuple, storage);

	if (tuple->repl_flag != TUPLE_REPL_SENT)
		tuple->repl_flag = TUPLE_REPL_SENT;
}

static void pack_entity(b2bl_tuple_t* tuple, enum b2b_entity_type entity_type,
	str *entity_key, int event_type, bin_packet_t *storage)
{
	b2bl_entity_id_t *entity = NULL, **entity_head = NULL;
	int entity_no;

	entity = b2bl_search_entity(tuple, entity_key, entity_type, &entity_head);
	if (!entity) {
		LM_ERR("Entity [%.*s] not found\n", entity_key->len, entity_key->s);
		return;
	}
	entity_no = bridge_get_entityno(tuple, entity);
	if (entity_no < 0) {
		LM_ERR("Entity [%.*s] not found in bridge array\n",
			entity_key->len, entity_key->s);
		return;
	}

	if (event_type == B2B_EVENT_CREATE) {
		bin_push_str(storage, &entity->scenario_id);

		bin_push_str(storage, &entity->to_uri);
		bin_push_str(storage, &entity->from_uri);
		bin_push_str(storage, &entity->from_dname);
		bin_push_str(storage, &entity->hdrs);

		bin_push_str(storage, &entity->dlginfo->callid);
		bin_push_str(storage, &entity->dlginfo->fromtag);
		bin_push_str(storage, &entity->dlginfo->totag);
	}

	bin_push_int(storage, entity->stats.start_time);
	bin_push_int(storage, entity->stats.setup_time);
	bin_push_int(storage, entity->stats.call_time);

	bin_push_int(storage, entity_no);
}

void entity_event_trigger(enum b2b_entity_type etype, str *entity_key,
	str *b2bl_key, enum b2b_event_type event_type, bin_packet_t *storage,
	int backend)
{
	unsigned int hash_index, local_index;
	b2bl_tuple_t* tuple;
	int tuple_repl_new = 0;

	LM_DBG("Triggerd event [%d] for entity [%.*s]\n",
		event_type, entity_key->len, entity_key->s);

	if (b2bl_parse_key(b2bl_key, &hash_index, &local_index) < 0) {
		LM_ERR("Bad tuple key: %.*s\n", b2bl_key->len, b2bl_key->s);
		return;
	}

	if (b2bl_htable[hash_index].locked_by != process_no)
		lock_get(&b2bl_htable[hash_index].lock);

	tuple = b2bl_search_tuple_safe(hash_index, local_index);

	if ((backend & B2BCB_BACKEND_DB) == B2BCB_BACKEND_DB) {
		/* if the backend is only DB, use the entity storage to only persist
		 * the context values */

		if (tuple) {
			bin_push_int(storage, STORAGE_ONLY_VALS);

			pack_context_vals(tuple, storage);
		} else if (event_type != B2B_EVENT_DELETE) {
			LM_ERR("Tuple [%.*s] not found\n", b2bl_key->len, b2bl_key->s);
			if (b2bl_htable[hash_index].locked_by != process_no)
				lock_release(&b2bl_htable[hash_index].lock);
			return;
		}

		if (b2bl_htable[hash_index].locked_by != process_no)
			lock_release(&b2bl_htable[hash_index].lock);
		return;
	}

	switch (event_type) {
	case B2B_EVENT_CREATE:
		tuple_repl_new = 1;
		/* fall through */
	case B2B_EVENT_UPDATE:
		if (!tuple) {
			LM_ERR("Tuple [%.*s] not found\n", b2bl_key->len, b2bl_key->s);
			if (b2bl_htable[hash_index].locked_by != process_no)
				lock_release(&b2bl_htable[hash_index].lock);
			return;
		}
		pack_tuple(tuple, storage, tuple_repl_new);
		pack_entity(tuple, etype, entity_key, event_type, storage);
		break;
	case B2B_EVENT_ACK:
		if (!tuple) {
			LM_ERR("Tuple [%.*s] not found\n", b2bl_key->len, b2bl_key->s);
			if (b2bl_htable[hash_index].locked_by != process_no)
				lock_release(&b2bl_htable[hash_index].lock);
			return;
		}
		pack_tuple(tuple, storage, tuple_repl_new);
		break;
	case B2B_EVENT_DELETE:
		if (!tuple) {
			LM_DBG("Tuple [%.*s] already deleted, no tuple info to push\n",
				b2bl_key->len, b2bl_key->s);
			bin_push_int(storage, REPL_TUPLE_NO_INFO);
		} else
			pack_tuple(tuple, storage, 0);
		break;
	default:
		LM_ERR("Bad entity callback event type!\n");
	}

	if (b2bl_htable[hash_index].locked_by != process_no)
		lock_release(&b2bl_htable[hash_index].lock);
}

static void receive_entity_create(enum b2b_entity_type entity_type,
	str *entity_key, str *b2bl_key, bin_packet_t *storage)
{
	unsigned int hash_index, local_index;
	b2bl_tuple_t *tuple = NULL, *old_tuple;
	int tuple_repl_type;
	str scenario_id;
	str params_s[MAX_SCENARIO_PARAMS];
	str* params_p[MAX_SCENARIO_PARAMS];
	str tuple_sdp;
	str extra_headers;
	int lifetime;
	b2b_dlginfo_t dlginfo;
	b2bl_entity_id_t *entity = NULL, **entity_head = NULL;
	str entity_sid, to_uri, from_uri, from_dname, hdrs;

	LM_DBG("Received CREATE event for entity [%.*s]\n",
		entity_key->len, entity_key->s);

	if (b2bl_parse_key(b2bl_key, &hash_index, &local_index) < 0) {
		LM_ERR("Bad tuple key: %.*s\n", b2bl_key->len, b2bl_key->s);
		return;
	}

	lock_get(&b2bl_htable[hash_index].lock);

	old_tuple = b2bl_search_tuple_safe(hash_index, local_index);

	bin_pop_int(storage, &tuple_repl_type);

	switch (tuple_repl_type) {
	case REPL_TUPLE_NEW:
		if (!old_tuple) {
			bin_pop_str(storage, &scenario_id);

			bin_pop_str(storage, &params_s[0]);
			params_p[0] = &params_s[0];
			bin_pop_str(storage, &params_s[1]);
			params_p[1] = &params_s[1];
			bin_pop_str(storage, &params_s[2]);
			params_p[2] = &params_s[2];
			bin_pop_str(storage, &params_s[3]);
			params_p[3] = &params_s[3];
			bin_pop_str(storage, &params_s[4]);
			params_p[4] = &params_s[4];

			bin_pop_str(storage, &tuple_sdp);
			bin_pop_str(storage, &extra_headers);
		} else {
			LM_DBG("Tuple [%.*s] already created\n", b2bl_key->len, b2bl_key->s);
			bin_skip_str(storage, 8);
		}

		if (old_tuple) {
			tuple = old_tuple;
		} else {
			tuple = b2bl_insert_new(NULL, hash_index, get_scenario_id(&scenario_id),
				params_p, tuple_sdp.s ? &tuple_sdp : NULL, &extra_headers,
				local_index, &b2bl_key, INSERTDB_FLAG, TUPLE_REPL_RECV);
			if (!tuple) {
				LM_ERR("Failed to insert new tuple\n");
				goto error;
			}
		}

		bin_pop_int(storage, &tuple->scenario_state);
		bin_pop_int(storage, &tuple->next_scenario_state);

		bin_pop_int(storage, &lifetime);
		tuple->lifetime = lifetime ? get_ticks() + lifetime : 0;

		if (unpack_context_vals(tuple, storage) < 0) {
			LM_ERR("Failed to unpack context values\n");
			goto error;
		}
		break;
	case REPL_TUPLE_UPDATE:
		if (!old_tuple) {
			LM_ERR("Tuple to update [%.*s] not found\n", b2bl_key->len, b2bl_key->s);
			goto error;
		}
		tuple = old_tuple;

		bin_pop_int(storage, &tuple->scenario_state);
		bin_pop_int(storage, &tuple->next_scenario_state);

		bin_pop_int(storage, &lifetime);
		tuple->lifetime = lifetime ? get_ticks() + lifetime : 0;

		if (unpack_context_vals(tuple, storage) < 0) {
			LM_ERR("Failed to unpack context values\n");
			goto error;
		}
		break;
	default:
		LM_ERR("Bad tuple replication type: %d\n", tuple_repl_type);
		goto error;
	}

	entity = b2bl_search_entity(tuple, entity_key, entity_type, &entity_head);
	if (entity) {
		LM_DBG("Entity [%.*s] already exists\n", entity_key->len, entity_key->s);
		lock_release(&b2bl_htable[hash_index].lock);
		return;
	}

	if (b2b_api.restore_logic_info(entity_type, entity_key,
		entity_type == B2B_SERVER ? b2b_server_notify : b2b_client_notify) < 0) {
		LM_ERR("Failed to restore entity notify callback\n");
		goto error;
	}

	bin_pop_str(storage, &entity_sid);
	bin_pop_str(storage, &to_uri);
	bin_pop_str(storage, &from_uri);
	bin_pop_str(storage, &from_dname);
	bin_pop_str(storage, &hdrs);

	entity = b2bl_create_new_entity(entity_type, entity_key, &to_uri, &from_uri,
		&from_dname, &entity_sid, &hdrs, NULL);
	if (!entity) {
		LM_ERR("Failed to create entity\n");
		goto error;
	}

	memset(&dlginfo, 0, sizeof dlginfo);
	bin_pop_str(storage, &dlginfo.callid);
	bin_pop_str(storage, &dlginfo.fromtag);
	bin_pop_str(storage, &dlginfo.totag);

	if (entity_add_dlginfo(entity, &dlginfo) < 0) {
		LM_ERR("Failed to add entity dialoginfo\n");
		goto error;
	}

	bin_pop_int(storage, &entity->stats.start_time);
	bin_pop_int(storage, &entity->stats.setup_time);
	bin_pop_int(storage, &entity->stats.call_time);

	bin_pop_int(storage, &entity->no);

	if (entity->no > 1) {
		LM_ERR("Bad entity bridge no [%d] for tuple [%.*s]\n",
			entity->no, b2bl_key->len, b2bl_key->s);
		goto error;
	}
	tuple->bridge_entities[entity->no] = entity;

	if (tuple->bridge_entities[1])
		tuple->bridge_entities[1]->peer = tuple->bridge_entities[0];
	if (tuple->bridge_entities[0])
		tuple->bridge_entities[0]->peer = tuple->bridge_entities[1];

	if (entity_type == B2B_SERVER) {
		if (b2bl_add_server(tuple, entity) < 0) {
			LM_ERR("Failed to add entity [%.*s]\n", entity_key->len, entity_key->s);
			goto error;
		}
	} else {
		if (b2bl_add_client(tuple, entity) < 0) {
			LM_ERR("Failed to add entity [%.*s]\n", entity_key->len, entity_key->s);
			goto error;
		}
	}

	entity->state = B2BL_ENT_CONFIRMED;

	if (b2bl_db_mode == WRITE_THROUGH) {
		if (old_tuple)
			b2bl_db_update(tuple);
		else
			b2bl_db_insert(tuple);
	} else {
		if (old_tuple)
			UPDATE_DBFLAG(tuple);
	}

	lock_release(&b2bl_htable[hash_index].lock);

	return;
error:
	if (tuple && !old_tuple)
		b2bl_delete(tuple, hash_index, 0, 0);
	lock_release(&b2bl_htable[hash_index].lock);
	if (entity) {
		if (entity->dlginfo)
			shm_free(entity->dlginfo);
		shm_free(entity);
	}
	LM_ERR("Failed to process received entity [%.*s]\n",
		entity_key->len, entity_key->s);
}

static void receive_entity_update(enum b2b_entity_type entity_type,
	str *entity_key, str *b2bl_key, bin_packet_t *storage)
{
	unsigned int hash_index, local_index;
	b2bl_tuple_t* tuple = NULL;
	int tuple_repl_type;
	int lifetime;
	b2bl_entity_id_t *entity = NULL, **entity_head = NULL;

	LM_DBG("Received UPDATE event for entity [%.*s]\n",
		entity_key->len, entity_key->s);

	if (b2bl_parse_key(b2bl_key, &hash_index, &local_index) < 0) {
		LM_ERR("Bad tuple key: %.*s\n", b2bl_key->len, b2bl_key->s);
		return;
	}

	lock_get(&b2bl_htable[hash_index].lock);

	tuple = b2bl_search_tuple_safe(hash_index, local_index);
	if (!tuple) {
		LM_ERR("Tuple [%.*s] not found\n", b2bl_key->len, b2bl_key->s);
		goto error;
	}

	bin_pop_int(storage, &tuple_repl_type);
	if (tuple_repl_type != REPL_TUPLE_UPDATE) {
		LM_ERR("Bad tuple replication type: %d\n", tuple_repl_type);
		goto error;
	}

	bin_pop_int(storage, &tuple->scenario_state);
	bin_pop_int(storage, &tuple->next_scenario_state);
	bin_pop_int(storage, &lifetime);

	tuple->lifetime = lifetime ? get_ticks() + lifetime : 0;

	if (unpack_context_vals(tuple, storage) < 0) {
		LM_ERR("Failed to unpack context values\n");
		goto error;
	}

	entity = b2bl_search_entity(tuple, entity_key, entity_type, &entity_head);
	if (!entity) {
		LM_ERR("Entity [%.*s] does not exist\n", entity_key->len, entity_key->s);
		goto error;
	}

	bin_pop_int(storage, &entity->stats.start_time);
	bin_pop_int(storage, &entity->stats.setup_time);
	bin_pop_int(storage, &entity->stats.call_time);

	bin_pop_int(storage, &entity->no);

	if (entity->no > 1) {
		LM_ERR("Bad entity bridge no [%d] for tuple [%.*s]\n",
			entity->no, b2bl_key->len, b2bl_key->s);
		goto error;
	}
	tuple->bridge_entities[entity->no] = entity;

	if (tuple->bridge_entities[1])
		tuple->bridge_entities[1]->peer = tuple->bridge_entities[0];
	if (tuple->bridge_entities[0])
		tuple->bridge_entities[0]->peer = tuple->bridge_entities[1];

	entity->state = B2BL_ENT_CONFIRMED;

	if(b2bl_db_mode == WRITE_THROUGH)
		b2bl_db_update(tuple);
	else
		UPDATE_DBFLAG(tuple);

	lock_release(&b2bl_htable[hash_index].lock);

	return;
error:
	lock_release(&b2bl_htable[hash_index].lock);
	LM_ERR("Failed to process received entity [%.*s]\n",
		entity_key->len, entity_key->s);
}

static void receive_entity_ack(enum b2b_entity_type entity_type,
	str *entity_key, str *b2bl_key, bin_packet_t *storage)
{
	unsigned int hash_index, local_index;
	b2bl_tuple_t* tuple = NULL;
	int tuple_repl_type;
	int lifetime;

	LM_DBG("Received ACK event for entity [%.*s]\n",
		entity_key->len, entity_key->s);

	if (b2bl_parse_key(b2bl_key, &hash_index, &local_index) < 0) {
		LM_ERR("Bad tuple key: %.*s\n", b2bl_key->len, b2bl_key->s);
		return;
	}

	lock_get(&b2bl_htable[hash_index].lock);

	tuple = b2bl_search_tuple_safe(hash_index, local_index);
	if (!tuple) {
		LM_ERR("Tuple [%.*s] not found\n", b2bl_key->len, b2bl_key->s);
		lock_release(&b2bl_htable[hash_index].lock);
		return;
	}

	bin_pop_int(storage, &tuple_repl_type);
	if (tuple_repl_type != REPL_TUPLE_UPDATE) {
		LM_ERR("Bad tuple replication type: %d\n", tuple_repl_type);
		lock_release(&b2bl_htable[hash_index].lock);
		return;
	}

	bin_pop_int(storage, &tuple->scenario_state);
	bin_pop_int(storage, &tuple->next_scenario_state);
	bin_pop_int(storage, &lifetime);

	tuple->lifetime = lifetime ? get_ticks() + lifetime : 0;

	if (unpack_context_vals(tuple, storage) < 0)
		LM_ERR("Failed to unpack context values\n");

	lock_release(&b2bl_htable[hash_index].lock);
}

static void receive_entity_delete(enum b2b_entity_type entity_type,
	str *entity_key, str *b2bl_key, bin_packet_t *storage)
{
	unsigned int hash_index, local_index;
	b2bl_tuple_t* tuple = NULL;
	int tuple_repl_type;
	int lifetime;
	b2bl_entity_id_t *entity = NULL, **entity_head = NULL;
	int i;

	LM_DBG("Received DELETE event for entity [%.*s]\n",
		entity_key->len, entity_key->s);

	if (b2bl_parse_key(b2bl_key, &hash_index, &local_index) < 0) {
		LM_ERR("Bad tuple key: %.*s\n", b2bl_key->len, b2bl_key->s);
		return;
	}

	lock_get(&b2bl_htable[hash_index].lock);

	tuple = b2bl_search_tuple_safe(hash_index, local_index);
	if (!tuple) {
		/* tuple might have already expired locally */
		LM_DBG("Tuple [%.*s] not found, discarding entity [%.*s] delete\n",
			b2bl_key->len, b2bl_key->s, entity_key->len, entity_key->s);
		lock_release(&b2bl_htable[hash_index].lock);
		return;
	}

	bin_pop_int(storage, &tuple_repl_type);

	switch (tuple_repl_type) {
	case REPL_TUPLE_UPDATE:
		bin_pop_int(storage, &tuple->scenario_state);
		bin_pop_int(storage, &tuple->next_scenario_state);
		bin_pop_int(storage, &lifetime);

		tuple->lifetime = lifetime ? get_ticks() + lifetime : 0;

		if (unpack_context_vals(tuple, storage) < 0) {
			LM_ERR("Failed to unpack context values\n");
			lock_release(&b2bl_htable[hash_index].lock);
			return;
		}
		break;
	case REPL_TUPLE_NO_INFO:
		/* tuple already deleted on sender, no info to pop */
		break;
	default:
		LM_ERR("Bad tuple replication type: %d\n", tuple_repl_type);
		lock_release(&b2bl_htable[hash_index].lock);
		return;
	}

	entity = b2bl_search_entity(tuple, entity_key, entity_type, &entity_head);
	if (entity)
		b2bl_delete_entity(entity, tuple, hash_index, 0);
	else
		LM_DBG("Entity [%.*s] does not exist\n", entity_key->len, entity_key->s);

	for (i = 0; i < MAX_BRIDGE_ENT && !tuple->bridge_entities[i]; i++) ;
	if (i == MAX_BRIDGE_ENT)
		/* no other bridge entities remaining, delete the tuple */
		b2bl_delete(tuple, hash_index, 1, 0);

	lock_release(&b2bl_htable[hash_index].lock);
}

void entity_event_received(enum b2b_entity_type etype, str *entity_key,
	str *b2bl_key, enum b2b_event_type event_type, bin_packet_t *storage,
	int backend)
{
	int tuple_storage_type;
	unsigned int hash_index, local_index;
	b2bl_tuple_t* tuple;

	if (storage == NULL)
		return;

	if (backend == B2BCB_BACKEND_DB) {
		if (b2bl_parse_key(b2bl_key, &hash_index, &local_index) < 0) {
			LM_ERR("Bad tuple key: %.*s\n", b2bl_key->len, b2bl_key->s);
			return;
		}

		lock_get(&b2bl_htable[hash_index].lock);

		tuple = b2bl_search_tuple_safe(hash_index, local_index);
		if (!tuple) {
			LM_ERR("Tuple [%.*s] not found\n", b2bl_key->len, b2bl_key->s);
			lock_release(&b2bl_htable[hash_index].lock);
			return;
		}

		bin_pop_int(storage, &tuple_storage_type);

		switch (tuple_storage_type) {
		case STORAGE_ONLY_VALS:
			/* there is no replication info in the storage */
			if (unpack_context_vals(tuple, storage) < 0)
				LM_ERR("Failed to unpack context values\n");
			break;
		case REPL_TUPLE_NEW:
			bin_skip_str(storage, 8);
			/* fall through */
		case REPL_TUPLE_UPDATE:
			bin_skip_int(storage, 3);
			if (unpack_context_vals(tuple, storage) < 0)
				LM_ERR("Failed to unpack context values\n");
			break;
		case REPL_TUPLE_NO_INFO:
			break;
		default:
			LM_ERR("Bad tuple replication type: %d\n", tuple_storage_type);
		}

		lock_release(&b2bl_htable[hash_index].lock);
		return;
	}

	switch (event_type) {
	case B2B_EVENT_CREATE:
		receive_entity_create(etype, entity_key, b2bl_key, storage);
		break;
	case B2B_EVENT_UPDATE:
		receive_entity_update(etype, entity_key, b2bl_key, storage);
		break;
	case B2B_EVENT_DELETE:
		receive_entity_delete(etype, entity_key, b2bl_key, storage);
		break;
	case B2B_EVENT_ACK:
		receive_entity_ack(etype, entity_key, b2bl_key, storage);
		break;
	default:
		LM_ERR("Bad entity callback event type!\n");
		return;
	}
}
