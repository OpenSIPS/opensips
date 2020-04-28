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

#include "../presence/hash.h"
#include "b2be_clustering.h"
#include "b2b_entities.h"
#include "b2be_db.h"
#include "../../pt.h"

#define NO_REPL_CONSTANT_STRS 10

struct clusterer_binds cl_api;
str entities_repl_cap = str_init("b2be-entities-repl");

void b2be_recv_bin_packets(bin_packet_t *packet);
void b2be_cluster_event(enum clusterer_event ev, int node_id);

int b2be_init_clustering(void)
{
	if (b2be_cluster == 0)
		return 0;

	if (b2be_cluster < 0) {
		LM_ERR("Invalid 'cluster_id'!  It must be a positive integer!\n");
		return -1;
	}

	if (load_clusterer_api(&cl_api) != 0) {
		LM_ERR("failed to load clusterer API\n");
		return -1;
	}

	if (cl_api.register_capability(&entities_repl_cap, b2be_recv_bin_packets,
		b2be_cluster_event, b2be_cluster, 1, NODE_CMP_ANY) < 0) {
		LM_ERR("cannot register callbacks to clusterer module!\n");
		return -1;
	}

	if (cl_api.request_sync(&entities_repl_cap, b2be_cluster) < 0)
		LM_ERR("Sync request failed\n");

	return 0;
}

static inline void bin_pack_entity_coords(bin_packet_t *packet, b2b_dlg_t *dlg,
	int etype)
{
	bin_push_int(packet, etype);

	bin_push_str(packet, &dlg->tag[0]);
	bin_push_str(packet, &dlg->tag[1]);
	bin_push_str(packet, &dlg->callid);
}

void bin_pack_entity(bin_packet_t *packet, b2b_dlg_t *dlg, int etype)
{
	bin_pack_entity_coords(packet, dlg, etype);

	bin_push_str(packet, &dlg->ruri);
	bin_push_str(packet, &dlg->from_uri);
	bin_push_str(packet, &dlg->from_dname);
	bin_push_str(packet, &dlg->to_uri);
	bin_push_str(packet, &dlg->to_dname);
	bin_push_str(packet, &dlg->route_set[0]);
	bin_push_str(packet, &dlg->route_set[1]);
	bin_push_str(packet, dlg->send_sock ?
		get_socket_internal_name(dlg->send_sock) : NULL);
	bin_push_str(packet, &dlg->param);
	bin_push_str(packet, &dlg->mod_name);

	bin_push_int(packet, dlg->state);
	bin_push_int(packet, dlg->cseq[0]);
	bin_push_int(packet, dlg->cseq[1]);
	bin_push_int(packet, dlg->last_method);
	bin_push_int(packet, dlg->last_reply_code);
	bin_push_int(packet, dlg->last_invite_cseq);

	bin_push_str(packet, &dlg->contact[0]);
	bin_push_str(packet, &dlg->contact[1]);

	if (dlg->legs) {
		bin_push_str(packet, &dlg->legs->tag);
		bin_push_int(packet, dlg->legs->cseq);
		bin_push_str(packet, &dlg->legs->contact);
		bin_push_str(packet, &dlg->legs->route_set);
	} else
		bin_push_str(packet, NULL);
}

void replicate_entity_create(b2b_dlg_t *dlg, int etype, unsigned int hash_index,
	bin_packet_t *storage)
{
	int rc;
	bin_packet_t packet;
	b2b_table htable = (etype == B2B_SERVER) ? server_htable : client_htable;
	str storage_cnt_buf;

	lock_get(&htable[hash_index].lock);

	if (dlg->replicated) {
		lock_release(&htable[hash_index].lock);
		return;
	} else
		dlg->replicated = 1;

	if (bin_init(&packet, &entities_repl_cap, REPL_ENTITY_CREATE,
		B2BE_BIN_VERSION, 0) != 0) {
		LM_ERR("Failed to init bin packet\n");
		lock_release(&htable[hash_index].lock);
		return;
	}

	bin_pack_entity(&packet, dlg, etype);

	if (storage->buffer.s) {  /* the callback was called */
		bin_get_content_start(storage, &storage_cnt_buf);
		if (storage_cnt_buf.len > 0 &&  /* content has been pushed */
			bin_append_buffer(&packet, &storage_cnt_buf) < 0) {
			LM_ERR("Failed to push the entity storage content into the packet\n");
			lock_release(&htable[hash_index].lock);
			goto end;
		}
	}

	lock_release(&htable[hash_index].lock);

	rc = cl_api.send_all(&packet, b2be_cluster);
	switch (rc) {
	case CLUSTERER_CURR_DISABLED:
		LM_INFO("Current node is disabled in cluster: %d\n", b2be_cluster);
		goto end;
	case CLUSTERER_DEST_DOWN:
		LM_INFO("All destinations in cluster: %d are down or probing\n",
			b2be_cluster);
		goto end;
	case CLUSTERER_SEND_ERR:
		LM_ERR("Error sending in cluster: %d\n", b2be_cluster);
		goto end;
	}

	LM_DBG("Replicated entity [%.*s] [%.*s]\n", dlg->tag[1].len, dlg->tag[1].s,
		dlg->callid.len, dlg->callid.s);

end:
	bin_free_packet(&packet);
	return;
}

void replicate_entity_update(b2b_dlg_t *dlg, int etype, unsigned int hash_index,
	str *b2bl_param, int event_type, bin_packet_t *storage)
{
	int rc;
	bin_packet_t packet;
	b2b_table htable = (etype == B2B_SERVER) ? server_htable : client_htable;
	str storage_cnt_buf;
	int pkt_type;

	lock_get(&htable[hash_index].lock);

	if (dlg->state < B2B_CONFIRMED) {
		lock_release(&htable[hash_index].lock);
		return;
	}

	switch (event_type) {
	case -1:
		pkt_type = REPL_ENTITY_PARAM_UPDATE;
		break;
	case B2B_EVENT_ACK:
		pkt_type = REPL_ENTITY_ACK;
		break;
	case B2B_EVENT_UPDATE:
		pkt_type = REPL_ENTITY_UPDATE;
		break;
	default:
		LM_ERR("Bad entity event %d\n", event_type);
		lock_release(&htable[hash_index].lock);
		return;
	}

	if (bin_init(&packet, &entities_repl_cap, pkt_type, B2BE_BIN_VERSION, 0) < 0) {
		LM_ERR("Failed to init bin packet\n");
		lock_release(&htable[hash_index].lock);
		return;
	}

	if (pkt_type == REPL_ENTITY_PARAM_UPDATE) {  /* replicate only the b2bl param update */
		bin_pack_entity_coords(&packet, dlg, etype);
		bin_push_str(&packet, b2bl_param);
	} else {
		bin_pack_entity(&packet, dlg, etype);

		if (storage->buffer.s) {
			bin_get_content_start(storage, &storage_cnt_buf);
			if (storage_cnt_buf.len > 0 &&
				bin_append_buffer(&packet, &storage_cnt_buf) < 0) {
				LM_ERR("Failed to push the entity storage content into the packet\n");
				lock_release(&htable[hash_index].lock);
				goto end;
			}
		}
	}

	lock_release(&htable[hash_index].lock);

	rc = cl_api.send_all(&packet, b2be_cluster);
	switch (rc) {
	case CLUSTERER_CURR_DISABLED:
		LM_INFO("Current node is disabled in cluster: %d\n", b2be_cluster);
		goto end;
	case CLUSTERER_DEST_DOWN:
		LM_INFO("All destinations in cluster: %d are down or probing\n",
			b2be_cluster);
		goto end;
	case CLUSTERER_SEND_ERR:
		LM_ERR("Error sending in cluster: %d\n", b2be_cluster);
		goto end;
	}

	LM_DBG("Replicated entity update [%.*s] [%.*s]\n", dlg->tag[1].len, dlg->tag[1].s,
		dlg->callid.len, dlg->callid.s);

end:
	bin_free_packet(&packet);
	return;
}

void replicate_entity_delete(b2b_dlg_t *dlg, int etype, unsigned int hash_index,
	bin_packet_t *storage)
{
	int rc;
	bin_packet_t packet;
	b2b_table htable = (etype == B2B_SERVER) ? server_htable : client_htable;
	str storage_cnt_buf;

	lock_get(&htable[hash_index].lock);

	if (dlg->state != B2B_TERMINATED) {
		lock_release(&htable[hash_index].lock);
		return;
	}

	if (bin_init(&packet, &entities_repl_cap, REPL_ENTITY_DELETE,
		B2BE_BIN_VERSION, 0) != 0) {
		LM_ERR("Failed to init bin packet\n");
		lock_release(&htable[hash_index].lock);
		return;
	}

	bin_pack_entity_coords(&packet, dlg, etype);

	if (storage->buffer.s) {
		bin_get_content_start(storage, &storage_cnt_buf);
		if (storage_cnt_buf.len > 0 &&
			bin_append_buffer(&packet, &storage_cnt_buf) < 0) {
			LM_ERR("Failed to push the entity storage content into the packet\n");
			lock_release(&htable[hash_index].lock);
			goto end;
		}
	}

	lock_release(&htable[hash_index].lock);

	rc = cl_api.send_all(&packet, b2be_cluster);
	switch (rc) {
	case CLUSTERER_CURR_DISABLED:
		LM_INFO("Current node is disabled in cluster: %d\n", b2be_cluster);
		goto end;
	case CLUSTERER_DEST_DOWN:
		LM_INFO("All destinations in cluster: %d are down or probing\n",
			b2be_cluster);
		goto end;
	case CLUSTERER_SEND_ERR:
		LM_ERR("Error sending in cluster: %d\n", b2be_cluster);
		goto end;
	}

	LM_DBG("Replicated entity delete [%.*s] [%.*s]\n", dlg->tag[1].len, dlg->tag[1].s,
		dlg->callid.len, dlg->callid.s);

end:
	bin_free_packet(&packet);
	return;
}

static struct socket_info *fetch_socket_info(str *addr)
{
	struct socket_info *sock;
	int port, proto;
	str host;

	if (!addr->s || addr->s[0] == 0)
		return NULL;

	if (parse_phostport(addr->s, addr->len, &host.s, &host.len,
		&port, &proto) != 0) {
		LM_ERR("bad socket <%.*s>\n", addr->len, addr->s);
		return NULL;
	}

	sock = grep_internal_sock_info(&host, (unsigned short) port,
		(unsigned short) proto);
	if (!sock) {
		LM_WARN("non-local socket <%.*s>...ignoring\n", addr->len, addr->s);
	}

	return sock;
}

static inline void unpack_update_fields(bin_packet_t *packet, b2b_dlg_t *dlg)
{
	str s;

	bin_skip_str(packet, NO_REPL_CONSTANT_STRS);

	bin_pop_int(packet, &dlg->state);
	bin_pop_int(packet, &dlg->cseq[0]);
	bin_pop_int(packet, &dlg->cseq[1]);
	bin_pop_int(packet, &dlg->last_method);
	bin_pop_int(packet, &dlg->last_reply_code);
	bin_pop_int(packet, &dlg->last_invite_cseq);

	bin_skip_str(packet, 2);

	bin_pop_str(packet, &s);
	if (s.s) {
		bin_skip_int(packet, 1);
		bin_skip_str(packet, 2);
	}
}

int receive_entity_create(bin_packet_t *packet, b2b_dlg_t *dlg, int type,
	b2b_table htable, unsigned int hash_index, unsigned int local_index,
	uint64_t timestamp)
{
	b2b_dlg_t tmp_dlg, *new_dlg = NULL;
	unsigned int h_idx, l_idx;
	int rcv_type;
	str *new_key;
	str sock_str;
	str b2be_key;
	dlg_leg_t leg, *new_leg = NULL;
	uint64_t ts;

	if (!dlg) {
		memset(&tmp_dlg, 0, sizeof(b2b_dlg_t));

		bin_pop_int(packet, &rcv_type);
		bin_pop_str(packet, &tmp_dlg.tag[0]);
		bin_pop_str(packet, &tmp_dlg.tag[1]);
		bin_pop_str(packet, &tmp_dlg.callid);

		if (rcv_type == B2B_SERVER) {
			htable = server_htable;
			b2be_key = tmp_dlg.tag[1];
			tmp_dlg.tag[1].s = NULL;
			tmp_dlg.tag[1].len = 0;
		} else {
			htable = client_htable;
			b2be_key = tmp_dlg.callid;
		}

		LM_DBG("Received replicated entity [%.*s]\n", b2be_key.len, b2be_key.s);

		if (b2b_parse_key(&b2be_key, &h_idx, &l_idx, &ts) < 0) {
			LM_ERR("Wrong format for b2b key [%.*s]\n",
				b2be_key.len, b2be_key.s);
			return -1;
		}

		lock_get(&htable[h_idx].lock);
		dlg = b2b_search_htable(htable, h_idx, l_idx);
		if (dlg) {
			if (packet->type == SYNC_PACKET_TYPE)
				/* treat this as an UPDATE */
				unpack_update_fields(packet, dlg);
			else
				LM_DBG("Entity [%.*s] already created\n",
					b2be_key.len, b2be_key.s);

			lock_release(&htable[h_idx].lock);
			return 0;
		}
		lock_release(&htable[h_idx].lock);

		hash_index = h_idx;
		local_index = l_idx;
		timestamp = ts;
		dlg = &tmp_dlg;
		type = rcv_type;
	}

	dlg->id = local_index;

	bin_pop_str(packet, &dlg->ruri);
	bin_pop_str(packet, &dlg->from_uri);
	bin_pop_str(packet, &dlg->from_dname);
	bin_pop_str(packet, &dlg->to_uri);
	bin_pop_str(packet, &dlg->to_dname);
	bin_pop_str(packet, &dlg->route_set[0]);
	bin_pop_str(packet, &dlg->route_set[1]);
	bin_pop_str(packet, &sock_str);

	if (sock_str.s && !(dlg->send_sock = fetch_socket_info(&sock_str))) {
		LM_ERR("Replicated entity send socket doesn't match any local socket\n");
		return -1;
	}

	bin_pop_str(packet, &dlg->param);
	bin_pop_str(packet, &dlg->mod_name);

	bin_pop_int(packet, &dlg->state);
	bin_pop_int(packet, &dlg->cseq[0]);
	bin_pop_int(packet, &dlg->cseq[1]);
	bin_pop_int(packet, &dlg->last_method);
	bin_pop_int(packet, &dlg->last_reply_code);
	bin_pop_int(packet, &dlg->last_invite_cseq);
	bin_pop_str(packet, &dlg->contact[0]);
	bin_pop_str(packet, &dlg->contact[1]);

	dlg->db_flag = INSERTDB_FLAG;

	memset(&leg, 0, sizeof(dlg_leg_t));

	bin_pop_str(packet, &leg.tag);

	if (leg.tag.s) {
		bin_pop_int(packet, &leg.cseq);
		bin_pop_str(packet, &leg.contact);
		bin_pop_str(packet, &leg.route_set);

		new_leg = b2b_dup_leg(&leg, SHM_MEM_TYPE);
		if (!new_leg) {
			LM_ERR("Failed to construct b2b leg structure\n");
			return -1;
		}
	}

	new_dlg = b2b_dlg_copy(dlg);
	if (!new_dlg) {
		LM_ERR("Failed to create new dialog structure\n");
		goto error;
	}

	if (leg.tag.s)
		new_dlg->legs = new_leg;

	lock_get(&htable[hash_index].lock);

	new_key = b2b_htable_insert(htable, new_dlg, hash_index, (time_t)timestamp,
		type, 1, 1);
	if (new_key == NULL) {
		LM_ERR("Failed to insert new record\n");
		goto error;
	}

	htable[hash_index].locked_by = process_no;
	b2b_run_cb(new_dlg, hash_index, type, B2BCB_RECV_EVENT, B2B_EVENT_CREATE,
		packet, B2BCB_BACKEND_CLUSTER);
	htable[hash_index].locked_by = -1;

	lock_release(&htable[hash_index].lock);

	pkg_free(new_key);

	return 0;

error:
	if (new_leg)
		shm_free(new_leg);
	if (new_dlg)
		shm_free(new_dlg);
	return -1;
}

static inline int recv_b2bl_param_update(bin_packet_t *packet, b2b_dlg_t *dlg)
{
	str param;

	bin_pop_str(packet, &param);

	if (param.len > B2BL_MAX_KEY_LEN) {
		LM_ERR("b2bl parameter too long, received [%d], maximum [%d]\n",
			param.len, B2BL_MAX_KEY_LEN);
		return -1;
	}
	memcpy(dlg->param.s, param.s, param.len);
	dlg->param.len = param.len;

	return 0;
}

int receive_entity_update(bin_packet_t *packet)
{
	b2b_dlg_t tmp_dlg, *dlg;
	unsigned int hash_index, local_index;
	int type;
	str b2be_key;
	b2b_table htable;
	uint64_t timestamp;
	int rc = 0;

	memset(&tmp_dlg, 0, sizeof(b2b_dlg_t));

	bin_pop_int(packet, &type);
	bin_pop_str(packet, &tmp_dlg.tag[0]);
	bin_pop_str(packet, &tmp_dlg.tag[1]);
	bin_pop_str(packet, &tmp_dlg.callid);

	if (type == B2B_SERVER) {
		htable = server_htable;
		b2be_key = tmp_dlg.tag[1];
		tmp_dlg.tag[1].s = NULL;
		tmp_dlg.tag[1].len = 0;
	} else {
		htable = client_htable;
		b2be_key = tmp_dlg.callid;
	}

	LM_DBG("Received replicated update for entity [%.*s]\n",
		b2be_key.len, b2be_key.s);

	if (b2b_parse_key(&b2be_key, &hash_index, &local_index, &timestamp) < 0) {
		LM_ERR("Wrong format for b2b key [%.*s]\n", b2be_key.len, b2be_key.s);
		return -1;
	}

	lock_get(&htable[hash_index].lock);

	dlg = b2b_search_htable(htable, hash_index, local_index);
	if (!dlg) {
		LM_DBG("Entity [%.*s] not found\n", b2be_key.len, b2be_key.s);
		lock_release(&htable[hash_index].lock);

		if (packet->type == REPL_ENTITY_UPDATE)
			return receive_entity_create(packet, &tmp_dlg, type, htable,
				hash_index, local_index, timestamp);
		else
			return 0;
	}

	if (dlg->state == B2B_TERMINATED) {
		lock_release(&htable[hash_index].lock);
		return 0;
	}

	if (packet->type != REPL_ENTITY_PARAM_UPDATE) {
		unpack_update_fields(packet, dlg);

		htable[hash_index].locked_by = process_no;
		b2b_run_cb(dlg, hash_index, type, B2BCB_RECV_EVENT,
			packet->type == REPL_ENTITY_UPDATE ? B2B_EVENT_UPDATE : B2B_EVENT_ACK,
			packet, B2BCB_BACKEND_CLUSTER);
		htable[hash_index].locked_by = -1;
	} else {
		rc = recv_b2bl_param_update(packet, dlg);
	}

	UPDATE_DBFLAG(dlg);
	if (b2be_db_mode == WRITE_THROUGH && b2be_db_update(dlg, type) < 0)
		LM_ERR("Failed to update in database\n");

	lock_release(&htable[hash_index].lock);

	return rc;
}

int receive_entity_delete(bin_packet_t *packet)
{
	b2b_dlg_t *dlg;
	unsigned int hash_index, local_index;
	int type;
	str *b2be_key;
	b2b_table htable;
	str callid, tag0, tag1;

	bin_pop_int(packet, &type);
	bin_pop_str(packet, &tag0);
	bin_pop_str(packet, &tag1);
	bin_pop_str(packet, &callid);

	if (type == B2B_SERVER) {
		htable = server_htable;
		b2be_key = &tag1;
	} else {
		htable = client_htable;
		b2be_key = &callid;
	}

	LM_DBG("Received replicated delete for entity [%.*s]\n",
		b2be_key->len, b2be_key->s);

	if (b2b_parse_key(b2be_key, &hash_index, &local_index, NULL) < 0) {
		LM_ERR("Wrong format for b2b key [%.*s]\n", b2be_key->len, b2be_key->s);
		return -1;
	}

	lock_get(&htable[hash_index].lock);

	dlg = b2b_search_htable(htable, hash_index, local_index);
	if (!dlg) {
		LM_DBG("Entity [%.*s] not found\n", b2be_key->len, b2be_key->s);
		lock_release(&htable[hash_index].lock);

		return 0;
	}

	htable[hash_index].locked_by = process_no;
	b2b_run_cb(dlg, hash_index, type, B2BCB_RECV_EVENT, B2B_EVENT_DELETE, packet,
		B2BCB_BACKEND_CLUSTER);
	htable[hash_index].locked_by = -1;

	b2b_entity_db_delete(type, dlg);
	b2b_delete_record(dlg, htable, hash_index);

	lock_release(&htable[hash_index].lock);

	return 0;
}

void b2be_recv_bin_packets(bin_packet_t *packet)
{
	int rc;
	bin_packet_t *pkt;

	for (pkt = packet; pkt; pkt = pkt->next) {
		LM_DBG("received a binary packet [%d]!\n", pkt->type);

		switch (pkt->type) {
		case REPL_ENTITY_CREATE:
			ensure_bin_version(pkt, B2BE_BIN_VERSION);

			rc = receive_entity_create(pkt, NULL, B2B_NONE, NULL, 0, 0, 0);
			break;
		case REPL_ENTITY_UPDATE:
		case REPL_ENTITY_PARAM_UPDATE:
		case REPL_ENTITY_ACK:
			ensure_bin_version(pkt, B2BE_BIN_VERSION);

			rc = receive_entity_update(pkt);
			break;
		case REPL_ENTITY_DELETE:
			ensure_bin_version(pkt, B2BE_BIN_VERSION);

			rc = receive_entity_delete(pkt);
			break;
		case SYNC_PACKET_TYPE:
			ensure_bin_version(pkt, B2BE_BIN_VERSION);

			while (cl_api.sync_chunk_iter(pkt))
				if (receive_entity_create(pkt, NULL, B2B_NONE, NULL, 0, 0, 0) < 0) {
					LM_ERR("Failed to process sync packet\n");
					return;
				}
			rc = 0;
			break;
		default:
			rc = -1;
			LM_ERR("invalid usrloc binary packet type: %d\n", pkt->type);
		}

		if (rc != 0)
			LM_ERR("failed to process binary packet!\n");
	}
}

static int pack_entities_sync(bin_packet_t **sync_packet, int node_id,
	b2b_table htable, unsigned int hsize, int etype, bin_packet_t *storage,
	int *free_prev)
{
	int i;
	b2b_dlg_t *dlg;
	str storage_cnt_buf;

	storage->buffer.s = NULL;

	for (i = 0; i < hsize; i++) {
		lock_get(&htable[i].lock);

		for (dlg = htable[i].first; dlg; dlg = dlg->next) {
			if (dlg->state < B2B_CONFIRMED) {
				lock_release(&htable[i].lock);
				continue;
			}

			if (*free_prev && storage->buffer.s)
				bin_free_packet(storage);

			*sync_packet = cl_api.sync_chunk_start(&entities_repl_cap,
				b2be_cluster, node_id, B2BE_BIN_VERSION);
			if (!*sync_packet) {
				lock_release(&htable[i].lock);
				return -1;
			}

			b2b_run_cb(dlg, i, etype, B2BCB_TRIGGER_EVENT, B2B_EVENT_CREATE,
				storage, serialize_backend);

			bin_pack_entity(*sync_packet, dlg, etype);

			if (storage->buffer.s) {  /* the callback was called */
				bin_get_content_start(storage, &storage_cnt_buf);
				if (storage_cnt_buf.len > 0 &&  /* content has been pushed */
					bin_append_buffer(*sync_packet, &storage_cnt_buf) < 0) {
					LM_ERR("Failed to push the entity storage content into the packet\n");
					lock_release(&htable[i].lock);
					return -1;
				}
			}

			*free_prev = 1;
		}

		lock_release(&htable[i].lock);
	}

	return 0;
}

static int receive_sync_request(int node_id)
{
	bin_packet_t *sync_packet = NULL;
	int free_prev = 0;
	bin_packet_t storage;

	if (pack_entities_sync(&sync_packet, node_id, server_htable, server_hsize,
		B2B_SERVER, &storage, &free_prev) < 0) {
		LM_ERR("Failed to pack sever entities for sync\n");
		return -1;
	}
	if (pack_entities_sync(&sync_packet, node_id, client_htable, client_hsize,
		B2B_CLIENT, &storage, &free_prev) < 0) {
		LM_ERR("Failed to pack client entities for sync\n");
		return -1;
	}

	if (free_prev && storage.buffer.s)
		bin_free_packet(&storage);

	return 0;
}

void b2be_cluster_event(enum clusterer_event ev, int node_id)
{
	if (ev == SYNC_REQ_RCV && receive_sync_request(node_id) < 0)
		LM_ERR("Failed to send sync data to node: %d\n", node_id);
}
