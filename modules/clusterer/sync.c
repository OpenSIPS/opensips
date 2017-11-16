/* Copyright (C) 2015-2017 OpenSIPS Project
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include "../../rw_locking.h"

#include "api.h"
#include "node_info.h"
#include "clusterer.h"
#include "sync.h"

int sync_packet_size = DEFAULT_SYNC_PACKET_SIZE;
int _sync_from_id = 0;

static bin_packet_t *sync_packet_snd;
static int sync_prev_buf_len;

int send_sync_req(str *capability, int cluster_id, int source_id)
{
	bin_packet_t packet;
	int rc;

	if (bin_init(&packet, &cl_extra_cap, CLUSTERER_SYNC_REQ, BIN_VERSION, 0) < 0) {
		LM_ERR("Failed to init bin send buffer\n");
		return -1;
	}

	bin_push_str(&packet, capability);
	msg_add_trailer(&packet, cluster_id, source_id);

	rc = clusterer_send_msg(&packet, cluster_id, source_id);
	if (rc == CLUSTERER_SEND_SUCCES)
		LM_DBG("Sent sync request for capability: %.*s to node: %d\n",
			capability->len, capability->s, source_id);

	bin_free_packet(&packet);

	return rc;
}

int get_sync_source(cluster_info_t *cluster)
{
	node_info_t *node;
	int nhop;

	if (!_sync_from_id) {
		LM_ERR("No node to sync from defined\n");
		return -1;
	}

	node = get_node_by_id(cluster, _sync_from_id);
	if (!node)
		return 0;

	nhop = get_next_hop(node);

	return (nhop > 0) ? _sync_from_id : nhop;
}

int cl_request_sync(str *capability, int cluster_id)
{
	cluster_info_t *cluster;
	struct local_cap *lcap;
	int source_id;

	cluster = get_cluster_by_id(cluster_id);
	if (!cluster) {
		LM_ERR("Unknown cluster [%d]\n", cluster_id);
		return -1;
	}

	for (lcap = cluster->capabilities; lcap; lcap = lcap->next)
		if (!str_strcmp(capability, &lcap->reg->name))
			break;
	if (!lcap) {
		LM_ERR("Request sync for unknown capability: %.*s\n",
			capability->len, capability->s);
		return -1;
	}

	source_id = get_sync_source(cluster);
	if (source_id < 0) {
		LM_ERR("Failed to obtain node to sync from\n");
		return -1;
	} else if (source_id == 0) {
		lock_get(cluster->lock);
		lcap->sync_req_pending = 1;
		lock_release(cluster->lock);
		return 0;
	} else
		if (send_sync_req(capability, cluster_id, source_id) != CLUSTERER_SEND_SUCCES)
			return -1;

	return 0;
}

bin_packet_t *cl_sync_chunk_start(str *capability, int cluster_id, int dst_id)
{
	str bin_buffer;
	int prev_chunk_size = 0;
	int aloc_new_pkt = 0;
	bin_packet_t *new_packet = NULL;

	if (sync_packet_snd) {
		bin_get_buffer(sync_packet_snd, &bin_buffer);
		prev_chunk_size = bin_buffer.len - sync_prev_buf_len;
		/* assume this chunk will have aprox the same size as the previous one
		 * and check if there is enough space in the packet */
		if (bin_buffer.len + prev_chunk_size > sync_packet_size)
			aloc_new_pkt = 1;
	} else
		aloc_new_pkt = 1;

	if (aloc_new_pkt) {  /* next chunk will be in a new packet */
		if (sync_packet_snd) {
			/* send and free the previous packet */
			msg_add_trailer(sync_packet_snd, cluster_id, dst_id);

			if (clusterer_send_msg(sync_packet_snd, cluster_id, dst_id) < 0)
				LM_ERR("Failed to send sync packet\n");

			bin_free_packet(sync_packet_snd);
			pkg_free(sync_packet_snd);
			sync_packet_snd = NULL;
		}

		new_packet = pkg_malloc(sizeof *new_packet);
		if (!new_packet) {
			LM_ERR("No more pkg memory\n");
			return NULL;
		}
		sync_packet_snd = new_packet;

		if (bin_init(new_packet,&cl_extra_cap,CLUSTERER_SYNC,BIN_VERSION,0)<0) {
			LM_ERR("Failed to init bin packet\n");
			pkg_free(sync_packet_snd);
			sync_packet_snd = NULL;
			return NULL;
		}
		bin_push_str(new_packet, capability);
		bin_push_int(new_packet, SYNC_CHUNK_START_MARKER);

		bin_get_buffer(new_packet, &bin_buffer);
		sync_prev_buf_len = bin_buffer.len;

		return new_packet;
	} else {  /* next chunk will be in the same packet */
		bin_push_int(sync_packet_snd, SYNC_CHUNK_START_MARKER);

		bin_get_buffer(sync_packet_snd, &bin_buffer);
		sync_prev_buf_len = bin_buffer.len;

		return sync_packet_snd;
	}
}

int cl_sync_chunk_iter(bin_packet_t *packet)
{
	int start_marker;
	int rc;

	if (!packet) {
		LM_ERR("No sync packet\n");
		return 0;
	}

	rc = bin_pop_int(packet, &start_marker);
	if (rc < 0) {
		LM_ERR("Error retrieving sync chunk start marker\n");
		return 0;
	} else if (rc == 0) {
		if (start_marker != SYNC_CHUNK_START_MARKER) {
			LM_ERR("Bad sync chunk start marker\n");
			return 0;
		}
		return 1;
	} else  /* no more chunks in this packet */
		return 0;
}

int send_sync_repl(cluster_info_t *cluster, int node_id, str *cap_name)
{
	bin_packet_t sync_end_pkt;
	struct local_cap *cap;
	int rc;

	for (cap = cluster->capabilities; cap; cap = cap->next)
		if (!str_strcmp(cap_name, &cap->reg->name))
			break;
	if (!cap) {
		LM_ERR("Sync request for unknown capability: %.*s\n",
			cap_name->len, cap_name->s);
		return -1;
	}

	cap->reg->event_cb(SYNC_REQ_RCV, node_id);

	if (sync_packet_snd) {
		/* send and free the previously built packet */
		msg_add_trailer(sync_packet_snd, cluster->cluster_id, node_id);

		if ((rc = clusterer_send_msg(sync_packet_snd, cluster->cluster_id, node_id))<0)
			LM_ERR("Failed to send sync packet, rc=%d\n", rc);

		bin_free_packet(sync_packet_snd);
		pkg_free(sync_packet_snd);
		sync_packet_snd = NULL;
	}

	/* send indication that all sync packets were sent */
	if (bin_init(&sync_end_pkt,&cl_extra_cap,CLUSTERER_SYNC_END,BIN_VERSION,0)<0) {
		LM_ERR("Failed to init bin packet\n");
		return -1;
	}
	bin_push_str(&sync_end_pkt, cap_name);
	msg_add_trailer(&sync_end_pkt, cluster->cluster_id, node_id);

	if (clusterer_send_msg(&sync_end_pkt, cluster->cluster_id, node_id) < 0) {
		LM_ERR("Failed to send sync end message\n");
		bin_free_packet(&sync_end_pkt);
		return -1;
	}

	bin_free_packet(&sync_end_pkt);

	LM_DBG("Sent all sync packets for capability: %.*s to node: %d\n",
		cap_name->len, cap_name->s, node_id);

	return 0;
}

void handle_sync_request(bin_packet_t *packet, cluster_info_t *cluster,
							node_info_t *source)
{
	str cap_name;
	struct remote_cap *cap;
	int nhop;

	bin_pop_str(packet, &cap_name);

	LM_DBG("Received sync request for capability: %.*s from: %d\n", cap_name.len,
		cap_name.s, source->node_id);

	nhop = get_next_hop(source);
	if (nhop > 0) {
		send_sync_repl(cluster, source->node_id, &cap_name);
	} else {
		for (cap = source->capabilities; cap; cap = cap->next)
			if (!str_strcmp(&cap_name, &cap->name))
				break;
		if (!cap) {
			LM_ERR("Requesting node does not appear to have capability: %.*s\n",
				cap_name.len, cap_name.s);
			return;
		}
		lock_get(source->lock);
		cap->sync_repl_pending = 1;
		lock_release(source->lock);
	}
}

void handle_sync_packet(bin_packet_t *packet, int packet_type,
								cluster_info_t *cluster, int source_id)
{
	str cap_name;
	struct local_cap *cap;
	struct buf_bin_pkt *buf_pkt, *buf_tmp, *cutpos_next;
	bin_packet_t *bin_pkt_list, *bin_pkt, *bin_tmp;

	bin_pop_str(packet, &cap_name);
	for (cap = cluster->capabilities; cap; cap = cap->next)
		if (!str_strcmp(&cap_name, &cap->reg->name))
			break;
	if (!cap) {
		LM_ERR("Capability: %.*s from sync packet, not found\n",
			cap_name.len, cap_name.s);
		return;
	}

	if (packet_type == CLUSTERER_SYNC) {
		lock_get(cluster->lock);
		cap->pkt_buffering = 1;
		lock_release(cluster->lock);

		/* overwrite packet type with one identifiable by modules */
		packet->type = SYNC_PACKET_TYPE;
		packet->src_id = source_id;

		cap->reg->packet_cb(packet);
	} else { /* CLUSTERER_SYNC_END */
		LM_DBG("Received all sync packets for capability: %.*s\n", cap_name.len,
			cap_name.s);

		lock_get(cluster->lock);

		/* post-sync phase */
		while (cap->pkt_q_front) {
			/* delimit list of buffered packets to deliver for processing */
			cap->pkt_q_cutpos = cap->pkt_q_back;

			for (bin_tmp = NULL, buf_pkt = cap->pkt_q_front;
				buf_pkt != cap->pkt_q_cutpos->next;
				bin_tmp = bin_pkt, buf_pkt = buf_pkt->next) {
				/* aloc and init a bin_packet_t */
				bin_pkt = pkg_malloc(sizeof *bin_pkt);
				if (!bin_pkt) {
					LM_ERR("No more pkg mem\n");
					lock_release(cluster->lock);
					return;
				}

				bin_init_buffer(bin_pkt, buf_pkt->buf.s, buf_pkt->buf.len);
				bin_pkt->src_id = buf_pkt->src_id;

				if (bin_tmp)
					bin_tmp->next = bin_pkt;
				else
					bin_pkt_list = bin_pkt;
			}

			lock_release(cluster->lock);

			/* deliver list of bin packets to module for processing */
			cap->reg->packet_cb(bin_pkt_list);

			lock_get(cluster->lock);

			/* free previously processed packets */
			buf_pkt = cap->pkt_q_front;
			cutpos_next = cap->pkt_q_cutpos->next;
			bin_pkt = bin_pkt_list;
			while (buf_pkt != cutpos_next) {
				buf_tmp = buf_pkt;
				bin_tmp = bin_pkt;
				buf_pkt = buf_pkt->next;
				bin_pkt = bin_pkt->next;
				/* do shm_free() instead of bin_free_packet() becuase the buffer
				 * in bin_packet_t points to the shm buf in struct buf_bin_pkt */
				shm_free(buf_tmp->buf.s);
				pkg_free(bin_tmp);
				shm_free(buf_tmp);
			}
			cap->pkt_q_front = cutpos_next;
			if (!cap->pkt_q_front)
				cap->pkt_q_back = NULL;
		}

		/* no more buffered packets to process, stop buffering */
		cap->pkt_buffering = 0;

		lock_release(cluster->lock);
	}
}

int buffer_bin_pkt(bin_packet_t *packet, struct local_cap *cap, int src_id)
{
	struct buf_bin_pkt *saved_pkt;
	struct buf_bin_pkt *prev_q_back;
	str bin_buffer;

	saved_pkt = shm_malloc(sizeof *saved_pkt);
	if (!saved_pkt) {
		LM_ERR("No more sh memory\n");
		return -1;
	}

	saved_pkt->next = NULL;
	saved_pkt->src_id = src_id;

	if (!cap->pkt_q_back)
		cap->pkt_q_front = saved_pkt;
	else
		cap->pkt_q_back->next = saved_pkt;

	prev_q_back = cap->pkt_q_back;
	cap->pkt_q_back = saved_pkt;

	bin_get_buffer(packet, &bin_buffer);
	saved_pkt->buf.s = shm_malloc(bin_buffer.len);
	if (!saved_pkt->buf.s) {
		cap->pkt_q_back = prev_q_back;
		if (!prev_q_back)
			cap->pkt_q_front = NULL;
		else
			cap->pkt_q_back->next = NULL;
		shm_free(saved_pkt);
		LM_ERR("No more shm memory\n");
		return -1;
	}
	memcpy(saved_pkt->buf.s, bin_buffer.s, bin_buffer.len);
	saved_pkt->buf.len = bin_buffer.len;

	return 0;
}

