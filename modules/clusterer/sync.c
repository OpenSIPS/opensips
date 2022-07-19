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
#include "../../ipc.h"
#include "../../status_report.h"

#include "api.h"
#include "node_info.h"
#include "topology.h"
#include "clusterer.h"
#include "sync.h"

int sync_packet_size = DEFAULT_SYNC_PACKET_SIZE;
int _sync_from_id = 0;

static bin_packet_t *sync_packet_snd;
static int sync_prev_buf_len;
static int *sync_last_chunk_sz;

int send_sync_req(str *capability, int cluster_id, int source_id)
{
	bin_packet_t packet;
	int rc;

	if (bin_init(&packet, &cl_extra_cap, CLUSTERER_SYNC_REQ, BIN_SYNC_VERSION, 0) < 0) {
		LM_ERR("Failed to init bin send buffer\n");
		return -1;
	}

	bin_push_str(&packet, capability);
	msg_add_trailer(&packet, cluster_id, source_id);

	rc = clusterer_send_msg(&packet, cluster_id, source_id, 0, 1);
	if (rc == CLUSTERER_SEND_SUCCESS)
		LM_INFO("Sent sync request for capability '%.*s' to node %d, "
		        "cluster %d\n", capability->len, capability->s, source_id,
		        cluster_id);

	bin_free_packet(&packet);

	return rc;
}

static int get_sync_source(cluster_info_t *cluster, str *capability,
                           enum cl_node_match_op match_cond)
{
	node_info_t *node;
	struct remote_cap *cap;

	for (node = cluster->node_list; node; node = node->next) {
		if (get_next_hop(node) == 0)
			continue;

		if (!match_node(cluster->current_node, node, match_cond))
			continue;

		lock_get(node->lock);
		for (cap = node->capabilities; cap; cap = cap->next)
			if (!str_strcmp(capability, &cap->name))
				break;

		/* if the node does have the capability and it's in the OK state
		 * then it can be a source for syncing */
		if (cap && cap->flags & CAP_STATE_OK) {
			lock_release(node->lock);
			return node->node_id;
		}

		lock_release(node->lock);
	}

	return 0;
}

int queue_sync_request(cluster_info_t *cluster, struct local_cap *lcap)
{
	lock_get(cluster->lock);
	lcap->flags |= CAP_SYNC_PENDING;

	if (cluster->current_node->flags & NODE_IS_SEED)
		gettimeofday(&lcap->sync_req_time, NULL);

	lock_release(cluster->lock);

	sr_set_status(cl_srg, STR2CI(lcap->reg.sr_id), CAP_SR_SYNC_PENDING,
		STR2CI(CAP_SR_STATUS_STR(CAP_SR_SYNC_PENDING)), 0);
	if (sr_add_report_fmt(cl_srg, STR2CI(lcap->reg.sr_id), 0, "Sync requested"))
		return -1;

	return 0;
}

int cl_request_sync(str *capability, int cluster_id)
{
	cluster_info_t *cluster;
	struct local_cap *lcap;
	int source_id;

	LM_DBG("requesting %.*s sync in cluster %d\n",
	       capability->len, capability->s, cluster_id);

	cluster = get_cluster_by_id(cluster_id);
	if (!cluster) {
		LM_ERR("Unknown cluster [%d]\n", cluster_id);
		return -1;
	}

	for (lcap = cluster->capabilities; lcap; lcap = lcap->next)
		if (!str_strcmp(capability, &lcap->reg.name))
			break;
	if (!lcap) {
		LM_ERR("Request sync for unknown capability: %.*s\n",
			capability->len, capability->s);
		return -1;
	}

	lock_get(cluster->lock);
	if (lcap->flags & CAP_SYNC_PENDING) {
		lock_release(cluster->lock);
		LM_DBG("Sync request already pending\n");
		return 0;
	}
	if (lcap->flags & CAP_SYNC_IN_PROGRESS) {
		lock_release(cluster->lock);
		LM_DBG("Sync already in progress\n");
		return 1;
	}

	if (!(lcap->flags & CAP_STATE_ENABLED)) {
		lock_release(cluster->lock);
		LM_DBG("Capability disabled, skip send sync request\n");
		return 0;
	}

	lcap->sync_total_chunks_cnt = 0;
	lcap->sync_cur_chunks_cnt = 0;

	/* node is no longer OK for this capability if it previously were */
	if (lcap->flags & CAP_STATE_OK) {
		lcap->flags &= ~CAP_STATE_OK;
		lock_release(cluster->lock);
		send_single_cap_update(cluster, lcap, 0);
	} else
		lock_release(cluster->lock);

	source_id = get_sync_source(cluster, capability, lcap->reg.sync_cond);
	if (source_id == 0) {	/* we didn't find any node ready to sync from */
		LM_DBG("donor node not found\n");
		/* send requst later */
		queue_sync_request(cluster, lcap);
	} else {
		LM_DBG("found donor node: %d\n", source_id);
		if (send_sync_req(capability, cluster_id, source_id) !=
			CLUSTERER_SEND_SUCCESS) {
			 /* retry request later */
			queue_sync_request(cluster, lcap);
		} else {
			sr_set_status(cl_srg, STR2CI(lcap->reg.sr_id), CAP_SR_SYNC_PENDING,
				STR2CI(CAP_SR_STATUS_STR(CAP_SR_SYNC_PENDING)), 0);
			if (sr_add_report_fmt(cl_srg, STR2CI(lcap->reg.sr_id), 0,
				"Sync requested from node [%d]", source_id))
				return -1;
		}
	}

	return 0;
}

static int no_sync_chunks_sent;

bin_packet_t *cl_sync_chunk_start(str *capability, int cluster_id, int dst_id,
                                  short data_version)
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
			*sync_last_chunk_sz = prev_chunk_size;

			/* send and free the previous packet */
			msg_add_trailer(sync_packet_snd, cluster_id, dst_id);

			if (clusterer_send_msg(sync_packet_snd, cluster_id, dst_id, 0,
				1 /* we should be in a SYNC_REQ_RCV callback here so
				   * already locked*/) < 0)
				LM_ERR("Failed to send sync packet\n");

			bin_free_packet(sync_packet_snd);
			pkg_free(sync_packet_snd);
			sync_packet_snd = NULL;
			sync_last_chunk_sz = NULL;
		}

		new_packet = pkg_malloc(sizeof *new_packet);
		if (!new_packet) {
			LM_ERR("No more pkg memory\n");
			return NULL;
		}

		if (bin_init(new_packet,&cl_extra_cap,CLUSTERER_SYNC,BIN_SYNC_VERSION,0)<0) {
			LM_ERR("Failed to init bin packet\n");
			pkg_free(new_packet);
			return NULL;
		}

		bin_push_str(new_packet, capability);
		bin_push_int(new_packet, data_version);
		sync_packet_snd = new_packet;
	}

	if (sync_last_chunk_sz)
		*sync_last_chunk_sz = prev_chunk_size;

	/* reserve and remember a holder for the upcoming data chunk size */
	bin_get_buffer(sync_packet_snd, &bin_buffer);
	bin_push_int(sync_packet_snd, 0);
	sync_last_chunk_sz = (int *)(bin_buffer.s + bin_buffer.len);

	bin_push_int(sync_packet_snd, SYNC_CHUNK_START_MARKER);

	bin_get_buffer(sync_packet_snd, &bin_buffer);
	sync_prev_buf_len = bin_buffer.len;

	no_sync_chunks_sent++;

	return sync_packet_snd;
}

int no_sync_chunks_iter;

/* this mechanism allows modules to ignore all or part of a sync chunk
 * without disrupting the sequencing / consuming of the remaining data */
char *next_data_chunk;

int cl_sync_chunk_iter(bin_packet_t *packet)
{
	str bin_buffer;
	int next_chunk_sz, start_marker;
	int rc;

	if (!packet) {
		LM_ERR("No sync packet\n");
		return 0;
	}

	if (next_data_chunk) {
		bin_get_buffer(packet, &bin_buffer);
		if (next_data_chunk < bin_buffer.s ||
		        next_data_chunk >= bin_buffer.s + bin_buffer.len) {
			next_data_chunk = NULL; /* no more chunks */
			return 0;
		}

		packet->front_pointer = next_data_chunk;
	}

	rc = bin_pop_int(packet, &next_chunk_sz);
	if (rc < 0) {
		LM_ERR("error retrieving next sync chunk size\n");
		return 0;
	} else if (rc > 0) {
		/* no more chunks in this packet */
		return 0;
	}

	rc = bin_pop_int(packet, &start_marker);
	if (rc < 0) {
		LM_ERR("Error retrieving sync chunk start marker\n");
		return 0;
	} else if (rc > 0) {
		LM_ERR("no more data: failed to read sync chunk start marker\n");
		return 0;
	} else if (start_marker != SYNC_CHUNK_START_MARKER) {
		LM_ERR("Bad sync chunk start marker\n");
		return 0;
	}

	no_sync_chunks_iter++;

	next_data_chunk = packet->front_pointer + next_chunk_sz;
	return 1;
}

void send_sync_repl(int sender, void *param)
{
	bin_packet_t sync_end_pkt;
	str bin_buffer;
	struct local_cap *cap;
	int rc, cluster_id;
	struct reply_rpc_params *p = (struct reply_rpc_params *)param;

	lock_start_read(cl_list_lock);

	for (cap = p->cluster->capabilities; cap; cap = cap->next)
		if (!str_strcmp(&p->cap_name, &cap->reg.name))
			break;
	if (!cap) {
		LM_ERR("Sync request for unknown capability: %.*s\n",
			p->cap_name.len, p->cap_name.s);
		lock_stop_read(cl_list_lock);
		return;
	}

	no_sync_chunks_sent = 0;

	cap->reg.event_cb(SYNC_REQ_RCV, p->node_id);

	if (sync_packet_snd) {
		bin_get_buffer(sync_packet_snd, &bin_buffer);
		*sync_last_chunk_sz = bin_buffer.len - sync_prev_buf_len;

		/* send and free the lastly built packet */
		msg_add_trailer(sync_packet_snd, p->cluster->cluster_id, p->node_id);

		if ((rc = clusterer_send_msg(sync_packet_snd, p->cluster->cluster_id,
			p->node_id, 0, 1))<0)
			LM_ERR("Failed to send sync packet, rc=%d\n", rc);

		bin_free_packet(sync_packet_snd);
		pkg_free(sync_packet_snd);
		sync_packet_snd = NULL;
		sync_last_chunk_sz = NULL;
	}

	/* send indication that all sync packets were sent */
	if (bin_init(&sync_end_pkt,&cl_extra_cap,CLUSTERER_SYNC_END,BIN_SYNC_VERSION,0)<0) {
		LM_ERR("Failed to init bin packet\n");
		lock_stop_read(cl_list_lock);
		return;
	}
	bin_push_str(&sync_end_pkt, &p->cap_name);
	bin_push_int(&sync_end_pkt, no_sync_chunks_sent);
	msg_add_trailer(&sync_end_pkt, p->cluster->cluster_id, p->node_id);

	if (clusterer_send_msg(&sync_end_pkt, p->cluster->cluster_id, p->node_id,
		0, 1) < 0) {
		LM_ERR("Failed to send sync end message\n");
		bin_free_packet(&sync_end_pkt);
		lock_stop_read(cl_list_lock);
		return;
	}

	cluster_id = p->cluster->cluster_id;
	lock_stop_read(cl_list_lock);

	bin_free_packet(&sync_end_pkt);

	LM_INFO("Sent all sync packets for capability '%.*s' to node %d, cluster "
	        "%d\n", p->cap_name.len, p->cap_name.s, p->node_id, cluster_id);

	shm_free(param);
}

int ipc_dispatch_sync_reply(cluster_info_t *cluster, int node_id, str *cap_name)
{
	struct reply_rpc_params *params;

	params = shm_malloc(sizeof *params + cap_name->len);
	if (!params) {
		LM_ERR("oom!\n");
		return -1;
	}
	memset(params, 0, sizeof *params);
	params->cap_name.s = (char *)(params + 1);

	memcpy(params->cap_name.s, cap_name->s, cap_name->len);
	params->cap_name.len = cap_name->len;
	params->node_id = node_id;
	params->cluster = cluster;

	if (ipc_dispatch_rpc(send_sync_repl, params) < 0) {
		LM_ERR("Failed to dispatch rpc\n");
		return -1;
	}

	return 0;
}

void handle_sync_request(bin_packet_t *packet, cluster_info_t *cluster,
							node_info_t *source)
{
	str cap_name;
	struct remote_cap *cap;
	int rc;

	bin_pop_str(packet, &cap_name);

	LM_INFO("Received sync request for capability '%.*s' from node %d, "
	        "cluster %d\n", cap_name.len, cap_name.s, source->node_id,
	        cluster->cluster_id);

	rc = get_capability_status(cluster, &cap_name);
	if (rc == -1) {
		return;
	} else if (rc == 0) {
		LM_DBG("capability disabled, drop sync request\n");
		return;
	}

	if (get_next_hop(source)) {
		if (ipc_dispatch_sync_reply(cluster, source->node_id, &cap_name) < 0)
			LM_ERR("Failed to dispatch sync reply job\n");
	} else {
		lock_get(source->lock);

		for (cap = source->capabilities; cap; cap = cap->next)
			if (!str_strcmp(&cap_name, &cap->name))
				break;
		if (!cap) {
			LM_ERR("Requesting node does not appear to have capability: %.*s\n",
				cap_name.len, cap_name.s);
			lock_release(source->lock);
			return;
		}

		/* reply to sync later when the node is up */
		cap->flags |= CAP_SYNC_PENDING;
		lock_release(source->lock);
	}
}

static void run_cb_buf_pkt(int sender, void *param)
{
	struct packet_rpc_params *p = (struct packet_rpc_params *)param;
	bin_packet_t packet;

	if (p->pkt_buf.s) {
		bin_init_buffer(&packet, p->pkt_buf.s, p->pkt_buf.len);
		packet.src_id = p->pkt_src_id;

		p->cap->packet_cb(&packet);
	} else {
		p->cap->event_cb(SYNC_DONE, p->pkt_src_id);
	}

	shm_free(param);
}

int ipc_dispatch_buf_pkt(struct buf_bin_pkt *buf_pkt,
	struct capability_reg *cap, int source_id)
{
	struct packet_rpc_params *params;

	params = shm_malloc(sizeof *params + (buf_pkt ? buf_pkt->buf.len : 0));
	if (!params) {
		LM_ERR("oom!\n");
		return -1;
	}
	memset(params, 0, sizeof *params);

	if (buf_pkt) {
		params->pkt_buf.s = (char *)(params + 1);
		memcpy(params->pkt_buf.s, buf_pkt->buf.s, buf_pkt->buf.len);
		params->pkt_buf.len = buf_pkt->buf.len;
	}

	params->pkt_src_id = source_id;
	params->cap = cap;

	if (ipc_dispatch_rpc(run_cb_buf_pkt, params) < 0) {
		LM_ERR("Failed to dispatch rpc\n");
		return -1;
	}

	return 0;
}

void handle_sync_end(cluster_info_t *cluster, struct local_cap *cap,
	int source_id, int no_sync_chunks, int is_timeout)
{
	struct buf_bin_pkt *buf_pkt, *buf_tmp;

	/* post-sync phase */
	buf_pkt = cap->pkt_q_front;
	while (buf_pkt) {
		ipc_dispatch_buf_pkt(buf_pkt, &cap->reg, source_id);

		buf_tmp = buf_pkt;
		buf_pkt = buf_pkt->next;
		/* do shm_free() instead of bin_free_packet() becuase the buffer
		 * in bin_packet_t points to the shm buf in struct buf_bin_pkt */
		shm_free(buf_tmp->buf.s);
		shm_free(buf_tmp);
	}

	cap->pkt_q_front = NULL;
	cap->pkt_q_back = NULL;

	/* no more buffered packets to process, stop buffering */
	cap->flags &= ~CAP_SYNC_IN_PROGRESS;

	if (!is_timeout) {
		cap->flags |= CAP_STATE_OK;

		sr_set_status(cl_srg, STR2CI(cap->reg.sr_id), CAP_SR_SYNCED,
			STR2CI(CAP_SR_STATUS_STR(CAP_SR_SYNCED)), 0);
		sr_add_report_fmt(cl_srg, STR2CI(cap->reg.sr_id), 0,
			"Sync completed, received [%d] chunks", no_sync_chunks);

		/* inform module that sync is finished; this job is also dispatched */
		ipc_dispatch_buf_pkt(NULL, &cap->reg, source_id);

		/* send update about the state of this capability */
		send_single_cap_update(cluster, cap, 1);
	}
}

void handle_sync_packet(bin_packet_t *packet, int packet_type,
								cluster_info_t *cluster, int source_id)
{
	str cap_name;
	struct local_cap *cap;
	int data_version;
	int no_sync_chunks;
	int was_in_progress = 0;

	if (get_bin_pkg_version(packet) != BIN_SYNC_VERSION) {
		LM_INFO("discarding sync packet version %d, need version %d\n",
		        get_bin_pkg_version(packet), BIN_SYNC_VERSION);
		return;
	}

	bin_pop_str(packet, &cap_name);
	for (cap = cluster->capabilities; cap; cap = cap->next)
		if (!str_strcmp(&cap_name, &cap->reg.name))
			break;
	if (!cap) {
		LM_ERR("Capability: %.*s from sync packet, not found\n",
			cap_name.len, cap_name.s);
		return;
	}

	if (get_capability_status(cluster, &cap_name) != 1) {
		LM_DBG("capability disabled, drop sync packet\n");
		return;
	}

	if (packet_type == CLUSTERER_SYNC) {
		bin_pop_int(packet, &data_version);

		lock_get(cluster->lock);
		if (cap->flags & CAP_SYNC_IN_PROGRESS)
			was_in_progress = 1;
		/* buffer other types of packets during sync */
		cap->flags |= CAP_SYNC_IN_PROGRESS;
		cap->last_sync_pkt = get_ticks();
		lock_release(cluster->lock);

		if (!was_in_progress) {
			sr_set_status(cl_srg, STR2CI(cap->reg.sr_id), CAP_SR_SYNCING,
				STR2CI(CAP_SR_STATUS_STR(CAP_SR_SYNCING)), 0);
			sr_add_report_fmt(cl_srg, STR2CI(cap->reg.sr_id), 0,
				"Sync started from node [%d]", source_id);
		}

		/* overwrite packet type with one identifiable by modules */
		packet->type = SYNC_PACKET_TYPE;
		packet->src_id = source_id;
		set_bin_pkg_version(packet, (short)data_version);

		if (ipc_dispatch_mod_packet(packet, &cap->reg, cluster->cluster_id) < 0)
			LM_ERR("Failed to dispatch handling of module packet\n");
	} else { /* CLUSTERER_SYNC_END */
		LM_INFO("Received all sync packets for capability '%.*s' in "
		        "cluster %d\n", cap_name.len, cap_name.s, cluster->cluster_id);

		bin_pop_int(packet, &no_sync_chunks);

		lock_get(cluster->lock);

		cap->sync_total_chunks_cnt = no_sync_chunks;

		/* if all chunks have been processed run the sync end actions */
		if (cap->sync_cur_chunks_cnt == no_sync_chunks)
			handle_sync_end(cluster, cap, source_id, no_sync_chunks, 0);

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

int update_sync_chunks_cnt(int cluster_id, str *cap_name, int source_id)
{
	cluster_info_t *cluster;
	struct local_cap *cap;

	lock_start_read(cl_list_lock);

	cluster = get_cluster_by_id(cluster_id);
	if (!cluster) {
		LM_ERR("unknown cluster, id [%d]\n", cluster_id);
		goto error;
	}

	for (cap = cluster->capabilities; cap; cap = cap->next)
		if (!str_strcmp(&cap->reg.name, cap_name))
			break;
	if (!cap) {
		LM_ERR("capability: %.*s not found in cluster info\n",
			cap_name->len, cap_name->s);
		goto error;
	}

	lock_get(cluster->lock);

	cap->sync_cur_chunks_cnt += no_sync_chunks_iter;

	/* if we know the total number of chunks and this is the last chunk,
	 * run the sync end actions */
	if (cap->sync_total_chunks_cnt != 0 &&
		cap->sync_cur_chunks_cnt == cap->sync_total_chunks_cnt)
		handle_sync_end(cluster, cap, source_id, cap->sync_total_chunks_cnt, 0);

	lock_release(cluster->lock);

	lock_stop_read(cl_list_lock);

	return 0;

error:
	lock_stop_read(cl_list_lock);
	return -1;
}
