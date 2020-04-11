/*
 * Copyright (C) 2017 OpenSIPS Project
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
 * Foundation Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

#include "../../ut.h"
#include "../../rw_locking.h"
#include "lb_data.h"
#include "lb_bl.h"
#include "lb_clustering.h"

#define BIN_VERSION 1

#define REPL_LB_STATUS_UPDATE 1

int lb_cluster_id = 0;

str lb_cluster_shtag = {NULL,0};

static struct clusterer_binds c_api;
static str status_repl_cap = str_init("load_balancer-status-repl");

/* implemented in load_balancer.c which has no .h file */
int lb_update_from_replication( unsigned int group, str *uri,
		unsigned int flags, int raise_event);


int lb_cluster_shtag_is_active(void)
{
	if ( lb_cluster_id<=0 || lb_cluster_shtag.s==NULL ||
	c_api.shtag_get(&lb_cluster_shtag,lb_cluster_id)==SHTAG_STATE_ACTIVE )
		/* no clustering support or sharing tag found on not-active */
		return 1;

	return 0;
}

static void bin_push_dst_status(bin_packet_t *packet, struct lb_dst *dst)
{
	bin_push_int(packet, dst->group);
	bin_push_str(packet, &dst->uri);
	bin_push_int(packet, dst->flags&LB_DST_STAT_MASK);
}

void replicate_lb_status(struct lb_dst *dst)
{
	bin_packet_t packet;
	int rc;

	if ( lb_cluster_id<=0 || (lb_cluster_shtag.s &&
	c_api.shtag_get(&lb_cluster_shtag,lb_cluster_id)!=SHTAG_STATE_ACTIVE) )
		/* no clustering support or sharing tag found on not-active */
		return;

	if (bin_init(&packet, &status_repl_cap, REPL_LB_STATUS_UPDATE, BIN_VERSION, 0)!=0){
		LM_ERR("failed to replicate this event\n");
		return;
	}

	bin_push_dst_status(&packet, dst);

	rc = c_api.send_all(&packet, lb_cluster_id);
	switch (rc) {
	case CLUSTERER_CURR_DISABLED:
		LM_INFO("Current node is disabled in cluster: %d\n", lb_cluster_id);
		break;
	case CLUSTERER_DEST_DOWN:
		LM_INFO("All destinations in cluster: %d are down or probing\n",
			lb_cluster_id);
		break;
	case CLUSTERER_SEND_ERR:
		LM_ERR("Error sending in cluster: %d\n", lb_cluster_id);
		break;
	}

	bin_free_packet(&packet);
}

static int lb_recv_status_update(bin_packet_t *packet, int raise_event)
{
	unsigned int group, flags;
	str uri;

	bin_pop_int(packet, &group);
	bin_pop_str(packet, &uri);
	bin_pop_int(packet, &flags);

	return lb_update_from_replication( group, &uri, flags, raise_event);
}

static void receive_lb_binary_packet(bin_packet_t *packet)
{
	bin_packet_t *pkt;

	for (pkt = packet; pkt; pkt = pkt->next) {
		LM_DBG("received a binary packet [%d]!\n", packet->type);

		switch (pkt->type) {
		case REPL_LB_STATUS_UPDATE:
			ensure_bin_version(pkt, BIN_VERSION);

			if (lb_recv_status_update(pkt, 1)<0)
				LM_ERR("failed to process binary packet!\n");
			break;
		case SYNC_PACKET_TYPE:
			_ensure_bin_version(pkt, BIN_VERSION, "load_balancer sync packet");

			while (c_api.sync_chunk_iter(pkt))
				if (lb_recv_status_update(pkt, 0) < 0)
					LM_WARN("failed to process sync chunk!\n");
			break;
		default:
			LM_ERR("invalid load_balancer binary packet type: %d\n", pkt->type);
		}
	}
}

static int lb_recv_sync_request(int node_id)
{
	bin_packet_t *sync_packet;
	struct lb_dst *dst;

	lock_start_read(ref_lock);

	for (dst = (*curr_data)->dsts; dst; dst = dst->next) {
		sync_packet = c_api.sync_chunk_start(&status_repl_cap, lb_cluster_id,
			node_id, BIN_VERSION);
		if (!sync_packet)
			goto error;

		bin_push_dst_status(sync_packet, dst);
	}

	lock_stop_read(ref_lock);

	return 0;

error:
	return -1;
	lock_stop_read(ref_lock);
}

void receive_lb_cluster_event(enum clusterer_event ev, int node_id)
{
	if (ev == SYNC_REQ_RCV && lb_recv_sync_request(node_id) < 0)
		LM_ERR("Failed to send sync data to node: %d\n", node_id);
	else if (ev == SYNC_DONE)
		LM_INFO("Synchronized destinations status from cluster\n");
}

int lb_cluster_sync(void) {
	if (c_api.request_sync(&status_repl_cap, lb_cluster_id) < 0) {
		LM_ERR("Sync request failed\n");
		return -1;
	}

	return 0;
}

int lb_init_cluster(void)
{
	if (load_clusterer_api(&c_api)!=0) {
		LM_ERR("failed to find clusterer API - is clusterer "
			"module loaded?\n");
		return -1;
	}

	/* register handler for processing load-balancer  packets 
	 * to the clusterer module */
	if (c_api.register_capability( &status_repl_cap,
		receive_lb_binary_packet, receive_lb_cluster_event, lb_cluster_id, 1,
		NODE_CMP_ANY) < 0) {
		LM_ERR("cannot register binary packet callback to "
			"clusterer module!\n");
		return -1;
	}

	/* "register" the sharing tag */
	if (lb_cluster_shtag.s) {
		lb_cluster_shtag.len = strlen(lb_cluster_shtag.s);
		if (c_api.shtag_get( &lb_cluster_shtag, lb_cluster_id)<0) {
			LM_ERR("failed to initialized the sharing tag <%.*s>\n",
				lb_cluster_shtag.len, lb_cluster_shtag.s);
			return -1;
		}
	} else {
		lb_cluster_shtag.len = 0;
	}

	if (c_api.request_sync(&status_repl_cap, lb_cluster_id) < 0) {
		LM_ERR("Sync request failed\n");
		return -1;
	}

	if (lb_cluster_sync() < 0)
		return -1;

	return 0;
}
