/*
 * Copyright (C) 2018 OpenSIPS Project
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

#include "../../ip_addr.h"
#include "../../ut.h"
#include "ds_clustering.h"
#include "dispatch.h"

#define BIN_VERSION 1

#define REPL_DS_STATUS_UPDATE 1

/* the cluster ID  */
int ds_cluster_id = 0;

str ds_cluster_shtag = {NULL,0};

static str status_repl_cap = str_init("dispatcher-status-repl");
static struct clusterer_binds c_api;

extern ds_partition_t *partitions;

int ds_cluster_shtag_is_active(void)
{
	if ( ds_cluster_id<=0 || ds_cluster_shtag.s==NULL ||
	c_api.shtag_get(&ds_cluster_shtag,ds_cluster_id)==SHTAG_STATE_ACTIVE )
		/* no clustering support or sharing tag found active */
		return 1;

	return 0;
}

static void bin_push_dst_status(bin_packet_t *packet, str *partition,
	int group, str *address, int type, int state, int is_sync)
{
	/* replicate the partition name */
	bin_push_str(packet, partition);
	/* replicate the group ID */
	bin_push_int(packet, group);
	/* replicate the address of the destination */
	bin_push_str(packet, address);

	if (!is_sync)
		/* replicate the type of operation set/reset */
		bin_push_int(packet, type);

	/* replicate the state of the destination */
	bin_push_int(packet, state);
}

void replicate_ds_status_event(str *partition, int group, str *address,
														int state, int type)
{
	bin_packet_t packet;
	int rc;

	if ( ds_cluster_id<=0 || (ds_cluster_shtag.s &&
	c_api.shtag_get(&ds_cluster_shtag,ds_cluster_id)!=SHTAG_STATE_ACTIVE) )
		/* no clustering support or sharing tag found on not-active */
		return;

	if (bin_init(&packet, &status_repl_cap, REPL_DS_STATUS_UPDATE,
	BIN_VERSION, 0)!=0){
		LM_ERR("failed to replicate this event\n");
		return;
	}

	bin_push_dst_status(&packet, partition, group, address, type, state, 0);

	rc = c_api.send_all(&packet, ds_cluster_id);
	switch (rc) {
	case CLUSTERER_CURR_DISABLED:
		LM_INFO("Current node is disabled in cluster: %d\n", ds_cluster_id);
		break;
	case CLUSTERER_DEST_DOWN:
		LM_INFO("All destinations in cluster: %d are down or probing\n",
			ds_cluster_id);
		break;
	case CLUSTERER_SEND_ERR:
		LM_ERR("Error sending in cluster: %d\n", ds_cluster_id);
		break;
	}

	bin_free_packet(&packet);
}


static int ds_status_update(bin_packet_t *packet, int is_sync)
{
	unsigned int group, state;
	int type = -1;
	str address, partition_name;
	ds_partition_t *partition;

	bin_pop_str(packet, &partition_name);
	bin_pop_int(packet, &group);
	bin_pop_str(packet, &address);

	if (!is_sync)
		bin_pop_int(packet, &type);

	bin_pop_int(packet, &state);

	partition = find_partition_by_name(&partition_name);
	if (partition == NULL)
		return -1;

	if (ds_set_state_repl( group, &address, state, type, partition,
		0 /*no repl*/, is_sync) < 0)
		return -1;

	return 0;
}

static void receive_ds_binary_packet(bin_packet_t *packet)
{
	bin_packet_t *pkt;
	int rc = 0;

	for (pkt = packet; pkt; pkt = pkt->next) {
		LM_DBG("received a binary packet [%d]!\n", packet->type);

		switch (packet->type) {
		case REPL_DS_STATUS_UPDATE:
			ensure_bin_version(pkt, BIN_VERSION);

			rc = ds_status_update(packet, 0);
			break;
		case SYNC_PACKET_TYPE:
			_ensure_bin_version(pkt, BIN_VERSION, "dispatcher sync packet");

			while (c_api.sync_chunk_iter(pkt))
				if (ds_status_update(pkt, 1) < 0)
					LM_WARN("failed to process sync chunk!\n");
			break;
		default:
			LM_WARN("Invalid dispatcher binary packet command: %d "
				"(from node: %d in cluster: %d)\n",
				packet->type, packet->src_id, ds_cluster_id);
		}

		if (rc != 0)
			LM_ERR("failed to process binary packet!\n");
	}
}

static int ds_recv_sync_request(int node_id)
{
	bin_packet_t *sync_packet;
	ds_partition_t *part_it;
	ds_set_p set;
	int i;

	for (part_it = partitions; part_it; part_it = part_it->next) {
		if ((*part_it->data)->sets == NULL)
			continue;

		lock_start_read(part_it->lock);

		for (set = (*part_it->data)->sets; set; set = set->next)
			for(i = 0; i < set->nr; i++) {
				sync_packet = c_api.sync_chunk_start(&status_repl_cap,
					ds_cluster_id, node_id, BIN_VERSION);
				if (!sync_packet)
					goto error;

				bin_push_dst_status(sync_packet, &part_it->name, set->id,
					&set->dlist[i].uri, -1, set->dlist[i].flags, 1);
			}

		lock_stop_read(part_it->lock);
	}

	return 0;

error:
	lock_stop_read(part_it->lock);
	return -1;
}

void receive_ds_cluster_event(enum clusterer_event ev, int node_id)
{
	if (ev == SYNC_REQ_RCV && ds_recv_sync_request(node_id) < 0)
		LM_ERR("Failed to send sync data to node: %d\n", node_id);
	else if (ev == SYNC_DONE)
		LM_INFO("Synchronized destinations status from cluster\n");
}

int ds_cluster_sync(void) {
	if (c_api.request_sync(&status_repl_cap, ds_cluster_id) < 0) {
		LM_ERR("Sync request failed\n");
		return -1;
	}

	return 0;
}

int ds_init_cluster(void)
{
	if (load_clusterer_api(&c_api)!=0) {
		LM_ERR("failed to find clusterer API - is clusterer "
			"module loaded?\n");
		return -1;
	}

	/* register handler for processing drouting packets 
	 * to the clusterer module */
	if (c_api.register_capability( &status_repl_cap,
		receive_ds_binary_packet, receive_ds_cluster_event, ds_cluster_id, 0,
		NODE_CMP_ANY) < 0) {
		LM_ERR("cannot register binary packet callback to "
			"clusterer module!\n");
		return -1;
	}

	/* "register" the sharing tag */
	if (ds_cluster_shtag.s) {
		ds_cluster_shtag.len = strlen(ds_cluster_shtag.s);
		if (c_api.shtag_get( &ds_cluster_shtag, ds_cluster_id)<0) {
			LM_ERR("failed to initialized the sharing tag <%.*s>\n",
				ds_cluster_shtag.len, ds_cluster_shtag.s);
			return -1;
		}
	} else {
		ds_cluster_shtag.len = 0;
	}

	if (ds_cluster_sync() < 0)
		return -1;

	return 0;
}

