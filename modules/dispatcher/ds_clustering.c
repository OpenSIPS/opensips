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


int ds_cluster_shtag_is_active(void)
{
	if ( ds_cluster_id<=0 || ds_cluster_shtag.s==NULL ||
	c_api.shtag_get(&ds_cluster_shtag,ds_cluster_id)==SHTAG_STATE_ACTIVE )
		/* no clustering support or sharing tag found active */
		return 1;

	return 0;
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

	/* replicate the partition name */
	bin_push_str(&packet, partition);
	/* replicate the group ID */
	bin_push_int(&packet, group);
	/* replicate the address of the destination */
	bin_push_str(&packet, address);
	/* replicate the type of operation set/reset */
	bin_push_int(&packet, type);
	/* replicate the state of the destination */
	bin_push_int(&packet, state);

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


static int ds_status_update(bin_packet_t *packet)
{
	unsigned int group, state;
	int type;
	str address, partition_name;
	ds_partition_t *partition;

	bin_pop_str(packet, &partition_name);
	bin_pop_int(packet, &group);
	bin_pop_str(packet, &address);
	bin_pop_int(packet, &type);
	bin_pop_int(packet, &state);

	partition = find_partition_by_name(&partition_name);
	if (partition == NULL)
		return -1;

	ds_set_state_repl( group, &address, state, type, partition, 0 /*no repl*/);

	return 0;
}


static void receive_ds_binary_packet(bin_packet_t *packet)
{
	LM_DBG("received a binary packet [%d]!\n", packet->type);

	if(get_bin_pkg_version(packet) != BIN_VERSION) {
		LM_ERR("incompatible bin protocol version\n");
		return;
	}

	switch (packet->type) {
	case REPL_DS_STATUS_UPDATE:
		ds_status_update(packet);
		break;
	default:
		LM_WARN("Invalid dispatcher binary packet command: %d "
			"(from node: %d in cluster: %d)\n",
			packet->type, packet->src_id, ds_cluster_id);
	}
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
	receive_ds_binary_packet, NULL, ds_cluster_id, 0, NODE_CMP_ANY) < 0) {
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

	return 0;
}


