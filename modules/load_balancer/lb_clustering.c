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
		unsigned int flags);


int lb_cluster_shtag_is_active(void)
{
	if ( lb_cluster_id<=0 || lb_cluster_shtag.s==NULL ||
	c_api.shtag_get(&lb_cluster_shtag,lb_cluster_id)==SHTAG_STATE_ACTIVE )
		/* no clustering support or sharing tag found on not-active */
		return 1;

	return 0;
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

	bin_push_int(&packet, dst->group);
	bin_push_str(&packet, &dst->uri);
	bin_push_int(&packet, dst->flags&LB_DST_STAT_MASK);

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


static void receive_lb_binary_packet(bin_packet_t *packet)
{
	unsigned int group, flags;
	str uri;

	LM_DBG("received a binary packet [%d]!\n", packet->type);

	if(get_bin_pkg_version(packet) != BIN_VERSION) {
		LM_ERR("incompatible bin protocol version\n");
		return;
	}

	if (packet->type == REPL_LB_STATUS_UPDATE) {
		bin_pop_int(packet, &group);
		bin_pop_str(packet, &uri);
		bin_pop_int(packet, &flags);

		lb_update_from_replication( group, &uri, flags);
	} else {
		LM_ERR("invalid load_balancer binary packet type: %d\n", packet->type);
	}
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
	receive_lb_binary_packet, NULL, lb_cluster_id, 0, NODE_CMP_ANY) < 0) {
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

	return 0;
}

