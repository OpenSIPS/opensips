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
#include "lb_replication.h"

str repl_lb_module_name = str_init("load_balancer");
struct clusterer_binds clusterer_api;

int accept_replicated_status = 0;
int replicated_status_cluster = 0;


void replicate_lb_status(struct lb_dst *dst)
{
	bin_packet_t packet;
	int rc;

	if (bin_init(&packet, &repl_lb_module_name, REPL_LB_STATUS_UPDATE, BIN_VERSION, 0)!=0){
		LM_ERR("failed to replicate this event\n");
		return;
	}

	bin_push_int(&packet, dst->group);
	bin_push_str(&packet, &dst->uri);
	bin_push_int(&packet, dst->flags&LB_DST_STAT_MASK);

	rc = clusterer_api.send_all(&packet, replicated_status_cluster);
	switch (rc) {
	case CLUSTERER_CURR_DISABLED:
		LM_INFO("Current node is disabled in cluster: %d\n", replicated_status_cluster);
		break;
	case CLUSTERER_DEST_DOWN:
		LM_INFO("All destinations in cluster: %d are down or probing\n",
			replicated_status_cluster);
		break;
	case CLUSTERER_SEND_ERR:
		LM_ERR("Error sending in cluster: %d\n", replicated_status_cluster);
		break;
	}

	bin_free_packet(&packet);
}


int replicate_lb_status_update(bin_packet_t *packet, struct lb_data *data)
{
	struct lb_dst *dst;
	unsigned int group, flags;
	str uri;
	bin_pop_int(packet, &group);
	bin_pop_str(packet, &uri);
	bin_pop_int(packet, &flags);

	for( dst=data->dsts; dst; dst=dst->next ) {
		if ( (dst->group == group) &&
		(strncmp(dst->uri.s, uri.s, dst->uri.len) == 0)) {
			if ((dst->flags&LB_DST_STAT_MASK) != flags) {
				/* import the status flags */
				dst->flags = ((~LB_DST_STAT_MASK)&dst->flags)|
					(LB_DST_STAT_MASK&flags);
				/* raise event of status change */
				lb_raise_event(dst);
				return 0;
			}
		}
	}

	return -1;
}

