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

#include "../../ip_addr.h"
#include "../../ut.h"
#include "prefix_tree.h"
#include "dr_partitions.h"
#include "dr_clustering.h"

#define BIN_VERSION 1

#define REPL_GW_STATUS_UPDATE 1
#define REPL_CR_STATUS_UPDATE 2

/* the cluster ID  */
int dr_cluster_id = 0;

str dr_cluster_shtag = {NULL,0};

static str status_repl_cap = str_init("drouting-status-repl");
static struct clusterer_binds c_api;

/* implemented in drouting.c */
void dr_raise_event(struct head_db *p, pgw_t *gw);

extern struct head_db * head_db_start;


int dr_cluster_shtag_is_active(void)
{
	if ( dr_cluster_id<=0 || dr_cluster_shtag.s==NULL ||
	c_api.shtag_get(&dr_cluster_shtag,dr_cluster_id)==SHTAG_STATE_ACTIVE )
		/* no clustering support or sharing tag found active */
		return 1;

	return 0;
}

void replicate_dr_gw_status_event(struct head_db *p, pgw_t *gw)
{
	bin_packet_t packet;
	int rc;

	if ( dr_cluster_id<=0 || (dr_cluster_shtag.s &&
	c_api.shtag_get(&dr_cluster_shtag,dr_cluster_id)!=SHTAG_STATE_ACTIVE) )
		/* no clustering support or sharing tag found on not-active */
		return;

	if (bin_init(&packet, &status_repl_cap, REPL_GW_STATUS_UPDATE,
	BIN_VERSION, 0)!=0){
		LM_ERR("failed to replicate this event\n");
		return;
	}

	/* replicate the partition name */
	bin_push_str(&packet, &p->partition);
	/* replicate the ID of the gateway */
	bin_push_str(&packet, &gw->id);
	/* replicate the state-related flags of the gateway */
	bin_push_int(&packet, gw->flags&DR_DST_STAT_MASK);

	rc = c_api.send_all(&packet, dr_cluster_id);
	switch (rc) {
	case CLUSTERER_CURR_DISABLED:
		LM_INFO("Current node is disabled in cluster: %d\n", dr_cluster_id);
		break;
	case CLUSTERER_DEST_DOWN:
		LM_INFO("All destinations in cluster: %d are down or probing\n",
			dr_cluster_id);
		break;
	case CLUSTERER_SEND_ERR:
		LM_ERR("Error sending in cluster: %d\n", dr_cluster_id);
		break;
	}

	bin_free_packet(&packet);
}


void replicate_dr_carrier_status_event(struct head_db *p, pcr_t *cr)
{
	bin_packet_t packet;
	int rc;

	if ( dr_cluster_id<=0 || (dr_cluster_shtag.s &&
	c_api.shtag_get(&dr_cluster_shtag,dr_cluster_id)!=SHTAG_STATE_ACTIVE) )
		/* no clustering support or sharing tag found on not-active */
		return;

	if (bin_init(&packet, &status_repl_cap, REPL_CR_STATUS_UPDATE,
	BIN_VERSION, 0)!=0) {
		LM_ERR("failed to replicate this event\n");
		return;
	}

	/* replicate the partition name */
	bin_push_str(&packet, &p->partition);
	/* replicate the ID of the carrier */
	bin_push_str(&packet, &cr->id);
	/* replicate the state-related flags of the gateway */
	bin_push_int(&packet, cr->flags&DR_CR_FLAG_IS_OFF);

	rc = c_api.send_all(&packet, dr_cluster_id);
	switch (rc) {
	case CLUSTERER_CURR_DISABLED:
		LM_INFO("Current node is disabled in cluster: %d\n", dr_cluster_id);
		break;
	case CLUSTERER_DEST_DOWN:
		LM_INFO("All destinations in cluster: %d are down or probing\n",
			dr_cluster_id);
		break;
	case CLUSTERER_SEND_ERR:
		LM_ERR("Error sending in cluster: %d\n", dr_cluster_id);
		break;
	}

	bin_free_packet(&packet);
}


static int gw_status_update(bin_packet_t *packet)
{
	struct head_db *part;
	str gw_id;
	str part_name;
	int flags;
	pgw_t *gw;

	bin_pop_str(packet, &part_name);
	bin_pop_str(packet, &gw_id);
	bin_pop_int(packet, &flags);

	part = get_partition( &part_name );
	if (part==NULL)
		return -1;

	lock_start_read(part->ref_lock);

	gw = get_gw_by_id(part->rdata->pgw_tree, &gw_id);
	if (gw && ((gw->flags&DR_DST_STAT_MASK)!=flags)) {
		/* import the status flags */
		gw->flags = ((~DR_DST_STAT_MASK)&gw->flags) | (DR_DST_STAT_MASK&flags);
		/* set the DIRTY flag to force flushing to DB */
		gw->flags |= DR_DST_STAT_DIRT_FLAG;
		/* raise event for the status change */
		dr_raise_event(part, gw);
		lock_stop_read(part->ref_lock);
		return 0;
	}

	lock_stop_read(part->ref_lock);

	return -1;
}


static int cr_status_update(bin_packet_t *packet)
{
	struct head_db *part;
	str cr_id;
	str part_name;
	int flags;
	pcr_t *cr;

	bin_pop_str(packet, &part_name);
	bin_pop_str(packet, &cr_id);
	bin_pop_int(packet, &flags);

	part = get_partition( &part_name );
	if (part==NULL)
		return -1;

	lock_start_read(part->ref_lock);

	cr = get_carrier_by_id(part->rdata->carriers_tree, &cr_id);
	if (cr && ((cr->flags&DR_CR_FLAG_IS_OFF)!=flags)) {
		/* import the status flags */
		cr->flags = ((~DR_CR_FLAG_IS_OFF)&cr->flags)|(DR_CR_FLAG_IS_OFF&flags);
		/* set the DIRTY flag to force flushing to DB */
		cr->flags |= DR_CR_FLAG_DIRTY;
		lock_stop_read(part->ref_lock);
		return 0;
	}

	lock_stop_read(part->ref_lock);

	return -1;
}


static void receive_dr_binary_packet(bin_packet_t *packet)
{
	LM_DBG("received a binary packet [%d]!\n", packet->type);

	if(get_bin_pkg_version(packet) != BIN_VERSION) {
		LM_ERR("incompatible bin protocol version\n");
		return;
	}

	switch (packet->type) {
	case REPL_GW_STATUS_UPDATE:
		gw_status_update(packet);
		break;
	case REPL_CR_STATUS_UPDATE:
		cr_status_update(packet);
		break;
	default:
		LM_WARN("Invalid drouting binary packet command: %d "
			"(from node: %d in cluster: %d)\n",
			packet->type, packet->src_id, dr_cluster_id);
	}
}


int dr_init_cluster(void)
{
	if (load_clusterer_api(&c_api)!=0) {
		LM_ERR("failed to find clusterer API - is clusterer "
			"module loaded?\n");
		return -1;
	}

	/* register handler for processing drouting packets 
	 * to the clusterer module */
	if (c_api.register_capability( &status_repl_cap,
	receive_dr_binary_packet, NULL, dr_cluster_id, 0, NODE_CMP_ANY) < 0) {
		LM_ERR("cannot register binary packet callback to "
			"clusterer module!\n");
		return -1;
	}

	/* "register" the sharing tag */
	if (dr_cluster_shtag.s) {
		dr_cluster_shtag.len = strlen(dr_cluster_shtag.s);
		if (c_api.shtag_get( &dr_cluster_shtag, dr_cluster_id)<0) {
			LM_ERR("failed to initialized the sharing tag <%.*s>\n",
				dr_cluster_shtag.len, dr_cluster_shtag.s);
			return -1;
		}
	} else {
		dr_cluster_shtag.len = 0;
	}

	return 0;
}


