/*
 * Copyright (C) 2017 OpenSIPS Project
 * Copyright (C) 2018-2020 OpenSIPS Solutions
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
char* dr_cluster_prob_mode_s = NULL;
int dr_cluster_prob_mode = DR_CLUSTER_PROB_MODE_ALL;

static str status_repl_cap = str_init("drouting-status-repl");
static struct clusterer_binds c_api;

/* implemented in drouting.c */
void dr_raise_event(struct head_db *p, pgw_t *gw,
		char *reason_s, int reason_len);
void dr_raise_cr_event(struct head_db *p, pcr_t *cr,
		char *reason_s, int reason_len);


extern struct head_db * head_db_start;


int dr_cluster_shtag_is_active(void)
{
	if ( dr_cluster_id<=0 || dr_cluster_shtag.s==NULL ||
	c_api.shtag_get(&dr_cluster_shtag,dr_cluster_id)==SHTAG_STATE_ACTIVE )
		/* no clustering support or sharing tag found active */
		return 1;

	return 0;
}

int dr_cluster_get_my_index(int *size)
{
	if (dr_cluster_id>0)
		return c_api.get_my_index( dr_cluster_id, &status_repl_cap, size);
	*size = 1;
	return 0;

}

static void bin_push_gw_status(bin_packet_t *packet, str *part_name,
	pgw_t *gw)
{
	/* replicate the partition name */
	bin_push_str(packet, part_name);
	/* replicate the ID of the gateway */
	bin_push_str(packet, &gw->id);
	/* replicate the state-related flags of the gateway */
	bin_push_int(packet, gw->flags&DR_DST_STAT_MASK);
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

	bin_push_gw_status(&packet, &p->partition, gw);

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

static void bin_push_carrier_status(bin_packet_t *packet, str *part_name,
	pcr_t *cr)
{
	/* replicate the partition name */
	bin_push_str(packet, part_name);
	/* replicate the ID of the carrier */
	bin_push_str(packet, &cr->id);
	/* replicate the state-related flags of the gateway */
	bin_push_int(packet, cr->flags&DR_CR_FLAG_IS_OFF);
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

	bin_push_carrier_status(&packet, &p->partition, cr);

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


static int gw_status_update(bin_packet_t *packet, int raise_event)
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
	if (part==NULL || part->rdata==NULL)
		return -1;

	lock_start_read(part->ref_lock);

	gw = get_gw_by_id(part->rdata->pgw_tree, &gw_id);
	if (gw && ((gw->flags&DR_DST_STAT_MASK)!=flags)) {
		/* import the status flags */
		gw->flags = ((~DR_DST_STAT_MASK)&gw->flags) | (DR_DST_STAT_MASK&flags);
		/* set the DIRTY flag to force flushing to DB */
		gw->flags |= DR_DST_STAT_DIRT_FLAG;
		if (raise_event)
			/* raise event for the status change */
			dr_raise_event(part, gw, MI_SSTR("replicated info"));
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
	if (part==NULL || part->rdata==NULL)
		return -1;

	lock_start_read(part->ref_lock);

	cr = get_carrier_by_id(part->rdata->carriers_tree, &cr_id);
	if (cr && ((cr->flags&DR_CR_FLAG_IS_OFF)!=flags)) {
		/* import the status flags */
		cr->flags = ((~DR_CR_FLAG_IS_OFF)&cr->flags)|(DR_CR_FLAG_IS_OFF&flags);
		/* set the DIRTY flag to force flushing to DB */
		cr->flags |= DR_CR_FLAG_DIRTY;
		dr_raise_cr_event( part, cr, MI_SSTR("replicated info"));
		lock_stop_read(part->ref_lock);
		return 0;
	}

	lock_stop_read(part->ref_lock);

	return -1;
}


static void dr_recv_sync_packet(bin_packet_t *packet)
{
	int is_gw;

	while (c_api.sync_chunk_iter(packet)) {
		bin_pop_int(packet, &is_gw);
		if (is_gw) {
			if (gw_status_update(packet, 0) < 0)
				LM_WARN("failed to process sync chunk!\n");
		} else
			if (cr_status_update(packet) < 0)
				LM_WARN("failed to process sync chunk!\n");
	}
}

static void receive_dr_binary_packet(bin_packet_t *pkt)
{
	int rc = 0;

	LM_DBG("received a binary packet [%d]!\n", pkt->type);

	switch (pkt->type) {
	case REPL_GW_STATUS_UPDATE:
		ensure_bin_version(pkt, BIN_VERSION);

		rc = gw_status_update(pkt, 1);
		break;
	case REPL_CR_STATUS_UPDATE:
		ensure_bin_version(pkt, BIN_VERSION);

		rc = cr_status_update(pkt);
		break;
	case SYNC_PACKET_TYPE:
		_ensure_bin_version(pkt, BIN_VERSION, "drouting sync packet");

		dr_recv_sync_packet(pkt);
		break;
	default:
		LM_WARN("Invalid drouting binary packet command: %d "
			"(from node: %d in cluster: %d)\n",
			pkt->type, pkt->src_id, dr_cluster_id);
	}

	if (rc != 0)
		LM_ERR("failed to process binary packet!\n");
}

static int dr_recv_sync_request(int node_id)
{
	bin_packet_t *sync_packet;
	struct head_db *cur_part;
	map_iterator_t it;
	void** dest;

	for (cur_part = head_db_start; cur_part; cur_part = cur_part->next) {
		lock_start_read(cur_part->ref_lock);

		if (!cur_part->rdata) {
			lock_stop_read(cur_part->ref_lock);
			continue;
		}

		for (map_first(cur_part->rdata->carriers_tree, &it);
			iterator_is_valid(&it); iterator_next(&it)) {
			dest = iterator_val(&it);
			if (!dest)
				continue;

			sync_packet = c_api.sync_chunk_start(&status_repl_cap,
				dr_cluster_id, node_id, BIN_VERSION);
			if (!sync_packet)
				goto error;

			/* carrier status in this chunk */
			bin_push_int(sync_packet, 0);

			bin_push_carrier_status(sync_packet, &cur_part->partition,
				(pcr_t*)*dest);
		}

		for (map_first(cur_part->rdata->pgw_tree, &it);
			iterator_is_valid(&it); iterator_next(&it)) {
			dest = iterator_val(&it);
			if (!dest)
				continue;

			sync_packet = c_api.sync_chunk_start(&status_repl_cap,
				dr_cluster_id, node_id, BIN_VERSION);
			if (!sync_packet)
				goto error;

			/* gateway status in this chunk */
			bin_push_int(sync_packet, 1);

			bin_push_gw_status(sync_packet, &cur_part->partition,
				(pgw_t*)*dest);
		}

		lock_stop_read(cur_part->ref_lock);
	}

	return 0;

error:
	lock_stop_read(cur_part->ref_lock);
	return -1;
}

void receive_dr_cluster_event(enum clusterer_event ev, int node_id)
{
	if (ev == SYNC_REQ_RCV && dr_recv_sync_request(node_id) < 0)
		LM_ERR("Failed to send sync data to node: %d\n", node_id);
	else if (ev == SYNC_DONE)
		LM_INFO("Synchronized carriers and gateways status from cluster\n");
}

int dr_cluster_sync(void)
{
	if (!dr_cluster_id)
		return 0;

	if (c_api.request_sync(&status_repl_cap, dr_cluster_id, 0) < 0) {
		LM_ERR("Sync request failed\n");
		return -1;
	}

	return 0;
}

static int get_cluster_prob_mode(char *mode)
{
	if ( strcasecmp( mode, "all")==0 )
		return DR_CLUSTER_PROB_MODE_ALL;
	if ( strcasecmp( mode, "by-shtag")==0 )
		return DR_CLUSTER_PROB_MODE_SHTAG;
	if ( strcasecmp( mode, "distributed")==0 )
		return DR_CLUSTER_PROB_MODE_DISTRIBUTED;
	return -1;
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
		receive_dr_binary_packet, receive_dr_cluster_event, dr_cluster_id, 1,
		NODE_CMP_ANY) < 0) {
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

	if (dr_cluster_prob_mode_s) {
		dr_cluster_prob_mode =
			get_cluster_prob_mode(dr_cluster_prob_mode_s);
		if (dr_cluster_prob_mode < 0) {
			LM_ERR("failed to initialized the cluster prob mode <%s>,"
				" unknown value\n", dr_cluster_prob_mode_s);
			return -1;
		}
	}

	if ( (dr_cluster_prob_mode == DR_CLUSTER_PROB_MODE_SHTAG)
	&& (dr_cluster_shtag.len == 0)) {
		LM_ERR("cluster probing mode 'by-shtag' requires the definition"
			" of a sharing tag\n");
		return -1;
	}

	return 0;
}
