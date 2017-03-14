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
#include "dr_replication.h"


/* module parameter to control the replication */
int accept_replicated_status = 1;
int replicated_status_cluster = 0;

str repl_dr_module_name = str_init("drouting");
struct clusterer_binds clusterer_api;

/* implemented in drouting.c */
void dr_raise_event(pgw_t *gw);

extern struct head_db * head_db_start;


void replicate_dr_gw_status_event(struct head_db *p, pgw_t *gw, int cluster)
{
	if(bin_init(&repl_dr_module_name, REPL_GW_STATUS_UPDATE, BIN_VERSION)!=0){
		LM_ERR("failed to replicate this event\n");
		return;
	}

	bin_push_int(clusterer_api.get_my_id());

	/* replicate the partition name */
	bin_push_str(&p->partition);
	/* replicate the ID of the gateway */
	bin_push_str(&gw->id);
	/* replicate the state-related flags of the gateway */
	bin_push_int(gw->flags&DR_DST_STAT_MASK);

	if (clusterer_api.send_to(cluster, PROTO_BIN) < 0) {
		LM_ERR("replication via cluster failed\n");
	}
}


void replicate_dr_carrier_status_event(struct head_db *p, pcr_t *cr,
																int cluster)
{
	if(bin_init(&repl_dr_module_name, REPL_CR_STATUS_UPDATE, BIN_VERSION)!=0){
		LM_ERR("failed to replicate this event\n");
		return;
	}

	bin_push_int(clusterer_api.get_my_id());

	/* replicate the partition name */
	bin_push_str(&p->partition);
	/* replicate the ID of the carrier */
	bin_push_str(&cr->id);
	/* replicate the state-related flags of the gateway */
	bin_push_int(cr->flags&DR_CR_FLAG_IS_OFF);

	if (clusterer_api.send_to(cluster, PROTO_BIN) < 0) {
		LM_ERR("replication via cluster failed\n");
	}
}


static int gw_status_update(void)
{
	struct head_db *part;
	str gw_id;
	str part_name;
	int flags;
	pgw_t *gw;

	bin_pop_str(&part_name);
	bin_pop_str(&gw_id);
	bin_pop_int(&flags);

	part = get_partition( &part_name );
	if (part==NULL)
		return -1;

	lock_start_read(part->ref_lock);

	gw = get_gw_by_id( (*part->rdata)->pgw_tree, &gw_id);
	if (gw && ((gw->flags&DR_DST_STAT_MASK)!=flags)) {
		/* import the status flags */
		gw->flags = ((~DR_DST_STAT_MASK)&gw->flags) | (DR_DST_STAT_MASK&flags);
		/* set the DIRTY flag to force flushing to DB */
		gw->flags |= DR_DST_STAT_DIRT_FLAG;
		/* raise event for the status change */
		dr_raise_event(gw);
		lock_stop_read(part->ref_lock);
		return 0;
	}

	lock_stop_read(part->ref_lock);

	return -1;
}


static int cr_status_update(void)
{
	struct head_db *part;
	str cr_id;
	str part_name;
	int flags;
	pcr_t *cr;

	bin_pop_str(&part_name);
	bin_pop_str(&cr_id);
	bin_pop_int(&flags);

	part = get_partition( &part_name );
	if (part==NULL)
		return -1;

	lock_start_read(part->ref_lock);

	cr = get_carrier_by_id( (*part->rdata)->carriers_tree, &cr_id);
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


void receive_dr_binary_packet(int packet_type, struct receive_info *ri,
																void *att)
{
	int server_id;
	char *ip;
	unsigned short port;

	LM_DBG("received a binary packet [%d]!\n", packet_type);

	if(get_bin_pkg_version() != BIN_VERSION) {
		LM_ERR("incompatible bin protocol version\n");
		return;
	}

	if (bin_pop_int(&server_id) < 0) {
		LM_ERR("failed to obtain server id from binary packet\n");
		return;
	}

	if (!clusterer_api.check(replicated_status_cluster, &ri->src_su,
	server_id, ri->proto)) {
		get_su_info(&ri->src_su.s, ip, port);
		LM_WARN("received bin packet from unknown source: %s:%hu\n", ip, port);
		return;
	}

	if (packet_type == REPL_GW_STATUS_UPDATE) {
		gw_status_update();
	}else
	if (packet_type == REPL_CR_STATUS_UPDATE) {
		cr_status_update();
	} else {
		LM_ERR("invalid drouting binary packet type: %d\n", packet_type);
	}
}
