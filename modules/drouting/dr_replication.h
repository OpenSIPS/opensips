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

#ifndef _DROUTING_REPLICATION_H_
#define _DROUTING_REPLICATION_H_

#include "../../sr_module.h"
#include "../../bin_interface.h"
#include "../clusterer/api.h"

#define BIN_VERSION 1

#define REPL_GW_STATUS_UPDATE 1
#define REPL_CR_STATUS_UPDATE 2

extern int accept_replicated_status;
extern int replicated_status_cluster;

extern str repl_dr_module_name;
extern struct clusterer_binds clusterer_api;

/* replicate the GW status via BIN */
void replicate_dr_gw_status_event(struct head_db *p, pgw_t *gw, int cluster);

/* replicate the Carrier status via BIN */
void replicate_dr_carrier_status_event(struct head_db *p, pcr_t *cr,
																int cluster);

/* handler for incoming BIN packets */
void receive_dr_binary_packet(enum clusterer_event ev, bin_packet_t *packet, int packet_type,
				struct receive_info *ri, int cluster_id, int src_id, int dest_id);



#endif
