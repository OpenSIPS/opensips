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

#ifndef CLUSTERER_SYNC_H
#define CLUSTERER_SYNC_H

#include "../../bin_interface.h"

#define DEFAULT_SYNC_PACKET_SIZE 32768
#define SYNC_CHUNK_START_MARKER 101010101

extern int sync_packet_size;

struct reply_rpc_params {
	cluster_info_t *cluster;
	str cap_name;
	int node_id;
};

int cl_request_sync(str *capability, int cluster_id);
bin_packet_t *cl_sync_chunk_start(str *capability, int cluster_id, int dst_id,
                                  short data_version);
int cl_sync_chunk_iter(bin_packet_t *packet);

void handle_sync_request(bin_packet_t *packet, cluster_info_t *cluster,
							node_info_t *source);
void handle_sync_packet(bin_packet_t *packet, int packet_type,
								cluster_info_t *cluster, int source_id);

int buffer_bin_pkt(bin_packet_t *packet, struct local_cap *cap, int src_id);
int send_sync_req(str *capability, int cluster_id, int source_id);
int ipc_dispatch_sync_reply(cluster_info_t *cluster, int node_id, str *cap_name);

#endif  /* CLUSTERER_SYNC_H */

