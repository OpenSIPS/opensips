/*
 * Copyright (C) 2021 OpenSIPS Project
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 *
 */

#include "node_info.h"

void heartbeats_timer(void);
node_info_t *get_next_hop_2(node_info_t *dest);
int get_next_hop(struct node_info *dest);
int flood_message(bin_packet_t *packet, cluster_info_t *cluster,
	int source_id, int rst_req_repl);
void handle_full_top_update(bin_packet_t *packet, node_info_t *source,
									int *ev_actions_required);
void handle_internal_msg_unknown(bin_packet_t *received, cluster_info_t *cl,
	int packet_type, union sockaddr_union *src_su, int proto, int src_node_id);
void handle_ls_update(bin_packet_t *received, node_info_t *src_node,
								int *ev_actions_required);
void handle_unknown_id(node_info_t *src_node);
void handle_ping(bin_packet_t *received, node_info_t *src_node,
	struct timeval rcv_time, int *ev_actions_required);
void handle_pong(bin_packet_t *received, node_info_t *src_node,
	struct timeval rcv_time, int *ev_actions_required);

int set_link_w_neigh(clusterer_link_state new_ls, node_info_t *neigh);
int set_link_w_neigh_adv(int prev_ls, clusterer_link_state new_ls,
						node_info_t *neigh);
int delete_neighbour(node_info_t *from_node, node_info_t *to_delete_n);