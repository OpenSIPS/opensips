/*
 * Copyright (C) 2015-2017 OpenSIPS Project
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
 *
 *
 * history:
 * ---------
 *	2015-07-07 created (Marius Cristian Eseanu)
 *  2016-07-xx rework (rvlad-patrascu)
 */

#ifndef CLUSTERER_H
#define CLUSTERER_H

#include "api.h"

#define BIN_VERSION 1
#define DEFAULT_PING_INTERVAL 4
#define DEFAULT_NODE_TIMEOUT 60
#define DEFAULT_PING_TIMEOUT 1000 /* in milliseconds */
#define UPDATE_MAX_PATH_LEN 25
#define SMALL_MSG 300

#define TAG_RAND_LEN 24
#define TAG_FIX_MAXLEN 6	/* "XX-YY-" */

#define MI_CMD_MAX_NR_PARAMS 15

/* node flags */
#define NODE_STATE_ENABLED	(1<<0)
#define CALL_CBS_DOWN		(1<<1)
#define CALL_CBS_UP			(1<<2)
#define DB_PROVISIONED		(1<<3)

typedef enum { CLUSTERER_PING, CLUSTERER_PONG,
				CLUSTERER_LS_UPDATE, CLUSTERER_FULL_TOP_UPDATE,
				CLUSTERER_UNKNOWN_ID, CLUSTERER_NODE_DESCRIPTION,
				CLUSTERER_GENERIC_MSG,
				CLUSTERER_MI_CMD
} clusterer_msg_type;

typedef enum {
	LS_UP,
	LS_DOWN,
	/* probing states */
	LS_RETRY_SEND_FAIL,
	LS_RESTART_PINGING,
	LS_RESTARTED,
	LS_RETRYING,
	/* link not established */
	LS_NO_LINK
} clusterer_link_state;

typedef enum {
	JOIN_INIT,
	JOIN_REQ_SENT,
	JOIN_CONFIRM_SENT,
	JOIN_SUCCESS
} clusterer_join_state;

struct mod_registration {
   str mod_name;
   clusterer_cb_f cb;
   int auth_check;
   int accept_clusters_ids[MAX_MOD_REG_CLUSTERS];
   int no_accept_clusters;
   struct mod_registration *next;
};

struct node_info;

/* used for adjacency list */
struct neighbour {
	struct node_info *node;
	struct neighbour *next;
};

/* entry in queue used for shortest path searching */
struct node_search_info {
	struct node_info *node;
	struct node_search_info *parent;
	struct node_search_info *next;      /* linker in queue */
};

extern struct mod_registration *clusterer_reg_modules;
extern enum sip_protos clusterer_proto;

void heartbeats_timer(void);

void bin_rcv_cl_packets(bin_packet_t *packet, int packet_type,
									struct receive_info *ri, void *att);

int get_next_hop(struct node_info *dest);

enum clusterer_send_ret send_gen_msg(int cluster_id, int node_id, str *gen_msg,
										str *exchg_tag, int req_like);
enum clusterer_send_ret bcast_gen_msg(int cluster_id, str *gen_msg, str *exchg_tag);
enum clusterer_send_ret send_mi_cmd(int cluster_id, int dst_id, str cmd_name,
										str *cmd_params, int no_params);

int gen_rcv_evs_init(void);
void gen_rcv_evs_destroy(void);

int cl_set_state(int cluster_id, enum cl_node_state state);
int clusterer_check_addr(int cluster_id, union sockaddr_union *su);
enum clusterer_send_ret cl_send_to(bin_packet_t *, int cluster_id, int node_id);
enum clusterer_send_ret cl_send_all(bin_packet_t *, int cluster_id);
int cl_register_module(char *mod_name,  clusterer_cb_f cb, int auth_check,
								int *accept_clusters_ids, int no_accept_clusters);

struct mi_root *run_rcv_mi_cmd(str *cmd_name, str *cmd_params, int nr_params);

#endif  /* CLUSTERER_H */
