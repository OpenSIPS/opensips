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

#include "../../mi/item.h"
#include "../../timer.h"
#include "api.h"

#define BIN_VERSION 1
#define BIN_SYNC_VERSION 2
#define DEFAULT_PING_INTERVAL 4
#define DEFAULT_NODE_TIMEOUT 60
#define DEFAULT_PING_TIMEOUT 1000 /* in milliseconds */
#define DEFAULT_SEED_FB_INTERVAL 5
#define SEED_FB_CHECK_INTERVAL 500 /* ms */
#define UPDATE_MAX_PATH_LEN 25
#define SMALL_MSG 300

#define TAG_RAND_LEN 24
#define TAG_FIX_MAXLEN 6	/* "XX-YY-" */

#define MI_CMD_MAX_NR_PARAMS 15

/* node flags */
#define NODE_STATE_ENABLED	(1<<0)
#define NODE_EVENT_DOWN		(1<<1)
#define NODE_EVENT_UP		(1<<2)
#define NODE_IS_SEED		(1<<3)

/* capability flags */
#define CAP_STATE_OK		(1<<0)
#define CAP_SYNC_PENDING	(1<<1)
#define CAP_PKT_BUFFERING	(1<<2)
#define CAP_STATE_ENABLED	(1<<3)

#define CAP_DISABLED 0
#define CAP_ENABLED  1

typedef enum { CLUSTERER_PING, CLUSTERER_PONG,
				CLUSTERER_LS_UPDATE, CLUSTERER_FULL_TOP_UPDATE,
				CLUSTERER_UNKNOWN_ID, CLUSTERER_NODE_DESCRIPTION,
				CLUSTERER_REMOVE_NODE,
				CLUSTERER_GENERIC_MSG,
				CLUSTERER_MI_CMD,
				CLUSTERER_CAP_UPDATE,
				CLUSTERER_SYNC_REQ, CLUSTERER_SYNC, CLUSTERER_SYNC_END,
				CLUSTERER_SHTAG_ACTIVE
} clusterer_msg_type;

typedef enum {
	LS_UP,
	LS_DOWN,
	/* probing states */
	LS_RETRY_SEND_FAIL,
	LS_RESTART_PINGING,
	LS_RESTARTED,
	LS_RETRYING,
	LS_TEMP
} clusterer_link_state;

struct capability_reg {
	str name;
	enum cl_node_match_op sync_cond;
	cl_packet_cb_f packet_cb;
	cl_event_cb_f event_cb;
};

struct buf_bin_pkt {
	str buf;
	int src_id;
	struct buf_bin_pkt *next;
};

struct local_cap {
	struct capability_reg reg;
	struct buf_bin_pkt *pkt_q_front;
	struct buf_bin_pkt *pkt_q_back;
	struct timeval sync_req_time;
	unsigned int flags;
	struct local_cap *next;
};

struct remote_cap {
	str name;
	unsigned int flags;
	struct remote_cap *next;
};

struct packet_rpc_params {
	struct capability_reg *cap;
	int pkt_src_id;
	str pkt_buf;
};

struct node_info;
struct cluster_info;

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

#define TIME_DIFF(_start, _now) \
	((_now).tv_sec*1000000 + (_now).tv_usec \
	- (_start).tv_sec*1000000 - (_start).tv_usec)

extern enum sip_protos clusterer_proto;

extern str cl_internal_cap;
extern str cl_extra_cap;

void seed_fb_check_timer(utime_t ticks, void *param);

void bin_rcv_cl_packets(bin_packet_t *packet, int packet_type,
									struct receive_info *ri, void *att);
void bin_rcv_cl_extra_packets(bin_packet_t *packet, int packet_type,
									struct receive_info *ri, void *att);

int msg_add_trailer(bin_packet_t *packet, int cluster_id, int dst_id);
enum clusterer_send_ret clusterer_send_msg(bin_packet_t *packet,
	int cluster_id, int dst_id, int check_cap);
int send_single_cap_update(struct cluster_info *cluster, struct local_cap *cap,
							int cap_state);
int send_cap_update(struct node_info *dest_node, int require_reply);
void do_actions_node_ev(struct cluster_info *clusters, int *select_cluster,
								int no_clusters);

void remove_node(struct cluster_info *cl, struct node_info *node);

enum clusterer_send_ret send_gen_msg(int cluster_id, int node_id, str *gen_msg,
										str *exchg_tag, int req_like);
enum clusterer_send_ret bcast_gen_msg(int cluster_id, str *gen_msg, str *exchg_tag);
enum clusterer_send_ret send_mi_cmd(int cluster_id, int dst_id, str cmd_name,
									mi_item_t *cmd_params_arr, int no_params);
enum clusterer_send_ret bcast_remove_node(int cluster_id, int target_node);

int cl_set_state(int cluster_id, int node_id, enum cl_node_state state);
int clusterer_check_addr(int cluster_id, str *ip_str,
							enum node_addr_type check_type);
enum clusterer_send_ret cl_send_to(bin_packet_t *, int cluster_id, int node_id);
enum clusterer_send_ret cl_send_all(bin_packet_t *, int cluster_id);
enum clusterer_send_ret
cl_send_all_having(bin_packet_t *packet, int dst_cluster_id,
                   enum cl_node_match_op match_op);
int cl_register_cap(str *cap, cl_packet_cb_f packet_cb, cl_event_cb_f event_cb,
            int cluster_id, int require_sync, enum cl_node_match_op sync_cond);
struct local_cap *dup_caps(struct local_cap *caps);

int preserve_reg_caps(struct cluster_info *new_info);

int mi_cap_set_state(int cluster_id, str *capability, int status);
int get_capability_status(struct cluster_info *cluster, str *capability);

int run_rcv_mi_cmd(str *cmd_name, str *cmd_params_arr, int no_params);

int ipc_dispatch_mod_packet(bin_packet_t *packet, struct capability_reg *cap);

#endif  /* CLUSTERER_H */
