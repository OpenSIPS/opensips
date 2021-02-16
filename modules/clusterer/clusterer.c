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
 *  2015-07-07  created  by Marius Cristian Eseanu
 *	2016-07-xx 	rework (rvlad-patrascu)
 */

#include "../../str.h"
#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../locking.h"
#include "../../rw_locking.h"
#include "../../bin_interface.h"
#include "../../timer.h"
#include "../../forward.h"
#include "../../ipc.h"

#include "api.h"
#include "node_info.h"
#include "clusterer.h"
#include "sync.h"
#include "sharing_tags.h"

struct clusterer_binds clusterer_api;

enum sip_protos clusterer_proto = PROTO_BIN;

str cl_internal_cap = str_init("clusterer-internal");
str cl_extra_cap = str_init("clusterer-extra");

extern int ping_interval;
extern int node_timeout;
extern int ping_timeout;
extern int seed_fb_interval;

static event_id_t ei_req_rcv_id = EVI_ERROR;
static event_id_t ei_rpl_rcv_id = EVI_ERROR;
static event_id_t ei_node_state_id = EVI_ERROR;
static str ei_req_rcv_name = str_init("E_CLUSTERER_REQ_RECEIVED");
static str ei_rpl_rcv_name = str_init("E_CLUSTERER_RPL_RECEIVED");
static str ei_node_state_name = str_init("E_CLUSTERER_NODE_STATE_CHANGED");

static evi_params_p ei_event_params;
static evi_param_p ei_clid_p, ei_srcid_p, ei_msg_p, ei_tag_p;
static str ei_clid_pname = str_init("cluster_id");
static str ei_srcid_pname = str_init("src_id");
static str ei_msg_pname = str_init("msg");
static str ei_tag_pname = str_init("tag");

static evi_params_p ei_node_event_params;
static evi_param_p ei_clusterid_p, ei_nodeid_p, ei_newstate_p;
static str ei_clusterid_pname = str_init("cluster_id");
static str ei_nodeid_pname = str_init("node_id");
static str ei_newstate_pname = str_init("new_state");


static int set_link(clusterer_link_state new_ls, node_info_t *node_a,
						node_info_t *node_b);
static int set_link_w_neigh(clusterer_link_state new_ls, node_info_t *neigh);
static int set_link_w_neigh_adv(int prev_ls, clusterer_link_state new_ls,
							node_info_t *neigh);
static int set_link_w_neigh_up(node_info_t *neigh, int nr_nodes, int *node_list);
static void do_actions_node_ev(cluster_info_t *clusters, int *select_cluster,
								int no_clusters);
static int send_cap_update(node_info_t *dest_node, int require_reply);

#define PING_REPLY_INTERVAL(_node) \
	((_node)->last_pong.tv_sec*1000000 + (_node)->last_pong.tv_usec \
	- (_node)->last_ping.tv_sec*1000000 - (_node)->last_ping.tv_usec)

#define TIME_DIFF(_start, _now) \
	((_now).tv_sec*1000000 + (_now).tv_usec \
	- (_start).tv_sec*1000000 - (_start).tv_usec)

static int send_ping(node_info_t *node, int req_node_list)
{
	struct timeval now;
	str send_buffer;
	bin_packet_t packet;
	int rc;

	gettimeofday(&now, NULL);

	if (bin_init(&packet, &cl_internal_cap, CLUSTERER_PING, BIN_VERSION,
		SMALL_MSG) < 0) {
		LM_ERR("Failed to init bin send buffer\n");
		return -1;
	}
	bin_push_int(&packet, node->cluster->cluster_id);
	bin_push_int(&packet, current_id);
	bin_push_int(&packet, req_node_list);	/* request list of known nodes ? */
	bin_get_buffer(&packet, &send_buffer);

	#ifndef CLUSTERER_EXTRA_BIN_DBG
	set_proc_log_level(L_INFO);
	#endif

	rc = msg_send(node->cluster->send_sock, clusterer_proto, &node->addr, 0,
		send_buffer.s, send_buffer.len, 0);

	#ifndef CLUSTERER_EXTRA_BIN_DBG
	reset_proc_log_level();
	#endif

	lock_get(node->lock);
	node->last_ping_state = rc;
	node->last_ping = now;
	lock_release(node->lock);

	bin_free_packet(&packet);

	return rc;
}

/* actions to be done for the transitions of the simple state machine' used for
 * establishing the link states with the other nodes */

static void do_action_trans_0(node_info_t *node, int *link_state_to_set)
{
	if (send_ping(node, 1) < 0) {
		LM_ERR("Failed to send ping to node [%d]\n", node->node_id);
		if (node->no_ping_retries == 0)
			*link_state_to_set = LS_DOWN;
		else {
			node->curr_no_retries = node->no_ping_retries;
			*link_state_to_set = LS_RETRY_SEND_FAIL;
		}
	} else {
		*link_state_to_set = LS_RESTARTED;
		LM_DBG("Sent ping to node [%d]\n", node->node_id);
	}
}

static void do_action_trans_1(node_info_t *node, int *link_state_to_set)
{
	node->curr_no_retries--;

	if (send_ping(node, 1) < 0) {
		LM_ERR("Failed to send ping retry to node [%d]\n", node->node_id);
		if (node->curr_no_retries == 0) {
			*link_state_to_set = LS_DOWN;
			LM_INFO("Maximum number of retries reached, node [%d] is down\n",
				node->node_id);
		}
	} else {
		LM_DBG("Sent ping to node [%d]\n", node->node_id);
		*link_state_to_set = LS_RETRYING;
	}
}

static void do_action_trans_2(node_info_t *node, int *link_state_to_set)
{
	if (node->no_ping_retries == 0) {
		*link_state_to_set = LS_DOWN;
		LM_INFO("Ping reply not received, node [%d] is down\n", node->node_id);
	} else {
		LM_INFO("Ping reply not received, node [%d] is possibly down, retrying\n",
			node->node_id);

		if (send_ping(node, 1) < 0) {
			LM_ERR("Failed to send ping to node [%d]\n", node->node_id);
			node->curr_no_retries = node->no_ping_retries;
			*link_state_to_set = LS_RETRY_SEND_FAIL;
		} else {
			LM_DBG("Sent ping retry to node [%d]\n", node->node_id);
			*link_state_to_set = LS_RETRYING;
			node->curr_no_retries = --node->no_ping_retries;
		}
	}
}

static void do_action_trans_3(node_info_t *node, int *link_state_to_set)
{
	if (node->curr_no_retries > 0) {
		if (send_ping(node, 1) < 0) {
			LM_ERR("Failed to send ping retry to node [%d]\n",
				node->node_id);
			*link_state_to_set = LS_RETRY_SEND_FAIL;
		} else {
			LM_DBG("Sent ping retry to node [%d]\n", node->node_id);
			node->curr_no_retries--;
		}
	} else {
		*link_state_to_set = LS_DOWN;
		LM_INFO("Ping reply not received, node [%d] is down\n", node->node_id);
	}
}

static void do_action_trans_4(node_info_t *node, int *link_state_to_set)
{
	LM_INFO("Node timeout passed, restart pinging node [%d]\n",
		node->node_id);

	if (send_ping(node, 1) < 0) {
		LM_ERR("Failed to send ping to node [%d]\n", node->node_id);
		if (node->no_ping_retries != 0) {
			node->curr_no_retries = node->no_ping_retries;
			*link_state_to_set = LS_RETRY_SEND_FAIL;
		}
	} else {
		*link_state_to_set = LS_RESTARTED;
		LM_DBG("Sent ping to node [%d]\n", node->node_id);
	}
}

static void do_action_trans_5(node_info_t *node, int *link_state_to_set,
								int *ev_actions_required, int no_clusters)
{
	if (send_ping(node, 0) < 0) {
		LM_ERR("Failed to send ping to node [%d]\n", node->node_id);
		if (node->no_ping_retries == 0)
			*link_state_to_set = LS_DOWN;
		else {
			node->curr_no_retries = node->no_ping_retries;
			*link_state_to_set = LS_RETRY_SEND_FAIL;
		}
		ev_actions_required[no_clusters] = 1;
	} else
		LM_DBG("Sent ping to node [%d]\n", node->node_id);
}

void heartbeats_timer(void)
{
	struct timeval now;
	utime_t last_ping_int, ping_reply_int;
	cluster_info_t *clusters_it;
	node_info_t *node;
	int ev_actions_required[MAX_NO_CLUSTERS] = {0};
	int no_clusters = 0;
	int prev_ls, new_ls;

	lock_start_read(cl_list_lock);

	for (clusters_it = *cluster_list; clusters_it; clusters_it = clusters_it->next) {
		lock_get(clusters_it->current_node->lock);
		if (!(clusters_it->current_node->flags & NODE_STATE_ENABLED)) {
			lock_release(clusters_it->current_node->lock);
			continue;
		}
		lock_release(clusters_it->current_node->lock);

		for(node = clusters_it->node_list; node; node = node->next) {
			lock_get(node->lock);

			gettimeofday(&now, NULL);
			ping_reply_int = PING_REPLY_INTERVAL(node);
			last_ping_int = TIME_DIFF(node->last_ping, now);

			prev_ls = -1;
			new_ls = -1;

			if (node->link_state == LS_RESTART_PINGING) {
				prev_ls = node->link_state;
				lock_release(node->lock);

				/* restart pinging sequence */
				do_action_trans_0(node, &new_ls);
			} else if (node->link_state == LS_RETRY_SEND_FAIL &&
				last_ping_int >= (utime_t)ping_timeout*1000) {
				prev_ls = node->link_state;
				lock_release(node->lock);

				/* failed to send previous ping, retry */
				do_action_trans_1(node, &new_ls);
			} else if ((node->link_state == LS_UP || node->link_state == LS_RESTARTED) &&
				(ping_reply_int >= (utime_t)ping_timeout*1000 || ping_reply_int <= 0) &&
				last_ping_int >= (utime_t)ping_timeout*1000) {
				prev_ls = -2;
				lock_release(node->lock);

				/* send first ping retry */
				do_action_trans_2(node, &new_ls);
				ev_actions_required[no_clusters] = 1;
			} else if (node->link_state == LS_RETRYING &&
				(ping_reply_int >= (utime_t)ping_timeout*1000 || ping_reply_int <= 0) &&
				last_ping_int >= (utime_t)ping_timeout*1000) {
				prev_ls = node->link_state;
				lock_release(node->lock);

				/* previous ping retry not replied, continue to retry */
				do_action_trans_3(node, &new_ls);
			} else if (node->link_state == LS_DOWN &&
				last_ping_int >= (utime_t)node_timeout*1000000) {
				prev_ls = node->link_state;
				lock_release(node->lock);

				/* ping a failed node after node_timeout since last ping */
				do_action_trans_4(node, &new_ls);
			} else if (node->link_state == LS_UP &&
				last_ping_int >= (utime_t)ping_interval*1000000) {
				prev_ls = node->link_state;
				lock_release(node->lock);

				/* send regular ping */
				do_action_trans_5(node, &new_ls, ev_actions_required, no_clusters);
			} else
				lock_release(node->lock);

			if (new_ls >= 0)
				set_link_w_neigh_adv(prev_ls, new_ls, node);
		}

		no_clusters++;
	}

	do_actions_node_ev(*cluster_list, ev_actions_required, no_clusters);

	lock_stop_read(cl_list_lock);
}

void seed_fb_check_timer(utime_t ticks, void *param)
{
	cluster_info_t *cl;
	struct local_cap *cap;
	struct timeval now;

	gettimeofday(&now, NULL);

	lock_start_read(cl_list_lock);

	for (cl = *cluster_list; cl; cl = cl->next) {
		lock_get(cl->current_node->lock);
		if (!(cl->current_node->flags & NODE_STATE_ENABLED)) {
			lock_release(cl->current_node->lock);
			continue;
		}
		lock_release(cl->current_node->lock);

		for (cap = cl->capabilities; cap; cap = cap->next) {
			lock_get(cl->lock);
			if (!(cap->flags & CAP_STATE_OK) &&
				(cl->current_node->flags & NODE_IS_SEED) &&
				(TIME_DIFF(cap->sync_req_time, now) >= seed_fb_interval*1000000)) {
				cap->flags = CAP_STATE_OK;
				LM_INFO("No donor found, falling back to synced state\n");
				/* send update about the state of this capability */
				send_single_cap_update(cl, cap, 1);
			}

			lock_release(cl->lock);
		}
	}

	lock_stop_read(cl_list_lock);
}

int cl_set_state(int cluster_id, enum cl_node_state state)
{
	cluster_info_t *cluster = NULL;
	node_info_t *node;
	int ev_actions_required = 1;
	int new_link_states = 0;

	lock_start_read(cl_list_lock);

	cluster = get_cluster_by_id(cluster_id);
	if (!cluster) {
		lock_stop_read(cl_list_lock);
		LM_ERR("Cluster id [%d] not found\n", cluster_id);
		return -1;
	}

	lock_get(cluster->current_node->lock);

	if (state == STATE_DISABLED && cluster->current_node->flags & NODE_STATE_ENABLED)
		new_link_states = LS_DOWN;
	else if (state == STATE_ENABLED && !(cluster->current_node->flags & NODE_STATE_ENABLED))
		new_link_states = LS_RESTART_PINGING;

	if (state == STATE_DISABLED)
		cluster->current_node->flags &= ~NODE_STATE_ENABLED;
	else
		cluster->current_node->flags |= NODE_STATE_ENABLED;

	lock_release(cluster->current_node->lock);

	if (new_link_states == LS_DOWN) {
		for (node = cluster->node_list; node; node = node->next)
			set_link_w_neigh(LS_DOWN, node);

		do_actions_node_ev(cluster, &ev_actions_required, 1);
	} else if (new_link_states == LS_RESTART_PINGING) {
		for (node = cluster->node_list; node; node = node->next)
			set_link_w_neigh(LS_RESTART_PINGING, node);
	}

	lock_stop_read(cl_list_lock);

	LM_INFO("Set state: %s for local node in cluster: %d\n",
			state ? "enabled" : "disabled", cluster_id);

	if (db_mode && update_db_state(state) < 0)
		LM_ERR("Failed to update state in clusterer DB for cluster [%d]\n", cluster->cluster_id);

	return 0;
}

static void prio_enqueue(struct node_search_info **queue_front, struct neighbour *neigh)
{
	struct node_search_info *q_it;

	if (!(*queue_front)) {
		*queue_front = neigh->node->sp_info;
		return;
	}

	/* check first entry */
	if (((*queue_front)->node->priority == neigh->node->priority &&
		(*queue_front)->node->node_id > neigh->node->node_id) ||
		(*queue_front)->node->priority > neigh->node->priority) {
		neigh->node->sp_info->next = *queue_front;
		*queue_front = neigh->node->sp_info;
		return;
	}

	for (q_it = *queue_front; q_it->next; q_it = q_it->next)
		if ((q_it->next->node->priority == neigh->node->priority &&
			q_it->next->node->node_id > neigh->node->node_id) ||
			q_it->next->node->priority > neigh->node->priority) {
			neigh->node->sp_info->next = q_it->next;
			q_it->next = neigh->node->sp_info;
			return;
		}

	q_it->next = neigh->node->sp_info;
}

/* Compute the next hop in the path to the given destination node, according to the
 * local 'routing table', looking for paths of at least 2 links.
 * Returns NULL if no other path(node is down) or error.
 */
static node_info_t *get_next_hop_2(node_info_t *dest)
{
	node_info_t *n, *next_hop;
	struct node_search_info *queue_front;
    struct node_search_info *root, *curr;
    struct neighbour *neigh;

    lock_get(dest->cluster->lock);

    /* run BFS */
	if (dest->cluster->top_version != dest->sp_top_version) {
		lock_get(dest->lock);
		dest->next_hop = NULL;
		lock_release(dest->lock);

		/* init nodes search info */
		for (n = dest->cluster->node_list; n; n = n->next) {
			n->sp_info->parent = NULL;
			n->sp_info->next = NULL;
		}
		/* init root search info */
		root = dest->cluster->current_node->sp_info;
		root->parent = NULL;
		root->next = NULL;

		/* enqueue root */
		queue_front = root;

		while (queue_front) {	/* while queue not empty */
			/* dequeue */
			curr = queue_front;
			queue_front = queue_front->next;

			/* found, get back to root */
			if (curr->node->node_id == dest->node_id) {
				if (!curr->parent || !curr->parent->parent) {
					lock_release(dest->cluster->lock);
					return NULL;
				}

				while (curr->parent->parent)
					curr = curr->parent;
				if (curr->parent != root) {
					lock_release(dest->cluster->lock);
					return NULL;
				}

				lock_get(dest->lock);
				dest->next_hop = curr->node;
				next_hop = dest->next_hop;
				lock_release(dest->lock);

				lock_release(dest->cluster->lock);

				return next_hop;
			}

			lock_get(curr->node->lock);
			/* for each node reachable from current */
			for (neigh = curr->node->neighbour_list; neigh; neigh = neigh->next)
				if (!neigh->node->sp_info->parent) {
					/* set parent */
					neigh->node->sp_info->parent = curr;
					/* enqueue node*/
					prio_enqueue(&queue_front, neigh);
				}
			lock_release(curr->node->lock);
		}

		dest->sp_top_version = dest->cluster->top_version;
	}

	lock_get(dest->lock);
	next_hop = dest->next_hop;
	lock_release(dest->lock);

	lock_release(dest->cluster->lock);

	return next_hop;
}

/* @return:
 *  	> 0: next hop id
 * 		0  : error or no other path(node is down)
 */
int get_next_hop(node_info_t *dest)
{
	node_info_t *nhop;

	lock_get(dest->lock);

	if (dest->link_state == LS_UP) {
		dest->next_hop = dest;

		lock_release(dest->lock);

		return dest->node_id;
	} else {
		lock_release(dest->lock);

		nhop = get_next_hop_2(dest);
		return nhop ? nhop->node_id : 0;
	}
}

/* @return:
 *  0 : success, message sent
 * -1 : error, unable to send
 * -2 : dest down or probing
 */
static int msg_send_retry(bin_packet_t *packet, node_info_t *dest,
							int change_dest, int *ev_actions_required)
{
	int retr_send = 0;
	node_info_t *chosen_dest = dest;
	str send_buffer;

	do {
		lock_get(chosen_dest->lock);

		if (chosen_dest->link_state != LS_UP) {
			lock_release(chosen_dest->lock);

			chosen_dest = get_next_hop_2(dest);
			if (!chosen_dest) {
				if (retr_send)
					return -1;
				else
					return -2;
			}
		} else
			lock_release(chosen_dest->lock);

		/* change destination node id */
		if (change_dest || chosen_dest != dest) {
			bin_remove_int_buffer_end(packet, 1);
			bin_push_int(packet, dest->node_id);
		}
		bin_get_buffer(packet, &send_buffer);

		if (msg_send(chosen_dest->cluster->send_sock, clusterer_proto,
			&chosen_dest->addr, 0, send_buffer.s, send_buffer.len, 0) < 0) {
			LM_ERR("msg_send() to node [%d] failed\n", chosen_dest->node_id);
			retr_send = 1;

			/* this node was supposed to be up, retry pinging */
			set_link_w_neigh_adv(-1, LS_RESTART_PINGING, chosen_dest);

			*ev_actions_required = 1;
		} else {
			LM_DBG("sent bin packet to node [%d]\n", chosen_dest->node_id);
			retr_send = 0;
		}
	} while (retr_send);

	return 0;
}

enum clusterer_send_ret clusterer_send_msg(bin_packet_t *packet,
											int cluster_id, int dst_node_id)
{
	node_info_t *node;
	int rc;
	cluster_info_t *cl;
	int ev_actions_required = 0;

	if (!cl_list_lock) {
		LM_ERR("cluster shutdown - cannot send new messages!\n");
		return CLUSTERER_CURR_DISABLED;
	}
	lock_start_read(cl_list_lock);

	cl = get_cluster_by_id(cluster_id);
	if (!cl) {
		LM_ERR("Unknown cluster id [%d]\n", cluster_id);
		lock_stop_read(cl_list_lock);
		return CLUSTERER_SEND_ERR;
	}

	lock_get(cl->current_node->lock);
	if (!(cl->current_node->flags & NODE_STATE_ENABLED)) {
		lock_release(cl->current_node->lock);
		lock_stop_read(cl_list_lock);
		return CLUSTERER_CURR_DISABLED;
	}
	lock_release(cl->current_node->lock);

	node = get_node_by_id(cl, dst_node_id);
	if (!node) {
		LM_ERR("Node id [%d] not found in cluster\n", dst_node_id);
		lock_stop_read(cl_list_lock);
		return CLUSTERER_SEND_ERR;
	}

	rc = msg_send_retry(packet, node, 0, &ev_actions_required);

	bin_remove_int_buffer_end(packet, 3);

	if (ev_actions_required)
		do_actions_node_ev(cl, &ev_actions_required, 1);

	lock_stop_read(cl_list_lock);

	switch (rc) {
	case  0:
		return CLUSTERER_SEND_SUCCESS;
	case -1:
		return CLUSTERER_SEND_ERR;
	case -2:
		return CLUSTERER_DEST_DOWN;
	}

	return CLUSTERER_SEND_ERR;
}

static enum clusterer_send_ret
clusterer_bcast_msg(bin_packet_t *packet, int dst_cid,
                    enum cl_node_match_op match_op)
{
	node_info_t *node;
	int rc, sent = 0, down = 1, matched_once = 0;
	cluster_info_t *dst_cl;
	int ev_actions_required = 0;

	if (!cl_list_lock) {
		LM_ERR("cluster shutdown - cannot send new messages!\n");
		return CLUSTERER_CURR_DISABLED;
	}
	lock_start_read(cl_list_lock);

	dst_cl = get_cluster_by_id(dst_cid);
	if (!dst_cl) {
		LM_ERR("Unknown cluster, id [%d]\n", dst_cid);
		lock_stop_read(cl_list_lock);
		return CLUSTERER_SEND_ERR;
	}

	lock_get(dst_cl->current_node->lock);
	if (!(dst_cl->current_node->flags & NODE_STATE_ENABLED)) {
		lock_release(dst_cl->current_node->lock);
		lock_stop_read(cl_list_lock);
		return CLUSTERER_CURR_DISABLED;
	}
	lock_release(dst_cl->current_node->lock);

	for (node = dst_cl->node_list; node; node = node->next) {
		if (!match_node(dst_cl->current_node, node, match_op))
			continue;

		matched_once = 1;

		rc = msg_send_retry(packet, node, 1, &ev_actions_required);
		if (rc != -2)	/* at least one node is up */
			down = 0;
		if (rc == 0)	/* at least one message is sent successfully */
			sent = 1;
	}

	bin_remove_int_buffer_end(packet, 3);

	if (ev_actions_required)
		do_actions_node_ev(dst_cl, &ev_actions_required, 1);

	lock_stop_read(cl_list_lock);

	if (!matched_once)
		return CLUSTERER_SEND_SUCCESS;

	if (down)
		return CLUSTERER_DEST_DOWN;
	if (sent)
		return CLUSTERER_SEND_SUCCESS;
	else
		return CLUSTERER_SEND_ERR;
}

int msg_add_trailer(bin_packet_t *packet, int cluster_id, int dst_id)
{
	if (bin_push_int(packet, cluster_id) < 0)
		return -1;
	if (bin_push_int(packet, current_id) < 0)
		return -1;
	if (bin_push_int(packet, dst_id) < 0)
		return -1;

	return 0;
}

static int prep_gen_msg(bin_packet_t *packet, int cluster_id, int dst_id,
							str *gen_msg, str *exchg_tag, int req_like)
{
	/* build packet */
	if (bin_init(packet, &cl_extra_cap, CLUSTERER_GENERIC_MSG, BIN_VERSION, 0) < 0) {
		LM_ERR("Failed to init bin send buffer\n");
		return -1;
	}

	/* mark this message as request-like if it is the case */
	if (bin_push_int(packet, req_like) < 0)
		return -1;
	/* include an 'exchange tag' in order to possbily correlate the messages
	 * sent with replies to be received (which should contain the same tag) */
	if (bin_push_str(packet, exchg_tag) < 0)
		return -1;
	if (bin_push_str(packet, gen_msg) < 0)
		return -1;
	/* add the trailer as for an usual module message */
	if (msg_add_trailer(packet, cluster_id, dst_id) < 0)
		return -1;

	return 0;
}

enum clusterer_send_ret cl_send_to(bin_packet_t *packet, int cluster_id, int node_id)
{
	if (msg_add_trailer(packet, cluster_id, node_id) < 0) {
		LM_ERR("Failed to add trailer to module's message\n");
		return CLUSTERER_SEND_ERR;
	}

	return clusterer_send_msg(packet, cluster_id, node_id);
}

enum clusterer_send_ret cl_send_all(bin_packet_t *packet, int cluster_id)
{
	if (msg_add_trailer(packet, cluster_id, -1 /* dummy value */) < 0) {
		LM_ERR("Failed to add trailer to module's message\n");
		return CLUSTERER_SEND_ERR;
	}

	return clusterer_bcast_msg(packet, cluster_id, NODE_CMP_ANY);
}

enum clusterer_send_ret
cl_send_all_having(bin_packet_t *packet, int dst_cluster_id,
                   enum cl_node_match_op match_op)
{
	if (msg_add_trailer(packet, dst_cluster_id, -1 /* dummy value */) < 0) {
		LM_ERR("Failed to add trailer to module's message\n");
		return CLUSTERER_SEND_ERR;
	}

	return clusterer_bcast_msg(packet, dst_cluster_id, match_op);
}

enum clusterer_send_ret send_gen_msg(int cluster_id, int dst_id, str *gen_msg,
										str *exchg_tag, int req_like)
{
	bin_packet_t packet;
	int rc;

	if (prep_gen_msg(&packet, cluster_id, dst_id, gen_msg, exchg_tag, req_like) < 0) {
		LM_ERR("Failed to build generic clusterer message\n");
		return CLUSTERER_SEND_ERR;
	}

	rc = clusterer_send_msg(&packet, cluster_id, dst_id);

	bin_free_packet(&packet);

	return rc;
}

enum clusterer_send_ret bcast_gen_msg(int cluster_id, str *gen_msg, str *exchg_tag)
{
	bin_packet_t packet;
	int rc;

	if (prep_gen_msg(&packet, cluster_id, -1 /* dummy value */, gen_msg,
			exchg_tag, 1) < 0) {
		LM_ERR("Failed to build generic clusterer message\n");
		return CLUSTERER_SEND_ERR;
	}

	rc = clusterer_bcast_msg(&packet, cluster_id, NODE_CMP_ANY);

	bin_free_packet(&packet);

	return rc;
}

enum clusterer_send_ret send_mi_cmd(int cluster_id, int dst_id, str cmd_name,
								mi_item_t *cmd_params_arr, int no_params)
{
	bin_packet_t packet;
	int i, rc;
	str val;

	if (bin_init(&packet, &cl_extra_cap, CLUSTERER_MI_CMD, BIN_VERSION, 0) < 0) {
		LM_ERR("Failed to init bin send buffer\n");
		return CLUSTERER_SEND_ERR;
	}

	if (bin_push_str(&packet, &cmd_name) < 0)
		return CLUSTERER_SEND_ERR;
	if (bin_push_int(&packet, no_params) < 0)
		return CLUSTERER_SEND_ERR;
	for (i = 0; i < no_params; i++) {
		if (get_mi_arr_param_string(cmd_params_arr, i, &val.s, &val.len) < 0)
			return CLUSTERER_SEND_ERR;

		if (bin_push_str(&packet, &val) < 0)
			return CLUSTERER_SEND_ERR;
	}

	if (msg_add_trailer(&packet, cluster_id, dst_id ? dst_id : -1) < 0) {
		LM_ERR("Failed to add trailer to module's message\n");
		return CLUSTERER_SEND_ERR;
	}

	if (dst_id)
		rc = clusterer_send_msg(&packet, cluster_id, dst_id);
	else
		rc = clusterer_bcast_msg(&packet, cluster_id, NODE_CMP_ANY);

	bin_free_packet(&packet);

	return rc;
}

static inline int su_ip_cmp(union sockaddr_union* s1, union sockaddr_union* s2)
{
	if (s1->s.sa_family != s2->s.sa_family)
		return 0;
	switch(s1->s.sa_family) {
		case AF_INET:
			return (memcmp(&s1->sin.sin_addr, &s2->sin.sin_addr, 4) == 0);
		case AF_INET6:
			return (memcmp(&s1->sin6.sin6_addr, &s2->sin6.sin6_addr, 16) == 0);
		default:
			LM_CRIT("unknown address family %d\n",
						s1->s.sa_family);
			return 0;
	}
}

static int ip_check(cluster_info_t *cluster, union sockaddr_union *su, str *ip_str)
{
	node_info_t *node;
	str sip_addr;
	char *p;

	for (node = cluster->node_list; node; node = node->next)
		if (su) {
			if (su_ip_cmp(su, &node->addr))
				return 1;
		} else if (ip_str && ip_str->s) {
			if ((p = q_memchr(node->sip_addr.s, ':', node->sip_addr.len))) {
				sip_addr.s = node->sip_addr.s;
				sip_addr.len = p - node->sip_addr.s;
			} else
				sip_addr = node->sip_addr;

			if (!str_strcmp(ip_str, &sip_addr))
				return 1;
		} else {
			LM_ERR("No address to check\n");
			return 0;
		}

	return 0;
}

int clusterer_check_addr(int cluster_id, str *ip_str,
							enum node_addr_type check_type)
{
	cluster_info_t *cluster;
	int rc;
	struct ip_addr ip;
	union sockaddr_union su;

	lock_start_read(cl_list_lock);
	cluster = get_cluster_by_id(cluster_id);
	if (!cluster) {
		LM_WARN("Unknown cluster id [%d]\n", cluster_id);
		return 0;
	}

	if (check_type == NODE_BIN_ADDR) {
		ip.af = AF_INET;
		ip.len = 16;
		if (inet_pton(AF_INET, ip_str->s, ip.u.addr) <= 0) {
			LM_ERR("Invalid IP address\n");
			return 0;
		}
		ip_addr2su(&su, &ip, 0);

		rc = ip_check(cluster, &su, NULL);
		
	} else if (check_type == NODE_SIP_ADDR) {
		rc = ip_check(cluster, NULL, ip_str);
	} else {
		LM_ERR("Bad address type\n");
		rc = 0;
	}

	lock_stop_read(cl_list_lock);
	/* return 1 if addr matched, 0 for ALL other cases, unless return codes implemented */
	return rc;
}

static int flood_message(bin_packet_t *packet, cluster_info_t *cluster,
							int source_id, int rst_req_repl)
{
	int path_len;
	int path_nodes[UPDATE_MAX_PATH_LEN];
	node_info_t *tmp_path_node;
	struct neighbour *neigh;
	int msg_altered = 0;
	str bin_buffer;
	int i;
	int skip_nodes[MAX_NO_NODES];
	int no_skip_nodes = 0;
	int skip;
	node_info_t *destinations[MAX_NO_NODES];
	int no_dests = 0;

	bin_pop_int(packet, &path_len);
	if (path_len > UPDATE_MAX_PATH_LEN) {
		LM_INFO("Too many hops for message with source [%d]\n",
			source_id);
		return -1;
	}

	/* save nodes from the path in order to skip them when flooding */
	for (i = 0; i < path_len; i++) {
		bin_pop_int(packet, &path_nodes[i]);
		tmp_path_node = get_node_by_id(cluster, path_nodes[i]);
		if (!tmp_path_node) {
			LM_DBG("Unknown node in message path, id [%d]\n", path_nodes[i]);
			continue;
		}
		skip_nodes[no_skip_nodes++] = tmp_path_node->node_id;
	}

	if (rst_req_repl) {
		/* message has a require_reply field and it should be reset */
		bin_remove_int_buffer_end(packet, path_len + 2);
		bin_push_int(packet, 0);
		bin_skip_int_packet_end(packet, path_len + 1);
	}

	lock_get(cluster->current_node->lock);

	/* flood update to all neighbours */
	for (neigh = cluster->current_node->neighbour_list; neigh; neigh = neigh->next) {
		/* skip node that already got this update */
		skip = 0;
		for (i = 0; i < no_skip_nodes; i++)
			if (neigh->node->node_id == skip_nodes[i]) {
				skip = 1;
				break;
			}
		if (skip)
			continue;

		if (!msg_altered) {
			/* return to the path length position in the buffer */
			bin_remove_int_buffer_end(packet, path_len + 1);
			/* set new path length */
			bin_push_int(packet, path_len + 1);
			/* go to end of the buffer and include current node in path */
			bin_skip_int_packet_end(packet, path_len);
			bin_push_int(packet, current_id);
			bin_get_buffer(packet, &bin_buffer);
			msg_altered = 1;
		}

		destinations[no_dests++] = neigh->node;
	}

	lock_release(cluster->current_node->lock);

	for (i = 0; i < no_dests; i++) {
		if (msg_send(cluster->send_sock, clusterer_proto, &destinations[i]->addr,
			0, bin_buffer.s, bin_buffer.len, 0) < 0) {
			LM_ERR("Failed to flood message to node [%d]\n",
				destinations[i]->node_id);

			/* this node was supposed to be up, restart pinging */
			set_link_w_neigh_adv(-1, LS_RESTART_PINGING, destinations[i]);
		}
	}

	if (msg_altered)
		LM_DBG("Flooded message with source [%d] to all reachable neighbours\n",
			source_id);

	return 0;
}

static inline int validate_update(int seq_no, int msg_seq_no, int timestamp,
									int msg_timestamp, int val_type, int node_id)
{
	if (msg_seq_no == 0) {
		if (seq_no == 0 && msg_timestamp <= timestamp)
			return -1;
	} else if (msg_seq_no <= seq_no)
		return -1;

	return 0;
}

static node_info_t *add_node(bin_packet_t *received, cluster_info_t *cl,
								int src_node_id, str *str_vals, int *int_vals)
{
	node_info_t *new_node = NULL;
	int lock_old_flag;

	str_vals[STR_VALS_FLAGS_COL].s = 0;
	str_vals[STR_VALS_DESCRIPTION_COL].s = 0;
	int_vals[INT_VALS_ID_COL] = -1;	/* no DB id */
	int_vals[INT_VALS_CLUSTER_ID_COL] = cl->cluster_id;
	int_vals[INT_VALS_NODE_ID_COL] = src_node_id;
	int_vals[INT_VALS_STATE_COL] = 1;	/* enabled */

	lock_switch_write(cl_list_lock, lock_old_flag);

	if (add_node_info(&new_node, &cl, int_vals, str_vals) != 0) {
		LM_ERR("Unable to add node info to backing list\n");
		lock_switch_read(cl_list_lock, lock_old_flag);
		return NULL;
	}
	if (!new_node) {
		LM_ERR("Unable to add node info to backing list\n");
		lock_switch_read(cl_list_lock, lock_old_flag);
		return NULL;
	}

	lock_switch_read(cl_list_lock, lock_old_flag);

	return new_node;
}

static void handle_full_top_update(bin_packet_t *packet, node_info_t *source,
									int *ev_actions_required)
{
	node_info_t *top_node, *top_neigh, *it;
	int seq_no, timestamp;
	int no_nodes;
	int i, j;
	int skip;
	int present_nodes[MAX_NO_NODES];
	int rcv_desc_ints[2][MAX_NO_NODES];
	str rcv_desc_strs[2][MAX_NO_NODES];
	int top_node_id[MAX_NO_NODES];
	int top_node_info[MAX_NO_NODES][4+MAX_NO_NODES];
	str str_vals[NO_DB_STR_VALS];
	int int_vals[NO_DB_INT_VALS];
	int no_present_nodes = 0;
	int present;
	int n_idx;

	bin_pop_int(packet, &seq_no);
	bin_pop_int(packet, &timestamp);

	lock_get(source->lock);
	if (validate_update(source->top_seq_no, seq_no,
		source->top_timestamp, timestamp, 2, source->node_id) < 0) {
		lock_release(source->lock);
		return;
	} else {
		source->top_seq_no = seq_no;
		source->top_timestamp = timestamp;
	}
	lock_release(source->lock);

	bin_pop_int(packet, &no_nodes);

	for (i = 0; i < no_nodes; i++) {
		bin_pop_int(packet, &top_node_id[i]);		/* node id */

		bin_pop_int(packet, &top_node_info[i][0]);  /* has_description */
		if (top_node_info[i][0]) {
			bin_pop_str(packet, &rcv_desc_strs[0][i]);  /* url */
			bin_pop_str(packet, &rcv_desc_strs[1][i]);  /* sip_addr */
			bin_pop_int(packet, &rcv_desc_ints[0][i]);  /* priority */
			bin_pop_int(packet, &rcv_desc_ints[1][i]);  /* no_ping_retries */
		}

		bin_pop_int(packet, &top_node_info[i][1]);  /* ls_seq_no */
		bin_pop_int(packet, &top_node_info[i][2]);  /* ls_timestamp */
		bin_pop_int(packet, &top_node_info[i][3]);  /* no_neigh */

		for (j = 0; j < top_node_info[i][3]; j++)
			bin_pop_int(packet, &top_node_info[i][j+4]);  /* neighbor id */
	}

	for (i = 0; i < no_nodes; i++) {
		skip = 0;

		if (top_node_id[i] == current_id)
			skip = 1;

		top_node = get_node_by_id(source->cluster, top_node_id[i]);

		if (!skip && !top_node) {
			if (!top_node_info[i][0]) {
				LM_WARN("Unknown node id [%d] in topology update with "
					"source [%d]\n", top_node_id[i], source->node_id);
				skip = 1;
			} else {
				str_vals[STR_VALS_URL_COL] = rcv_desc_strs[0][i];
				str_vals[STR_VALS_SIP_ADDR_COL] = rcv_desc_strs[1][i];
				int_vals[INT_VALS_PRIORITY_COL] = rcv_desc_ints[0][i];
				int_vals[INT_VALS_NO_PING_RETRIES_COL] = rcv_desc_ints[1][i];
				top_node = add_node(packet, source->cluster, top_node_id[i],
									str_vals, int_vals);
				if (!top_node)
					skip = 1;
				else
					LM_DBG("Added info about node [%d]\n", top_node_id[i]);
			}
		}

		if (top_node)
			lock_get(top_node->lock);

		if (!skip && i > 0)
			if (validate_update(top_node->ls_seq_no, top_node_info[i][1],
				top_node->ls_timestamp, top_node_info[i][2], 3, top_node->node_id) < 0)
				skip = 1;

		if (skip) {
			if (top_node)
				lock_release(top_node->lock);
			continue;
		}

		top_node->ls_seq_no = top_node_info[i][1];
		top_node->ls_timestamp = top_node_info[i][2];

		lock_release(top_node->lock);

		for (j = 0; j < top_node_info[i][3]; j++) {
			top_neigh = get_node_by_id(source->cluster, top_node_info[i][j+4]);
			if (!top_neigh && top_node_info[i][j+4] != current_id) {
				for (n_idx = 0;
					 n_idx < no_nodes && top_node_info[i][j+4] != top_node_id[n_idx];
					 n_idx++);
				if (n_idx == no_nodes || !top_node_info[n_idx][0]) {
					LM_WARN("Unknown neighbour id [%d] in topology update "
						"about node [%d] with source [%d]\n",
						top_node_info[i][j+4], top_node_id[i], source->node_id);
					continue;
				} else {
					str_vals[STR_VALS_URL_COL] = rcv_desc_strs[0][n_idx];
					str_vals[STR_VALS_SIP_ADDR_COL] = rcv_desc_strs[1][n_idx];
					int_vals[INT_VALS_PRIORITY_COL] = rcv_desc_ints[0][n_idx];
					int_vals[INT_VALS_NO_PING_RETRIES_COL] = rcv_desc_ints[1][n_idx];
					top_neigh = add_node(packet, source->cluster, top_node_id[n_idx],
										str_vals, int_vals);
					if (!top_neigh)
						continue;
					else
						LM_DBG("Added info about node [%d]\n", top_node_id[n_idx]);
				}
			}

			if (top_node_info[i][j+4] == current_id) {
				lock_get(top_node->lock);
				if (top_node->link_state == LS_DOWN) {
					lock_release(top_node->lock);

					set_link_w_neigh(LS_RESTART_PINGING, top_node);
					*ev_actions_required = 1;
				} else
					lock_release(top_node->lock);
			} else {
				set_link(LS_UP, top_node, top_neigh);
				*ev_actions_required = 1;

				/* save the node in order to identify neighbours which are missing
				 * from the adjacency list and thus represent failed links */
				present_nodes[no_present_nodes++] = top_neigh->node_id;
			}
		}

		/* search the saved nodes to delete the corresponding links */
		for (it = source->cluster->node_list; it; it = it->next) {
			if (it->node_id == top_node_id[i] ||
				/* a node has no info about the links from it's neighbours to itself */
				it->node_id == source->node_id)
				continue;

			present = 0;
			for (j = 0; j < no_present_nodes; j++)
				if (it->node_id == present_nodes[j]) {
					present = 1;
					break;
				}
			if (!present) {
				set_link(LS_DOWN, top_node, it);
				*ev_actions_required = 1;
			}
		}
	}

	flood_message(packet, source->cluster, source->node_id, 0);
}

static void handle_cap_update(bin_packet_t *packet, node_info_t *source)
{
	str cap;
	int nr_cap, i, j;
	struct remote_cap *cur;
	struct local_cap *lcap;
	int nr_nodes;
	int node_id;
	node_info_t *node;
	int cap_state;
	int rc;
	int require_reply;

	bin_pop_int(packet, &nr_nodes);

	for (i = 0; i < nr_nodes; i++) {
		bin_pop_int(packet, &node_id);

		if (node_id == current_id) {
			bin_pop_int(packet, &nr_cap);
			for (j = 0; j < nr_cap; j++) {
				bin_pop_str(packet, &cap);
				bin_pop_int(packet, &cap_state);
			}
			continue;
		}
		node = get_node_by_id(source->cluster, node_id);
		if (!node) {
			LM_ERR("Unknown id [%d] in capability update from node [%d]\n",
				node_id, source->node_id);
			return;
		}

		bin_pop_int(packet, &nr_cap);
		for (j = 0; j < nr_cap; j++) {
			bin_pop_str(packet, &cap);
			bin_pop_int(packet, &cap_state);

			lock_get(node->lock);

			for (cur = node->capabilities; cur && str_strcmp(&cap, &cur->name);
				cur = cur->next) ;
			if (!cur) {	/* new capability */
				cur = shm_malloc(sizeof(struct remote_cap) + cap.len);
				if (!cur) {
					LM_ERR("No more shm memory!\n");
					lock_release(node->lock);
					return;
				}
				memset(cur, 0, sizeof *cur);
				cur->name.s = (char *)(cur + 1);
				cur->name.len = cap.len;
				memcpy(cur->name.s, cap.s, cap.len);

				cur->next = node->capabilities;
				node->capabilities = cur;
			}

			if (cap_state == 0)
				cur->flags &= ~CAP_STATE_OK;
			else if (cap_state == 1)
				cur->flags |= CAP_STATE_OK;
			else
				LM_ERR("Received bad state for capability:%.*s from node [%d]\n",
					cap.len, cap.s, source->node_id);
			lock_release(node->lock);

			/* for a node in state OK, check pending sync requests */
			if (cap_state == 1) {
				for (lcap = source->cluster->capabilities; lcap; lcap = lcap->next)
					if (!str_strcmp(&cap, &lcap->reg.name))
						break;
				if (lcap) {
					lock_get(source->cluster->lock);
					if (lcap->flags & CAP_SYNC_PENDING) {
						lock_release(source->cluster->lock);

						if (!match_node(source->cluster->current_node, node,
						                lcap->reg.sync_cond)) {
							LM_DBG("no match for node id %d\n", node->node_id);
							continue;
						}

						rc = send_sync_req(&cap, source->cluster->cluster_id,
											node_id);
						if (rc == CLUSTERER_SEND_SUCCESS) {
							lock_get(source->cluster->lock);
							lcap->flags &= ~CAP_SYNC_PENDING;
							lock_release(source->cluster->lock);
						} else if (rc == CLUSTERER_SEND_ERR)
							LM_ERR("Failed to send sync request to node: %d\n",
								node_id);
					} else
						lock_release(source->cluster->lock);
				}
			}
		}
	}

	bin_pop_int(packet, &require_reply);
	if (require_reply)
		/* also send current node's capabilities information to source node */
		send_cap_update(source, 0);

	/* flood to other neighbours */
	flood_message(packet, source->cluster, source->node_id, require_reply);
}

static void handle_internal_msg_unknown(bin_packet_t *received, cluster_info_t *cl,
					int packet_type, union sockaddr_union *src_su, int src_node_id)
{
	str bin_buffer;
	int req_list;
	str str_vals[NO_DB_STR_VALS];
	int int_vals[NO_DB_INT_VALS];

	bin_packet_t packet;

	switch (packet_type) {
	case CLUSTERER_PING:
		bin_pop_int(received, &req_list);

		/* reply in order to inform the node that the current node has no info about it */
		if (bin_init(&packet, &cl_internal_cap, CLUSTERER_UNKNOWN_ID, BIN_VERSION, SMALL_MSG) < 0) {
			LM_ERR("Failed to init bin send buffer\n");
			return;
		}
		bin_push_int(&packet, cl->cluster_id);
		bin_push_int(&packet, current_id);
		bin_get_buffer(&packet, &bin_buffer);

		if (msg_send(cl->send_sock, clusterer_proto, src_su, 0, bin_buffer.s,
			bin_buffer.len, 0) < 0)
			LM_ERR("Failed to reply to ping from unknown node, id [%d]\n", src_node_id);
		else
			LM_DBG("Replied to ping from unknown node, id [%d]\n", src_node_id);

		bin_free_packet(&packet);
		break;
	case CLUSTERER_NODE_DESCRIPTION:
		LM_DBG("Received node description from sorce [%d]\n", src_node_id);

		bin_pop_str(received, &str_vals[STR_VALS_URL_COL]);
		bin_pop_str(received, &str_vals[STR_VALS_SIP_ADDR_COL]);
		bin_pop_int(received, &int_vals[INT_VALS_PRIORITY_COL]);
		bin_pop_int(received, &int_vals[INT_VALS_NO_PING_RETRIES_COL]);
		add_node(received, cl, src_node_id, str_vals, int_vals);

		flood_message(received, cl, src_node_id, 0);
		break;
	default:
		LM_DBG("Ignoring message, type: %d from unknown source, id [%d]\n",
			packet_type, src_node_id);
	}
}

static void handle_ls_update(bin_packet_t *received, node_info_t *src_node,
								int *ev_actions_required)
{
	int seq_no, timestamp;
	int neigh_id;
	int new_ls;
	node_info_t *ls_neigh;

	lock_get(src_node->lock);

	bin_pop_int(received, &seq_no);
	bin_pop_int(received, &timestamp);

	if (validate_update(src_node->ls_seq_no, seq_no, src_node->ls_timestamp,
		timestamp, 1, src_node->node_id) < 0) {
		lock_release(src_node->lock);
		return;
	}
	else {
		src_node->ls_seq_no = seq_no;
		src_node->ls_timestamp = timestamp;
	}

	bin_pop_int(received, &neigh_id);
	bin_pop_int(received, &new_ls);
	ls_neigh = get_node_by_id(src_node->cluster, neigh_id);
	if (!ls_neigh && neigh_id != current_id) {
		LM_WARN("Received link state update about unknown node id [%d]\n", neigh_id);
		lock_release(src_node->lock);
		return;
	}

	LM_DBG("Received link state update with source [%d] about node [%d], new state=%s\n",
		src_node->node_id, neigh_id, new_ls ? "DOWN" : "UP");

	if (neigh_id == current_id) {
		if ((new_ls == LS_UP && src_node->link_state == LS_DOWN) ||
			(new_ls == LS_DOWN && src_node->link_state == LS_UP)) {
			lock_release(src_node->lock);

			set_link_w_neigh_adv(-1, LS_RESTART_PINGING, src_node);
			*ev_actions_required = 1;
		} else
			lock_release(src_node->lock);
	} else {
		lock_release(src_node->lock);

		set_link(new_ls, src_node, ls_neigh);

		*ev_actions_required = 1;
	}

	flood_message(received, src_node->cluster, src_node->node_id, 0);
}

static inline void bin_push_node_info(bin_packet_t *packet, node_info_t *node)
{
	bin_push_str(packet, &node->url);
	bin_push_str(packet, &node->sip_addr);
	bin_push_int(packet, node->priority);
	bin_push_int(packet, node->no_ping_retries);
}

static void handle_unknown_id(node_info_t *src_node)
{
	bin_packet_t packet;
	str bin_buffer;

	/* send description */
	if (bin_init(&packet, &cl_internal_cap, CLUSTERER_NODE_DESCRIPTION,
		BIN_VERSION, SMALL_MSG) < 0) {
		LM_ERR("Failed to init bin send buffer\n");
		return;
	}
	bin_push_int(&packet, src_node->cluster->cluster_id);
	bin_push_int(&packet, current_id);

	/* include info about current node */
	bin_push_node_info(&packet, src_node->cluster->current_node);

	/* path length is 1, only current node at this point */
	bin_push_int(&packet, 1);
	bin_push_int(&packet, current_id);

	bin_get_buffer(&packet, &bin_buffer);
	if (msg_send(src_node->cluster->send_sock, clusterer_proto, &src_node->addr,
		0, bin_buffer.s, bin_buffer.len, 0) < 0)
		LM_ERR("Failed to send node description to node [%d]\n", src_node->node_id);
	else
		LM_DBG("Sent node description to node [%d]\n", src_node->node_id);
	bin_free_packet(&packet);

	set_link_w_neigh_adv(-1, LS_RESTART_PINGING, src_node);
}

static void handle_internal_msg(bin_packet_t *received, int packet_type,
		node_info_t *src_node, struct timeval rcv_time, int *ev_actions_required)
{
	node_info_t *it;
	str bin_buffer;
	int send_rc;
	int new_ls = -1;
	int rst_ping_now = 0;
	int req_list;
	int node_list[MAX_NO_NODES], i, nr_nodes;
	bin_packet_t packet;

	switch (packet_type) {
	case CLUSTERER_PONG:
		LM_DBG("Received ping reply from node [%d]\n", src_node->node_id);

		bin_pop_int(received, &nr_nodes);
		for (i=0; i<nr_nodes; i++)
			bin_pop_int(received, &node_list[i]);

		lock_get(src_node->lock);

		src_node->last_pong = rcv_time;

		/* check possible races between setting the appropriate state
		 * after sending ping and receiving the reply */
		if ((src_node->link_state == LS_RESTART_PINGING ||
			src_node->link_state == LS_RETRY_SEND_FAIL ||
			src_node->link_state == LS_DOWN) &&
			src_node->last_ping_state == 0 &&
			TIME_DIFF(src_node->last_ping, rcv_time) < (utime_t)ping_timeout*1000)
			src_node->link_state = LS_TEMP;

		/* if the node was retried and a reply was expected, it should be UP again */
		if ((src_node->link_state == LS_RESTARTED ||
			src_node->link_state == LS_RETRYING ||
			src_node->link_state == LS_TEMP) &&
			PING_REPLY_INTERVAL(src_node) > 0 &&
			PING_REPLY_INTERVAL(src_node) < (utime_t)ping_timeout*1000) {
			lock_release(src_node->lock);

			set_link_w_neigh_up(src_node, nr_nodes, node_list);
			*ev_actions_required = 1;

			LM_INFO("Node [%d] is UP\n", src_node->node_id);
		} else
			lock_release(src_node->lock);

		break;
	case CLUSTERER_PING:
		bin_pop_int(received, &req_list);

		/* reply with pong */
		if (bin_init(&packet, &cl_internal_cap, CLUSTERER_PONG, BIN_VERSION,
			SMALL_MSG) < 0) {
			LM_ERR("Failed to init bin send buffer\n");
			return;
		}
		bin_push_int(&packet, src_node->cluster->cluster_id);
		bin_push_int(&packet, current_id);

		if (req_list) {
			/* include a list of known nodes */
			bin_push_int(&packet, src_node->cluster->no_nodes - 1);
			for (it = src_node->cluster->node_list; it; it = it->next)
				if (it->node_id != src_node->node_id)
					bin_push_int(&packet, it->node_id);
		} else
			bin_push_int(&packet, 0);

		bin_get_buffer(&packet, &bin_buffer);

		#ifndef CLUSTERER_EXTRA_BIN_DBG
		set_proc_log_level(L_INFO);
		#endif

		send_rc = msg_send(src_node->cluster->send_sock, clusterer_proto,
			&src_node->addr, 0, bin_buffer.s, bin_buffer.len, 0);

		#ifndef CLUSTERER_EXTRA_BIN_DBG
		reset_proc_log_level();
		#endif

		lock_get(src_node->lock);

		if (send_rc < 0) {
			LM_ERR("Failed to reply to ping from node [%d]\n", src_node->node_id);
			if (src_node->link_state == LS_UP) {
				new_ls = LS_RESTART_PINGING;
				*ev_actions_required = 1;
			}
		} else
			LM_DBG("Replied to ping from node [%d]\n", src_node->node_id);

		/* if the node was down, restart pinging */
		if (src_node->link_state == LS_DOWN) {
			LM_DBG("Received ping from failed node, restart pinging\n");

			if (send_rc == 0)
				/* restart right now */
				rst_ping_now = 1;
			else
				/* restart on timer */
				new_ls = LS_RESTART_PINGING;
		}

		lock_release(src_node->lock);

		if (rst_ping_now)
			do_action_trans_0(src_node, &new_ls);

		if (new_ls >= 0)
			set_link_w_neigh_adv(-1, new_ls, src_node);

		bin_free_packet(&packet);
		break;
	case CLUSTERER_LS_UPDATE:
		handle_ls_update(received, src_node, ev_actions_required);
		break;
	case CLUSTERER_FULL_TOP_UPDATE:
		LM_DBG("Received full topology update with source [%d]\n", src_node->node_id);
		handle_full_top_update(received, src_node, ev_actions_required);
		break;
	case CLUSTERER_UNKNOWN_ID:
		LM_DBG("Received UNKNOWN_ID from node [%d]\n", src_node->node_id);
		handle_unknown_id(src_node);
		break;
	case CLUSTERER_NODE_DESCRIPTION:
		LM_DBG("Already got node description for source [%d], drop this message\n",
			src_node->node_id);
		break;
	case CLUSTERER_CAP_UPDATE:
		LM_DBG("Received capability update with source [%d]\n", src_node->node_id);
		handle_cap_update(received, src_node);
		break;
	default:
		LM_WARN("Invalid clusterer binary packet command from node: %d\n",
			src_node->node_id);
	}
}

static void handle_cl_gen_msg(bin_packet_t *packet, int cluster_id, int source_id)
{
	int req_like;
	str rcv_msg, rcv_tag;

	LM_DBG("Received generic clusterer message\n");

	bin_pop_int(packet, &req_like);
	bin_pop_str(packet, &rcv_tag);
	bin_pop_str(packet, &rcv_msg);

	if (evi_param_set_int(ei_clid_p, &cluster_id) < 0) {
		LM_ERR("cannot set cluster id event parameter\n");
		return;
	}
	if (evi_param_set_int(ei_srcid_p, &source_id) < 0) {
		LM_ERR("cannot set source id event parameter\n");
		return;
	}
	if (evi_param_set_str(ei_msg_p, &rcv_msg) < 0) {
		LM_ERR("cannot set message event parameter\n");
		return;
	}
	if (evi_param_set_str(ei_tag_p, &rcv_tag) < 0) {
		LM_ERR("cannot set tag event parameter\n");
		return;
	}

	/* raise event interface event for generic msg */
	if (req_like) {
		if (evi_raise_event(ei_req_rcv_id, ei_event_params) < 0) {
			LM_ERR("cannot raise event\n");
			return;
		}
	} else {
		if (evi_raise_event(ei_rpl_rcv_id, ei_event_params) < 0) {
			LM_ERR("cannot raise event\n");
			return;
		}
	}
}

static void handle_cl_mi_msg(bin_packet_t *packet)
{
	str cmd_params[MI_CMD_MAX_NR_PARAMS];
	str cmd_name;
	int i, no_params;
	int rc;

	bin_pop_str(packet, &cmd_name);
	LM_DBG("Received MI command <%.*s>\n", cmd_name.len, cmd_name.s);

	bin_pop_int(packet, &no_params);
	for (i = 0; i < no_params; i++)
		bin_pop_str(packet, &cmd_params[i]);

	rc = run_rcv_mi_cmd(&cmd_name, cmd_params, no_params);
	if (rc == -1) {
		LM_ERR("MI command <%.*s> failed\n", cmd_name.len, cmd_name.s);
		return;
	}

	LM_INFO("MI command <%.*s> returned with %s\n",
		cmd_name.len, cmd_name.s, (rc == 1) ? "error" : "success");
}

void bin_rcv_cl_extra_packets(bin_packet_t *packet, int packet_type,
									struct receive_info *ri, void *att)
{
	int source_id, dest_id, cluster_id;
	cluster_info_t *cl;
	node_info_t *node;
	int ev_actions_required = 0;
	char *ip;
	unsigned short port;

	bin_pop_back_int(packet, &dest_id);
	bin_pop_back_int(packet, &source_id);
	bin_pop_back_int(packet, &cluster_id);

	get_su_info(&ri->src_su.s, ip, port);
	LM_DBG("received clusterer message from: %s:%hu with source id: %d and"
			" cluster id: %d\n", ip, port, source_id, cluster_id);

	if (source_id == current_id) {
		LM_ERR("Received message with bad source - same node id as this instance\n");
		return;
	}

	lock_start_read(cl_list_lock);

	cl = get_cluster_by_id(cluster_id);
	if (!cl) {
		LM_WARN("Received message, type: %d, from unknown cluster id [%d]\n",
			packet_type, cluster_id);
		goto exit;
	}

	lock_get(cl->current_node->lock);
	if (!(cl->current_node->flags & NODE_STATE_ENABLED)) {
		lock_release(cl->current_node->lock);
		LM_INFO("Current node disabled, ignoring received bin packet\n");
		goto exit;
	}
	lock_release(cl->current_node->lock);

	node = get_node_by_id(cl, source_id);
	if (!node) {
		LM_WARN("Received message with unknown source id [%d]\n", source_id);
		goto exit;
	}

	lock_get(node->lock);

	/* if the node was down, restart pinging */
	if (node->link_state == LS_DOWN) {
		lock_release(node->lock);
		LM_DBG("Received bin packet from failed node, restart pinging\n");
		set_link_w_neigh(LS_RESTART_PINGING, node);
	} else
		lock_release(node->lock);

	if (dest_id != current_id) {
		/* route the message */
		bin_push_int(packet, cluster_id);
		bin_push_int(packet, source_id);
		bin_push_int(packet, dest_id);

		node = get_node_by_id(cl, dest_id);
		if (!node) {
			LM_WARN("Received message with unknown destination id [%d]\n", source_id);
			goto exit;
		}

		if (msg_send_retry(packet, node, 0, &ev_actions_required) < 0) {
			LM_ERR("Failed to route message with source id [%d] and destination id [%d]\n",
				source_id, dest_id);
			if (ev_actions_required)
				do_actions_node_ev(cl, &ev_actions_required, 1);

			goto exit;
		} else {
			LM_DBG("Routed message with source id [%d] and destination id [%d]\n",
				source_id, dest_id);
			if (ev_actions_required)
				do_actions_node_ev(cl, &ev_actions_required, 1);

			goto exit;
		}
	} else {
		if (packet_type == CLUSTERER_GENERIC_MSG)
			handle_cl_gen_msg(packet, cluster_id, source_id);
		else if (packet_type == CLUSTERER_MI_CMD)
			handle_cl_mi_msg(packet);
		else if (packet_type == CLUSTERER_SHTAG_ACTIVE)
			handle_shtag_active(packet, cluster_id);
		else if (packet_type == CLUSTERER_SYNC_REQ)
			handle_sync_request(packet, cl, node);
		else if (packet_type == CLUSTERER_SYNC || packet_type == CLUSTERER_SYNC_END)
			handle_sync_packet(packet, packet_type, cl, source_id);
		else {
			LM_ERR("Unknown clusterer message type: %d\n", packet_type);
			goto exit;
		}
	}

exit:
	lock_stop_read(cl_list_lock);
}

void bin_rcv_cl_packets(bin_packet_t *packet, int packet_type,
									struct receive_info *ri, void *att)
{
	int source_id, cl_id;
	struct timeval now;
	node_info_t *node = NULL;
	cluster_info_t *cl;
	char *ip;
	unsigned short port;
	int ev_actions_required = 0;

	gettimeofday(&now, NULL);

	bin_pop_int(packet, &cl_id);
	bin_pop_int(packet, &source_id);

	get_su_info(&ri->src_su.s, ip, port);
	LM_DBG("received clusterer message from: %s:%hu with source id: %d and "
		"cluster id: %d\n", ip, port, source_id, cl_id);

	if (source_id == current_id) {
		LM_ERR("Received message with bad source - same node id as this instance\n");
		return;
	}

	lock_start_sw_read(cl_list_lock);

	cl = get_cluster_by_id(cl_id);
	if (!cl) {
		LM_WARN("Received message from unknown cluster id [%d]\n", cl_id);
		goto exit;
	}

	lock_get(cl->current_node->lock);
	if (!(cl->current_node->flags & NODE_STATE_ENABLED)) {
		lock_release(cl->current_node->lock);
		LM_INFO("Current node disabled, ignoring received clusterer bin packet\n");
		goto exit;
	}
	lock_release(cl->current_node->lock);

	node = get_node_by_id(cl, source_id);

	if (!node) {
		LM_INFO("Received message with unknown source id [%d]\n", source_id);
		handle_internal_msg_unknown(packet, cl, packet_type, &ri->src_su, source_id);
	} else {
		handle_internal_msg(packet, packet_type, node, now,	&ev_actions_required);
		if (ev_actions_required)
			do_actions_node_ev(cl, &ev_actions_required, 1);
	}

exit:
	lock_stop_sw_read(cl_list_lock);
}

void run_mod_packet_cb(int sender, void *param)
{
	extern char *next_data_chunk;
	struct packet_rpc_params *p = (struct packet_rpc_params *)param;
	bin_packet_t packet;
	str cap_name;
	int data_version;

	bin_init_buffer(&packet, p->pkt_buf.s, p->pkt_buf.len);
	packet.src_id = p->pkt_src_id;
	packet.type = p->pkt_type;

	if (packet.type == SYNC_PACKET_TYPE) {
		/* this packet is cloned and both below fields have been used */
		bin_pop_str(&packet, &cap_name);
		bin_pop_int(&packet, &data_version);
		next_data_chunk = NULL;
	}

	p->cap->packet_cb(&packet);

	shm_free(param);
}

int ipc_dispatch_mod_packet(bin_packet_t *packet, struct capability_reg *cap)
{
	struct packet_rpc_params *params;

	params = shm_malloc(sizeof *params + packet->buffer.len);
	if (!params) {
		LM_ERR("oom!\n");
		return -1;
	}
	memset(params, 0, sizeof *params);
	params->pkt_buf.s = (char *)(params + 1);

	memcpy(params->pkt_buf.s, packet->buffer.s, packet->buffer.len);
	params->pkt_buf.len = packet->buffer.len;
	params->cap = cap;
	params->pkt_type = packet->type;
	params->pkt_src_id = packet->src_id;

	if (ipc_dispatch_rpc(run_mod_packet_cb, params) < 0) {
		LM_ERR("Failed to dispatch rpc\n");
		return -1;
	}

	return 0;
}

static void bin_rcv_mod_packets(bin_packet_t *packet, int packet_type,
									struct receive_info *ri, void *ptr)
{
	struct capability_reg *cap;
	struct local_cap *cl_cap;
	unsigned short port;
	int source_id, dest_id, cluster_id;
	char *ip;
	node_info_t *node = NULL;
	cluster_info_t *cl;
	int ev_actions_required = 0;

	/* pop the source and destination from the bin packet */
	bin_pop_back_int(packet, &dest_id);
	bin_pop_back_int(packet, &source_id);
	bin_pop_back_int(packet, &cluster_id);

	get_su_info(&ri->src_su.s, ip, port);
	LM_DBG("received bin packet from: %s:%hu with source id: %d and cluster id: %d\n",
			ip, port, source_id, cluster_id);

	if (source_id == current_id) {
		LM_ERR("Received message with bad source - same node id as this instance\n");
		return;
	}

	cap = (struct capability_reg *)ptr;
	if (!cap) {
		LM_ERR("Failed to get bin callback parameter\n");
		return;
	}

	lock_start_read(cl_list_lock);

	cl = get_cluster_by_id(cluster_id);
	if (!cl) {
		LM_WARN("Received message from unknown cluster, id [%d]\n", cluster_id);
		goto exit;
	}

	lock_get(cl->current_node->lock);
	if (!(cl->current_node->flags & NODE_STATE_ENABLED)) {
		lock_release(cl->current_node->lock);
		LM_INFO("Current node disabled, ignoring received bin packet\n");
		goto exit;
	}
	lock_release(cl->current_node->lock);

	node = get_node_by_id(cl, source_id);
	if (!node) {
		LM_WARN("Received message with unknown source id [%d]\n", source_id);
		goto exit;
	}

	if (!su_ip_cmp(&ri->src_su, &node->addr) && !ip_check(cl, &ri->src_su, NULL)) {
		LM_WARN("Received message from unknown source, addr: %s\n", ip);
		goto exit;
	}

	lock_get(node->lock);

	/* if the node was down, restart pinging */
	if (node->link_state == LS_DOWN) {
		lock_release(node->lock);
		LM_DBG("Received bin packet from failed node, restart pinging\n");
		set_link_w_neigh(LS_RESTART_PINGING, node);
	} else
		lock_release(node->lock);

	if (dest_id != current_id) {
		/* route the message */
		bin_push_int(packet, cluster_id);
		bin_push_int(packet, source_id);
		bin_push_int(packet, dest_id);

		node = get_node_by_id(cl, dest_id);
		if (!node) {
			LM_WARN("Received message with unknown destination id [%d]\n",
				source_id);
			goto exit;
		}

		if (msg_send_retry(packet, node, 0, &ev_actions_required) < 0) {
			LM_ERR("Failed to route message with source id [%d] and destination "
				"id [%d]\n", source_id, dest_id);
			if (ev_actions_required)
				do_actions_node_ev(cl, &ev_actions_required, 1);
		} else {
			LM_DBG("Routed message with source id [%d] and destination id [%d]\n",
				source_id, dest_id);
			if (ev_actions_required)
				do_actions_node_ev(cl, &ev_actions_required, 1);
		}
	} else {
		/* try to pass message to registered callback */

		for (cl_cap = cl->capabilities; cl_cap; cl_cap = cl_cap->next)
			if (!str_strcmp(&cl_cap->reg.name, &cap->name))
				break;
		if (!cl_cap) {
			LM_ERR("Packet's capability: %.*s not found in cluster info\n",
				cap->name.len, cap->name.s);
			goto exit;
		}

		lock_get(cl->lock);

		if (cl_cap->flags & CAP_PKT_BUFFERING) {
			/* buffer regular packets during sync or during processing of
			 * previously buffered packets */
			buffer_bin_pkt(packet, cl_cap, source_id);
			lock_release(cl->lock);
		} else {
			lock_release(cl->lock);
			lock_stop_read(cl_list_lock);
			packet->src_id = source_id;

			if (ipc_dispatch_mod_packet(packet, cap) < 0)
				LM_ERR("Failed to dispatch handling of module packet\n");

			return;
		}
	}

exit:
	lock_stop_read(cl_list_lock);
}

static int delete_neighbour(node_info_t *from_node, node_info_t *to_delete_n)
{
	struct neighbour *neigh, *tmp;

	neigh = from_node->neighbour_list;
	if (!neigh)
		return 0;

	if (neigh->node->node_id == to_delete_n->node_id) {
		from_node->neighbour_list = neigh->next;
		shm_free(neigh);
		return 1;
	}
	while (neigh->next) {
		if (neigh->next->node->node_id == to_delete_n->node_id) {
			tmp = neigh->next;
			neigh->next = neigh->next->next;
			shm_free(tmp);
			return 1;
		}
		neigh = neigh->next;
	}

	return 0;
}

static int add_neighbour(node_info_t *to_node, node_info_t *new_n)
{
	struct neighbour *neigh;

	neigh = to_node->neighbour_list;
	while (neigh) {
		if (neigh->node->node_id == new_n->node_id)
			return 0;
		neigh = neigh->next;
	}

	neigh = shm_malloc(sizeof *neigh);
	if (!neigh) {
		LM_ERR("No more shm mem\n");
		return -1;
	}
	neigh->node = new_n;
	neigh->next = to_node->neighbour_list;
	to_node->neighbour_list = neigh;
	return 1;
}

/* topology update packets(CLUSTERER_FULL_TOP_UPDATE and CLUSTERER_LS_UPDATE) format:
 * +---------------------------------------------------------------------------------------------+
 * | cluster | src_node | seq_no | timestamp | update_content | path_len | node_1 | node_2 | ... |
 * +---------------------------------------------------------------------------------------------+
 */

static int send_full_top_update(node_info_t *dest_node, int nr_nodes, int *node_list)
{
	str bin_buffer;
	struct neighbour *neigh;
	node_info_t *it;
	int no_neigh;
	bin_packet_t packet;
	int timestamp;
	int i;

	timestamp = time(NULL);

	lock_get(dest_node->cluster->current_node->lock);

	if (bin_init(&packet, &cl_internal_cap, CLUSTERER_FULL_TOP_UPDATE, BIN_VERSION, 0) < 0) {
		lock_release(dest_node->cluster->current_node->lock);
		LM_ERR("Failed to init bin send buffer\n");
		return -1;
	}
	bin_push_int(&packet, dest_node->cluster->cluster_id);
	bin_push_int(&packet, current_id);
	bin_push_int(&packet, ++dest_node->cluster->current_node->top_seq_no);
	bin_push_int(&packet, timestamp);

	/* CLUSTERER_FULL_TOP_UPDATE message update content:
     * +----------------------------------------------------------------------------------------------------------------------+
	 * | no_nodes | node_1 | has_descr | descr | ls_seq_no | ls_timestamp | no_neigh | neigh_1 | neigh_2 | ... | node_2 | ... |
	 * +----------------------------------------------------------------------------------------------------------------------+
     */
    bin_push_int(&packet, dest_node->cluster->no_nodes);

	/* the first adjacency list in the message is for the current node */
	bin_push_int(&packet, current_id);
	bin_push_int(&packet, 0);	/* no description for current node */
	bin_push_int(&packet, dest_node->cluster->current_node->ls_seq_no);
	bin_push_int(&packet, dest_node->cluster->current_node->ls_timestamp);
	bin_push_int(&packet, 0); /* no neighbours for now */
	for (neigh = dest_node->cluster->current_node->neighbour_list, no_neigh = 0;
		 neigh; neigh = neigh->next, no_neigh++)
		bin_push_int(&packet, neigh->node->node_id);
	/* set the number of neighbours */
	bin_remove_int_buffer_end(&packet, no_neigh + 1);
	bin_push_int(&packet, no_neigh);
	bin_skip_int_packet_end(&packet, no_neigh);

	lock_release(dest_node->cluster->current_node->lock);

	/* the adjacency lists for the rest of the nodes */
	for (it = dest_node->cluster->node_list; it; it = it->next) {
		/* skip requesting node */
		if (it->node_id == dest_node->node_id)
			continue;

		lock_get(it->lock);

		bin_push_int(&packet, it->node_id);

		for (i = 0; i < nr_nodes && it->node_id != node_list[i]; i++);
		if (i == nr_nodes) {
			/* include info about this node */
			bin_push_int(&packet, 1);
			bin_push_node_info(&packet, it);
		} else
			bin_push_int(&packet, 0);

		bin_push_int(&packet, it->ls_seq_no);
		bin_push_int(&packet, it->ls_timestamp);
		bin_push_int(&packet, 0);
		for (neigh = it->neighbour_list, no_neigh = 0; neigh;
			neigh = neigh->next, no_neigh++)
			bin_push_int(&packet, neigh->node->node_id);
		/* set the number of neighbours */
		bin_remove_int_buffer_end(&packet, no_neigh + 1);
		bin_push_int(&packet, no_neigh);
		bin_skip_int_packet_end(&packet, no_neigh);

		lock_release(it->lock);
	}

	bin_push_int(&packet, 1);	/* path length is 1, only current node at this point */
	bin_push_int(&packet, current_id);
	bin_get_buffer(&packet, &bin_buffer);

	if (msg_send(dest_node->cluster->send_sock, clusterer_proto, &dest_node->addr,
		0, bin_buffer.s, bin_buffer.len, 0) < 0) {
		LM_ERR("Failed to send topology update to node [%d]\n", dest_node->node_id);
		set_link_w_neigh_adv(-1, LS_RESTART_PINGING, dest_node);
	} else
		LM_DBG("Sent topology update to node [%d]\n", dest_node->node_id);

	bin_free_packet(&packet);
	return 0;
}

static int send_ls_update(node_info_t *node, clusterer_link_state new_ls)
{
	struct neighbour *neigh;
	str send_buffer;
	node_info_t* destinations[MAX_NO_NODES];
	int no_dests = 0, i;
	bin_packet_t packet;
	int timestamp;

	timestamp = time(NULL);

	lock_get(node->cluster->current_node->lock);

	for (neigh = node->cluster->current_node->neighbour_list; neigh;
		neigh = neigh->next) {
		if (neigh->node->node_id == node->node_id)
			continue;

		destinations[no_dests++] = neigh->node;
	}

	if (no_dests == 0) {
		lock_release(node->cluster->current_node->lock);
		return 0;
	}

	if (bin_init(&packet, &cl_internal_cap, CLUSTERER_LS_UPDATE, BIN_VERSION,
		SMALL_MSG) < 0) {
		LM_ERR("Failed to init bin send buffer\n");
		lock_release(node->cluster->current_node->lock);
		return -1;
	}
	bin_push_int(&packet, node->cluster->cluster_id);
	bin_push_int(&packet, current_id);
	bin_push_int(&packet, ++node->cluster->current_node->ls_seq_no);
	bin_push_int(&packet, timestamp);

	/* The link state update message's update content consists of a neighbour
	 * and it's new link state */
	bin_push_int(&packet, node->node_id);
	bin_push_int(&packet, new_ls);

	/* path length is 1, only current node at this point */
	bin_push_int(&packet, 1);
	bin_push_int(&packet, current_id);

	lock_release(node->cluster->current_node->lock);

	bin_get_buffer(&packet, &send_buffer);
	for (i = 0; i < no_dests; i++) {
		if (msg_send(destinations[i]->cluster->send_sock, clusterer_proto,
			&destinations[i]->addr, 0, send_buffer.s, send_buffer.len, 0) < 0) {
			LM_ERR("Failed to send link state update to node [%d]\n",
				destinations[i]->node_id);
			/* this node was supposed to be up, restart pinging */
			set_link_w_neigh_adv(-1, LS_RESTART_PINGING, destinations[i]);
		}
	}

	bin_free_packet(&packet);
	LM_DBG("Sent link state update about node [%d] to all reachable neighbours\n",
		node->node_id);

	return 0;
}

int send_single_cap_update(cluster_info_t *cluster, struct local_cap *cap,
							int cap_state)
{
	bin_packet_t packet;
	str bin_buffer;
	node_info_t* destinations[MAX_NO_NODES];
	struct neighbour *neigh;
	int no_dests = 0, i;

	lock_get(cluster->current_node->lock);

	for (neigh = cluster->current_node->neighbour_list; neigh;
		neigh = neigh->next)
		destinations[no_dests++] = neigh->node;

	lock_release(cluster->current_node->lock);

	if (no_dests == 0)
		return 0;

	if (bin_init(&packet, &cl_internal_cap, CLUSTERER_CAP_UPDATE,
		BIN_VERSION, 0) < 0) {
		LM_ERR("Failed to init bin send buffer\n");
		return -1;
	}
	bin_push_int(&packet, cluster->cluster_id);
	bin_push_int(&packet, current_id);

	/* only the current node */
	bin_push_int(&packet, 1);
	bin_push_int(&packet, current_id);

	/* only a single capability */
	bin_push_int(&packet, 1);
	bin_push_str(&packet, &cap->reg.name);
	bin_push_int(&packet, cap_state);

	bin_push_int(&packet, 0);  /* don't require reply */

	bin_push_int(&packet, 1);	/* path length is 1, only current node at this point */
	bin_push_int(&packet, current_id);
	bin_get_buffer(&packet, &bin_buffer);

	for (i = 0; i < no_dests; i++)
		if (msg_send(cluster->send_sock, clusterer_proto,
			&destinations[i]->addr, 0, bin_buffer.s, bin_buffer.len, 0) < 0) {
			LM_ERR("Failed to send capability update to node [%d]\n",
				destinations[i]->node_id);
			set_link_w_neigh_adv(-1, LS_RESTART_PINGING, destinations[i]);
		} else
			LM_DBG("Sent capability update to node [%d]\n",
				destinations[i]->node_id);

	bin_free_packet(&packet);

	return 0;
}

static int send_cap_update(node_info_t *dest_node, int require_reply)
{
	bin_packet_t packet;
	str bin_buffer;
	struct local_cap *cl_cap;
	struct remote_cap *n_cap;
	int nr_cap, nr_nodes = 0;
	node_info_t *node;

	if (dest_node->cluster->capabilities)
		nr_nodes++;

	for (node = dest_node->cluster->node_list; node; node = node->next) {
		lock_get(node->lock);
		if (node->capabilities && node->node_id != dest_node->node_id)
			nr_nodes++;
		lock_release(node->lock);
	}

	if (nr_nodes == 0)
		return 0;

	if (bin_init(&packet, &cl_internal_cap, CLUSTERER_CAP_UPDATE, BIN_VERSION, 0) < 0) {
		LM_ERR("Failed to init bin send buffer\n");
		return -1;
	}
	bin_push_int(&packet, dest_node->cluster->cluster_id);
	bin_push_int(&packet, current_id);

	bin_push_int(&packet, nr_nodes);

	/* current node's capabilities */
	for (cl_cap = dest_node->cluster->capabilities, nr_cap = 0; cl_cap;
		cl_cap = cl_cap->next, nr_cap++) ;
	if (nr_cap) {
		bin_push_int(&packet, current_id);
		bin_push_int(&packet, nr_cap);
		for (cl_cap=dest_node->cluster->capabilities;cl_cap;cl_cap=cl_cap->next) {
			bin_push_str(&packet, &cl_cap->reg.name);
			lock_get(dest_node->cluster->lock);
			bin_push_int(&packet, cl_cap->flags & CAP_STATE_OK ? 1 : 0);
			lock_release(dest_node->cluster->lock);
		}
	}

	/* known capabilities for other nodes */
	for (node = dest_node->cluster->node_list; node; node = node->next) {
		if (node->node_id == dest_node->node_id)
			continue;
		lock_get(node->lock);
		for (n_cap = node->capabilities, nr_cap = 0; n_cap;
			n_cap = n_cap->next, nr_cap++) ;
		if (nr_cap) {
			bin_push_int(&packet, node->node_id);
			bin_push_int(&packet, nr_cap);
			for (n_cap = node->capabilities; n_cap; n_cap = n_cap->next) {
				bin_push_str(&packet, &n_cap->name);
				bin_push_int(&packet, n_cap->flags & CAP_STATE_OK ? 1 : 0);
			}
		}
		lock_release(node->lock);
	}

	bin_push_int(&packet, require_reply);

	bin_push_int(&packet, 1);	/* path length is 1, only current node at this point */
	bin_push_int(&packet, current_id);
	bin_get_buffer(&packet, &bin_buffer);

	if (msg_send(dest_node->cluster->send_sock, clusterer_proto, &dest_node->addr,
		0, bin_buffer.s, bin_buffer.len, 0) < 0) {
		LM_ERR("Failed to send capability update to node [%d]\n", dest_node->node_id);
		set_link_w_neigh_adv(-1, LS_RESTART_PINGING, dest_node);
	} else
		LM_DBG("Sent capability update to node [%d]\n", dest_node->node_id);

	bin_free_packet(&packet);

	return 0;
}

static int raise_node_state_ev(enum clusterer_event ev, int cluster_id, int node_id)
{
	int new_state = ev == CLUSTER_NODE_DOWN ? 0 : 1;

	if (evi_param_set_int(ei_clusterid_p, &cluster_id) < 0) {
		LM_ERR("cannot set cluster_id event parameter\n");
		return -1;
	}
	if (evi_param_set_int(ei_nodeid_p, &node_id) < 0) {
		LM_ERR("cannot set node_id event parameter\n");
		return -1;
	}
	if (evi_param_set_int(ei_newstate_p, &new_state) < 0) {
		LM_ERR("cannot set new_state event parameter\n");
		return -1;
	}

	if (evi_raise_event(ei_node_state_id, ei_node_event_params) < 0) {
		LM_ERR("cannot raise event\n");
		return -1;
	}

	return 0;
}

static void do_actions_node_ev(cluster_info_t *clusters, int *select_cluster,
								int no_clusters)
{
	node_info_t *node;
	cluster_info_t *cl;
	struct local_cap *cap_it;
	struct remote_cap *n_cap;
	int k;
	int rc;

	for (k = 0, cl = clusters; k < no_clusters && cl; k++, cl = clusters->next) {
		if (!select_cluster[k])
			continue;

		for (node = cl->node_list; node; node = node->next) {
			lock_get(node->lock);

			if (node->flags	& NODE_EVENT_DOWN) {
				node->flags &= ~NODE_EVENT_DOWN;
				lock_release(node->lock);

				for (cap_it = cl->capabilities; cap_it; cap_it = cap_it->next)
					if (cap_it->reg.event_cb)
						cap_it->reg.event_cb(CLUSTER_NODE_DOWN, node->node_id);

				if (raise_node_state_ev(CLUSTER_NODE_DOWN, cl->cluster_id,
					node->node_id) < 0)
					LM_ERR("Failed to raise node state changed event for: "
						"cluster_id=%d node_id=%d, new_state=node down\n",
						cl->cluster_id, node->node_id);

				shtag_event_handler(cl->cluster_id, CLUSTER_NODE_DOWN,
					node->node_id);

			} else if (node->flags & NODE_EVENT_UP) {
				node->flags &= ~NODE_EVENT_UP;

				/* check pending sync replies */
				for (n_cap = node->capabilities; n_cap; n_cap = n_cap->next) {
					if (n_cap->flags & CAP_SYNC_PENDING) {
						n_cap->flags &= ~CAP_SYNC_PENDING;
						lock_release(node->lock);
						/* reply now that the node is up */
						if (ipc_dispatch_sync_reply(cl, node->node_id,
							&n_cap->name) < 0)
							LM_ERR("Failed to dispatch sync reply job\n");
						lock_get(node->lock);
					}
				}
				lock_release(node->lock);

				for (cap_it = cl->capabilities; cap_it; cap_it = cap_it->next) {
					/* check pending sync request */
					lock_get(cl->lock);
					if (cap_it->flags & CAP_SYNC_PENDING) {
						lock_release(cl->lock);

						if (!match_node(cl->current_node, node,
						                cap_it->reg.sync_cond)) {
							LM_DBG("no match for node id %d\n", node->node_id);
							continue;
						}

						lock_get(node->lock);
						for (n_cap = node->capabilities; n_cap;
							n_cap = n_cap->next) {
							if (!str_strcmp(&cap_it->reg.name, &n_cap->name)) {
								if (n_cap->flags & CAP_STATE_OK) {
									lock_release(node->lock);
									rc = send_sync_req(&n_cap->name,
										cl->cluster_id, node->node_id);
									if (rc == CLUSTERER_SEND_SUCCESS) {
										lock_get(cl->lock);
										cap_it->flags &= ~CAP_SYNC_PENDING;
										lock_release(cl->lock);
									} else if (rc == CLUSTERER_SEND_ERR)
										LM_ERR("Failed to send sync request to"
											"node: %d\n", node->node_id);
									lock_get(node->lock);
								}
							}
						}
						lock_release(node->lock);
					} else
						lock_release(cl->lock);

					if (cap_it->reg.event_cb)
						cap_it->reg.event_cb(CLUSTER_NODE_UP, node->node_id);
				}

				if (raise_node_state_ev(CLUSTER_NODE_UP, cl->cluster_id,
					node->node_id) < 0)
					LM_ERR("Failed to raise node state changed event for: "
						"cluster_id=%d node_id=%d, new_state=node up\n",
						cl->cluster_id, node->node_id);

				shtag_event_handler(cl->cluster_id, CLUSTER_NODE_UP,
					node->node_id);

			} else
				lock_release(node->lock);
		}
	}
}

static void check_node_events(node_info_t *node_s, enum clusterer_event ev)
{
	node_info_t *n;
	int nhop, had_nhop;

	for(n = node_s->cluster->node_list; n; n = n->next) {
		if (n == node_s)
			continue;

		lock_get(n->lock);
		had_nhop = n->next_hop ? 1 : 0;
		lock_release(n->lock);

		nhop = get_next_hop(n);

		lock_get(n->lock);
		if (n->link_state != LS_UP) {
			if(ev == CLUSTER_NODE_DOWN && had_nhop && !nhop)
				n->flags |= NODE_EVENT_DOWN;
			if(ev == CLUSTER_NODE_UP && !had_nhop && nhop)
				n->flags |= NODE_EVENT_UP;
		}
		lock_release(n->lock);
	}
}

static int set_link_w_neigh(clusterer_link_state new_ls, node_info_t *neigh)
{
	node_info_t *nhop;

	LM_DBG("setting link with neighbour [%d] to state <%d>\n",
		neigh->node_id, new_ls);

	lock_get(neigh->lock);

	if (new_ls != LS_UP && neigh->link_state == LS_UP) {
		lock_release(neigh->lock);

		lock_get(neigh->cluster->current_node->lock);
		delete_neighbour(neigh->cluster->current_node, neigh);
		lock_release(neigh->cluster->current_node->lock);

		lock_get(neigh->cluster->lock);
		neigh->cluster->top_version++;
		lock_release(neigh->cluster->lock);

		/* if there is no other path to this neighbour, we check if any other nodes
		 * were reachable only through this link and should be now down */
		nhop = get_next_hop_2(neigh);
		if (!nhop)
			check_node_events(neigh, CLUSTER_NODE_DOWN);

		lock_get(neigh->lock);

		if (!nhop)
			neigh->flags |= NODE_EVENT_DOWN;

	} else if (new_ls == LS_UP && neigh->link_state != LS_UP) {
		lock_release(neigh->lock);

		lock_get(neigh->cluster->current_node->lock);
		if (add_neighbour(neigh->cluster->current_node, neigh) < 0) {
			lock_release(neigh->cluster->current_node->lock);
			LM_ERR("Unable to add neighbour [%d] to topology\n", neigh->node_id);
			return -1;
		}
		lock_release(neigh->cluster->current_node->lock);

		lock_get(neigh->cluster->lock);
		neigh->cluster->top_version++;
		lock_release(neigh->cluster->lock);

		lock_get(neigh->lock);

		/* if there was no other path to this neighbour, we check if any other nodes
		 * are now reachable through this new link */
		if (!neigh->next_hop) {
			neigh->flags |= NODE_EVENT_UP;
			lock_release(neigh->lock);
			check_node_events(neigh, CLUSTER_NODE_UP);
			lock_get(neigh->lock);
		}
		neigh->next_hop = neigh;
	}

	neigh->link_state = new_ls;

	lock_release(neigh->lock);

	return 0;
}

static int set_link_w_neigh_adv(int prev_ls, clusterer_link_state new_ls,
						node_info_t *neigh)
{
	lock_get(neigh->lock);

	if ((prev_ls >= 0 && prev_ls != neigh->link_state) ||
		(prev_ls == -2 && neigh->link_state != LS_UP &&
		neigh->link_state != LS_RESTARTED)) {
		lock_release(neigh->lock);
		return 0;
	}

	if (new_ls != LS_UP && neigh->link_state == LS_UP) {
		lock_release(neigh->lock);

		if (set_link_w_neigh(new_ls, neigh) < 0)
			return -1;

		send_ls_update(neigh, LS_DOWN);
	} else {
		neigh->link_state = new_ls;
		lock_release(neigh->lock);
		LM_DBG("setting link with neighbour [%d] to state <%d>\n",
			neigh->node_id, new_ls);
	}

	return 0;
}

static int set_link_w_neigh_up(node_info_t *neigh, int nr_nodes, int *node_list)
{
	if (set_link_w_neigh(LS_UP, neigh) < 0)
		return -1;

	/* send link state update about this neigbour to the others */
	send_ls_update(neigh, LS_UP);
	/* send topology update to neighbour */
	if (send_full_top_update(neigh, nr_nodes, node_list) < 0)
		return -1;
	/* send capabilities update to neighbour */
	send_cap_update(neigh, 1);

	return 0;
}

static int set_link(clusterer_link_state new_ls, node_info_t *node_a,
						node_info_t *node_b)
{
	int top_change;

	if (new_ls == LS_DOWN) {
		lock_get(node_a->lock);

		if (delete_neighbour(node_a, node_b)) {
			if (node_a->next_hop) {
				lock_release(node_a->lock);

				if (get_next_hop(node_b) == 0) {
					lock_get(node_b->lock);
					node_b->flags |= NODE_EVENT_DOWN;
					lock_release(node_b->lock);

					check_node_events(node_b, CLUSTER_NODE_DOWN);
				}
			} else
				lock_release(node_a->lock);

			lock_get(node_a->cluster->lock);
			node_a->cluster->top_version++;
			lock_release(node_a->cluster->lock);
			LM_DBG("setting link between nodes [%d] and [%d] to state <%d>\n",
				node_a->node_id, node_b->node_id, new_ls);
		} else
			lock_release(node_a->lock);
	} else { /* new_ls == LS_UP */
		lock_get(node_a->lock);

		top_change = add_neighbour(node_a, node_b);
		if (top_change < 0) {
			lock_release(node_a->lock);
			return -1;
		} else if (top_change > 0) {
			if (node_a->next_hop) {
				lock_release(node_a->lock);

				lock_get(node_b->lock);
				if (!node_b->next_hop) {
					node_b->flags |= NODE_EVENT_UP;
					lock_release(node_b->lock);

					check_node_events(node_b, CLUSTER_NODE_UP);

					get_next_hop_2(node_b);
				} else
					lock_release(node_b->lock);
			} else
				lock_release(node_a->lock);

			lock_get(node_a->cluster->lock);
			node_a->cluster->top_version++;
			lock_release(node_a->cluster->lock);
			LM_DBG("setting link between nodes [%d] and [%d] to state <%d>\n",
				node_a->node_id, node_b->node_id, new_ls);
		} else
			lock_release(node_a->lock);
	}

	return 0;
}

int cl_register_cap(str *cap, cl_packet_cb_f packet_cb, cl_event_cb_f event_cb,
             int cluster_id, int startup_sync, enum cl_node_match_op sync_cond)
{
	struct local_cap *new_cl_cap = NULL;
	cluster_info_t *cluster;

	cluster = get_cluster_by_id(cluster_id);
	if (!cluster) {
		LM_ERR("cluster id %d is not defined in the %s\n", cluster_id,
		       db_mode ? "DB" : "script");
		return -1;
	}

	new_cl_cap = shm_malloc(sizeof *new_cl_cap);
	if (!new_cl_cap) {
		LM_ERR("No more shm memory\n");
		return -1;
	}
	memset(new_cl_cap, 0, sizeof *new_cl_cap);

	new_cl_cap->reg.name.len = cap->len;
	new_cl_cap->reg.name.s = cap->s;
	new_cl_cap->reg.sync_cond = sync_cond;
	new_cl_cap->reg.packet_cb = packet_cb;
	new_cl_cap->reg.event_cb = event_cb;

	if (!startup_sync)
		new_cl_cap->flags |= CAP_STATE_OK;

	new_cl_cap->next = cluster->capabilities;
	cluster->capabilities = new_cl_cap;

	bin_register_cb(cap, bin_rcv_mod_packets, &new_cl_cap->reg,
		sizeof new_cl_cap->reg);

	LM_DBG("Registered capability: %.*s\n", cap->len, cap->s);

	return 0;
}

struct local_cap *dup_caps(struct local_cap *caps)
{
	struct local_cap *cap, *ret = NULL;

	for (; caps; caps = caps->next) {
		cap = shm_malloc(sizeof *cap);
		if (!cap) {
			LM_ERR("No more shm memory\n");
			return NULL;
		}
		memcpy(cap, caps, sizeof *caps);

		cap->next = NULL;

		add_last(cap, ret);
	}

	return ret;
}

int preserve_reg_caps(cluster_info_t *new_info)
{
	cluster_info_t *cl, *new_cl;

	for (cl = *cluster_list; cl; cl = cl->next)
		for (new_cl = new_info; new_cl; new_cl = new_cl->next)
			if (new_cl->cluster_id == cl->cluster_id && cl->capabilities) {
				new_cl->capabilities = dup_caps(cl->capabilities);
				if (!new_cl->capabilities) {
					LM_ERR("Failed to duplicate capabilities info\n");
					return -1;
				}
			}

	return 0;
}

int gen_rcv_evs_init(void)
{
	/* publish the events */
	ei_req_rcv_id = evi_publish_event(ei_req_rcv_name);
	if (ei_req_rcv_id == EVI_ERROR) {
		LM_ERR("cannot register message received event\n");
		return -1;
	}
	ei_rpl_rcv_id = evi_publish_event(ei_rpl_rcv_name);
	if (ei_rpl_rcv_id == EVI_ERROR) {
		LM_ERR("cannot register reply received event\n");
		return -1;
	}

	ei_event_params = pkg_malloc(sizeof(evi_params_t));
	if (ei_event_params == NULL) {
		LM_ERR("no more pkg mem\n");
		return -1;
	}
	memset(ei_event_params, 0, sizeof(evi_params_t));

	ei_clid_p = evi_param_create(ei_event_params, &ei_clid_pname);
	if (ei_clid_p == NULL)
		goto create_error;
	ei_srcid_p = evi_param_create(ei_event_params, &ei_srcid_pname);
	if (ei_srcid_p == NULL)
		goto create_error;
	ei_msg_p = evi_param_create(ei_event_params, &ei_msg_pname);
	if (ei_msg_p == NULL)
		goto create_error;
	ei_tag_p = evi_param_create(ei_event_params, &ei_tag_pname);
	if (ei_tag_p == NULL)
		goto create_error;

	return 0;

create_error:
	LM_ERR("cannot create event parameter\n");
	return -1;
}

int node_state_ev_init(void)
{
	/* publish the events */
	ei_node_state_id = evi_publish_event(ei_node_state_name);
	if (ei_node_state_id == EVI_ERROR) {
		LM_ERR("cannot register node state changed event\n");
		return -1;
	}

	ei_node_event_params = pkg_malloc(sizeof(evi_params_t));
	if (ei_node_event_params == NULL) {
		LM_ERR("no more pkg mem\n");
		return -1;
	}
	memset(ei_node_event_params, 0, sizeof(evi_params_t));

	ei_clusterid_p = evi_param_create(ei_node_event_params, &ei_clusterid_pname);
	if (ei_clusterid_p == NULL)
		goto create_error;

	ei_nodeid_p = evi_param_create(ei_node_event_params, &ei_nodeid_pname);
	if (ei_nodeid_p == NULL)
		goto create_error;

	ei_newstate_p = evi_param_create(ei_node_event_params, &ei_newstate_pname);
	if (ei_newstate_p == NULL)
		goto create_error;

	return 0;

create_error:
	LM_ERR("cannot create event parameter\n");
	return -1;
}

void gen_rcv_evs_destroy(void)
{
	evi_free_params(ei_event_params);
}

void node_state_ev_destroy(void)
{
	evi_free_params(ei_node_event_params);
}
