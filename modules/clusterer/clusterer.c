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
#include "../../mi/tree.h"

#include "api.h"
#include "node_info.h"
#include "clusterer.h"

struct clusterer_binds clusterer_api;

struct mod_registration *clusterer_reg_modules;
enum sip_protos clusterer_proto = PROTO_BIN;

extern int ping_interval;
extern int node_timeout;
extern int ping_timeout;

static event_id_t ei_req_rcv_id = EVI_ERROR;
static event_id_t ei_rpl_rcv_id = EVI_ERROR;
static str ei_req_rcv_name = str_init("E_CLUSTERER_REQ_RECEIVED");
static str ei_rpl_rcv_name = str_init("E_CLUSTERER_RPL_RECEIVED");

static evi_params_p ei_event_params;
static evi_param_p ei_clid_p, ei_srcid_p, ei_msg_p, ei_tag_p;
static str ei_clid_pname = str_init("cluster_id");
static str ei_srcid_pname = str_init("src_id");
static str ei_msg_pname = str_init("msg");
static str ei_tag_pname = str_init("tag");

static int set_link(clusterer_link_state new_ls, node_info_t *node_a,
						node_info_t *node_b);
static int set_link_w_neigh(clusterer_link_state new_ls, node_info_t *neigh);
static int set_link_w_neigh_adv(clusterer_link_state new_ls, node_info_t *neigh);
static int set_link_w_neigh_up(node_info_t *neigh, int nr_nodes, int *node_list);
static void call_cbs_event(bin_packet_t *,cluster_info_t *clusters,
							int *clusters_to_call, int no_clusters);

/* actions to be done for the transitions of the simple 'state machine' used for
 * establishing the link states with the other nodes */

static void do_action_trans_0(node_info_t *node, int *link_state_to_set)
{
	struct timeval now;
	static str module_name = str_init("clusterer");
	str send_buffer;
	bin_packet_t packet;

	gettimeofday(&now, NULL);

	node->last_ping = now;

	if (bin_init(&packet, &module_name, CLUSTERER_PING, BIN_VERSION, SMALL_MSG) < 0) {
		LM_ERR("Failed to init bin send buffer\n");
		return;
	}
	bin_push_int(&packet, node->cluster->cluster_id);
	bin_push_int(&packet, current_id);
	bin_push_int(&packet, 1);	/* request list of known nodes */
	bin_get_buffer(&packet, &send_buffer);

	if (msg_send(NULL, clusterer_proto, &node->addr, 0, send_buffer.s,
		send_buffer.len, 0) < 0) {
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

	bin_free_packet(&packet);
}

static void do_action_trans_1(node_info_t *node, int *link_state_to_set)
{
	struct timeval now;
	static str module_name = str_init("clusterer");
	str send_buffer;
	bin_packet_t packet;

	gettimeofday(&now, NULL);

	node->last_ping = now;
	node->curr_no_retries--;

	if (bin_init(&packet, &module_name, CLUSTERER_PING, BIN_VERSION, SMALL_MSG) < 0) {
		LM_ERR("Failed to init bin send buffer\n");
		return;
	}
	bin_push_int(&packet, node->cluster->cluster_id);
	bin_push_int(&packet, current_id);
	bin_push_int(&packet, 1);	/* request list of known nodes */
	bin_get_buffer(&packet, &send_buffer);

	if (msg_send(NULL, clusterer_proto, &node->addr, 0, send_buffer.s,
		send_buffer.len, 0) < 0) {
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

	bin_free_packet(&packet);
}

static void do_action_trans_2(node_info_t *node, int *link_state_to_set)
{
	struct timeval now;
	static str module_name = str_init("clusterer");
	str send_buffer;
	bin_packet_t packet;

	gettimeofday(&now, NULL);

	if (node->no_ping_retries == 0) {
		*link_state_to_set = LS_DOWN;
		LM_INFO("Pong not received, node [%d] is down\n", node->node_id);
	} else {
		LM_INFO("Pong not received, node [%d] is possibly down, retrying\n",
			node->node_id);
		node->last_ping = now;

		if (bin_init(&packet, &module_name, CLUSTERER_PING, BIN_VERSION, SMALL_MSG) < 0) {
			LM_ERR("Failed to init bin send buffer\n");
			return;
		}
		bin_push_int(&packet, node->cluster->cluster_id);
		bin_push_int(&packet, current_id);
		bin_push_int(&packet, 1);	/* request list of known nodes */
		bin_get_buffer(&packet, &send_buffer);

		if (msg_send(NULL, clusterer_proto, &node->addr, 0, send_buffer.s,
			send_buffer.len, 0) < 0) {
			LM_ERR("Failed to send ping to node [%d]\n", node->node_id);
			node->curr_no_retries = node->no_ping_retries;
			*link_state_to_set = LS_RETRY_SEND_FAIL;
		} else {
			LM_DBG("Sent ping retry to node [%d]\n", node->node_id);
			*link_state_to_set = LS_RETRYING;
			node->curr_no_retries = --node->no_ping_retries;
		}

		bin_free_packet(&packet);
	}
}

static void do_action_trans_3(node_info_t *node, int *link_state_to_set)
{
	struct timeval now;
	static str module_name = str_init("clusterer");
	str send_buffer;
	bin_packet_t packet;

	gettimeofday(&now, NULL);

	if (node->curr_no_retries > 0) {
		node->last_ping = now;

		if (bin_init(&packet, &module_name, CLUSTERER_PING, BIN_VERSION, SMALL_MSG) < 0) {
			LM_ERR("Failed to init bin send buffer\n");
			return;
		}
		bin_push_int(&packet, node->cluster->cluster_id);
		bin_push_int(&packet, current_id);
		bin_push_int(&packet, 1);	/* request list of known nodes */
		bin_get_buffer(&packet, &send_buffer);

		if (msg_send(NULL, clusterer_proto, &node->addr, 0, send_buffer.s,
			send_buffer.len, 0) < 0) {
			LM_ERR("Failed to send ping retry to node [%d]\n",
				node->node_id);
			*link_state_to_set = LS_RETRY_SEND_FAIL;
		} else {
			LM_DBG("Sent ping retry to node [%d]\n", node->node_id);
			node->curr_no_retries--;
		}

		bin_free_packet(&packet);
	} else {
		*link_state_to_set = LS_DOWN;
		LM_INFO("Pong not received, node [%d] is down\n", node->node_id);
	}
}

static void do_action_trans_4(node_info_t *node, int *link_state_to_set)
{
	struct timeval now;
	static str module_name = str_init("clusterer");
	str send_buffer;
	bin_packet_t packet;

	gettimeofday(&now, NULL);

	LM_INFO("Node timeout passed, restart pinging node [%d]\n",
		node->node_id);

	node->last_ping = now;

	if (bin_init(&packet, &module_name, CLUSTERER_PING, BIN_VERSION, SMALL_MSG) < 0) {
		LM_ERR("Failed to init bin send buffer\n");
		return;
	}
	bin_push_int(&packet, node->cluster->cluster_id);
	bin_push_int(&packet, current_id);
	bin_push_int(&packet, 1);	/* request list of known nodes */
	bin_get_buffer(&packet, &send_buffer);

	if (msg_send(NULL, clusterer_proto, &node->addr, 0, send_buffer.s,
		send_buffer.len, 0) < 0) {
		LM_ERR("Failed to send ping to node [%d]\n", node->node_id);
		if (node->no_ping_retries != 0) {
			node->curr_no_retries = node->no_ping_retries;
			*link_state_to_set = LS_RETRY_SEND_FAIL;
		}
	} else {
		*link_state_to_set = LS_RESTARTED;
		LM_DBG("Sent ping to node [%d]\n", node->node_id);
	}

	bin_free_packet(&packet);
}

static void do_action_trans_5(node_info_t *node, int *link_state_to_set,
								int *check_call_cbs_event, int no_clusters)
{
	struct timeval now;
	static str module_name = str_init("clusterer");
	str send_buffer;
	bin_packet_t packet;

	gettimeofday(&now, NULL);

	node->last_ping = now;

	if (bin_init(&packet, &module_name, CLUSTERER_PING, BIN_VERSION, SMALL_MSG) < 0) {
		LM_ERR("Failed to init bin send buffer\n");
		return;
	}
	bin_push_int(&packet, node->cluster->cluster_id);
	bin_push_int(&packet, current_id);
	bin_push_int(&packet, 0);	/* don't request list of known nodes */
	bin_get_buffer(&packet, &send_buffer);

	if (msg_send(NULL, clusterer_proto, &node->addr, 0, send_buffer.s,
		send_buffer.len, 0) < 0) {
		LM_ERR("Failed to send ping to node [%d]\n", node->node_id);
		if (node->no_ping_retries == 0)
			*link_state_to_set = LS_DOWN;
		else {
			node->curr_no_retries = node->no_ping_retries;
			*link_state_to_set = LS_RETRY_SEND_FAIL;
		}
		check_call_cbs_event[no_clusters] = 1;
	} else
		LM_DBG("Sent ping to node [%d]\n", node->node_id);

	bin_free_packet(&packet);
}

void heartbeats_timer(void)
{
	struct timeval now;
	utime_t last_ping_int, ping_reply_int;
	cluster_info_t *clusters_it;
	node_info_t *node;
	int check_call_cbs_event[MAX_NO_CLUSTERS] = {0};
	int no_clusters = 0;
	int action_trans;
	int link_state_to_set;

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
			ping_reply_int = node->last_pong.tv_sec*1000000 + node->last_pong.tv_usec
							- node->last_ping.tv_sec*1000000 - node->last_ping.tv_usec;
			last_ping_int = now.tv_sec*1000000 + now.tv_usec
							- node->last_ping.tv_sec*1000000 - node->last_ping.tv_usec;

			action_trans = -1;

			if (node->link_state == LS_RESTART_PINGING)
				/* restart pinging sequence */
				action_trans = 0;
			else if (node->link_state == LS_RETRY_SEND_FAIL &&
				last_ping_int >= (utime_t)ping_timeout*1000)
				/* failed to send previous ping, retry */
				action_trans = 1;
			else if ((node->link_state == LS_UP || node->link_state == LS_RESTARTED) &&
				(ping_reply_int >= (utime_t)ping_timeout*1000 || ping_reply_int <= 0) &&
				last_ping_int >= (utime_t)ping_timeout*1000)
				/* send first ping retry */
				action_trans = 2;
			else if (node->link_state == LS_RETRYING &&
				(ping_reply_int >= (utime_t)ping_timeout*1000 || ping_reply_int <= 0) &&
				last_ping_int >= (utime_t)ping_timeout*1000)
				/* previous ping retry not replied, continue to retry */
				action_trans = 3;
			else if (node->link_state == LS_DOWN &&
				last_ping_int >= (utime_t)node_timeout*1000000)
				/* ping a failed node after node_timeout since last ping */
				action_trans = 4;
			else if (node->link_state == LS_UP &&
				last_ping_int >= (utime_t)ping_interval*1000000)
				/* send regular ping */
				action_trans = 5;

			lock_release(node->lock);

			link_state_to_set = -1;

			switch (action_trans) {
				case 0:
					do_action_trans_0(node, &link_state_to_set);

					lock_get(node->lock);
					if (node->link_state != LS_RESTART_PINGING) {
						lock_release(node->lock);
						continue;
					}
					lock_release(node->lock);
					break;
				case 1:
					do_action_trans_1(node, &link_state_to_set);

					lock_get(node->lock);
					if (node->link_state != LS_RETRY_SEND_FAIL) {
						lock_release(node->lock);
						continue;
					}
					lock_release(node->lock);
					break;
				case 2:
					do_action_trans_2(node, &link_state_to_set);
					check_call_cbs_event[no_clusters] = 1;

					lock_get(node->lock);
					if (node->link_state != LS_UP && node->link_state != LS_RESTARTED) {
						lock_release(node->lock);
						continue;
					}
					lock_release(node->lock);
					break;
				case 3:
					do_action_trans_3(node, &link_state_to_set);

					lock_get(node->lock);
					if (node->link_state != LS_RETRYING) {
						lock_release(node->lock);
						continue;
					}
					lock_release(node->lock);
					break;
				case 4:
					do_action_trans_4(node, &link_state_to_set);

					lock_get(node->lock);
					if (node->link_state != LS_DOWN) {
						lock_release(node->lock);
						continue;
					}
					lock_release(node->lock);
					break;
				case 5:
					do_action_trans_5(node, &link_state_to_set, check_call_cbs_event,
						no_clusters);

					lock_get(node->lock);
					if (node->link_state != LS_UP) {
						lock_release(node->lock);
						continue;
					}
					lock_release(node->lock);
					break;
				default:
					continue;
			}

			if (link_state_to_set >= 0)
				set_link_w_neigh_adv(link_state_to_set, node);
		}

		no_clusters++;
	}

	call_cbs_event(NULL, *cluster_list, check_call_cbs_event, no_clusters);

	lock_stop_read(cl_list_lock);
}

int cl_set_state(int cluster_id, enum cl_node_state state)
{
	cluster_info_t *cluster = NULL;
	node_info_t *node;
	int check_call_cbs_event = 1;
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

		call_cbs_event(NULL, cluster, &check_call_cbs_event, 1);
	} else if (new_link_states == LS_RESTART_PINGING) {
		for (node = cluster->node_list; node; node = node->next)
			set_link_w_neigh(LS_RESTART_PINGING, node);
	}

	lock_stop_read(cl_list_lock);

	LM_INFO("Set state: %s for current node in cluster: %d\n",
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

/* compute the next hop in the path to the given destination node, according to the
 * local 'routing table', looking for paths of at least 2 links
 * @return:
 *  	> 0: next hop id
 * 		0  : no other path(node is down)
 *		< 0: error
 */
static int get_next_hop_2(node_info_t *dest)
{
	node_info_t *n;
	struct node_search_info *queue_front;
    struct node_search_info *root, *curr;
    struct neighbour *neigh;
    int nhop_id;

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
					return -1;
				}

				while (curr->parent->parent)
					curr = curr->parent;
				if (curr->parent != root) {
					lock_release(dest->cluster->lock);
					return -1;
				}

				lock_get(dest->lock);
				dest->next_hop = curr->node;
				nhop_id = dest->next_hop->node_id;
				lock_release(dest->lock);

				lock_release(dest->cluster->lock);

				return nhop_id;
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
	if (dest->next_hop)
		nhop_id = dest->next_hop->node_id;
	else
		nhop_id = 0;
	lock_release(dest->lock);

	lock_release(dest->cluster->lock);

	return nhop_id;
}

/* @return:
 *  	> 0: next hop id
 * 		0  : no other path(node is down)
 *		< 0: error
 */
int get_next_hop(node_info_t *dest)
{
	lock_get(dest->lock);

	if (dest->link_state == LS_UP) {
		dest->next_hop = dest;

		lock_release(dest->lock);

		return dest->node_id;
	} else {
		lock_release(dest->lock);

		return get_next_hop_2(dest);
	}
}

/* @return:
 *  0 : success, message sent
 * -1 : error, unable to send
 * -2 : dest down or probing
 */
static int msg_send_retry(bin_packet_t *packet, node_info_t *dest, int change_dest,
							int *check_call_cbs_event)
{
	int retr_send = 0;
	node_info_t *chosen_dest = dest;
	str send_buffer;

	do {
		lock_get(chosen_dest->lock);

		if (chosen_dest->link_state != LS_UP) {
			lock_release(chosen_dest->lock);

			if (get_next_hop_2(dest) <= 0) {
				if (retr_send)
					return -1;
				else
					return -2;
			} else {
				lock_get(dest->lock);
				chosen_dest = dest->next_hop;
				lock_release(dest->lock);
			}
		} else
			lock_release(chosen_dest->lock);

		/* change destination node id */
		if (change_dest || chosen_dest != dest) {
			bin_remove_int_buffer_end(packet, 1);
			bin_push_int(packet, dest->node_id);
		}
		bin_get_buffer(packet, &send_buffer);

		if (msg_send(NULL, clusterer_proto, &chosen_dest->addr, 0, send_buffer.s,
				send_buffer.len, 0) < 0) {
			LM_ERR("msg_send() to node [%d] failed\n", chosen_dest->node_id);
			retr_send = 1;

			/* this node was supposed to be up, retry pinging */
			set_link_w_neigh_adv(LS_RESTART_PINGING, chosen_dest);

			*check_call_cbs_event = 1;
		} else {
			LM_DBG("sent bin packet to node [%d]\n", chosen_dest->node_id);
			retr_send = 0;
		}
	} while (retr_send);

	return 0;
}

enum clusterer_send_ret clusterer_send_msg(bin_packet_t *packet,
											int cluster_id, int dst_id)
{
	node_info_t *node;
	int rc;
	cluster_info_t *cl;
	int check_call_cbs_event = 0;

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

	node = get_node_by_id(cl, dst_id);
	if (!node) {
		LM_ERR("Node id [%d] not found in cluster\n", dst_id);
		lock_stop_read(cl_list_lock);
		return CLUSTERER_SEND_ERR;
	}

	rc = msg_send_retry(packet, node, 0, &check_call_cbs_event);

	bin_remove_int_buffer_end(packet, 3);

	if (check_call_cbs_event)
		call_cbs_event(packet ,cl, &check_call_cbs_event, 1);

	lock_stop_read(cl_list_lock);

	switch (rc) {
	case  0:
		return CLUSTERER_SEND_SUCCES;
	case -1:
		return CLUSTERER_SEND_ERR;
	case -2:
		return CLUSTERER_DEST_DOWN;
	}

	return CLUSTERER_SEND_ERR;
}

enum clusterer_send_ret clusterer_bcast_msg(bin_packet_t *packet, int cluster_id)
{
	node_info_t *node;
	int rc, sent = 0, down = 1;
	cluster_info_t *cl;
	int check_call_cbs_event = 0;

	if (!cl_list_lock) {
		LM_ERR("cluster shutdown - cannot send new messages!\n");
		return CLUSTERER_CURR_DISABLED;
	}
	lock_start_read(cl_list_lock);

	cl = get_cluster_by_id(cluster_id);
	if (!cl) {
		LM_ERR("Unknown cluster, id [%d]\n", cluster_id);
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

	for (node = cl->node_list; node; node = node->next) {
		rc = msg_send_retry(packet, node, 1, &check_call_cbs_event);
		if (rc != -2)	/* at least one node is up */
			down = 0;
		if (rc == 0)	/* at least one message is sent successfuly*/
			sent = 1;
	}

	bin_remove_int_buffer_end(packet, 3);

	if (check_call_cbs_event)
		call_cbs_event(packet, cl, &check_call_cbs_event, 1);

	lock_stop_read(cl_list_lock);

	if (down)
		return CLUSTERER_DEST_DOWN;
	if (sent)
		return CLUSTERER_SEND_SUCCES;
	else
		return CLUSTERER_SEND_ERR;
}

static inline int msg_add_trailer(bin_packet_t *packet, int cluster_id, int dst_id)
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
	static str module_name = str_init("clusterer");

	/* build packet */
	if (bin_init(packet, &module_name, CLUSTERER_GENERIC_MSG, BIN_VERSION, 0) < 0) {
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

	return clusterer_bcast_msg(packet, cluster_id);
}

enum clusterer_send_ret send_gen_msg(int cluster_id, int dst_id, str *gen_msg,
										str *exchg_tag, int req_like)
{
	bin_packet_t packet;

	if (prep_gen_msg(&packet, cluster_id, dst_id, gen_msg, exchg_tag, req_like) < 0) {
		LM_ERR("Failed to build generic clusterer message\n");
		return CLUSTERER_SEND_ERR;
	}

	return clusterer_send_msg(&packet, cluster_id, dst_id);
}

enum clusterer_send_ret bcast_gen_msg(int cluster_id, str *gen_msg, str *exchg_tag)
{
	bin_packet_t packet;

	if (prep_gen_msg(&packet, cluster_id, -1 /* dummy value */, gen_msg,
			exchg_tag, 1) < 0) {
		LM_ERR("Failed to build generic clusterer message\n");
		return CLUSTERER_SEND_ERR;
	}

	return clusterer_bcast_msg(&packet, cluster_id);
}

enum clusterer_send_ret send_mi_cmd(int cluster_id, int dst_id, str cmd_name,
										str *cmd_params, int no_params)
{
	static str module_name = str_init("clusterer");
	bin_packet_t packet;
	int i;

	if (bin_init(&packet, &module_name, CLUSTERER_MI_CMD, BIN_VERSION, 0) < 0) {
		LM_ERR("Failed to init bin send buffer\n");
		return CLUSTERER_SEND_ERR;
	}

	if (bin_push_str(&packet, &cmd_name) < 0)
		return CLUSTERER_SEND_ERR;
	if (bin_push_int(&packet, no_params) < 0)
		return CLUSTERER_SEND_ERR;
	for (i = 0; i < no_params; i++)
		if (bin_push_str(&packet, &cmd_params[i]) < 0)
			return CLUSTERER_SEND_ERR;

	if (msg_add_trailer(&packet, cluster_id, dst_id ? dst_id : -1) < 0) {
		LM_ERR("Failed to add trailer to module's message\n");
		return CLUSTERER_SEND_ERR;
	}

	if (dst_id)
		return clusterer_send_msg(&packet, cluster_id, dst_id);
	else
		return clusterer_bcast_msg(&packet, cluster_id);
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

static int ip_check(cluster_info_t *cluster, union sockaddr_union *su)
{
	node_info_t *node;

	for (node = cluster->node_list; node; node = node->next)
		if (su_ip_cmp(su, &node->addr))
			return 1;
	return 0;
}

int clusterer_check_addr(int cluster_id, union sockaddr_union *su)
{
	cluster_info_t *cluster;
	int rc;

	lock_start_read(cl_list_lock);
	cluster = get_cluster_by_id(cluster_id);
	if (!cluster) {
		LM_WARN("Unknown cluster id [%d]\n", cluster_id);
		return 0;
	}
	rc = ip_check(cluster, su);
	lock_stop_read(cl_list_lock);

	return rc;
}

static int flood_message(bin_packet_t *packet, cluster_info_t *cluster,
							int source_id)
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
		if (msg_send(NULL, clusterer_proto, &destinations[i]->addr, 0, bin_buffer.s,
			bin_buffer.len, 0) < 0) {
			LM_ERR("Failed to flood message to node [%d]\n",
				destinations[i]->node_id);

			/* this node was supposed to be up, restart pinging */
			set_link_w_neigh_adv(LS_RESTART_PINGING, destinations[i]);
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
	char *char_str_vals[NO_DB_STR_VALS];
	node_info_t *new_node = NULL;
	int lock_old_flag;

	char_str_vals[STR_VALS_URL_COL] = shm_malloc(str_vals[STR_VALS_URL_COL].len+1);
	memcpy(char_str_vals[STR_VALS_URL_COL],
		str_vals[STR_VALS_URL_COL].s, str_vals[STR_VALS_URL_COL].len);
	char_str_vals[STR_VALS_URL_COL][str_vals[STR_VALS_URL_COL].len] = 0;

	char_str_vals[STR_VALS_SIP_ADDR_COL] = shm_malloc(str_vals[STR_VALS_SIP_ADDR_COL].len+1);
	memcpy(char_str_vals[STR_VALS_SIP_ADDR_COL],
		str_vals[STR_VALS_SIP_ADDR_COL].s, str_vals[STR_VALS_SIP_ADDR_COL].len);
	char_str_vals[STR_VALS_SIP_ADDR_COL][str_vals[STR_VALS_SIP_ADDR_COL].len] = 0;

	char_str_vals[STR_VALS_DESCRIPTION_COL] = 0;

	int_vals[INT_VALS_ID_COL] = -1;	/* no DB id */
	int_vals[INT_VALS_CLUSTER_ID_COL] = cl->cluster_id;
	int_vals[INT_VALS_NODE_ID_COL] = src_node_id;
	int_vals[INT_VALS_STATE_COL] = 1;	/* enabled */

	lock_switch_write(cl_list_lock, lock_old_flag);

	if (add_node_info(&new_node, &cl, int_vals, char_str_vals) != 0) {
		LM_ERR("Unable to add node info to backing list\n");
		lock_switch_read(cl_list_lock, lock_old_flag);
		return NULL;
	}
	if (!new_node) {
		LM_ERR("Unable to add node info to backing list\n");
		lock_switch_read(cl_list_lock, lock_old_flag);
		return NULL;
	}
	shm_free(char_str_vals[STR_VALS_URL_COL]);
	shm_free(char_str_vals[STR_VALS_SIP_ADDR_COL]);

	lock_switch_read(cl_list_lock, lock_old_flag);

	return new_node;
}

static void handle_full_top_update(bin_packet_t *packet, node_info_t *source,
									int *check_call_cbs_event)
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
					*check_call_cbs_event = 1;
				} else
					lock_release(top_node->lock);
			} else {
				set_link(LS_UP, top_node, top_neigh);
				*check_call_cbs_event = 1;

				/* save the node in order to identify neighbours which are missing
				 * from the adjacency list and thus represent failed links */
				present_nodes[no_present_nodes++] = top_neigh->node_id;
			}
		}

		/* search the saved nodes to delete the corresponding links */
		for (it = source->cluster->node_list; it; it = it->next) {
			if (it->node_id == top_node_id[i])
				continue;

			present = 0;
			for (j = 0; j < no_present_nodes; j++)
				if (it->node_id == present_nodes[j]) {
					present = 1;
					break;
				}
			if (!present) {
				set_link(LS_DOWN, top_node, it);
				*check_call_cbs_event = 1;
			}
		}
	}

	flood_message(packet, source->cluster, source->node_id);
}

static void handle_internal_msg_unknown(bin_packet_t *received, cluster_info_t *cl,
					int packet_type, union sockaddr_union *src_su, int src_node_id)
{
	static str module_name = str_init("clusterer");
	str bin_buffer;
	int req_list;
	str str_vals[NO_DB_STR_VALS];
	int int_vals[NO_DB_INT_VALS];

	bin_packet_t packet;

	switch (packet_type) {
	case CLUSTERER_PING:
		bin_pop_int(received, &req_list);

		/* reply in order to inform the node that the current node has no info about it */
		if (bin_init(&packet, &module_name, CLUSTERER_UNKNOWN_ID, BIN_VERSION, SMALL_MSG) < 0) {
			LM_ERR("Failed to init bin send buffer\n");
			return;
		}
		bin_push_int(&packet, cl->cluster_id);
		bin_push_int(&packet, current_id);
		bin_get_buffer(&packet, &bin_buffer);

		if (msg_send(NULL, clusterer_proto, src_su, 0, bin_buffer.s,
			bin_buffer.len, 0) < 0)
			LM_ERR("Failed to reply to ping from unknown node, id [%d]\n", src_node_id);
		else
			LM_DBG("Replied to ping from unknown node, id [%d]\n", src_node_id);

		bin_free_packet(&packet);
		break;
	case CLUSTERER_NODE_DESCRIPTION:
		LM_DBG("Received node descripiton from sorce [%d]\n", src_node_id);

		bin_pop_str(received, &str_vals[STR_VALS_URL_COL]);
		bin_pop_str(received, &str_vals[STR_VALS_SIP_ADDR_COL]);
		bin_pop_int(received, &int_vals[INT_VALS_PRIORITY_COL]);
		bin_pop_int(received, &int_vals[INT_VALS_NO_PING_RETRIES_COL]);
		add_node(received, cl, src_node_id, str_vals, int_vals);

		flood_message(received, cl, src_node_id);
		break;
	default:
		LM_DBG("Ignoring message, type: %d from unknown source, id [%d]\n",
			packet_type, src_node_id);
	}
}

static void handle_ls_update(bin_packet_t *received, node_info_t *src_node,
								int *check_call_cbs_event)
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

			set_link_w_neigh_adv(LS_RESTART_PINGING, src_node);
			*check_call_cbs_event = 1;
		} else
			lock_release(src_node->lock);
	} else {
		lock_release(src_node->lock);

		set_link(new_ls, src_node, ls_neigh);

		*check_call_cbs_event = 1;
	}

	flood_message(received, src_node->cluster, src_node->node_id);
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
	static str module_name = str_init("clusterer");

	/* send description */
	if (bin_init(&packet, &module_name, CLUSTERER_NODE_DESCRIPTION,
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
	if (msg_send(NULL, clusterer_proto, &src_node->addr, 0, bin_buffer.s,
		bin_buffer.len, 0) < 0)
		LM_ERR("Failed to send node description to node [%d]\n", src_node->node_id);
	else
		LM_DBG("Sent node description to node [%d]\n", src_node->node_id);
	bin_free_packet(&packet);

	set_link_w_neigh_adv(LS_RESTART_PINGING, src_node);
}

static void handle_internal_msg(bin_packet_t *received, int packet_type,
		node_info_t *src_node, struct timeval rcv_time, int *check_call_cbs_event)
{
	node_info_t *it;
	static str module_name = str_init("clusterer");
	str bin_buffer;
	int send_rc;
	int set_ls_restart = 0;
	int req_list;
	int node_list[MAX_NO_NODES], i, nr_nodes;
	bin_packet_t packet;

	switch (packet_type) {
	case CLUSTERER_PONG:
		LM_DBG("Received pong from node [%d]\n", src_node->node_id);

		bin_pop_int(received, &nr_nodes);
		for (i=0; i<nr_nodes; i++)
			bin_pop_int(received, &node_list[i]);

		lock_get(src_node->lock);

		src_node->last_pong = rcv_time;

		/* if the node was retried and a reply was expected, it should be UP again */
		if (src_node->link_state == LS_RESTARTED || src_node->link_state == LS_RETRYING) {
			lock_release(src_node->lock);

			set_link_w_neigh_up(src_node, nr_nodes, node_list);
			*check_call_cbs_event = 1;

			LM_INFO("Node [%d] is UP\n", src_node->node_id);
		} else
			lock_release(src_node->lock);

		break;
	case CLUSTERER_PING:
		bin_pop_int(received, &req_list);

		/* reply with pong */
		if (bin_init(&packet, &module_name, CLUSTERER_PONG, BIN_VERSION, SMALL_MSG) < 0) {
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

		send_rc = msg_send(NULL, clusterer_proto, &src_node->addr, 0, bin_buffer.s,
			bin_buffer.len, 0);

		lock_get(src_node->lock);

		if (send_rc < 0) {
			LM_ERR("Failed to reply to ping from node [%d]\n", src_node->node_id);
			if (src_node->link_state == LS_UP) {
				set_ls_restart = 1;
				*check_call_cbs_event = 1;
			}
		} else
			LM_DBG("Replied to ping from node [%d]\n", src_node->node_id);

		/* if the node was down, restart pinging */
		if (src_node->link_state == LS_DOWN) {
			LM_DBG("Received ping from failed node, restart pinging\n");
			set_ls_restart = 1;
		}

		lock_release(src_node->lock);

		if (set_ls_restart)
			set_link_w_neigh_adv(LS_RESTART_PINGING, src_node);

		bin_free_packet(&packet);
		break;
	case CLUSTERER_LS_UPDATE:
		handle_ls_update(received, src_node, check_call_cbs_event);
		break;
	case CLUSTERER_FULL_TOP_UPDATE:
		LM_DBG("Received full topology update with source [%d]\n", src_node->node_id);
		handle_full_top_update(received, src_node, check_call_cbs_event);
		break;
	case CLUSTERER_UNKNOWN_ID:
		LM_DBG("Received UNKNOWN_ID from node [%d]\n", src_node->node_id);
		handle_unknown_id(src_node);
		break;
	case CLUSTERER_NODE_DESCRIPTION:
		LM_DBG("Already got node descripiton for source [%d], drop this message\n",
			src_node->node_id);
		break;
	default:
		LM_WARN("Invalid clusterer binary packet command from node: %d\n",
			src_node->node_id);
	}
}

static void handle_cl_gen_msg(bin_packet_t *packet)
{
	int req_like;
	str rcv_msg, rcv_tag;
	int cluster_id, source_id;

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
	struct mi_root *cmd_rpl;

	bin_pop_str(packet, &cmd_name);
	LM_DBG("Received MI command <%.*s>\n", cmd_name.len, cmd_name.s);

	bin_pop_int(packet, &no_params);
	for (i = 0; i < no_params; i++)
		bin_pop_str(packet, &cmd_params[i]);

	cmd_rpl = run_rcv_mi_cmd(&cmd_name, cmd_params, no_params);
	if (!cmd_rpl) {
		LM_ERR("MI command <%.*s> failed\n", cmd_name.len, cmd_name.s);
		return;
	}

	LM_INFO("MI command <%.*s> returned with: code <%d>, reason <%.*s>\n",
		cmd_name.len, cmd_name.s, cmd_rpl->code, cmd_rpl->reason.len, cmd_rpl->reason.s);
}

static void handle_other_cl_msg(bin_packet_t *packet, int packet_type)
{
	int source_id, dest_id, cluster_id;
	cluster_info_t *cl;
	node_info_t *node;
	int check_call_cbs_event = 0;

	bin_pop_back_int(packet, &dest_id);
	bin_pop_back_int(packet, &source_id);
	bin_pop_back_int(packet, &cluster_id);

	lock_start_read(cl_list_lock);

	cl = get_cluster_by_id(cluster_id);
	if (!cl) {
		LM_WARN("Received message from unknown cluster, id [%d]\n", cluster_id);
		goto exit;
	}

	lock_get(cl->current_node->lock);
	if (!(cl->current_node->flags & NODE_STATE_ENABLED)) {
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

		if (msg_send_retry(packet, node, 0, &check_call_cbs_event) < 0) {
			LM_ERR("Failed to route message with source id [%d] and destination id [%d]\n",
				source_id, dest_id);
			if (check_call_cbs_event)
				call_cbs_event(packet, cl, &check_call_cbs_event, 1);

			goto exit;
		} else {
			LM_DBG("Routed message with source id [%d] and destination id [%d]\n",
				source_id, dest_id);
			if (check_call_cbs_event)
				call_cbs_event(packet, cl, &check_call_cbs_event, 1);

			goto exit;
		}
	} else {
		if (packet_type == CLUSTERER_GENERIC_MSG)
			handle_cl_gen_msg(packet);
		else if (packet_type == CLUSTERER_MI_CMD)
			handle_cl_mi_msg(packet);
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
	int check_call_cbs_event = 0;

	gettimeofday(&now, NULL);

	get_su_info(&ri->src_su.s, ip, port);
	LM_DBG("received clusterer message from: %s:%hu\n", ip, port);

	if (packet_type == CLUSTERER_GENERIC_MSG || packet_type == CLUSTERER_MI_CMD) {
		handle_other_cl_msg(packet, packet_type);
		return;
	}

	bin_pop_int(packet, &cl_id);
	bin_pop_int(packet, &source_id);

	lock_start_sw_read(cl_list_lock);

	cl = get_cluster_by_id(cl_id);
	if (!cl) {
		LM_WARN("Received message from unknown cluster id [%d]\n", cl_id);
		goto exit;
	}

	lock_get(cl->current_node->lock);
	if (!(cl->current_node->flags & NODE_STATE_ENABLED)) {
		LM_INFO("Current node disabled, ignoring received clusterer bin packet\n");
		lock_release(cl->current_node->lock);
		goto exit;
	}
	lock_release(cl->current_node->lock);

	node = get_node_by_id(cl, source_id);

	if (!node) {
		LM_INFO("Received message with unknown source id [%d]\n", source_id);
		handle_internal_msg_unknown(packet, cl, packet_type, &ri->src_su, source_id);
	} else {
		handle_internal_msg(packet, packet_type, node, now,	&check_call_cbs_event);
		if (check_call_cbs_event)
			call_cbs_event(NULL, cl, &check_call_cbs_event, 1);
	}

exit:
	lock_stop_sw_read(cl_list_lock);
}

static void bin_rcv_mod_packets(bin_packet_t *packet, int packet_type,
									struct receive_info *ri, void *ptr)
{
	struct mod_registration *module;
	unsigned short port;
	int source_id, dest_id, cluster_id;
	char *ip;
	node_info_t *node = NULL;
	cluster_info_t *cl;
	int i;
	int check_call_cbs_event = 0;

	/* pop the source and destination from the bin packet */
	bin_pop_back_int(packet, &dest_id);
	bin_pop_back_int(packet, &source_id);
	bin_pop_back_int(packet, &cluster_id);

	get_su_info(&ri->src_su.s, ip, port);
	LM_DBG("received bin packet from: %s:%hu\n with source id [%d] and cluster id [%d]\n",
		ip, port, source_id, cluster_id);

	module = (struct mod_registration *)ptr;

	for (i = 0; i < module->no_accept_clusters ||
			module->accept_clusters_ids[i] != cluster_id; i++);
	if (i == module->no_accept_clusters) {
		LM_DBG("Received message from unaccepted cluster [%d], ignoring\n", cluster_id);
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
		LM_INFO("Current node disabled, ignoring received bin packet\n");
		goto exit;
	}
	lock_release(cl->current_node->lock);

	node = get_node_by_id(cl, source_id);
	if (!node) {
		LM_WARN("Received message with unknown source id [%d]\n", source_id);
		goto exit;
	}

	if (module->auth_check && !ip_check(cl, &ri->src_su)) {
		LM_WARN("Received message from unknown source, addr: %s\n", ip);
		goto exit;
	}

	lock_get(node->lock);

	/* if the node was down, restart pinging */
	if (node->link_state == LS_DOWN) {
		lock_release(node->lock);
		LM_DBG("Received bin packet from failed node, restart pinging");
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

		if (msg_send_retry(packet, node, 0, &check_call_cbs_event) < 0) {
			LM_ERR("Failed to route message with source id [%d] and destination id [%d]\n",
				source_id, dest_id);
			if (check_call_cbs_event)
				call_cbs_event(packet, cl, &check_call_cbs_event, 1);

			lock_stop_read(cl_list_lock);

			module->cb(CLUSTER_ROUTE_FAILED, packet, packet_type, ri, cluster_id, source_id, dest_id);
			return;
		} else {
			LM_DBG("Routed message with source id [%d] and destination id [%d]\n",
				source_id, dest_id);
			if (check_call_cbs_event)
				call_cbs_event(packet, cl, &check_call_cbs_event, 1);

			lock_stop_read(cl_list_lock);
			return;
		}
	} else {
		/* pass message to module*/
		lock_stop_read(cl_list_lock);
		module->cb(CLUSTER_RECV_MSG, packet, packet_type, ri, cluster_id, source_id, dest_id);
		return;
	}

exit:
	lock_stop_read(cl_list_lock);
}

static int delete_neighbour(node_info_t *from_n, node_info_t *old_n)
{
	struct neighbour *neigh, *tmp;

	neigh = from_n->neighbour_list;
	if (!neigh)
		return 0;

	if (neigh->node->node_id == old_n->node_id) {
		from_n->neighbour_list = neigh->next;
		shm_free(neigh);
		return 1;
	}
	while (neigh->next) {
		if (neigh->next->node->node_id == old_n->node_id) {
			tmp = neigh->next;
			neigh->next = neigh->next->next;
			shm_free(tmp);
			return 1;
		}
		neigh = neigh->next;
	}

	return 0;
}

static int add_neighbour(node_info_t *to_n, node_info_t *new_n)
{
	struct neighbour *neigh;

	neigh = to_n->neighbour_list;
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
	neigh->next = to_n->neighbour_list;
	to_n->neighbour_list = neigh;
	return 1;
}

/* topology update packets(CLUSTERER_TOP_UPDATE and CLUSTERER_LS_UPDATE) format:
 * +---------------------------------------------------------------------------------------------+
 * | cluster | src_node | seq_no | timestamp | update_content | path_len | node_1 | node_2 | ... |
 * +---------------------------------------------------------------------------------------------+
 */

static int send_top_update(node_info_t *dest_node, int nr_nodes, int *node_list)
{
	static str module_name = str_init("clusterer");
	str bin_buffer;
	struct neighbour *neigh;
	node_info_t *it;
	int no_neigh;
	bin_packet_t packet;
	int timestamp;
	int i;

	timestamp = time(NULL);

	lock_get(dest_node->cluster->current_node->lock);

	if (bin_init(&packet, &module_name, CLUSTERER_FULL_TOP_UPDATE, BIN_VERSION, 0) < 0) {
		LM_ERR("Failed to init bin send buffer\n");
		return -1;
	}
	bin_push_int(&packet, dest_node->cluster->cluster_id);
	bin_push_int(&packet, current_id);
	bin_push_int(&packet, ++dest_node->cluster->current_node->top_seq_no);
	bin_push_int(&packet, timestamp);

	/* CLUSTERER_TOP_UPDATE message update content:
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
		/* the current node does not appear in the neighbour_list of other nodes
		 * but it should be present in the adjacency list to be sent if there is a link */
		if (it->link_state == LS_UP) {
			bin_push_int(&packet, current_id);
			no_neigh++;
		}
		/* set the number of neighbours */
		bin_remove_int_buffer_end(&packet, no_neigh + 1);
		bin_push_int(&packet, no_neigh);
		bin_skip_int_packet_end(&packet, no_neigh);

		lock_release(it->lock);
	}

	bin_push_int(&packet, 1);	/* path length is 1, only current node at this point */
	bin_push_int(&packet, current_id);
	bin_get_buffer(&packet, &bin_buffer);

	if (msg_send(NULL, clusterer_proto, &dest_node->addr, 0, bin_buffer.s,
		bin_buffer.len, 0) < 0) {
		LM_ERR("Failed to send topology update to node [%d]\n", dest_node->node_id);
		set_link_w_neigh_adv(LS_RESTART_PINGING, dest_node);
	} else
		LM_DBG("Sent topology update to node [%d]\n", dest_node->node_id);

	bin_free_packet(&packet);
	return 0;
}

static int send_ls_update(node_info_t *node, clusterer_link_state new_ls)
{
	struct neighbour *neigh;
	static str module_name = str_init("clusterer");
	str send_buffer;
	int msg_created = 0;
	node_info_t* destinations[MAX_NO_NODES];
	int no_dests = 0, i;
	bin_packet_t packet;
	int timestamp;

	timestamp = time(NULL);

	lock_get(node->cluster->current_node->lock);

	/* send link state update to all neighbours */
	for (neigh = node->cluster->current_node->neighbour_list; neigh;
		neigh = neigh->next) {
		if (neigh->node->node_id == node->node_id)
			continue;

		if (!msg_created) {
			if (bin_init(&packet, &module_name, CLUSTERER_LS_UPDATE, BIN_VERSION, SMALL_MSG) < 0) {
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
			bin_push_int(&packet, new_ls != LS_UP ? LS_DOWN : LS_UP);
			bin_push_int(&packet, 1);	/* path length is 1, only current node at this point */
			bin_push_int(&packet, current_id);
			bin_get_buffer(&packet, &send_buffer);
			msg_created = 1;
		}

		destinations[no_dests++] = neigh->node;
	}

	lock_release(node->cluster->current_node->lock);

	for (i = 0; i < no_dests; i++) {
		if (msg_send(NULL, clusterer_proto, &destinations[i]->addr, 0, send_buffer.s,
			send_buffer.len, 0) < 0) {
			LM_ERR("Failed to send link state update to node [%d]\n", destinations[i]->node_id);
			/* this node was supposed to be up, restart pinging */
			set_link_w_neigh_adv(LS_RESTART_PINGING, destinations[i]);
		}
	}

	if (msg_created){
		bin_free_packet(&packet);
		LM_DBG("Sent link state update about node [%d] to all reachable neighbours\n",
			node->node_id);
	}

	return 0;
}

/* Although the callbacks are called with cl_list_lock acquired, a deadlock is not possible
 * because the api functions which could be called from within the callbacks only acquire the
 * same lock for reading (RW lock, so multiple readers is ok) and never for writing
*/
static void call_cbs_event(bin_packet_t *packet, cluster_info_t *clusters,
							int *clusters_to_call, int no_clusters)
{
	node_info_t *node;
	cluster_info_t *cl;
	struct cluster_mod *mod_it;
	int k;

	for (k = 0, cl = clusters; k < no_clusters && cl; k++, cl = clusters->next) {
		if (!clusters_to_call[k])
			continue;

		for (node = cl->node_list; node; node = node->next) {
			lock_get(node->lock);
			if (node->flags	& CALL_CBS_DOWN) {
				node->flags &= ~CALL_CBS_DOWN;
				lock_release(node->lock);

				for (mod_it = cl->modules; mod_it; mod_it = mod_it->next)
					mod_it->reg->cb(CLUSTER_NODE_DOWN,packet,  UNDEFINED_PACKET_TYPE, NULL,
						cl->cluster_id, INVAL_NODE_ID, node->node_id);
			} else if (node->flags & CALL_CBS_UP) {
				node->flags &= ~CALL_CBS_UP;
				lock_release(node->lock);

				for (mod_it = cl->modules; mod_it; mod_it = mod_it->next)
					mod_it->reg->cb(CLUSTER_NODE_UP, packet, UNDEFINED_PACKET_TYPE, NULL,
						cl->cluster_id, INVAL_NODE_ID, node->node_id);
			} else
				lock_release(node->lock);
		}
	}
}

static void check_node_events(node_info_t *node_s, enum clusterer_event ev)
{
	node_info_t *n;
	int nhop;

	for(n = node_s->cluster->node_list; n; n = n->next) {
		if (n == node_s)
			continue;

		nhop = get_next_hop_2(n);

		lock_get(n->lock);
		if (n->link_state != LS_UP) {
			if(ev == CLUSTER_NODE_DOWN && n->next_hop && nhop <= 0)
				n->flags |= CALL_CBS_DOWN;
			if(ev == CLUSTER_NODE_UP && !n->next_hop && nhop > 0)
				n->flags |= CALL_CBS_UP;
		}
		lock_release(n->lock);
	}
}

static int set_link_w_neigh(clusterer_link_state new_ls, node_info_t *neigh)
{
	int nhop;

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
		if (nhop <= 0)
			check_node_events(neigh, CLUSTER_NODE_DOWN);

		lock_get(neigh->lock);

		if (nhop <= 0)
			neigh->flags |= CALL_CBS_DOWN;

	} else if (new_ls == LS_UP && neigh->link_state != LS_UP) {
		lock_release(neigh->lock);

		lock_get(neigh->cluster->current_node->lock);
		if (add_neighbour(neigh->cluster->current_node, neigh) < 0) {
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
			neigh->flags |= CALL_CBS_UP;
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

static int set_link_w_neigh_adv(clusterer_link_state new_ls, node_info_t *neigh)
{
	lock_get(neigh->lock);

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
	if (send_top_update(neigh, nr_nodes, node_list) < 0)
		return -1;

	return 0;
}

static int set_link(clusterer_link_state new_ls, node_info_t *node_a,
						node_info_t *node_b)
{
	int top_change = 0;
	int lock_a_released = 0;

	if (new_ls == LS_DOWN) {
		lock_get(node_b->lock);
		top_change = delete_neighbour(node_b, node_a);
		lock_release(node_b->lock);

		lock_get(node_a->lock);

		top_change += delete_neighbour(node_a, node_b);

		if (top_change > 0) {
			if (node_a->next_hop) {
				lock_release(node_a->lock);
				lock_a_released = 1;

				if (get_next_hop(node_b) <= 0) {
					lock_get(node_b->lock);
					node_b->flags |= CALL_CBS_DOWN;
					lock_release(node_b->lock);

					check_node_events(node_b, CLUSTER_NODE_DOWN);
				}
			}
		}

		if (!lock_a_released)
			lock_release(node_a->lock);

		if (top_change > 0) {
			lock_get(node_a->cluster->lock);
			node_a->cluster->top_version++;
			lock_release(node_a->cluster->lock);
			LM_DBG("setting link between nodes [%d] and [%d] to state <%d>\n",
				node_a->node_id, node_b->node_id, new_ls);
		}
	} else { /* new_ls == LS_UP */
		lock_get(node_b->lock);
		top_change = add_neighbour(node_b, node_a);
		if (top_change < 0) {
			lock_release(node_b->lock);
			return -1;
		}
		lock_release(node_b->lock);

		lock_get(node_a->lock);

		top_change += add_neighbour(node_a, node_b);

		if (top_change < 0) {
			lock_release(node_a->lock);
			return -1;
		}

		if (top_change > 0) {
			if (node_a->next_hop) {
				lock_release(node_a->lock);
				lock_a_released = 1;

				lock_get(node_b->lock);
				if (!node_b->next_hop) {
					node_b->flags |= CALL_CBS_UP;
					lock_release(node_b->lock);

					check_node_events(node_b, CLUSTER_NODE_UP);

					get_next_hop_2(node_b);
				} else
					lock_release(node_b->lock);
			}
		}

		if (!lock_a_released)
			lock_release(node_a->lock);

		if (top_change > 0) {
			lock_get(node_a->cluster->lock);
			node_a->cluster->top_version++;
			lock_release(node_a->cluster->lock);
			LM_DBG("setting link between nodes [%d] and [%d] to state <%d>\n",
				node_a->node_id, node_b->node_id, new_ls);
		}
	}

	return 0;
}

int cl_register_module(char *mod_name,  clusterer_cb_f cb, int auth_check,
								int *accept_clusters_ids, int no_accept_clusters)
{
	struct mod_registration *new_module;
	int i;

	new_module = shm_malloc(sizeof *new_module);
	if (!new_module) {
		LM_ERR("No more shm memory\n");
		return -1;
	}
	new_module->mod_name.len = strlen(mod_name);
	new_module->mod_name.s = mod_name;
	new_module->cb = cb;
	new_module->auth_check = auth_check;

	if (no_accept_clusters > MAX_MOD_REG_CLUSTERS) {
		LM_CRIT("Module: %*.s registered to too many clusters: %d\n",
			new_module->mod_name.len, new_module->mod_name.s, no_accept_clusters);
		return -1;
	}
	for (i = 0; i < no_accept_clusters; i++) {
		if (accept_clusters_ids[i] < 1) {
			LM_CRIT("Bad cluster_id: %d for module: %*.s registration\n",
				accept_clusters_ids[i], new_module->mod_name.len, new_module->mod_name.s);
			return -1;
		}

		new_module->accept_clusters_ids[i] = accept_clusters_ids[i];
	}
	new_module->no_accept_clusters = no_accept_clusters;

	new_module->next = clusterer_reg_modules;
	clusterer_reg_modules = new_module;

	bin_register_cb(mod_name, bin_rcv_mod_packets, new_module);

	LM_DBG("Registered module: %s\n", mod_name);

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

void gen_rcv_evs_destroy(void)
{
	evi_free_params(ei_event_params);
}