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

#include "api.h"
#include "node_info.h"
#include "clusterer.h"

struct clusterer_binds clusterer_api;

struct mod_registration *clusterer_reg_modules;
enum sip_protos clusterer_proto = PROTO_BIN;

extern int ping_interval;
extern int node_timeout;
extern int ping_timeout;

static int set_link(clusterer_link_state new_ls, node_info_t *node_a, node_info_t *node_b);
static int set_link_for_current(clusterer_link_state new_ls, node_info_t *node);
static void call_cbs_event(bin_packet_t *,cluster_info_t *clusters, int *clusters_to_call, int no_clusters);

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
	bin_get_buffer(&packet, &send_buffer);

	if (msg_send(NULL, clusterer_proto, &node->addr, 0, send_buffer.s,
		send_buffer.len, 0) < 0) {
		LM_ERR("Failed to send ping to node: %d\n", node->node_id);
		if (node->no_ping_retries == 0)
			*link_state_to_set = LS_DOWN;
		else {
			node->curr_no_retries = node->no_ping_retries;
			*link_state_to_set = LS_RETRY_SEND_FAIL;
		}
	} else {
		*link_state_to_set = LS_RESTARTED;
		LM_DBG("Sent ping to node: %d\n", node->node_id);
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
	bin_get_buffer(&packet, &send_buffer);

	if (msg_send(NULL, clusterer_proto, &node->addr, 0, send_buffer.s,
		send_buffer.len, 0) < 0) {
		LM_ERR("Failed to send ping retry to node: %d\n", node->node_id);
		if (node->curr_no_retries == 0) {
			*link_state_to_set = LS_DOWN;
			LM_INFO("Maximum number of retries reached, node: %d is down\n",
				node->node_id);
		}
	} else {
		LM_DBG("Sent ping to node: %d\n", node->node_id);
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
		LM_INFO("Pong not received, node: %d is down\n", node->node_id);
	} else {
		LM_INFO("Pong not received, node: %d is possibly down, retrying\n",
			node->node_id);
		node->last_ping = now;

		if (bin_init(&packet, &module_name, CLUSTERER_PING, BIN_VERSION, SMALL_MSG) < 0) {
			LM_ERR("Failed to init bin send buffer\n");
			return;
		}
		bin_push_int(&packet, node->cluster->cluster_id);
		bin_push_int(&packet, current_id);
		bin_get_buffer(&packet, &send_buffer);

		if (msg_send(NULL, clusterer_proto, &node->addr, 0, send_buffer.s,
			send_buffer.len, 0) < 0) {
			LM_ERR("Failed to send ping to node: %d\n", node->node_id);
			node->curr_no_retries = node->no_ping_retries;
			*link_state_to_set = LS_RETRY_SEND_FAIL;
		} else {
			LM_DBG("Sent ping retry to node: %d\n", node->node_id);
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
		bin_get_buffer(&packet, &send_buffer);

		if (msg_send(NULL, clusterer_proto, &node->addr, 0, send_buffer.s,
			send_buffer.len, 0) < 0) {
			LM_ERR("Failed to send ping retry to node: %d\n",
				node->node_id);
			*link_state_to_set = LS_RETRY_SEND_FAIL;
		} else {
			LM_DBG("Sent ping retry to node: %d\n", node->node_id);
			node->curr_no_retries--;
		}

		bin_free_packet(&packet);
	} else {
		*link_state_to_set = LS_DOWN;
		LM_INFO("Pong not received, node: %d is down\n", node->node_id);
	}
}

static void do_action_trans_4(node_info_t *node, int *link_state_to_set)
{
	struct timeval now;
	static str module_name = str_init("clusterer");
	str send_buffer;
	bin_packet_t packet;

	gettimeofday(&now, NULL);

	LM_INFO("Node timeout passed, restart pinging node: %d\n",
		node->node_id);

	node->last_ping = now;

	if (bin_init(&packet, &module_name, CLUSTERER_PING, BIN_VERSION, SMALL_MSG) < 0) {
		LM_ERR("Failed to init bin send buffer\n");
		return;
	}
	bin_push_int(&packet, node->cluster->cluster_id);
	bin_push_int(&packet, current_id);
	bin_get_buffer(&packet, &send_buffer);

	if (msg_send(NULL, clusterer_proto, &node->addr, 0, send_buffer.s,
		send_buffer.len, 0) < 0) {
		LM_ERR("Failed to send ping to node: %d\n", node->node_id);
		if (node->no_ping_retries != 0) {
			node->curr_no_retries = node->no_ping_retries;
			*link_state_to_set = LS_RETRY_SEND_FAIL;
		}
	} else {
		*link_state_to_set = LS_RESTARTED;
		LM_DBG("Sent ping to node: %d\n", node->node_id);
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
	bin_get_buffer(&packet, &send_buffer);

	if (msg_send(NULL, clusterer_proto, &node->addr, 0, send_buffer.s,
		send_buffer.len, 0) < 0) {
		LM_ERR("Failed to send ping to node: %d\n", node->node_id);
		if (node->no_ping_retries == 0)
			*link_state_to_set = LS_DOWN;
		else {
			node->curr_no_retries = node->no_ping_retries;
			*link_state_to_set = LS_RETRY_SEND_FAIL;
		}
		check_call_cbs_event[no_clusters] = 1;
	} else
		LM_DBG("Sent ping to node: %d\n", node->node_id);

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
				last_ping_int >= ping_timeout*1000)
				/* failed to send previous ping, retry */
				action_trans = 1;
			else if ((node->link_state == LS_UP || node->link_state == LS_RESTARTED) &&
				(ping_reply_int >= ping_timeout*1000 || ping_reply_int <= 0) &&
				last_ping_int >= ping_timeout*1000)
				/* send first ping retry */
				action_trans = 2;
			else if (node->link_state == LS_RETRYING &&
				(ping_reply_int >= ping_timeout*1000 || ping_reply_int <= 0) &&
				last_ping_int >= ping_timeout*1000)
				/* previous ping retry not replied, continue to retry */
				action_trans = 3;
			else if (node->link_state == LS_DOWN && last_ping_int >= node_timeout*1000000)
				/* ping a failed node after node_timeout since last ping */
				action_trans = 4;
			else if (node->link_state == LS_UP && last_ping_int >= ping_interval*1000000)
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
				set_link(link_state_to_set, clusters_it->current_node, node);
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
		LM_ERR("Cluster id: %d not found\n", cluster_id);
		return -1;
	}

	lock_get(cluster->current_node->lock);

	if (state == STATE_DISABLED && cluster->current_node->flags & NODE_STATE_ENABLED) {
		new_link_states = LS_DOWN;
		cluster->current_node->flags &= ~DB_UPDATED;
	} else if (state == STATE_ENABLED && !(cluster->current_node->flags & NODE_STATE_ENABLED)) {
		new_link_states = LS_RESTART_PINGING;
		cluster->current_node->flags &= ~DB_UPDATED;
	}

	if (state == STATE_DISABLED)
		cluster->current_node->flags &= ~NODE_STATE_ENABLED;
	else
		cluster->current_node->flags |= NODE_STATE_ENABLED;

	lock_release(cluster->current_node->lock);

	if (new_link_states == LS_DOWN) {
		for (node = cluster->node_list; node; node = node->next)
			set_link_for_current(LS_DOWN, node);

		call_cbs_event(NULL, cluster, &check_call_cbs_event, 1);
	} else if (new_link_states == LS_RESTART_PINGING) {
		for (node = cluster->node_list; node; node = node->next)
			set_link_for_current(LS_RESTART_PINGING, node);
	}

	lock_stop_read(cl_list_lock);

	LM_INFO("Set state: %s for current node in cluster: %d\n",
			state ? "enabled" : "disabled", cluster_id);

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

#undef unlock_all_nodes

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
static int clusterer_send_msg(bin_packet_t *packet, node_info_t *dest, int chg_dest, int *check_call_cbs_event)
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
		if (chg_dest || chosen_dest != dest) {
			bin_remove_int_buffer_end(packet, 1);
			bin_push_int(packet, dest->node_id);
		}
		bin_get_buffer(packet, &send_buffer);

		if (msg_send(NULL, clusterer_proto, &chosen_dest->addr, 0, send_buffer.s,
				send_buffer.len, 0) < 0) {
			LM_ERR("msg_send() to node: %d failed\n", chosen_dest->node_id);
			retr_send = 1;

			/* this node was supposed to be up, retry pinging */
			set_link(LS_RESTART_PINGING, chosen_dest->cluster->current_node,
				chosen_dest);

			*check_call_cbs_event = 1;
		} else {
			LM_DBG("sent bin packet to node: %d\n", chosen_dest->node_id);
			retr_send = 0;
		}
	} while (retr_send);

	return 0;
}

enum clusterer_send_ret cl_send_to(bin_packet_t *packet, int cluster_id, int node_id)
{
	node_info_t *node;
	int rc;
	cluster_info_t *cl;
	int check_call_cbs_event = 0;

	lock_start_read(cl_list_lock);

	cl = get_cluster_by_id(cluster_id);
	if (!cl) {
		LM_ERR("Unknown cluster id: %d\n", cluster_id);
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

	node = get_node_by_id(cl, node_id);
	if (!node) {
		LM_ERR("Node id: %d not found in cluster\n", node_id);
		lock_stop_read(cl_list_lock);
		return CLUSTERER_SEND_ERR;
	}

	bin_push_int(packet, cluster_id);
	bin_push_int(packet, current_id);
	bin_push_int(packet, node->node_id);
	rc = clusterer_send_msg(packet, node, 0, &check_call_cbs_event);

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

enum clusterer_send_ret cl_send_all(bin_packet_t *packet, int cluster_id)
{
	node_info_t *node;
	int rc, sent = 0, down = 1;
	cluster_info_t *cl;
	int check_call_cbs_event = 0;

	lock_start_read(cl_list_lock);

	cl = get_cluster_by_id(cluster_id);
	if (!cl) {
		LM_ERR("Unknown cluster, id: %d\n", cluster_id);
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

	bin_push_int(packet, cluster_id);
	bin_push_int(packet, current_id);
	bin_push_int(packet, -1);	/* dummy value */

	for (node = cl->node_list; node; node = node->next) {
		rc = clusterer_send_msg(packet, node, 1, &check_call_cbs_event);
		if (rc != -2)	/* at least one node is up */
			down = 0;
		if (rc == 0)	/* at least one message is sent successfuly*/
			sent = 1;
	}

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
		LM_WARN("Unknown cluster id: %d\n", cluster_id);
		return 0;
	}
	rc = ip_check(cluster, su);
	lock_stop_read(cl_list_lock);

	return rc;
}

static int flood_message(bin_packet_t *packet, cluster_info_t *cluster, int source_id, int alter_is_orig_src)
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
		LM_INFO("Too many hops for message from node: %d\n",
			source_id);
		return -1;
	}

	/* save nodes from the path in order to skip them when flooding */
	for (i = 0; i < path_len; i++) {
		bin_pop_int(packet, &path_nodes[i]);
		tmp_path_node = get_node_by_id(cluster, path_nodes[i]);
		if (!tmp_path_node) {
			LM_DBG("Unknown node in message path, id: %d\n", path_nodes[i]);
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
			if (alter_is_orig_src) {
				bin_remove_int_buffer_end(packet, path_len + 2);
				bin_push_int(packet, 0);
			} else
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
			LM_ERR("Failed to flood message to node: %d\n",
				destinations[i]->node_id);

			/* this node was supposed to be up, restart pinging */
			set_link(LS_RESTART_PINGING, cluster->current_node, destinations[i]);
		}
	}

	if (msg_altered)
		LM_DBG("Flooded messages to all reachable neighbours\n");

	return 0;
}

static void receive_full_top_update(bin_packet_t *packet, cluster_info_t *cluster, node_info_t *source,
										int *check_call_cbs_event)
{
	int seq_no;
	int no_nodes, no_neigh;
	int i, j;
	int skip;
	int top_node_id, neigh_id;
	node_info_t *top_node, *top_neigh, *it;
	int present_nodes[MAX_NO_NODES];
	int no_present_nodes = 0;
	int present;

	lock_get(source->lock);

	bin_pop_int(packet, &seq_no);
	if (seq_no <= source->top_seq_no) {
		lock_release(source->lock);
		return;
	}
	else
		source->top_seq_no = seq_no;

	lock_release(source->lock);

	bin_pop_int(packet, &no_nodes);
	for (i = 0; i < no_nodes; i++) {
		skip = 0;

		bin_pop_int(packet, &top_node_id);
		if (top_node_id == current_id)
			skip = 1;
		top_node = get_node_by_id(cluster, top_node_id);
		if (!skip && !top_node) {
			LM_WARN("Unknown node id: %d in topology update from "
				"node: %d\n", top_node_id, source->node_id);
			skip = 1;
		}

		if (top_node)
			lock_get(top_node->lock);

		bin_pop_int(packet, &seq_no);
		if (!skip && i > 0)
			if (seq_no <= top_node->ls_seq_no)
				skip = 1;
		bin_pop_int(packet, &no_neigh);
		if (skip) {
			bin_skip_int(packet, no_neigh);
			if (top_node)
				lock_release(top_node->lock);
			continue;
		}

		top_node->ls_seq_no = seq_no;

		lock_release(top_node->lock);

		for (j = 0; j < no_neigh; j++) {
			bin_pop_int(packet, &neigh_id);
			top_neigh = get_node_by_id(cluster, neigh_id);
			if (!top_neigh && neigh_id != current_id) {
				LM_WARN("Unknown neighbour id: %d in topology update "
					"about node: %d from source node: %d\n",
					neigh_id, top_node_id, source->node_id);
				continue;
			}

			if (neigh_id == current_id) {
				lock_get(top_node->lock);
				if (top_node->link_state == LS_DOWN) {
					lock_release(top_node->lock);

					set_link_for_current(LS_RESTART_PINGING, top_node);
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
		for (it = cluster->node_list; it; it = it->next) {
			if (it->node_id == top_node_id)
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

	flood_message(packet, cluster, source->node_id, 0);
}

static void receive_top_description(bin_packet_t *packet, cluster_info_t *cluster, node_info_t *source)
{
	int no_nodes, no_neigh;
	int i, j;
	int skip;
	int top_node_id, neigh_id;
	node_info_t *top_node, *top_neigh, *it;

	bin_pop_int(packet, &no_nodes);
	for (i = 0; i < no_nodes; i++) {
		skip = 0;

		bin_pop_int(packet, &top_node_id);
		if (top_node_id == current_id)
			skip = 1;
		top_node = get_node_by_id(cluster, top_node_id);
		if (!skip && !top_node) {
			LM_WARN("Unknown node id: %d in topology description from "
				"node: %d\n", top_node_id, source->node_id);
			skip = 1;
		}

		bin_pop_int(packet, &no_neigh);
		if (skip) {
			bin_skip_int(packet, no_neigh);
			continue;
		}

		for (j = 0; j < no_neigh; j++) {
			bin_pop_int(packet, &neigh_id);
			top_neigh = get_node_by_id(cluster, neigh_id);
			if (!top_neigh && neigh_id != current_id) {
				LM_WARN("Unknown neighbour id: %d in topology update "
					"about node: %d from source node: %d\n",
					neigh_id, top_node_id, source->node_id);
				continue;
			}
			if (neigh_id != current_id)
				set_link(LS_UP, top_node, top_neigh);
		}
	}

	for (it = cluster->node_list; it; it = it->next) {
		lock_get(it->lock);
		it->link_state = LS_RESTART_PINGING;
		lock_release(it->lock);
	}

	lock_get(cluster->lock);
	cluster->join_state = JOIN_SUCCESS;
	lock_release(cluster->lock);
}

/* CLUSTERER_TOP_DESCRIPTION message format:
 * +--------------------------------------------------------------------------------------------+
 * | cluster | src_node | no_nodes | node_1 | no_neigh | neigh_1 | neigh_2 | ... | node_2 | ... |
 * +--------------------------------------------------------------------------------------------+
 */
static int send_top_description(cluster_info_t *cluster, node_info_t *dest_node)
{
	static str module_name = str_init("clusterer");
	str bin_buffer;
	struct neighbour *neigh;
	node_info_t *it;
	int no_neigh;
	bin_packet_t packet;

	if (bin_init(&packet, &module_name, CLUSTERER_TOP_DESCRIPTION, BIN_VERSION, 0) < 0) {
		LM_ERR("Failed to init bin send buffer\n");
		return -1;
	}
	bin_push_int(&packet, cluster->cluster_id);
	bin_push_int(&packet, current_id);

    bin_push_int(&packet, cluster->no_nodes);

    lock_get(cluster->current_node->lock);

	/* the first adjacency list in the message is for the current node */
	bin_push_int(&packet, current_id);
	bin_push_int(&packet, 0); /* no neighbours for now */
	for (neigh = cluster->current_node->neighbour_list, no_neigh = 0; neigh;
		neigh = neigh->next, no_neigh++)
		bin_push_int(&packet, neigh->node->node_id);
	/* set the number of neighbours */
	bin_remove_int_buffer_end(&packet, no_neigh + 1);
	bin_push_int(&packet, no_neigh);
	bin_skip_int_packet_end(&packet, no_neigh);

	lock_release(cluster->current_node->lock);

	/* the adjacency lists for the rest of the nodes */
	for (it = cluster->node_list; it; it = it->next) {
		/* skip requesting node */
		if (it->node_id == dest_node->node_id)
			continue;
		bin_push_int(&packet, it->node_id);
		bin_push_int(&packet, 0);

		lock_get(it->lock);

		for (neigh = it->neighbour_list, no_neigh = 0; neigh;
			neigh = neigh->next, no_neigh++)
			bin_push_int(&packet, neigh->node->node_id);
		/* the current node does not appear in the neighbour_list of other nodes
		 * but it should be present in the adjacency list to be sent if there is a link */
		if (it->link_state == LS_UP) {
			bin_push_int(&packet, current_id);
			no_neigh++;
		}

		lock_release(it->lock);

		/* set the number of neighbours */
		bin_remove_int_buffer_end(&packet, no_neigh + 1);
		bin_push_int(&packet, no_neigh);
		bin_skip_int_packet_end(&packet, no_neigh);

	}

	bin_get_buffer(&packet ,&bin_buffer);

	if (msg_send(NULL, clusterer_proto, &dest_node->addr, 0, bin_buffer.s,
		bin_buffer.len, 0) < 0) {
		LM_ERR("Failed to send topology description to node: %d\n", dest_node->node_id);
		bin_free_packet(&packet);
		return -1;
	} else
		LM_DBG("Sent topology description to node: %d\n", dest_node->node_id);

	bin_free_packet(&packet);
	return 0;
}

static void receive_msg_unknown_source(bin_packet_t *received, cluster_info_t *cl, int packet_type,
										union sockaddr_union *src_su, int src_node_id)
{
	static str module_name = str_init("clusterer");
	str bin_buffer;
	int is_orig_src;
	str str_vals[NO_DB_STR_VALS];
	char *char_str_vals[NO_DB_STR_VALS];
	int int_vals[NO_DB_INT_VALS];
	node_info_t *new_node;
	int lock_old_flag;
	bin_packet_t packet;

	switch (packet_type) {
	case CLUSTERER_PING:
		/* reply in order to inform node that it has an unknown id */
		if (bin_init(&packet, &module_name, CLUSTERER_UNKNOWN_ID, BIN_VERSION, SMALL_MSG) < 0) {
			LM_ERR("Failed to init bin send buffer\n");
			return;
		}
		bin_push_int(&packet, cl->cluster_id);
		bin_push_int(&packet, current_id);
		bin_get_buffer(&packet, &bin_buffer);

		if (msg_send(NULL, clusterer_proto, src_su, 0, bin_buffer.s,
			bin_buffer.len, 0) < 0)
			LM_ERR("Failed to reply to ping from unknown node, id: %d\n", src_node_id);
		else
			LM_DBG("Replied to ping from unknown node, id: %d\n", src_node_id);

		bin_free_packet(&packet);
		break;
	case CLUSTERER_JOIN_REQUEST:
		if (src_node_id == current_id)
			break;

		if (bin_init(&packet, &module_name, CLUSTERER_JOIN_ACCEPT, BIN_VERSION, SMALL_MSG) < 0) {
			LM_ERR("Failed to init bin send buffer\n");
			return;
		}
		bin_push_int(&packet, cl->cluster_id);
		bin_push_int(&packet, current_id);
		bin_get_buffer(&packet, &bin_buffer);

		if (msg_send(NULL, clusterer_proto, src_su, 0, bin_buffer.s,
			bin_buffer.len, 0) < 0)
			LM_ERR("Failed to reply to join request from unknown node, id: %d\n", src_node_id);
		else
			LM_DBG("Replied to join request from unknown node, id: %d\n", src_node_id);

		bin_free_packet(&packet);
		break;
	case CLUSTERER_JOIN_CONFIRM:
		LM_DBG("Received join confirm message from node: %d\n", src_node_id);
		/* pop info from message */
		bin_pop_str(received, &str_vals[STR_VALS_DESCRIPTION_COL]);
		char_str_vals[STR_VALS_DESCRIPTION_COL] = shm_malloc(str_vals[STR_VALS_DESCRIPTION_COL].len+1);
		memcpy(char_str_vals[STR_VALS_DESCRIPTION_COL],
			str_vals[STR_VALS_DESCRIPTION_COL].s, str_vals[STR_VALS_DESCRIPTION_COL].len);
		char_str_vals[STR_VALS_DESCRIPTION_COL][str_vals[STR_VALS_DESCRIPTION_COL].len] = 0;

		bin_pop_str(received, &str_vals[STR_VALS_URL_COL]);
		char_str_vals[STR_VALS_URL_COL] = shm_malloc(str_vals[STR_VALS_URL_COL].len+1);
		memcpy(char_str_vals[STR_VALS_URL_COL],
			str_vals[STR_VALS_URL_COL].s, str_vals[STR_VALS_URL_COL].len);
		char_str_vals[STR_VALS_URL_COL][str_vals[STR_VALS_URL_COL].len] = 0;

		bin_pop_str(received, &str_vals[STR_VALS_SIP_ADDR_COL]);
		char_str_vals[STR_VALS_SIP_ADDR_COL] = shm_malloc(str_vals[STR_VALS_SIP_ADDR_COL].len+1);
		memcpy(char_str_vals[STR_VALS_SIP_ADDR_COL],
			str_vals[STR_VALS_SIP_ADDR_COL].s, str_vals[STR_VALS_SIP_ADDR_COL].len);
		char_str_vals[STR_VALS_SIP_ADDR_COL][str_vals[STR_VALS_SIP_ADDR_COL].len] = 0;

		bin_pop_int(received, &int_vals[INT_VALS_PRIORITY_COL]);
		bin_pop_int(received, &int_vals[INT_VALS_NO_PING_RETRIES_COL]);
		bin_pop_int(received, &int_vals[INT_VALS_LS_SEQ_COL]);
		bin_pop_int(received, &int_vals[INT_VALS_TOP_SEQ_COL]);
		bin_pop_int(received, &is_orig_src);

		int_vals[INT_VALS_ID_COL] = 0;	/* no valid DB id since it isn't loaded from DB */
		int_vals[INT_VALS_CLUSTER_ID_COL] = cl->cluster_id;
		int_vals[INT_VALS_NODE_ID_COL] = src_node_id;
		int_vals[INT_VALS_STATE_COL] = 1;	/* enabled since messages were received from this node */

		lock_switch_write(cl_list_lock, lock_old_flag);

		new_node = add_node_info(&cl, int_vals, char_str_vals);
		if (!new_node) {
			LM_ERR("Unable to add node info to backing list\n");
			return;
		}
		shm_free(char_str_vals[STR_VALS_DESCRIPTION_COL]);
		shm_free(char_str_vals[STR_VALS_URL_COL]);
		shm_free(char_str_vals[STR_VALS_SIP_ADDR_COL]);
		new_node->link_state = LS_RESTART_PINGING;
		new_node->flags = NODE_STATE_ENABLED;

		lock_switch_read(cl_list_lock, lock_old_flag);

		/* only the first node that receives the join confirm message sends back a topology description
		 * to the joining node, the other nodes just flood it */
		if (is_orig_src)
			flood_message(received, cl, src_node_id, 1);
		else
			flood_message(received, cl, src_node_id, 0);

		/* send topology description to joining node */
		if (is_orig_src)
			send_top_description(cl, new_node);

		break;
	default:
		LM_DBG("Ignoring message, type: %d from unknown source\n", packet_type);
	}
}

static void receive_msg_known_source(bin_packet_t *received, cluster_info_t *cl, int packet_type,
				node_info_t *src_node, struct timeval timestamp, int *check_call_cbs_event)
{
	node_info_t *ls_neigh;
	static str module_name = str_init("clusterer");
	str bin_buffer;
	int seq_no, neigh_id, new_ls;
	int send_rc;
	int set_ls_restart = 0;
	bin_packet_t packet;

	switch (packet_type) {
	case CLUSTERER_PONG:
		LM_DBG("Received pong from node: %d\n", src_node->node_id);

		lock_get(src_node->lock);

		src_node->last_pong = timestamp;

		/* if the node was retried and a reply was expected, it should be UP again */
		if (src_node->link_state == LS_RESTARTED || src_node->link_state == LS_RETRYING) {
			lock_release(src_node->lock);

			set_link(LS_UP, cl->current_node, src_node);
			*check_call_cbs_event = 1;

			LM_INFO("Node: %d is up\n", src_node->node_id);
		} else
			lock_release(src_node->lock);

		break;
	case CLUSTERER_PING:
		/* reply with pong */
		if (bin_init(&packet, &module_name, CLUSTERER_PONG, BIN_VERSION, SMALL_MSG) < 0) {
			LM_ERR("Failed to init bin send buffer\n");
			return;
		}
		bin_push_int(&packet, cl->cluster_id);
		bin_push_int(&packet, current_id);

		bin_get_buffer(&packet, &bin_buffer);

		send_rc = msg_send(NULL, clusterer_proto, &src_node->addr, 0, bin_buffer.s,
			bin_buffer.len, 0);

		lock_get(src_node->lock);

		if (send_rc < 0) {
			LM_ERR("Failed to reply to ping from node: %d\n", src_node->node_id);
			if (src_node->link_state == LS_UP) {
				set_ls_restart = 1;
				*check_call_cbs_event = 1;
			}
		} else
			LM_DBG("Replied to ping from node: %d\n", src_node->node_id);

		/* if the node was down, restart pinging */
		if (src_node->link_state == LS_DOWN) {
			LM_DBG("Received ping from failed node, restart pinging");
			set_ls_restart = 1;
		}

		lock_release(src_node->lock);

		if (set_ls_restart)
			set_link(LS_RESTART_PINGING, cl->current_node, src_node);

		bin_free_packet(&packet);
		break;
	case CLUSTERER_LS_UPDATE:
		lock_get(src_node->lock);

		bin_pop_int(received, &seq_no);
		if (seq_no <= src_node->ls_seq_no) {
			lock_release(src_node->lock);
			return;
		}
		else
			src_node->ls_seq_no = seq_no;

		bin_pop_int(received, &neigh_id);
		bin_pop_int(received, &new_ls);
		ls_neigh = get_node_by_id(cl, neigh_id);
		if (!ls_neigh && neigh_id != current_id) {
			LM_WARN("Received link state update about unknown node id: %d\n", neigh_id);
			lock_release(src_node->lock);
			return;
		}

		LM_DBG("Received link state update from node: %d about node: %d, new state=%s\n",
			src_node->node_id, neigh_id, new_ls ? "DOWN" : "UP");

		if (neigh_id == current_id) {
			if ((new_ls == LS_UP && src_node->link_state == LS_DOWN) ||
				(new_ls == LS_DOWN && src_node->link_state == LS_UP)) {
				lock_release(src_node->lock);

				set_link_for_current(LS_RESTART_PINGING, src_node);
				*check_call_cbs_event = 1;
			} else
				lock_release(src_node->lock);
		} else {
			lock_release(src_node->lock);

			set_link(new_ls, src_node, ls_neigh);

			*check_call_cbs_event = 1;
		}

		flood_message(received, cl, src_node->node_id, 0);

		break;
	case CLUSTERER_FULL_TOP_UPDATE:
		LM_DBG("Received full topology update from node: %d\n", src_node->node_id);

		receive_full_top_update(received ,cl, src_node, check_call_cbs_event);
		break;
	case CLUSTERER_UNKNOWN_ID:
		LM_DBG("Received CLUSTERER_UNKNOWN_ID from node: %d\n", src_node->node_id);

		lock_get(cl->lock);

		if (cl->join_state != JOIN_SUCCESS) {
			lock_get(src_node->lock);
			src_node->link_state = LS_NO_LINK;
			lock_release(src_node->lock);
		}

		if (cl->join_state != JOIN_INIT && cl->join_state != JOIN_REQ_SENT) {
			lock_release(cl->lock);
			break;
		}

		lock_release(cl->lock);

		/* send request to join the cluster */
		if (bin_init(&packet, &module_name, CLUSTERER_JOIN_REQUEST, BIN_VERSION, SMALL_MSG) < 0) {
			LM_ERR("Failed to init bin send buffer\n");
			return;
		}
		bin_push_int(&packet, cl->cluster_id);
		bin_push_int(&packet, current_id);
		bin_get_buffer(&packet, &bin_buffer);

		if (msg_send(NULL, clusterer_proto, &src_node->addr, 0, bin_buffer.s,
			bin_buffer.len, 0) < 0)
			LM_ERR("Failed to send cluster join request to node: %d\n", src_node->node_id);
		else {
			LM_DBG("Sent cluster join request to node: %d\n", src_node->node_id);
			lock_get(cl->lock);
			cl->join_state = JOIN_REQ_SENT;
			lock_release(cl->lock);
		}

		bin_free_packet(&packet);
		break;
	case CLUSTERER_JOIN_ACCEPT:
		lock_get(cl->lock);

		if (cl->join_state != JOIN_REQ_SENT) {
			/* the confirmation is not actually sent right here but we want to prevent
			 * other processes which may have received accepts to try to send confirmations
			 * anyway */
			cl->join_state = JOIN_CONFIRM_SENT;
			lock_release(cl->lock);
			break;
		}

		lock_release(cl->lock);

		/* send confirmation to join the cluster, acknowledging that the node was accepted */
		if (bin_init(&packet, &module_name, CLUSTERER_JOIN_CONFIRM, BIN_VERSION, 0) < 0) {
			LM_ERR("Failed to init bin send buffer\n");
			return;
		}
		bin_push_int(&packet, cl->cluster_id);
		bin_push_int(&packet, current_id);

		/* include info about current node */
		bin_push_str(&packet, &cl->current_node->description);
		bin_push_str(&packet, &cl->current_node->url);
		bin_push_str(&packet, &cl->current_node->sip_addr);
		bin_push_int(&packet, cl->current_node->priority);
		bin_push_int(&packet, cl->current_node->no_ping_retries);
		bin_push_int(&packet, cl->current_node->ls_seq_no);
		bin_push_int(&packet, cl->current_node->top_seq_no);

		bin_push_int(&packet, 1);	/* original source of this join confirm message */

		bin_push_int(&packet, 1);	/* path length is 1, only current node at this point */
		bin_push_int(&packet, current_id);

		bin_get_buffer(&packet, &bin_buffer);
		if (msg_send(NULL, clusterer_proto, &src_node->addr, 0, bin_buffer.s,
			bin_buffer.len, 0) < 0) {
			LM_ERR("Failed to send cluster join confirmation to node: %d\n", src_node->node_id);

			lock_get(cl->lock);
			cl->join_state = JOIN_REQ_SENT;
			lock_release(cl->lock);
		} else
			LM_DBG("Sent cluster join confirmation to node: %d\n", src_node->node_id);

		bin_free_packet(&packet);
		break;
	case CLUSTERER_JOIN_CONFIRM:
		LM_DBG("Already got join confirm from node: %d, drop this message\n", src_node->node_id);
		break;
	case CLUSTERER_TOP_DESCRIPTION:
		LM_DBG("Received topology description from node: %d\n", src_node->node_id);
		receive_top_description(received, cl, src_node);
		break;
	default:
		LM_WARN("Invalid clusterer binary packet command from node: %d\n",
			src_node->node_id);
	}
}

void receive_clusterer_bin_packets(bin_packet_t *packet, int packet_type, struct receive_info *ri, void *att)
{
	int source_id, cl_id;
	struct timeval now;
	node_info_t *node = NULL;
	cluster_info_t *cl;
	char *ip;
	unsigned short port;
	int check_call_cbs_event = 0;

	gettimeofday(&now, NULL);

	bin_pop_int(packet, &cl_id);
	bin_pop_int(packet, &source_id);

	get_su_info(&ri->src_su.s, ip, port);
	LM_DBG("received clusterer message from: %s:%hu\n with source id: %d and cluster id: %d\n",
		ip, port, source_id, cl_id);

	lock_start_sw_read(cl_list_lock);

	cl = get_cluster_by_id(cl_id);
	if (!cl) {
		LM_WARN("Received message from unknown cluster, id: %d\n", cl_id);
		goto end;
	}

	lock_get(cl->current_node->lock);
	if (!(cl->current_node->flags & NODE_STATE_ENABLED)) {
		LM_INFO("Current node disabled, ignoring received clusterer bin packet\n");
		lock_release(cl->current_node->lock);
		goto end;
	}
	lock_release(cl->current_node->lock);

	node = get_node_by_id(cl, source_id);

	if (!node) {
		LM_INFO("Received message from unknown source node, id: %d\n", source_id);

		receive_msg_unknown_source(packet, cl, packet_type, &ri->src_su, source_id);
	} else
		receive_msg_known_source(packet, cl, packet_type, node, now, &check_call_cbs_event);

end:
	if (check_call_cbs_event)
		call_cbs_event(NULL, cl, &check_call_cbs_event, 1);

	lock_stop_sw_read(cl_list_lock);
}

static void bin_receive_packets(bin_packet_t *packet, int packet_type, struct receive_info *ri, void *ptr)
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
	LM_DBG("received bin packet from: %s:%hu\n with source id: %d and cluster id: %d\n",
		ip, port, source_id, cluster_id);

	module = (struct mod_registration *)ptr;

	for (i = 0; i < module->no_accept_clusters ||
			module->accept_clusters_ids[i] != cluster_id; i++);
	if (i == module->no_accept_clusters) {
		LM_DBG("Received message from unaccepted cluster: %d, ignoring\n", cluster_id);
		return;
	}

	lock_start_read(cl_list_lock);

	cl = get_cluster_by_id(cluster_id);
	if (!cl) {
		LM_WARN("Received message from unknown cluster, id: %d\n", cluster_id);
		goto end;
	}

	lock_get(cl->current_node->lock);
	if (!(cl->current_node->flags & NODE_STATE_ENABLED)) {
		LM_INFO("Current node disabled, ignoring received bin packet\n");
		goto end;
	}
	lock_release(cl->current_node->lock);

	node = get_node_by_id(cl, source_id);
	if (!node) {
		LM_WARN("Received message with unknown source id: %d\n", source_id);
		goto end;
	}

	if (module->auth_check && !ip_check(cl, &ri->src_su)) {
		LM_WARN("Received message from unknown source, addr: %s\n", ip);
		goto end;
	}

	lock_get(node->lock);

	/* if the node was down, restart pinging */
	if (node->link_state == LS_DOWN) {
		lock_release(node->lock);
		LM_DBG("Received bin packet from failed node, restart pinging");
		set_link(LS_RESTART_PINGING, cl->current_node, node);
	} else
		lock_release(node->lock);

	if (dest_id != current_id) {
		bin_push_int(packet, cluster_id);
		bin_push_int(packet, source_id);
		bin_push_int(packet, dest_id);

		node = get_node_by_id(cl, dest_id);
		if (!node) {
			LM_WARN("Received message with unknown destination id: %d\n", source_id);
			goto end;
		}

		if (clusterer_send_msg(packet, node, 0, &check_call_cbs_event) < 0) {
			LM_ERR("Failed to route message with source, id: %d and destination, id: %d\n",
				source_id, dest_id);
			if (check_call_cbs_event)
				call_cbs_event(packet, cl, &check_call_cbs_event, 1);

			lock_stop_read(cl_list_lock);

			module->cb(CLUSTER_ROUTE_FAILED, packet, packet_type, ri, cluster_id, source_id, dest_id);
			return;
		} else {
			LM_DBG("Routed message with source, id: %d and destination, id: %d\n",
				source_id, dest_id);
			if (check_call_cbs_event)
				call_cbs_event(packet, cl, &check_call_cbs_event, 1);

			lock_stop_read(cl_list_lock);
			return;
		}
	} else {
		lock_stop_read(cl_list_lock);
		module->cb(CLUSTER_RECV_MSG, packet, packet_type, ri, cluster_id, source_id, dest_id);
		return;
	}

end:
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
 * +---------------------------------------------------------------------------------+
 * | cluster | src_node | seq_no | update_content | path_len | node_1 | node_2 | ... |
 * +---------------------------------------------------------------------------------+
 */

static int send_top_update(cluster_info_t *cluster, node_info_t *dest_node)
{
	static str module_name = str_init("clusterer");
	str bin_buffer;
	struct neighbour *neigh;
	node_info_t *it;
	int no_neigh;
	bin_packet_t packet;

	lock_get(cluster->current_node->lock);

	if (bin_init(&packet, &module_name, CLUSTERER_FULL_TOP_UPDATE, BIN_VERSION, 0) < 0) {
		LM_ERR("Failed to init bin send buffer\n");
		return -1;
	}
	bin_push_int(&packet, cluster->cluster_id);
	bin_push_int(&packet, current_id);
	bin_push_int(&packet, ++cluster->current_node->top_seq_no);
	cluster->current_node->flags &= ~DB_UPDATED;

	/* CLUSTERER_TOP_UPDATE message update content:
     * +-----------------------------------------------------------------------------------+
	 * | no_nodes | node_1 | ls_seq_no | no_neigh | neigh_1 | neigh_2 | ... | node_2 | ... |
	 * +-----------------------------------------------------------------------------------+
     */
    bin_push_int(&packet, cluster->no_nodes);

	/* the first adjacency list in the message is for the current node */
	bin_push_int(&packet, current_id);
	bin_push_int(&packet, cluster->current_node->ls_seq_no);
	bin_push_int(&packet, 0); /* no neighbours for now */
	for (neigh = cluster->current_node->neighbour_list, no_neigh = 0; neigh;
		neigh = neigh->next, no_neigh++)
		bin_push_int(&packet, neigh->node->node_id);
	/* set the number of neighbours */
	bin_remove_int_buffer_end(&packet, no_neigh + 1);
	bin_push_int(&packet, no_neigh);
	bin_skip_int_packet_end(&packet, no_neigh);

	lock_release(cluster->current_node->lock);

	/* the adjacency lists for the rest of the nodes */
	for (it = cluster->node_list; it; it = it->next) {
		/* skip requesting node */
		if (it->node_id == dest_node->node_id)
			continue;

		lock_get(it->lock);

		bin_push_int(&packet, it->node_id);
		bin_push_int(&packet, it->ls_seq_no);
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
		LM_ERR("Failed to send topology update to node: %d\n", dest_node->node_id);
		set_link(LS_RESTART_PINGING, cluster->current_node, dest_node);
	} else
		LM_DBG("Sent topology update to node: %d\n", dest_node->node_id);

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
			node->cluster->current_node->flags &= ~DB_UPDATED;
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
			LM_ERR("Failed to send link state update to node: %d\n", destinations[i]->node_id);
			/* this node was supposed to be up, restart pinging */
			set_link(LS_RESTART_PINGING, node->cluster->current_node, destinations[i]);
		}
	}

	if (msg_created){
		bin_free_packet(&packet);
		LM_DBG("Sent link state update about node: %d to all reachable neighbours\n",
			node->node_id);
	}

	return 0;
}

/* Although the callbacks are called with cl_list_lock acquired, a deadlock is not possible
 * because the api functions which could be called from within the callbacks only acquire the
 * same lock for reading (RW lock, so multiple readers is ok) and never for writing
*/
static void call_cbs_event(bin_packet_t *packet, cluster_info_t *clusters, int *clusters_to_call, int no_clusters)
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

static int set_link_for_current(clusterer_link_state new_ls, node_info_t *node)
{
	int nhop;

	lock_get(node->lock);

	if (new_ls != LS_UP && node->link_state == LS_UP) {
		lock_release(node->lock);

		lock_get(node->cluster->current_node->lock);
		delete_neighbour(node->cluster->current_node, node);
		lock_release(node->cluster->current_node->lock);

		lock_get(node->cluster->lock);
		node->cluster->top_version++;
		lock_release(node->cluster->lock);

		/* if there is no other path to this neighbour, we check if any other nodes
		 * were reachable only through this link and should be now down */
		nhop = get_next_hop_2(node);
		if (nhop <= 0)
			check_node_events(node, CLUSTER_NODE_DOWN);

		lock_get(node->lock);

		if (nhop <= 0)
			node->flags |= CALL_CBS_DOWN;

	} else if (new_ls == LS_UP && node->link_state != LS_UP) {
		lock_release(node->lock);

		lock_get(node->cluster->current_node->lock);
		if (add_neighbour(node->cluster->current_node, node) < 0) {
			LM_ERR("Unable to add neighbour: %d to topology\n", node->node_id);
			return -1;
		}
		lock_release(node->cluster->current_node->lock);

		lock_get(node->cluster->lock);
		node->cluster->top_version++;
		lock_release(node->cluster->lock);

		lock_get(node->lock);

		/* if there was no other path to this neighbour, we check if any other nodes
		 * are now reachable through this new link */
		if (!node->next_hop) {
			node->flags |= CALL_CBS_UP;
			lock_release(node->lock);
			check_node_events(node, CLUSTER_NODE_UP);
			lock_get(node->lock);
		}
		node->next_hop = node;
	}

	node->link_state = new_ls;

	lock_release(node->lock);

	return 0;
}

static int set_link(clusterer_link_state new_ls, node_info_t *node_a,
						node_info_t *node_b)
{
	int top_change = 0;
	int lock_a_released = 0;

	LM_DBG("setting link between node: %d and node: %d with state=%d\n",
		node_a->node_id, node_b->node_id, new_ls);

	if (node_a->node_id == current_id) {	/* link with current node's neighbours */
		lock_get(node_b->lock);

		if (new_ls != LS_UP && node_b->link_state == LS_UP) {
			lock_release(node_b->lock);

			if (set_link_for_current(new_ls, node_b) < 0)
				return -1;

			send_ls_update(node_b, LS_DOWN);
		} else if (new_ls == LS_UP && node_b->link_state != LS_UP) {
			lock_release(node_b->lock);

			if (set_link_for_current(new_ls, node_b) < 0)
				return -1;

			/* send link state update about this neigbour to the others */
			send_ls_update(node_b, LS_UP);
			/* send topology update to neighbour */
			if (send_top_update(node_b->cluster, node_b) < 0)
				return -1;
		} else {
			node_b->link_state = new_ls;
			lock_release(node_b->lock);
		}
	} else {	/* for non-neighbours we only have UP or DOWN link states */
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
			}
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

	bin_register_cb(mod_name, bin_receive_packets, new_module);

	LM_DBG("Registered module: %s\n", mod_name);

	return 0;
}

