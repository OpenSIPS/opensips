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

#include "../../forward.h"

#include "api.h"
#include "node_info.h"
#include "clusterer.h"
#include "topology.h"

extern int ping_interval;
extern int node_timeout;
extern int ping_timeout;

#define PING_REPLY_INTERVAL(_node) \
	((_node)->last_pong.tv_sec*1000000 + (_node)->last_pong.tv_usec \
	- (_node)->last_ping.tv_sec*1000000 - (_node)->last_ping.tv_usec)

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

	rc = msg_send(node->cluster->send_sock, node->proto, &node->addr, 0,
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

			if (!(node->flags & NODE_STATE_ENABLED)) {
				lock_release(node->lock);
				continue;
			}

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
node_info_t *get_next_hop_2(node_info_t *dest)
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

int flood_message(bin_packet_t *packet, cluster_info_t *cluster,
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
		if (msg_send(cluster->send_sock, destinations[i]->proto,
			&destinations[i]->addr, 0, bin_buffer.s, bin_buffer.len, 0) < 0) {
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

static inline void bin_push_node_info(bin_packet_t *packet, node_info_t *node)
{
	bin_push_str(packet, &node->url);
	bin_push_str(packet, &node->sip_addr);
	bin_push_int(packet, node->priority);
	bin_push_int(packet, node->no_ping_retries);
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

	if (msg_send(dest_node->cluster->send_sock, dest_node->proto, &dest_node->addr,
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
		if (msg_send(destinations[i]->cluster->send_sock, destinations[i]->proto,
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

int delete_neighbour(node_info_t *from_node, node_info_t *to_delete_n)
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

int set_link_w_neigh(clusterer_link_state new_ls, node_info_t *neigh)
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

int set_link_w_neigh_adv(int prev_ls, clusterer_link_state new_ls,
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

void handle_full_top_update(bin_packet_t *packet, node_info_t *source,
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
			if (db_mode) {
				skip = 1;
			} else if (!top_node_info[i][0]) {
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
				if (db_mode)
					continue;
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
				if (top_node->link_state == LS_DOWN &&
					top_node->flags & NODE_STATE_ENABLED) {
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

void handle_internal_msg_unknown(bin_packet_t *received, cluster_info_t *cl,
	int packet_type, union sockaddr_union *src_su, int proto, int src_node_id)
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

		if (msg_send(cl->send_sock, proto, src_su, 0, bin_buffer.s,
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

void handle_ls_update(bin_packet_t *received, node_info_t *src_node,
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
		if (!db_mode)
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

void handle_unknown_id(node_info_t *src_node)
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
	if (msg_send(src_node->cluster->send_sock, src_node->proto, &src_node->addr,
		0, bin_buffer.s, bin_buffer.len, 0) < 0)
		LM_ERR("Failed to send node description to node [%d]\n", src_node->node_id);
	else
		LM_DBG("Sent node description to node [%d]\n", src_node->node_id);
	bin_free_packet(&packet);

	set_link_w_neigh_adv(-1, LS_RESTART_PINGING, src_node);
}

void handle_ping(bin_packet_t *received, node_info_t *src_node,
	struct timeval rcv_time, int *ev_actions_required)
{
	node_info_t *it;
	str bin_buffer;
	int send_rc;
	int new_ls = -1;
	int rst_ping_now = 0;
	int req_list;
	bin_packet_t packet;

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

	send_rc = msg_send(src_node->cluster->send_sock, src_node->proto,
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
}

void handle_pong(bin_packet_t *received, node_info_t *src_node,
	struct timeval rcv_time, int *ev_actions_required)
{
	int node_list[MAX_NO_NODES], i, nr_nodes;

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
}
