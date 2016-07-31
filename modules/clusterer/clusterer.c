/*
 * Copyright (C) 2011 OpenSIPS Project
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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

inline void heartbeats_timer(void)
{
	struct timeval now;
	utime_t last_ping_int;
	utime_t ping_reply_int;
	cluster_info_t *clusters_it;
	node_info_t *node;
	static str module_name = str_init("clusterer");
	str send_buffer;
	int init_buffer;

	gettimeofday(&now, NULL);

	lock_start_write(ref_lock);

	for (clusters_it = *cluster_list; clusters_it; clusters_it = clusters_it->next) {
		if (clusters_it->current_node->enabled == STATE_DISABLED)
			continue;

		init_buffer = 1;

		for(node = clusters_it->node_list; node; node = node->next) {
			if (init_buffer) {
				if (bin_init(&module_name, CLUSTERER_PING, BIN_VERSION) < 0) {
					LM_ERR("Failed to init bin send buffer\n");
					continue;
				}
				bin_push_int(clusters_it->cluster_id);
				bin_push_int(current_id);
				bin_get_buffer(&send_buffer);
				init_buffer = 0;
			}

			/* restart pinging sequence */
			if (node->link_state == LS_RESTART_PINGING) {
				node->last_ping = now;
				if (msg_send(NULL, clusterer_proto, &node->addr, 0, send_buffer.s,
					send_buffer.len, 0) < 0) {
					LM_ERR("Failed to send ping to node: %d\n", node->node_id);
					if (node->no_ping_retries == 0)
						set_link(LS_DOWN, clusters_it->current_node, node);
					else {
						node->curr_no_retries = node->no_ping_retries;
						set_link(LS_RETRY_SEND_FAIL, clusters_it->current_node, node);
					}
				} else {
					set_link(LS_RESTARTED, clusters_it->current_node, node);
					LM_DBG("Sent ping to node: %d\n", node->node_id);
				}
				init_buffer = 1;
				continue;
			}

			ping_reply_int = node->last_pong.tv_sec*1000000 + node->last_pong.tv_usec
				- node->last_ping.tv_sec*1000000 - node->last_ping.tv_usec;
			last_ping_int = now.tv_sec*1000000 + now.tv_usec
				- node->last_ping.tv_sec*1000000 - node->last_ping.tv_usec;

			if (node->link_state == LS_RETRY_SEND_FAIL &&
				last_ping_int >= ping_timeout*1000) {
				node->last_ping = now;
				node->curr_no_retries--;
				if (msg_send(NULL, clusterer_proto, &node->addr, 0, send_buffer.s,
					send_buffer.len, 0) < 0) {
					LM_ERR("Failed to send ping retry to node: %d\n", node->node_id);
					if (node->curr_no_retries == 0) {
						set_link(LS_DOWN, clusters_it->current_node, node);
						init_buffer = 1;
						LM_INFO("Maximum number of retries reached, node: %d is down\n",
							node->node_id);
					}
				} else {
					LM_DBG("Sent ping to node: %d\n", node->node_id);
					set_link(LS_RETRYING, clusters_it->current_node, node);
					init_buffer = 1;
				}
				continue;
			}

			/* send first ping retry */
			if ((node->link_state == LS_UP ||
				node->link_state == LS_RESTARTED) &&
				(ping_reply_int >= ping_timeout*1000 || ping_reply_int <= 0) &&
				last_ping_int >= ping_timeout*1000) {
				if (node->no_ping_retries == 0) {
					set_link(LS_DOWN, clusters_it->current_node, node);
					LM_INFO("Pong not received, node: %d is down\n", node->node_id);
				} else {
					LM_INFO("Pong not received, node: %d is possibly down, retrying\n",
						node->node_id);
					node->last_ping = now;
					if (msg_send(NULL, clusterer_proto, &node->addr, 0, send_buffer.s,
						send_buffer.len, 0) < 0) {
						LM_ERR("Failed to send ping to node: %d\n", node->node_id);
						node->curr_no_retries = node->no_ping_retries;
						set_link(LS_RETRY_SEND_FAIL, clusters_it->current_node, node);
					} else {
						LM_DBG("Sent ping retry to node: %d\n", node->node_id);
						set_link(LS_RETRYING, clusters_it->current_node, node);
						node->curr_no_retries = --node->no_ping_retries;
					}
					continue;
				}
				init_buffer = 1;
			}

			/* previous ping retry not replied, continue to retry */
			if (node->link_state == LS_RETRYING &&
				(ping_reply_int >= ping_timeout*1000 || ping_reply_int <= 0) &&
				last_ping_int >= ping_timeout*1000) {
				if (node->curr_no_retries > 0) {
					node->last_ping = now;
					if (msg_send(NULL, clusterer_proto, &node->addr, 0, send_buffer.s,
						send_buffer.len, 0) < 0) {
						LM_ERR("Failed to send ping retry to node: %d\n",
							node->node_id);
						set_link(LS_RETRY_SEND_FAIL, clusters_it->current_node, node);
						init_buffer = 1;
					} else {
						LM_DBG("Sent ping retry to node: %d\n", node->node_id);
						node->curr_no_retries--;
					}
					continue;
				} else {
					set_link(LS_DOWN, clusters_it->current_node, node);
					init_buffer = 1;
					LM_INFO("Pong not received, node: %d is down\n", node->node_id);
				}
			}

			/* ping a failed node after node_timeout since last ping */
			if (node->link_state == LS_DOWN && last_ping_int >= node_timeout*1000000) {
				LM_INFO("Node timeout passed, restart pinging node: %d\n",
					node->node_id);

				if (init_buffer) {
					if (bin_init(&module_name, CLUSTERER_PING, BIN_VERSION) < 0) {
						LM_ERR("Failed to init bin send buffer\n");
						continue;
					}
					bin_push_int(clusters_it->cluster_id);
					bin_push_int(current_id < 0);
					bin_get_buffer(&send_buffer);
				}

				node->last_ping = now;
				if (msg_send(NULL, clusterer_proto, &node->addr, 0, send_buffer.s,
					send_buffer.len, 0) < 0) {
					LM_ERR("Failed to send ping to node: %d\n", node->node_id);
					if (node->no_ping_retries != 0) {
						node->curr_no_retries = node->no_ping_retries;
						set_link(LS_RETRY_SEND_FAIL, clusters_it->current_node, node);
					}
				} else {
					set_link(LS_RESTARTED, clusters_it->current_node, node);
					LM_DBG("Sent ping to node: %d\n", node->node_id);
				}
				init_buffer = 1;
				continue;
			}

			/* send regular ping */
			if (node->link_state == LS_UP && last_ping_int >= ping_interval*1000000) {
				node->last_ping = now;
				if (msg_send(NULL, clusterer_proto, &node->addr, 0, send_buffer.s,
					send_buffer.len, 0) < 0) {
					LM_ERR("Failed to send ping to node: %d\n", node->node_id);
					if (node->no_ping_retries == 0)
						set_link(LS_DOWN, clusters_it->current_node, node);
					else {
						node->curr_no_retries = node->no_ping_retries;
						set_link(LS_RETRY_SEND_FAIL, clusters_it->current_node, node);
					}
					init_buffer = 1;
				} else
					LM_DBG("Sent ping to node: %d\n", node->node_id);
			}
		}
	}

	lock_stop_write(ref_lock);
}

int set_state(int cluster_id, enum cl_node_state state)
{
	cluster_info_t *cluster = NULL;
	node_info_t *node;

	lock_start_write(ref_lock);

	cluster = get_cluster_by_id(cluster_id);
	if (!cluster) {
		lock_stop_write(ref_lock);
		LM_ERR("Cluster id: %d not found\n", cluster_id);
		return -1;
	}

	if (state == STATE_DISABLED && cluster->current_node->enabled == STATE_ENABLED) {
		for (node = cluster->node_list; node; node = node->next)
			set_link_for_current(LS_DOWN, node);
		cluster->current_node->db_synched = 0;
	} else if (state == STATE_ENABLED && cluster->current_node->enabled == STATE_DISABLED) {
		for (node = cluster->node_list; node; node = node->next)
			set_link_for_current(LS_RESTART_PINGING, node);
		cluster->current_node->db_synched = 0;
	}

	cluster->current_node->enabled = state;

	lock_stop_write(ref_lock);

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

    /* run BFS */
	if (dest->cluster->top_version != dest->sp_top_version) {
		dest->next_hop = NULL;

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
				if (!curr->parent || !curr->parent->parent)
					return -1;
				while (curr->parent->parent)
					curr = curr->parent;
				if (curr->parent != root)
					return -1;

				dest->next_hop = curr->node;
				return dest->next_hop->node_id;
			}

			/* for each node reachable from current */
			for (neigh = curr->node->neighbour_list; neigh; neigh = neigh->next)
				if (!neigh->node->sp_info->parent) {
					/* set parent */
					neigh->node->sp_info->parent = curr;
					/* enqueue node*/
					prio_enqueue(&queue_front, neigh);
				}
		}

		dest->sp_top_version = dest->cluster->top_version;
	}

	if (dest->next_hop)
		return dest->next_hop->node_id;
	else
		return 0;
}

/* @return:
 *  	> 0: next hop id
 * 		0  : no other path(node is down)
 *		< 0: error
 */
int get_next_hop(node_info_t *dest)
{
	if (dest->link_state == LS_UP) {
		dest->next_hop = dest;
		return dest->node_id;
	}
	else
		return get_next_hop_2(dest);
}

/* @return:
 *  0 : success, message sent
 * -1 : error, unable to send
 * -2 : dest down or probing
 */
static int clusterer_send_msg(node_info_t *dest, int chg_dest)
{
	int retr_send = 0;
	node_info_t *chosen_dest = dest;
	str tmp_buff, send_buffer;

	do {
		if (chosen_dest->link_state != LS_UP) {
			if (get_next_hop_2(dest) <= 0) {
				if (retr_send)
					return -1;
				else
					return -2;
			} else
				chosen_dest = dest->next_hop;
		}

		/* change destination node id */
		if (chg_dest || chosen_dest != dest) {
			bin_alter_pop_int(1);
			bin_push_int(dest->node_id);
		}
		bin_get_buffer(&send_buffer);

		if (msg_send(NULL, clusterer_proto, &chosen_dest->addr, 0, send_buffer.s,
				send_buffer.len, 0) < 0) {
			LM_ERR("msg_send() to node: %d failed\n", chosen_dest->node_id);
			retr_send = 1;
			memcpy(tmp_buff.s, send_buffer.s, send_buffer.len);
			tmp_buff.len = send_buffer.len;
			set_link(LS_RESTART_PINGING, chosen_dest->cluster->current_node,
				chosen_dest);	/* this node was supposed to be up, retry pinging */
			bin_set_send_buffer(tmp_buff);
		} else {
			LM_DBG("sent bin packet to node: %d\n", chosen_dest->node_id);
			retr_send = 0;
		}
	} while (retr_send);

	return 0;
}

enum clusterer_send_ret send_to(int cluster_id, int node_id)
{
	node_info_t *node;
	int rc;
	cluster_info_t *cl;

	lock_start_write(ref_lock);

	cl = get_cluster_by_id(cluster_id);
	if (!cl) {
		LM_ERR("Unknown cluster id: %d\n", cluster_id);
		lock_stop_write(ref_lock);
		return CLUSTERER_SEND_ERR;
	}
	if (!cl->current_node->enabled) {
		lock_stop_write(ref_lock);
		return CLUSTERER_CURR_DISABLED;
	}
	node = get_node_by_id(cl, node_id);
	if (!node) {
		LM_ERR("Node id: %d not found in cluster\n", node_id);
		lock_stop_write(ref_lock);
		return CLUSTERER_SEND_ERR;
	}

	bin_push_int(cluster_id);
	bin_push_int(current_id);
	bin_push_int(node->node_id);
	rc = clusterer_send_msg(node, 0);

	lock_stop_write(ref_lock);

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

enum clusterer_send_ret send_all(int cluster_id)
{
	node_info_t *node;
	int rc, sent = 0, down = 1;
	cluster_info_t *cl;

	lock_start_write(ref_lock);

	cl = get_cluster_by_id(cluster_id);
	if (!cl) {
		LM_ERR("Unknown cluster, id: %d\n", cluster_id);
		lock_stop_write(ref_lock);
		return CLUSTERER_SEND_ERR;
	}
	if (!cl->current_node->enabled) {
		lock_stop_write(ref_lock);
		return CLUSTERER_CURR_DISABLED;
	}

	bin_push_int(cluster_id);
	bin_push_int(current_id);
	bin_push_int(-1);	/* dummy value */

	for (node = cl->node_list; node; node = node->next) {
		rc = clusterer_send_msg(node, 1);
		if (rc != -2)	/* at least one node is up */
			down = 0;
		if (rc == 0)	/* at least one message is sent successfuly*/
			sent = 1;
	}

	lock_stop_write(ref_lock);

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

	lock_start_read(ref_lock);
	cluster = get_cluster_by_id(cluster_id);
	if (!cluster) {
		LM_WARN("Unknown cluster id: %d\n", cluster_id);
		return 0;
	}
	rc = ip_check(cluster, su);
	lock_stop_read(ref_lock);

	return rc;
}

static int flood_update(cluster_info_t *cluster, int source_id)
{
	int path_len;
	int path_nodes[UPDATE_MAX_PATH_LEN];
	node_info_t *tmp_path_node;
	struct neighbour *neigh;
	int msg_altered = 0;
	str bin_buffer;
	int i;

	bin_pop_int(&path_len);
	if (path_len > UPDATE_MAX_PATH_LEN) {
		LM_INFO("Too many hops for clusterer topology update message from node: %d\n",
			source_id);
		return -1;
	}

	/* mark nodes in the path in order to skip them when flooding */
	for (i = 0; i < path_len; i++) {
		bin_pop_int(&path_nodes[i]);
		tmp_path_node = get_node_by_id(cluster, path_nodes[i]);
		if (!tmp_path_node) {
			LM_DBG("Unknown node in topology update path, id: %d\n", path_nodes[i]);
			continue;
		}
		tmp_path_node->tmp = 1;
	}

	/* flood update to all neighbours */
	for (neigh = cluster->current_node->neighbour_list; neigh; neigh = neigh->next) {
		/* skip node that already got this update */
		if (neigh->node->tmp)
			continue;

		if (!msg_altered) {
			bin_get_recv_buffer(&bin_buffer);
			bin_set_send_buffer(bin_buffer);
			/* return to the path length position in the buffer */
			bin_alter_pop_int(path_len + 1);
			/* set new path length */
			bin_push_int(path_len + 1);
			/* go to end of buffer */
			bin_skip_int_send_buffer(path_len);
			/* include current node in path */
			bin_push_int(current_id);
			bin_get_buffer(&bin_buffer);
			msg_altered = 1;
		}

		if (msg_send(NULL, clusterer_proto, &neigh->node->addr, 0, bin_buffer.s,
			bin_buffer.len, 0) < 0) {
			LM_ERR("Failed to flood topology update to node: %d\n",
				neigh->node->node_id);
			/* this node was supposed to be up, restart pinging */
			set_link(LS_RESTART_PINGING, cluster->current_node, neigh->node);
		}
	}

	if (msg_altered)
		LM_DBG("Flooded topology update to all reachable neighbours\n");

	/* reset marked nodes */
	for (i = 0; i < path_len; i++) {
		tmp_path_node = get_node_by_id(cluster, path_nodes[i]);
		if (!tmp_path_node)
			continue;
		tmp_path_node->tmp = 0;
	}

	return 0;
}

void receive_clusterer_bin_packets(int packet_type, struct receive_info *ri, void *att)
{
	int source_id, cl_id;
	struct timeval now;
	node_info_t *node = NULL, *ls_neigh, *top_neigh, *it, *top_node;
	cluster_info_t *cl;
	static str module_name = str_init("clusterer");
	str bin_buffer;
	int seq_no, neigh_id, new_ls;
	int i, j;
	int skip;
	int no_neigh, no_nodes;
	int top_node_id;
	char *ip;
	unsigned short port;

	gettimeofday(&now, NULL);

	bin_pop_int(&cl_id);
	bin_pop_int(&source_id);

	get_su_info(&ri->src_su.s, ip, port);
	LM_DBG("received clusterer message from: %s:%hu\n with source id: %d and cluster id: %d\n",
		ip, port, source_id, cl_id);

	lock_start_write(ref_lock);

	cl = get_cluster_by_id(cl_id);
	if (!cl) {
		LM_WARN("Received message from unknown cluster, id: %d\n", cl_id);
		goto end;
	}
	if (!cl->current_node->enabled) {
		LM_INFO("Current node disabled, ignoring received clusterer bin packet\n");
		goto end;
	}
	node = get_node_by_id(cl, source_id);
	if (!node) {
		LM_WARN("Received message from unknown source node, id: %d\n", source_id);
		goto end;
	}

	switch (packet_type) {
	case CLUSTERER_PONG:
		LM_DBG("Received pong from node: %d\n", source_id);
		node->last_pong = now;

		/* if the node was retried and a reply was expected, it should be UP again */
		if (node->link_state == LS_RESTARTED || node->link_state == LS_RETRYING) {
			LM_INFO("Node: %d is up\n", source_id);
			set_link(LS_UP, cl->current_node, node);
		}

		break;
	case CLUSTERER_PING:
		/* reply with pong */
		if (bin_init(&module_name, CLUSTERER_PONG, BIN_VERSION) < 0) {
			LM_ERR("Failed to init bin send buffer\n");
			goto end;
		}
		bin_push_int(cl_id);
		bin_push_int(current_id);

		bin_get_buffer(&bin_buffer);

		if (msg_send(NULL, clusterer_proto, &node->addr, 0, bin_buffer.s,
			bin_buffer.len, 0) < 0) {
			LM_ERR("Failed to reply to ping from node: %d\n", source_id);
			if (node->link_state == LS_UP)
				set_link(LS_RESTART_PINGING, cl->current_node, node);
		} else
			LM_DBG("Replied to ping from node: %d\n", source_id);

		/* if the node was down, restart pinging */
		if (node->link_state == LS_DOWN) {
			LM_DBG("Received ping from failed node, restart pinging");
			set_link(LS_RESTART_PINGING, cl->current_node, node);
		}

		break;
	case CLUSTERER_LS_UPDATE:
		bin_pop_int(&seq_no);
		if (seq_no <= node->ls_seq_no)
			goto end;
		else
			node->ls_seq_no = seq_no;

		bin_pop_int(&neigh_id);
		bin_pop_int(&new_ls);
		ls_neigh = get_node_by_id(cl, neigh_id);
		if (!ls_neigh && neigh_id != current_id) {
			LM_WARN("Received link state update about unknown node id: %d\n", neigh_id);
			goto end;
		}

		LM_DBG("Received link state update from node: %d about node: %d, new state=%s\n",
			source_id, neigh_id, new_ls ? "DOWN" : "UP");

		if (neigh_id == current_id) {
			if ((new_ls == LS_UP && node->link_state == LS_DOWN) ||
				(new_ls == LS_DOWN && node->link_state == LS_UP)) {
				set_link_for_current(LS_RESTART_PINGING, node);
			}
		} else
			set_link(new_ls, node, ls_neigh);

		flood_update(cl, source_id);

		break;
	case CLUSTERER_FULL_TOP_UPDATE:
		bin_pop_int(&seq_no);
		if (seq_no <= node->top_seq_no)
			goto end;
		else
			node->top_seq_no = seq_no;
		bin_pop_int(&no_nodes);

		LM_DBG("Received full topology update from node: %d\n", source_id);

		for (i = 0; i < no_nodes; i++) {
			skip = 0;

			bin_pop_int(&top_node_id);
			if (top_node_id == current_id)
				skip = 1;
			top_node = get_node_by_id(cl, top_node_id);
			if (!skip && !top_node) {
				LM_WARN("Unknown node id: %d in topology update from "
					"node: %d\n", top_node_id, source_id);
				skip = 1;
			}
			bin_pop_int(&seq_no);
			if (!skip && i > 0)
				if (seq_no <= top_node->ls_seq_no)
					skip = 1;
			bin_pop_int(&no_neigh);
			if (skip) {
				bin_skip_int(no_neigh);
				continue;
			}

			top_node->ls_seq_no = seq_no;

			for (j = 0; j < no_neigh; j++) {
				bin_pop_int(&neigh_id);
				top_neigh = get_node_by_id(cl, neigh_id);
				if (!top_neigh && neigh_id != current_id) {
					LM_WARN("Unknown neighbour id: %d in topology update "
						"about node: %d from source node: %d\n",
						neigh_id, top_node_id, source_id);
					continue;
				}
				if (neigh_id == current_id) {
					if (top_node->link_state == LS_DOWN) {
						set_link_for_current(LS_RESTART_PINGING, top_node);
					}
				} else {
					set_link(LS_UP, top_node, top_neigh);
					/* mark the node in order to identify neighbours which are missing
					 * from the adjacency list and thus represent failed links */
					top_neigh->tmp = 1;
				}
			}

			/* search the marked nodes to delete the corresponding links */
			for (it = cl->node_list; it; it = it->next) {
				if (it->node_id == top_node_id) {
					it->tmp = 0;
					continue;
				}
				if (!it->tmp)
					set_link(LS_DOWN, top_node, it);

				it->tmp = 0;
			}
		}

		flood_update(cl, source_id);
		
		break;
	default:
		LM_WARN("Invalid clusterer binary packet command from node: %d\n",
			source_id);
	}
end:
	lock_stop_write(ref_lock);
}

static void bin_receive_packets(int packet_type, struct receive_info *ri, void *ptr)
{
	struct mod_registration *module;
	unsigned short port;
	int source_id, dest_id, cluster_id;
	char *ip;
	node_info_t *node = NULL;
	cluster_info_t *cl;
	str recv_buf;
	int i;

	/* pop the source and destination from the bin packet */
	bin_pop_back_int(&dest_id);
	bin_pop_back_int(&source_id);
	bin_pop_back_int(&cluster_id);

	get_su_info(&ri->src_su.s, ip, port);
	LM_DBG("received bin packet from: %s:%hu\n with source id: %d and cluster id: %d\n",
		ip, port, source_id, cluster_id);

	module = (struct mod_registration *)ptr;

	for (i = 0; i < module->no_accept_clusters ||
			module->accept_clusters_ids[i] != cluster_id; i++);
	if (i == module->no_accept_clusters) {
		LM_DBG("Received message from unaccepted cluster: %d, ignoring\n", cluster_id);
		goto end;
	}

	lock_start_write(ref_lock);

	cl = get_cluster_by_id(cluster_id);
	if (!cl) {
		LM_WARN("Received message from unknown cluster, id: %d\n", cluster_id);
		goto end;
	}
	if (!cl->current_node->enabled) {
		LM_INFO("Current node disabled, ignoring received bin packet\n");
		goto end;
	}
	node = get_node_by_id(cl, source_id);
	if (!node) {
		LM_WARN("Received message with unknown source id: %d\n", source_id);
		goto end;
	}

	if (module->auth_check && !ip_check(cl, &ri->src_su)) {
		LM_WARN("Received message from unknown source, addr: %s\n", ip);
		goto end;
	}

	/* if the node was down, restart pinging */
	if (node->link_state == LS_DOWN) {
		LM_DBG("Received bin packet from failed node, restart pinging");
		set_link(LS_RESTART_PINGING, cl->current_node, node);
	}

	if (dest_id != current_id) {
		bin_get_recv_buffer(&recv_buf);
		bin_set_send_buffer(recv_buf);
		bin_push_int(source_id);
		bin_push_int(dest_id);

		node = get_node_by_id(cl, dest_id);
		if (!node) {
			LM_WARN("Received message with unknown destination id: %d\n", source_id);
			goto end;
		}

		if (clusterer_send_msg(node, 0) < 0) {
			LM_ERR("Failed to route message with source, id: %d and destination, id: %d\n",
				source_id, dest_id);
			module->cb(CLUSTER_ROUTE_FAILED, packet_type, ri, cluster_id, source_id, dest_id);
		} else
			LM_DBG("Routed message with source, id: %d and destination, id: %d\n",
				source_id, dest_id);
	} else
		module->cb(CLUSTER_RECV_MSG, packet_type, ri, cluster_id, source_id, dest_id);

end:
	lock_stop_write(ref_lock);
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

	if (bin_init(&module_name, CLUSTERER_FULL_TOP_UPDATE, BIN_VERSION) < 0) {
		LM_ERR("Failed to init bin send buffer\n");
		return -1;
	}
	bin_push_int(cluster->cluster_id);
	bin_push_int(current_id);
	bin_push_int(++cluster->current_node->top_seq_no);
	cluster->current_node->db_synched = 0;

	/* CLUSTERER_TOP_UPDATE message update content:
     * +-----------------------------------------------------------------------------------+
	 * | no_nodes | node_1 | ls_seq_no | no_neigh | neigh_1 | neigh_2 | ... | node_2 | ... |
	 * +-----------------------------------------------------------------------------------+
     */
    bin_push_int(cluster->no_nodes);

	/* the first adjacency list in the message is for the current node */
	bin_push_int(current_id);
	bin_push_int(cluster->current_node->ls_seq_no);
	bin_push_int(0); /* no neighbours for now */
	for (neigh = cluster->current_node->neighbour_list, no_neigh = 0; neigh;
		neigh = neigh->next, no_neigh++)
		bin_push_int(neigh->node->node_id);
	/* set the number of neighbours */
	bin_alter_pop_int(no_neigh + 1);
	bin_push_int(no_neigh);
	bin_skip_int_send_buffer(no_neigh);

	/* the adjacency lists for the rest of the nodes */
	for (it = cluster->node_list; it; it = it->next) {
		/* skip requesting node */
		if (it->node_id == dest_node->node_id)
			continue;
		bin_push_int(it->node_id);
		bin_push_int(it->ls_seq_no);
		bin_push_int(0);
		for (neigh = it->neighbour_list, no_neigh = 0; neigh;
			neigh = neigh->next, no_neigh++)
			bin_push_int(neigh->node->node_id);
		/* the current node does not appear in the neighbour_list of other nodes
		 * but it should be present in the adjacency list to be sent if there is a link */
		if (it->link_state == LS_UP) {
			bin_push_int(current_id);
			no_neigh++;
		}
		/* set the number of neighbours */
		bin_alter_pop_int(no_neigh + 1);
		bin_push_int(no_neigh);
		bin_skip_int_send_buffer(no_neigh);

	}

	bin_push_int(1);	/* path length is 1, only current node at this point */
	bin_push_int(current_id);
	bin_get_buffer(&bin_buffer);

	if (msg_send(NULL, clusterer_proto, &dest_node->addr, 0, bin_buffer.s,
		bin_buffer.len, 0) < 0) {
		LM_ERR("Failed to send topology update to node: %d\n", dest_node->node_id);
		set_link(LS_RESTART_PINGING, cluster->current_node, dest_node);
	} else
		LM_DBG("Sent topology update to node: %d\n", dest_node->node_id);

	return 0;
}

static int send_ls_update(node_info_t *node, clusterer_link_state new_ls)
{
	struct neighbour *neigh;
	static str module_name = str_init("clusterer");
	str send_buffer;
	int msg_created = 0;

	/* send link state update to all neighbours */
	for (neigh = node->cluster->current_node->neighbour_list; neigh;
		neigh = neigh->next) {
		if (neigh->node->node_id == node->node_id)
			continue;

		if (!msg_created) {
			if (bin_init(&module_name, CLUSTERER_LS_UPDATE, BIN_VERSION) < 0) {
				LM_ERR("Failed to init bin send buffer\n");
				return -1;
			}
			bin_push_int(node->cluster->cluster_id);
			bin_push_int(current_id);
			bin_push_int(++node->cluster->current_node->ls_seq_no);
			node->cluster->current_node->db_synched = 0;
			/* The link state update message's update content consists of a neighbour
			 * and it's new link state */
			bin_push_int(node->node_id);
			bin_push_int(new_ls != LS_UP ? LS_DOWN : LS_UP);
			bin_push_int(1);	/* path length is 1, only current node at this point */
			bin_push_int(current_id);
			bin_get_buffer(&send_buffer);
			msg_created = 1;
		}

		if (msg_send(NULL, clusterer_proto, &neigh->node->addr, 0, send_buffer.s,
			send_buffer.len, 0) < 0) {
			LM_ERR("Failed to send link state update to node: %d\n", neigh->node->node_id);
			/* this node was supposed to be up, restart pinging */
			set_link(LS_RESTART_PINGING, node->cluster->current_node, neigh->node);
		}
	}

	if (msg_created)
		LM_DBG("Sent link state update about node: %d to all reachable neighbours\n",
			node->node_id);

	return 0;
}

#define call_cbs_node_down(_node) \
	do { \
		struct cluster_mod *m_it = (_node)->cluster->modules; \
		while (m_it) { \
			m_it->reg->cb(CLUSTER_NODE_DOWN, UNDEFINED_PACKET_TYPE, NULL, \
				(_node)->cluster->cluster_id, INVAL_NODE_ID, (_node)->node_id); \
			m_it = m_it->next; \
		} \
	} while(0)

static int set_link_for_current(clusterer_link_state new_ls, node_info_t *node)
{
	if (new_ls != LS_UP && node->link_state == LS_UP) {
		delete_neighbour(node->cluster->current_node, node);
		node->cluster->top_version++;
		if (get_next_hop_2(node) <= 0)
			call_cbs_node_down(node);
	} else if (new_ls == LS_UP && node->link_state != LS_UP) {
		if (add_neighbour(node->cluster->current_node, node) < 0)
			return -1;
		node->cluster->top_version++;
	}

	node->link_state = new_ls;

	return 0;
}

static int set_link(clusterer_link_state new_ls, node_info_t *node_a,
						node_info_t *node_b)
{
	int top_change = 0;

	LM_DBG("setting link between node: %d and node: %d with state=%d\n",
		node_a->node_id, node_b->node_id, new_ls);

	if (node_a->node_id == current_id) {	/* link with current node's neighbours */
		if (new_ls != LS_UP && node_b->link_state == LS_UP) {
			if (set_link_for_current(new_ls, node_b) < 0)
				return -1;

			send_ls_update(node_b, LS_DOWN);
		} else if (new_ls == LS_UP && node_b->link_state != LS_UP) {
			if (set_link_for_current(new_ls, node_b) < 0)
				return -1;

			send_ls_update(node_b, LS_UP);

			/* send topology update */
			if (send_top_update(node_b->cluster, node_b) < 0)
				return -1;
		} else
			node_b->link_state = new_ls;
	} else {	/* for non-neighbours we only have UP or DOWN link states */
		if (new_ls == LS_DOWN) {
			top_change = delete_neighbour(node_a, node_b);
			top_change += delete_neighbour(node_b, node_a);
			if (top_change > 0) {
				node_a->cluster->top_version++;
				if (get_next_hop(node_b) <= 0)
					call_cbs_node_down(node_b);
			}
		} else {
			top_change = add_neighbour(node_a, node_b);
			if (top_change < 0)
				return -1;
			top_change += add_neighbour(node_b, node_a);
			if (top_change < 0)
				return -1;

			if (top_change > 0)
				node_a->cluster->top_version++;
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

