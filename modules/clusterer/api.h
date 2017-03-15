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
 *  2015-07-07 created (Marius Cristian Eseanu)
 *  2016-07-xx rework (rvlad-patrascu)
 */

#ifndef CLUSTERER_API_H
#define CLUSTERER_API_H

#include "../../str.h"
#include "../../ip_addr.h"
#include "../../sr_module.h"
#include "../../bin_interface.h"

#define UNDEFINED_PACKET_TYPE -1
#define INVAL_NODE_ID -1
#define MAX_MOD_REG_CLUSTERS 8

enum cl_node_state {
	STATE_DISABLED,	/* the node does not send any messages and ignores received ones */
	STATE_ENABLED
};

typedef struct clusterer_node {
	int node_id;
	union sockaddr_union addr;
	str sip_addr;
	str description;
	struct clusterer_node *next;
} clusterer_node_t;

enum clusterer_send_ret {
	CLUSTERER_SEND_SUCCES = 0,
	CLUSTERER_CURR_DISABLED = 1,  /* current node disabled */
	CLUSTERER_DEST_DOWN = -1,     /* destination node(s) already down or probing */
	CLUSTERER_SEND_ERR = -2       /* error */
};

enum clusterer_event {
	/* node with id provided in the @dest_id param of clusterer_cb_f is back up */
	CLUSTER_NODE_UP,
	/* node with id provided in the @dest_id param of clusterer_cb_f is unreachable */
	CLUSTER_NODE_DOWN,
	/* failed to route received message (source and destination nodes
	 * provided in clusterer_cb_f params) */
	CLUSTER_ROUTE_FAILED,
	/* received message for current node */
	CLUSTER_RECV_MSG
};

/* returns the list of reachable nodes in the cluster */
typedef clusterer_node_t* (*get_nodes_f)(int cluster_id);

/* free the list returned by the get_nodes_f function */
typedef void (*free_nodes_f)(clusterer_node_t *list);

/* sets the state (enabled or disabled) of the current node in the cluster */
typedef int (*set_state_f)(int cluster_id, enum cl_node_state state);

/* checks if the given address belongs to one of the nodes in the cluster */
typedef int (*check_addr_f)(int cluster_id, union sockaddr_union *su);

/* get the node id of the current node */
typedef int (*get_my_id_f)(void);

/* send message to specific node in the cluster */
typedef enum clusterer_send_ret (*send_to_f)(bin_packet_t *packet, int cluster_id, int node_id);

/* send message to all nodes in the cluster */
typedef enum clusterer_send_ret (*send_all_f)(bin_packet_t *packet, int cluster_id);

/* return the next hop from the shortest path to the given destination */
typedef clusterer_node_t* (*get_next_hop_f)(int cluster_id, int node_id);

/* free node returned by get_next_hop_f function */
typedef void (*free_next_hop_f)(clusterer_node_t *next_hop);

/*
 * This function will be called for every binary packet received or
 * to signal certain cluster events.
 */
typedef void (*clusterer_cb_f)(enum clusterer_event ev,bin_packet_t *, int packet_type,
				struct receive_info *ri, int cluster_id, int src_id, int dest_id);

/* Register module to clusterer; must be called only once for each module
 * @accept_clusters_ids accept - array of cluster ids from wich packets are accepted */
typedef int (*register_module_f)(char *mod_name,  clusterer_cb_f cb, int auth_check,
									int *accept_clusters_ids, int no_accept_clusters);

struct clusterer_binds {
	get_nodes_f get_nodes;
	free_nodes_f free_nodes;
	set_state_f set_state;
	check_addr_f check_addr;
	get_my_id_f get_my_id;
	send_to_f send_to;
	send_all_f send_all;
	get_next_hop_f get_next_hop;
	free_next_hop_f free_next_hop;
	register_module_f register_module;
};

typedef int (*load_clusterer_f)(struct clusterer_binds *binds);

int load_clusterer(struct clusterer_binds *binds);

static inline int load_clusterer_api(struct clusterer_binds *binds) {
	load_clusterer_f load_clusterer;

	/* import the DLG auto-loading function */
	if (!(load_clusterer = (load_clusterer_f) find_export("load_clusterer", 0, 0)))
		return -1;

	/* let the auto-loading function load all DLG stuff */
	if (load_clusterer(binds) == -1)
		return -1;

	return 0;
}

#endif  /* CLUSTERER_API_H */

