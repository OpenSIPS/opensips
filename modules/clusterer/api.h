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

/* the type for any sync packet, for any capability */
#define SYNC_PACKET_TYPE 101

/* values returned by shtag_get_f and shtag_set_f */
#define SHTAG_STATE_BACKUP 0
#define SHTAG_STATE_ACTIVE 1

enum cl_node_state {
	STATE_DISABLED,	/* don't send any messages and drop received ones */
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
	CLUSTERER_SEND_SUCCESS = 0,
	CLUSTERER_CURR_DISABLED = 1,  /* current node disabled */
	CLUSTERER_DEST_DOWN = -1,     /* destination node(s) already down or probing */
	CLUSTERER_SEND_ERR = -2       /* error */
};

enum clusterer_event {
	CLUSTER_NODE_UP,	/* node became reachable */
	CLUSTER_NODE_DOWN,	/* node became unreachable */
	SYNC_REQ_RCV,		/* received a data sync request */
	SYNC_DONE			/* sync finished - all sync packets received and
						 * all packets buffered during sync delivered */
};

enum cl_node_match_op {
	NODE_CMP_ANY,
	NODE_CMP_EQ_SIP_ADDR,
	NODE_CMP_NEQ_SIP_ADDR
};

enum node_addr_type {
	NODE_BIN_ADDR,
	NODE_SIP_ADDR
};

/*
 * Return the list of reachable nodes in the cluster.
 */
typedef clusterer_node_t* (*get_nodes_f)(int cluster_id);
/*
 * Free the list returned by the get_nodes_f function.
 */
typedef void (*free_nodes_f)(clusterer_node_t *list);

/*
 * Set the state (enabled or disabled) of the current node in the cluster.
 */
typedef int (*set_state_f)(int cluster_id, enum cl_node_state state);

/*
 * Check if the given address belongs to one of the nodes in the cluster.
 * The address to be checked can be the node's bin connector or the provisioned
 * sip_addr in the clusterer table.
 */
typedef int (*check_addr_f)(int cluster_id, str *ip_str,
							enum node_addr_type check_type);

/*
 * Get the node id of the current node.
 */
typedef int (*get_my_id_f)(void);

/*
 * Get the SIP address of the current node within cluster @cluster_id.
 *
 * Return: 0 on success, -1 otherwise.
 *         IMPORTANT: pkg_free(out_addr->s) after you're done!
 */
typedef int (*get_my_sip_addr_f)(int cluster_id, str *out_addr);

/*
 * Return an index for the current node, with a value between [0, @nr_nodes-1],
 * which belongs to a continuous sequence of identifiers for the nodes in the cluster.
 * This function operates on a set of nodes which are reachable and
 * synchronized/OK (for a certain capability).
 *
 * @nr_nodes - output parameter, the number of nodes in the set.  Guaranteed
 *             to be a positive integer!
 */
typedef int (*get_my_index_f)(int cluster_id, str *capability, int *nr_nodes);

/*
 * Send a message to a specific node in the cluster.
 */
typedef enum clusterer_send_ret (*send_to_f)(bin_packet_t *packet, int cluster_id,
												int node_id);
/*
 * Send a message to all the nodes in the cluster.
 */
typedef enum clusterer_send_ret (*send_all_f)(bin_packet_t *packet, int cluster_id);

/*
 * Send a message to all @dst_cluster_id nodes (excluding self)
 * which match ourselves using the @match_op filtering operator.
 */
typedef enum clusterer_send_ret (*send_all_having_f)(bin_packet_t *packet,
                        int dst_cluster_id, enum cl_node_match_op match_op);

/*
 * Return the next hop from the shortest path to the given destination.
 */
typedef clusterer_node_t* (*get_next_hop_f)(int cluster_id, int node_id);
/*
 * Free node returned by the get_next_hop_f function.
 */
typedef void (*free_next_hop_f)(clusterer_node_t *next_hop);

/*
 * This function will be called for:
 *   - every regular binary packet received;
 *   - every sync packet received;
 *   - all regular packets buffered during sync (@packet - list head).
 */
typedef void (*cl_packet_cb_f)(bin_packet_t *packet);
/*
 * This function will be called in order to signal certain cluster events.
 */
typedef void (*cl_event_cb_f)(enum clusterer_event ev, int node_id);

/*
 * Register a capability(grouping of BIN packets/cluster events used to
 * achieve a certain functionality).
 *
 * @startup_sync: require a sync on startup (1), or just start this cap
 *                in the OK state (0)
 * @sync_cond: only sync with certain types of nodes
 *             (useful for federated usrloc)
 */
typedef int (*register_capability_f)(str *cap, cl_packet_cb_f packet_cb,
					cl_event_cb_f event_cb, int cluster_id, int startup_sync,
					enum cl_node_match_op sync_cond);

/*
 * Request to synchronize data for a given capability from another node.
 */
typedef int (*request_sync_f)(str * capability, int cluster_id);
/*
 * Returns a BIN packet in which to include a distinct "chunk" of data
 * (e.g. info about a single usrloc contact) to sync.
 *
 * The same packet will be returned multiple times if there is enough space left
 * otherwise, a new packet will be built and the previous one will be sent out.
 *
 * @data_version: a way for modules to avoid data corruption when receiving
 *                sync packets from an OpenSIPS running a different version
 *
 * This function should only be called from the callback for the SYNC_REQ_RCV event.
 */
typedef bin_packet_t* (*sync_chunk_start_f)(str *capability, int cluster_id,
                                            int dst_id, short data_version);
/*
 * Iterate over chunks of data from a received sync packet.
 *
 * Returns 1 if there are any chunks left, and 0 otherwise.
 */
typedef int (*sync_chunk_iter_f)(bin_packet_t *packet);

/*
 * Gets the state of a sharing tag by name and cluster ID
 *
 * Returns -1 if error or the status of the tag (>=0)
 */
typedef int (*shtag_get_f)(str *tag, int cluster_id);

/*
 * Activates a sharing tag by name and cluster ID
 *
 * Returns -1 if error or the new status of the tag (>=0)
 */
typedef int (*shtag_activate_f)(str *tag, int cluster_id);

/*
 * Gets a list with all the active tags from a cluster
 *
 * Returns NULL if none or a list of pointers to the tag names
 */
typedef str** (*shtag_get_all_active_f)(int cluster_id);

/*
 * Callback function for monitoring the changes in the state of shtag
 */

typedef void (*shtag_cb_f)(str *tag_name, int state, int c_id, void *param);

/*
 * Registers a callback to notify upon changes in a sharing tag state
 * If the tag_name is NULL or empty, the callback will be triggered for
 * all the tags in the given cluster. If the cluster ID is negative, the
 * callback will be triggered for tags in all clusters.
 *
 * Returns -1 if error, 0 if success
 */
typedef int (*shtag_register_callback_f)(str *tag_name, int c_id,
		void *param, shtag_cb_f func);


struct clusterer_binds {
	get_nodes_f get_nodes;
	free_nodes_f free_nodes;
	set_state_f set_state;
	check_addr_f check_addr;
	get_my_id_f get_my_id;
	get_my_sip_addr_f get_my_sip_addr;
	get_my_index_f get_my_index;
	send_to_f send_to;
	send_all_f send_all;
	send_all_having_f send_all_having;
	get_next_hop_f get_next_hop;
	free_next_hop_f free_next_hop;
	register_capability_f register_capability;
	request_sync_f request_sync;
	sync_chunk_start_f sync_chunk_start;
	sync_chunk_iter_f sync_chunk_iter;
	shtag_get_f shtag_get;
	shtag_activate_f shtag_activate;
	shtag_get_all_active_f shtag_get_all_active;
	shtag_register_callback_f shtag_register_callback;
};

typedef int (*load_clusterer_f)(struct clusterer_binds *binds);

int load_clusterer(struct clusterer_binds *binds);

static inline int load_clusterer_api(struct clusterer_binds *binds) {
	load_clusterer_f load_clusterer;

	/* import the clusterer auto-loading function */
	if (!(load_clusterer = (load_clusterer_f) find_export("load_clusterer", 0)))
		return -1;

	/* let the auto-loading function load all clusterer API functions */
	if (load_clusterer(binds) == -1)
		return -1;

	return 0;
}

/* function used to add dependencies to clusterer module */
static inline module_dependency_t *get_deps_clusterer(param_export_t *param)
{
	int cluster_id = *(int *)param->param_pointer;

	if (cluster_id <= 0)
		return NULL;

	return alloc_module_dep(MOD_TYPE_DEFAULT, "clusterer", DEP_ABORT);
}


#endif  /* CLUSTERER_API_H */

