/*
 * clusterer_ctrl.h — Controller API for the clusterer module
 *
 * Allows an external module (clusterer_controller) to drive the clusterer
 * topology at runtime without any DB or static configuration.
 *
 * Copyright (C) 10/07/2026 Yury Kirsanov
 *                          VoIPLine Telecom
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef CLUSTERER_CTRL_H
#define CLUSTERER_CTRL_H

#include "../../str.h"

/**
 * clusterer_ctrl_binds - API struct loaded by clusterer_controller.
 *
 * Usage in clusterer_controller mod_init():
 *
 *   #include "../clusterer/clusterer_ctrl.h"
 *   static clusterer_ctrl_binds_t clctl;
 *   if (load_clusterer_ctrl_binds(&clctl) < 0) { ... }
 *
 * Then from the worker process / callbacks:
 *
 *   str url = str_init("bin:10.22.23.191:5566");
 *   clctl.set_my_identity(1, my_node_id, &url);
 *
 *   str peer_url = str_init("bin:10.22.23.192:5566");
 *   clctl.add_node(1, peer_node_id, &peer_url);
 *
 *   clctl.remove_node(1, departed_node_id);
 */
typedef struct clusterer_ctrl_binds {
    /**
     * set_my_identity() — register this node's identity in a cluster.
     *
     * Creates the cluster_info_t if it does not yet exist.
     * Sets global current_id and marks cluster->current_node.
     * Must be called before add_node() for the same cluster_id.
     *
     * Called by controller after node_id is allocated (either from
     * existing master via NODE_ASSIGN or from join deadline expiry).
     *
     * @cluster_id  integer cluster identifier (matches controller cluster)
     * @node_id     integer allocated by the controller master (>= 1)
     * @bin_url     str pointing to "bin:IP:PORT"
     * @return 0 on success, -1 on error
     */
    int (*set_my_identity)(int cluster_id, int node_id, str *bin_url);

    /**
     * add_node() — add a peer node to a cluster at runtime.
     *
     * Creates the node_info_t, adds it to the cluster's node_list.
     * The clusterer ping timer picks it up within one ping interval
     * and establishes the BIN link automatically.
     *
     * Called on every CC_PKT_NODE_ASSIGN received for a peer.
     * Safe to call if the node already exists — returns 0 (no-op).
     *
     * @cluster_id  must match a cluster initialised by set_my_identity()
     * @node_id     peer's allocated node_id
     * @bin_url     peer's "bin:IP:PORT" string
     * @return 0 on success, -1 on error
     */
    int (*add_node)(int cluster_id, int node_id, str *bin_url);

    /**
     * remove_node() — remove a peer node from a cluster at runtime.
     *
     * Removes from the node_list and cleans up routing state.
     * The BIN connection is closed by the clusterer's own cleanup path.
     *
     * Called on CC_PKT_GOODBYE or when election-window expiry removes
     * the peer from the controller's own peer table.
     *
     * @cluster_id  cluster the node belongs to
     * @node_id     node_id to remove
     * @return 0 on success, -1 if cluster or node not found
     */
    int (*remove_node)(int cluster_id, int node_id);
    /**
     * update_identity() — correct this node's node_id after master assignment.
     *
     * Called when the real node_id arrives via NODE_ASSIGN and differs from
     * the optimistic value set at startup.  Removes the old current_node
     * entry and adds a new one with the correct node_id, updating both
     * global current_id and cluster->current_node atomically.
     *
     * Safe to call with the same node_id as already set — returns 0 (no-op).
     *
     * @cluster_id  cluster to update
     * @new_node_id the master-assigned node_id
     * @bin_url     this node's "bin:IP:PORT" (may be identical to current)
     * @return 0 on success, -1 on error
     */
    int (*update_identity)(int cluster_id, int new_node_id, str *bin_url);

    /**
     * sync_current_id() - sync local current_id from shared memory.
     *
     * Must be called from child_init() in every child process after fork.
     * current_id is a process-local global — after fork each child inherits
     * the pre-fork value.  This re-reads the correct id from the shared
     * cluster->current_node so BIN packets carry the right source node_id.
     *
     * @return 0 always
     */
    int (*sync_current_id)(void);
} clusterer_ctrl_binds_t;

/**
 * load_clusterer_ctrl_binds() — fill a clusterer_ctrl_binds_t struct.
 *
 * Called from clusterer_controller's mod_init().  Returns -1 if clusterer
 * is not loaded or was not built with use_controller support.
 */
typedef int (*load_clusterer_ctrl_binds_f)(clusterer_ctrl_binds_t *binds);

int load_clusterer_ctrl_binds(clusterer_ctrl_binds_t *binds);

#endif /* CLUSTERER_CTRL_H */
