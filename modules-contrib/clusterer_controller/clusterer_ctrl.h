/*
 * clusterer_ctrl.h — Controller API for the clusterer module
 *
 * Allows an external module (clusterer_controller) to drive the clusterer
 * topology at runtime without any DB or static configuration.
 *
 * Copyright (C) 2026 Yury Kirsanov
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
#include "../../ip_addr.h"   /* union sockaddr_union */

/* clusterer's side of the controller: what the controller calls in it */

/* register this node in a cluster (created if new) as its current_node;
 * call before add_node(), @bin_url is "bin:IP:PORT" */
int clusterer_ctrl_set_identity(int cluster_id, int node_id, str *bin_url);

/* add a peer at runtime (0, no-op, if present); the ping timer brings up
 * its BIN link within one ping interval */
int clusterer_ctrl_add_node(int cluster_id, int node_id, str *bin_url);

/* remove a peer at runtime and close its BIN connection;
 * -1 if the cluster or node is unknown */
int clusterer_ctrl_remove_node(int cluster_id, int node_id);

/* close a node's BIN connection but keep it in the topology */
int clusterer_ctrl_close_node_conn(int cluster_id, int node_id);

/* replace this node's optimistic node_id with the master-assigned one
 * (0, no-op, if unchanged) */
int clusterer_ctrl_update_identity(int cluster_id, int new_node_id, str *bin_url);

/* activate all BACKUP sharing tags: master only, when a peer departs or
 * this node becomes master */
int clusterer_ctrl_activate_backup_shtags(int cluster_id);

/* force all local sharing tags to BACKUP regardless of =active,
 * at startup when the controller manages tags */
int clusterer_ctrl_force_backup_shtags(int cluster_id);

/* block MI clusterer_set_tag_active and $shtag() writes for the cluster so
 * they cannot fight controller failover (manage_shtags=1) */
int clusterer_ctrl_set_shtag_managed(int cluster_id);

/* re-allow MI/script shtag changes, on adopting a running cluster's
 * manage_shtags=0 (on_config_mismatch=adopt) */
int clusterer_ctrl_unset_shtag_managed(int cluster_id);

/* cluster_ids with cluster_options use_controller=1: returns the count,
 * @ids points at clusterer's own array (valid for the process lifetime) */
int clusterer_ctrl_managed(const int **ids);

/* the node id configured with my_node_id (-1 when it is not set) */
int clusterer_ctrl_configured_id(void);
/* a controller cluster's heartbeats: liveness, a node's links (node_id bitmap)
 * and its capability states, none of it flooded */
int clusterer_ctrl_set_heard(int cluster_id, int node_id, int heard);
int clusterer_ctrl_set_links(int cluster_id, int node_id,
                             const unsigned char *bm, int bm_sz);
int clusterer_ctrl_set_cap_state(int cluster_id, int node_id, str *cap, int ok);
/* data plane: @node_id's BIN address and this node's id; 1 if it matches
 * @match_op, 0 if not, -1 if unknown */
int clusterer_ctrl_data_peer(int cluster_id, int node_id, int match_op,
                             union sockaddr_union *su, int *self_id);
int clusterer_ctrl_self_id(int cluster_id);
/* raise @node_id down then up to this node's modules (broadcasts it sent were
 * lost); 1 if raised, 0 if it is not up to them, -1 if unknown */
int clusterer_ctrl_node_bounce(int cluster_id, int node_id);
/* every capability that syncs at startup syncs again, from @node_id when it can
 * serve it (0: any donor); how many requests were made */
int clusterer_ctrl_resync_from(int cluster_id, int node_id);
/* a cluster_options string; -1 on an unknown or repeated key or a bad value */
int cl_ctr_parse_options(str *descr, int *cid, int *uc);

#endif /* CLUSTERER_CTRL_H */
