/*
 * clusterer_ctrl.c — Controller API implementation for clusterer
 *
 * Copyright (C) 2026 Yury Kirsanov
 *                          VoIPLine Telecom
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "../../dprint.h"
#include "../../rw_locking.h"
#include "../../mem/shm_mem.h"
#include "../../locking.h"

#include "node_info.h"        /* add_node_info, remove_node_list,
                                  get_cluster_by_id, get_node_by_id,
                                  cluster_list, cl_list_lock, current_id */
#include "clusterer.h"        /* LS_DOWN, do_actions_node_ev, MAX_NO_CLUSTERS */
#include "sharing_tags.h"
#include "topology.h"       /* delete_neighbour */     /* shtag_event_handler */
#include "../../net/net_tcp.h" /* tcp_close_connection                       */
#include "clusterer_ctrl.h"

/* This whole API is compiled only when the clusterer_controller module is part
 * of the build (see modules/clusterer/Makefile).  In a stock clusterer build the
 * translation unit is empty. */
#ifdef CLUSTERER_CTRL_SUPPORT

/* declared in clusterer.c — raises E_CLUSTERER_NODE_STATE_CHANGED */
int report_node_state(enum clusterer_event event, int cluster_id, int node_id);

/* Free a current_node entry that is NOT in node_list.
 * remove_node_list() walks node_list looking for the pointer — if current_node
 * was never added there (our set_my_identity path) it crashes. */
static void free_current_node(node_info_t *node)
{
    if (!node) return;
    if (node->lock) {
	lock_destroy(node->lock);
	lock_dealloc(node->lock);
    }
    if (node->sp_info)       shm_free(node->sp_info);
    if (node->description.s) shm_free(node->description.s);
    if (node->sip_addr.s)    shm_free(node->sip_addr.s);
    if (node->url.s)         shm_free(node->url.s);
    shm_free(node);
}

/**
 * clusterer_ctrl_set_identity() - register this node's own identity.
 *
 * CRITICAL: current_id MUST be set before calling add_node_info().
 * add_node_info() checks (node_id == current_id) to decide whether to
 * place the entry in cluster->current_node (self, not pinged) or
 * cluster->node_list (peer, pinged).  Setting it after causes the local
 * node to land in node_list and get pinged — "same node id" errors.
 */
int clusterer_ctrl_set_identity(int cluster_id, int node_id, str *bin_url)
{
    node_info_t    *new_node  = NULL;
    cluster_info_t *cl;
    int             int_vals[NO_DB_INT_VALS];
    str             str_vals[NO_DB_STR_VALS];
    static str      desc = str_init("controller");
    static str      seed = str_init("seed");

    int_vals[INT_VALS_ID_COL]              = 0;
    int_vals[INT_VALS_CLUSTER_ID_COL]      = cluster_id;
    int_vals[INT_VALS_NODE_ID_COL]         = node_id;
    int_vals[INT_VALS_STATE_COL]           = 1;
    int_vals[INT_VALS_NO_PING_RETRIES_COL] = DEFAULT_NO_PING_RETRIES;
    int_vals[INT_VALS_PRIORITY_COL]        = DEFAULT_PRIORITY;

    memset(str_vals, 0, sizeof str_vals);
    str_vals[STR_VALS_URL_COL]         = *bin_url;
    str_vals[STR_VALS_FLAGS_COL]       = seed;
    str_vals[STR_VALS_DESCRIPTION_COL] = desc;

    /* Set current_id BEFORE add_node_info */
    current_id = node_id;
    if (_current_id_shm) *_current_id_shm = node_id;

    lock_start_write(cl_list_lock);

    if (add_node_info(&new_node, cluster_list, int_vals, str_vals, node_id) < 0) {
	lock_stop_write(cl_list_lock);
	LM_ERR("clusterer: set_my_identity: add_node_info failed for "
	       "cluster %d node %d\n", cluster_id, node_id);
	return -1;
    }

    cl = get_cluster_by_id(cluster_id);
    if (cl && new_node && !cl->current_node)
	cl->current_node = new_node;

    lock_stop_write(cl_list_lock);

    LM_INFO("clusterer: [cluster %d] identity set: node_id=%d url=%.*s\n",
            cluster_id, node_id, bin_url->len, bin_url->s);
    return 0;
}

/**
 * clusterer_ctrl_add_node() - add a discovered peer at runtime.
 */
int clusterer_ctrl_add_node(int cluster_id, int node_id, str *bin_url)
{
    node_info_t    *new_node  = NULL;
    cluster_info_t *cl;
    int             int_vals[NO_DB_INT_VALS];
    str             str_vals[NO_DB_STR_VALS];
    static str      desc = str_init("controller");
    static str      seed = str_init("seed");

    lock_start_write(cl_list_lock);

    cl = get_cluster_by_id(cluster_id);
    if (cl && get_node_by_id(cl, node_id)) {
	lock_stop_write(cl_list_lock);
	LM_DBG("clusterer: [cluster %d] node %d already present\n",
	       cluster_id, node_id);
	return 0;
    }

    int_vals[INT_VALS_ID_COL]              = 0;
    int_vals[INT_VALS_CLUSTER_ID_COL]      = cluster_id;
    int_vals[INT_VALS_NODE_ID_COL]         = node_id;
    int_vals[INT_VALS_STATE_COL]           = 1;
    int_vals[INT_VALS_NO_PING_RETRIES_COL] = DEFAULT_NO_PING_RETRIES;
    int_vals[INT_VALS_PRIORITY_COL]        = DEFAULT_PRIORITY;

    memset(str_vals, 0, sizeof str_vals);
    str_vals[STR_VALS_URL_COL]         = *bin_url;
    str_vals[STR_VALS_FLAGS_COL]       = seed;
    str_vals[STR_VALS_DESCRIPTION_COL] = desc;

    if (add_node_info(&new_node, cluster_list, int_vals, str_vals, cluster_self_id(cl)) < 0) {
	lock_stop_write(cl_list_lock);
	LM_ERR("clusterer: add_node: add_node_info failed for "
	       "cluster %d node %d\n", cluster_id, node_id);
	return -1;
    }

    lock_stop_write(cl_list_lock);

    LM_INFO("clusterer: [cluster %d] added peer node_id=%d url=%.*s\n",
            cluster_id, node_id, bin_url->len, bin_url->s);
    return 0;
}

/* Longest BIN url we will copy out of a node before it is freed.
 * "bins:[<ipv6>]:<port>" fits comfortably. */
#define CL_CTRL_URL_BUF  128

/**
 * close_node_bin_conn() - drop the BIN connection to a node's url.
 *
 * Removing a node from the topology does NOT touch the transport: clusterer
 * sends via msg_send(send_sock, proto, &node->addr), and the core keeps the
 * TCP connection in its own table keyed by destination.  So a node that has
 * been declared dead keeps a perfectly good socket open until the TCP layer
 * times it out or the peer closes first - and a node that is dead to the
 * control plane but still reachable on BIN (hung, or partitioned only on the
 * control plane) holds it open indefinitely.
 *
 * This lives in clusterer rather than in clusterer_controller on purpose: the
 * BIN transport is clusterer's, and the controller should drive it through
 * this API rather than reaching into the core's TCP layer itself.
 *
 * Must be called WITHOUT cl_list_lock held - closing dispatches to the TCP
 * main process, and the url must have been copied out of the node first,
 * because remove_node_list() frees the node.
 */
static void close_node_bin_conn(int cluster_id, str *url)
{
    if (!url || !url->len)
        return;

    LM_INFO("clusterer: [cluster %d] dropping BIN connection to %.*s\n",
            cluster_id, url->len, url->s);

    /* 0 is also returned when there is simply no open connection, which is a
     * perfectly normal state - only a parse/lookup failure is worth a word. */
    if (tcp_close_connection(url) < 0)
        LM_DBG("clusterer: [cluster %d] could not close BIN connection to "
               "%.*s\n", cluster_id, url->len, url->s);
}

/**
 * clusterer_ctrl_close_node_conn() - close a node's BIN connection, leaving
 * the node in the topology.
 *
 * Exposed so the controller can drop a peer's transport explicitly.  The
 * usual path is clusterer_ctrl_remove_node(), which now does this for you.
 */
int clusterer_ctrl_close_node_conn(int cluster_id, int node_id)
{
    cluster_info_t *cl;
    node_info_t    *node;
    char            buf[CL_CTRL_URL_BUF];
    str             url = {NULL, 0};

    lock_start_read(cl_list_lock);
    cl   = get_cluster_by_id(cluster_id);
    node = cl ? get_node_by_id(cl, node_id) : NULL;
    if (node && node->url.s && node->url.len > 0 &&
        node->url.len < (int)sizeof buf) {
        memcpy(buf, node->url.s, node->url.len);
        buf[node->url.len] = '\0';
        url.s   = buf;
        url.len = node->url.len;
    }
    lock_stop_read(cl_list_lock);

    if (!url.len) {
        LM_WARN("clusterer: close_node_conn: node %d not found in cluster %d, "
                "or it has no usable url\n", node_id, cluster_id);
        return -1;
    }

    close_node_bin_conn(cluster_id, &url);
    return 0;
}

/**
 * clusterer_ctrl_remove_node() - remove a departed peer at runtime.
 */
int clusterer_ctrl_remove_node(int cluster_id, int node_id)
{
    cluster_info_t *cl;
    node_info_t    *node;
    /* copied out under the lock, used after the node has been freed */
    char            url_buf[CL_CTRL_URL_BUF];
    str             url = {NULL, 0};

    lock_start_write(cl_list_lock);

    cl = get_cluster_by_id(cluster_id);
    if (!cl) {
	lock_stop_write(cl_list_lock);
	LM_WARN("clusterer: remove_node: cluster %d not found\n", cluster_id);
	return -1;
    }

    node = get_node_by_id(cl, node_id);
    if (!node) {
	lock_stop_write(cl_list_lock);
	LM_WARN("clusterer: remove_node: node %d not found in cluster %d\n",
	        node_id, cluster_id);
	return -1;
    }

    /* Purge all topology references to the departing node BEFORE
     * freeing it: neighbour lists of current_node and every peer,
     * plus next_hop pointers. Freed-node reuse (same node_id
     * reassigned later) otherwise leaves dangling pointers that
     * crash with bogus proto/node values.                        */
    {
        node_info_t *it;
        if (cl->current_node)
            delete_neighbour(cl->current_node, node);
        for (it = cl->node_list; it; it = it->next) {
            if (it == node) continue;
            lock_get(it->lock);
            delete_neighbour(it, node);
            if (it->next_hop && it->next_hop->node_id == node_id)
                it->next_hop = NULL;
            lock_release(it->lock);
        }
    }

    /* remove_node_list() frees the node, so take the BIN url now - we need it
     * after the lock is dropped to close the connection. */
    if (node->url.s && node->url.len > 0 &&
        node->url.len < (int)sizeof url_buf) {
        memcpy(url_buf, node->url.s, node->url.len);
        url_buf[node->url.len] = '\0';
        url.s   = url_buf;
        url.len = node->url.len;
    }

    /* Remove node from list, then fire callbacks outside the lock.
     * Callbacks (dialog rcv_cluster_event) call back into clusterer
     * to send BIN packets and need cl_list_lock for read.          */
    remove_node_list(cl, node);

    {
        struct local_cap *cap_it;
        struct local_cap *caps = cl->capabilities;
        lock_stop_write(cl_list_lock);
        for (cap_it = caps; cap_it; cap_it = cap_it->next)
            if (cap_it->reg.event_cb)
                cap_it->reg.event_cb(CLUSTER_NODE_DOWN, node_id);
        report_node_state(CLUSTER_NODE_DOWN, cluster_id, node_id);
    }

    /* Last, and deliberately after the callbacks: a capability's event_cb may
     * still want to send a final BIN packet to the departing node, and pulling
     * the socket out from under it first would only turn that into an error. */
    close_node_bin_conn(cluster_id, &url);

    LM_INFO("clusterer: [cluster %d] removed node_id=%d\n",
            cluster_id, node_id);
    return 0;
}

/**
 * clusterer_ctrl_update_identity() - correct this node's node_id.
 *
 * Replaces the optimistic node_id=1 with the real master-assigned id.
 * No-op if id unchanged.
 *
 * CRITICAL: current_id must be set BEFORE free+add so add_node_info
 * routes the new entry to current_node (self) not node_list (peer).
 * current_node is NOT in node_list so we free it directly — calling
 * remove_node_list() on it would crash walking the list for a pointer
 * that isn't there.
 */
int clusterer_ctrl_update_identity(int cluster_id, int new_node_id, str *bin_url)
{
    cluster_info_t *cl;
    node_info_t    *new_node  = NULL;
    node_info_t    *old_node;
    int             int_vals[NO_DB_INT_VALS];
    str             str_vals[NO_DB_STR_VALS];
    static str      desc = str_init("controller");
    static str      seed = str_init("seed");

    lock_start_write(cl_list_lock);

    cl = get_cluster_by_id(cluster_id);
    if (!cl) {
	lock_stop_write(cl_list_lock);
	LM_ERR("clusterer: update_identity: cluster %d not found\n", cluster_id);
	return -1;
    }

    if (cl->current_node && cl->current_node->node_id == new_node_id) {
	lock_stop_write(cl_list_lock);
	return 0;   /* no-op */
    }

    /* Set current_id BEFORE free+add */
    current_id = new_node_id;
    if (_current_id_shm) *_current_id_shm = new_node_id;

    old_node = cl->current_node;
    cl->current_node = NULL;

    /* Purge all peer neighbour references to the old current_node before
     * freeing it — same as clusterer_ctrl_remove_node does for peers. */
    if (old_node) {
        node_info_t *it;
        for (it = cl->node_list; it; it = it->next) {
            lock_get(it->lock);
            delete_neighbour(it, old_node);
            if (it->next_hop && it->next_hop->node_id == old_node->node_id)
                it->next_hop = NULL;
            lock_release(it->lock);
        }
    }

    int_vals[INT_VALS_ID_COL]              = 0;
    int_vals[INT_VALS_CLUSTER_ID_COL]      = cluster_id;
    int_vals[INT_VALS_NODE_ID_COL]         = new_node_id;
    int_vals[INT_VALS_STATE_COL]           = 1;
    int_vals[INT_VALS_NO_PING_RETRIES_COL] = DEFAULT_NO_PING_RETRIES;
    int_vals[INT_VALS_PRIORITY_COL]        = DEFAULT_PRIORITY;

    memset(str_vals, 0, sizeof str_vals);
    str_vals[STR_VALS_URL_COL]         = *bin_url;
    str_vals[STR_VALS_FLAGS_COL]       = seed;
    str_vals[STR_VALS_DESCRIPTION_COL] = desc;

    if (add_node_info(&new_node, cluster_list, int_vals, str_vals, new_node_id) < 0) {
	lock_stop_write(cl_list_lock);
	LM_ERR("clusterer: update_identity: add_node_info failed for "
	       "cluster %d node %d\n", cluster_id, new_node_id);
	free_current_node(old_node);
	return -1;
    }

    cl->current_node = new_node;

    lock_stop_write(cl_list_lock);

    /* Free old entry outside the lock */
    free_current_node(old_node);

    LM_INFO("clusterer: [cluster %d] identity updated to node_id=%d url=%.*s\n",
            cluster_id, new_node_id, bin_url->len, bin_url->s);
    return 0;
}

/**
 * load_clusterer_ctrl_binds() - fill the API struct for use by controller.
 */
int clusterer_ctrl_sync_current_id(void)
{
	cluster_info_t *cl;

	if (!cl_list_lock || !cluster_list || !*cluster_list)
		return 0;

	lock_start_read(cl_list_lock);
	for (cl = *cluster_list; cl; cl = cl->next) {
		if (cl->current_node) {
			current_id = cl->current_node->node_id;
			break;
		}
	}
	lock_stop_read(cl_list_lock);
	return 0;
}

int clusterer_ctrl_activate_backup_shtags(int cluster_id)
{
	return shtag_activate_all_backup(cluster_id);
}

int clusterer_ctrl_force_backup_shtags(int cluster_id)
{
	return shtag_force_all_backup(cluster_id);
}

int clusterer_ctrl_set_shtag_managed(int cluster_id)
{
	cluster_info_t *cl;

	lock_start_write(cl_list_lock);
	cl = get_cluster_by_id(cluster_id);
	if (!cl) {
		lock_stop_write(cl_list_lock);
		LM_ERR("clusterer: set_shtag_managed: cluster %d not found\n",
		       cluster_id);
		return -1;
	}
	cl->shtag_managed = 1;
	lock_stop_write(cl_list_lock);

	LM_INFO("clusterer: [cluster %d] sharing tags are now "
	        "controller-managed (MI and script changes blocked)\n",
	        cluster_id);
	return 0;
}

int clusterer_ctrl_unset_shtag_managed(int cluster_id)
{
	cluster_info_t *cl;

	lock_start_write(cl_list_lock);
	cl = get_cluster_by_id(cluster_id);
	if (!cl) {
		lock_stop_write(cl_list_lock);
		LM_ERR("clusterer: unset_shtag_managed: cluster %d not found\n",
		       cluster_id);
		return -1;
	}
	cl->shtag_managed = 0;
	lock_stop_write(cl_list_lock);

	LM_INFO("clusterer: [cluster %d] sharing tags are no longer "
	        "controller-managed (MI and script changes allowed again)\n",
	        cluster_id);
	return 0;
}

/* 1 once a controller module has bound this API (see clusterer_ctrl.h). */
int clusterer_ctrl_bound = 0;

int load_clusterer_ctrl_binds(clusterer_ctrl_binds_t *binds)
{
    if (!binds) {
	LM_ERR("clusterer: load_clusterer_ctrl_binds: NULL binds\n");
	return -1;
    }
    clusterer_ctrl_bound   = 1;
    binds->managed_count   = cl_ctr_stub_count;
    binds->managed_ids     = cl_ctr_stub_ids;
    binds->set_my_identity        = clusterer_ctrl_set_identity;
    binds->add_node               = clusterer_ctrl_add_node;
    binds->remove_node            = clusterer_ctrl_remove_node;
    binds->close_node_conn        = clusterer_ctrl_close_node_conn;
    binds->update_identity        = clusterer_ctrl_update_identity;
    binds->sync_current_id        = clusterer_ctrl_sync_current_id;
    binds->activate_backup_shtags = clusterer_ctrl_activate_backup_shtags;
    binds->set_shtag_managed      = clusterer_ctrl_set_shtag_managed;
    binds->unset_shtag_managed    = clusterer_ctrl_unset_shtag_managed;
    binds->force_backup_shtags    = clusterer_ctrl_force_backup_shtags;
    return 0;
}

#endif /* CLUSTERER_CTRL_SUPPORT */
