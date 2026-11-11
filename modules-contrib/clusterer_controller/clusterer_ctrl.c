/*
 * clusterer_ctrl.c — Controller API implementation for clusterer
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

#include <stdlib.h>
#include <sys/time.h>
#include "../../dprint.h"
#include "../../rw_locking.h"
#include "../../mem/shm_mem.h"
#include "../../locking.h"

#include "node_info.h"
#include "clusterer.h"        /* LS_DOWN, do_actions_node_ev, MAX_NO_CLUSTERS */
#include "sharing_tags.h"
#include "topology.h"       /* delete_neighbour */
#include "../../net/net_tcp.h" /* tcp_close_connection                       */
#include "clusterer_ctrl.h"
#include "sync.h"           /* cl_request_sync_from */

/* declared in clusterer.c - raises E_CLUSTERER_NODE_STATE_CHANGED */
int report_node_state(enum clusterer_event event, int cluster_id, int node_id);

/* current_node is not in node_list: remove_node_list() would walk the list
 * for it and crash */
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

/* @node_id as self_id makes add_node_info() put the entry in current_node
 * (self, not pinged) rather than node_list */
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

    /* the controller announced it, so it is alive; the first probes of a
     * batch of joiners spread out, like corosync's send_join */
    if (new_node && new_node->cluster) {
	struct timeval now, spread;
	int ms = new_node->cluster->no_nodes * CL_CTR_PROBE_SPREAD_MS;

	if (ms > CL_CTR_PROBE_SPREAD_MAX_MS)
	    ms = CL_CTR_PROBE_SPREAD_MAX_MS;
	ms = ms > 0 ? rand() % ms : 0;
	gettimeofday(&now, NULL);
	spread.tv_sec  = ms / 1000;
	spread.tv_usec = (ms % 1000) * 1000;
	lock_get(new_node->lock);
	new_node->flags |= NODE_HEARD;
	timeradd(&now, &spread, &new_node->probe_after);
	lock_release(new_node->lock);
    }

    lock_stop_write(cl_list_lock);

    LM_INFO("clusterer: [cluster %d] added peer node_id=%d url=%.*s\n",
            cluster_id, node_id, bin_url->len, bin_url->s);
    return 0;
}

/* longest BIN url copied out of a node; "bins:[<ipv6>]:<port>" fits */
#define CL_CTRL_URL_BUF  128
/* paranoia bound on the close loop below */
#define CL_CTRL_MAX_CONN_CLOSE 16

/* the core keeps BIN TCP conns keyed by destination, untouched by topology
 * removal; call without cl_list_lock (dispatches to TCP main), on a copied url */
static void close_node_bin_conn(int cluster_id, str *url)
{
    int closed = 0, rc = 0;

    if (!url || !url->len)
        return;

    /* usually two conns (ours out, its in - aliased to this addr); each call
     * closes one and sets F_CONN_FORCE_CLOSED so the next lookup skips it */
    while ((rc = tcp_close_connection(url)) == 1)
        if (++closed >= CL_CTRL_MAX_CONN_CLOSE) {
            LM_WARN("clusterer: [cluster %d] stopped after closing %d BIN "
                    "connections to %.*s - more may remain\n",
                    cluster_id, closed, url->len, url->s);
            return;
        }

    if (rc < 0)
        LM_ERR("clusterer: [cluster %d] failed to close a BIN connection to "
               "%.*s (closed %d before the failure)\n",
               cluster_id, url->len, url->s, closed);
    else if (closed)
        LM_INFO("clusterer: [cluster %d] closed %d BIN connection(s) to %.*s\n",
                cluster_id, closed, url->len, url->s);
    else
        LM_DBG("clusterer: [cluster %d] no open BIN connection to %.*s\n",
               cluster_id, url->len, url->s);
}

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

int clusterer_ctrl_set_cap_state(int cluster_id, int node_id, str *cap, int ok)
{
    cluster_info_t    *cl;
    node_info_t       *node;
    struct remote_cap *cur;
    int                was;

    lock_start_read(cl_list_lock);
    cl = get_cluster_by_id(cluster_id);
    node = cl ? get_node_by_id(cl, node_id) : NULL;
    if (!node) {
	lock_stop_read(cl_list_lock);
	return -1;
    }

    lock_get(node->lock);
    for (cur = node->capabilities; cur && str_strcmp(cap, &cur->name);
	 cur = cur->next) ;
    if (!cur) {
	cur = shm_malloc(sizeof *cur + cap->len);
	if (!cur) {
	    lock_release(node->lock);
	    lock_stop_read(cl_list_lock);
	    LM_ERR("No more shm memory!\n");
	    return -1;
	}
	memset(cur, 0, sizeof *cur);
	cur->name.s   = (char *)(cur + 1);
	cur->name.len = cap->len;
	memcpy(cur->name.s, cap->s, cap->len);
	cur->next = node->capabilities;
	node->capabilities = cur;
    }
    was = !!(cur->flags & CAP_STATE_OK);
    if (ok)
	cur->flags |= CAP_STATE_OK;
    else
	cur->flags &= ~CAP_STATE_OK;
    /* the timer checks it for syncs waiting on a donor */
    if (ok && !was)
	node->flags |= NODE_CAPS_NEW;
    lock_release(node->lock);

    lock_stop_read(cl_list_lock);
    return 0;
}

int clusterer_ctrl_remove_node(int cluster_id, int node_id)
{
    cluster_info_t *cl;
    node_info_t    *node;
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

    /* drop all neighbour/next_hop references before the free, or a reused
     * node_id later follows dangling pointers and crashes */
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

    /* remove_node_list() frees the node: copy the url to close the conn
     * after unlocking */
    if (node->url.s && node->url.len > 0 &&
        node->url.len < (int)sizeof url_buf) {
        memcpy(url_buf, node->url.s, node->url.len);
        url_buf[node->url.len] = '\0';
        url.s   = url_buf;
        url.len = node->url.len;
    }

    /* callbacks run unlocked: they (e.g. dialog rcv_cluster_event) send BIN
     * packets, which takes cl_list_lock for read */
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

    /* after the callbacks: an event_cb may still send a last BIN packet */
    close_node_bin_conn(cluster_id, &url);

    LM_INFO("clusterer: [cluster %d] removed node_id=%d\n",
            cluster_id, node_id);
    return 0;
}

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
	return 0;
    }

    old_node = cl->current_node;
    cl->current_node = NULL;

    /* drop peers' references to the old self before it is freed */
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

    free_current_node(old_node);

    LM_INFO("clusterer: [cluster %d] identity updated to node_id=%d url=%.*s\n",
            cluster_id, new_node_id, bin_url->len, bin_url->s);
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

int clusterer_ctrl_configured_id(void)
{
	return current_id;
}

int clusterer_ctrl_managed(const int **ids)
{
	*ids = cl_ctr_stub_ids;
	return cl_ctr_stub_count;
}


int clusterer_ctrl_data_peer(int cluster_id, int node_id, int match_op,
                             union sockaddr_union *su, int *self_id)
{
    cluster_info_t *cl;
    node_info_t    *node;
    int             rc = -1;

    lock_start_read(cl_list_lock);
    cl = get_cluster_by_id(cluster_id);
    if (!cl || !cl_ctr_owns_membership(cl) || !cl->current_node)
	goto out;
    *self_id = cl->current_node->node_id;
    node = get_node_by_id(cl, node_id);
    if (!node || node == cl->current_node)
	goto out;
    memcpy(su, &node->addr, sizeof *su);
    rc = match_node(node, cl->current_node, (enum cl_node_match_op)match_op);
out:
    lock_stop_read(cl_list_lock);
    return rc;
}

int clusterer_ctrl_self_id(int cluster_id)
{
    int id;

    lock_start_read(cl_list_lock);
    id = cluster_self_id(get_cluster_by_id(cluster_id));
    lock_stop_read(cl_list_lock);
    return id;
}

int clusterer_ctrl_node_bounce(int cluster_id, int node_id)
{
    cluster_info_t *cl;
    node_info_t    *node;
    int             one = 1, rc = -1;

    lock_start_read(cl_list_lock);
    cl = get_cluster_by_id(cluster_id);
    node = cl ? get_node_by_id(cl, node_id) : NULL;
    if (node) {
	rc = 0;
	lock_get(node->lock);
	/* only while modules see it up, and no event of its own is queued */
	if ((node->flags & NODE_REACH) &&
		!(node->flags & (NODE_EVENT_DOWN | NODE_EVENT_UP))) {
	    node->flags |= NODE_EVENT_DOWN | NODE_EVENT_UP;
	    rc = 1;
	}
	lock_release(node->lock);
	/* each pass raises one queued event: the down, then the up */
	if (rc == 1) {
	    do_actions_node_ev(cl, &one, 1);
	    do_actions_node_ev(cl, &one, 1);
	}
    }
    lock_stop_read(cl_list_lock);
    return rc;
}

int clusterer_ctrl_resync_from(int cluster_id, int node_id)
{
    cluster_info_t   *cl;
    struct local_cap *lc;
    int               sent = 0;

    /* from_cb = 1: the list lock is held, as in a module's own callback */
    lock_start_read(cl_list_lock);
    cl = get_cluster_by_id(cluster_id);
    for (lc = cl ? cl->capabilities : NULL; lc; lc = lc->next)
	if ((lc->flags & CAP_SYNC_WANTED) &&
	        cl_request_sync_from(&lc->reg.name, cluster_id, 1, node_id) == 0)
	    sent++;
    lock_stop_read(cl_list_lock);
    return sent;
}
