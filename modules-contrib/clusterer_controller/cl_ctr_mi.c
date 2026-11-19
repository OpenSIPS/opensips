/*
 * clusterer_controller - MI commands
 *
 * Copyright (C) 2026 Yury Kirsanov
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

#include "cl_ctr.h"
#include "cl_ctr_caps.h"
#include "cl_ctr_identity.h"

/* clusterer:list_members */
mi_response_t *mi_cl_ctr_members(const mi_params_t *params,
                                     struct mi_handler *hdl)
{
    mi_response_t  *resp;
    mi_item_t      *arr, *cl_obj, *members_arr, *peer_obj, *bin_arr;
    int             i, j, ci, im;
    cl_ctr_cluster_t   *cl;

    resp = init_mi_result_array(&arr);
    if (!resp)
	return NULL;

    for (ci = 0; ci < cl_ctr_cluster_count; ci++) {
	cl = &cl_ctr_clusters[ci];
	if (!cl->peers)
	    continue;

	cl_obj = add_mi_object(arr, NULL, 0);
	if (!cl_obj) goto error;

	if (add_mi_number(cl_obj, MI_SSTR("cluster_id"), cl->cluster_id) < 0)
	    goto error;

	members_arr = add_mi_array(cl_obj, MI_SSTR("members"));
	if (!members_arr) goto error;

	lock_start_read(cl->peers->lock);
	/* capabilities only where known first-hand: every member's on the master
	 * (ALIVEs go there), the master's and its own on a member */
	im = cl_ctr_i_am_master_locked(cl);

	for (i = 0; i < cl->peers->count; i++) {
	    cl_ctr_peer_t *e = &cl->peers->entries[i];

	    peer_obj = add_mi_object(members_arr, NULL, 0);
	    if (!peer_obj) {
		lock_stop_read(cl->peers->lock);
		goto error;
	    }
	    if (add_mi_number(peer_obj, MI_SSTR("mtu"), e->mtu) < 0 ||
	        add_mi_string(peer_obj, MI_SSTR("ip"),
	                      e->ip, strlen(e->ip)) < 0 ||
	        add_mi_number(peer_obj, MI_SSTR("node_id"), e->node_id) < 0 ||
	        add_mi_string(peer_obj, MI_SSTR("status"),
	                      e->is_master ? "master" : (e->is_backup ? "backup" : "member"),
	                      6) < 0 ||
	        add_mi_string(peer_obj, MI_SSTR("maintenance"),
	                      cl_ctr_maint_name(e->maint),
	                      strlen(cl_ctr_maint_name(e->maint))) < 0 ||
	        add_mi_string(peer_obj, MI_SSTR("admission"),
	                      e->connecting ? "connecting" : "online",
	                      e->connecting ? 10 : 6) < 0 ||
	        ((im || e->is_master || strcmp(e->ip, my_ip) == 0) &&
	         cl_ctr_mi_add_caps(peer_obj, MI_SSTR("capabilities"),
	                            strcmp(e->ip, my_ip) == 0 ? cl_ctr_caps_mine(cl)
	                                                      : e->caps) < 0)) {
		lock_stop_read(cl->peers->lock);
		goto error;
	    }

	    bin_arr = add_mi_array(peer_obj, MI_SSTR("bin_sockets"));
	    if (!bin_arr) {
		lock_stop_read(cl->peers->lock);
		goto error;
	    }
	    for (j = 0; j < (int)e->bin_count; j++) {
		if (add_mi_string(bin_arr, NULL, 0,
		                  e->bin_sockets[j],
		                  strlen(e->bin_sockets[j])) < 0) {
		    lock_stop_read(cl->peers->lock);
		    goto error;
		}
	    }
	}

	lock_stop_read(cl->peers->lock);
    }

    return resp;

error:
    LM_ERR("clusterer_controller: mi_cl_ctr_members: failed to build response\n");
    free_mi_response(resp);
    return NULL;
}

/* clusterer:node_info node_id=N */
mi_response_t *mi_cl_ctr_node_info(const mi_params_t *params,
                                      struct mi_handler *hdl)
{
    mi_response_t  *resp;
    mi_item_t      *root, *bin_arr;
    int             target_id;
    int             i, j, ci;
    cl_ctr_cluster_t   *cl;
    cl_ctr_peer_t      *e;

    if (get_mi_int_param(params, "node_id", &target_id) < 0)
	return init_mi_param_error();

    for (ci = 0; ci < cl_ctr_cluster_count; ci++) {
	cl = &cl_ctr_clusters[ci];
	if (!cl->peers)
	    continue;

	lock_start_read(cl->peers->lock);
	for (i = 0; i < cl->peers->count; i++) {
	    e = &cl->peers->entries[i];
	    if ((int)e->node_id != target_id)
		continue;

	    resp = init_mi_result_object(&root);
	    if (!resp) {
		lock_stop_read(cl->peers->lock);
		return NULL;
	    }
	    if (add_mi_number(root, MI_SSTR("mtu"),        e->mtu)                 < 0 ||
	        add_mi_number(root, MI_SSTR("node_id"),    e->node_id)             < 0 ||
	        add_mi_string(root, MI_SSTR("ip"),         e->ip, strlen(e->ip))   < 0 ||
	        add_mi_number(root, MI_SSTR("cluster_id"), cl->cluster_id)          < 0 ||
	        add_mi_string(root, MI_SSTR("status"),
	                      e->is_master ? "master" : (e->is_backup ? "backup" : "member"),
	                      6)                                                     < 0 ||
	        add_mi_string(root, MI_SSTR("admission"),
	                      e->connecting ? "connecting" : "online",
	                      e->connecting ? 10 : 6)                                < 0) {
		lock_stop_read(cl->peers->lock);
		goto error_node;
	    }
	    bin_arr = add_mi_array(root, MI_SSTR("bin_sockets"));
	    if (!bin_arr) {
		lock_stop_read(cl->peers->lock);
		goto error_node;
	    }
	    for (j = 0; j < (int)e->bin_count; j++) {
		if (add_mi_string(bin_arr, NULL, 0,
		                  e->bin_sockets[j],
		                  strlen(e->bin_sockets[j])) < 0) {
		    lock_stop_read(cl->peers->lock);
		    goto error_node;
		}
	    }
	    lock_stop_read(cl->peers->lock);
	    return resp;
	}
	lock_stop_read(cl->peers->lock);
    }

    return init_mi_error(404, MI_SSTR("node_id not found"));

error_node:
    LM_ERR("clusterer_controller: mi_cl_ctr_node_info: failed to build response\n");
    free_mi_response(resp);
    return NULL;
}

/* clusterer:list_config - each cluster's effective settings and counters;
 * the password is deliberately not shown */
mi_response_t *mi_cl_ctr_config(const mi_params_t *params,
                                     struct mi_handler *hdl)
{
    mi_response_t  *resp;
    mi_item_t      *arr, *cl_obj;
    int             ci, members;
    char            mcast[INET_ADDRSTRLEN + 8];  /* "IP:PORT" */
    char            shtag_mode[24];              /* "auto" / "override:<id>" */
    cl_ctr_cluster_t   *cl;

    resp = init_mi_result_array(&arr);
    if (!resp)
	return NULL;

    for (ci = 0; ci < cl_ctr_cluster_count; ci++) {
	cl = &cl_ctr_clusters[ci];

	cl_obj = add_mi_object(arr, NULL, 0);
	if (!cl_obj) goto error;

	snprintf(mcast, sizeof(mcast), "%s:%d",
	         cl->multicast_address, cl->multicast_port);

	members = 0;
	/* the effective (possibly adopted) settings the worker mirrors in shm;
	 * the configured ones until the peer table is up */
	int eff_manage = cl->manage_shtags, eff_stick = cl->master_stickiness,
	    eff_qt = query_time;
	unsigned int term = 0;
	char cid_s[37] = "";
	const char *cid_st = "none";
	uint32_t      ccaps;
	unsigned long foreign = 0, refused = 0, stalls = 0, terms_refused = 0,
	              rx_drops = 0, holds = 0, ka_false = 0;
	int           ka_mean = 0, ka_dev = 0, ka_margin = 0, ka_to = 0, lhm = 0,
	              released = 0;
	int           rcvbuf = 0, nforeign = 0, k;
	long long     stall_max = 0;
	time_t        tnow = cl_ctr_now();
	struct { char uuid[37], ip[CL_CTR_MAX_IP_LEN + 1];
	         long first_ago, last_ago; unsigned long pkts; }
	              fc[CL_CTR_FOREIGN_MAX];
	mi_item_t    *fc_arr, *fc_obj;
	{
	    uint16_t forced = 0;
	    if (cl->peers) {
		lock_start_read(cl->peers->lock);
		members    = cl->peers->count;
		term       = cl->peers->master_term;
		cid_st     = cl_ctr_cid_state_name(cl->peers->cid_state);
		if (cl->peers->cid_state != CL_CTR_CID_NONE)
		    cl_ctr_cid_str(cl->peers->cid, cid_s);
		foreign    = cl->peers->foreign_pkts;
		refused    = cl->peers->peers_refused;
		stalls     = cl->peers->self_stalls;
		terms_refused = cl->peers->terms_refused;
		rx_drops   = cl->peers->rx_kernel_drops;
		holds      = cl->peers->election_holds;
		ka_mean    = cl->peers->ka_mean_ms;
		ka_dev     = cl->peers->ka_dev_ms;
		ka_margin  = cl->peers->ka_margin_ms;
		ka_to      = cl->peers->ka_timeout_ms;
		ka_false   = cl->peers->ka_false_suspicions;
		lhm        = cl->peers->local_health;
		released   = cl->peers->tag_released;
		rcvbuf     = cl->peers->rcvbuf_bytes;
		stall_max  = cl->peers->self_stall_max_ms;
		forced     = cl->peers->shtag_forced_node_id;
		eff_manage = cl->peers->eff_manage_shtags;
		eff_stick  = cl->peers->eff_master_stickiness;
		eff_qt     = cl->peers->eff_query_time;
		nforeign   = cl->peers->foreign_n;
		for (k = 0; k < nforeign; k++) {
		    cl_ctr_cid_str(cl->peers->foreign[k].uuid, fc[k].uuid);
		    memcpy(fc[k].ip, cl->peers->foreign[k].last_ip,
		           sizeof(fc[k].ip));
		    fc[k].first_ago = (long)(tnow - cl->peers->foreign[k].first_seen);
		    fc[k].last_ago  = (long)(tnow - cl->peers->foreign[k].last_seen);
		    fc[k].pkts      = cl->peers->foreign[k].pkts;
		}
		lock_stop_read(cl->peers->lock);
	    }
	    /* "auto" = master-driven, "override:<node_id>" = clusterer:shtag_force
	     * ("manual" is reserved for maintenance mode) */
	    if (forced)
		snprintf(shtag_mode, sizeof(shtag_mode), "override:%u", forced);
	    else
		snprintf(shtag_mode, sizeof(shtag_mode), "auto");
	}

	ccaps = cl->peers ? cl_ctr_cluster_caps(cl) : cl_ctr_caps_mine(cl);
	if (add_mi_number(cl_obj, MI_SSTR("cluster_id"),   cl->cluster_id)        < 0 ||
	    add_mi_string(cl_obj, MI_SSTR("multicast"),    mcast, strlen(mcast))  < 0 ||
	    add_mi_string(cl_obj, MI_SSTR("my_ip"),        my_ip, strlen(my_ip))  < 0 ||
	    add_mi_string(cl_obj, MI_SSTR("bin_socket"),
	                  cl->bin_socket, strlen(cl->bin_socket))                 < 0 ||
	    add_mi_number(cl_obj, MI_SSTR("mtu"),          cc_mtu)                 < 0 ||
	    add_mi_string(cl_obj, MI_SSTR("identity_source"),
	                  cl_ctr_identity_src, strlen(cl_ctr_identity_src))       < 0 ||
	    add_mi_number(cl_obj, MI_SSTR("proposed_node_id"), cl_ctr_proposal)   < 0 ||
	    add_mi_string(cl_obj, MI_SSTR("interface"),
	                  my_interface_buf[0] ? my_interface_buf : "(unknown)",
	                  my_interface_buf[0] ? strlen(my_interface_buf) : 9)      < 0 ||
	    add_mi_number(cl_obj, MI_SSTR("query_time"),   eff_qt)                < 0 ||
	    add_mi_number(cl_obj, MI_SSTR("master_stickiness"), eff_stick)        < 0 ||
	    add_mi_number(cl_obj, MI_SSTR("manage_shtags"), eff_manage)           < 0 ||
	    add_mi_string(cl_obj, MI_SSTR("shtag_mode"),
	                  shtag_mode, strlen(shtag_mode))                         < 0 ||
	    add_mi_number(cl_obj, MI_SSTR("member_count"), members)               < 0 ||
	    add_mi_number(cl_obj, MI_SSTR("term"),         term)                  < 0 ||
	    add_mi_string(cl_obj, MI_SSTR("cluster_uuid"), cid_s, strlen(cid_s))  < 0 ||
	    add_mi_string(cl_obj, MI_SSTR("cluster_uuid_state"),
	                  cid_st, strlen(cid_st))                                 < 0 ||
	    add_mi_number(cl_obj, MI_SSTR("foreign_packets"), foreign)            < 0 ||
	    add_mi_number(cl_obj, MI_SSTR("peer_capacity"), CL_CTR_MAX_PEERS)     < 0 ||
	    add_mi_number(cl_obj, MI_SSTR("peers_refused"), refused)              < 0 ||
	    add_mi_number(cl_obj, MI_SSTR("self_stalls"), stalls)                 < 0 ||
	    add_mi_number(cl_obj, MI_SSTR("self_stall_max_ms"), stall_max)        < 0 ||
	    add_mi_number(cl_obj, MI_SSTR("terms_refused"), terms_refused)        < 0 ||
	    add_mi_number(cl_obj, MI_SSTR("election_holds"), holds)               < 0 ||
	    add_mi_number(cl_obj, MI_SSTR("master_ka_mean_ms"), ka_mean)          < 0 ||
	    add_mi_number(cl_obj, MI_SSTR("master_ka_dev_ms"), ka_dev)            < 0 ||
	    add_mi_number(cl_obj, MI_SSTR("master_ka_margin_ms"), ka_margin)      < 0 ||
	    add_mi_number(cl_obj, MI_SSTR("master_timeout_ms"), ka_to)            < 0 ||
	    add_mi_number(cl_obj, MI_SSTR("master_false_suspicions"), ka_false)   < 0 ||
	    add_mi_number(cl_obj, MI_SSTR("local_health"), lhm)                   < 0 ||
	    add_mi_number(cl_obj, MI_SSTR("release_tag_when_isolated"),
	                  release_tag_when_isolated)                              < 0 ||
	    add_mi_number(cl_obj, MI_SSTR("tag_released"), released)              < 0 ||
	    add_mi_number(cl_obj, MI_SSTR("rcvbuf_bytes"), rcvbuf)                < 0 ||
	    add_mi_number(cl_obj, MI_SSTR("rx_kernel_drops"), rx_drops)           < 0 ||
	    cl_ctr_mi_add_caps(cl_obj, MI_SSTR("cluster_capabilities"), ccaps)  < 0)
	    goto error;
	fc_arr = add_mi_array(cl_obj, MI_SSTR("foreign_clusters"));
	if (!fc_arr)
	    goto error;
	for (k = 0; k < nforeign; k++) {
	    fc_obj = add_mi_object(fc_arr, NULL, 0);
	    if (!fc_obj ||
	        add_mi_string(fc_obj, MI_SSTR("cluster_uuid"), fc[k].uuid,
	                      strlen(fc[k].uuid))                         < 0 ||
	        add_mi_string(fc_obj, MI_SSTR("last_sender"), fc[k].ip,
	                      strlen(fc[k].ip))                           < 0 ||
	        add_mi_number(fc_obj, MI_SSTR("first_seen_s_ago"), fc[k].first_ago) < 0 ||
	        add_mi_number(fc_obj, MI_SSTR("last_seen_s_ago"), fc[k].last_ago)   < 0 ||
	        add_mi_number(fc_obj, MI_SSTR("packets"), fc[k].pkts)       < 0)
		goto error;
	}
    }

    return resp;

error:
    LM_ERR("clusterer_controller: mi_cl_ctr_config: failed to build response\n");
    free_mi_response(resp);
    return NULL;
}

/* IPC job in the worker once MI has set shtag_forced_node_id: apply it now and,
 * on the master, re-broadcast MEMBER_LIST so members learn it */
static void cl_ctr_rpc_apply_shtags(int sender, void *param)
{
    cl_ctr_cluster_t *cl = (cl_ctr_cluster_t *)param;
    int i_am_master;

    (void)sender;
    if (!cl || !cl->peers)
	return;

    cl_ctr_apply_shtags(cl);

    lock_start_read(cl->peers->lock);
    i_am_master = cl_ctr_i_am_master_locked(cl);
    lock_stop_read(cl->peers->lock);

    if (i_am_master && cl->sock >= 0)
	cl_ctr_send_member_list(cl->sock, cl);
}

static cl_ctr_cluster_t *cl_ctr_mi_find_cluster(int cluster_id)
{
    int ci;
    for (ci = 0; ci < cl_ctr_cluster_count; ci++)
	if (cl_ctr_clusters[ci].cluster_id == cluster_id)
	    return &cl_ctr_clusters[ci];
    return NULL;
}

/* clusterer:maintenance - puts this node in or out of maintenance */
mi_response_t *mi_cl_ctr_maintenance(const mi_params_t *params,
                                            struct mi_handler *hdl)
{
    int               cluster_id, st;
    str               state;
    cl_ctr_cluster_t *cl;

    if (get_mi_int_param(params, "cluster_id", &cluster_id) < 0 ||
        get_mi_string_param(params, "state", &state.s, &state.len) < 0)
	return init_mi_param_error();
    st = cl_ctr_maint_parse(state.s, state.len);
    if (st < 0)
	return init_mi_error(400, MI_SSTR("state must be evicted, full or none"));
    cl = cl_ctr_mi_find_cluster(cluster_id);
    if (!cl || !cl->peers)
	return init_mi_error(404, MI_SSTR("cluster_id not found"));
    if (cl_ctr_set_my_maint(cl, st) < 0)
	return init_mi_error(500, MI_SSTR("controller worker not running yet"));
    return init_mi_result_ok();
}

/* with node_id: multicast to the cluster, the node named applies it to itself */
mi_response_t *mi_cl_ctr_maintenance_node(const mi_params_t *params,
                                                 struct mi_handler *hdl)
{
    int               cluster_id, node_id, st, k, found = 0, me = 0;
    str               state;
    cl_ctr_cluster_t *cl;

    if (get_mi_int_param(params, "cluster_id", &cluster_id) < 0 ||
        get_mi_string_param(params, "state", &state.s, &state.len) < 0 ||
        get_mi_int_param(params, "node_id", &node_id) < 0)
	return init_mi_param_error();
    st = cl_ctr_maint_parse(state.s, state.len);
    if (st < 0)
	return init_mi_error(400, MI_SSTR("state must be evicted, full or none"));
    cl = cl_ctr_mi_find_cluster(cluster_id);
    if (!cl || !cl->peers)
	return init_mi_error(404, MI_SSTR("cluster_id not found"));
    lock_start_read(cl->peers->lock);
    for (k = 0; k < cl->peers->count; k++) {
	cl_ctr_peer_t *e = &cl->peers->entries[k];
	if (node_id > 0 && e->node_id == node_id)
	    found = 1;
	if (strcmp(e->ip, my_ip) == 0)
	    me = e->node_id;
    }
    lock_stop_read(cl->peers->lock);
    if (!found)
	return init_mi_error(404, MI_SSTR("node_id not a member of this cluster"));
    if ((node_id == me ? cl_ctr_set_my_maint(cl, st)
                       : cl_ctr_set_node_maint(cl, (uint16_t)node_id, st)) < 0)
	return init_mi_error(500, MI_SSTR("controller worker not running yet"));
    return init_mi_result_ok();
}

/* clusterer:shtag_force - master only; pins the active tag on node_id until
 * shtag_auto, across failover, cleared when that node leaves */
mi_response_t *mi_cl_ctr_shtag_force(const mi_params_t *params,
                                        struct mi_handler *hdl)
{
    int            cluster_id, node_id;
    cl_ctr_cluster_t  *cl;
    int            i_am_master, found = 0, in_maint = 0, proc_no;

    if (get_mi_int_param(params, "cluster_id", &cluster_id) < 0 ||
        get_mi_int_param(params, "node_id",    &node_id)    < 0)
	return init_mi_param_error();

    if (node_id <= 0 || node_id > 0xFFFF)
	return init_mi_error(400, MI_SSTR("node_id out of range"));

    cl = cl_ctr_mi_find_cluster(cluster_id);
    if (!cl || !cl->peers)
	return init_mi_error(404, MI_SSTR("cluster_id not found"));

    if (!cl->manage_shtags)
	return init_mi_error(409,
	        MI_SSTR("shtag management is disabled for this cluster"));

    lock_start_write(cl->peers->lock);
    i_am_master = cl_ctr_i_am_master_locked(cl);
    if (i_am_master) {
	int i;
	for (i = 0; i < cl->peers->count; i++) {
	    if ((int)cl->peers->entries[i].node_id == node_id) {
		found = 1;
		break;
	    }
	}
	/* a node in maintenance holds no tag (a pin on one entering maintenance
	 * is cleared by cl_ctr_maint_peer_changed()) */
	if (found && cl->peers->entries[i].maint != CL_CTR_MAINT_NONE)
	    in_maint = 1;
	else if (found)
	    cl->peers->shtag_forced_node_id = (uint16_t)node_id;
    }
    proc_no = cl->peers->worker_proc_no;
    lock_stop_write(cl->peers->lock);

    if (!i_am_master)
	return init_mi_error(409,
	        MI_SSTR("not the master - issue clusterer:shtag_force on the master node"));
    if (!found)
	return init_mi_error(404, MI_SSTR("node_id not a member of this cluster"));
    if (in_maint)
	return init_mi_error(409, MI_SSTR("node is in maintenance - it cannot hold the tag"));

    /* Apply locally and broadcast the new override from the worker process. */
    if (proc_no >= 0)
	ipc_send_rpc(proc_no, cl_ctr_rpc_apply_shtags, cl);

    LM_INFO("clusterer_controller: [cluster %d] operator forced shtag onto "
            "node %d\n", cluster_id, node_id);
    return init_mi_result_ok();
}

/* clusterer:shtag_auto - master only; drops the shtag_force override */
mi_response_t *mi_cl_ctr_shtag_auto(const mi_params_t *params,
                                       struct mi_handler *hdl)
{
    int            cluster_id;
    cl_ctr_cluster_t  *cl;
    int            i_am_master, proc_no;

    if (get_mi_int_param(params, "cluster_id", &cluster_id) < 0)
	return init_mi_param_error();

    cl = cl_ctr_mi_find_cluster(cluster_id);
    if (!cl || !cl->peers)
	return init_mi_error(404, MI_SSTR("cluster_id not found"));

    lock_start_write(cl->peers->lock);
    i_am_master = cl_ctr_i_am_master_locked(cl);
    if (i_am_master)
	cl->peers->shtag_forced_node_id = 0;
    proc_no = cl->peers->worker_proc_no;
    lock_stop_write(cl->peers->lock);

    if (!i_am_master)
	return init_mi_error(409,
	        MI_SSTR("not the master - issue clusterer:shtag_auto on the master node"));

    if (proc_no >= 0)
	ipc_send_rpc(proc_no, cl_ctr_rpc_apply_shtags, cl);

    LM_INFO("clusterer_controller: [cluster %d] operator resumed automatic "
            "shtag allocation\n", cluster_id);
    return init_mi_result_ok();
}
