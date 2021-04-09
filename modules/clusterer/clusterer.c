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
#include "../../ipc.h"

#include "api.h"
#include "node_info.h"
#include "clusterer.h"
#include "topology.h"
#include "sync.h"
#include "sharing_tags.h"
#include "clusterer_evi.h"

struct clusterer_binds clusterer_api;

enum sip_protos clusterer_proto = PROTO_BIN;

str cl_internal_cap = str_init("clusterer-internal");
str cl_extra_cap = str_init("clusterer-extra");

extern int ping_interval;
extern int node_timeout;
extern int ping_timeout;
extern int seed_fb_interval;

void seed_fb_check_timer(utime_t ticks, void *param)
{
	cluster_info_t *cl;
	struct local_cap *cap;
	struct timeval now;

	gettimeofday(&now, NULL);

	lock_start_read(cl_list_lock);

	for (cl = *cluster_list; cl; cl = cl->next) {
		lock_get(cl->current_node->lock);
		if (!(cl->current_node->flags & NODE_STATE_ENABLED)) {
			lock_release(cl->current_node->lock);
			continue;
		}
		lock_release(cl->current_node->lock);

		for (cap = cl->capabilities; cap; cap = cap->next) {
			lock_get(cl->lock);
			if ((cap->flags & CAP_STATE_ENABLED) &&
				!(cap->flags & CAP_STATE_OK) &&
				(cl->current_node->flags & NODE_IS_SEED) &&
				(TIME_DIFF(cap->sync_req_time, now) >= seed_fb_interval*1000000)) {
				cap->flags |= CAP_STATE_OK;
				LM_INFO("No donor found, falling back to synced state\n");
				/* send update about the state of this capability */
				send_single_cap_update(cl, cap, 1);
			}

			lock_release(cl->lock);
		}
	}

	lock_stop_read(cl_list_lock);
}

int cl_set_state(int cluster_id, int node_id, enum cl_node_state state)
{
	cluster_info_t *cluster = NULL;
	node_info_t *node;
	int ev_actions_required = 1;
	int new_link_states = 0;

	lock_start_read(cl_list_lock);

	cluster = get_cluster_by_id(cluster_id);
	if (!cluster) {
		lock_stop_read(cl_list_lock);
		LM_ERR("Cluster id [%d] not found\n", cluster_id);
		return -1;
	}

	if (node_id != current_id) {
		node = get_node_by_id(cluster, node_id);
		if (!node) {
			lock_stop_read(cl_list_lock);
			LM_ERR("Node id [%d] not found\n", node_id);
			return 1;
		}

		lock_get(node->lock);

		if (state == STATE_DISABLED && node->flags & NODE_STATE_ENABLED)
			new_link_states = LS_DOWN;
		else if (state == STATE_ENABLED && !(node->flags & NODE_STATE_ENABLED))
			new_link_states = LS_RESTART_PINGING;

		if (state == STATE_DISABLED)
			node->flags &= ~NODE_STATE_ENABLED;
		else
			node->flags |= NODE_STATE_ENABLED;

		lock_release(node->lock);

		if (new_link_states == LS_DOWN) {
			set_link_w_neigh_adv(-1, LS_DOWN, node);

			do_actions_node_ev(cluster, &ev_actions_required, 1);
		} else if (new_link_states == LS_RESTART_PINGING) {
			set_link_w_neigh(LS_RESTART_PINGING, node);
		}

		lock_stop_read(cl_list_lock);

		LM_INFO("Set state: %s for node: %d in cluster: %d\n",
				state ? "enabled" : "disabled", node_id, cluster_id);

		if (db_mode && update_db_state(cluster_id, node_id, state) < 0)
			LM_ERR("Failed to update state in clusterer DB for node [%d] cluster [%d]\n",
				node_id, cluster_id);

		return 0;
	}

	lock_get(cluster->current_node->lock);

	if (state == STATE_DISABLED && cluster->current_node->flags & NODE_STATE_ENABLED)
		new_link_states = LS_DOWN;
	else if (state == STATE_ENABLED && !(cluster->current_node->flags & NODE_STATE_ENABLED))
		new_link_states = LS_RESTART_PINGING;

	if (state == STATE_DISABLED)
		cluster->current_node->flags &= ~NODE_STATE_ENABLED;
	else
		cluster->current_node->flags |= NODE_STATE_ENABLED;

	lock_release(cluster->current_node->lock);

	if (new_link_states == LS_DOWN) {
		for (node = cluster->node_list; node; node = node->next)
			set_link_w_neigh(LS_DOWN, node);

		do_actions_node_ev(cluster, &ev_actions_required, 1);
	} else if (new_link_states == LS_RESTART_PINGING) {
		for (node = cluster->node_list; node; node = node->next)
			set_link_w_neigh(LS_RESTART_PINGING, node);
	}

	lock_stop_read(cl_list_lock);

	LM_INFO("Set state: %s for local node in cluster: %d\n",
			state ? "enabled" : "disabled", cluster_id);

	if (db_mode && update_db_state(cluster_id, current_id, state) < 0)
		LM_ERR("Failed to update state in clusterer DB for cluster [%d]\n", cluster->cluster_id);

	return 0;
}

int mi_cap_set_state(int cluster_id, str *capability, int status)
{
	cluster_info_t *cluster;
	struct local_cap *cap;
	int change = 0;

	lock_start_read(cl_list_lock);

	cluster = get_cluster_by_id(cluster_id);
	if (!cluster) {
		lock_stop_read(cl_list_lock);
		LM_ERR("Cluster id [%d] not found\n", cluster_id);
		return -1;
	}

	for (cap = cluster->capabilities; cap &&
		str_strcmp(capability, &cap->reg.name); cap = cap->next) ;
	if (!cap) {
		lock_stop_read(cl_list_lock);
		LM_ERR("Capability [%.*s] not found\n",
			capability->len, capability->s);
		return -2;
	}

	lock_get(cluster->lock);

	if (status == CAP_DISABLED && cap->flags & CAP_STATE_ENABLED) {
		cap->flags &= ~CAP_STATE_ENABLED;
		cap->flags &= ~CAP_STATE_OK;
		change = 1;
	} else if (status == CAP_ENABLED && !(cap->flags & CAP_STATE_ENABLED)) {
		cap->flags |= CAP_STATE_ENABLED;
		change = 1;
	}

	lock_release(cluster->lock);

	if (change)
		send_single_cap_update(cluster, cap, status);

	lock_stop_read(cl_list_lock);

	return 0;
}

int get_capability_status(cluster_info_t *cluster, str *capability)
{
	struct local_cap *cap;

	for (cap = cluster->capabilities; cap &&
		str_strcmp(capability, &cap->reg.name); cap = cap->next) ;
	if (!cap) {
		LM_ERR("Capability [%.*s] not found\n",
			capability->len, capability->s);
		return -1;
	}

	return (cap->flags&CAP_STATE_ENABLED) ?
		CAP_ENABLED : CAP_DISABLED;
}

/* @return:
 *  0 : success, message sent
 * -1 : error, unable to send
 * -2 : dest down or probing
 */
static int msg_send_retry(bin_packet_t *packet, node_info_t *dest,
							int change_dest, int *ev_actions_required)
{
	int retr_send = 0;
	node_info_t *chosen_dest = dest;
	str send_buffer;

	do {
		lock_get(chosen_dest->lock);

		if (chosen_dest->link_state != LS_UP) {
			lock_release(chosen_dest->lock);

			chosen_dest = get_next_hop_2(dest);
			if (!chosen_dest) {
				if (retr_send)
					return -1;
				else
					return -2;
			}
		} else
			lock_release(chosen_dest->lock);

		/* change destination node id */
		if (change_dest || chosen_dest != dest) {
			bin_remove_int_buffer_end(packet, 1);
			bin_push_int(packet, dest->node_id);
		}
		bin_get_buffer(packet, &send_buffer);

		if (msg_send(chosen_dest->cluster->send_sock, chosen_dest->proto,
			&chosen_dest->addr, 0, send_buffer.s, send_buffer.len, 0) < 0) {
			LM_ERR("msg_send() to node [%d] failed\n", chosen_dest->node_id);
			retr_send = 1;

			/* this node was supposed to be up, retry pinging */
			set_link_w_neigh_adv(-1, LS_RESTART_PINGING, chosen_dest);

			*ev_actions_required = 1;
		} else {
			LM_DBG("sent bin packet to node [%d]\n", chosen_dest->node_id);
			retr_send = 0;
		}
	} while (retr_send);

	return 0;
}

enum clusterer_send_ret clusterer_send_msg(bin_packet_t *packet,
	int cluster_id, int dst_node_id, int check_cap)
{
	node_info_t *node;
	int rc;
	cluster_info_t *cl;
	int ev_actions_required = 0;
	str capability;

	if (!cl_list_lock) {
		LM_ERR("cluster shutdown - cannot send new messages!\n");
		return CLUSTERER_CURR_DISABLED;
	}
	lock_start_read(cl_list_lock);

	cl = get_cluster_by_id(cluster_id);
	if (!cl) {
		LM_ERR("Unknown cluster id [%d]\n", cluster_id);
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

	node = get_node_by_id(cl, dst_node_id);
	if (!node) {
		LM_ERR("Node id [%d] not found in cluster\n", dst_node_id);
		lock_stop_read(cl_list_lock);
		return CLUSTERER_SEND_ERR;
	}

	lock_get(node->lock);
	if (!(node->flags & NODE_STATE_ENABLED)) {
		lock_release(node->lock);
		lock_stop_read(cl_list_lock);
		LM_DBG("node disabled, skip message sending\n");
		return CLUSTERER_SEND_SUCCESS;
	}
	lock_release(node->lock);

	if (check_cap) {
		bin_get_capability(packet, &capability);
		rc = get_capability_status(cl, &capability);
		if (rc == -1) {
			lock_stop_read(cl_list_lock);
			return CLUSTERER_SEND_ERR;
		} else if (rc == CAP_DISABLED) {
			lock_stop_read(cl_list_lock);
			LM_DBG("capability disabled, skip message sending\n");
			return CLUSTERER_SEND_SUCCESS;
		}
	}

	rc = msg_send_retry(packet, node, 0, &ev_actions_required);

	bin_remove_int_buffer_end(packet, 3);

	if (ev_actions_required)
		do_actions_node_ev(cl, &ev_actions_required, 1);

	lock_stop_read(cl_list_lock);

	switch (rc) {
	case  0:
		return CLUSTERER_SEND_SUCCESS;
	case -1:
		return CLUSTERER_SEND_ERR;
	case -2:
		return CLUSTERER_DEST_DOWN;
	}

	return CLUSTERER_SEND_ERR;
}

static enum clusterer_send_ret
clusterer_bcast_msg(bin_packet_t *packet, int dst_cid,
                    enum cl_node_match_op match_op, int check_cap)
{
	node_info_t *node;
	int rc, sent = 0, down = 1, matched_once = 0;
	cluster_info_t *dst_cl;
	int ev_actions_required = 0;
	str capability;

	if (!cl_list_lock) {
		LM_ERR("cluster shutdown - cannot send new messages!\n");
		return CLUSTERER_CURR_DISABLED;
	}
	lock_start_read(cl_list_lock);

	dst_cl = get_cluster_by_id(dst_cid);
	if (!dst_cl) {
		LM_ERR("Unknown cluster, id [%d]\n", dst_cid);
		lock_stop_read(cl_list_lock);
		return CLUSTERER_SEND_ERR;
	}

	lock_get(dst_cl->current_node->lock);
	if (!(dst_cl->current_node->flags & NODE_STATE_ENABLED)) {
		lock_release(dst_cl->current_node->lock);
		lock_stop_read(cl_list_lock);
		return CLUSTERER_CURR_DISABLED;
	}
	lock_release(dst_cl->current_node->lock);

	if (check_cap) {
		bin_get_capability(packet, &capability);
		rc = get_capability_status(dst_cl, &capability);
		if (rc == -1) {
			lock_stop_read(cl_list_lock);
			return CLUSTERER_SEND_ERR;
		} else if (rc == CAP_DISABLED) {
			lock_stop_read(cl_list_lock);
			LM_DBG("capability [%.*s] disabled, skip message sending\n",
				capability.len, capability.s);
			return CLUSTERER_SEND_SUCCESS;
		}
	}

	for (node = dst_cl->node_list; node; node = node->next) {
		if (!match_node(dst_cl->current_node, node, match_op))
			continue;

		lock_get(node->lock);
		if (!(node->flags & NODE_STATE_ENABLED)) {
			lock_release(node->lock);
			LM_DBG("node disabled, skip message sending\n");
			continue;
		}
		lock_release(node->lock);

		matched_once = 1;

		rc = msg_send_retry(packet, node, 1, &ev_actions_required);
		if (rc != -2)	/* at least one node is up */
			down = 0;
		if (rc == 0)	/* at least one message is sent successfully */
			sent = 1;
	}

	bin_remove_int_buffer_end(packet, 3);

	if (ev_actions_required)
		do_actions_node_ev(dst_cl, &ev_actions_required, 1);

	lock_stop_read(cl_list_lock);

	if (!matched_once)
		return CLUSTERER_SEND_SUCCESS;

	if (down)
		return CLUSTERER_DEST_DOWN;
	if (sent)
		return CLUSTERER_SEND_SUCCESS;
	else
		return CLUSTERER_SEND_ERR;
}

int msg_add_trailer(bin_packet_t *packet, int cluster_id, int dst_id)
{
	if (bin_push_int(packet, cluster_id) < 0)
		return -1;
	if (bin_push_int(packet, current_id) < 0)
		return -1;
	if (bin_push_int(packet, dst_id) < 0)
		return -1;

	return 0;
}

static int prep_gen_msg(bin_packet_t *packet, int cluster_id, int dst_id,
							str *gen_msg, str *exchg_tag, int req_like)
{
	/* build packet */
	if (bin_init(packet, &cl_extra_cap, CLUSTERER_GENERIC_MSG, BIN_VERSION, 0) < 0) {
		LM_ERR("Failed to init bin send buffer\n");
		return -1;
	}

	/* mark this message as request-like if it is the case */
	if (bin_push_int(packet, req_like) < 0)
		return -1;
	/* include an 'exchange tag' in order to possbily correlate the messages
	 * sent with replies to be received (which should contain the same tag) */
	if (bin_push_str(packet, exchg_tag) < 0)
		return -1;
	if (bin_push_str(packet, gen_msg) < 0)
		return -1;
	/* add the trailer as for an usual module message */
	if (msg_add_trailer(packet, cluster_id, dst_id) < 0)
		return -1;

	return 0;
}

enum clusterer_send_ret cl_send_to(bin_packet_t *packet, int cluster_id, int node_id)
{
	if (msg_add_trailer(packet, cluster_id, node_id) < 0) {
		LM_ERR("Failed to add trailer to module's message\n");
		return CLUSTERER_SEND_ERR;
	}

	return clusterer_send_msg(packet, cluster_id, node_id, 1);
}

enum clusterer_send_ret cl_send_all(bin_packet_t *packet, int cluster_id)
{
	if (msg_add_trailer(packet, cluster_id, -1 /* dummy value */) < 0) {
		LM_ERR("Failed to add trailer to module's message\n");
		return CLUSTERER_SEND_ERR;
	}

	return clusterer_bcast_msg(packet, cluster_id, NODE_CMP_ANY, 1);
}

enum clusterer_send_ret
cl_send_all_having(bin_packet_t *packet, int dst_cluster_id,
                   enum cl_node_match_op match_op)
{
	if (msg_add_trailer(packet, dst_cluster_id, -1 /* dummy value */) < 0) {
		LM_ERR("Failed to add trailer to module's message\n");
		return CLUSTERER_SEND_ERR;
	}

	return clusterer_bcast_msg(packet, dst_cluster_id, match_op, 1);
}

enum clusterer_send_ret send_gen_msg(int cluster_id, int dst_id, str *gen_msg,
										str *exchg_tag, int req_like)
{
	bin_packet_t packet;
	int rc;

	if (prep_gen_msg(&packet, cluster_id, dst_id, gen_msg, exchg_tag, req_like) < 0) {
		LM_ERR("Failed to build generic clusterer message\n");
		return CLUSTERER_SEND_ERR;
	}

	rc = clusterer_send_msg(&packet, cluster_id, dst_id, 0);

	bin_free_packet(&packet);

	return rc;
}

enum clusterer_send_ret bcast_gen_msg(int cluster_id, str *gen_msg, str *exchg_tag)
{
	bin_packet_t packet;
	int rc;

	if (prep_gen_msg(&packet, cluster_id, -1 /* dummy value */, gen_msg,
			exchg_tag, 1) < 0) {
		LM_ERR("Failed to build generic clusterer message\n");
		return CLUSTERER_SEND_ERR;
	}

	rc = clusterer_bcast_msg(&packet, cluster_id, NODE_CMP_ANY, 0);

	bin_free_packet(&packet);

	return rc;
}

enum clusterer_send_ret send_mi_cmd(int cluster_id, int dst_id, str cmd_name,
								mi_item_t *cmd_params_arr, int no_params)
{
	bin_packet_t packet;
	int i, rc;
	str val;

	if (bin_init(&packet, &cl_extra_cap, CLUSTERER_MI_CMD, BIN_VERSION, 0) < 0) {
		LM_ERR("Failed to init bin send buffer\n");
		return CLUSTERER_SEND_ERR;
	}

	if (bin_push_str(&packet, &cmd_name) < 0)
		return CLUSTERER_SEND_ERR;
	if (bin_push_int(&packet, no_params) < 0)
		return CLUSTERER_SEND_ERR;
	for (i = 0; i < no_params; i++) {
		if (get_mi_arr_param_string(cmd_params_arr, i, &val.s, &val.len) < 0)
			return CLUSTERER_SEND_ERR;

		if (bin_push_str(&packet, &val) < 0)
			return CLUSTERER_SEND_ERR;
	}

	if (msg_add_trailer(&packet, cluster_id, dst_id ? dst_id : -1) < 0) {
		LM_ERR("Failed to add trailer to module's message\n");
		return CLUSTERER_SEND_ERR;
	}

	if (dst_id)
		rc = clusterer_send_msg(&packet, cluster_id, dst_id, 0);
	else
		rc = clusterer_bcast_msg(&packet, cluster_id, NODE_CMP_ANY, 0);

	bin_free_packet(&packet);

	return rc;
}

enum clusterer_send_ret bcast_remove_node(int cluster_id, int target_node)
{
	bin_packet_t packet;
	int rc;

	if (bin_init(&packet, &cl_extra_cap, CLUSTERER_REMOVE_NODE,
		BIN_VERSION, 0) < 0) {
		LM_ERR("Failed to init bin send buffer\n");
		return CLUSTERER_SEND_ERR;
	}

	if (bin_push_int(&packet, target_node) < 0)
		return CLUSTERER_SEND_ERR;

	if (msg_add_trailer(&packet, cluster_id, -1) < 0) {
		LM_ERR("Failed to add trailer to module's message\n");
		return CLUSTERER_SEND_ERR;
	}

	rc = clusterer_bcast_msg(&packet, cluster_id, NODE_CMP_ANY, 0);

	bin_free_packet(&packet);

	return rc;
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

static int ip_check(cluster_info_t *cluster, union sockaddr_union *su, str *ip_str)
{
	node_info_t *node;
	str sip_addr;
	char *p;

	for (node = cluster->node_list; node; node = node->next)
		if (su) {
			if (su_ip_cmp(su, &node->addr))
				return 1;
		} else if (ip_str && ip_str->s) {
			if ((p = q_memchr(node->sip_addr.s, ':', node->sip_addr.len))) {
				sip_addr.s = node->sip_addr.s;
				sip_addr.len = p - node->sip_addr.s;
			} else
				sip_addr = node->sip_addr;

			if (!str_strcmp(ip_str, &sip_addr))
				return 1;
		} else {
			LM_ERR("No address to check\n");
			return 0;
		}

	return 0;
}

int clusterer_check_addr(int cluster_id, str *ip_str,
							enum node_addr_type check_type)
{
	cluster_info_t *cluster;
	int rc;
	struct ip_addr ip;
	union sockaddr_union su;

	lock_start_read(cl_list_lock);
	cluster = get_cluster_by_id(cluster_id);
	if (!cluster) {
		LM_WARN("Unknown cluster id [%d]\n", cluster_id);
		return 0;
	}

	if (check_type == NODE_BIN_ADDR) {
		ip.af = AF_INET;
		ip.len = 16;
		if (inet_pton(AF_INET, ip_str->s, ip.u.addr) <= 0) {
			LM_ERR("Invalid IP address\n");
			return 0;
		}
		ip_addr2su(&su, &ip, 0);

		rc = ip_check(cluster, &su, NULL);
		
	} else if (check_type == NODE_SIP_ADDR) {
		rc = ip_check(cluster, NULL, ip_str);
	} else {
		LM_ERR("Bad address type\n");
		rc = 0;
	}

	lock_stop_read(cl_list_lock);
	/* return 1 if addr matched, 0 for ALL other cases, unless return codes implemented */
	return rc;
}

static void handle_cap_update(bin_packet_t *packet, node_info_t *source)
{
	str cap;
	int nr_cap, i, j;
	struct remote_cap *cur;
	struct local_cap *lcap;
	int nr_nodes;
	int node_id;
	node_info_t *node;
	int cap_state;
	int rc;
	int require_reply;

	bin_pop_int(packet, &nr_nodes);

	for (i = 0; i < nr_nodes; i++) {
		bin_pop_int(packet, &node_id);

		if (node_id == current_id) {
			bin_pop_int(packet, &nr_cap);
			for (j = 0; j < nr_cap; j++) {
				bin_pop_str(packet, &cap);
				bin_pop_int(packet, &cap_state);
			}
			continue;
		}
		node = get_node_by_id(source->cluster, node_id);
		if (!node) {
			LM_ERR("Unknown id [%d] in capability update from node [%d]\n",
				node_id, source->node_id);
			return;
		}

		bin_pop_int(packet, &nr_cap);
		for (j = 0; j < nr_cap; j++) {
			bin_pop_str(packet, &cap);
			bin_pop_int(packet, &cap_state);

			lock_get(node->lock);

			for (cur = node->capabilities; cur && str_strcmp(&cap, &cur->name);
				cur = cur->next) ;
			if (!cur) {	/* new capability */
				cur = shm_malloc(sizeof(struct remote_cap) + cap.len);
				if (!cur) {
					LM_ERR("No more shm memory!\n");
					lock_release(node->lock);
					return;
				}
				memset(cur, 0, sizeof *cur);
				cur->name.s = (char *)(cur + 1);
				cur->name.len = cap.len;
				memcpy(cur->name.s, cap.s, cap.len);

				cur->next = node->capabilities;
				node->capabilities = cur;
			}

			if (cap_state == 0)
				cur->flags &= ~CAP_STATE_OK;
			else if (cap_state == 1)
				cur->flags |= CAP_STATE_OK;
			else
				LM_ERR("Received bad state for capability:%.*s from node [%d]\n",
					cap.len, cap.s, source->node_id);
			lock_release(node->lock);

			/* for a node in state OK, check pending sync requests */
			if (cap_state == 1) {
				for (lcap = source->cluster->capabilities; lcap; lcap = lcap->next)
					if (!str_strcmp(&cap, &lcap->reg.name))
						break;
				if (lcap) {
					lock_get(source->cluster->lock);
					if (lcap->flags & CAP_SYNC_PENDING) {
						lock_release(source->cluster->lock);

						if (!match_node(source->cluster->current_node, node,
						                lcap->reg.sync_cond)) {
							LM_DBG("no match for node id %d\n", node->node_id);
							continue;
						}

						rc = send_sync_req(&cap, source->cluster->cluster_id,
											node_id);
						if (rc == CLUSTERER_SEND_SUCCESS) {
							lock_get(source->cluster->lock);
							lcap->flags &= ~CAP_SYNC_PENDING;
							lock_release(source->cluster->lock);
						} else if (rc == CLUSTERER_SEND_ERR)
							LM_ERR("Failed to send sync request to node: %d\n",
								node_id);
					} else
						lock_release(source->cluster->lock);
				}
			}
		}
	}

	bin_pop_int(packet, &require_reply);
	if (require_reply)
		/* also send current node's capabilities information to source node */
		send_cap_update(source, 0);

	/* flood to other neighbours */
	flood_message(packet, source->cluster, source->node_id, require_reply);
}

static void handle_internal_msg(bin_packet_t *received, int packet_type,
		node_info_t *src_node, struct timeval rcv_time, int *ev_actions_required)
{
	switch (packet_type) {
	case CLUSTERER_PONG:
		LM_DBG("Received ping reply from node [%d]\n", src_node->node_id);
		handle_pong(received, src_node, rcv_time, ev_actions_required);
		break;
	case CLUSTERER_PING:
		handle_ping(received, src_node, rcv_time, ev_actions_required);
		break;
	case CLUSTERER_LS_UPDATE:
		handle_ls_update(received, src_node, ev_actions_required);
		break;
	case CLUSTERER_FULL_TOP_UPDATE:
		LM_DBG("Received full topology update with source [%d]\n", src_node->node_id);
		handle_full_top_update(received, src_node, ev_actions_required);
		break;
	case CLUSTERER_UNKNOWN_ID:
		LM_DBG("Received UNKNOWN_ID from node [%d]\n", src_node->node_id);
		handle_unknown_id(src_node);
		break;
	case CLUSTERER_NODE_DESCRIPTION:
		LM_DBG("Already got node description for source [%d], drop this message\n",
			src_node->node_id);
		break;
	case CLUSTERER_CAP_UPDATE:
		LM_DBG("Received capability update with source [%d]\n", src_node->node_id);
		handle_cap_update(received, src_node);
		break;
	default:
		LM_WARN("Invalid clusterer binary packet command from node: %d\n",
			src_node->node_id);
	}
}

static void handle_cl_gen_msg(bin_packet_t *packet, int cluster_id, int source_id)
{
	int req_like;
	str rcv_msg, rcv_tag;

	LM_DBG("Received generic clusterer message\n");

	bin_pop_int(packet, &req_like);
	bin_pop_str(packet, &rcv_tag);
	bin_pop_str(packet, &rcv_msg);

	if (raise_gen_msg_ev(cluster_id, source_id, req_like, &rcv_tag, &rcv_msg)) {
		LM_ERR("Failed to raise event for a received generic message!\n");
		return;
	}
}

static void handle_cl_mi_msg(bin_packet_t *packet)
{
	str cmd_params[MI_CMD_MAX_NR_PARAMS];
	str cmd_name;
	int i, no_params;
	int rc;

	bin_pop_str(packet, &cmd_name);
	LM_DBG("Received MI command <%.*s>\n", cmd_name.len, cmd_name.s);

	bin_pop_int(packet, &no_params);
	for (i = 0; i < no_params; i++)
		bin_pop_str(packet, &cmd_params[i]);

	rc = run_rcv_mi_cmd(&cmd_name, cmd_params, no_params);
	if (rc == -1) {
		LM_ERR("MI command <%.*s> failed\n", cmd_name.len, cmd_name.s);
		return;
	}

	LM_INFO("MI command <%.*s> returned with %s\n",
		cmd_name.len, cmd_name.s, (rc == 1) ? "error" : "success");
}

static void handle_remove_node(bin_packet_t *packet, cluster_info_t *cl)
{
	int target_node;
	int lock_old_flag;
	node_info_t *node;
	int ev_actions_cl = 1;

	bin_pop_int(packet, &target_node);
	LM_DBG("Received remove node command for node id: [%d]\n", target_node);

	if (db_mode) {
		LM_DBG("We are in DB mode, ignoring received remove node command\n");
		return;
	}

	if (target_node == current_id) {
		lock_get(cl->current_node->lock);

		if (cl->current_node->flags & NODE_STATE_ENABLED) {
			cl->current_node->flags &= ~NODE_STATE_ENABLED;
			lock_release(cl->current_node->lock);

			for (node = cl->node_list; node; node = node->next) {
				set_link_w_neigh(LS_DOWN, node);

				do_actions_node_ev(cl, &ev_actions_cl, 1);
			}
		} else {
			lock_release(cl->current_node->lock);
		}

		return;
	}

	node = get_node_by_id(cl, target_node);
	if (!node) {
		LM_DBG("Unknown node [%d] to remove\n", target_node);
		return;
	}

	lock_switch_write(cl_list_lock, lock_old_flag);
	remove_node(cl, node);
	lock_switch_read(cl_list_lock, lock_old_flag);
}

void bin_rcv_cl_extra_packets(bin_packet_t *packet, int packet_type,
									struct receive_info *ri, void *att)
{
	int source_id, dest_id, cluster_id;
	cluster_info_t *cl;
	node_info_t *node;
	int ev_actions_required = 0;
	char *ip;
	unsigned short port;

	bin_pop_back_int(packet, &dest_id);
	bin_pop_back_int(packet, &source_id);
	bin_pop_back_int(packet, &cluster_id);

	get_su_info(&ri->src_su.s, ip, port);
	LM_DBG("received clusterer message from: %s:%hu with source id: %d and"
			" cluster id: %d\n", ip, port, source_id, cluster_id);

	if (source_id == current_id) {
		LM_ERR("Received message with bad source - same node id as this instance\n");
		return;
	}

	if (!db_mode && packet_type == CLUSTERER_REMOVE_NODE)
		lock_start_sw_read(cl_list_lock);
	else
		lock_start_read(cl_list_lock);

	cl = get_cluster_by_id(cluster_id);
	if (!cl) {
		LM_WARN("Received message, type: %d, from unknown cluster id [%d]\n",
			packet_type, cluster_id);
		goto exit;
	}

	lock_get(cl->current_node->lock);
	if (!(cl->current_node->flags & NODE_STATE_ENABLED)) {
		lock_release(cl->current_node->lock);
		LM_INFO("Current node disabled, ignoring received bin packet\n");
		goto exit;
	}
	lock_release(cl->current_node->lock);

	node = get_node_by_id(cl, source_id);
	if (!node) {
		LM_WARN("Received message with unknown source id [%d]\n", source_id);
		goto exit;
	}

	if (!su_ip_cmp(&ri->src_su, &node->addr) &&
		!ip_check(cl, &ri->src_su, NULL)) {
		LM_WARN("Received message from unknown source, addr: %s\n", ip);
		goto exit;
	}

	lock_get(node->lock);

	if (!(node->flags & NODE_STATE_ENABLED)) {
		lock_release(node->lock);
		LM_DBG("node disabled, ignoring received clusterer bin packet\n");
		goto exit;
	}

	/* if the node was down, restart pinging */
	if (node->link_state == LS_DOWN) {
		lock_release(node->lock);
		LM_DBG("Received bin packet from failed node, restart pinging\n");
		set_link_w_neigh(LS_RESTART_PINGING, node);
	} else
		lock_release(node->lock);

	if (dest_id != current_id) {
		/* route the message */
		bin_push_int(packet, cluster_id);
		bin_push_int(packet, source_id);
		bin_push_int(packet, dest_id);

		node = get_node_by_id(cl, dest_id);
		if (!node) {
			LM_WARN("Received message with unknown destination id [%d]\n", source_id);
			goto exit;
		}

		if (msg_send_retry(packet, node, 0, &ev_actions_required) < 0) {
			LM_ERR("Failed to route message with source id [%d] and destination id [%d]\n",
				source_id, dest_id);
			if (ev_actions_required)
				do_actions_node_ev(cl, &ev_actions_required, 1);

			goto exit;
		} else {
			LM_DBG("Routed message with source id [%d] and destination id [%d]\n",
				source_id, dest_id);
			if (ev_actions_required)
				do_actions_node_ev(cl, &ev_actions_required, 1);

			goto exit;
		}
	} else {
		if (packet_type == CLUSTERER_REMOVE_NODE)
			handle_remove_node(packet, cl);
		else if (packet_type == CLUSTERER_GENERIC_MSG)
			handle_cl_gen_msg(packet, cluster_id, source_id);
		else if (packet_type == CLUSTERER_MI_CMD)
			handle_cl_mi_msg(packet);
		else if (packet_type == CLUSTERER_SHTAG_ACTIVE)
			handle_shtag_active(packet, cluster_id);
		else if (packet_type == CLUSTERER_SYNC_REQ)
			handle_sync_request(packet, cl, node);
		else if (packet_type == CLUSTERER_SYNC || packet_type == CLUSTERER_SYNC_END)
			handle_sync_packet(packet, packet_type, cl, source_id);
		else {
			LM_ERR("Unknown clusterer message type: %d\n", packet_type);
			goto exit;
		}
	}

exit:
	if (!db_mode && packet_type == CLUSTERER_REMOVE_NODE)
		lock_stop_sw_read(cl_list_lock);
	else
		lock_stop_read(cl_list_lock);
}

void bin_rcv_cl_packets(bin_packet_t *packet, int packet_type,
									struct receive_info *ri, void *att)
{
	int source_id, cl_id;
	struct timeval now;
	node_info_t *node = NULL;
	cluster_info_t *cl;
	char *ip;
	unsigned short port;
	int ev_actions_required = 0;

	gettimeofday(&now, NULL);

	bin_pop_int(packet, &cl_id);
	bin_pop_int(packet, &source_id);

	get_su_info(&ri->src_su.s, ip, port);
	LM_DBG("received clusterer message from: %s:%hu with source id: %d and "
		"cluster id: %d\n", ip, port, source_id, cl_id);

	if (source_id == current_id) {
		LM_ERR("Received message with bad source - same node id as this instance\n");
		return;
	}

	if (!db_mode && packet_type == CLUSTERER_NODE_DESCRIPTION)
		lock_start_sw_read(cl_list_lock);
	else
		lock_start_read(cl_list_lock);

	cl = get_cluster_by_id(cl_id);
	if (!cl) {
		LM_WARN("Received message from unknown cluster id [%d]\n", cl_id);
		goto exit;
	}

	lock_get(cl->current_node->lock);
	if (!(cl->current_node->flags & NODE_STATE_ENABLED)) {
		lock_release(cl->current_node->lock);
		LM_INFO("Current node disabled, ignoring received clusterer bin packet\n");
		goto exit;
	}
	lock_release(cl->current_node->lock);

	node = get_node_by_id(cl, source_id);

	if (!node) {
		LM_INFO("Received message with unknown source id [%d]\n", source_id);
		if (!db_mode)
			handle_internal_msg_unknown(packet, cl, packet_type, &ri->src_su,
				ri->proto, source_id);
	} else {
		if (!su_ip_cmp(&ri->src_su, &node->addr) &&
			!ip_check(cl, &ri->src_su, NULL)) {
			LM_WARN("Received message from unknown source, addr: %s\n", ip);
			goto exit;
		}

		lock_get(node->lock);
		if (!(node->flags & NODE_STATE_ENABLED)) {
			lock_release(node->lock);
			LM_DBG("node disabled, ignoring received clusterer bin packet\n");
			goto exit;
		}
		lock_release(node->lock);

		handle_internal_msg(packet, packet_type, node, now,	&ev_actions_required);
		if (ev_actions_required)
			do_actions_node_ev(cl, &ev_actions_required, 1);
	}

exit:
	if (!db_mode && packet_type == CLUSTERER_NODE_DESCRIPTION)
		lock_stop_sw_read(cl_list_lock);
	else
		lock_stop_read(cl_list_lock);
}

void run_mod_packet_cb(int sender, void *param)
{
	struct packet_rpc_params *p = (struct packet_rpc_params *)param;
	bin_packet_t packet;

	bin_init_buffer(&packet, p->pkt_buf.s, p->pkt_buf.len);
	packet.src_id = p->pkt_src_id;
	packet.type = p->pkt_type;

	p->cap->packet_cb(&packet);

	shm_free(param);
}

int ipc_dispatch_mod_packet(bin_packet_t *packet, struct capability_reg *cap)
{
	struct packet_rpc_params *params;

	params = shm_malloc(sizeof *params + packet->buffer.len);
	if (!params) {
		LM_ERR("oom!\n");
		return -1;
	}
	memset(params, 0, sizeof *params);
	params->pkt_buf.s = (char *)(params + 1);

	memcpy(params->pkt_buf.s, packet->buffer.s, packet->buffer.len);
	params->pkt_buf.len = packet->buffer.len;
	params->cap = cap;
	params->pkt_type = packet->type;
	params->pkt_src_id = packet->src_id;

	if (ipc_dispatch_rpc(run_mod_packet_cb, params) < 0) {
		LM_ERR("Failed to dispatch rpc\n");
		return -1;
	}

	return 0;
}

static void bin_rcv_mod_packets(bin_packet_t *packet, int packet_type,
									struct receive_info *ri, void *ptr)
{
	struct capability_reg *cap;
	struct local_cap *cl_cap;
	unsigned short port;
	int source_id, dest_id, cluster_id;
	char *ip;
	node_info_t *node = NULL;
	cluster_info_t *cl;
	int ev_actions_required = 0;
	int rc;

	/* pop the source and destination from the bin packet */
	bin_pop_back_int(packet, &dest_id);
	bin_pop_back_int(packet, &source_id);
	bin_pop_back_int(packet, &cluster_id);

	get_su_info(&ri->src_su.s, ip, port);
	LM_DBG("received bin packet from: %s:%hu with source id: %d and cluster id: %d\n",
			ip, port, source_id, cluster_id);

	if (source_id == current_id) {
		LM_ERR("Received message with bad source - same node id as this instance\n");
		return;
	}

	cap = (struct capability_reg *)ptr;
	if (!cap) {
		LM_ERR("Failed to get bin callback parameter\n");
		return;
	}

	lock_start_read(cl_list_lock);

	cl = get_cluster_by_id(cluster_id);
	if (!cl) {
		LM_WARN("Received message from unknown cluster, id [%d]\n", cluster_id);
		goto exit;
	}

	lock_get(cl->current_node->lock);
	if (!(cl->current_node->flags & NODE_STATE_ENABLED)) {
		lock_release(cl->current_node->lock);
		LM_INFO("Current node disabled, ignoring received bin packet\n");
		goto exit;
	}
	lock_release(cl->current_node->lock);

	node = get_node_by_id(cl, source_id);
	if (!node) {
		LM_WARN("Received message with unknown source id [%d]\n", source_id);
		goto exit;
	}

	if (!su_ip_cmp(&ri->src_su, &node->addr) &&
		!ip_check(cl, &ri->src_su, NULL)) {
		LM_WARN("Received message from unknown source, addr: %s\n", ip);
		goto exit;
	}

	lock_get(node->lock);

	if (!(node->flags & NODE_STATE_ENABLED)) {
		lock_release(node->lock);
		LM_DBG("node disabled, ignoring received bin packet\n");
		goto exit;
	}

	rc = get_capability_status(cl, &cap->name);
	if (rc == -1) {
		goto exit;
	} else if (rc == 0) {
		LM_DBG("capability disabled, ignoring received bin packet\n");
		goto exit;
	}

	/* if the node was down, restart pinging */
	if (node->link_state == LS_DOWN) {
		lock_release(node->lock);
		LM_DBG("Received bin packet from failed node, restart pinging\n");
		set_link_w_neigh(LS_RESTART_PINGING, node);
	} else
		lock_release(node->lock);

	if (dest_id != current_id) {
		/* route the message */
		bin_push_int(packet, cluster_id);
		bin_push_int(packet, source_id);
		bin_push_int(packet, dest_id);

		node = get_node_by_id(cl, dest_id);
		if (!node) {
			LM_WARN("Received message with unknown destination id [%d]\n",
				source_id);
			goto exit;
		}

		if (msg_send_retry(packet, node, 0, &ev_actions_required) < 0) {
			LM_ERR("Failed to route message with source id [%d] and destination "
				"id [%d]\n", source_id, dest_id);
			if (ev_actions_required)
				do_actions_node_ev(cl, &ev_actions_required, 1);
		} else {
			LM_DBG("Routed message with source id [%d] and destination id [%d]\n",
				source_id, dest_id);
			if (ev_actions_required)
				do_actions_node_ev(cl, &ev_actions_required, 1);
		}
	} else {
		/* try to pass message to registered callback */

		for (cl_cap = cl->capabilities; cl_cap; cl_cap = cl_cap->next)
			if (!str_strcmp(&cl_cap->reg.name, &cap->name))
				break;
		if (!cl_cap) {
			LM_ERR("Packet's capability: %.*s not found in cluster info\n",
				cap->name.len, cap->name.s);
			goto exit;
		}

		lock_get(cl->lock);

		if (cl_cap->flags & CAP_PKT_BUFFERING) {
			/* buffer regular packets during sync or during processing of
			 * previously buffered packets */
			buffer_bin_pkt(packet, cl_cap, source_id);
			lock_release(cl->lock);
		} else {
			lock_release(cl->lock);
			lock_stop_read(cl_list_lock);
			packet->src_id = source_id;

			if (ipc_dispatch_mod_packet(packet, cap) < 0)
				LM_ERR("Failed to dispatch handling of module packet\n");

			return;
		}
	}

exit:
	lock_stop_read(cl_list_lock);
}

int send_single_cap_update(cluster_info_t *cluster, struct local_cap *cap,
							int cap_state)
{
	bin_packet_t packet;
	str bin_buffer;
	node_info_t* destinations[MAX_NO_NODES];
	struct neighbour *neigh;
	int no_dests = 0, i;

	lock_get(cluster->current_node->lock);

	for (neigh = cluster->current_node->neighbour_list; neigh;
		neigh = neigh->next)
		destinations[no_dests++] = neigh->node;

	lock_release(cluster->current_node->lock);

	if (no_dests == 0)
		return 0;

	if (bin_init(&packet, &cl_internal_cap, CLUSTERER_CAP_UPDATE,
		BIN_VERSION, 0) < 0) {
		LM_ERR("Failed to init bin send buffer\n");
		return -1;
	}
	bin_push_int(&packet, cluster->cluster_id);
	bin_push_int(&packet, current_id);

	/* only the current node */
	bin_push_int(&packet, 1);
	bin_push_int(&packet, current_id);

	/* only a single capability */
	bin_push_int(&packet, 1);
	bin_push_str(&packet, &cap->reg.name);
	bin_push_int(&packet, cap_state);

	bin_push_int(&packet, 0);  /* don't require reply */

	bin_push_int(&packet, 1);	/* path length is 1, only current node at this point */
	bin_push_int(&packet, current_id);
	bin_get_buffer(&packet, &bin_buffer);

	for (i = 0; i < no_dests; i++)
		if (msg_send(cluster->send_sock, destinations[i]->proto,
			&destinations[i]->addr, 0, bin_buffer.s, bin_buffer.len, 0) < 0) {
			LM_ERR("Failed to send capability update to node [%d]\n",
				destinations[i]->node_id);
			set_link_w_neigh_adv(-1, LS_RESTART_PINGING, destinations[i]);
		} else
			LM_DBG("Sent capability update to node [%d]\n",
				destinations[i]->node_id);

	bin_free_packet(&packet);

	return 0;
}

int send_cap_update(node_info_t *dest_node, int require_reply)
{
	bin_packet_t packet;
	str bin_buffer;
	struct local_cap *cl_cap;
	struct remote_cap *n_cap;
	int nr_cap, nr_nodes = 0;
	node_info_t *node;

	if (dest_node->cluster->capabilities)
		nr_nodes++;

	for (node = dest_node->cluster->node_list; node; node = node->next) {
		lock_get(node->lock);
		if (node->capabilities && node->node_id != dest_node->node_id)
			nr_nodes++;
		lock_release(node->lock);
	}

	if (nr_nodes == 0)
		return 0;

	if (bin_init(&packet, &cl_internal_cap, CLUSTERER_CAP_UPDATE, BIN_VERSION, 0) < 0) {
		LM_ERR("Failed to init bin send buffer\n");
		return -1;
	}
	bin_push_int(&packet, dest_node->cluster->cluster_id);
	bin_push_int(&packet, current_id);

	bin_push_int(&packet, nr_nodes);

	/* current node's capabilities */
	for (cl_cap = dest_node->cluster->capabilities, nr_cap = 0; cl_cap;
		cl_cap = cl_cap->next, nr_cap++) ;
	if (nr_cap) {
		bin_push_int(&packet, current_id);
		bin_push_int(&packet, nr_cap);
		for (cl_cap=dest_node->cluster->capabilities;cl_cap;cl_cap=cl_cap->next) {
			bin_push_str(&packet, &cl_cap->reg.name);
			lock_get(dest_node->cluster->lock);
			bin_push_int(&packet, cl_cap->flags & CAP_STATE_OK ? 1 : 0);
			lock_release(dest_node->cluster->lock);
		}
	}

	/* known capabilities for other nodes */
	for (node = dest_node->cluster->node_list; node; node = node->next) {
		if (node->node_id == dest_node->node_id)
			continue;
		lock_get(node->lock);
		for (n_cap = node->capabilities, nr_cap = 0; n_cap;
			n_cap = n_cap->next, nr_cap++) ;
		if (nr_cap) {
			bin_push_int(&packet, node->node_id);
			bin_push_int(&packet, nr_cap);
			for (n_cap = node->capabilities; n_cap; n_cap = n_cap->next) {
				bin_push_str(&packet, &n_cap->name);
				bin_push_int(&packet, n_cap->flags & CAP_STATE_OK ? 1 : 0);
			}
		}
		lock_release(node->lock);
	}

	bin_push_int(&packet, require_reply);

	bin_push_int(&packet, 1);	/* path length is 1, only current node at this point */
	bin_push_int(&packet, current_id);
	bin_get_buffer(&packet, &bin_buffer);

	if (msg_send(dest_node->cluster->send_sock, dest_node->proto, &dest_node->addr,
		0, bin_buffer.s, bin_buffer.len, 0) < 0) {
		LM_ERR("Failed to send capability update to node [%d]\n", dest_node->node_id);
		set_link_w_neigh_adv(-1, LS_RESTART_PINGING, dest_node);
	} else
		LM_DBG("Sent capability update to node [%d]\n", dest_node->node_id);

	bin_free_packet(&packet);

	return 0;
}

void do_actions_node_ev(cluster_info_t *clusters, int *select_cluster,
								int no_clusters)
{
	node_info_t *node;
	cluster_info_t *cl;
	struct local_cap *cap_it;
	struct remote_cap *n_cap;
	int k;
	int rc;
	int rst_sync_pending;

	for (k = 0, cl = clusters; k < no_clusters && cl; k++, cl = clusters->next) {
		if (!select_cluster[k])
			continue;

		for (node = cl->node_list; node; node = node->next) {
			lock_get(node->lock);

			if (node->flags	& NODE_EVENT_DOWN) {
				node->flags &= ~NODE_EVENT_DOWN;
				lock_release(node->lock);

				for (cap_it = cl->capabilities; cap_it; cap_it = cap_it->next)
					if (cap_it->reg.event_cb)
						cap_it->reg.event_cb(CLUSTER_NODE_DOWN, node->node_id);

				if (raise_node_state_ev(CLUSTER_NODE_DOWN, cl->cluster_id,
					node->node_id) < 0)
					LM_ERR("Failed to raise node state changed event for: "
						"cluster_id=%d node_id=%d, new_state=node down\n",
						cl->cluster_id, node->node_id);

				shtag_event_handler(cl->cluster_id, CLUSTER_NODE_DOWN,
					node->node_id);

			} else if (node->flags & NODE_EVENT_UP) {
				node->flags &= ~NODE_EVENT_UP;

				/* check pending sync replies */
				for (n_cap = node->capabilities; n_cap; n_cap = n_cap->next) {
					if (n_cap->flags & CAP_SYNC_PENDING) {
						n_cap->flags &= ~CAP_SYNC_PENDING;
						lock_release(node->lock);
						/* reply now that the node is up */
						if (ipc_dispatch_sync_reply(cl, node->node_id,
							&n_cap->name) < 0)
							LM_ERR("Failed to dispatch sync reply job\n");
						lock_get(node->lock);
					}
				}
				lock_release(node->lock);

				for (cap_it = cl->capabilities; cap_it; cap_it = cap_it->next) {
					/* check pending sync request */
					rst_sync_pending = 0;
					lock_get(cl->lock);
					if (cap_it->flags & CAP_SYNC_PENDING) {
						lock_release(cl->lock);

						if (!match_node(cl->current_node, node,
						                cap_it->reg.sync_cond)) {
							LM_DBG("no match for node id %d\n", node->node_id);
							continue;
						}

						lock_get(node->lock);
						for (n_cap = node->capabilities; n_cap;
							n_cap = n_cap->next) {
							if (!str_strcmp(&cap_it->reg.name, &n_cap->name)) {
								if (n_cap->flags & CAP_STATE_OK) {
									lock_release(node->lock);
									rc = send_sync_req(&n_cap->name,
										cl->cluster_id, node->node_id);
									if (rc == CLUSTERER_SEND_SUCCESS)
										rst_sync_pending = 1;
									else if (rc == CLUSTERER_SEND_ERR)
										LM_ERR("Failed to send sync request to"
											"node: %d\n", node->node_id);
									lock_get(node->lock);
								}
							}
						}
						lock_release(node->lock);
					} else
						lock_release(cl->lock);

					if (cap_it->reg.event_cb)
						cap_it->reg.event_cb(CLUSTER_NODE_UP, node->node_id);

					/* reset the sync pending flag only after the event CB is
					 * run, in order to prevent a double sync request in case
					 * a module tries to sync on node UP event */
					if (rst_sync_pending) {
						lock_get(cl->lock);
						cap_it->flags &= ~CAP_SYNC_PENDING;
						lock_release(cl->lock);
					}
				}

				if (raise_node_state_ev(CLUSTER_NODE_UP, cl->cluster_id,
					node->node_id) < 0)
					LM_ERR("Failed to raise node state changed event for: "
						"cluster_id=%d node_id=%d, new_state=node up\n",
						cl->cluster_id, node->node_id);

				shtag_event_handler(cl->cluster_id, CLUSTER_NODE_UP,
					node->node_id);

			} else
				lock_release(node->lock);
		}
	}
}

int cl_register_cap(str *cap, cl_packet_cb_f packet_cb, cl_event_cb_f event_cb,
             int cluster_id, int startup_sync, enum cl_node_match_op sync_cond)
{
	struct local_cap *new_cl_cap = NULL;
	cluster_info_t *cluster;

	cluster = get_cluster_by_id(cluster_id);
	if (!cluster) {
		LM_ERR("cluster id %d is not defined in the %s\n", cluster_id,
		       db_mode ? "DB" : "script");
		return -1;
	}

	new_cl_cap = shm_malloc(sizeof *new_cl_cap);
	if (!new_cl_cap) {
		LM_ERR("No more shm memory\n");
		return -1;
	}
	memset(new_cl_cap, 0, sizeof *new_cl_cap);

	new_cl_cap->reg.name.len = cap->len;
	new_cl_cap->reg.name.s = cap->s;
	new_cl_cap->reg.sync_cond = sync_cond;
	new_cl_cap->reg.packet_cb = packet_cb;
	new_cl_cap->reg.event_cb = event_cb;

	if (!startup_sync)
		new_cl_cap->flags |= CAP_STATE_OK;

	new_cl_cap->flags |= CAP_STATE_ENABLED;

	new_cl_cap->next = cluster->capabilities;
	cluster->capabilities = new_cl_cap;

	bin_register_cb(cap, bin_rcv_mod_packets, &new_cl_cap->reg,
		sizeof new_cl_cap->reg);

	LM_DBG("Registered capability: %.*s\n", cap->len, cap->s);

	return 0;
}

struct local_cap *dup_caps(struct local_cap *caps)
{
	struct local_cap *cap, *ret = NULL;

	for (; caps; caps = caps->next) {
		cap = shm_malloc(sizeof *cap);
		if (!cap) {
			LM_ERR("No more shm memory\n");
			return NULL;
		}
		memcpy(cap, caps, sizeof *caps);

		cap->next = NULL;

		add_last(cap, ret);
	}

	return ret;
}

int preserve_reg_caps(cluster_info_t *new_info)
{
	cluster_info_t *cl, *new_cl;

	for (cl = *cluster_list; cl; cl = cl->next)
		for (new_cl = new_info; new_cl; new_cl = new_cl->next)
			if (new_cl->cluster_id == cl->cluster_id && cl->capabilities) {
				new_cl->capabilities = dup_caps(cl->capabilities);
				if (!new_cl->capabilities) {
					LM_ERR("Failed to duplicate capabilities info\n");
					return -1;
				}
			}

	return 0;
}

void remove_node(struct cluster_info *cl, struct node_info *node)
{
	node_info_t *it;
	int ev_actions_cl = 1;

	set_link_w_neigh(LS_DOWN, node);

	do_actions_node_ev(cl, &ev_actions_cl, 1);

	for (it = cl->node_list; it; it = it->next) {
		lock_get(it->lock);
		delete_neighbour(it, node);
		lock_release(it->lock);
	}

	remove_node_list(cl, node);
}
