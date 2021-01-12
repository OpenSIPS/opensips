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

#include "../../evi/evi_modules.h"

#include "api.h"

event_id_t ei_req_rcv_id = EVI_ERROR;
event_id_t ei_rpl_rcv_id = EVI_ERROR;
event_id_t ei_node_state_id = EVI_ERROR;
static str ei_req_rcv_name = str_init("E_CLUSTERER_REQ_RECEIVED");
static str ei_rpl_rcv_name = str_init("E_CLUSTERER_RPL_RECEIVED");
static str ei_node_state_name = str_init("E_CLUSTERER_NODE_STATE_CHANGED");

static evi_params_p ei_event_params;
static evi_param_p ei_clid_p, ei_srcid_p, ei_msg_p, ei_tag_p;
static str ei_clid_pname = str_init("cluster_id");
static str ei_srcid_pname = str_init("src_id");
static str ei_msg_pname = str_init("msg");
static str ei_tag_pname = str_init("tag");

static evi_params_p ei_node_event_params;
static evi_param_p ei_clusterid_p, ei_nodeid_p, ei_newstate_p;
static str ei_clusterid_pname = str_init("cluster_id");
static str ei_nodeid_pname = str_init("node_id");
static str ei_newstate_pname = str_init("new_state");

int gen_rcv_evs_init(void)
{
	/* publish the events */
	ei_req_rcv_id = evi_publish_event(ei_req_rcv_name);
	if (ei_req_rcv_id == EVI_ERROR) {
		LM_ERR("cannot register message received event\n");
		return -1;
	}
	ei_rpl_rcv_id = evi_publish_event(ei_rpl_rcv_name);
	if (ei_rpl_rcv_id == EVI_ERROR) {
		LM_ERR("cannot register reply received event\n");
		return -1;
	}

	ei_event_params = pkg_malloc(sizeof(evi_params_t));
	if (ei_event_params == NULL) {
		LM_ERR("no more pkg mem\n");
		return -1;
	}
	memset(ei_event_params, 0, sizeof(evi_params_t));

	ei_clid_p = evi_param_create(ei_event_params, &ei_clid_pname);
	if (ei_clid_p == NULL)
		goto create_error;
	ei_srcid_p = evi_param_create(ei_event_params, &ei_srcid_pname);
	if (ei_srcid_p == NULL)
		goto create_error;
	ei_msg_p = evi_param_create(ei_event_params, &ei_msg_pname);
	if (ei_msg_p == NULL)
		goto create_error;
	ei_tag_p = evi_param_create(ei_event_params, &ei_tag_pname);
	if (ei_tag_p == NULL)
		goto create_error;

	return 0;

create_error:
	LM_ERR("cannot create event parameter\n");
	return -1;
}

int node_state_ev_init(void)
{
	/* publish the events */
	ei_node_state_id = evi_publish_event(ei_node_state_name);
	if (ei_node_state_id == EVI_ERROR) {
		LM_ERR("cannot register node state changed event\n");
		return -1;
	}

	ei_node_event_params = pkg_malloc(sizeof(evi_params_t));
	if (ei_node_event_params == NULL) {
		LM_ERR("no more pkg mem\n");
		return -1;
	}
	memset(ei_node_event_params, 0, sizeof(evi_params_t));

	ei_clusterid_p = evi_param_create(ei_node_event_params, &ei_clusterid_pname);
	if (ei_clusterid_p == NULL)
		goto create_error;

	ei_nodeid_p = evi_param_create(ei_node_event_params, &ei_nodeid_pname);
	if (ei_nodeid_p == NULL)
		goto create_error;

	ei_newstate_p = evi_param_create(ei_node_event_params, &ei_newstate_pname);
	if (ei_newstate_p == NULL)
		goto create_error;

	return 0;

create_error:
	LM_ERR("cannot create event parameter\n");
	return -1;
}

int raise_node_state_ev(enum clusterer_event ev, int cluster_id, int node_id)
{
	int new_state = ev == CLUSTER_NODE_DOWN ? 0 : 1;

	if (evi_param_set_int(ei_clusterid_p, &cluster_id) < 0) {
		LM_ERR("cannot set cluster_id event parameter\n");
		return -1;
	}
	if (evi_param_set_int(ei_nodeid_p, &node_id) < 0) {
		LM_ERR("cannot set node_id event parameter\n");
		return -1;
	}
	if (evi_param_set_int(ei_newstate_p, &new_state) < 0) {
		LM_ERR("cannot set new_state event parameter\n");
		return -1;
	}

	if (evi_raise_event(ei_node_state_id, ei_node_event_params) < 0) {
		LM_ERR("cannot raise event\n");
		return -1;
	}

	return 0;
}

int raise_gen_msg_ev(int cluster_id, int source_id,
	int req_like, str *rcv_msg, str *rcv_tag)
{
	if (evi_param_set_int(ei_clid_p, &cluster_id) < 0) {
		LM_ERR("cannot set cluster id event parameter\n");
		return -1;
	}
	if (evi_param_set_int(ei_srcid_p, &source_id) < 0) {
		LM_ERR("cannot set source id event parameter\n");
		return -1;
	}
	if (evi_param_set_str(ei_msg_p, rcv_msg) < 0) {
		LM_ERR("cannot set message event parameter\n");
		return -1;
	}
	if (evi_param_set_str(ei_tag_p, rcv_tag) < 0) {
		LM_ERR("cannot set tag event parameter\n");
		return -1;
	}

	/* raise event interface event for generic msg */
	if (req_like) {
		if (evi_raise_event(ei_req_rcv_id, ei_event_params) < 0) {
			LM_ERR("cannot raise event\n");
			return -1;
		}
	} else {
		if (evi_raise_event(ei_rpl_rcv_id, ei_event_params) < 0) {
			LM_ERR("cannot raise event\n");
			return -1;
		}
	}

	return 0;
}

void gen_rcv_evs_destroy(void)
{
	evi_free_params(ei_event_params);
}

void node_state_ev_destroy(void)
{
	evi_free_params(ei_node_event_params);
}
