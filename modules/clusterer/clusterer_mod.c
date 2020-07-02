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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 *
 */


#include "../../sr_module.h"
#include "../../str.h"
#include "../../dprint.h"
#include "../../db/db.h"
#include "../../mem/shm_mem.h"
#include "../../locking.h"
#include "../../rw_locking.h"
#include "../../ut.h"
#include "../../mi/mi.h"
#include "../../timer.h"
#include "../../bin_interface.h"

#include "api.h"
#include "node_info.h"
#include "clusterer.h"
#include "sync.h"
#include "sharing_tags.h"

int ping_interval = DEFAULT_PING_INTERVAL;
int node_timeout = DEFAULT_NODE_TIMEOUT;
int ping_timeout = DEFAULT_PING_TIMEOUT;
int seed_fb_interval = DEFAULT_SEED_FB_INTERVAL;
int current_id = -1;
int db_mode = 1;

str clusterer_db_url = {NULL, 0};
str db_table = str_init("clusterer");
str id_col = str_init("id");	/* PK column */
str cluster_id_col = str_init("cluster_id");
str node_id_col = str_init("node_id");
str url_col = str_init("url");
str state_col = str_init("state");
str no_ping_retries_col = str_init("no_ping_retries");
str priority_col = str_init("priority");
str sip_addr_col = str_init("sip_addr");
str flags_col = str_init("flags");
str description_col = str_init("description");

extern db_con_t *db_hdl;
extern db_func_t dr_dbf;

/* module interface functions */
static int mod_init(void);
static int child_init(int rank);
static void destroy(void);

/* MI functions */
static mi_response_t *clusterer_reload(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *clusterer_set_status(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *clusterer_list(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *clusterer_list_topology(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *cluster_send_mi(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *cluster_bcast_mi(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *clusterer_list_cap(const mi_params_t *params,
								struct mi_handler *async_hdl);

static void heartbeats_timer_handler(unsigned int ticks, void *param);
static void heartbeats_utimer_handler(utime_t ticks, void *param);

int cmd_broadcast_req(struct sip_msg *msg, int *cluster_id, str *gen_msg,
									pv_spec_t *param_tag);
int cmd_send_req(struct sip_msg *msg, int *cluster_id, int *node_id,
								str *gen_msg, pv_spec_t *param_tag);
int cmd_send_rpl(struct sip_msg *msg, int *cluster_id, int *node_id,
								str *gen_msg, pv_spec_t *param_tag);
int cmd_check_addr(struct sip_msg *msg, int *cluster_id, str *ip_str,
					str *addr_type_str);


 /*
 * Exported functionsu
 */

static cmd_export_t cmds[] = {
	{"load_clusterer",  (cmd_function)load_clusterer, {{0,0,0}}, 0},
	{"cluster_broadcast_req", (cmd_function)cmd_broadcast_req, {
		{CMD_PARAM_INT,0,0},
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT,0,0}, {0,0,0}},
		REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE | LOCAL_ROUTE | BRANCH_ROUTE | EVENT_ROUTE},
	{"cluster_send_req", (cmd_function)cmd_send_req, {
		{CMD_PARAM_INT,0,0},
		{CMD_PARAM_INT,0,0},
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT,0,0}, {0,0,0}},
		REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE | LOCAL_ROUTE | BRANCH_ROUTE | EVENT_ROUTE},
	{"cluster_send_rpl", (cmd_function)cmd_send_rpl, {
		{CMD_PARAM_INT,0,0},
		{CMD_PARAM_INT,0,0},
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_VAR,0,0}, {0,0,0}},
		REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE | LOCAL_ROUTE | BRANCH_ROUTE | EVENT_ROUTE},
	{"cluster_check_addr", (cmd_function)cmd_check_addr, {
		{CMD_PARAM_INT,0,0},
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, {0,0,0}},
		REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE | LOCAL_ROUTE | BRANCH_ROUTE | EVENT_ROUTE},
	{0,0,{{0,0,0}},0}
};

/*
 * Exported parameters
 */
static param_export_t params[] = {
	{"db_url",				STR_PARAM,	&clusterer_db_url.s	},
	{"db_table",			STR_PARAM,	&db_table.s			},
	{"my_node_id",			INT_PARAM,	&current_id			},
	{"ping_interval",		INT_PARAM,	&ping_interval		},
	{"node_timeout",		INT_PARAM,	&node_timeout		},
	{"ping_timeout",		INT_PARAM,	&ping_timeout		},
	{"seed_fallback_interval", INT_PARAM, &seed_fb_interval	},
	{"id_col",				STR_PARAM,	&id_col.s			},
	{"cluster_id_col",		STR_PARAM,	&cluster_id_col.s	},
	{"node_id_col",			STR_PARAM,	&node_id_col.s		},
	{"url_col",				STR_PARAM,	&url_col.s			},
	{"state_col",			STR_PARAM,	&state_col.s		},
	{"no_ping_retries_col",	STR_PARAM,	&no_ping_retries_col.s	},
	{"priority_col",		STR_PARAM,  &priority_col.s		},
	{"sip_addr_col",		STR_PARAM,	&sip_addr_col.s		},
	{"flags_col",			STR_PARAM,	&flags_col.s		},
	{"description_col",		STR_PARAM,	&description_col.s	},
	{"db_mode",				INT_PARAM,	&db_mode			},
	{"neighbor_node_info",	STR_PARAM|USE_FUNC_PARAM,
		(void*)&provision_neighbor},
	{"my_node_info",		STR_PARAM|USE_FUNC_PARAM,
		(void*)&provision_current},
	{"sharing_tag",			STR_PARAM|USE_FUNC_PARAM,
		(void*)&shtag_modparam_func},
	{"sync_packet_size",	INT_PARAM,	&sync_packet_size	},
	{0, 0, 0}
};

/*
 * Exported MI functions
 */	
static mi_export_t mi_cmds[] = {
	{ "clusterer_reload", "reloads stored data from the database", 0,0,{
		{clusterer_reload, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "clusterer_set_status", "sets the status for a specified connection", 0,0,{
		{clusterer_set_status, {"cluster_id", "status", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "clusterer_list", "lists the available connections for the specified server", 0,0,{
		{clusterer_list, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "clusterer_list_topology", "lists the topology as known by the current node", 0,0,{
		{clusterer_list_topology, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "cluster_send_mi", "sends an MI command to be run on a specific node in a cluster", 0,0,{
		{cluster_send_mi, {"cluster_id", "destination", "cmd_name", 0}},
		{cluster_send_mi, {"cluster_id", "destination", "cmd_name", "cmd_params", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "cluster_broadcast_mi", "dispatches an MI command to be run on all nodes in a cluster", 0,0,{
		{cluster_bcast_mi, {"cluster_id", "cmd_name", 0}},
		{cluster_bcast_mi, {"cluster_id", "cmd_name", "cmd_params", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "clusterer_list_cap", "lists registered capabilities and their states", 0,0,{
		{clusterer_list_cap, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "clusterer_list_shtags", "lists the sharing tags and their states", 0,0,{
		{shtag_mi_list, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "clusterer_shtag_set_active", "switch the status of the give sharing tag to active", 0,0,{
		{shtag_mi_set_active, {"tag", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};


static pv_export_t mod_vars[] = {
	{ {"cluster.sh_tag", sizeof("cluster.sh_tag")-1}, 1000, var_get_sh_tag,
		var_set_sh_tag,  var_parse_sh_tag_name , 0, 0, 0 },
	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};


static module_dependency_t *get_deps_db_mode(param_export_t *param)
{
	int db_mode = *(int *)param->param_pointer;

	if (db_mode == 0)
		return NULL;

	return alloc_module_dep(MOD_TYPE_SQLDB, NULL, DEP_ABORT);
}

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "proto_bin", DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ "db_mode",			get_deps_db_mode },
		{ NULL, NULL },
	},
};

/**
 * module exports
 */
struct module_exports exports = {
	"clusterer",			/* module name */
	MOD_TYPE_DEFAULT,		/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,		/* dlopen flags */
	0,						/* load function */
	&deps,            		/* OpenSIPS module dependencies */
	cmds,					/* exported functions */
	0,						/* exported async functions */
	params,					/* exported parameters */
	0,						/* exported statistics */
	mi_cmds,				/* exported MI functions */
	mod_vars,				/* exported variables */
	0,						/* exported transformations */
	0,						/* extra processes */
	0,						/* module pre-initialization function */
	mod_init,				/* module initialization function */
	0,						/* response handling function */
	destroy,				/* destroy function */
	child_init,				/* per-child init function */
	0						/* reload confirm function */
};

static inline int gcd(int a, int b) {
	int t;

	while(b) {
		t = a;
		a = b;
		b = t % b;
	}
	return a;
}

#define PARSE_PROP(col_name, _col_idx, _type) \
do { \
	p = str_strstr(descr, &col_name);	\
	if (p) {	\
		p = p + col_name.len;	\
		p = q_memchr(p, '=', descr->s + descr->len - p); \
		if (!p) {	\
			LM_ERR("Expected '=' after <%.*s>\n", col_name.len,	\
				col_name.s);	\
			return -1;	\
		}	\
		p++;	\
		pe = q_memchr(p, ',', descr->s + descr->len - p);	\
		aux.s = p;	\
		aux.len = pe ? pe - p : descr->s + descr->len - p;	\
		if (aux.len == 0) {	\
			LM_ERR("<%.*s> value expected\n", col_name.len,	\
				col_name.s);	\
			return -1;	\
		}	\
		str_trim_spaces_lr(aux); \
		if ((_type) == 0) {	\
			if (str2int(&aux, (unsigned int*)&int_vals[(_col_idx)])) {	\
				LM_ERR("Bad value for <%.*s>\n", col_name.len,	\
					col_name.s);	\
				return -1;	\
			}	\
		} else	\
			str_vals[(_col_idx)] = aux;	\
	} else {	\
		if ((_type) == 0)	\
			int_vals[(_col_idx)] = -1;	\
		else	\
			str_vals[(_col_idx)].s = NULL;	\
	}	\
} while(0)

int parse_param_node_info(str *descr, int *int_vals, str *str_vals)
{
	char *p, *pe;
	str aux;

	PARSE_PROP(cluster_id_col, INT_VALS_CLUSTER_ID_COL, 0);
	PARSE_PROP(node_id_col, INT_VALS_NODE_ID_COL, 0);
	PARSE_PROP(url_col, STR_VALS_URL_COL, 1);
	PARSE_PROP(no_ping_retries_col, INT_VALS_NO_PING_RETRIES_COL, 0);
	PARSE_PROP(priority_col, INT_VALS_PRIORITY_COL, 0);
	PARSE_PROP(sip_addr_col, STR_VALS_SIP_ADDR_COL, 1);
	PARSE_PROP(flags_col, STR_VALS_FLAGS_COL, 1);

	return 0;
}

static int mod_init(void)
{
	int heartbeats_timer_interval;
	cluster_info_t *cl;

	LM_INFO("Clusterer module - initializing\n");

	db_table.len = strlen(db_table.s);
	id_col.len = strlen(id_col.s);
	cluster_id_col.len = strlen(cluster_id_col.s);
	node_id_col.len = strlen(node_id_col.s);
	url_col.len = strlen(url_col.s);
	state_col.len = strlen(state_col.s);
	no_ping_retries_col.len = strlen(no_ping_retries_col.s);
	priority_col.len = strlen(priority_col.s);
	sip_addr_col.len = strlen(sip_addr_col.s);
	flags_col.len = strlen(flags_col.s);
	description_col.len = strlen(description_col.s);

	/* only allow the DB URL to be skipped in "P2P discovery" mode */
	init_db_url(clusterer_db_url, db_mode == 0);

	if (current_id < 1) {
		LM_CRIT("Invalid 'my_node_id' parameter\n");
		return -1;
	}
	if (ping_interval <= 0) {
		LM_WARN("Invalid ping_interval parameter, using default value\n");
		ping_interval = DEFAULT_PING_INTERVAL;
	}
	if (node_timeout < 0) {
		LM_WARN("Invalid node_timeout parameter, using default value\n");
		node_timeout = DEFAULT_NODE_TIMEOUT;
	}
	if (ping_timeout <= 0) {
		LM_WARN("Invalid ping_timeout parameter, using default value\n");
		ping_timeout = DEFAULT_PING_TIMEOUT;
	}
	if (seed_fb_interval < 0) {
		LM_WARN("Invalid seed_fallback_interval parameter, using default value\n");
		seed_fb_interval = DEFAULT_SEED_FB_INTERVAL;
	}

	/* create & init lock */
	if ((cl_list_lock = lock_init_rw()) == NULL) {
		LM_CRIT("Failed to init lock\n");
		return -1;
	}

	/* data pointer in shm */
	if (cluster_list == NULL) {
		cluster_list = shm_malloc(sizeof *cluster_list);
		if (!cluster_list) {
			LM_CRIT("No more shm memory\n");
			goto error;
		}
		*cluster_list = NULL;
	} else {
		/* sanity check of my_node_id if node_id also set in a my_node_info param */
		for (cl = *cluster_list; cl; cl = cl->next) {
			if (!cl->current_node) {
				LM_ERR("current node is not part of cluster %d\n",
				       cl->cluster_id);
				goto error;
			}

			if (cl->current_node->node_id != current_id) {
				LM_ERR("Bad 'my_node_id' parameter, value: %d different than"
					" the node_id property in the 'my_node_info' parameter\n", current_id);
				goto error;
			}
		}
	}

	if (db_mode) {
		/* bind to the mysql module */
		if (db_bind_mod(&clusterer_db_url, &dr_dbf)) {
			LM_CRIT("Cannot bind to database module! "
				"Did you forget to load a database module ?\n");
			goto error;
		}
		if (!DB_CAPABILITY(dr_dbf, DB_CAP_QUERY)) {
			LM_CRIT("Given SQL DB does not provide query types needed by this module!\n");
			goto error;
		}
		/* init DB connection */
		if ((db_hdl = dr_dbf.init(&clusterer_db_url)) == 0) {
			LM_ERR("cannot initialize database connection\n");
			goto error;
		}
		if (load_db_info(&dr_dbf, db_hdl, &db_table, cluster_list) < 0) {
			LM_ERR("Failed to load info from DB\n");
			goto error;
		}

		dr_dbf.close(db_hdl);
		db_hdl = NULL;
	}

	/* register timer */
	heartbeats_timer_interval = gcd(ping_interval*1000, ping_timeout);
	heartbeats_timer_interval = gcd(heartbeats_timer_interval, node_timeout*1000);

	if (heartbeats_timer_interval % 1000 == 0) {
		if (register_timer("clstr-heartbeats-timer", heartbeats_timer_handler,
			NULL, heartbeats_timer_interval/1000, TIMER_FLAG_DELAY_ON_DELAY) < 0) {
			LM_CRIT("Unable to register clusterer heartbeats timer\n");
			goto error;
		}
	} else {
		if (register_utimer("clstr-heartbeats-utimer", heartbeats_utimer_handler,
			NULL, heartbeats_timer_interval*1000, TIMER_FLAG_DELAY_ON_DELAY) < 0) {
			LM_CRIT("Unable to register clusterer heartbeats timer\n");
			goto error;
		}
	}

	if (register_utimer("cl-seed-fb-check", seed_fb_check_timer,
		NULL, SEED_FB_CHECK_INTERVAL*1000, TIMER_FLAG_DELAY_ON_DELAY) < 0) {
		LM_CRIT("Unable to register clusterer seed check timer\n");
		goto error;
	}

	if (bin_register_cb(&cl_internal_cap, bin_rcv_cl_packets, NULL, 0) < 0) {
		LM_CRIT("Cannot register clusterer binary packet callback!\n");
		goto error;
	}
	if (bin_register_cb(&cl_extra_cap, bin_rcv_cl_extra_packets, NULL, 0) < 0) {
		LM_CRIT("Cannot register extra clusterer binary packet callback!\n");
		goto error;
	}

	/* create generic message receiving events */
	if (gen_rcv_evs_init() < 0) {
		LM_ERR("cannot create cluster message received event\n");
		return -1;
	}

	/* create node state event */
	if (node_state_ev_init() < 0) {
		LM_ERR("cannot create node state change event\n");
		return -1;
	}

	/* check if the cluster IDs in the the sharing tag list are valid */
	shtag_init_list();
	shtag_validate_list();

	return 0;
error:
	lock_destroy_rw(cl_list_lock);
	cl_list_lock = NULL;
	if (cluster_list) {
		shm_free(cluster_list);
		cluster_list = 0;
	}
	return -1;
}

/* initialize child */
static int child_init(int rank)
{
	if (db_mode) {
		/* init DB connection */
		if ((db_hdl = dr_dbf.init(&clusterer_db_url)) == 0) {
			LM_ERR("cannot initialize database connection\n");
			return -1;
		}
	}
	return 0;
}

mi_response_t *clusterer_reload(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	cluster_info_t *new_info;
	cluster_info_t *old_info;

	if (!db_mode) {
		LM_ERR("Running in non-DB mode\n");
		return init_mi_error(400, MI_SSTR("Non-DB mode"));
	}

	if (load_db_info(&dr_dbf, db_hdl, &db_table, &new_info) != 0) {
		LM_ERR("Failed to load info from DB\n");
		return init_mi_error(500, MI_SSTR("Failed to reload"));
	}

	lock_start_write(cl_list_lock);
	if (preserve_reg_caps(new_info) < 0) {
		lock_stop_write(cl_list_lock);
		LM_ERR("Failed to preserve registered capabilities\n");

		if (new_info)
			free_info(new_info);

		return init_mi_error(500, "Failed to reload", 16);
	}
	old_info = *cluster_list;
	*cluster_list = new_info;
	lock_stop_write(cl_list_lock);

	if (old_info)
		free_info(old_info);

	LM_INFO("Reloaded DB info\n");

	/* check if the cluster IDs in the the sharing tag list are valid */
	shtag_validate_list();

	return init_mi_result_ok();
}

static mi_response_t *clusterer_set_status(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int cluster_id;
	int state;
	int rc;

	if (get_mi_int_param(params, "cluster_id", &cluster_id) < 0)
		return init_mi_param_error();
	if (cluster_id < 1)
		return init_mi_error(400, MI_SSTR("Bad value for 'cluster_id'"));

	if (get_mi_int_param(params, "status", &state) < 0)
		return init_mi_param_error();
	if (state != STATE_DISABLED && state != STATE_ENABLED)
		return init_mi_error(400, MI_SSTR("Bad value for 'status'"));

	rc = cl_set_state(cluster_id, state);
	if (rc == -1)
		return init_mi_error(404, MI_SSTR("Cluster id not found"));
	if (rc == 1)
		return init_mi_error(404, MI_SSTR("Node id not found"));

	return init_mi_result_ok();
}

static mi_response_t *clusterer_list(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	cluster_info_t *cl;
	node_info_t *n_info;
	str val;
	mi_response_t *resp = NULL;
	mi_item_t *resp_obj;
	mi_item_t *clusters_arr, *cluster_item, *nodes_arr, *node_item;
	static str str_up   = 	str_init("Up");
	static str str_prob = 	str_init("Probe");
	static str str_down = 	str_init("Down");
	static str str_none = 	str_init("none");
	int n_hop;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	clusters_arr = add_mi_array(resp_obj, MI_SSTR("Clusters"));
	if (!clusters_arr) {
		free_mi_response(resp);
		return 0;
	}

	lock_start_read(cl_list_lock);

	/* iterate through clusters */
	for (cl = *cluster_list; cl; cl = cl->next) {
		cluster_item = add_mi_object(clusters_arr, NULL, 0);
		if (!cluster_item)
			goto error;

		if (add_mi_number(cluster_item, MI_SSTR("cluster_id"), cl->cluster_id) < 0)
			goto error;

		nodes_arr = add_mi_array(cluster_item, MI_SSTR("Nodes"));
		if (!nodes_arr)
			goto error;

		/* iterate through nodes */
		for (n_info = cl->node_list; n_info; n_info = n_info->next) {
			node_item = add_mi_object(nodes_arr, NULL, 0);
			if (!node_item)
				goto error;

			if (add_mi_number(node_item, MI_SSTR("node_id"), n_info->node_id) < 0)
				goto error;

			if (add_mi_number(node_item, MI_SSTR("db_id"), n_info->id) < 0)
				goto error;

			if (add_mi_string(node_item, MI_SSTR("url"),
				n_info->url.s, n_info->url.len) < 0)
				goto error;

			lock_get(n_info->lock);

			if (n_info->link_state == LS_UP)
				val = str_up;
			else if (n_info->link_state == LS_DOWN)
				val = str_down;
			else
				val = str_prob;

			if (add_mi_string(node_item, MI_SSTR("link_state"),
				val.s, val.len) < 0) {
				lock_release(n_info->lock);
				goto error;
			}

			lock_release(n_info->lock);

			n_hop = get_next_hop(n_info); 
			if (!n_hop)
				val = str_none;
			else
				val.s = int2str(n_hop, &val.len);

			if (add_mi_string(node_item, MI_SSTR("next_hop"), val.s, val.len) < 0)
				goto error;

			if (n_info->description.s) {
				if (add_mi_string(node_item, MI_SSTR("description"),
					n_info->description.s, n_info->description.len) < 0)
					goto error;
			} else
				if (add_mi_string(node_item, MI_SSTR("description"),
					MI_SSTR("none")) < 0)
					goto error;
		}
	}

	lock_stop_read(cl_list_lock);
	return resp;
error:
	lock_stop_read(cl_list_lock);
	if (resp) free_mi_response(resp);
	return NULL;
}

static mi_response_t *clusterer_list_cap(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp = NULL;
	mi_item_t *resp_obj;
	mi_item_t *clusters_arr, *cluster_item;
	mi_item_t *cap_arr, *cap_item;
	cluster_info_t *cl;
	struct local_cap *cap;
	static str str_ok = str_init("Ok");
	static str str_not_synced = str_init("not synced");

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	clusters_arr = add_mi_array(resp_obj, MI_SSTR("Clusters"));
	if (!clusters_arr) {
		free_mi_response(resp);
		return 0;
	}

	lock_start_read(cl_list_lock);

	for (cl = *cluster_list; cl; cl = cl->next) {
		cluster_item = add_mi_object(clusters_arr, NULL, 0);
		if (!cluster_item)
			goto error;

		if (add_mi_number(cluster_item, MI_SSTR("cluster_id"), cl->cluster_id) < 0)
			goto error;

		cap_arr = add_mi_array(cluster_item, MI_SSTR("Capabilities"));
		if (!cap_arr)
			goto error;

		for (cap = cl->capabilities; cap; cap = cap->next) {
			cap_item = add_mi_object(cap_arr, NULL, 0);
			if (!cap_item)
				goto error;

			if (add_mi_string(cap_item, MI_SSTR("name"),
				cap->reg.name.s, cap->reg.name.len) < 0)
				goto error;

			lock_get(cl->lock);

			if (add_mi_string(cap_item, MI_SSTR("state"),
				(cap->flags & CAP_STATE_OK) ? str_ok.s : str_not_synced.s,
				(cap->flags & CAP_STATE_OK) ? str_ok.len : str_not_synced.len) < 0) {
				lock_release(cl->lock);
				goto error;
			}

			lock_release(cl->lock);
	   }
	}

	lock_stop_read(cl_list_lock);
	return resp;

error:
	lock_stop_read(cl_list_lock);
	if (resp) free_mi_response(resp);
	return NULL;
}

/* lists the clusters' topology as viewed by the current node*/
static mi_response_t *clusterer_list_topology(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp = NULL;
	mi_item_t *resp_obj;
	mi_item_t *clusters_arr, *cluster_item, *nodes_arr, *node_item;
	mi_item_t *neigh_arr;
	cluster_info_t *cl;
	node_info_t *n_info;
	struct neighbour *neigh;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	clusters_arr = add_mi_array(resp_obj, MI_SSTR("Clusters"));
	if (!clusters_arr) {
		free_mi_response(resp);
		return 0;
	}

	lock_start_read(cl_list_lock);

	/* iterate through clusters */
	for (cl = *cluster_list; cl; cl = cl->next) {
		cluster_item = add_mi_object(clusters_arr, NULL, 0);
		if (!cluster_item)
			goto error;

		if (add_mi_number(cluster_item, MI_SSTR("cluster_id"), cl->cluster_id) < 0)
			goto error;

		nodes_arr = add_mi_array(cluster_item, MI_SSTR("Nodes"));
		if (!nodes_arr)
			goto error;

		node_item = add_mi_object(nodes_arr, 0, 0);
		if (!node_item)
			goto error;

		if (add_mi_number(node_item, MI_SSTR("node_id"), current_id) < 0)
			goto error;

		neigh_arr = add_mi_array(node_item, MI_SSTR("Neighbours"));
		if (!neigh_arr)
			goto error;

		for (neigh = cl->current_node->neighbour_list; neigh; neigh = neigh->next)
			if (add_mi_number(neigh_arr, 0,0, neigh->node->node_id) < 0)
				goto error;

		for (n_info = cl->node_list; n_info; n_info = n_info->next) {
			node_item = add_mi_object(nodes_arr, NULL, 0);
			if (!node_item)
				goto error;

			if (add_mi_number(node_item, MI_SSTR("node_id"), n_info->node_id) < 0)
				goto error;

			neigh_arr = add_mi_array(node_item, MI_SSTR("Neighbours"));
			if (!neigh_arr)
				goto error;

			lock_get(n_info->lock);

			for (neigh = n_info->neighbour_list; neigh; neigh = neigh->next)
				if (add_mi_number(neigh_arr, 0,0, neigh->node->node_id) < 0) {
					lock_release(n_info->lock);
					goto error;
				}

			if (n_info->link_state == LS_UP)
				if (add_mi_number(neigh_arr, 0,0, current_id) < 0) {
					lock_release(n_info->lock);
					goto error;
				}

			lock_release(n_info->lock);
		}
	}

	lock_stop_read(cl_list_lock);
	return resp;
error:
	lock_stop_read(cl_list_lock);
	if (resp) free_mi_response(resp);
	return NULL;
}

static mi_response_t *cl_run_mi_cmd(str *cmd_name, mi_item_t *item_params_arr,
										str *str_params_arr, int no_params)
{
	struct mi_cmd *cmd = NULL;
	mi_response_t *resp = NULL;
	mi_request_t req_item;
	mi_item_t *param_item;
	int i;
	str val;

	memset(&req_item, 0, sizeof req_item);

	req_item.req_obj = cJSON_CreateObject();
	if (!req_item.req_obj) {
		LM_ERR("Failed to build temporary json request\n");
		return NULL;
	}

	cmd = lookup_mi_cmd(cmd_name->s, cmd_name->len);
	if (!cmd) {
		resp = init_mi_error(400, MI_SSTR("Command to be run not found"));
		goto out;
	}

	if (cmd->flags & MI_ASYNC_RPL_FLAG) {
		resp = init_mi_error(400, MI_SSTR("Async commands not supported"));
		goto out;
	}
	if (cmd->flags & MI_NAMED_PARAMS_ONLY) {
		resp = init_mi_error(400, MI_SSTR("Commands requiring named params not supported"));
		goto out;
	}

	if (no_params) {
		req_item.params = cJSON_CreateArray();
		if (!req_item.params) {
			LM_ERR("Failed to add 'params' to temporary json request\n");
			goto out;
		}
		cJSON_AddItemToObject(req_item.req_obj, JSONRPC_PARAMS_S,
			req_item.params);
	}

	for (i = 0; i < no_params; i++) {
		if (item_params_arr) {
			if (get_mi_arr_param_string(item_params_arr, i, &val.s, &val.len) < 0) {
				resp = init_mi_param_error();
				goto out;
			}
		} else {
			val.s = str_params_arr[i].s;
			val.len = str_params_arr[i].len;
		}

		param_item = cJSON_CreateStr(val.s, val.len);
		if (!param_item) {
			LM_ERR("Failed to create string item in temporary json request\n");
			goto out;
		}

		cJSON_AddItemToArray(req_item.params, param_item);
	}

	resp = handle_mi_request(&req_item, cmd, NULL);
	LM_DBG("got mi response = [%p]\n", resp);

out:
	cJSON_Delete(req_item.req_obj);
	return resp;
}

static mi_response_t *run_mi_cmd_local(str *cmd_name, mi_item_t *cmd_params_arr,
									int no_params)
{
	return cl_run_mi_cmd(cmd_name, cmd_params_arr, NULL, no_params);
}

int run_rcv_mi_cmd(str *cmd_name, str *cmd_params_arr, int no_params)
{
	mi_response_t *resp;
	mi_item_t *err_item;

	resp = cl_run_mi_cmd(cmd_name, NULL, cmd_params_arr, no_params);

	if (resp) {
		err_item = cJSON_GetObjectItem(resp, JSONRPC_ERROR_S);
		free_mi_response(resp);
		return err_item ? 1 : 0;
	} else {
		LM_ERR("Failed to build MI command response\n");
		return -1;
	}
}

static mi_response_t *cluster_send_mi(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int cluster_id, node_id;
	int rc;
	str cmd_name;
	mi_item_t *cmd_params_arr = NULL;
	int no_params = 0;

	if (get_mi_int_param(params, "cluster_id", &cluster_id) < 0)
		return init_mi_param_error();
	if (cluster_id < 1)
		return init_mi_error(400, MI_SSTR("Bad value for 'cluster_id'"));

	if (get_mi_int_param(params, "destination", &node_id) < 0)
		return init_mi_param_error();
	if (node_id < 1)
		return init_mi_error(400, MI_SSTR("Bad value for 'destination'"));
	if (node_id == current_id)
		return init_mi_error(400, MI_SSTR("Local node specified as destination"));

	if (get_mi_string_param(params, "cmd_name", &cmd_name.s, &cmd_name.len) < 0)
		return init_mi_param_error();

	rc = try_get_mi_array_param(params, "cmd_params", &cmd_params_arr, &no_params);
	if (rc < 0) {
		cmd_params_arr = NULL;
		if (rc == -2)
			return init_mi_param_error();
	}

	rc = send_mi_cmd(cluster_id, node_id, cmd_name, cmd_params_arr, no_params);
	switch (rc) {
		case CLUSTERER_SEND_SUCCESS:
			LM_DBG("MI command <%.*s> sent\n", cmd_name.len, cmd_name.s);
			return init_mi_result_ok();
		case CLUSTERER_CURR_DISABLED:
			LM_INFO("Local node disabled, MI command <%.*s> not sent\n",
				cmd_name.len, cmd_name.s);
			return init_mi_result_string(MI_SSTR("Local node disabled"));
		case CLUSTERER_DEST_DOWN:
			LM_ERR("Destination down, MI command <%.*s> not sent\n",
				cmd_name.len, cmd_name.s);
			return init_mi_error(400, MI_SSTR("Destination down"));
		case CLUSTERER_SEND_ERR:
			LM_ERR("Error sending MI command <%.*s>+\n",
				cmd_name.len, cmd_name.s);
			return init_mi_error(400, MI_SSTR("Send error"));
		default:
			LM_BUG("Bad send error code\n");
			return init_mi_error(400, MI_SSTR("Internal error"));
	}
}

static mi_response_t *cluster_bcast_mi(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int cluster_id;
	int rc;
	str cmd_name;
	mi_item_t *cmd_params_arr = NULL;
	int no_params = 0;

	if (get_mi_int_param(params, "cluster_id", &cluster_id) < 0)
		return init_mi_param_error();
	if (cluster_id < 1)
		return init_mi_error(400, MI_SSTR("Bad value for 'cluster_id'"));

	if (get_mi_string_param(params, "cmd_name", &cmd_name.s, &cmd_name.len) < 0)
		return init_mi_param_error();

	rc = try_get_mi_array_param(params, "cmd_params", &cmd_params_arr, &no_params);
	if (rc < 0) {
		cmd_params_arr = NULL;
		if (rc == -2)
			return init_mi_param_error();
	}

	rc = send_mi_cmd(cluster_id, 0, cmd_name, cmd_params_arr, no_params);
	switch (rc) {
		case CLUSTERER_SEND_SUCCESS:
			LM_DBG("MI command <%.*s> sent\n", cmd_name.len, cmd_name.s);
			break;
		case CLUSTERER_CURR_DISABLED:
			LM_INFO("Local node disabled, MI command <%.*s> not sent\n",
				cmd_name.len, cmd_name.s);
			break;
		case CLUSTERER_DEST_DOWN:
			LM_ERR("All nodes down, MI command <%.*s> not sent\n",
				cmd_name.len, cmd_name.s);
			break;
		case CLUSTERER_SEND_ERR:
			LM_ERR("Error sending MI command <%.*s>+\n",
				cmd_name.len, cmd_name.s);
			break;
	}

	return run_mi_cmd_local(&cmd_name, cmd_params_arr, no_params);
}

static void heartbeats_timer_handler(unsigned int ticks, void *param)
{
	heartbeats_timer();
}

static void heartbeats_utimer_handler(utime_t ticks, void *param)
{
	heartbeats_timer();
}

static inline void generate_msg_tag(pv_value_t *tag_val, int cluster_id)
{
	static char gen_tag_buf[TAG_RAND_LEN+TAG_FIX_MAXLEN];
	int i, len;
	int r;
	char *tmp;

	memset(tag_val, 0, sizeof(pv_value_t));
	tag_val->flags = PV_VAL_STR;
	tag_val->rs.s = gen_tag_buf;

	/* a fixed part - cluster id, node id */
	tmp = int2str(cluster_id, &len);
	memcpy(tag_val->rs.s, tmp, len);
	tag_val->rs.s[len] = '-';
	tag_val->rs.len = len + 1;
	tmp = int2str(current_id, &len);
	memcpy(tag_val->rs.s + tag_val->rs.len, tmp, len);
	tag_val->rs.s[tag_val->rs.len + len] = '-';
	tag_val->rs.len += len + 1;
	/* random string part */
	for (i = 0; i < TAG_RAND_LEN; i++) {
		r = rand() % ('z'- 'A') + 'A';
	    if (r > 'Z' && r < 'a')
			r = '0'+ (r - 'Z');
		tag_val->rs.s[tag_val->rs.len] = r;
		tag_val->rs.len++;
	}
}

int cmd_broadcast_req(struct sip_msg *msg, int *cluster_id, str *gen_msg,
									pv_spec_t *param_tag)
{
	pv_value_t tag_val;
	int rc;

	/* generate tag */
	generate_msg_tag(&tag_val, *cluster_id);

	if (param_tag && pv_set_value(msg, param_tag, 0, &tag_val) < 0) {
		LM_ERR("Unable to set tag pvar\n");
		return -1;
	}

	rc = bcast_gen_msg(*cluster_id, gen_msg, &tag_val.rs);
	switch (rc) {
		case 0:
			return 1;
		case 1:
			return -1;
		case -1:
			return -2;
		case -2:
			return -3;
		default:
			return -4;
	}
}

int cmd_send_req(struct sip_msg *msg, int *cluster_id, int *node_id,
								str *gen_msg, pv_spec_t *param_tag)
{
	pv_value_t tag_val;
	int rc;

	/* generate tag */
	generate_msg_tag(&tag_val, *cluster_id);

	if (param_tag && pv_set_value(msg, param_tag, 0, &tag_val) < 0) {
		LM_ERR("Unable to set tag pvar\n");
		return -1;
	}

	rc = send_gen_msg(*cluster_id, *node_id, gen_msg, &tag_val.rs, 1);
	switch (rc) {
		case 0:
			return 1;
		case 1:
			return -1;
		case -1:
			return -2;
		case -2:
			return -3;
		default:
			return -3;
	}
}

int cmd_send_rpl(struct sip_msg *msg, int *cluster_id, int *node_id,
								str *gen_msg, pv_spec_t *param_tag)
{
	pv_value_t tag_val;
	int rc;

	if (pv_get_spec_value(msg, param_tag, &tag_val) < 0) {
		LM_ERR("Failed to fetch tag parameter\n");
		return -1;
	}
	if (tag_val.flags & PV_VAL_NULL ||
		(tag_val.flags & PV_VAL_STR && tag_val.rs.len == 0)) {
		LM_ERR("Empty tag\n");
		return -1;
	}

	rc = send_gen_msg(*cluster_id, *node_id, gen_msg, &tag_val.rs, 0);
	switch (rc) {
		case 0:
			return 1;
		case 1:
			return -1;
		case -1:
			return -2;
		case -2:
			return -3;
		default:
			return -3;
	}
}

int cmd_check_addr(struct sip_msg *msg, int *cluster_id, str *ip_str,
					str *addr_type_str)
{
	static str bin_addr_t = str_init("bin");
	static str sip_addr_t = str_init("sip");
	enum node_addr_type check_type;

	if (addr_type_str) {
		if (!str_strcasecmp(addr_type_str, &bin_addr_t))
			check_type = NODE_BIN_ADDR;
		else if (!str_strcasecmp(addr_type_str, &sip_addr_t))
			check_type = NODE_SIP_ADDR;
		else {
			LM_ERR("Bad address type, should be 'bin' or 'sip'\n");
			return -1;
		}
	} else
		check_type = NODE_SIP_ADDR;

	if (clusterer_check_addr(*cluster_id, ip_str, check_type) == 0)
		return -1;
	else
		return 1;
}

static void destroy(void)
{
	/* destroy data */
	if (cluster_list) {
		if (*cluster_list)
			free_info(*cluster_list);
		shm_free(cluster_list);
		cluster_list = NULL;
	}

	/* destroy lock */
	if (cl_list_lock) {
		lock_destroy_rw(cl_list_lock);
		cl_list_lock = NULL;
	}

	/* free evi events */
	gen_rcv_evs_destroy();
	node_state_ev_destroy();
}

int load_clusterer(struct clusterer_binds *binds)
{
	memset(binds, 0, sizeof *binds);

	binds->get_nodes = get_clusterer_nodes;
	binds->free_nodes = free_clusterer_nodes;
	binds->set_state = cl_set_state;
	binds->check_addr = clusterer_check_addr;
	binds->get_my_id = cl_get_my_id;
	binds->get_my_sip_addr = cl_get_my_sip_addr;
	binds->get_my_index = cl_get_my_index;
	binds->send_to = cl_send_to;
	binds->send_all = cl_send_all;
	binds->send_all_having = cl_send_all_having;
	binds->get_next_hop = api_get_next_hop;
	binds->free_next_hop = api_free_next_hop;
	binds->register_capability = cl_register_cap;
	binds->request_sync = cl_request_sync;
	binds->sync_chunk_start = cl_sync_chunk_start;
	binds->sync_chunk_iter = cl_sync_chunk_iter;
	binds->shtag_get = shtag_get;
	binds->shtag_activate = shtag_activate;
	binds->shtag_get_all_active = shtag_get_all_active;
	binds->shtag_register_callback = shtag_register_callback;

	return 1;
}

