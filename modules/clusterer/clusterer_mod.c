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
 *	2016-07-xx split from clusterer.c (rvlad-patrascu)
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
#include "../../mod_fix.h"

#include "api.h"
#include "node_info.h"
#include "clusterer.h"

int ping_interval = DEFAULT_PING_INTERVAL;
int node_timeout = DEFAULT_NODE_TIMEOUT;
int ping_timeout = DEFAULT_PING_TIMEOUT;
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
str description_col = str_init("description");

extern db_con_t *db_hdl;
extern db_func_t dr_dbf;

/* module interface functions */
static int mod_init(void);
static int child_init(int rank);
static void destroy(void);

/* MI functions */
static struct mi_root* clusterer_reload(struct mi_root* root, void *param);
static struct mi_root* clusterer_set_status(struct mi_root *cmd, void *param);
static struct mi_root* clusterer_list(struct mi_root *root, void *param);
static struct mi_root* clusterer_list_topology(struct mi_root *cmd_tree, void *param);
static struct mi_root* cluster_send_mi(struct mi_root *cmd, void *param);
static struct mi_root* cluster_bcast_mi(struct mi_root *cmd, void *param);

static void heartbeats_timer_handler(unsigned int ticks, void *param);
static void heartbeats_utimer_handler(utime_t ticks, void *param);

int cmd_broadcast_req(struct sip_msg *msg, char *param_cluster, char *param_msg,
									char *param_tag);
int cmd_send_req(struct sip_msg *msg, char *param_cluster, char *param_node,
								char *param_msg, char *param_tag);
int cmd_send_rpl(struct sip_msg *msg, char *param_cluster, char *param_node,
								char *param_msg, char *param_tag);
static int fixup_broadcast(void ** param, int param_no);
static int fixup_send(void ** param, int param_no);

 /*
 * Exported functionsu
 */

static cmd_export_t cmds[] = {
	{"load_clusterer",  (cmd_function)load_clusterer, 0, 0, 0, 0},
	{"cluster_broadcast_req", (cmd_function)cmd_broadcast_req, 2, fixup_broadcast, 0,
		REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE | LOCAL_ROUTE | BRANCH_ROUTE | EVENT_ROUTE},
	{"cluster_broadcast_req", (cmd_function)cmd_broadcast_req, 3, fixup_broadcast, 0,
		REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE | LOCAL_ROUTE | BRANCH_ROUTE | EVENT_ROUTE},
	{"cluster_send_req", (cmd_function)cmd_send_req, 3, fixup_send, 0,
		REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE | LOCAL_ROUTE | BRANCH_ROUTE | EVENT_ROUTE},
	{"cluster_send_req", (cmd_function)cmd_send_req, 4, fixup_send, 0,
		REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE | LOCAL_ROUTE | BRANCH_ROUTE | EVENT_ROUTE},
	{"cluster_send_rpl", (cmd_function)cmd_send_rpl, 4, fixup_send, 0,
		REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE | LOCAL_ROUTE | BRANCH_ROUTE | EVENT_ROUTE},
	{0,0,0,0,0,0}
};

/*
 * Exported parameters
 */
static param_export_t params[] = {
	{"db_url",				STR_PARAM,	&clusterer_db_url.s	},
	{"db_table",			STR_PARAM,	&db_table.s			},
	{"current_id",			INT_PARAM,	&current_id			},
	{"ping_interval",		INT_PARAM,	&ping_interval		},
	{"node_timeout",		INT_PARAM,	&node_timeout		},
	{"ping_timeout",		INT_PARAM,	&ping_timeout		},
	{"id_col",				STR_PARAM,	&id_col.s			},
	{"cluster_id_col",		STR_PARAM,	&cluster_id_col.s	},
	{"node_id_col",			STR_PARAM,	&node_id_col.s		},
	{"url_col",				STR_PARAM,	&url_col.s			},
	{"state_col",			STR_PARAM,	&state_col.s		},
	{"no_ping_retries_col",	STR_PARAM,	&no_ping_retries_col.s	},
	{"priority_col",		STR_PARAM,  &priority_col		},
	{"sip_addr_col",		STR_PARAM,	&sip_addr_col.s		},
	{"description_col",		STR_PARAM,	&description_col.s	},
	{"db_mode",				INT_PARAM,	&db_mode			},
	{"neighbor_info",		STR_PARAM|USE_FUNC_PARAM,	(void*)&provision_neighbor},
	{"current_info",		STR_PARAM|USE_FUNC_PARAM,	(void*)&provision_current},
	{0, 0, 0}
};

/*
 * Exported MI functions
 */	
static mi_export_t mi_cmds[] = {
	{ "clusterer_reload", "reloads stored data from the database",
	clusterer_reload, 0, 0, 0},
	{ "clusterer_set_status", "sets the status for a specified connection",
	clusterer_set_status, 0, 0, 0},
	{ "clusterer_list", "lists the available connections for the specified server",
	clusterer_list, 0, 0, 0},
	{ "clusterer_list_topology", "lists the topology as known by the current node",
	clusterer_list_topology, 0, 0, 0},
	{ "cluster_send_mi", "sends an MI command to be run on a specific node in a cluster",
	cluster_send_mi, MI_ASYNC_RPL_FLAG, 0, 0},
	{ "cluster_broadcast_mi", "dispatches an MI command to be run on all nodes in a cluster",
	cluster_bcast_mi, MI_ASYNC_RPL_FLAG, 0, 0},
	{0, 0, 0, 0, 0, 0}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_SQLDB, NULL, DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
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
	&deps,            		/* OpenSIPS module dependencies */
	cmds,					/* exported functions */
	0,						/* exported async functions */
	params,					/* exported parameters */
	0,						/* exported statistics */
	mi_cmds,				/* exported MI functions */
	0,						/* exported pseudo-variables */
	0,						/* exported transformations */
	0,						/* extra processes */
	mod_init,				/* module initialization function */
	0,						/* response handling function */
	destroy,				/* destroy function */
	child_init				/* per-child init function */
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
		if (*p != '=') {	\
			LM_ERR("Expected '=' after <%.*s>\n", col_name.len,	\
				col_name.s);	\
			return -1;	\
		}	\
		pe = q_memchr(p + 1, ',', descr->s + descr->len - p - 1);	\
		aux.s = p + 1;	\
		aux.len = pe ? pe - p - 1 : descr->s + descr->len - p - 1;	\
		if (aux.s >= descr->s + descr->len || !aux.len) {	\
			LM_ERR("<%.*s> value expected\n", col_name.len,	\
				col_name.s);	\
			return -1;	\
		}	\
		if ((_type) == 0) {	\
			if (str2int(&aux, (unsigned int*)&int_vals[(_col_idx)])) {	\
				LM_ERR("Bad value for <%.*s>\n", col_name.len,	\
					col_name.s);	\
				return -1;	\
			}	\
		} else \
			str_vals[(_col_idx)] = aux.len ? aux.s : NULL;	\
	} else {	\
		if ((_type) == 0)	\
			int_vals[(_col_idx)] = -1;	\
		else	\
			str_vals[(_col_idx)] = NULL;	\
	}	\
} while(0)

int parse_param_node_info(str *descr, int *int_vals, char **str_vals)
{
	char *p, *pe;
	str aux;

	PARSE_PROP(cluster_id_col, INT_VALS_CLUSTER_ID_COL, 0);
	PARSE_PROP(node_id_col, INT_VALS_NODE_ID_COL, 0);
	PARSE_PROP(url_col, STR_VALS_URL_COL, 1);
	PARSE_PROP(no_ping_retries_col, INT_VALS_NO_PING_RETRIES_COL, 0);
	PARSE_PROP(priority_col, INT_VALS_PRIORITY_COL, 0);
	PARSE_PROP(sip_addr_col, STR_VALS_SIP_ADDR_COL, 1);

	return 0;
}

static int mod_init(void)
{
	int heartbeats_timer_interval;

	LM_INFO("Clusterer module - initializing\n");

	init_db_url(clusterer_db_url, 1);
	db_table.len = strlen(db_table.s);
	id_col.len = strlen(id_col.s);
	cluster_id_col.len = strlen(cluster_id_col.s);
	node_id_col.len = strlen(node_id_col.s);
	id_col.len = strlen(id_col.s);
	url_col.len = strlen(url_col.s);
	state_col.len = strlen(state_col.s);
	no_ping_retries_col.len = strlen(no_ping_retries_col.s);
	priority_col.len = strlen(priority_col.s);
	sip_addr_col.len = strlen(sip_addr_col.s);
	description_col.len = strlen(description_col.s);

	if (current_id < 1) {
		LM_CRIT("Invalid current_id parameter\n");
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

	if (bin_register_cb("clusterer", bin_rcv_cl_packets, NULL) < 0) {
		LM_CRIT("Cannot register clusterer binary packet callback!\n");
		goto error;
	}

	/* create generic message receiving events */
	if (gen_rcv_evs_init() < 0) {
		LM_ERR("cannot create cluster message received event\n");
		return -1;
	}

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
	if (!db_mode || rank == PROC_TCP_MAIN || rank == PROC_BIN)
		return 0;

	/* init DB connection */
	if ((db_hdl = dr_dbf.init(&clusterer_db_url)) == 0) {
		LM_ERR("cannot initialize database connection\n");
		return -1;
	}

	/* child 1 loads the clusterer DB info */
	if (rank == 1 && load_db_info(&dr_dbf, db_hdl, &db_table, cluster_list) < 0) {
		LM_ERR("Failed to load info from DB\n");
		return -1;
	}

	return 0;
}

static struct mi_root* clusterer_reload(struct mi_root* root, void *param)
{
	cluster_info_t *new_info;
	cluster_info_t *old_info;

	if (!db_mode) {
		LM_ERR("Running in non-DB mode\n");
		return init_mi_tree(400, "Non-DB mode", 11);
	}

	if (load_db_info(&dr_dbf, db_hdl, &db_table, &new_info) != 0) {
		LM_ERR("Failed to load info from DB\n");
		return init_mi_tree(500, "Failed to reload", 16);
	}

	lock_start_write(cl_list_lock);
	old_info = *cluster_list;
	*cluster_list = new_info;
	lock_stop_write(cl_list_lock);

	if (old_info)
		free_info(old_info);

	LM_INFO("Reloaded DB info\n");

	return init_mi_tree(200, MI_SSTR(MI_OK));
}

static struct mi_root* clusterer_set_status(struct mi_root *cmd, void *param)
{
	unsigned int cluster_id;
	unsigned int state;
	int rc;
	struct mi_node *node;

	node = cmd->node.kids;

	if (node == NULL || node->next == NULL || node->next->next != NULL)
		return init_mi_tree(400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	rc = str2int(&node->value, &cluster_id);
	if (rc < 0 || cluster_id < 1)
		return init_mi_tree(400, MI_SSTR(MI_BAD_PARM));

	rc = str2int(&node->next->value, &state);
	if (rc < 0 || (state != STATE_DISABLED && state != STATE_ENABLED))
		return init_mi_tree(400, MI_SSTR(MI_BAD_PARM));

	rc = cl_set_state(cluster_id, state);
	if (rc == -1)
		return init_mi_tree(404, "Cluster id not found", 20);
	if (rc == 1)
		return init_mi_tree(404, "Node id not found", 17);

	return init_mi_tree(200, MI_SSTR(MI_OK));
}

static struct mi_root * clusterer_list(struct mi_root *cmd_tree, void *param)
{
	cluster_info_t *cl;
	node_info_t *n_info;
	struct mi_root *rpl_tree = NULL;
	struct mi_node *node = NULL;
	struct mi_node *node_s = NULL;
	struct mi_attr* attr;
	str val;
	static str str_up   = 	str_init("Up     ");
	static str str_prob = 	str_init("Probe  ");
	static str str_down = 	str_init("Down   ");
	static str str_no_link =str_init("No_link");
	static str str_none = 	str_init("none");
	int n_hop;

	rpl_tree = init_mi_tree(200, MI_OK_S, MI_OK_LEN);
	if (!rpl_tree)
		return NULL;
	rpl_tree->node.flags |= MI_IS_ARRAY;

	lock_start_read(cl_list_lock);

	/* iterate through clusters */
	for (cl = *cluster_list; cl; cl = cl->next) {

		val.s = int2str(cl->cluster_id, &val.len);
		node = add_mi_node_child(&rpl_tree->node, MI_DUP_VALUE|MI_IS_ARRAY,
			MI_SSTR("Cluster"), val.s, val.len);
		if (!node) goto error;

		/* iterate through servers */
		for (n_info = cl->node_list; n_info; n_info = n_info->next) {

			val.s = int2str(n_info->node_id, &val.len);
			node_s = add_mi_node_child(node, MI_DUP_VALUE,
				MI_SSTR("Node"), val.s, val.len);
			if (!node) goto error;

			val.s = sint2str(n_info->id, &val.len);
			attr = add_mi_attr(node_s, MI_DUP_VALUE,
				MI_SSTR("DB_ID"), val.s, val.len);
			if (!attr) goto error;

			attr = add_mi_attr(node_s, MI_DUP_VALUE,
				MI_SSTR("URL"), n_info->url.s, n_info->url.len);
			if (!attr) goto error;

			lock_get(n_info->lock);

			val.s = int2str(n_info->flags & NODE_STATE_ENABLED ? 1 : 0, &val.len);
			attr = add_mi_attr(node_s, MI_DUP_VALUE,
				MI_SSTR("Enabled"), val.s, val.len);
			if (!attr) {
				lock_release(n_info->lock);
				goto error;
			}

			if (n_info->link_state == LS_UP)
				val = str_up;
			else if (n_info->link_state == LS_DOWN)
				val = str_down;
			else if (n_info->link_state == LS_NO_LINK)
				val = str_no_link;
			else
				val = str_prob;
			attr = add_mi_attr(node_s, MI_DUP_VALUE,
				MI_SSTR("Link_state"), val.s, val.len);
			if (!attr) {
				lock_release(n_info->lock);
				goto error;
			}

			lock_release(n_info->lock);

			n_hop = get_next_hop(n_info); 
			if (n_hop <= 0)
				val = str_none;
			else
				val.s = int2str(n_hop, &val.len);
			attr = add_mi_attr(node_s, MI_DUP_VALUE,
				MI_SSTR("Next_hop"), val.s, val.len);
			if (!attr)
				goto error;

			if (n_info->description.s)
				attr = add_mi_attr(node_s, MI_DUP_VALUE,
					MI_SSTR("Description"),
					n_info->description.s, n_info->description.len);
			else
				attr = add_mi_attr(node_s, MI_DUP_VALUE,
					MI_SSTR("Description"),
					"none", 4);
			if (!attr) goto error;
		}
	}

	lock_stop_read(cl_list_lock);
	return rpl_tree;
error:
	lock_stop_read(cl_list_lock);
	if (rpl_tree) free_mi_tree(rpl_tree);
	return NULL;
}

/* lists the clusters' topology as viewed by the current node*/
static struct mi_root * clusterer_list_topology(struct mi_root *cmd_tree, void *param)
{
	cluster_info_t *cl;
	node_info_t *n_info;
	struct mi_root *rpl_tree = NULL;
	struct mi_node *node = NULL;
	struct mi_node *node_s = NULL;
	struct mi_attr* attr;
	str val;
	char neigh_list[512];
	struct neighbour *neigh;

	rpl_tree = init_mi_tree(200, MI_OK_S, MI_OK_LEN);
	if (!rpl_tree)
		return NULL;
	rpl_tree->node.flags |= MI_IS_ARRAY;

	lock_start_read(cl_list_lock);

	/* iterate through clusters */
	for (cl = *cluster_list; cl; cl = cl->next) {

		val.s = int2str(cl->cluster_id, &val.len);
		node = add_mi_node_child(&rpl_tree->node, MI_DUP_VALUE|MI_IS_ARRAY,
			MI_SSTR("Cluster"), val.s, val.len);
		if (!node) goto error;

		val.s = int2str(current_id, &val.len);
		node_s = add_mi_node_child(node, MI_DUP_VALUE,
			MI_SSTR("Node"), val.s, val.len);
		if (!node_s) goto error;

		memset(neigh_list, 0, 500);
		for (neigh = cl->current_node->neighbour_list; neigh; neigh = neigh->next) {
			sprintf(neigh_list + strlen(neigh_list), "%d ", neigh->node->node_id);
		}
		val.s = neigh_list;
		val.len = strlen(neigh_list);

		attr = add_mi_attr(node_s, MI_DUP_VALUE,
			MI_SSTR("Neighbours"), val.s, val.len);
		if (!attr) goto error;

		for (n_info = cl->node_list; n_info; n_info = n_info->next) {

			val.s = int2str(n_info->node_id, &val.len);
			node_s = add_mi_node_child(node, MI_DUP_VALUE,
				MI_SSTR("Node"), val.s, val.len);
			if (!node_s) goto error;

			memset(neigh_list, 0, 500);

			lock_get(n_info->lock);

			for (neigh = n_info->neighbour_list; neigh; neigh = neigh->next) {
				sprintf(neigh_list + strlen(neigh_list), "%d ", neigh->node->node_id);
			}
			if (n_info->link_state == LS_UP)
				sprintf(neigh_list + strlen(neigh_list), "%d ", current_id);

			lock_release(n_info->lock);

			val.s = neigh_list;
			val.len = strlen(neigh_list);

			attr = add_mi_attr(node_s, MI_DUP_VALUE,
				MI_SSTR("Neighbours"), val.s, val.len);
			if (!attr) goto error;
		}
	}

	lock_stop_read(cl_list_lock);
	return rpl_tree;
error:
	lock_stop_read(cl_list_lock);
	if (rpl_tree) free_mi_tree(rpl_tree);
	return NULL;
}

static struct mi_root *run_mi_cmd_local(struct mi_cmd *f, str *cmd_params, int nr_params,
									struct mi_handler *async_hdl)
{
	struct mi_root *cmd_root = NULL, *cmd_rpl;
	int i;

	if (f->flags & MI_NO_INPUT_FLAG && nr_params)
		return init_mi_tree(400, MI_SSTR(MI_MISSING_PARM_S));

	if (!(f->flags & MI_NO_INPUT_FLAG)) {
		cmd_root = init_mi_tree(0,0,0);
		if (!cmd_root) {
			LM_ERR("the MI tree for the command to be run cannot be initialized!\n");
			return init_mi_tree(400, MI_SSTR(MI_INTERNAL_ERR));
		}
		cmd_root->async_hdl = async_hdl;
	}

	for (i = 0; i < nr_params; i++)
		if (!add_mi_node_child(&cmd_root->node, 0, 0, 0,
			cmd_params[i].s, cmd_params[i].len)) {
			LM_ERR("cannot add child node to the tree of the MI command to be run\n");
			free_mi_tree(cmd_root);
			return init_mi_tree(400, MI_SSTR(MI_INTERNAL_ERR));
		}

	if ((cmd_rpl = run_mi_cmd(f, cmd_root, 0, 0)) == NULL) {
		if (cmd_root)
			free_mi_tree(cmd_root);
		return init_mi_tree(400, MI_SSTR("MI command to be run failed"));
	}

	if (cmd_root)
		free_mi_tree(cmd_root);

	return cmd_rpl;
}

struct mi_root *run_rcv_mi_cmd(str *cmd_name, str *cmd_params, int nr_params)
{
	struct mi_cmd *f;
	struct mi_root *cmd_root = NULL, *cmd_rpl;
	int i;

	f = lookup_mi_cmd(cmd_name->s, cmd_name->len);
	if (!f) {
		LM_ERR("MI command to be run not found\n");
		return NULL;
	}

	if (f->flags & MI_NO_INPUT_FLAG && nr_params) {
		LM_ERR("MI command should not have parameters\n");
		return NULL;
	}

	if (!(f->flags & MI_NO_INPUT_FLAG)) {
		cmd_root = init_mi_tree(0,0,0);
		if (!cmd_root) {
			LM_ERR("the MI tree for the command to be run cannot be initialized!\n");
			return NULL;
		}
	}

	for (i = 0; i < nr_params; i++)
		if (!add_mi_node_child(&cmd_root->node, 0, 0, 0,
			cmd_params[i].s, cmd_params[i].len)) {
			free_mi_tree(cmd_root);
			LM_ERR("cannot add child node to the tree of the MI command to be run\n");
			return NULL;
		}

	if ((cmd_rpl = run_mi_cmd(f, cmd_root, 0, 0)) == NULL) {
		if (cmd_root)
			free_mi_tree(cmd_root);
		return NULL;
	}

	if (cmd_root)
		free_mi_tree(cmd_root);

	return cmd_rpl;
}

static struct mi_root* cluster_send_mi(struct mi_root *cmd, void *param)
{
	struct mi_node *node, *cmd_params_n;
	unsigned int cluster_id, node_id;
	int rc;
	str cl_cmd_name;
	str cl_cmd_params[MI_CMD_MAX_NR_PARAMS];
	int no_params = 0;

	node = cmd->node.kids;

	if (node == NULL || node->next == NULL || node->next->next == NULL)
		return init_mi_tree(400, MI_SSTR(MI_MISSING_PARM));

	rc = str2int(&node->value, &cluster_id);
	if (rc < 0 || cluster_id < 1)
		return init_mi_tree(400, MI_SSTR(MI_BAD_PARM));

	rc = str2int(&node->next->value, &node_id);
	if (rc < 0 || node_id < 1)
		return init_mi_tree(400, MI_SSTR(MI_BAD_PARM));
	if (node_id == current_id)
		return init_mi_tree(400, MI_SSTR("Local node specified as destination"));

	cl_cmd_name = node->next->next->value;

	cmd_params_n = node->next->next->next;
	for (; cmd_params_n; cmd_params_n = cmd_params_n->next, no_params++)
		cl_cmd_params[no_params] = cmd_params_n->value;

	/* send MI cmd in cluster */
	rc = send_mi_cmd(cluster_id, node_id, cl_cmd_name, cl_cmd_params, no_params);
	switch (rc) {
		case CLUSTERER_SEND_SUCCES:
			LM_DBG("MI command <%.*s> sent\n", cl_cmd_name.len, cl_cmd_name.s);
			break;
		case CLUSTERER_CURR_DISABLED:
			LM_INFO("Current node disabled, MI command <%.*s> not sent\n",
				cl_cmd_name.len, cl_cmd_name.s);
			break;
		case CLUSTERER_DEST_DOWN:
			LM_ERR("Destination down, MI command <%.*s> not sent\n",
				cl_cmd_name.len, cl_cmd_name.s);
			break;
		case CLUSTERER_SEND_ERR:
			LM_ERR("Error sending MI command <%.*s>+\n",
				cl_cmd_name.len, cl_cmd_name.s);
			break;
	}

	return init_mi_tree(200, MI_SSTR(MI_OK));
}

static struct mi_root* cluster_bcast_mi(struct mi_root *cmd, void *param)
{
	struct mi_node *node, *cmd_params_n;
	struct mi_cmd *f;
	unsigned int cluster_id;
	int rc;
	str cl_cmd_name;
	str cl_cmd_params[MI_CMD_MAX_NR_PARAMS];
	int no_params = 0;

	node = cmd->node.kids;

	if (node == NULL || node->next == NULL || node->next->next == NULL)
		return init_mi_tree(400, MI_SSTR(MI_MISSING_PARM));

	rc = str2int(&node->value, &cluster_id);
	if (rc < 0 || cluster_id < 1)
		return init_mi_tree(400, MI_SSTR(MI_BAD_PARM));

	cl_cmd_name = node->next->value;

	f = lookup_mi_cmd(cl_cmd_name.s, cl_cmd_name.len);
	if (!f)
		return init_mi_tree(400, MI_SSTR("MI command to be run not found"));

	cmd_params_n = node->next->next;
	for (; cmd_params_n; cmd_params_n = cmd_params_n->next, no_params++)
		cl_cmd_params[no_params] = cmd_params_n->value;

	/* send MI cmd in cluster */
	rc = send_mi_cmd(cluster_id, 0, cl_cmd_name, cl_cmd_params, no_params);
	switch (rc) {
		case CLUSTERER_SEND_SUCCES:
			LM_DBG("MI command <%.*s> sent\n", cl_cmd_name.len, cl_cmd_name.s);
			break;
		case CLUSTERER_CURR_DISABLED:
			LM_INFO("Current node disabled, MI command <%.*s> not sent\n",
				cl_cmd_name.len, cl_cmd_name.s);
			break;
		case CLUSTERER_DEST_DOWN:
			LM_ERR("All nodes down, MI command <%.*s> not sent\n",
				cl_cmd_name.len, cl_cmd_name.s);
			break;
		case CLUSTERER_SEND_ERR:
			LM_ERR("Error sending MI command <%.*s>+\n",
				cl_cmd_name.len, cl_cmd_name.s);
			break;
	}

	/* run MI cmd locally */
	return run_mi_cmd_local(f, cl_cmd_params, no_params, cmd->async_hdl);
}

static void heartbeats_timer_handler(unsigned int ticks, void *param)
{
	heartbeats_timer();
}

static void heartbeats_utimer_handler(utime_t ticks, void *param)
{
	heartbeats_timer();
}

static int fixup_broadcast(void ** param, int param_no)
{
	if (param_no == 1)
		return fixup_igp(param);
	else if (param_no == 2)
		return fixup_spve(param);
	else if (param_no == 3)
		return fixup_pvar(param);

	LM_CRIT("Unknown parameter number %d\n", param_no);
	return E_UNSPEC;
}

static int fixup_send(void ** param, int param_no)
{
	if (param_no == 1 || param_no == 2)
		return fixup_igp(param);
	else if (param_no == 3)
		return fixup_spve(param);
	else if (param_no == 4)
		return fixup_pvar(param);

	LM_CRIT("Unknown parameter number %d\n", param_no);
	return E_UNSPEC;
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

int cmd_broadcast_req(struct sip_msg *msg, char *param_cluster, char *param_msg,
									char *param_tag)
{
	int cluster_id;
	str gen_msg;
	pv_value_t tag_val;
	int rc;

	if (fixup_get_ivalue(msg, (gparam_p)param_cluster, &cluster_id) < 0) {
		LM_ERR("Failed to fetch cluster id parameter\n");
		return -1;
	}

	if (fixup_get_svalue(msg, (gparam_p)param_msg, &gen_msg) < 0) {
		LM_ERR("Failed to fetch message parameter\n");
		return -1;
	}

	/* generate tag */
	generate_msg_tag(&tag_val, cluster_id);

	if (param_tag && pv_set_value(msg, (pv_spec_p)param_tag, 0, &tag_val) < 0) {
		LM_ERR("Unable to set tag pvar\n");
		return -1;
	}

	rc = bcast_gen_msg(cluster_id, &gen_msg, &tag_val.rs);
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

int cmd_send_req(struct sip_msg *msg, char *param_cluster, char *param_node,
								char *param_msg, char *param_tag)
{
	int cluster_id, node_id;
	str gen_msg;
	pv_value_t tag_val;
	int rc;

	if (fixup_get_ivalue(msg, (gparam_p)param_cluster, &cluster_id) < 0) {
		LM_ERR("Failed to fetch cluster id parameter\n");
		return -1;
	}
	if (fixup_get_ivalue(msg, (gparam_p)param_node, &node_id) < 0) {
		LM_ERR("Failed to fetch node id parameter\n");
		return -1;
	}

	if (fixup_get_svalue(msg, (gparam_p)param_msg, &gen_msg) < 0) {
		LM_ERR("Failed to fetch message parameter\n");
		return -1;
	}

	/* generate tag */
	generate_msg_tag(&tag_val, cluster_id);

	if (param_tag && pv_set_value(msg, (pv_spec_p)param_tag, 0, &tag_val) < 0) {
		LM_ERR("Unable to set tag pvar\n");
		return -1;
	}

	rc = send_gen_msg(cluster_id, node_id, &gen_msg, &tag_val.rs, 1);
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

int cmd_send_rpl(struct sip_msg *msg, char *param_cluster, char *param_node,
								char *param_msg, char *param_tag)
{
	int cluster_id, node_id;
	str gen_msg;
	pv_value_t tag_val;
	int rc;

	if (fixup_get_ivalue(msg, (gparam_p)param_cluster, &cluster_id) < 0) {
		LM_ERR("Failed to fetch cluster id parameter\n");
		return -1;
	}
	if (fixup_get_ivalue(msg, (gparam_p)param_node, &node_id) < 0) {
		LM_ERR("Failed to fetch node id parameter\n");
		return -1;
	}

	if (fixup_get_svalue(msg, (gparam_p)param_msg, &gen_msg) < 0) {
		LM_ERR("Failed to fetch message parameter\n");
		return -1;
	}

	if (pv_get_spec_value(msg, (pv_spec_p)param_tag, &tag_val) < 0) {
		LM_ERR("Failed to fetch tag parameter\n");
		return -1;
	}
	if (tag_val.flags & PV_VAL_NULL ||
		(tag_val.flags & PV_VAL_STR && tag_val.rs.len == 0)) {
		LM_ERR("Empty tag\n");
		return -1;
	}

	rc = send_gen_msg(cluster_id, node_id, &gen_msg, &tag_val.rs, 0);
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

static void destroy(void)
{
	struct mod_registration *tmp;

	if (db_hdl) {
		/* close DB connection */
		dr_dbf.close(db_hdl);
		db_hdl = NULL;
	}

	/* destroy data */
	if (cluster_list) {
		if (*cluster_list)
			free_info(*cluster_list);
		shm_free(cluster_list);
		cluster_list = NULL;
	}

	while (clusterer_reg_modules) {
		tmp = clusterer_reg_modules;
		clusterer_reg_modules = clusterer_reg_modules->next;
		shm_free(tmp);
	}

	/* destroy lock */
	if (cl_list_lock) {
		lock_destroy_rw(cl_list_lock);
		cl_list_lock = NULL;
	}

	/* free generic message receiving events events */
	gen_rcv_evs_destroy();
}

int load_clusterer(struct clusterer_binds *binds)
{
	binds->get_nodes = get_clusterer_nodes;
	binds->free_nodes = free_clusterer_nodes;
	binds->set_state = cl_set_state;
	binds->check_addr = clusterer_check_addr;
	binds->get_my_id = cl_get_my_id;
	binds->send_to = cl_send_to;
	binds->send_all = cl_send_all;
	binds->get_next_hop = api_get_next_hop;
	binds->free_next_hop = api_free_next_hop;
	binds->register_module = cl_register_module;

	return 1;
}

