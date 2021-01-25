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

#include "../../str.h"
#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../locking.h"
#include "../../rw_locking.h"
#include "../../resolve.h"
#include "../../socket_info.h"

#include "api.h"
#include "node_info.h"
#include "clusterer.h"

/* DB */
extern str clusterer_db_url;
extern str db_table;
extern str id_col;
extern str cluster_id_col;
extern str node_id_col;
extern str url_col;
extern str state_col;
extern str ls_seq_no_col;
extern str top_seq_no_col;
extern str no_ping_retries_col;
extern str priority_col;
extern str sip_addr_col;
extern str flags_col;
extern str description_col;

int parse_param_node_info(str *descr, int *int_vals, str *str_vals);

db_con_t *db_hdl;
db_func_t dr_dbf;

static db_op_t op_eq = OP_EQ;
static db_key_t *clusterer_cluster_id_key;
static db_val_t *clusterer_cluster_id_value;

/* protects the cluster_list and the node_list from each cluster */
rw_lock_t *cl_list_lock;

cluster_info_t **cluster_list;

int add_node_info(node_info_t **new_info, cluster_info_t **cl_list, int *int_vals,
					str *str_vals)
{
	char *host;
	int hlen, port;
	int proto;
	struct hostent *he;
	int cluster_id;
	cluster_info_t *cluster = NULL;
	struct timeval t;
	str st;
	str seed_flag = str_init(SEED_NODE_FLAG_STR);

	cluster_id = int_vals[INT_VALS_CLUSTER_ID_COL];
	/* new_info is checked whether it is initialized or not in case of error,
	 * so we have to initialize it as soon as possible */
	*new_info = NULL;

	for (cluster = *cl_list; cluster && cluster->cluster_id != cluster_id;
		cluster = cluster->next) ;

	if (!cluster) {
		cluster = shm_malloc(sizeof *cluster);
		if (!cluster) {
			LM_ERR("no more shm memory\n");
			goto error;
		}
		memset(cluster, 0, sizeof *cluster);

		cluster->cluster_id = cluster_id;
		cluster->next = *cl_list;
		if ((cluster->lock = lock_alloc()) == NULL) {
			LM_CRIT("Failed to allocate lock\n");
			goto error;
		}
		if (!lock_init(cluster->lock)) {
			lock_dealloc(cluster->lock);
			LM_CRIT("Failed to init lock\n");
			goto error;
		}
		*cl_list = cluster;
	}

	*new_info = shm_malloc(sizeof **new_info);
	if (!*new_info) {
		LM_ERR("no more shm memory\n");
		goto error;
	}
	memset(*new_info, 0, sizeof **new_info);

	(*new_info)->flags = 0;

	(*new_info)->id = int_vals[INT_VALS_ID_COL];
	(*new_info)->node_id = int_vals[INT_VALS_NODE_ID_COL];
	if (int_vals[INT_VALS_STATE_COL])
		(*new_info)->flags |= NODE_STATE_ENABLED;
	else
		(*new_info)->flags &= ~NODE_STATE_ENABLED;

	if (int_vals[INT_VALS_NODE_ID_COL] != current_id)
		(*new_info)->link_state = LS_RESTART_PINGING;
	else
		(*new_info)->link_state = LS_UP;

	if (str_vals[STR_VALS_DESCRIPTION_COL].s &&
		str_vals[STR_VALS_DESCRIPTION_COL].len) {
		(*new_info)->description.len = str_vals[STR_VALS_DESCRIPTION_COL].len;
		(*new_info)->description.s =
			shm_malloc((*new_info)->description.len * sizeof(char));
		if ((*new_info)->description.s == NULL) {
			LM_ERR("no more shm memory\n");
			goto error;
		}
		memcpy((*new_info)->description.s, str_vals[STR_VALS_DESCRIPTION_COL].s,
			(*new_info)->description.len);
	} else {
		(*new_info)->description.s = NULL;
		(*new_info)->description.len = 0;
	}

	if (str_vals[STR_VALS_SIP_ADDR_COL].s &&
		str_vals[STR_VALS_SIP_ADDR_COL].len) {
		(*new_info)->sip_addr.len = str_vals[STR_VALS_SIP_ADDR_COL].len;
		(*new_info)->sip_addr.s = shm_malloc((*new_info)->sip_addr.len * sizeof(char));
		if ((*new_info)->sip_addr.s == NULL) {
			LM_ERR("no more shm memory\n");
			goto error;
		}
		memcpy((*new_info)->sip_addr.s, str_vals[STR_VALS_SIP_ADDR_COL].s,
			(*new_info)->sip_addr.len);
	} else {
		(*new_info)->sip_addr.s = NULL;
		(*new_info)->sip_addr.len = 0;
	}

	if (str_vals[STR_VALS_FLAGS_COL].s &&
		str_vals[STR_VALS_FLAGS_COL].len)
		if (memcmp(str_vals[STR_VALS_FLAGS_COL].s, seed_flag.s, seed_flag.len) == 0)
			(*new_info)->flags |= NODE_IS_SEED;

	if (str_vals[STR_VALS_URL_COL].s == NULL) {
		LM_ERR("no url specified in DB\n");
		return 1;
	}
	(*new_info)->url.len = str_vals[STR_VALS_URL_COL].len;
	(*new_info)->url.s = shm_malloc(str_vals[STR_VALS_URL_COL].len);
	if (!(*new_info)->url.s) {
		LM_ERR("no more shm memory\n");
		goto error;
	}
	memcpy((*new_info)->url.s, str_vals[STR_VALS_URL_COL].s, (*new_info)->url.len);

	if (parse_phostport((*new_info)->url.s, (*new_info)->url.len, &host, &hlen,
		&port, &proto) < 0) {
		LM_ERR("Bad URL!\n");
		return 1;
	}
	st.s = host;
	st.len = hlen;

	if (proto == PROTO_NONE)
		proto = clusterer_proto;
	if (proto != clusterer_proto) {
		LM_ERR("Clusterer currently supports only BIN protocol, but node: %d "
			"has proto=%d\n", int_vals[INT_VALS_NODE_ID_COL], proto);
		return 1;
	}

	if (int_vals[INT_VALS_NODE_ID_COL] != current_id) {
		he = sip_resolvehost(&st, (unsigned short *) &port,
			(unsigned short *)&proto, 0, 0);
		if (!he) {
			LM_ERR("Cannot resolve host: %.*s\n", hlen, host);
			return 1;
		}

		hostent2su(&((*new_info)->addr), he, 0, port);

		t.tv_sec = 0;
		t.tv_usec = 0;
		(*new_info)->last_ping = t;
		(*new_info)->last_pong = t;
	} else {
		cluster->send_sock = grep_sock_info(&st, port, proto);
		if (!cluster->send_sock) {
			LM_ERR("non-local socket <%.*s> for this node\n", st.len, st.s);
			goto error;
		}
	}

	(*new_info)->priority = int_vals[INT_VALS_PRIORITY_COL];

	(*new_info)->no_ping_retries = int_vals[INT_VALS_NO_PING_RETRIES_COL];

	(*new_info)->cluster = cluster;

	(*new_info)->ls_seq_no = -1;
	(*new_info)->top_seq_no = -1;
	(*new_info)->ls_timestamp = 0;
	(*new_info)->top_timestamp = 0;

	(*new_info)->sp_info = shm_malloc(sizeof(struct node_search_info));
	if (!(*new_info)->sp_info) {
		LM_ERR("no more shm memory\n");
		goto error;
	}
	(*new_info)->sp_info->node = *new_info;

	if (int_vals[INT_VALS_NODE_ID_COL] != current_id) {
		(*new_info)->next = cluster->node_list;
		cluster->node_list = *new_info;
		cluster->no_nodes++;
		if (cluster->no_nodes > MAX_NO_NODES) {
			LM_ERR("Defined: %d nodes for cluster: %d, maximum number of nodes "
				"supported(%d) exceeded\n", cluster->no_nodes,
				cluster->cluster_id, MAX_NO_NODES);
			goto error;
		}
	} else {
		(*new_info)->next = NULL;
		cluster->current_node = *new_info;
	}

	if (((*new_info)->lock = lock_alloc()) == NULL) {
		LM_CRIT("Failed to allocate lock\n");
		goto error;
	}
	if (!lock_init((*new_info)->lock)) {
		lock_dealloc((*new_info)->lock);
		LM_CRIT("Failed to init lock\n");
		goto error;
	}

	return 0;
error:
	if (*new_info) {
		if ((*new_info)->sip_addr.s)
			shm_free((*new_info)->sip_addr.s);

		if ((*new_info)->description.s)
			shm_free((*new_info)->description.s);

		if ((*new_info)->url.s)
			shm_free((*new_info)->url.s);

		if ((*new_info)->sp_info)
			shm_free((*new_info)->sp_info);

		shm_free(*new_info);
	}
	return -1;
}

#define check_val( _col, _val, _type, _not_null, _is_empty_str) \
    do { \
        if ((_val)->type!=_type) { \
            LM_ERR("column %.*s has a bad type\n", _col.len, _col.s); \
            return 2; \
        } \
        if (_not_null && (_val)->nul) { \
            LM_ERR("column %.*s is null\n", _col.len, _col.s); \
            return 2; \
        } \
        if (_is_empty_str && !VAL_STRING(_val)) { \
            LM_ERR("column %.*s (str) is empty\n", _col.len, _col.s); \
            return 2; \
        } \
    } while (0)

static void check_seed_flag(cluster_info_t **cl_list)
{
	cluster_info_t *cl;
	node_info_t *n;

	for (cl = *cl_list; cl; cl = cl->next) {
		for (n = cl->node_list; n; n = n->next)
			if (n->flags & NODE_IS_SEED)
				break;

		if (!n && cl->current_node &&
		        !(cl->current_node->flags & NODE_IS_SEED)) {
			LM_NOTICE("No seed node defined in cluster: %d! Some clustering "
			"capabilities might not be able to sync data\n", cl->cluster_id);
		}
	}
}

/* loads info from the db */
int load_db_info(db_func_t *dr_dbf, db_con_t* db_hdl, str *db_table,
					cluster_info_t **cl_list)
{
	int int_vals[NO_DB_INT_VALS];
	str str_vals[NO_DB_STR_VALS];
	int no_clusters;
	int i;
	int rc;
	node_info_t *_ = NULL;
	db_key_t columns[NO_DB_COLS];	/* the columns from the db table */
	db_res_t *res = NULL;
	db_row_t *row;
	static db_key_t clusterer_node_id_key = &node_id_col;
	static db_val_t clusterer_node_id_value = {
		.type = DB_INT,
		.nul = 0,
	};

	*cl_list = NULL;

	columns[0] = &id_col;
	columns[1] = &cluster_id_col;
	columns[2] = &node_id_col;
	columns[3] = &url_col;
	columns[4] = &state_col;
	columns[5] = &no_ping_retries_col;
	columns[6] = &priority_col;
	columns[7] = &sip_addr_col;
	columns[8] = &flags_col;
	columns[9] = &description_col;

	CON_OR_RESET(db_hdl);

	if (db_check_table_version(dr_dbf, db_hdl, db_table, CLUSTERER_TABLE_VERSION))
		goto error;

	if (dr_dbf->use_table(db_hdl, db_table) < 0) {
		LM_ERR("cannot select table: \"%.*s\"\n", db_table->len, db_table->s);
		goto error;
	}

	LM_DBG("DB query - retrieve the list of clusters"
		" in which the local node runs\n");

	VAL_INT(&clusterer_node_id_value) = current_id;

	/* first we see in which clusters the local node runs*/
	if (dr_dbf->query(db_hdl, &clusterer_node_id_key, &op_eq,
		&clusterer_node_id_value, columns+1, 1, 1, 0, &res) < 0) {
		LM_ERR("DB query failed - cannot retrieve the list of clusters in which"
			" the local node runs\n");
		goto error;
	}

	LM_DBG("%d rows found in %.*s\n",
		RES_ROW_N(res), db_table->len, db_table->s);

	if (RES_ROW_N(res) > MAX_NO_CLUSTERS) {
		LM_ERR("Defined: %d clusters for local node, maximum number of clusters "
			"supported(%d) exceeded\n", RES_ROW_N(res), MAX_NO_CLUSTERS);
		goto error;
	}

	if (RES_ROW_N(res) == 0) {
		LM_WARN("Current node does not belong to any cluster\n");
		return 1;
	}

	clusterer_cluster_id_key = pkg_realloc(clusterer_cluster_id_key,
		RES_ROW_N(res) * sizeof(db_key_t));
	if (!clusterer_cluster_id_key) {
		LM_ERR("no more pkg memory\n");
		goto error;
	}

	for (i = 0; i < RES_ROW_N(res); i++)
		clusterer_cluster_id_key[i] = &cluster_id_col;

	clusterer_cluster_id_value = pkg_realloc(clusterer_cluster_id_value,
		RES_ROW_N(res) * sizeof(db_val_t));
	if (!clusterer_cluster_id_value) {
		LM_ERR("no more pkg memory\n");
		goto error;
	}

	for (i = 0; i < RES_ROW_N(res); i++) {
		VAL_TYPE(clusterer_cluster_id_value + i) = DB_INT;
		VAL_NULL(clusterer_cluster_id_value + i) = 0;
	}

	for (i = 0; i < RES_ROW_N(res); i++) {
		row = RES_ROWS(res) + i;
		check_val(cluster_id_col, ROW_VALUES(row), DB_INT, 1, 0);
		VAL_INT(clusterer_cluster_id_value + i) = VAL_INT(ROW_VALUES(row));
	}

	no_clusters = RES_ROW_N(res);
	dr_dbf->free_result(db_hdl, res);
	res = NULL;

	LM_DBG("DB query - retrieve nodes info\n");

	CON_USE_OR_OP(db_hdl);

	if (dr_dbf->query(db_hdl, clusterer_cluster_id_key, 0,
		clusterer_cluster_id_value, columns, no_clusters, NO_DB_COLS, 0, &res) < 0) {
		LM_ERR("DB query failed - retrieve valid connections\n");
		goto error;
	}

	LM_DBG("%d rows found in %.*s\n",
		RES_ROW_N(res), db_table->len, db_table->s);

	if (RES_ROW_N(res) > MAX_NO_NODES) {
		LM_ERR("Defined: %d nodes in local node's clusters, maximum number of nodes "
			"supported(%d) exceeded\n", RES_ROW_N(res), MAX_NO_NODES);
		goto error;
	}

	for (i = 0; i < RES_ROW_N(res); i++) {
		row = RES_ROWS(res) + i;

		check_val(id_col, ROW_VALUES(row), DB_INT, 1, 0);
		int_vals[INT_VALS_ID_COL] = VAL_INT(ROW_VALUES(row));

		check_val(cluster_id_col, ROW_VALUES(row) + 1, DB_INT, 1, 0);
		int_vals[INT_VALS_CLUSTER_ID_COL] = VAL_INT(ROW_VALUES(row) + 1);

		check_val(node_id_col, ROW_VALUES(row) + 2, DB_INT, 1, 0);
		int_vals[INT_VALS_NODE_ID_COL] = VAL_INT(ROW_VALUES(row) + 2);

		check_val(url_col, ROW_VALUES(row) + 3, DB_STRING, 1, 1);
		str_vals[STR_VALS_URL_COL].s = (char*) VAL_STRING(ROW_VALUES(row) + 3);
		str_vals[STR_VALS_URL_COL].len = strlen(str_vals[STR_VALS_URL_COL].s);

		check_val(state_col, ROW_VALUES(row) + 4, DB_INT, 1, 0);
		int_vals[INT_VALS_STATE_COL] = VAL_INT(ROW_VALUES(row) + 4);

		check_val(no_ping_retries_col, ROW_VALUES(row) + 5, DB_INT, 1, 0);
		int_vals[INT_VALS_NO_PING_RETRIES_COL] = VAL_INT(ROW_VALUES(row) + 5);

		check_val(priority_col, ROW_VALUES(row) + 6, DB_INT, 1, 0);
		int_vals[INT_VALS_PRIORITY_COL] = VAL_INT(ROW_VALUES(row) + 6);

		check_val(sip_addr_col, ROW_VALUES(row) + 7, DB_STRING, 0, 0);
		str_vals[STR_VALS_SIP_ADDR_COL].s = (char*) VAL_STRING(ROW_VALUES(row) + 7);
		str_vals[STR_VALS_SIP_ADDR_COL].len = str_vals[STR_VALS_SIP_ADDR_COL].s ?
			strlen(str_vals[STR_VALS_SIP_ADDR_COL].s) : 0;

		check_val(flags_col, ROW_VALUES(row) + 8, DB_STRING, 0, 0);
		str_vals[STR_VALS_FLAGS_COL].s = (char*) VAL_STRING(ROW_VALUES(row) + 8);
		str_vals[STR_VALS_FLAGS_COL].len = str_vals[STR_VALS_FLAGS_COL].s ?
			strlen(str_vals[STR_VALS_FLAGS_COL].s) : 0;

		check_val(description_col, ROW_VALUES(row) + 9, DB_STRING, 0, 0);
		str_vals[STR_VALS_DESCRIPTION_COL].s = (char*) VAL_STRING(ROW_VALUES(row) + 9);
		str_vals[STR_VALS_DESCRIPTION_COL].len = str_vals[STR_VALS_DESCRIPTION_COL].s ?
			strlen(str_vals[STR_VALS_DESCRIPTION_COL].s) : 0;

		/* add info to backing list */
		if ((rc = add_node_info(&_, cl_list, int_vals, str_vals)) != 0) {
			LM_ERR("Unable to add node info to backing list\n");
			if (rc < 0)
				return -1;
			else
				return 2;
		}
	}

	/* warn if no seed node is defined in a cluster */
	check_seed_flag(cl_list);

	if (RES_ROW_N(res) == 1)
		LM_INFO("The local node is the only one in the cluster\n");

	dr_dbf->free_result(db_hdl, res);

	return 0;
error:
	if (res)
		dr_dbf->free_result(db_hdl, res);
	if (*cl_list)
		free_info(*cl_list);
	*cl_list = NULL;
	return -1;
}

int provision_neighbor(modparam_t type, void *val)
{
	int int_vals[NO_DB_INT_VALS];
	str str_vals[NO_DB_STR_VALS];
	str prov_str;
	node_info_t *new_info;

	if (db_mode) {
		LM_INFO("Running in db mode, provisioning from the script is ignored\n");
		return 0;
	}

	prov_str.s = (char*)val;
	prov_str.len = strlen(prov_str.s);

	if (parse_param_node_info(&prov_str, int_vals, str_vals) < 0) {
		LM_ERR("Unable to define a neighbor node\n");
		return -1;
	}

	if (int_vals[INT_VALS_CLUSTER_ID_COL] == -1 ||
		int_vals[INT_VALS_NODE_ID_COL] == -1 ||
		str_vals[STR_VALS_URL_COL].s == NULL) {
		LM_ERR("At least the cluster id, node id and url are required for a neighbor node\n");
		return -1;
	}
	int_vals[INT_VALS_STATE_COL] = 1;
	if (int_vals[INT_VALS_NO_PING_RETRIES_COL] == -1)
		int_vals[INT_VALS_NO_PING_RETRIES_COL] = DEFAULT_NO_PING_RETRIES;
	if (int_vals[INT_VALS_PRIORITY_COL] == -1)
		int_vals[INT_VALS_PRIORITY_COL] = DEFAULT_NO_PING_RETRIES;

	str_vals[STR_VALS_DESCRIPTION_COL].s = NULL;
	int_vals[INT_VALS_ID_COL] = -1;

	if (cluster_list == NULL) {
		cluster_list = shm_malloc(sizeof *cluster_list);
		if (!cluster_list) {
			LM_CRIT("No more shm memory\n");
			return -1;
		}
		*cluster_list = NULL;
	}

	if (add_node_info(&new_info, cluster_list, int_vals, str_vals) < 0) {
		LM_ERR("Unable to add node info to backing list\n");
		return -1;
	}

	return 0;
}

int provision_current(modparam_t type, void *val)
{
	int int_vals[NO_DB_INT_VALS];
	str str_vals[NO_DB_STR_VALS];
	node_info_t *new_info;
	str prov_str;

	if (db_mode) {
		LM_INFO("Running in db mode, provisioning from the script is ignored\n");
		return 0;
	}

	prov_str.s = (char*)val;
	prov_str.len = strlen(prov_str.s);

	if (parse_param_node_info(&prov_str, int_vals, str_vals) < 0) {
		LM_ERR("Unable to define local node\n");
		return -1;
	}

	if (int_vals[INT_VALS_CLUSTER_ID_COL] == -1 || str_vals[STR_VALS_URL_COL].s == NULL) {
		LM_ERR("At least the cluster ID and url are required for the local node\n");
		return -1;
	}

	if (int_vals[INT_VALS_NODE_ID_COL] == -1 && current_id == -1) {
		LM_ERR("Node ID not defined. Set either the value of the 'node_id' proprety"
			" of 'my_node_info' or set 'my_node_id' parameter before 'my_node_info'!\n");
		return -1;
	}
	if (current_id != -1 && int_vals[INT_VALS_NODE_ID_COL] != -1 &&
		int_vals[INT_VALS_NODE_ID_COL] != current_id) {
		LM_ERR("Bad value in 'my_node_info' parameter, node_id: %d different"
			" than 'my_node_id' parameter\n", int_vals[INT_VALS_NODE_ID_COL]);
		return -1;
	}
	if (int_vals[INT_VALS_NODE_ID_COL] != -1)
		current_id = int_vals[INT_VALS_NODE_ID_COL];
	else
		int_vals[INT_VALS_NODE_ID_COL] = current_id;

	int_vals[INT_VALS_STATE_COL] = 1;
	if (int_vals[INT_VALS_NO_PING_RETRIES_COL] == -1)
		int_vals[INT_VALS_NO_PING_RETRIES_COL] = DEFAULT_NO_PING_RETRIES;
	if (int_vals[INT_VALS_PRIORITY_COL] == -1)
		int_vals[INT_VALS_PRIORITY_COL] = DEFAULT_NO_PING_RETRIES;

	str_vals[STR_VALS_DESCRIPTION_COL].s = NULL;
	int_vals[INT_VALS_ID_COL] = -1;

	if (cluster_list == NULL) {
		cluster_list = shm_malloc(sizeof *cluster_list);
		if (!cluster_list) {
			LM_CRIT("No more shm memory\n");
			return -1;
		}
		*cluster_list = NULL;
	}

	if (add_node_info(&new_info, cluster_list, int_vals, str_vals) != 0) {
		LM_ERR("Unable to add node info to backing list\n");
		return -1;
	}

	return 0;
}

int update_db_state(int state) {
	db_key_t node_id_key = &node_id_col;
	db_val_t node_id_val;
	db_key_t update_key;
	db_val_t update_val;

	VAL_TYPE(&node_id_val) = DB_INT;
	VAL_NULL(&node_id_val) = 0;
	VAL_INT(&node_id_val) = current_id;
	update_key = &state_col;

	CON_OR_RESET(db_hdl);
	if (dr_dbf.use_table(db_hdl, &db_table) < 0) {
		LM_ERR("cannot select table: \"%.*s\"\n", db_table.len, db_table.s);
		return -1;
	}

	VAL_TYPE(&update_val) = DB_INT;
	VAL_NULL(&update_val) = 0;
	VAL_INT(&update_val) = state;

	if (dr_dbf.update(db_hdl, &node_id_key, 0, &node_id_val, &update_key,
		&update_val, 1, 1) < 0)
		return -1;

	return 0;
}

void free_info(cluster_info_t *cl_list)
{
	cluster_info_t *tmp_cl;
	node_info_t *info, *tmp_info;
	struct local_cap *cl_cap, *tmp_cl_cap;
	struct remote_cap *cap, *tmp_cap;

	while (cl_list != NULL) {
		tmp_cl = cl_list;
		cl_list = cl_list->next;

		info = tmp_cl->node_list;
		while (info != NULL) {
			if (info->url.s)
				shm_free(info->url.s);
			if (info->sip_addr.s)
				shm_free(info->sip_addr.s);
			if (info->description.s)
				shm_free(info->description.s);
			if (info->lock) {
				lock_destroy(info->lock);
				lock_dealloc(info->lock);
			}

			cap = info->capabilities;
			while (cap != NULL) {
				tmp_cap = cap;
				cap = cap->next;
				shm_free(tmp_cap);
			}

			tmp_info = info;
			info = info->next;
			shm_free(tmp_info);
		}

		cl_cap = tmp_cl->capabilities;
		while (cl_cap != NULL) {
			tmp_cl_cap = cl_cap;
			cl_cap = cl_cap->next;
			shm_free(tmp_cl_cap);
		}

		if (tmp_cl->lock) {
			lock_destroy(tmp_cl->lock);
			lock_dealloc(tmp_cl->lock);
		}

		shm_free(tmp_cl);
	}
}

static inline void free_clusterer_node(clusterer_node_t *node)
{
	if (node->description.s)
		pkg_free(node->description.s);
	if (node->sip_addr.s)
		pkg_free(node->sip_addr.s);
	pkg_free(node);
}

static int add_clusterer_node(clusterer_node_t **cl_node_list, node_info_t *n_info)
{
	clusterer_node_t *new_node = NULL;

	new_node = pkg_malloc(sizeof *new_node);
	if (!new_node) {
		LM_ERR("no more pkg memory\n");
		goto error;
	}

	new_node->node_id = n_info->node_id;

	if (n_info->description.s) {
		new_node->description.s = pkg_malloc(n_info->description.len * sizeof(char));
		if (!new_node->description.s) {
			LM_ERR("no more pkg memory\n");
			goto error;
		}
		new_node->description.len = n_info->description.len;
		memcpy(new_node->description.s, n_info->description.s, n_info->description.len);
	} else {
		new_node->description.s = NULL;
		new_node->description.len = 0;
	}

	if (n_info->sip_addr.s) {
		new_node->sip_addr.s = pkg_malloc(n_info->sip_addr.len * sizeof(char));
		if (!new_node->sip_addr.s) {
			LM_ERR("no more pkg memory\n");
			goto error;
		}
		new_node->sip_addr.len = n_info->sip_addr.len;
		memcpy(new_node->sip_addr.s, n_info->sip_addr.s, n_info->sip_addr.len);
	} else {
		new_node->sip_addr.s = NULL;
		new_node->sip_addr.len = 0;
	}

	memcpy(&new_node->addr, &n_info->addr, sizeof(n_info->addr));
	new_node->next = NULL;

	if (*cl_node_list)
		new_node->next = *cl_node_list;

	*cl_node_list = new_node;
	return 0;

error:
	if (new_node)
		free_clusterer_node(new_node);
	return -1;
}

void free_clusterer_nodes(clusterer_node_t *nodes)
{
	clusterer_node_t *tmp;

	while (nodes) {
		tmp = nodes;
		nodes = nodes->next;
		free_clusterer_node(tmp);
	}
}

clusterer_node_t* get_clusterer_nodes(int cluster_id)
{
	clusterer_node_t *ret_nodes = NULL;
	node_info_t *node;
	cluster_info_t *cl;

	lock_start_read(cl_list_lock);

	cl = get_cluster_by_id(cluster_id);
	if (!cl) {
		LM_ERR("cluster id: %d not found!\n", cluster_id);
		lock_stop_read(cl_list_lock);
		return NULL;
	}
	for (node = cl->node_list; node; node = node->next)
		if (get_next_hop(node) > 0)
			if (add_clusterer_node(&ret_nodes, node) < 0) {
				lock_stop_read(cl_list_lock);
				LM_ERR("Unable to add node: %d to the returned list of reachable nodes\n",
					node->node_id);
				free_clusterer_nodes(ret_nodes);
				return NULL;
			}

	lock_stop_read(cl_list_lock);

	return ret_nodes;
}

clusterer_node_t *api_get_next_hop(int cluster_id, int node_id)
{
	clusterer_node_t *ret = NULL;
	node_info_t *dest_node;
	cluster_info_t *cluster;

	lock_start_read(cl_list_lock);

	cluster = get_cluster_by_id(cluster_id);
	if (!cluster) {
		LM_DBG("Cluster id: %d not found!\n", cluster_id);
		return NULL;
	}
	dest_node = get_node_by_id(cluster, node_id);
	if (!dest_node) {
		LM_DBG("Node id: %d no found!\n", node_id);
		return NULL;
	}

	if (get_next_hop(dest_node) == 0) {
		LM_DBG("No other path to node: %d\n", node_id);
		return NULL;
	}

	lock_get(dest_node->lock);

	if (add_clusterer_node(&ret, dest_node->next_hop) < 0) {
		LM_ERR("Failed to allocate next hop\n");
		return NULL;
	}

	lock_release(dest_node->lock);

	lock_stop_read(cl_list_lock);

	return ret;
}

void api_free_next_hop(clusterer_node_t *next_hop)
{
	if (next_hop)
		free_clusterer_node(next_hop);
}

int cl_get_my_id(void)
{
	return current_id;
}

int cl_get_my_sip_addr(int cluster_id, str *out_addr)
{
	cluster_info_t *cl;
	int rc;

	if (!cl_list_lock) {
		LM_ERR("cluster shutdown\n");
		memset(out_addr, 0, sizeof *out_addr);
		return -1;
	}
	lock_start_read(cl_list_lock);

	cl = get_cluster_by_id(cluster_id);
	if (!cl) {
		LM_ERR("unknown cluster id: %d\n", cluster_id);
		lock_stop_read(cl_list_lock);
		memset(out_addr, 0, sizeof *out_addr);
		return -1;
	}

	lock_get(cl->current_node->lock);
	if (ZSTR(cl->current_node->sip_addr)) {
		memset(out_addr, 0, sizeof *out_addr);
		rc = 0;
	} else {
		if (pkg_str_dup(out_addr, &cl->current_node->sip_addr) != 0) {
			LM_ERR("oom\n");
			memset(out_addr, 0, sizeof *out_addr);
			rc = -1;
		} else {
			rc = 0;
		}
	}

	lock_release(cl->current_node->lock);
	lock_stop_read(cl_list_lock);
	return rc;
}

int cl_get_my_index(int cluster_id, str *capability, int *nr_nodes)
{
	int i, j, tmp;
	int sorted[MAX_NO_NODES];
	node_info_t *node;
	cluster_info_t *cl;
	struct remote_cap *cap;

	lock_start_read(cl_list_lock);

	cl = get_cluster_by_id(cluster_id);
	if (!cl) {
		LM_ERR("cluster id: %d not found!\n", cluster_id);
		lock_stop_read(cl_list_lock);
		return -1;
	}

	*nr_nodes = 0;
	for (node = cl->node_list; node; node = node->next)
		if (get_next_hop(node) > 0) {
			lock_get(node->lock);
			for (cap = node->capabilities; cap; cap = cap->next)
				if (!str_strcmp(capability, &cap->name))
					break;

			if (cap && cap->flags & CAP_STATE_OK)
				sorted[(*nr_nodes)++] = node->node_id;
			lock_release(node->lock);
		}

	lock_stop_read(cl_list_lock);

	/* sort array of reachable node ids */
	for (i = 1; i < *nr_nodes; i++) {
		tmp = sorted[i];
		for (j = i - 1; j >= 0 && sorted[j] > tmp; j = j - 1)
			sorted[j+1] = sorted[j];
		sorted[j+1] = tmp;
	}

	for (i = 0; i < *nr_nodes && sorted[i] < current_id; i++) ;

	(*nr_nodes)++;
	return i;
}

int match_node(const node_info_t *a, const node_info_t *b,
               enum cl_node_match_op match_op)
{
	switch (match_op) {
	case NODE_CMP_ANY:
		break;
	case NODE_CMP_EQ_SIP_ADDR:
		lock_get(a->lock);
		if (!a->sip_addr.s || !b->sip_addr.s ||
				str_strcmp(&a->sip_addr, &b->sip_addr)) {
			lock_release(a->lock);
			return 0;
		}
		lock_release(a->lock);
		break;
	case NODE_CMP_NEQ_SIP_ADDR:
		lock_get(a->lock);
		if (!a->sip_addr.s || !b->sip_addr.s ||
				!str_strcmp(&a->sip_addr, &b->sip_addr)) {
			lock_release(a->lock);
			return 0;
		}
		lock_release(a->lock);
		break;
	default:
		LM_BUG("unknown match_op: %d\n", match_op);
		return 0;
	}

	LM_DBG("matched node %d\n", b->node_id);
	return 1;
}
