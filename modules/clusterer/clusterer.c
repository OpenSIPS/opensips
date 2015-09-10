/*
 * Copyright (C) 2011 OpenSIPS Project
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *
 * history:
 * ---------
 *  2015-07-07  created  by Marius Cristian Eseanu
 */

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include "../../sr_module.h"
#include "../../str.h"
#include "../../dprint.h"
#include "../../usr_avp.h"
#include "../../db/db.h"
#include "../../socket_info.h"
#include "../../resolve.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../rw_locking.h"
#include "../../error.h"
#include "../../ut.h"
#include "../../mi/mi.h"
#include "../../timer.h"
#include "../../bin_interface.h"
#include "../../forward.h"
#include "clusterer.h"
#include "api.h"

#define DB_CAP DB_CAP_QUERY | DB_CAP_UPDATE

#define check_val( _col, _val, _type, _not_null, _is_empty_str) \
	do{\
		if ((_val)->type!=_type) { \
			LM_ERR("column %.*s has a bad type\n", _col.len, _col.s); \
			goto error;\
		} \
		if (_not_null && (_val)->nul) { \
			LM_ERR("column %.*s is null\n", _col.len, _col.s); \
			goto error;\
		} \
		if (_is_empty_str && VAL_STRING(_val)==0) { \
			LM_ERR("column %.*s (str) is empty\n", _col.len, _col.s); \
			goto error;\
		} \
	}while(0)


/* lock */
static rw_lock_t *ref_lock = NULL;

/* time interval */
static unsigned int prob_interval = 1;


struct clusterer_binds clusterer_api;

/* Database variables */

/* DB handler */
static db_con_t *db_hdl = 0;
/* DB functions */
static db_func_t dr_dbf;

/* DB URL */
str clusterer_db_url = {NULL, 0};
/* DB TABLE */
str db_table = str_init("clusterer");

/* db_table columns */

/* PK column */
str id_col = str_init("id");
str cluster_id_col = str_init("cluster_id");
str machine_id_col = str_init("machine_id");
str url_col = str_init("url");
str state_col = str_init("state");

str last_attempt_col = str_init("last_attempt");
str duration_col = str_init("duration");
str failed_attempts_col = str_init("failed_attempts");
str no_tries_col = str_init("no_tries");

str description_col = str_init("description");
static db_key_t *clusterer_machine_id_key = NULL;
static db_val_t *clusterer_machine_id_value = NULL;
static db_key_t *clusterer_cluster_id_key = NULL;
static db_val_t *clusterer_cluster_id_value = NULL;
/* EQUAL OPERATOR*/
static db_op_t op = OP_EQ;

int persistent_state = 0;

int server_id = -1;

/* shm data*/
static table_entry_t **tdata = 0;
static struct module_list *clusterer_modules = NULL;

/* initialize functions */
static int mod_init(void);
static int child_init(int rank);

/* destroy function */
static void destroy(void);

/* loads info from the db */
table_entry_t* load_info(db_func_t *dr_dbf, db_con_t* db_hdl, str *db_table);

/* deallocate memory */
void free_data(table_entry_t *data);

/* reloads data from the db */
/* if persistent mode is not set the local changes are lost */
static struct mi_root* clusterer_reload(struct mi_root* root, void *param);
static int reload_data();

/* sets a connection state */
static struct mi_root* clusterer_set_status(struct mi_root *cmd, void *param);
static int set_state(int cluster_id, int machine_id, int state, int proto);

/* lists the available connections for the specified server*/
static struct mi_root * clusterer_list(struct mi_root *root, void *param);
static void update_db_handler(unsigned int ticks, void* param);
static clusterer_node_t* get_nodes(int cluster_id,int proto);
static int clusterer_check(int cluster_id,union sockaddr_union *su, int machine_id, int proto);
static void free_nodes(clusterer_node_t *nodes);
static int su_ip_cmp(union sockaddr_union* s1, union sockaddr_union* s2);
static int get_my_id(void);
static void update_nodes_handler(unsigned int ticks, void *param);
static struct module_timestamp* create_module_timestamp(int ctime, struct module_list *module);
static table_entry_value_t *clusterer_find_nodes(int cluster_id, int proto);

static int su_ip_cmp(union sockaddr_union* s1, union sockaddr_union* s2)
{
	if (s1->s.sa_family!=s2->s.sa_family) return 0;
	switch(s1->s.sa_family){
		case AF_INET:
			return (memcmp(&s1->sin.sin_addr, &s2->sin.sin_addr, 4)==0);
		case AF_INET6:
			return (memcmp(&s1->sin6.sin6_addr, &s2->sin6.sin6_addr, 16)==0);
		default:
			LM_CRIT("unknown address family %d\n",
						s1->s.sa_family);
			return 0;
	}
}


int str_to_shm(str src, str * dest)
{
	if (src.len ==0 || src.s ==0)
		return 0;

	dest->s = (char*)shm_malloc((src.len+1) * sizeof(char));
	if (!dest->s) {
		LM_ERR("out of shm memory\n");
		return -1;
	}

	memcpy(dest->s, src.s, src.len);
	dest->s[src.len] = '\0';
	dest->len = src.len;

	return 0;
}


/*
 * Exported functions
 */
static cmd_export_t cmds[]={
	{"load_clusterer",  (cmd_function)load_clusterer, 0, 0, 0, 0},
	{0,0,0,0,0,0}
};

/*
 * Exported parameters
 */
static param_export_t params[] = {
	{"db_url",		STR_PARAM,	&clusterer_db_url.s		},
	{"db_table",		STR_PARAM,	&db_table.s		},
	{"server_id",		INT_PARAM,	&server_id		},
	{"persistent_state",	INT_PARAM,	&persistent_state	},
	{"cluster_id_col",	STR_PARAM,	&cluster_id_col.s	},
	{"machine_id_col",	STR_PARAM,	&machine_id_col.s	},
	{"clusterer_id_col",	INT_PARAM,	&id_col.s	},
	{"state_col",		STR_PARAM,	&state_col.s		},
	{"url_col",		STR_PARAM,	&url_col.s		},
	{"description_col",	STR_PARAM,	&description_col.s	},
	{"last_attempt_col",	STR_PARAM,	&last_attempt_col.s	},
	{"duration_col",	STR_PARAM,	&duration_col.s		},
	{"failed_attempts_col",	STR_PARAM,	&failed_attempts_col.s	},
	{"no_tries_col",	STR_PARAM,	&no_tries_col.s		},
	{0, 0, 0}
};	
	
/*
 * Exported MI functions
 */	
static mi_export_t mi_cmds[] = {
	{ "clusterer_reload", "reloads stored data from the database", clusterer_reload, 0, 0, 0},
	{ "clusterer_set_status", "sets the status for a specified connection", clusterer_set_status, 0, 0, 0},
	{ "clusterer_list", "lists the available connections for the specified server", clusterer_list, 0, 0, 0},
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
struct module_exports exports= {
	"clusterer",			/* module name */
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,			/* dlopen flags */
	&deps,            /* OpenSIPS module dependencies */
	cmds,							/* exported functions */
	0,							/* exported async functions */
	params,							/* exported parameters */
	0,							/* exported statistics */
	mi_cmds,							/* exported MI functions */
	0,							/* exported pseudo-variables */
	0,						/* extra processes */
	mod_init,					/* module initialization function */
	0,							/* response handling function */
	destroy,					/* destroy function */
	child_init					/* per-child init function */
};

/* initialize function */
static int mod_init(void)
{
	LM_INFO("Cluster-Info  - initializing\n");

	/* check the module params */
	init_db_url(clusterer_db_url, 0 /*cannot be null*/);

	if (server_id < 1) {
		LM_ERR("invalid machine id\n");
		return -1;
	}

	if (persistent_state > 1 && persistent_state < 0) {
		LM_WARN("invalid value for persistent state - using the default value\n");
		persistent_state = 0;
	}

	db_table.len = strlen(db_table.s);
	cluster_id_col.len = strlen(cluster_id_col.s);
	machine_id_col.len = strlen(machine_id_col.s);
	id_col.len = strlen(id_col.s);
	state_col.len = strlen(state_col.s);
	url_col.len = strlen(url_col.s);
	description_col.len = strlen(description_col.s);
	last_attempt_col.len = strlen(last_attempt_col.s);
	duration_col.len = strlen(duration_col.s);
	failed_attempts_col.len = strlen(failed_attempts_col.s);
	no_tries_col.len = strlen(no_tries_col.s);


	LM_INFO("LOCK  - initializing\n");
	/* create & init lock */
	if ((ref_lock = lock_init_rw()) == NULL) {
		LM_CRIT("failed to init lock\n");
		goto error;
	}

	LM_INFO("DATA  - initializing\n");
	/* data pointer in shm */
	tdata = (table_entry_t**) shm_malloc(sizeof(table_entry_t*));
	if (tdata == 0) {
		LM_CRIT("failed to get shm mem for data ptr\n");
		goto error;
	}
	*tdata = 0;

	LM_INFO("BINDING\n");
	/* bind to the mysql module */
	if (db_bind_mod(&clusterer_db_url, &dr_dbf)) {
		LM_CRIT("cannot bind to database module! "
			"Did you forget to load a database module ?\n");
		goto error;
	}

	LM_INFO("verifying db capabilities\n");
	if (!DB_CAPABILITY(dr_dbf, DB_CAP)) {
		LM_CRIT("database modules does not "
			"provide QUERY functions needed by DRounting module\n");
		goto error;
	}

	/*register timer*/
	if (persistent_state) {
		/* register function to flush changes in state */
		if (register_timer("update database", update_db_handler,
			NULL, prob_interval, TIMER_FLAG_DELAY_ON_DELAY) < 0) {
			LM_CRIT("unable to synchronize with the database\n");
			goto error;
		}
	}

	if (register_timer("update servers", update_nodes_handler,
		NULL, prob_interval, TIMER_FLAG_DELAY_ON_DELAY) < 0) {
		LM_CRIT("unable to update status for incoming clients\n");
		goto error;
	}


	/* everything is OK */
	return 0;
error:
	if (ref_lock) {
		lock_destroy_rw(ref_lock);
		ref_lock = 0;
	}
	if (tdata) {
		shm_free(tdata);
		tdata = 0;
	}
	return -1;

}

/* initialize child */
static int child_init(int rank)
{
	LM_DBG("initializing child %d\n", rank);

	if (rank == PROC_TCP_MAIN || rank == PROC_BIN)
		return 0;

	/* init DB connection */
	if ((db_hdl = dr_dbf.init(&clusterer_db_url)) == 0) {
		LM_CRIT("cannot initialize database connection\n");
		return -1;
	}

	/* child 1 load the routing info */
	if ((rank == 1) && reload_data() != 0) {
		LM_CRIT("failed to load routing data\n");
		return -1;
	}

	/* use db_table */
	if (dr_dbf.use_table(db_hdl, &db_table) < 0) {
		LM_ERR("cannot select table \"%.*s\"\n", db_table.len, db_table.s);
		return -1;
	}

	return 0;
}

static void update_nodes_handler(unsigned int ticks, void *param)
{
	/* data */
	table_entry_t *head_table;
	table_entry_info_t *info;
	table_entry_value_t *value;
	struct module_timestamp *head;
	uint64_t ctime;
	
	if(clusterer_modules == NULL)
		return;

	ctime = time(0);

	lock_start_write(ref_lock);
	head_table = *tdata;
	while (head_table != NULL) {
		info = head_table->info;
		while (info != NULL) {
			value = info->value;
			while (value != NULL) {
				head = value->in_timestamps;
				while (head != NULL) {
					if (head->state == 1 && (ctime - head->timestamp) > head->up->timeout) {
						head->up->cb(SERVER_TIMEOUT, NULL, value->id);
						head->timestamp = head->timestamp + head->up->timeout;
						head->state = 2;
					}
					if (head->state == 2 && (ctime - head->timestamp) > head->up->duration) {
						LM_DBG("node c_id %d m_id %d is up again\n", head_table->cluster_id, value->machine_id);
						head->state = 1;
						head->timestamp = ctime;
					}
					head = head->next;
				}
				value = value->next;
			}
			info = info->next;
		}
		head_table = head_table->next;
	}
	lock_stop_write(ref_lock);
}

/* synchronize backend with the db */
static void update_db_handler(unsigned int ticks, void* param)
{
	/* data */
	table_entry_t *head_table;
	table_entry_value_t *value;
	table_entry_info_t *info;
	/* columns to be compared ( clusterer_id_col ) */
	db_key_t key_cmp;
	/* with values */
	db_val_t val_cmp;
	/* columns to be set */
	db_key_t key_set[3];
	/* with values */
	db_val_t val_set[3];
	int i;

	CON_OR_RESET(db_hdl);

	/* table to use*/
	if (dr_dbf.use_table(db_hdl, &db_table) < 0) {
		LM_ERR("cannot select table \"%.*s\"\n", db_table.len, db_table.s);
		return;
	}

	val_cmp.type = DB_INT;
	val_cmp.nul = 0;

	for (i = 0; i < 2; ++i) {
		val_set[i].type = DB_INT;
		val_set[i].nul = 0;
	}

	val_set[2].type = DB_BIGINT;
	val_set[2].nul = 0;

	key_cmp = &id_col;

	key_set[0] = &state_col;
	key_set[1] = &no_tries_col;
	key_set[2] = &last_attempt_col;


	lock_start_write(ref_lock);

	head_table = *tdata;
	/* iterating through backend storage to find all data that
	 * must be synchronized with the db */
	while (head_table != NULL) {
		info = head_table->info;
		while (info != NULL) {
			value = info->value;
			while (value != NULL) {
				if (value->dirty_bit == 1) {
					LM_DBG("setting row with primary key %d the status %d\n",
						value->id, value->state);

					val_cmp.val.int_val = value->id;
					val_set[0].val.int_val = value->state;
					val_set[1].val.int_val = value->no_tries;
					val_set[2].val.int_val = value->last_attempt;

					/* updating */
					if (dr_dbf.update(db_hdl, &key_cmp, &op, &val_cmp, key_set, val_set, 1, 3) < 0) {
						LM_ERR("DB update failed\n");
					} else {
						/* only if the query is successful the data is synchronized */
						value->dirty_bit = 0;
					}
				}
				value = value->next;
			}
			info = info->next;
		}
		head_table = head_table->next;
	}

	lock_stop_write(ref_lock);

}

/* add a new information in the backend list*/
int add_info(table_entry_t **data, int *int_vals, unsigned long last_attempt, char **str_vals)
{
	char *host;
	int hlen, port;
	struct hostent *he;
	struct module_list *module;
	struct module_timestamp *new_timestamp;
	uint64_t ctime;
	int proto;
	int cluster_id;
	table_entry_t *head = NULL;
	table_entry_info_t *info_head = NULL;
	table_entry_value_t *value = NULL;
	str st;
	char *url;
	char *description;

	if (int_vals[INT_VALS_MACHINE_ID_COL] == server_id) {
		return 0;
	}

	url = str_vals[STR_VALS_URL_COL];

	if (url == NULL) {
		LM_ERR("no path specified\n");
		goto error;
	}

	if (parse_phostport(url, strlen(url), &host, &hlen, &port, &proto) < 0) {
		LM_ERR("Bad replication destination IP!\n");
		goto error;
	}

	if (proto == PROTO_NONE)
		proto = PROTO_UDP;

	cluster_id = int_vals[INT_VALS_CLUSTER_ID_COL];

	head = *data;
	while (head != NULL) {
		if (head->cluster_id == cluster_id) {
			info_head = head->info;
			while (info_head != NULL) {
				if (info_head->proto == proto) {
					break;
				}
				info_head = info_head->next;
			}
			if (info_head == NULL) {
				info_head = shm_malloc(sizeof(table_entry_info_t));
				if (info_head == NULL) {
					LM_ERR("no more shm memory\n");
					goto error;
				}
				info_head->proto = proto;
				info_head->next = head->info;
				info_head->value = NULL;
				head->info = info_head;
			}
			break;
		}
		head = head->next;
	}
	if (head == NULL) {
		head = shm_malloc(sizeof(table_entry_t));
		if (head == NULL) {
			LM_ERR("no more shm memory\n");
			goto error;
		}
		head->cluster_id = cluster_id;
		head->info = shm_malloc(sizeof(table_entry_info_t));
		if (head->info == NULL) {
			LM_ERR("no more shm memory\n");
			goto error;
		}
		head->info->proto = proto;
		head->info->next = NULL;
		head->info->value = NULL;
		info_head = head->info;
		info_head->proto = proto;
		head->next = *data;
		*data = head;
	}

	/* allocating memory*/
	value = shm_malloc(sizeof(table_entry_value_t));
	if (value == NULL) {
		LM_ERR("no more shm memory\n");
		goto error;
	}

	value->machine_id = int_vals[INT_VALS_MACHINE_ID_COL];
	value->id = int_vals[INT_VALS_CLUSTERER_ID_COL];
	value->state = int_vals[INT_VALS_STATE_COL];
	value->last_attempt = last_attempt;
	value->duration = int_vals[INT_VALS_DURATION_COL];
	value->failed_attempts = int_vals[INT_VALS_FAILED_ATTEMPTS_COL];
	value->no_tries = int_vals[INT_VALS_NO_TRIES_COL];
	value->dirty_bit = 0;
	value->prev_no_tries = -1;
	value->in_timestamps = NULL;
	description = str_vals[STR_VALS_DESCRIPTION_COL];

	value->path.s = shm_malloc(strlen(url) * sizeof(char));

	if (value->path.s == NULL) {
		LM_ERR("insufficient shm memory\n");
		goto error;
	}

	st.s = host;
	st.len = hlen;

	he = sip_resolvehost(&st, (unsigned short *) &port,
		(unsigned short *) &proto, 0, 0);
	if (!he) {
		LM_ERR("Cannot resolve host: %.*s\n", hlen, host);
		goto error;
	}

	hostent2su(&value->addr, he, 0, port);

	value->path.len = strlen(url);
	memcpy(value->path.s, url, value->path.len);

	if (strlen(description) != 0) {
		value->description.len = strlen(description);
		value->description.s = shm_malloc(value->description.len * sizeof(char));
		if (value->description.s == NULL) {
			LM_ERR("no more shm memory\n");
			goto error;
		}
		memcpy(value->description.s, description, value->description.len);
	} else {
		value->description.s = NULL;
		value->description.len = 0;
	}

	ctime = time(0);
	module = clusterer_modules;
	while (module != NULL) {
		if (cluster_id == module->accept_cluster_id && proto == module->proto) {
			new_timestamp = create_module_timestamp(ctime, module);
			if (new_timestamp == NULL)
				break;
			new_timestamp->next = value->in_timestamps;
			value->in_timestamps = new_timestamp;
		}
		module = module->next;
	}

	value->next = info_head->value;
	info_head->value = value;
	/* everything ok */
	return 0;
error:
	if (value) {
		if (value->description.s)
			shm_free(value->description.s);

		if (value->path.s)
			shm_free(value->path.s);
		shm_free(value);
	}
	if (info_head) {
		if (info_head->value == NULL) {
			if (head != NULL)
				head->info = head->info->next;
			shm_free(info_head);
		}
	}
	if (head) {
		if (head->info == NULL) {
			*tdata = (*tdata)->next;
			shm_free(head);
		}
	}
	return -1;
}

/* loads data from the db */
table_entry_t* load_info(db_func_t *dr_dbf, db_con_t* db_hdl, str *db_table)
{
	int int_vals[7];
	char *str_vals[2];
	int no_of_results;
	int i, n;
	int no_rows = 5;
	int db_cols = 10;
	unsigned long last_attempt;

	/* the columns from the db table */
	db_key_t columns[10];
	/* result from a db query */
	db_res_t* res;
	/* a row from the db table */
	db_row_t* row;
	/* the processed result */
	table_entry_t *data;

	res = 0;
	data = 0;

	columns[0] = &cluster_id_col;
	columns[1] = &machine_id_col;
	columns[2] = &state_col;
	columns[3] = &description_col;
	columns[4] = &url_col;
	columns[5] = &id_col;
	columns[6] = &last_attempt_col;
	columns[7] = &failed_attempts_col;
	columns[8] = &no_tries_col;
	columns[9] = &duration_col;

	CON_OR_RESET(db_hdl);

	/* allocating memory only once */
	if (!clusterer_machine_id_key) {
		clusterer_machine_id_key = pkg_malloc(sizeof(db_key_t));

		if (!clusterer_machine_id_key) {
			LM_ERR("no more pkg memory\n");
			goto error;
		}
		clusterer_machine_id_key[0] = &machine_id_col;
	}

	/* allocating memory only once */
	if (!clusterer_machine_id_value) {
		clusterer_machine_id_value = pkg_malloc(sizeof(db_val_t));
		if (!clusterer_machine_id_value) {
			LM_ERR("no more pkg memory\n");
			goto error;
		}
		VAL_TYPE(clusterer_machine_id_value) = DB_INT;
		VAL_NULL(clusterer_machine_id_value) = 0;
		VAL_INT(clusterer_machine_id_value) = server_id;

	}

	/* checking if the table version is up to date*/
	if (db_check_table_version(dr_dbf, db_hdl, db_table, 1/*version*/) != 0)
		goto error;

	/* read data */
	if (dr_dbf->use_table(db_hdl, db_table) < 0) {
		LM_ERR("cannot select table \"%.*s\"\n", db_table->len, db_table->s);
		goto error;
	}

	LM_DBG("DB query - retrieve the clusters list"
		"in which the specified server runs\n");

	/* first we see in which clusters the specified server runs*/
	if (dr_dbf->query(db_hdl, clusterer_machine_id_key, &op,
		clusterer_machine_id_value, columns, 1, 1, 0, &res) < 0) {
		LM_ERR("DB query failed - cannot retrieve the clusters list in which"
			" the specified server runs\n");
		goto error;
	}

	LM_DBG("%d rows found in %.*s\n",
		RES_ROW_N(res), db_table->len, db_table->s);

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

	no_of_results = RES_ROW_N(res);
	dr_dbf->free_result(db_hdl, res);
	res = 0;

	LM_DBG("DB query - retrieve valid connections\n");

	/* fetch is the best strategy */
	CON_USE_OR_OP(db_hdl);
	if (DB_CAPABILITY(*dr_dbf, DB_CAP_FETCH)) {

		if (dr_dbf->query(db_hdl, clusterer_cluster_id_key, 0,
			clusterer_cluster_id_value, columns, no_of_results, db_cols, 0, 0) < 0) {
			LM_ERR("DB query failed - retrieve valid connections \n");
			goto error;
		}
		no_rows = estimate_available_rows(4 + 4 + 4 + 64 + 4 + 45 + 4 + 8 + 4 + 4, db_cols);
		if (no_rows == 0) no_rows = 5;
		if (dr_dbf->fetch_result(db_hdl, &res, no_rows) < 0) {
			LM_ERR("Error fetching rows\n");
			goto error;
		}
	} else {
		if (dr_dbf->query(db_hdl, clusterer_cluster_id_key, 0,
			clusterer_cluster_id_value, columns, no_of_results, db_cols, 0, &res) < 0) {
			LM_ERR("DB query failed - retrieve valid connections\n");
			goto error;
		}
	}

	LM_DBG("%d rows found in %.*s\n",
		RES_ROW_N(res), db_table->len, db_table->s);

	n = 0;
	do {
		for (i = 0; i < RES_ROW_N(res); i++) {
			row = RES_ROWS(res) + i;
			/* CLUSTER ID column */
			check_val(cluster_id_col, ROW_VALUES(row), DB_INT, 1, 0);
			int_vals[INT_VALS_CLUSTER_ID_COL] = VAL_INT(ROW_VALUES(row));
			/* MACHINE ID column */
			check_val(machine_id_col, ROW_VALUES(row) + 1, DB_INT, 1, 0);
			int_vals[INT_VALS_MACHINE_ID_COL] = VAL_INT(ROW_VALUES(row) + 1);
			/* STATE column */
			check_val(state_col, ROW_VALUES(row) + 2, DB_INT, 1, 0);
			int_vals[INT_VALS_STATE_COL] = VAL_INT(ROW_VALUES(row) + 2);
			/* DESCRIPTION column */
			check_val(description_col, ROW_VALUES(row) + 3, DB_STRING, 0, 0);
			str_vals[STR_VALS_DESCRIPTION_COL] = (char*) VAL_STRING(ROW_VALUES(row) + 3);
			/* URL column */
			check_val(url_col, ROW_VALUES(row) + 4, DB_STRING, 1, 1);
			str_vals[STR_VALS_URL_COL] = (char*) VAL_STRING(ROW_VALUES(row) + 4);
			/* CLUSTERER_ID column */
			check_val(id_col, ROW_VALUES(row) + 5, DB_INT, 1, 0);
			int_vals[INT_VALS_CLUSTERER_ID_COL] = VAL_INT(ROW_VALUES(row) + 5);
			/* LAST_ATTEMPT column */
			check_val(last_attempt_col, ROW_VALUES(row) + 6, DB_BIGINT, 1, 0);
			last_attempt = VAL_BIGINT(ROW_VALUES(row) + 6);
			/* FAILED_ATTEMPTS column */
			check_val(failed_attempts_col, ROW_VALUES(row) + 7, DB_INT, 1, 0);
			int_vals[INT_VALS_FAILED_ATTEMPTS_COL] = VAL_INT(ROW_VALUES(row) + 7);
			/* NO_TRIES column */
			check_val(no_tries_col, ROW_VALUES(row) + 8, DB_INT, 1, 0);
			int_vals[INT_VALS_NO_TRIES_COL] = VAL_INT(ROW_VALUES(row) + 8);
			/* DURATIOH column */
			check_val(duration_col, ROW_VALUES(row) + 9, DB_INT, 1, 0);
			int_vals[INT_VALS_DURATION_COL] = VAL_INT(ROW_VALUES(row) + 9);


			/* store data */
			if (add_info(&data, int_vals, last_attempt, str_vals) < 0) {
				LM_DBG("error while adding info to shm\n");
				goto error;
			}

			LM_DBG("machine id %d\n", int_vals[0]);
			LM_DBG("cluster id %d\n", int_vals[1]);
			LM_DBG("state %d\n", int_vals[2]);
			LM_DBG("clusterer_id %d\n", int_vals[3]);
			LM_DBG("description %s\n", str_vals[0]);
			LM_DBG("url %s\n", str_vals[1]);

			n++;
		}
		if (DB_CAPABILITY(*dr_dbf, DB_CAP_FETCH)) {
			if (dr_dbf->fetch_result(db_hdl, &res, no_rows) < 0) {
				LM_ERR("fetching rows (1)\n");
				goto error;
			}
		} else {
			break;
		}
	} while (RES_ROW_N(res) > 0);

	LM_DBG("%d records found in %.*s\n",
		n, db_table->len, db_table->s);

	dr_dbf->free_result(db_hdl, res);
	res = 0;

	return data;
error:
	if (res)
		dr_dbf->free_result(db_hdl, res);
	if (data)
		free_data(data);
	data = NULL;
	return 0;
}

/* deallocates data */
void free_data(table_entry_t *data)
{
	table_entry_t *tmp_entry;
	table_entry_info_t *info;
	table_entry_info_t *tmp_info;
	table_entry_value_t *value;
	table_entry_value_t *tmp_value;

	struct module_timestamp *timestamp;
	struct module_timestamp *tmp_timestamp;

	while (data != NULL) {
		tmp_entry = data;
		data = data->next;
		info = tmp_entry->info;
		while (info != NULL) {
			value = info->value;
			while (value != NULL) {
				if (value->path.s)
					shm_free(value->path.s);
				if (value->description.s)
					shm_free(value->description.s);
				timestamp = value->in_timestamps;
				while (timestamp != NULL) {
					tmp_timestamp = timestamp;
					timestamp = timestamp->next;
					shm_free(tmp_timestamp);
				}
				tmp_value = value;
				value = value->next;
				shm_free(tmp_value);
			}
			tmp_info = info;
			info = info->next;
			shm_free(tmp_info);
		}
		shm_free(tmp_entry);
	}
}

/* reloads data from the db */
static int reload_data(void)
{
	struct module_list* modules;
	table_entry_t *new_data;
	table_entry_t *old_data;
	table_entry_t *new_head;
	table_entry_t *old_head;
	table_entry_info_t *new_info;
	table_entry_info_t *old_info;
	table_entry_value_t *new_value;
	table_entry_value_t *old_value;

	struct module_timestamp *aux;

	new_data = load_info(&dr_dbf, db_hdl, &db_table);
	if (new_data == 0) {
		LM_CRIT("failed to load routing info\n");
		return -1;
	}

	lock_start_write(ref_lock);

	/* no more active readers -> do the swapping */

	old_head = *tdata;
	while (old_head != NULL) {
		new_head = new_data;
		while (new_head != NULL) {
			if (old_head->cluster_id != new_head->cluster_id) {
				new_head = new_head->next;
				continue;
			}
			old_info = old_head->info;
			while (old_info != NULL) {
				new_info = new_head->info;
				while (new_info != NULL) {
					if (old_info->proto != new_info->proto) {
						new_info = new_info->next;
						continue;
					}
					old_value = old_info->value;
					while (old_value != NULL) {
						new_value = new_info->value;
						while (new_value != NULL) {
							if (su_cmp(&new_value->addr, &old_value->addr)) {
								aux = new_value->in_timestamps;
								new_value->in_timestamps = old_value->in_timestamps;
								old_value->in_timestamps = aux;
								break;
							}
							new_value = new_value->next;
						}
						old_value = old_value->next;
					}
					new_info = new_info->next;
				}
				old_info = old_info->next;
			}
			new_head = new_head->next;
		}
		old_head = old_head->next;
	}

	modules = clusterer_modules;

	old_data = *tdata;
	*tdata = new_data;

	while (modules != NULL) {
		modules->values = clusterer_find_nodes(modules->accept_cluster_id, modules->proto);
		modules = modules->next;
	}

	lock_stop_write(ref_lock);

	/* free old data */
	if (old_data)
		free_data(old_data);

	return 0;
}

/* destroy function */
static void destroy(void)
{
	LM_INFO("destroy function\n");

	struct module_list *tmp;
	
	/* close DB connection */
	if (db_hdl) {
		dr_dbf.close(db_hdl);
		db_hdl = 0;
	}

	/* destroy data */
	if (tdata) {
		if (*tdata)
			free_data(*tdata);
		shm_free(tdata);
		tdata = 0;
	}

	while (clusterer_modules != NULL) {
		tmp = clusterer_modules;
		clusterer_modules = clusterer_modules->next;
		shm_free(tmp);

	}
	
	/* destroy lock */
	if (ref_lock) {
		lock_destroy_rw(ref_lock);
		ref_lock = 0;
	}

	return;
}

/* reloads data from the db */
static struct mi_root* clusterer_reload(struct mi_root* root, void *param)
{
	LM_INFO("reload data MI command received!\n");

	/* first if in persistent mode we synchronize data */
	if (persistent_state)
		update_db_handler(0, NULL);

	if (reload_data() < 0) {
		LM_CRIT("failed to load routing data\n");
		return init_mi_tree(500, "Failed to reload", 16);
	}

	return init_mi_tree(200, MI_SSTR(MI_OK));
}

static void temp_disable_machine(table_entry_value_t *head)
{
	head->dirty_bit = 1;
	head->no_tries++;
	head->last_attempt = time(0);
	if (head->no_tries == head->failed_attempts) {
		head->state = 2;
	}
}

static struct module_timestamp* create_module_timestamp(int ctime, struct module_list *module)
{
	struct module_timestamp *new_node;
	new_node = shm_malloc(sizeof(struct module_timestamp));
	if (new_node == NULL) {
		LM_ERR("not enough shm memory");
		goto error;
	}
	new_node->state = 1;
	new_node->timestamp = ctime;
	new_node->up = module;
	new_node->next = NULL;
	return new_node;
error:
	return NULL;
}

static int set_in_timestamp(struct module_list *module, int machine_id)
{
	table_entry_value_t *values;
	int is_ok = 1;
	uint64_t ctime = time(0);
	struct module_timestamp *head;
	LM_DBG("setting timestamp for node with c_id %d m_id %d proto%d\n", module->accept_cluster_id,
		machine_id, module->proto);

	/* finding the machine */
	lock_start_write(ref_lock);

	values = module->values;

	/* if the protocol is not specified */
	while (values != NULL) {
		if (values->machine_id == machine_id) {
			is_ok = 0;
			head = values->in_timestamps;
			while (head != NULL) {
				if (head->up == module) {
					if (head->state == 2) {
						LM_DBG("state for node with clusterer_id %d is 2\n", values->id);
						is_ok = -1;
					} else
						head->timestamp = ctime;
					break;
				}
				head = head->next;
			}
			break;
		}
		values = values->next;
	}
	lock_stop_write(ref_lock);
	return is_ok;
}

/* setting a connection status */
static int set_state(int cluster_id, int machine_id, int state, int proto)
{
	table_entry_value_t *head_table;
	int is_ok = 1;
	LM_DBG("setting node with c_id %d m_id %d proto %d with state %d\n", cluster_id,
		machine_id, proto, state);
	/* finding the machine */
	lock_start_write(ref_lock);

	head_table = clusterer_find_nodes(cluster_id, proto);

	/* if the protocol is not specified */
	while (head_table != NULL) {
		if (head_table->machine_id == machine_id) {
			head_table->dirty_bit = 1;
			if (state == 2) {
				head_table->no_tries++;
				head_table->last_attempt = time(0);
				if (head_table->no_tries == head_table->failed_attempts) {
					head_table->state = 2;
				}
			} else {
				head_table->state = state;
			}
			is_ok = 0;
			break;
		}
		head_table = head_table->next;
	}
	lock_stop_write(ref_lock);
	return is_ok;
}

/* setting a connection status command function*/
static struct mi_root* clusterer_set_status(struct mi_root *cmd, void *param)
{
	unsigned int cluster_id;
	unsigned int machine_id;
	unsigned int state;
	int proto;
	int rc;
	struct mi_node* node;
	struct mi_node* prot_node;

	LM_INFO("set status MI command received!\n");

	if (cmd == NULL || cmd->node.kids == NULL || cmd->node.kids->value.s == NULL) {
		LM_DBG("no values specified\n");
		return init_mi_tree(400, MI_SSTR(MI_MISSING_PARM));
	}

	node = cmd->node.kids;

	if (node->next == NULL || node->next->value.s == NULL) {
		LM_DBG("only one value specified\n");
		return init_mi_tree(400, MI_SSTR(MI_MISSING_PARM));
	}

	if (node->next->next == NULL || node->next->next->value.s == NULL) {
		LM_DBG("no state specified\n");
		return init_mi_tree(400, MI_SSTR(MI_MISSING_PARM));
	}

	rc = str2int(&node->value, &cluster_id);

	if (rc == -1 || cluster_id == 0) {
		LM_DBG("the cluster_id parameter is not a valid digit\n");
		return init_mi_tree(400, MI_SSTR(MI_BAD_PARM));
	}

	rc = str2int(&node->next->value, &machine_id);
	if (rc == -1 || machine_id == 0) {
		LM_DBG("the machine_id parameter is not a valid digit\n");
		return init_mi_tree(400, MI_SSTR(MI_BAD_PARM));
	}

	rc = str2int(&node->next->next->value, &state);
	if (rc == -1 || state < 0 || state > 1) {
		LM_DBG("the state parameter is not valid\n");
		return init_mi_tree(400, MI_SSTR(MI_BAD_PARM));
	}

	prot_node = node->next->next->next;
	if (prot_node == NULL || prot_node->value.s == NULL) {
		LM_DBG("the protocol parameter is missing\n");
		return init_mi_tree(400, MI_SSTR(MI_BAD_PARM));
	}

	if (parse_proto((unsigned char*) prot_node->value.s, prot_node->value.len, &proto) < 0) {
		LM_DBG("the protocol parameter is not valid\n");
		return init_mi_tree(400, MI_SSTR(MI_BAD_PARM));
	}

	rc = set_state(cluster_id, machine_id, state, proto);

	if (rc == -1) {
		LM_DBG("cluster id or machine id are not smaller than 1\n");
		return init_mi_tree(400, MI_SSTR(MI_BAD_PARM));
	}

	if (rc == 1) {
		LM_DBG("there is no machine id %d in the cluster %d\n", machine_id, cluster_id);
	}

	return init_mi_tree(200, MI_SSTR(MI_OK));
}

/* lists all valid connections */
static struct mi_root * clusterer_list(struct mi_root *cmd_tree, void *param)
{
	table_entry_t *head_table;
	table_entry_info_t *info;
	table_entry_value_t *value;
	struct mi_node *root = NULL;
	struct mi_root *rpl_tree = NULL;
	struct mi_node *node = NULL;
	struct mi_attr* attr;
	str cluster_id;
	str clusterer_id;
	str machine_id;
	str state;
	str no_tries;
	str duration;
	str last_attempt;
	str failed_attempts;

	rpl_tree = init_mi_tree(200, MI_OK_S, MI_OK_LEN);
	if (rpl_tree == NULL)
		return NULL;

	lock_start_read(ref_lock);

	head_table = *tdata;
	root = &rpl_tree->node;
	for (head_table = *tdata; head_table != NULL; head_table = head_table->next) {
		for (info = head_table->info; info != NULL; info = info->next) {
			for (value = info->value; value != NULL; value = value->next) {
				clusterer_id.s = int2str(value->id, &clusterer_id.len);
				node = add_mi_node_child(root, MI_DUP_VALUE, "Clusterer ID", 12,
					clusterer_id.s, clusterer_id.len);
				if (node == NULL) goto error;

				cluster_id.s = int2str(head_table->cluster_id, &cluster_id.len);
				attr = add_mi_attr(node, MI_DUP_VALUE, "Cluster ID", 10,
					cluster_id.s, cluster_id.len);
				if (attr == NULL) goto error;

				machine_id.s = int2str(value->machine_id, &machine_id.len);
				attr = add_mi_attr(node, MI_DUP_VALUE, "Machine ID", 10,
					machine_id.s, machine_id.len);
				if (attr == NULL) goto error;

				state.s = int2str(value->state, &state.len);
				attr = add_mi_attr(node, MI_DUP_VALUE, "STATE", 5,
					state.s, state.len);
				if (attr == NULL) goto error;

				last_attempt.s = int2str(value->last_attempt, &last_attempt.len);
				attr = add_mi_attr(node, MI_DUP_VALUE, "LAST_FAILED_ATTEMPT", 19,
					last_attempt.s, last_attempt.len);
				if (attr == NULL) goto error;

				failed_attempts.s = int2str(value->failed_attempts, &failed_attempts.len);
				attr = add_mi_attr(node, MI_DUP_VALUE, "MAX_FAILED_ATTEMPTS", 19,
					failed_attempts.s, failed_attempts.len);
				if (attr == NULL) goto error;

				no_tries.s = int2str(value->no_tries, &no_tries.len);
				attr = add_mi_attr(node, MI_DUP_VALUE, "NO_TRIES", 8,
					no_tries.s, no_tries.len);
				if (attr == NULL) goto error;

				duration.s = int2str(value->duration, &duration.len);
				attr = add_mi_attr(node, MI_DUP_VALUE, "SECONDS_UNTIL_ENABLING", 22,
					duration.s, duration.len);
				if (attr == NULL) goto error;

				attr = add_mi_attr(node, MI_DUP_VALUE, "PATH", 4,
					value->path.s, value->path.len);
				if (attr == NULL) goto error;

				if (value->description.s)
					attr = add_mi_attr(node, MI_DUP_VALUE, "DESCRIPTION", 11,
					value->description.s, value->description.len);
				else
					attr = add_mi_attr(node, MI_DUP_VALUE, "DESCRIPTION", 11,
					"none", 4);
				if (attr == NULL) goto error;
			}
		}

	}

	lock_stop_read(ref_lock);

	return rpl_tree;
error:
	lock_stop_read(ref_lock);
	if (rpl_tree) free_mi_tree(rpl_tree);
	return NULL;
}

static void free_node(clusterer_node_t *node)
{
	if (node) {
		if (node->description.s)
			pkg_free(node->description.s);
		pkg_free(node);
	}

}

static int add_node(clusterer_node_t **nodes, table_entry_value_t *head, int proto)
{
	clusterer_node_t *new_node = NULL;
	struct ip_addr ip;
	new_node = pkg_malloc(sizeof(clusterer_node_t));
	if (new_node == NULL) {
		LM_ERR("no more pkg memory\n");
		goto error;
	}

	new_node->next = NULL;
	new_node->description.s = NULL;
	new_node->machine_id = head->machine_id;
	new_node->state = head->state;
	new_node->proto = proto;

	memcpy(&new_node->addr, &head->addr, sizeof(head->addr));
	new_node->description.s = pkg_malloc(head->description.len * sizeof(char));
	if (new_node->description.s == NULL) {
		LM_ERR("no more pkg memory\n");
		goto error;
	}

	memcpy(new_node->description.s, head->description.s, head->description.len);

	su2ip_addr(&ip, &new_node->addr);
	new_node->description.len = head->description.len;
	if (*nodes)
		new_node->next = *nodes;

	*nodes = new_node;
	return 0;
error:
	free_node(new_node);
	return -1;
}

static void free_nodes(clusterer_node_t *nodes)
{
	clusterer_node_t* tmp;
	LM_DBG("freeing all the nodes\n");
	while (nodes != NULL) {
		tmp = nodes;
		nodes = nodes->next;
		free_node(tmp);
	}
}

static clusterer_node_t* get_nodes(int cluster_id, int proto)
{
	clusterer_node_t* tmp;
	clusterer_node_t* nodes = NULL;
	table_entry_value_t* head;
	unsigned long ctime = time(0);

	lock_start_read(ref_lock);

	head = clusterer_find_nodes(cluster_id, proto);
	while (head != NULL) {
		if (head->state == 1) {
			if (head->prev_no_tries != -1 &&
				head->no_tries > 0 &&
				head->prev_no_tries == head->no_tries) {
				head->no_tries = 0;
			}
			head->prev_no_tries = head->no_tries;
		}

		if (head->state == 2) {
			if ((ctime - head->last_attempt) >= head->duration) {
				head->last_attempt = ctime;
				head->state = 1;
				head->no_tries = 0;
			}
		}
		if (head->state == 1 && add_node(&nodes, head, proto) < 0) {
			goto error;
		}

		head = head->next;
	}

	lock_stop_read(ref_lock);

	return nodes;
error:
	lock_stop_read(ref_lock);
	while (nodes != NULL) {
		tmp = nodes;
		nodes = nodes->next;
		free_node(tmp);
	}
	return NULL;
}

int clusterer_check(int cluster_id, union sockaddr_union* su, int machine_id, int proto)
{
	int rc = 0;
	table_entry_value_t *head;

	LM_INFO("checking connection\n");

	lock_start_read(ref_lock);

	head = clusterer_find_nodes(cluster_id, proto);
	while (head != NULL) {
		if (su_ip_cmp(su, &head->addr) && head->machine_id == machine_id) {
			rc = 1;
			break;
		}
		head = head->next;
	}

	lock_stop_read(ref_lock);

	return rc;
}

static int get_my_id(void)
{
	return server_id;
}

static table_entry_value_t *clusterer_find_nodes(int cluster_id, int proto)
{
	table_entry_t* head;
	table_entry_info_t *info = NULL;
	table_entry_value_t *value;

	value = NULL;
	head = *tdata;

	while (head != NULL) {
		if (head->cluster_id != cluster_id) {
			head = head->next;
			continue;
		}
		info = head->info;
		while (info != NULL) {
			if (info->proto != proto) {
				info = info->next;
				continue;
			}
			value = info->value;
			break;
		}
		break;
	}
	return value;
}

static int send_to(int cluster_id, int proto)
{
	table_entry_value_t *value;
	str send_buffer;
	unsigned long ctime = time(0);
	int ok = -1;
	LM_INFO("get nodes \n");

	if (proto == PROTO_BIN) {
		bin_get_buffer(&send_buffer);
	}
	lock_start_read(ref_lock);

	value = clusterer_find_nodes(cluster_id, proto);
	while (value != NULL) {
		ok = 0;
		if (value->state == 1) {
			if (value->prev_no_tries != -1 &&
				value->no_tries > 0 &&
				value->prev_no_tries == value->no_tries) {
				value->no_tries = 0;
			}
			value->prev_no_tries = value->no_tries;
		}

		if (value->state == 2) {
			if ((ctime - value->last_attempt) >= value->duration) {
				value->last_attempt = ctime;
				value->state = 1;
				value->no_tries = 0;
			}
		}
		if (value->state == 1) {
			if (proto == PROTO_BIN) {
				if (msg_send(NULL, PROTO_BIN, &value->addr, 0, send_buffer.s, send_buffer.len, 0) != 0) {
					LM_ERR("cannot send message\n");
					temp_disable_machine(value);
				}
			}

		}
		value = value->next;
	}

	lock_stop_read(ref_lock);

	return ok;
}

static void bin_receive_packets(int packet_type, struct receive_info *ri, void *ptr)
{
	struct module_list *module;
	unsigned short port;
	int machine_id;
	char *ip;
	int rc;

	rc = bin_pop_int(&machine_id);
	if (rc < 0)
		return;

	get_su_info(&ri->src_su.s, ip, port);
	LM_WARN("received bin packet from source: %s:%hu\n",
		ip, port);

	module = (struct module_list *) ptr;

	if (module->auth_check) {
		if (!clusterer_check(module->accept_cluster_id, &ri->src_su, machine_id, ri->proto)) {
			get_su_info(&ri->src_su.s, ip, port);
			LM_WARN("received bin packet from unknown source: %s:%hu\n",
				ip, port);
			return;
		}
	}

	rc = set_in_timestamp(module, machine_id);

	if (rc < 0) {
		module->cb(SERVER_TEMP_DISABLED, ri, machine_id);
		return;
	}

	module->cb(packet_type, ri, machine_id);
}

static int cl_register_module(char *mod_name, int proto, void (*cb)(int, struct receive_info *, int),
	int timeout, int auth_check, int accept_cluster_id)
{

	LM_DBG("register module %s\n", mod_name);
	struct module_list *new_module;

	if (auth_check && !accept_cluster_id) {
		LM_ERR("provided bad cluster_id\n");
		return -1;
	}

	new_module = shm_malloc(sizeof(struct module_list));
	if (new_module == NULL) {
		LM_ERR("insufficient shm memory\n");
		return -1;
	}
	new_module->mod_name.len = strlen(mod_name);
	new_module->mod_name.s = mod_name;
	new_module->proto = proto;
	new_module->cb = cb;
	new_module->timeout = timeout;
	new_module->auth_check = auth_check;
	new_module->accept_cluster_id = accept_cluster_id;
	new_module->duration = 2 * timeout;
	new_module->next = NULL;

	switch (proto) {
	case PROTO_BIN:
		bin_register_cb(mod_name, bin_receive_packets, new_module);
		break;
	default:
		LM_ERR("unidentified protocol\n");
		shm_free(new_module);
		return -1;
	}

	new_module->values = NULL;
	new_module->next = clusterer_modules;
	clusterer_modules = new_module;

	return 0;
}

int load_clusterer(struct clusterer_binds *binds)
{
	binds->get_nodes = get_nodes;
	binds->set_state = set_state;
	binds->free_nodes = free_nodes;
	binds->check = clusterer_check;
	binds->get_my_id = get_my_id;
	binds->send_to = send_to;
	binds->register_module = cl_register_module;
	/* everything ok*/
	return 1;
}
