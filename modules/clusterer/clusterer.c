#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>

#include "../../sr_module.h"
#include "../../str.h"
#include "../../dprint.h"
#include "../../usr_avp.h"
#include "../../db/db.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../rw_locking.h"
/* for errors like bad ip */
#include "../../error.h"
/* int2str */
#include "../../ut.h"
#include "../../mi/mi.h"
#include "../../timer.h"
#include "clusterer.h"

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
static unsigned int prob_interval = 30;

/* Database variables */

/* DB handler */
static db_con_t *db_hdl = 0;
/* DB functions */
static db_func_t dr_dbf;

/* DB URL */
str db_url = str_init("mysql://root:admin@localhost/opensips"); //{NULL, 0};
/* DB TABLE */
str db_table = str_init("clusterer");

/* db_table columns */

/* PK column */
str clusterer_id_col = str_init("clusterer_id");
str cluster_id_col = str_init("cluster_id");
str machine_id_col = str_init("machine_id");
str url_col = str_init("url");
str state_col = str_init("state");

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
static int set_state(int cluster_id, int machine_id, int state, str *proto);

/* lists the available connections for the specified server*/
static struct mi_root * clusterer_list(struct mi_root *root, void *param);
static void update_db_handler(unsigned int ticks, void* param);


/*
 * Exported parameters
 */
static param_export_t params[] = {
	{"db_url",		STR_PARAM,	&db_url.s		},
	{"db_table",		STR_PARAM,	&db_table.s		},
	{"server_id",		INT_PARAM,	&server_id		},
	{"persistent_state",	INT_PARAM,	&persistent_state	},
	{"cluster_id_col",	STR_PARAM,	&cluster_id_col.s	},
	{"machine_id_col",	STR_PARAM,	&machine_id_col.s	},
	{"clusterer_id_col",	INT_PARAM,	&clusterer_id_col.s	},
	{"state_col",		STR_PARAM,	&state_col.s		},
	{"url_col",		STR_PARAM,	&url_col.s		},
	{"description_col",	STR_PARAM,	&description_col.s	},
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

/**
 * module exports
 */
struct module_exports exports= {
	"clusterer",			/* module name */
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,			/* dlopen flags */
	NULL,            /* OpenSIPS module dependencies */
	0,							/* exported functions */
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
	init_db_url(db_url, 0 /*cannot be null*/);

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
	clusterer_id_col.len = strlen(clusterer_id_col.s);
	state_col.len = strlen(state_col.s);
	url_col.len = strlen(url_col.s);
	description_col.len = strlen(description_col.s);

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
	if (db_bind_mod(&db_url, &dr_dbf)) {
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
	/* everything is OK */
	return 0;
error:
	if (ref_lock) {
		lock_destroy_rw(ref_lock);
		ref_lock = 0;
	}
	if (db_hdl) {
		dr_dbf.close(db_hdl);
		db_hdl = 0;
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
	LM_DBG("initializing child %d", rank);

	if (rank == PROC_TCP_MAIN || rank == PROC_BIN)
		return 0;

	/* init DB connection */
	if ((db_hdl = dr_dbf.init(&db_url)) == 0) {
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

/* synchronize backend with the db */
static void update_db_handler(unsigned int ticks, void* param)
{
	/* data */
	table_entry_t *head_table;
	/* columns to be compared ( clusterer_id_col ) */
	db_key_t key_cmp;
	/* with values */
	db_val_t val_cmp;
	/* columns to be set ( state_col )*/
	db_key_t key_set;
	/* with values */
	db_val_t val_set;

	CON_OR_RESET(db_hdl);

	/* table to use*/
	if (dr_dbf.use_table(db_hdl, &db_table) < 0) {
		LM_ERR("cannot select table \"%.*s\"\n", db_table.len, db_table.s);
		return;
	}

	val_cmp.type = DB_INT;
	val_cmp.nul = 0;

	val_set.type = DB_INT;
	val_set.nul = 0;

	key_cmp = &clusterer_id_col;
	key_set = &state_col;

	lock_start_write(ref_lock);

	head_table = *tdata;
	/* iterating through backend storage to find all data that
	 * must be synchronized with the db */
	while (head_table != NULL) {
		if (head_table->dirty_bit == 1) {
			LM_DBG("setting row with primary key %d the status %d\n",
				head_table->clusterer_id, head_table->state);

			val_cmp.val.int_val = head_table->clusterer_id;
			val_set.val.int_val = head_table->state;

			/* updating */
			if (dr_dbf.update(db_hdl, &key_cmp, &op, &val_cmp, &key_set, &val_set, 1, 1) < 0) {
				LM_ERR("DB update failed\n");
			}

			/* only if the query is successful the data is synchronized */
			head_table->dirty_bit = 0;
		}
		head_table = head_table->next;
	}

	lock_stop_write(ref_lock);

}

/* add a new information in the backend list*/
int add_info(table_entry_t **data, int clusterer_id, int cluster_id, int machine_id, int state,
	char *description, char* url)
{
	/* path */
	char *path;
	/* protocol length */
	int prot_len;

	/* allocating memory*/
	table_entry_t *new_entry = shm_malloc(sizeof(table_entry_t));
	if (new_entry == NULL) {
		LM_ERR("error allocating local storage structure\n");
		goto error;
	}

	new_entry->cluster_id = cluster_id;
	new_entry->machine_id = machine_id;
	new_entry->clusterer_id = clusterer_id;
	new_entry->state = state;
	new_entry->dirty_bit = 0;

	path = memchr(url, ':', strlen(url));

	if (path == NULL || strlen(path + 1) == 0) {
		LM_ERR("no path specified\n");
		goto error;
	}

	prot_len = path - url;

	if (prot_len == 0) {
		LM_ERR("no protocol specified\n");
		goto error;
	}

	/* allocate memory fot the protocol*/
	new_entry->proto.s = shm_malloc(prot_len * sizeof(char*));

	if (new_entry->proto.s == NULL) {
		LM_ERR("insufficient shm memory\n");
		goto error;
	}

	new_entry->proto.len = prot_len;
	memcpy(new_entry->proto.s, url, prot_len);

	/* exclude delimiter from path */
	path++;

	new_entry->path.len = strlen(path);
	new_entry->path.s = shm_malloc(new_entry->path.len * sizeof(char*));

	if (new_entry->path.s == NULL) {
		LM_ERR("insufficient shm memory\n");
		goto error;
	}

	memcpy(new_entry->path.s, path, new_entry->path.len);

	if (description) {
		new_entry->description.len = strlen(description);
		new_entry->description.s = shm_malloc(new_entry->description.len * sizeof(char*));
		memcpy(new_entry->description.s, description, new_entry->description.len);
	} else {
		new_entry->description.s = NULL;
		new_entry->description.len = 0;
	}

	if (*data)
		new_entry->next = *data;
	else
		new_entry->next = NULL;
	*data = new_entry;

	/* everything ok */
	return 0;
error:
	if (new_entry) {
		if (new_entry->proto.s)
			shm_free(new_entry->proto.s);
		shm_free(new_entry);
	}
	return -1;
}

/* loads data from the db */
table_entry_t* load_info(db_func_t *dr_dbf, db_con_t* db_hdl, str *db_table)
{
	int int_vals[4];
	char *str_vals[2];
	int no_of_results;
	int i, n;
	int no_rows = 5;
	int db_cols = 6;

	/* the columns from the db table */
	db_key_t columns[6];
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
	columns[5] = &clusterer_id_col;

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
		no_rows = estimate_available_rows(4 + 4 + 4 + 64 + 45 + 4, db_cols);
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
			check_val(clusterer_id_col, ROW_VALUES(row) + 5, DB_INT, 1, 0);
			int_vals[INT_VALS_CLUSTERER_ID_COL] = VAL_INT(ROW_VALUES(row) + 5);

			/* store data */
			if (add_info(&data, int_vals[INT_VALS_CLUSTERER_ID_COL],
				int_vals[INT_VALS_CLUSTER_ID_COL],
				int_vals[INT_VALS_MACHINE_ID_COL],
				int_vals[INT_VALS_STATE_COL],
				str_vals[STR_VALS_DESCRIPTION_COL],
				str_vals[STR_VALS_URL_COL]) < 0) {
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
	table_entry_t *tmp;

	while (data != NULL) {
		tmp = data;
		data = data->next;
		if (tmp->path.s)
			shm_free(tmp->path.s);
		if (tmp->proto.s)
			shm_free(tmp->proto.s);
		if (tmp->description.s)
			shm_free(tmp->description.s);

	}
}

/* reloads data from the db */
static int reload_data(void)
{
	table_entry_t *new_data;
	table_entry_t *old_data;

	new_data = load_info(&dr_dbf, db_hdl, &db_table);
	if (new_data == 0) {
		LM_CRIT("failed to load routing info\n");
		return -1;
	}

	lock_start_write(ref_lock);

	/* no more active readers -> do the swapping */
	old_data = *tdata;
	*tdata = new_data;

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

	/* close DB connection */
	if (db_hdl) {
		dr_dbf.close(db_hdl);
		db_hdl = 0;
	}

	/* destroy data */
	if (tdata) {
		if (*tdata)
			free_data(*tdata);
		free(tdata);
		tdata = 0;
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

/* setting a connection status */
static int set_state(int cluster_id, int machine_id, int state, str *proto)
{
	table_entry_t *head_table;
	int is_ok = 1;

	/* finding the machine */
	lock_start_write(ref_lock);

	head_table = *tdata;

	/* if the protocol is not specified */
	if (proto == NULL) {
		while (head_table != NULL) {
			if (head_table->cluster_id == cluster_id
				&& head_table->machine_id == machine_id) {
				head_table->state = state;
				head_table->dirty_bit = 1;
				is_ok = 0;
			}
			head_table = head_table->next;
		}
	} else {
		while (head_table != NULL) {
			if (head_table->cluster_id == cluster_id
				&& head_table->machine_id == machine_id
				&& proto->len == head_table->proto.len
				&& memcmp(proto->s, head_table->proto.s, proto->len) == 0) {
				head_table->state = state;
				head_table->dirty_bit = 1;
				is_ok = 0;
				break;
			}
			head_table = head_table->next;
		}
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
	int rc;
	struct mi_node* node;
	struct mi_node* state_node;

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

	state_node = node->next->next->next;
	if (state_node && state_node->value.len != 0)
		rc = set_state(cluster_id, machine_id, state, &state_node->value);
	else
		rc = set_state(cluster_id, machine_id, state, NULL);

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
	struct mi_node *root = NULL;
	struct mi_root *rpl_tree = NULL;
	struct mi_node *node = NULL;
	struct mi_attr* attr;
	str cluster_id;
	str machine_id;
	str state;

	rpl_tree = init_mi_tree(200, MI_OK_S, MI_OK_LEN);
	if (rpl_tree == NULL)
		return NULL;

	lock_start_read(ref_lock);

	head_table = *tdata;
	root = &rpl_tree->node;
	while (head_table != NULL) {

		cluster_id.s = int2str(head_table->cluster_id, &cluster_id.len);
		node = add_mi_node_child(root, MI_DUP_VALUE, "Cluster ID", 10,
			cluster_id.s, cluster_id.len);
		if (node == NULL) goto error;

		machine_id.s = int2str(head_table->machine_id, &machine_id.len);
		attr = add_mi_attr(node, MI_DUP_VALUE, "Machine ID", 10,
			machine_id.s, machine_id.len);
		if (attr == NULL) goto error;

		state.s = int2str(head_table->state, &state.len);
		attr = add_mi_attr(node, MI_DUP_VALUE, "STATE", 5,
			state.s, state.len);
		if (attr == NULL) goto error;

		attr = add_mi_attr(node, MI_DUP_VALUE, "DESCRIPTION", 11,
			head_table->description.s, head_table->description.len);
		if (attr == NULL) goto error;

		attr = add_mi_attr(node, MI_DUP_VALUE, "PROTOCOL", 8,
			head_table->proto.s, head_table->proto.len);
		if (attr == NULL) goto error;

		attr = add_mi_attr(node, MI_DUP_VALUE, "PATH", 4,
			head_table->path.s, head_table->path.len);
		if (attr == NULL) goto error;

		head_table = head_table->next;

	}

	lock_stop_read(ref_lock);

	return rpl_tree;
error:
	lock_stop_read(ref_lock);
	if (rpl_tree) free_mi_tree(rpl_tree);
	return NULL;
}