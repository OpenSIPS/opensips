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
#include "clusterer.h"

#define DB_CAP ( DB_CAP_ALL | DB_CAP_FETCH | DB_CAP_RAW_QUERY )

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

static int mod_init(void);
static void destroy(void);
static int child_init(int rank);
table_entry_t* load_info(db_func_t *dr_dbf, db_con_t* db_hdl, str *db_table);
table_entry_t* build_data(void);
void free_data(table_entry_t *data);
static struct mi_root* mi_reload(struct mi_root* root, void *param);
static struct mi_root* mi_set_status(struct mi_root *cmd, void *param);
static struct mi_root * mi_list_clusterer(struct mi_root *root, void *param);
static int reload_data();
static int set_state(int cluster_id, int machine_id, int state);
/* lock */
static rw_lock_t *ref_lock = NULL;

/* Database variables */
static db_con_t *db_hdl = 0; /* DB handler */
static db_func_t dr_dbf; /* DB functions */

str db_url = str_init("mysql://root:admin@localhost/opensips"); //{NULL, 0};
str db_table = str_init("clusterer");
str cluster_id_col = str_init("cluster_id");
str machine_id_col = str_init("machine_id");
str url_col = str_init("url");
str state_col = str_init("state");
str description_col = str_init("description");
int server_id = -1;
static table_entry_t **tdata = 0;

/*
 * Exported parameters
 */
static param_export_t params[] = {
	{"db_url",		STR_PARAM, &db_url.s		},
	{"db_table",		STR_PARAM, &db_table.s		},
	{"server_id",		INT_PARAM, &server_id		},
	{"cluster_id_col",	STR_PARAM, &cluster_id_col.s	},
	{"machine_id_col",	STR_PARAM, &machine_id_col.s	},
	{"state_col",		STR_PARAM, &state_col.s		},
	{"url_col",		STR_PARAM, &url_col.s		},
	{"description_col",	STR_PARAM, &description_col.s	},
	{0, 0, 0}
};	
	
/*
 * Exported MI functions
 */	
static mi_export_t mi_cmds[] = {
	{ "mi_reload", "reloades stored data from the database", mi_reload, 0, 0, 0},
	{ "mi_set_status", "sets the status for a specified connexion", mi_set_status, 0, 0, 0},
	{ "mi_list_clusterer", "sets the status for a specified connexion", mi_list_clusterer, 0, 0, 0},
	{0, 0, 0, 0, 0, 0}
};

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

	db_table.len = strlen(db_table.s);
	cluster_id_col.len = strlen(cluster_id_col.s);
	machine_id_col.len = strlen(machine_id_col.s);
	state_col.len = strlen(state_col.s);
	url_col.len = strlen(url_col.s);
	description_col.len = strlen(description_col.s);

	/* create & init lock */
	if ((ref_lock = lock_init_rw()) == NULL) {
		LM_CRIT("failed to init lock\n");
		goto error;
	}
	LM_INFO("LOCK  - initializing\n");
	/* data pointer in shm */
	tdata = (table_entry_t**) shm_malloc(sizeof(table_entry_t*));
	if (tdata == 0) {
		LM_CRIT("failed to get shm mem for data ptr\n");
		goto error;
	}
	*tdata = 0;
	LM_INFO("DATA  - initializing\n");
	/* bind to the mysql module */
	if (db_bind_mod(&db_url, &dr_dbf)) {
		LM_CRIT("cannot bind to database module! "
			"Did you forget to load a database module ?\n");
		goto error;
	}
	LM_INFO("BINDING - initializing\n");
	// DB_CAP_QUERY
	if (!DB_CAPABILITY(dr_dbf, DB_CAP)) {
		LM_CRIT("database modules does not "
			"provide QUERY functions needed by DRounting module\n");
		goto error;
	}
	LM_INFO("CAPABILITIES - initializing\n");

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

static int child_init(int rank)
{

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

	/* set CLUSTERER table */
	if (dr_dbf.use_table(db_hdl, &db_table) < 0) {
		LM_ERR("cannot select table \"%.*s\"\n", db_table.len, db_table.s);
		return -1;
	}

	return 0;
}

table_entry_t* build_data(void)
{
	table_entry_t *data = NULL;

	if (NULL == (data = shm_malloc(sizeof(table_entry_t)))) {
		LM_ERR("no more shm mem\n");
		goto err_exit;
	}
	memset(data, 0, sizeof(table_entry_t));

	return data;
err_exit:
	if (data)
		shm_free(data);
	return 0;
}

int add_info(table_entry_t **data, int cluster_id, int machine_id, int state,
	char *description, char* url)
{

	char *path;
	int prot_len;
	table_entry_t *new_entry = shm_malloc(sizeof(table_entry_t));
	if (new_entry == NULL) {
		LM_ERR("error allocating local storage structure\n");
		goto error;
	}

	new_entry->cluster_id = cluster_id;

	new_entry->machine_id = machine_id;
	new_entry->state = state;
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


	return 0;
error:
	if (new_entry) {
		if (new_entry->proto.s)
			shm_free(new_entry->proto.s);
		shm_free(new_entry);
	}
	return -1;
}

table_entry_t* load_info(db_func_t *dr_dbf, db_con_t* db_hdl, str *db_table)
{
	int int_vals[3];
	char *str_vals[2];

	/* the columns from the db table */
	db_key_t columns[5];
	/* result from a db query */
	db_res_t* res;
	/* a row from the db table */
	db_row_t* row;
	/* the processed result */
	table_entry_t *data;

	int i, n;
	int no_rows = 5;
	int db_cols = 5;

	res = 0;
	data = 0;

	/* checking if the table version is up to date*/
	if (db_check_table_version(dr_dbf, db_hdl, db_table, 1/*version*/) != 0)
		goto error;

	/* read data */
	if (dr_dbf->use_table(db_hdl, db_table) < 0) {
		LM_ERR("cannot select table \"%.*s\"\n", db_table->len, db_table->s);
		goto error;
	}

	columns[0] = &cluster_id_col;
	columns[1] = &machine_id_col;
	columns[2] = &state_col;
	columns[3] = &description_col;
	columns[4] = &url_col;

	/* fetch is the best strategy */
	if (DB_CAPABILITY(*dr_dbf, DB_CAP_FETCH)) {
		if (dr_dbf->query(db_hdl, 0, 0, 0, columns, 0, db_cols, 0, 0) < 0) {
			LM_ERR("DB query failed\n");
			goto error;
		}
		no_rows = estimate_available_rows(4 + 4 + 4 + 64 + 45, db_cols);
		if (no_rows == 0) no_rows = 5;
		if (dr_dbf->fetch_result(db_hdl, &res, no_rows) < 0) {
			LM_ERR("Error fetching rows\n");
			goto error;
		}
	} else {
		if (dr_dbf->query(db_hdl, 0, 0, 0, columns, 0, db_cols, 0, &res) < 0) {
			LM_ERR("DB query failed\n");
			goto error;
		}
	}

	LM_DBG("%d records found in %.*s\n",
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

			/* store data */

			if (add_info(&data, int_vals[INT_VALS_CLUSTER_ID_COL],
				int_vals[INT_VALS_MACHINE_ID_COL],
				int_vals[INT_VALS_STATE_COL],
				str_vals[STR_VALS_DESCRIPTION_COL],
				str_vals[STR_VALS_URL_COL]) < 0) {
				LM_DBG("error while adding info to shm\n");
				goto error;
			}

			LM_DBG("new_entry %d \n", data->cluster_id);
			LM_DBG("machine id %d\n", int_vals[0]);
			LM_DBG("cluster id %d\n", int_vals[1]);
			LM_DBG("state %d\n", int_vals[2]);
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

	dr_dbf->free_result(db_hdl, res);
	res = 0;

	LM_DBG("%d total records loaded from table %.*s\n", n,
		db_table->len, db_table->s);

	return data;
error:
	if (res)
		dr_dbf->free_result(db_hdl, res);
	if (data)
		free_data(data);
	data = NULL;
	return 0;
}

/* deallocate used data */
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

	/* no more activ readers -> do the swapping */
	old_data = *tdata;
	*tdata = new_data;

	lock_stop_write(ref_lock);

	/* free old data */
	if (old_data)
		free_data(old_data);

	return 0;
}

static void destroy(void)
{
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

static struct mi_root* mi_reload(struct mi_root* root, void *param)
{
	LM_INFO("reload data MI command received!\n");

	if (reload_data() < 0) {
		LM_CRIT("failed to load routing data\n");
		return init_mi_tree(500, "Failed to reload", 16);
	}
	return init_mi_tree(200, MI_SSTR(MI_OK));
}

static int set_state(int cluster_id, int machine_id, int state)
{
	table_entry_t *head_table;
	int is_ok = 1;

	/* finding the machine */
	lock_start_write(ref_lock);

	head_table = *tdata;
	while (head_table != NULL) {
		if (head_table->cluster_id == cluster_id
			&& head_table->machine_id == machine_id) {
			head_table->state = 0;
			is_ok = 0;
		}
		head_table = head_table->next;
	}

	lock_stop_write(ref_lock);
	return is_ok;
}

static struct mi_root* mi_set_status(struct mi_root *cmd, void *param)
{
	unsigned int cluster_id;
	unsigned int machine_id;
	unsigned int state;
	int rc;
	struct mi_node* node;

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

	rc = set_state(cluster_id, machine_id, state);

	if (rc == -1) {
		LM_DBG("cluster id or machine id are not smaller than 1\n");
		return init_mi_tree(400, MI_SSTR(MI_BAD_PARM));
	}

	if (rc == 1) {
		LM_DBG("there is no machine id %d in the cluster %d\n", machine_id, cluster_id);
	}

	return init_mi_tree(200, MI_SSTR(MI_OK));
}

static struct mi_root * mi_list_clusterer(struct mi_root *cmd_tree, void *param)
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
	//rpl_tree->node.flags |= MI_IS_ARRAY;

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