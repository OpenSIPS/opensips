 /*
￼ * Trie Module
￼ *
￼ * Copyright (C) 2024 OpenSIPS Project
￼ *
￼ * opensips is free software; you can redistribute it and/or modify
￼ * it under the terms of the GNU General Public License as published by
￼ * the Free Software Foundation; either version 2 of the License, or
￼ * (at your option) any later version.
￼ *
￼ * opensips is distributed in the hope that it will be useful,
￼ * but WITHOUT ANY WARRANTY; without even the implied warranty of
￼ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
￼ * GNU General Public License for more details.
￼ *
￼ * You should have received a copy of the GNU General Public License
￼ * along with this program; if not, write to the Free Software
￼ * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
￼ *
￼ * History:
￼ * --------
￼ * 2024-12-03 initial release (vlad)
￼ */

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>


#include "../../evi/evi.h"
#include "../../map.h"
#include "../../ipc.h"

#include "trie_load.h"
#include "trie_db_def.h"
#include "prefix_tree.h"
#include "trie_partitions.h"

#include "../../mem/rpm_mem.h"

#define TRIE_PARAM_STRICT_LEN         (1<<0)

#define TRIE_TABLE_VER 1
#define PART_TABLE_VER 1

#define MAX_LEN_NAME_W_PART 510 /* max len of variable containing
								   avp_spec and partition name */
#define MI_PART_NAME_S "Partition"
#define MI_PART_NAME_LEN (strlen(MI_PART_NAME_S))

#define MI_LAST_UPDATE_S "Date"
#define MI_LAST_UPDATE_LEN (strlen(MI_LAST_UPDATE_S))

#define MI_LAST_DB_URL_S "DB_URL"
#define MI_LAST_DB_URL_LEN (strlen(MI_LAST_DB_URL_S))

#define MI_HASH_S "HASH"
#define MI_HASH_LEN (strlen(MI_HASH_S))

/* reload control parameter */
static int no_concurrent_reload = 0;

/* parameters  */
static str db_url = {NULL,0};

/* statistic data */
int tree_size = 0;
static str attrs_empty = str_init("");

/* configuration loader from db specific stuff */
static str trie_partitions_table = str_init("trie_partitions");
static str trie_partitions_url;

static str data_dump_folder = {0,0};

int use_partitions = 0; /* by default don't use db for config */
static struct head_config {
	str partition; /* partition name extracted from database */
	str db_url;
	str trie_table; /* trie_table name extracted from database */
	struct head_config *next;
} *head_start;
int *n_partitions; /* total number of partitions (does not change at runtime) */

struct head_db *head_db_start;

static int get_config_from_db();
static int add_head_config();
void init_head_db(struct head_db *new);
static int db_connect_head(struct head_db*); /* populate a db connection */
static char *extra_prefix_chars;


/* reader-writers lock for reloading the data */
static rw_lock_t *ref_lock = NULL;

static int trie_init(void);
static int trie_child_init(int rank);
static int trie_exit(void);

static int fix_flags(void** param);
static int fix_partition(void** param);

static int trie_match(struct sip_msg* msg,str *number, long flags, 
		pv_spec_t* rule_att, pv_spec_t* match_prefix, struct head_db *part);

mi_response_t *trie_reload_cmd(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *trie_reload_cmd_1(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_trie_number_routing_1(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_trie_number_routing_2(const mi_params_t *params,
								struct mi_handler *async_hdl);

mi_response_t *mi_trie_reload_status(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_trie_reload_status_1(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_trie_remove_code_2(const mi_params_t *params,struct mi_handler *async_hdl);
mi_response_t *mi_trie_upsert_code_3(const mi_params_t *params,struct mi_handler *async_hdl);

/*
 * Exported functions
 */
static cmd_export_t cmds[] = {
	{"trie_search", (cmd_function)trie_match,
		{
		  {CMD_PARAM_STR, NULL, NULL},
		  {CMD_PARAM_STR|CMD_PARAM_OPT, fix_flags, NULL},
		  {CMD_PARAM_VAR|CMD_PARAM_OPT, NULL, NULL},
		  {CMD_PARAM_VAR|CMD_PARAM_OPT, NULL, NULL},
		  {CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_FIX_NULL, fix_partition,NULL},
		  {0 , 0, 0}
		},
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE
	},
	{0,0,{{0,0,0}},0}
};


/*
 * Exported parameters
 */
static param_export_t params[] = {
	{"use_partitions",    	INT_PARAM, &use_partitions 		},
	{"db_partitions_url",   STR_PARAM, &trie_partitions_url.s 	},
	{"db_partitions_table", STR_PARAM, &trie_partitions_table.s 	},
	{"db_url",           	STR_PARAM, &db_url.s			},
	{"trie_table",        	STR_PARAM, &trie_table.s		},
	{"no_concurrent_reload",INT_PARAM, &no_concurrent_reload	},
	{"extra_prefix_chars", 	STR_PARAM, &extra_prefix_chars		},
	{0, 0, 0}
};


/*
 * Exported MI functions
 */
#define HLP1 "Params: none ; Forces trie module to reload data from DB "\
	"into memory; A return string is returned only in case of error."
#define HLP2 "Params: [partition] number ; Check if a "\
	"number will match when searching through the trie. "\
"The partition parameter must be defined only if use_partitions = 1."
#define HLP3 "Params: [partition]; List the time of the last trie_reload"\
	" (load from database) for all partitions if no parameter is supplied, or"\
" for a partition given as parameter. If use_partitions is 0, you should"\
" not specify a partition."
#define HLP4 "Params: partitionid code_array ; Used to delete codes from the in-memory trie "
#define HLP5 "Params: partitionid code_array attrs_array ; Used to upsert codes in the in-memory trie" 

static mi_export_t mi_cmds[] = {
	{ "trie_reload", HLP1, 0, 0, {
		{trie_reload_cmd, {0}},
		{trie_reload_cmd_1, {"partition_name", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "trie_search", HLP2, MI_NAMED_PARAMS_ONLY, 0, {
		{mi_trie_number_routing_1, {"number", 0}},
		{mi_trie_number_routing_2, {"partition_name", "number", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "trie_reload_status", HLP3, 0, 0, {
		{mi_trie_reload_status, {0}},
		{mi_trie_reload_status_1, {"partition_name", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "trie_number_delete", HLP4, 0,0, {
		{mi_trie_remove_code_2, {"partition_name","number",0}}, 
		{EMPTY_MI_RECIPE}}
	},
	{ "trie_number_upsert", HLP5, 0,0, {
		{mi_trie_upsert_code_3, {"partition_name","number","attrs",0}}, 
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
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

struct module_exports exports = {
	"trie",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	&deps,           /* OpenSIPS module dependencies */
	cmds,            /* Exported functions */
	0,               /* Exported async functions */
	params,          /* Exported parameters */
	0,               /* exported statistics */
	mi_cmds,         /* exported MI functions */
	0,               /* exported pseudo-variables */
	0,	 	 /* exported transformations */
	0,               /* additional processes */
	0,               /* Module pre-initialization function */
	trie_init,         /* Module initialization function */
	(response_function) 0,
	(destroy_function) trie_exit,
	(child_init_function) trie_child_init, /* per-child init function */
	0                /* reload confirm function */
};

static void bin_hash_to_hex(HASH _b, HASHHEX _h)
{
	unsigned short i;
	unsigned char j;

	for (i = 0; i < HASHLEN; i++) {
		j = (_b[i] >> 4) & 0xf;
		if (j <= 9) {
			_h[i * 2] = (j + '0');
		} else {
			_h[i * 2] = (j + 'a' - 10);
		}

		j = _b[i] & 0xf;

		if (j <= 9) {
			_h[i * 2 + 1] = (j + '0');
		} else {
			_h[i * 2 + 1] = (j + 'a' - 10);
		}
	};

	_h[HASHHEXLEN] = '\0';
}

/*
 * if none is successfully loaded return
 * -1, else return 0
 */

static inline int trie_reload_data_head(struct head_db *hd,
                           str *part_name, int initial)
{
	trie_data_t *new_data;
	trie_data_t *old_data;
	time_t rawtime;
	MD5_CTX Md5Ctx;
	HASH bin_md5;
	FILE *fp=NULL;

	if (no_concurrent_reload) {
		lock_get( hd->ref_lock->lock );
		if (hd->ongoing_reload) {
			lock_release( hd->ref_lock->lock );
			LM_WARN("Reload already in progress, discarding this one\n");
			return -2;
		}
		hd->ongoing_reload = 1;
		lock_release( hd->ref_lock->lock );
	}

	LM_INFO("loading trie data in partition %.*s\n",part_name->len,part_name->s);
	MD5Init(&Md5Ctx);

	new_data = trie_load_info(hd, &Md5Ctx, fp);
	if ( new_data==0 ) {
		LM_CRIT("failed to load routing info\n");
		goto error;
	}

	lock_start_write( hd->ref_lock );

	/* no more activ readers -> do the swapping */
	old_data = hd->rdata;
	hd->rdata = new_data;
	/* update the time of the last reload for the current partition */
	time(&rawtime);

	hd->time_last_update = rawtime;

	MD5Final(bin_md5, &Md5Ctx);
	bin_hash_to_hex(bin_md5,hd->md5);

	lock_stop_write( (hd->ref_lock) );

	LM_INFO("loaded trie data in partition %.*s\n",part_name->len,part_name->s);

	/* destroy old data */
	if (old_data) {
		/* free old data */
		free_trie_data(old_data, hd->free);
	}
	LM_INFO("destroyed old trie data in partition %.*s\n",part_name->len,part_name->s);

	if (no_concurrent_reload)
		hd->ongoing_reload = 0;
	return 0;

error:
	if (no_concurrent_reload)
		hd->ongoing_reload = 0;

	return -1;
}

static inline int trie_reload_data(int initial)
{
	struct head_db *part;
	int ret_val = 0;

	for (part = head_db_start; part; part = part->next)
		if (trie_reload_data_head(part, &part->partition, initial) != 0)
			ret_val = -1;

	return ret_val;
}

static int cleanup_head_config( struct head_config *hd)
{
	if (hd == NULL)
		return 0;

	if (hd->db_url.s)
		shm_free(hd->db_url.s);
	if (hd->trie_table.s && hd->trie_table.s != trie_table.s)
		shm_free(hd->trie_table.s);

	return 0;
}


static void cleanup_head_db(struct head_db *hd)
{
	if (!hd)
		return;

	if (hd->db_con && *(hd->db_con))
		hd->db_funcs.close(*(hd->db_con));
	if( hd->ref_lock )
		lock_destroy_rw( ref_lock );
	if (hd->partition.s)
		shm_free(hd->partition.s);
	if (hd->db_url.s)
		shm_free( hd->db_url.s );
	if (hd->trie_table.s && hd->trie_table.s != trie_table.s)
		shm_free(hd->trie_table.s);
}

static void cleanup_head_db_table(void)
{
	struct head_db * it_head_db = 0;
	struct head_db * last_cleaned = 0;

	it_head_db = head_db_start;
	while (it_head_db) {

		cleanup_head_db(it_head_db);
		last_cleaned = it_head_db;
		it_head_db = it_head_db->next;
		shm_free(last_cleaned);
	}
	head_start = 0;
}

static void cleanup_head_config_table(void)
{
	struct head_config * it_head_config = 0;
	struct head_config * last_cleaned = 0;

	it_head_config = head_start;
	while (it_head_config) {

		cleanup_head_config(it_head_config);
		last_cleaned = it_head_config;
		it_head_config = it_head_config->next;
		shm_free(last_cleaned);
	}
	head_start = 0;
}

static int trie_init(void)
{
	str name_w_part;
	struct head_config * it_head_config = 0;
	struct head_db *db_part = NULL;
	char name_w_buf[MAX_LEN_NAME_W_PART];
	name_w_part.s = name_w_buf;

	if (data_dump_folder.s)
		data_dump_folder.len = strlen(data_dump_folder.s);

	LM_INFO("trie - initializing\n");

	n_partitions = shm_malloc(sizeof *n_partitions);
	if (!n_partitions) {
		LM_ERR("oom\n");
		return -1;
	}
	*n_partitions = 0;

	trie_table.len = strlen(trie_table.s);

	name_w_part.s = shm_malloc( MAX_LEN_NAME_W_PART );
	if( name_w_part.s == 0 ) {
		LM_ERR(" No more shm memory [trie:name_w_part.s]\n");
		goto error;
	}

	if( use_partitions == 1 ) { /* loading configurations from db */
		if (get_config_from_db() == -1) {
			LM_ERR("Failed to get configuration from db_config\n");
			return -1;
		}
	} else {
		init_db_url(db_url, 0);

		add_head_config();

		/* if not empty save to head_config structure */
		if (trie_table.s[0]==0) {
			LM_CRIT("mandatory parameter \"TRIE_TABLE\" found empty\n");
			goto error_cfg;
		}
		head_start->trie_table.s = shm_malloc(trie_table.len);
		if (head_start->trie_table.s == 0) {
			LM_ERR("no more shm memory [trie:head_start->trie_table.s]\n");
			goto error_cfg;
		}
		memcpy(head_start->trie_table.s, trie_table.s, trie_table.len);
		head_start->trie_table.len = trie_table.len;

		head_start->db_url.len = db_url.len;
		head_start->db_url.s = shm_malloc(db_url.len);
		if( head_start->db_url.s == 0 ) {
			LM_ERR("no more shm memory [trie:head_start->db_url.s]\n");
			goto error_cfg;
		}
		memcpy(head_start->db_url.s, db_url.s, db_url.len );

		head_start->partition.s = "Default";
		head_start->partition.len = strlen(head_start->partition.s);
	}

	if (init_prefix_tree( extra_prefix_chars )!=0) {
		LM_ERR("failed to initiate the prefix array\n");
		goto error;
	}

	for (it_head_config = head_start; it_head_config != NULL;
			it_head_config = it_head_config->next) {

		db_part = shm_malloc(sizeof(struct head_db));
		if (!db_part) {
			LM_ERR("could not allocate db part!\n");
			goto error_cfg;
		}
		init_head_db(db_part);

		if(shm_str_dup(&db_part->db_url, &it_head_config->db_url) != 0) {
			LM_ERR("shm_str_dup failed for db_url\n");
			goto error_cfg;
		}

		if(shm_str_dup(&db_part->partition, &it_head_config->partition) != 0) {
			LM_ERR("shm_str_dup failed for partition name\n");
			goto error_cfg;
		}

		if (!it_head_config->trie_table.s) {
			db_part->trie_table.s = trie_table.s;
			db_part->trie_table.len = trie_table.len;
		} else if (shm_str_dup(&db_part->trie_table, &it_head_config->trie_table) != 0) {
			LM_ERR("shm_str_dup failed for TRIE table\n");
			goto error_cfg;
		}

		/* create & init lock */
		if ((db_part->ref_lock = lock_init_rw()) == NULL) {
			LM_CRIT("failed to init lock\n");
			goto error_cfg;
		}

		db_part->db_con = pkg_malloc(sizeof(db_con_t *));
		if (!db_part->db_con) {
			LM_ERR("could not allocate db_connection in pkg mem!\n");
			goto error_cfg;
		}

		/* bind to the SQL module */
		if (db_bind_mod( &(db_part->db_url), &( db_part->db_funcs ))) {
			LM_CRIT("cannot bind to database module! "
					"Did you forget to load a database module ? (%.*s)\n",
					db_url.len, db_url.s);
			goto error_cfg;
		}

		if( (*db_part->db_con =
					db_part->db_funcs.init(&db_part->db_url)) == 0) {
			LM_ERR("failed to connect to db url <%.*s>\n",
				db_part->db_url.len, db_part->db_url.s);
			goto error_cfg;
		}

		if (!DB_CAPABILITY( db_part->db_funcs, DB_CAP_QUERY)) {
			LM_CRIT("database modules does not "
				"provide QUERY functions needed by DRouting module\n");
			goto error_cfg;
		}

		if(db_check_table_version(&db_part->db_funcs, *db_part->db_con,
					&db_part->trie_table, TRIE_TABLE_VER) < 0) {
			LM_ERR("error during table version check (trie table \'%.*s\',"
				" for partition \'%.*s\')\n", db_part->trie_table.len,
				db_part->trie_table.s, db_part->partition.len,
				db_part->partition.s);
			goto error_cfg;
		}

		(db_part->db_funcs).close(*db_part->db_con);
		*db_part->db_con = 0;

		/* all good now - add the partition to the list */
		db_part->next = head_db_start;
		head_db_start = db_part;
		db_part->malloc = shm_malloc_func;
		db_part->free = shm_free_func;
	}
	/* all good now - release the config */
	cleanup_head_config_table();

	LM_DBG("All in place in the init. Will return 0\n");
	return 0;

error_cfg:
	cleanup_head_config_table();
	if (db_part) {
		cleanup_head_db(db_part);
		shm_free(db_part);
	}
error:
	cleanup_head_db_table();
	return -1;
}

static int db_connect_head(struct head_db *x) {

	if( *(x->db_con) ) {
		LM_INFO("db_con already present\n");
		return 1;
	}
	if( x->db_url.s && (*(x->db_con) = x->db_funcs.init(&(x->db_url)))==0 ) {
		LM_ERR("cannot initialize database connection"
				"(partition:%.*s, db_url:%.*s, len:%d)\n", x->partition.len,
				x->partition.s, x->db_url.len, x->db_url.s, x->db_url.len);
		return -1;
	}
	return 0;
}

/* simple wrapper over trie_reload_data to make it compatible with ipc_rpc_f,
 * so triggerable via IPC */
static void rpc_trie_reload_data(int sender_id, void *unused)
{
	trie_reload_data(1);
}


static int trie_child_init(int rank)
{
	struct head_db *db = head_db_start;

	LM_DBG("Child initialization on rank %d \n",rank);

	for (db = head_db_start; db; db = db->next) {
		if (db_connect_head(db) < 0) {
			LM_ERR("failed to create DB connection\n");
			return -1;
		}
	}

	/* if child 1, send a job for itself to run the data loading after
	 * the init sequance is done */
	if ( (rank==1) && ipc_send_rpc( process_no, rpc_trie_reload_data, NULL)<0) {
		LM_CRIT("failed to RPC the data loading\n");
		return -1;
	}

	return 0;
}


static int trie_exit(void)
{
	struct head_db * it = head_db_start, *to_clean;

	while( it!=NULL ) {
		to_clean = it;
		it = it->next;

		/* destroy data */
		if (to_clean->rdata) {
			free_trie_data(to_clean->rdata, to_clean->free);
			to_clean->rdata = 0;
		}

		/* destroy lock */
		if (to_clean->ref_lock) {
			lock_destroy_rw( to_clean->ref_lock );
			to_clean->ref_lock = 0;
		}

		if(to_clean->trie_table.s && to_clean->trie_table.s != trie_table.s) {
			shm_free(to_clean->trie_table.s);
		}

		shm_free(to_clean);
	}

	return 0;
}

static mi_response_t *mi_trie_get_partition(const mi_params_t *params,
									struct head_db **partition)
{
	str part_name;

	if (!use_partitions)
		return init_mi_error_extra(400,
			MI_SSTR("Invalid parameter: 'partition_name'"),
			MI_SSTR("'partition_name' supported only when 'use_partitions' is set"));

	if (get_mi_string_param(params, "partition_name",
		&part_name.s, &part_name.len) < 0)
		return init_mi_param_error();

	if((*partition = get_partition(&part_name)) == NULL) {
		LM_ERR("Partition not found\n");
		return init_mi_error(404, MI_SSTR("Partition not found"));
	}

	return NULL;
}

mi_response_t *trie_reload_cmd(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	LM_INFO("trie_reload MI command received!\n");

	if (trie_reload_data(0) != 0) {
		LM_CRIT("failed to load routing data\n");
		return init_mi_error(500, MI_SSTR("Failed to reload"));
	}

	return init_mi_result_ok();
}

mi_response_t *trie_reload_cmd_1(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	struct head_db *part;
	mi_response_t *resp;

	LM_INFO("trie_reload MI command received!\n");

	resp = mi_trie_get_partition(params, &part);
	if (resp)
		return resp;

	if (trie_reload_data_head(part, &part->partition, 0) < 0) {
		LM_CRIT("Failed to load data head\n");
		return init_mi_error(500, MI_SSTR("Failed to reload"));
	}

	return init_mi_result_ok();
}

struct head_db * get_partition(const str *name)
{
	struct head_db * it = head_db_start;

	while( it!= NULL) {
		if( it->partition.len==name->len && memcmp( it->partition.s, name->s,
					name->len)==0 ) {
			return it;
		}
		it = it->next;
	}

	return NULL; /* partition was not found */
}

static int fix_flags(void** param)
{
	str *s = (str*)(*param);
	char *p;
	long flags=0;

	if (s) {
		for ( p=s->s ; p<s->s+s->len ; p++ ) {
			switch (*p) {
				case 'L':
					flags |= TRIE_PARAM_STRICT_LEN;
					LM_DBG("matching prefix with strict len\n");
					break;
				default:
					LM_DBG("unknown flag : [%c] . Skipping\n",*p);
			}
		}
		*param = (void*)(long)flags;
	}
	return 0;
}


static int fix_partition(void** param)
{
	str *s = (str*)(*param);
	struct head_db *part;

	if (s==NULL) {
		/* no partition defined */
		if (use_partitions==0) {
			if(head_db_start == NULL) {
				LM_ERR("Bad configuration, missing default partition\n");
				return -1;
			}
			part = head_db_start;
		} else {
			LM_ERR("Partition name is mandatory\n");
			return -1;
		}
	} else {
		/* partition name defined */
		if (s->len==1 && s->s[0]=='*') {
			/* partition wild card */
			part = NULL;
		} else {
			part = get_partition( s );
			if (part==NULL) {
				LM_ERR("partition <%.*s> used, but not defined\n",s->len,s->s);
				return -1;
			}
		}
	}
	*param = (void*)part;

	return 0;
}

static int trie_match(struct sip_msg* msg, str *number,long flags,
		pv_spec_t* rule_att, pv_spec_t* match_prefix, struct head_db *part)
{
	trie_info_t* rule;
	unsigned int matched_len;
	pv_value_t val;

	if (part==NULL || part->rdata == 0)
		return -1;

	lock_start_read( part->ref_lock );

	rule = get_trie_prefix(part->rdata->pt,number, &matched_len, 1);
	if (rule == NULL){
		goto failure;
	}

	/* was it a full prefix matching ? */
	if (flags & TRIE_PARAM_STRICT_LEN) {
		if (matched_len!=number->len)
			goto failure;
	}

	if (rule_att) {
		val.flags = PV_VAL_STR;
		val.rs = !rule->attrs.s ? attrs_empty : rule->attrs;
		if (pv_set_value(msg, rule_att, 0, &val) != 0) {
			LM_ERR("failed to set value for rule attrs pvar\n");
			goto failure;
		}
	}

	/* add RULE prefix avp */
	if (match_prefix) {
		val.flags = PV_VAL_STR;
		val.rs.s = number->s;
		val.rs.len = matched_len;
		if (pv_set_value(msg, match_prefix, 0, &val) != 0) {
			LM_ERR("failed to set value for rule attrs pvar\n");
			goto failure;
		}
	}

	lock_stop_read( part->ref_lock );

	return 1;

failure:
	lock_stop_read( part->ref_lock );
	return -1;
}

void init_head_db(struct head_db *new)
{
	memset(new, 0, sizeof(struct head_db));
}

/* use_partitions: use configurations from database */
int add_head_config(void)
{
	/* expand linked list */
	struct head_config *new;

	new = shm_malloc(sizeof(struct head_config));
	if( new == NULL ) {
		LM_ERR("no more shm memory\n");
		return -1;
	}
	memset(new, 0, sizeof(struct head_config));

	new->next = head_start;
	head_start = new;

	(*n_partitions)++;
	return 0;
}

#define init_head_config_value( from_head, external, default_val)\
	if( external.len!=0 ) {\
		shm_str_dup( &(from_head), &(external));\
	} else {\
		from_head = default_val;\
	}\

static int populate_head_config(struct head_config *current, str attr, int index) {
	switch(index) {
		case 0:
			if(shm_str_dup( &(current->partition), &attr) < 0) {
				LM_ERR("no more shm memory for partition_name in head_config\n");
			}
			break;
		case 1:
			if( shm_str_dup(&(current->db_url), &attr) < 0) {
				LM_ERR("no more shm memory for db_url in head_config\n");
			}
			break;
		case 2:
			init_head_config_value( current->trie_table, attr, trie_table);
			break;
		default:
			LM_DBG("Column from db_config not_known\n");
			return -1;
	}
	return 0;
}
static int get_config_from_db(void) {

	db_func_t db_funcs;
	db_res_t * query_res;
	db_con_t * db_con = 0;
	/* columns needed from db_confgir_url for query */
	str partition_col = str_init("partition_name");
	str db_url_col = str_init("db_url");
	str table_col = str_init("trie_table");
	int n_query_col = 4;
	db_key_t query_cols[] = {&partition_col, &db_url_col, &table_col};
	/* query result processing stuff */
	int nr_rows_db_config = 0 ;
	int nr_cols_db_config = 0 ;
	db_val_t * value;
	db_row_t *rows_db_config = NULL;
	int j;
	int i;
	str ans_col = {NULL, 0};

	init_db_url(trie_partitions_url, 0);
	trie_partitions_url.len = strlen(trie_partitions_url.s);
	trie_partitions_table.len = strlen(trie_partitions_table.s);

	if(db_bind_mod( &trie_partitions_url, &db_funcs) < 0) {
		LM_ERR("Unable to bind to database driver (partition definitions) "
				"<db url = %.*s>\n", trie_partitions_url.len,
				trie_partitions_url.s);
		goto error;
	}

	if( (db_con = db_funcs.init(&trie_partitions_url)) == 0 ) {
		LM_ERR("Cannot init connection to partitions table "
				"<db url = %.*s>\n", trie_partitions_url.len,
				trie_partitions_url.s);
		goto error;
	}


	if(db_check_table_version(&db_funcs, db_con,
				&trie_partitions_table, PART_TABLE_VER) < 0) {
		LM_ERR("error during table version check <partitions table:\'%.*s\'>.\n",
				trie_partitions_table.len, trie_partitions_table.s);
		return -1;
	}

	if( db_funcs.use_table( db_con, &trie_partitions_table) < 0) {
		LM_ERR("Cannot use the partitions table "
				"<table containing partition defs = %.*s ( in db %.*s "
				")>\n", trie_partitions_table.len, trie_partitions_table.s,
				trie_partitions_url.len, trie_partitions_url.s);
		goto error;
	}

	/* query for populating head_config structure */
	if( db_funcs.query( db_con, NULL, NULL, NULL, query_cols, 0, n_query_col,
				NULL, &query_res) < 0 ) {
		LM_ERR("Failed to query the table containing the partition definitions "
				"<db url = %.*s , partitions table = %.*s>\n",
				trie_partitions_url.len, trie_partitions_url.s,
				trie_partitions_table.len, trie_partitions_table.s);
		goto error;
	}

	nr_rows_db_config = RES_ROW_N(query_res);
	nr_cols_db_config = RES_COL_N(query_res);
	rows_db_config = RES_ROWS(query_res);

	LM_DBG("Got %d total trie partitions \n",nr_rows_db_config);

	for( i=0; i<nr_rows_db_config; i++) {
		value = ROW_VALUES(rows_db_config+i);
		add_head_config();
		for( j=0; j<nr_cols_db_config; j++) {
			if( VAL_NULL(value+j) ) {
				LM_DBG("Row %d is NULL\n", i);
			} else if( VAL_TYPE(value+j) == DB_STR || VAL_TYPE(value+j) == DB_STRING ) {
				if(VAL_TYPE(value+j) == DB_STR) {
					ans_col = VAL_STR(value+j);
				} else if(VAL_TYPE(value+j) == DB_STRING) {
					ans_col.s = (char*)VAL_STRING(value+j);
					ans_col.len = strlen(ans_col.s);
				}
				if (populate_head_config(head_start, ans_col, j) < 0 )
					LM_ERR("Column from partition table not recognized; will continue\n");

			} else {
				LM_ERR("Result from query is not a string\n");
			}
		}
	}



	db_funcs.free_result(db_con, query_res);
	if( db_con != 0 ) {
		db_funcs.close(db_con);
		db_con = 0;
	}

	return 0;
error:
	if( db_con != 0 ) {
		db_funcs.close(db_con);
		db_con = 0;
	}
	return -1;
}

mi_response_t *mi_trie_number_routing(const mi_params_t *params,
					struct head_db *partition)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	str number;
	trie_info_t *route;
	unsigned int matched_len;

	if (get_mi_string_param(params, "number", &number.s, &number.len) < 0)
		return init_mi_param_error();

	if (partition->rdata == 0)
		return init_mi_result_ok();

	lock_start_read( partition->ref_lock );

	if (partition->rdata == NULL) {
		lock_stop_read( partition->ref_lock );
		return init_mi_error(400, MI_SSTR("No data"));
	}


	route = get_trie_prefix(partition->rdata->pt,&number,&matched_len, 1);
	LM_DBG("Got back %p \n",route);
	if (route == NULL){
		lock_stop_read( partition->ref_lock );
		return init_mi_result_string(MI_SSTR("No match"));
	}

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if (add_mi_string(resp_obj, MI_SSTR("Matched Prefix"),
		number.s, matched_len) < 0)
		goto error;

	if (route->attrs.s != NULL && route->attrs.len > 0)
		if (add_mi_string(resp_obj, MI_SSTR("ATTRS"),
			route->attrs.s,route->attrs.len) < 0)
			goto error;

	lock_stop_read( partition->ref_lock );

	return resp;

error:
	lock_stop_read( partition->ref_lock );
	free_mi_response(resp);
	return 0;
}

mi_response_t *mi_trie_number_routing_1(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	if (use_partitions)
		return init_mi_error_extra(400,
			MI_SSTR("Missing parameter: 'partition_name'"),
			MI_SSTR("'partition_name' is required when 'use_partitions' is set"));

	return mi_trie_number_routing(params, head_db_start);
}

mi_response_t *mi_trie_number_routing_2(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	struct head_db * current_partition=0;
	mi_response_t *resp;

	resp = mi_trie_get_partition(params, &current_partition);
	if (resp)
		return resp;

	return mi_trie_number_routing(params, current_partition);
}

static int mi_trie_print_rld_status(mi_item_t *part_item, struct head_db * partition,
							int with_name)
{
	char ch_time[26];

	lock_start_read(partition->ref_lock);

	ctime_r(&partition->time_last_update, ch_time);
	LM_DBG("partition  %.*s was last updated:%s\n",
			partition->partition.len, partition->partition.s,
			ch_time);

	if (with_name && add_mi_string(part_item, MI_SSTR("name"),
		partition->partition.s, partition->partition.len) < 0)
		goto error;

	if (add_mi_string(part_item, MI_SSTR(MI_LAST_UPDATE_S),
		ch_time, strlen(ch_time)-1) < 0)
		goto error;

	if (add_mi_string(part_item,MI_SSTR(MI_HASH_S),partition->md5,strlen(partition->md5)) < 0)
		goto error;

	lock_stop_read(partition->ref_lock);

	return 0;

error:
	lock_stop_read(partition->ref_lock);
	return -1;
}

mi_response_t *mi_trie_reload_status(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	struct head_db * partition;
	mi_response_t *resp;
	mi_item_t *resp_obj;
	mi_item_t *parts_arr, *part_item;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if(use_partitions){
		/* display for all partitions */
		parts_arr = add_mi_array(resp_obj, MI_SSTR("Partitions"));
		if (!parts_arr)
			goto error;

		for(partition = head_db_start; partition; partition = partition->next) {
			part_item = add_mi_object(parts_arr, NULL, 0);
			if (!part_item)
				goto error;

			if (mi_trie_print_rld_status(part_item, partition, 1) < 0)
				goto error;
		}
	} else  /* just one partition */
		if (mi_trie_print_rld_status(resp_obj, head_db_start, 0) < 0)
			goto error;

	return resp;

error:
	free_mi_response(resp);
	return 0;
}

mi_response_t *mi_trie_reload_status_1(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	struct head_db * partition;
	mi_response_t *resp;
	mi_item_t *resp_obj;

	resp = mi_trie_get_partition(params, &partition);
	if (resp)
		return resp;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if (mi_trie_print_rld_status(resp_obj, partition, 1) < 0) {
		free_mi_response(resp);
		return 0;
	}

	return resp;
}

mi_response_t *mi_trie_remove_code_2(const mi_params_t *params,struct mi_handler *async_hdl)
{
	struct head_db *partition;
	str number;
	unsigned int matched_len;
	trie_info_t *route;
	mi_response_t *resp;
	mi_item_t *code_arr;
	int no_codes,i;

	resp = mi_trie_get_partition(params,&partition);
	if (resp)
		return resp;

        if (get_mi_array_param(params, "number", &code_arr, &no_codes) < 0)
                return init_mi_param_error();

	lock_start_read( partition->ref_lock );

	if (partition->rdata == NULL) {
		lock_stop_read( partition->ref_lock );
		return init_mi_error(400, MI_SSTR("No data"));
	}

        for (i = 0; i < no_codes; i++) {
                if (get_mi_arr_param_string(code_arr, i,
                        &number.s, &number.len) < 0) {
			lock_stop_read( partition->ref_lock );
                        return init_mi_param_error();
		}

		route = get_trie_prefix(((partition->rdata))->pt,
			&number, &matched_len,1);
		if (route == NULL) {
			LM_ERR("Failed to find DID to delete [%.*s]\n",number.len,number.s);
			continue;
		}

		if (matched_len != number.len) {
			LM_ERR("Failed to find entry to delete [%.*s]\n",number.len,number.s);
			continue;
		}

		route->enabled = 0;
	}

	lock_stop_read( partition->ref_lock );

	return init_mi_result_ok();
}

mi_response_t *mi_trie_upsert_code_3(const mi_params_t *params,struct mi_handler *async_hdl)
{
	struct head_db *partition;
	str number,attr,dyn_attr;
	unsigned int matched_len;
	trie_info_t *route;
	mi_response_t *resp;
	mi_item_t *code_arr, *attrs_arr;
	int no_codes,no_attrs,i;

	resp = mi_trie_get_partition(params,&partition);
	if (resp)
		return resp;

        if (get_mi_array_param(params, "number", &code_arr, &no_codes) < 0)
                return init_mi_param_error();
        if (get_mi_array_param(params, "attrs", &attrs_arr, &no_attrs) < 0)
                return init_mi_param_error();

	if (no_codes != no_attrs) {
		return init_mi_error(400, MI_SSTR("Code attrs missmatch"));
	}

	lock_start_read( partition->ref_lock );
	if (partition->rdata == NULL) {
		lock_stop_read( partition->ref_lock );
		return init_mi_error(400, MI_SSTR("No data"));
	}

        for (i = 0; i < no_codes; i++) {
                if (get_mi_arr_param_string(code_arr, i,
                        &number.s, &number.len) < 0) {
			lock_stop_read( partition->ref_lock );
                        return init_mi_param_error();
		}

                if (get_mi_arr_param_string(attrs_arr, i,
                        &attr.s, &attr.len) < 0) {
			lock_stop_read( partition->ref_lock );
                        return init_mi_param_error();
		}

		/* we search for all codes, enabled or disabled */
		route = get_trie_prefix(((partition->rdata))->pt,
			&number, &matched_len,0);

		if (matched_len != number.len){
			/* prefix not found, need to add it */

			route = build_trie_info(&attr,1,partition->malloc,partition->free);
			if (!route) {
				LM_ERR("Failed to build route info for DID upsert %.*s\n", number.len,number.s);
				lock_stop_read( partition->ref_lock );
				return init_mi_error(500, MI_SSTR("Internal Error"));
			}

			if (add_trie_prefix(((partition->rdata))->pt,&number,route,partition->malloc,partition->free) != 0) {
				LM_ERR("Failed to add route info for DID upsert %.*s\n", number.len,number.s);
				lock_stop_read( partition->ref_lock );
				free_trie_info(route,partition->free);
				return init_mi_error(500, MI_SSTR("Internal Error"));
			}
		} else {
			/* we found it, need to update in-place */
			dyn_attr.s = shm_malloc(attr.len);
			if (!dyn_attr.s) {
				LM_ERR("No more shm \n");
				lock_stop_read( partition->ref_lock );
				return init_mi_error(500, MI_SSTR("Internal Error"));
			}

			memcpy(dyn_attr.s,attr.s,attr.len);
			if (route->attrs.s) {
				shm_free(route->attrs.s);
			}

			route->attrs.len = attr.len;
			route->attrs.s = dyn_attr.s;

			/* if it was removed before, clear that flag */
			route->enabled = 1;
		}
	}

	lock_stop_read( partition->ref_lock );
	return init_mi_result_ok();
}
