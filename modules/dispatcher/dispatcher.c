/**
 * dispatcher module -- stateless load balancing
 *
 * Copyright (C) 2004-2005 FhG Fokus
 * Copyright (C) 2006-2010 Voice Sistem SRL
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History
 * -------
 * 2004-07-31  first version, by daniel
 * 2007-01-11  Added a function to check if a specific gateway is in a group
 *              (carsten - Carsten Bock, BASIS AudioNet GmbH)
 * 2007-02-09  Added active probing of failed destinations and automatic
 *              re-enabling of destinations (carsten)
 * 2007-05-08  Ported the changes to SVN-Trunk and renamed ds_is_domain
 *              to ds_is_from_list.  (carsten)
 * 2007-07-18  Added support for load/reload groups from DB
 *              reload triggered from ds_reload MI_Command (ancuta)
 * 2009-05-18  Added support for weights for the destinations;
 *              added support for custom "attrs" (opaque string) (bogdan)
 * 2013-12-02  Added support state persistency (restart and reload) (bogdan)
 * 2013-12-05  Added a safer reload mechanism based on locking read/writter (bogdan)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "../../sr_module.h"
#include "../../mi/mi.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../trim.h"
#include "../../route.h"
#include "../../mem/mem.h"
#include "../../mod_fix.h"
#include "../../db/db.h"

#include "../freeswitch/fs_api.h"

#include "dispatch.h"
#include "ds_bl.h"
#include "ds_fixups.h"


#define DS_SET_ID_COL		"setid"
#define DS_DEST_URI_COL		"destination"
#define DS_DEST_SOCK_COL	"socket"
#define DS_DEST_STATE_COL	"state"
#define DS_DEST_WEIGHT_COL	"weight"
#define DS_DEST_PRIO_COL	"priority"
#define DS_DEST_ATTRS_COL	"attrs"
#define DS_DEST_DESCRIPTION_COL	"description"
#define DS_TABLE_NAME 		"dispatcher"
#define DS_PARTITION_DELIM  ':'

/** parameters */
static str pvar_algo_param = str_init("");
str hash_pvar_param = {NULL, 0};

pv_elem_t * hash_param_model = NULL;


int probing_threshhold = 3; /* number of failed requests, before a destination
							   is taken into probing */
str ds_ping_method = {"OPTIONS",7};
str ds_ping_from   = {"sip:dispatcher@localhost", 24};
static int ds_ping_interval = 0;
/* no MAX-FWD enforced from the module */
int ds_ping_maxfwd = -1;
int ds_probing_mode = 0;
int ds_persistent_state = 1;
int_list_t *ds_probing_list = NULL;

/* db partiton info */

typedef struct _ds_db_head
{
	str partition_name;
	str db_url;
	str table_name;

	str dst_avp;
	str grp_avp;
	str cnt_avp;
	str sock_avp;
	str attrs_avp;

	struct _ds_db_head *next;
} ds_db_head_t;


ds_db_head_t default_db_head = {
	str_init(DS_DEFAULT_PARTITION_NAME),
	{NULL, 0},
	{NULL, 0},


	{NULL, 0},
	{NULL, 0},
	{NULL, 0},
	{NULL, 0},
	{NULL, 0},
	NULL
};
ds_db_head_t *ds_db_heads = NULL;

typedef struct {
	str name;
	str default_value;
	str* (*getter_func)(ds_db_head_t*);
} partition_specific_param_t;

#define DEF_GETTER_FUNC(PARAM_FIELD) str* getter_ ## PARAM_FIELD (ds_db_head_t \
		*head) { \
			return &(head-> PARAM_FIELD);}
#define GETTER_FUNC(PARAM_FIELD) &getter_ ## PARAM_FIELD
#define PARTITION_SPECIFIC_PARAM(PARAM_NAME, DEFAULT_VALUE) \
	{str_init(#PARAM_NAME), str_init(DEFAULT_VALUE), GETTER_FUNC(PARAM_NAME)}


/*db common attributes*/
str ds_set_id_col     = str_init(DS_SET_ID_COL);
str ds_dest_uri_col   = str_init(DS_DEST_URI_COL);
str ds_dest_sock_col  = str_init(DS_DEST_SOCK_COL);
str ds_dest_state_col = str_init(DS_DEST_STATE_COL);
str ds_dest_weight_col= str_init(DS_DEST_WEIGHT_COL);
str ds_dest_prio_col = str_init(DS_DEST_PRIO_COL);
str ds_dest_attrs_col = str_init(DS_DEST_ATTRS_COL);
str ds_dest_description_col = str_init(DS_DEST_DESCRIPTION_COL);

str ds_setid_pvname   = {NULL, 0};
pv_spec_t ds_setid_pv;

static str options_reply_codes_str= {0, 0};
static int* options_reply_codes = NULL;
static int options_codes_no;
static char *probing_sock_s = NULL;
struct socket_info *probing_sock = NULL;

ds_partition_t *partitions = NULL, *default_partition = NULL;

/* event */
static str dispatcher_event = str_init("E_DISPATCHER_STATUS");
event_id_t dispatch_evi_id;

int fetch_freeswitch_stats;
int max_freeswitch_weight = 100;

/** module functions */
static int mod_init(void);
static int ds_child_init(int rank);

static int w_ds_select_dst(struct sip_msg*, char*, char*);
static int w_ds_select_dst_limited(struct sip_msg*, char*, char*, char*);
static int w_ds_select_domain(struct sip_msg*, char*, char*);
static int w_ds_select_domain_limited(struct sip_msg*, char*, char*, char*);
static int w_ds_next_dst(struct sip_msg*, char*);
static int w_ds_next_domain(struct sip_msg*, char*);
static int w_ds_mark_dst(struct sip_msg*, char*, char*);
static int w_ds_mark_dst1(struct sip_msg*, char *);
static int w_ds_count(struct sip_msg*, char*, const char *, char*);

static int w_ds_is_in_list(struct sip_msg*, char*, char*, char*, char*);

static void destroy(void);

static struct mi_root* ds_mi_set(struct mi_root* cmd, void* param);
static struct mi_root* ds_mi_list(struct mi_root* cmd, void* param);
static struct mi_root* ds_mi_reload(struct mi_root* cmd_tree, void* param);
static int mi_child_init(void);

/* Parameters setters */

static int set_partition_arguments(unsigned int type, void * val);
static int set_probing_list(unsigned int type, void * val);

static cmd_export_t cmds[]={
	{"ds_select_dst",    (cmd_function)w_ds_select_dst, 2,
		ds_select_fixup,  NULL,
		REQUEST_ROUTE|FAILURE_ROUTE},
	{"ds_select_dst",    (cmd_function)w_ds_select_dst_limited, 3,
		ds_select_fixup,  NULL,
		REQUEST_ROUTE|FAILURE_ROUTE},
	{"ds_select_domain", (cmd_function)w_ds_select_domain, 2,
		ds_select_fixup,  NULL,
		REQUEST_ROUTE|FAILURE_ROUTE},
	{"ds_select_domain", (cmd_function)w_ds_select_domain_limited, 3,
		ds_select_fixup,  NULL,
		REQUEST_ROUTE|FAILURE_ROUTE},
	{"ds_next_dst",      (cmd_function)w_ds_next_dst,      0,
		NULL , NULL,
		REQUEST_ROUTE|FAILURE_ROUTE},
	{"ds_next_dst",      (cmd_function)w_ds_next_dst,      1,
		ds_next_fixup, NULL,
		REQUEST_ROUTE|FAILURE_ROUTE},
	{"ds_next_domain",   (cmd_function)w_ds_next_domain,   0,
		NULL , NULL,
		REQUEST_ROUTE|FAILURE_ROUTE},
	{"ds_next_domain",   (cmd_function)w_ds_next_domain,   1,
		ds_next_fixup,  NULL,
		REQUEST_ROUTE|FAILURE_ROUTE},
	{"ds_mark_dst",      (cmd_function)w_ds_mark_dst,      0,
		NULL , NULL,
		REQUEST_ROUTE|FAILURE_ROUTE},
	{"ds_mark_dst",      (cmd_function)w_ds_mark_dst1,     1,
		fixup_sgp_null, NULL,
		REQUEST_ROUTE|FAILURE_ROUTE},
	{"ds_mark_dst",      (cmd_function)w_ds_mark_dst,      2,
		ds_mark_fixup, NULL,
		REQUEST_ROUTE|FAILURE_ROUTE},
	{"ds_is_in_list",    (cmd_function)w_ds_is_in_list,    2,
		in_list_fixup, NULL,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"ds_is_in_list",    (cmd_function)w_ds_is_in_list,    3,
		in_list_fixup, NULL,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"ds_is_in_list",    (cmd_function)w_ds_is_in_list,    4,
		in_list_fixup, NULL,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"ds_count",    (cmd_function)w_ds_count,   3,
		ds_count_fixup, NULL,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{0,0,0,0,0,0}
};


static param_export_t params[]={
	{"partition",       STR_PARAM | USE_FUNC_PARAM, (void*)&set_partition_arguments},
	{"db_url",          STR_PARAM, &default_db_head.db_url.s},
	{"table_name",      STR_PARAM, &default_db_head.table_name.s},
	{"setid_col",       STR_PARAM, &ds_set_id_col.s},
	{"destination_col", STR_PARAM, &ds_dest_uri_col.s},
	{"socket_col",      STR_PARAM, &ds_dest_sock_col.s},
	{"state_col",       STR_PARAM, &ds_dest_state_col.s},
	{"weight_col",      STR_PARAM, &ds_dest_weight_col.s},
	{"priority_col",    STR_PARAM, &ds_dest_prio_col.s},
	{"attrs_col",       STR_PARAM, &ds_dest_attrs_col.s},
	{"description_col",       STR_PARAM, &ds_dest_description_col.s},
	{"dst_avp",         STR_PARAM, &default_db_head.dst_avp.s},
	{"grp_avp",         STR_PARAM, &default_db_head.grp_avp.s},
	{"cnt_avp",         STR_PARAM, &default_db_head.cnt_avp.s},
	{"sock_avp",        STR_PARAM, &default_db_head.sock_avp.s},
	{"attrs_avp",       STR_PARAM, &default_db_head.attrs_avp.s},
	{"hash_pvar",       STR_PARAM, &hash_pvar_param.s},
	{"setid_pvar",      STR_PARAM, &ds_setid_pvname.s},
	{"pvar_algo_pattern",     STR_PARAM, &pvar_algo_param.s},
	{"ds_probing_threshhold", INT_PARAM, &probing_threshhold},
	{"ds_ping_method",        STR_PARAM, &ds_ping_method.s},
	{"ds_ping_from",          STR_PARAM, &ds_ping_from.s},
	{"ds_ping_interval",      INT_PARAM, &ds_ping_interval},
	{"ds_ping_maxfwd",        INT_PARAM, &ds_ping_maxfwd},
	{"ds_probing_mode",       INT_PARAM, &ds_probing_mode},
	{"options_reply_codes",   STR_PARAM, &options_reply_codes_str.s},
	{"ds_probing_sock",       STR_PARAM, &probing_sock_s},
	{"ds_probing_list",       STR_PARAM|USE_FUNC_PARAM, (void*)set_probing_list},
	{"ds_define_blacklist",   STR_PARAM|USE_FUNC_PARAM, (void*)set_ds_bl},
	{"persistent_state",      INT_PARAM, &ds_persistent_state},
	{"fetch_freeswitch_stats", INT_PARAM, &fetch_freeswitch_stats},
	{"max_freeswitch_weight", INT_PARAM, &max_freeswitch_weight},
	{0,0,0}
};

static module_dependency_t *get_deps_ds_ping_interval(param_export_t *param)
{
	if (*(int *)param->param_pointer <= 0)
		return NULL;

	return alloc_module_dep(MOD_TYPE_DEFAULT, "tm", DEP_ABORT);
}

static module_dependency_t *get_deps_fetch_fs_load(param_export_t *param)
{
	if (*(int *)param->param_pointer <= 0)
		return NULL;

	return alloc_module_dep(MOD_TYPE_DEFAULT, "freeswitch", DEP_ABORT);
}

static mi_export_t mi_cmds[] = {
	{ "ds_set_state",   0, ds_mi_set,     0,                0,  0            },
	{ "ds_list",        0, ds_mi_list,    0,                0,  0            },
	{ "ds_reload",      0, ds_mi_reload,  0,                0,  mi_child_init},
	{ 0, 0, 0, 0, 0, 0}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_SQLDB, NULL, DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ "ds_ping_interval",      get_deps_ds_ping_interval },
		{ "fetch_freeswitch_stats", get_deps_fetch_fs_load },
		{ NULL, NULL },
	},
};

/** module exports */
struct module_exports exports= {
	"dispatcher",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	&deps,           /* OpenSIPS module dependencies */
	cmds,
	0,
	params,
	0,          /* exported statistics */
	mi_cmds,    /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,			/* exported transformations */
	0,          /* extra processes */
	mod_init,   /* module initialization function */
	(response_function) 0,
	(destroy_function) destroy,
	ds_child_init, /* per-child init function */
};


DEF_GETTER_FUNC(db_url);
DEF_GETTER_FUNC(table_name);
DEF_GETTER_FUNC(dst_avp);
DEF_GETTER_FUNC(grp_avp);
DEF_GETTER_FUNC(cnt_avp);
DEF_GETTER_FUNC(sock_avp);
DEF_GETTER_FUNC(attrs_avp);

static partition_specific_param_t partition_params[] = {
	{str_init("db_url"), {NULL, 0}, GETTER_FUNC(db_url)},
	PARTITION_SPECIFIC_PARAM (table_name, DS_TABLE_NAME),
	PARTITION_SPECIFIC_PARAM (dst_avp, "$avp(ds_dst_failover)"),
	PARTITION_SPECIFIC_PARAM (grp_avp, "$avp(ds_grp_failover)"),
	PARTITION_SPECIFIC_PARAM (cnt_avp, "$avp(ds_cnt_failover)"),
	PARTITION_SPECIFIC_PARAM (sock_avp, "$avp(ds_sock_failover)"),
	PARTITION_SPECIFIC_PARAM (attrs_avp, ""),
};

static const unsigned int partition_param_count = sizeof (partition_params) /
				sizeof (partition_specific_param_t);

/*
	Splits the arg from "partition_name[DELIM]value" to partition_name
	and value. The arg is modified and will contain only value
*/

static int split_partition_argument(str *arg, str *partition_name)
{
	char *delim_pos = memchr(arg->s, DS_PARTITION_DELIM, arg->len);
	partition_name->s = NULL;
	partition_name->len = 0;

	if (delim_pos == NULL) {
		/* No delim so the default partition is used */
		return 0;
	} else if (delim_pos - arg->s + 1 == arg->len){

		LM_WARN("possibly empty parameter %.*s\n", arg->len, arg->s);
		return 0;
	} else {

		switch (DS_PARTITION_DELIM) {

			case ':':
				if (*(delim_pos + 1) == '/'){
					/* Fake delimiter as in mysql://... */
					return 0;
				}
				/* else An actual delimiter has been found */
				break;

			default:
				LM_CRIT("Partition delimiter %c was not properly implemented\n",
						DS_PARTITION_DELIM);
				return -1;
				break;
		}
	}

	partition_name->s = arg->s;
	partition_name->len = delim_pos - arg->s;

	arg->s = delim_pos + 1;
	arg->len -= partition_name->len + 1;

	trim(partition_name);
	for (;arg->s[0] == ' ' && arg->len; ++arg->s, --arg->len);
	return 0;
}

/*
	Parse an argument "partition_name[DELIM]arg_value".
	The arg string will be modified and will contain only "arg_value"
	The found_head will contain the head which has the name
	"partition_name"
	If the head doesn't exist it will be created
*/
static int parse_partition_argument(str *arg, ds_db_head_t **found_head)
{
	str partition_name;

	if (split_partition_argument(arg, &partition_name) != 0)
		return -1;

	if (partition_name.len == 0
		|| str_strcmp(&default_db_head.partition_name, &partition_name) == 0){

		*found_head = &default_db_head;
		return 0;
	}

	/* There is a partition name in arg so we won't use default head*/
	ds_db_head_t *heads_it;
	for (heads_it = ds_db_heads; heads_it; heads_it = heads_it->next)
		if (memcmp(partition_name.s, heads_it->partition_name.s,
					partition_name.len) == 0){

			/* This partition already exists */
			*found_head = heads_it;
			return 0;
		}

	/* The partition does not exist - we create it */

	ds_db_head_t *new_partition = pkg_malloc(sizeof (ds_db_head_t));
	if (new_partition == NULL) {
		LM_ERR("failed to allocate data in shm\n");
		return -1;
	}

	/* Set default head values */

	memset(new_partition, 0, sizeof(ds_db_head_t));
	new_partition->next = ds_db_heads;
	ds_db_heads = new_partition;
	new_partition->partition_name = partition_name;

	*found_head = new_partition;
	return 0;
}

/*
	Find partition by name. Return null if no partition is matching the name
*/

static ds_partition_t* find_partition_by_name (const str *partition_name)
{
	if (partition_name->len == 0)
		return default_partition;

	ds_partition_t *part_it;

	for (part_it = partitions; part_it; part_it = part_it->next)
		if (str_strcmp(&part_it->name, partition_name) == 0)
			break;

	return part_it; //and NULL if there's no partition matching the name
}

/* Load setids this proxy is responsible for probing into list */
static int set_probing_list(unsigned int type, void *val) {
	str input = {(char*)val, strlen(val)};

        if (set_list_from_string(input, &ds_probing_list) != 0 ||
            ds_probing_list == NULL)
        {
            LM_ERR("Invalid set_probing_list input\n");
            return -1;
        }

        return 0;
}

/* We parse the "partition" argument as: partition_name:arg1=val1; arg2=val2;*/

static int set_partition_arguments(unsigned int type, void *val)
{
	static const char end_pair_delim = ';';
	static const char eq_val_delim = '=';
	static const str blacklist_param = str_init("ds_define_blacklist");
	unsigned int i;

	str raw_line = {(char*)val, strlen(val)};
	str arg, value;
	ds_db_head_t *head = NULL;

	if (raw_line.s[raw_line.len - 1] != end_pair_delim)
		raw_line.s[raw_line.len++] = end_pair_delim;

	if (parse_partition_argument(&raw_line, &head) != 0)
		return -1;

	char *first_pos = raw_line.s; /* just for error messages */
	char *end_pair_pos = q_memchr(raw_line.s, end_pair_delim, raw_line.len);
	char *eq_pos = q_memchr(raw_line.s, eq_val_delim, raw_line.len);

	while (end_pair_pos != NULL && eq_pos != NULL) {

		arg.s = raw_line.s;
		arg.len = eq_pos - arg.s;
		value.s = eq_pos + 1;
		value.len = end_pair_pos - eq_pos - 1;
		trim(&arg);
		trim(&value);

		if (arg.len <= 0 || value.len <= 0) {
			LM_ERR("Wrong format in partition arguments specifier at pos %d\n",
					(int)(arg.s - first_pos + 1));
			return -1;
		}

		for (i = 0; i < partition_param_count; ++i)
			if (str_strcmp(&arg, &partition_params[i].name) == 0) {
				*(partition_params[i].getter_func(head)) = value;
				break;
			}

		if ( i == partition_param_count) {
			if (str_strcmp(&blacklist_param, &arg) == 0) {
				value.s[value.len] = 0;
				if (set_ds_bl_partition(value.s, head->partition_name) != 0)
					return -1;
			}
			else{
				/* No parameter found */
				LM_ERR("No such parameter known: %.*s\n", arg.len, arg.s);
				return -1;
			}
		}

		raw_line.s = end_pair_pos + 1;
		end_pair_pos = q_memchr(raw_line.s, end_pair_delim, raw_line.len);
		eq_pos = q_memchr(raw_line.s, eq_val_delim, raw_line.len);
	}

	return 0;
}

static int partition_init(ds_db_head_t *db_head, ds_partition_t *partition)
{

	/* Load stuff from DB. URL cannot be null!*/
	if (db_head->db_url.s == NULL){
		LM_ERR("[%.*s] DB URL is not defined!\n", db_head->partition_name.len,
				db_head->partition_name.s);
		return -1;
	}

	memset(partition, 0, sizeof(ds_partition_t));
	partition->name = db_head->partition_name;
	partition->table_name = db_head->table_name;
	partition->db_url = db_head->db_url;
	partition->db_handle = pkg_malloc(sizeof(struct db_con_t *));
	if (partition->db_handle == NULL) {
		LM_ERR("Failed to allocate private data\n");
		return -1;
	}
	*partition->db_handle = NULL;

	/* handle AVPs spec */
	pv_spec_t avp_spec;

	if (pv_parse_spec(&db_head->dst_avp, &avp_spec)==0
	|| avp_spec.type!=PVT_AVP) {
		LM_ERR("malformed or non AVP %.*s AVP definition\n",
			db_head->dst_avp.len, db_head->dst_avp.s);
		return -1;
	}
	if(pv_get_avp_name(0, &(avp_spec.pvp), &partition->dst_avp_name,
				&partition->dst_avp_type)!=0) {
		LM_ERR("[%.*s]- invalid AVP definition\n", db_head->dst_avp.len,
			db_head->dst_avp.s);
		return -1;
	}

	if (pv_parse_spec(&db_head->grp_avp, &avp_spec)==0
	|| avp_spec.type!=PVT_AVP) {
		LM_ERR("malformed or non AVP %.*s AVP definition\n",
			db_head->grp_avp.len, db_head->grp_avp.s);
		return -1;
	}
	if(pv_get_avp_name(0, &(avp_spec.pvp), &partition->grp_avp_name,
				&partition->grp_avp_type)!=0) {
		LM_ERR("[%.*s]- invalid AVP definition\n", db_head->grp_avp.len,
			db_head->grp_avp.s);
		return -1;
	}

	if (pv_parse_spec(&db_head->cnt_avp, &avp_spec)==0
	|| avp_spec.type!=PVT_AVP) {
		LM_ERR("malformed or non AVP %.*s AVP definition\n",
			db_head->cnt_avp.len, db_head->cnt_avp.s);
		return -1;
	}
	if(pv_get_avp_name(0, &(avp_spec.pvp), &partition->cnt_avp_name,
				&partition->cnt_avp_type)!=0) {
		LM_ERR("[%.*s]- invalid AVP definition\n", db_head->cnt_avp.len,
			db_head->cnt_avp.s);
		return -1;
	}

	if (pv_parse_spec(&db_head->sock_avp, &avp_spec)==0
	|| avp_spec.type!=PVT_AVP) {
		LM_ERR("malformed or non AVP %.*s AVP definition\n",
			db_head->sock_avp.len, db_head->sock_avp.s);
		return -1;
	}
	if(pv_get_avp_name(0, &(avp_spec.pvp), &partition->sock_avp_name,
				&partition->sock_avp_type)!=0){
		LM_ERR("[%.*s]- invalid AVP definition\n", db_head->sock_avp.len,
			db_head->sock_avp.s);
		return -1;
	}

	if (db_head->attrs_avp.s && db_head->attrs_avp.len > 0) {
		if (pv_parse_spec(&db_head->attrs_avp, &avp_spec)==0
		|| avp_spec.type!=PVT_AVP) {
			LM_ERR("malformed or non AVP %.*s AVP definition\n",
					db_head->attrs_avp.len, db_head->attrs_avp.s);
			return -1;
		}

		if (pv_get_avp_name(0, &(avp_spec.pvp), &partition->attrs_avp_name,
		&partition->attrs_avp_type)!=0){
			LM_ERR("[%.*s]- invalid AVP definition\n", db_head->attrs_avp.len,
					db_head->attrs_avp.s);
			return -1;
		}
	} else {
		partition->attrs_avp_name = -1;
		partition->attrs_avp_type = 0;
	}

	return 0;
}


static int inherit_from_default_head(ds_db_head_t *head)
{
	unsigned int i;

	if (head == &default_db_head)
		return 0;

	for (i = 0; i < partition_param_count; ++i) {
		str *def_param = partition_params[i].getter_func(&default_db_head);
		str *p_param = partition_params[i].getter_func(head);

		if (p_param->len == 0 && def_param->len > 0) {
			/* Parameter not specified for function */
			if (strstr(partition_params[i].name.s, "avp")
				&& def_param->len > 0) {

				char *avp_end = q_memrchr(def_param->s, ')', def_param->len);
				if (avp_end == NULL) {
					LM_ERR ("wrong avp name %.*s\n", def_param->len,
							def_param->s);
					return -1;
				}

				p_param->len = def_param->len + 1 + head->partition_name.len;
				p_param->s = pkg_malloc(p_param->len);
				if (p_param->s == NULL) {
					LM_ERR ("no more private memory\n");
					return -1;
				}

				int fix_len = avp_end - def_param->s;
				int rem_len = def_param->len - fix_len;
				memcpy(p_param->s, def_param->s, fix_len);
				p_param->s[fix_len] = '_';
				memcpy(p_param->s + fix_len + 1, head->partition_name.s,
						head->partition_name.len);
				memcpy(p_param->s + fix_len + 1 + head->partition_name.len,
						def_param->s + fix_len, rem_len);
			}
			else
				memcpy(p_param, def_param, sizeof(str));
		}
	}
	return 0;
}

void set_default_head_values(ds_db_head_t *head)
{
	unsigned int i;

	for (i = 0; i < partition_param_count; ++i) {
		str *p_val = partition_params[i].getter_func(head);
		if (p_val->s == NULL)
			*p_val = partition_params[i].default_value;
		else
			p_val->len = strlen(p_val -> s);
	}
}

static inline int check_if_default_head_is_ok(void)
{
	unsigned int i;

	for (i = 0; i < partition_param_count; ++i)
		if (partition_params[i].getter_func(&default_db_head)->s != NULL)
			return 1;

	return 0;
}


/**
 * init module function
 */
static int mod_init(void)
{

	LM_DBG("initializing ...\n");

	if (check_if_default_head_is_ok()) {
		default_db_head.next = ds_db_heads;
		ds_db_heads = &default_db_head;
	}
	set_default_head_values(&default_db_head);

	ds_set_id_col.len = strlen(ds_set_id_col.s);
	ds_dest_uri_col.len = strlen(ds_dest_uri_col.s);
	ds_dest_sock_col.len = strlen(ds_dest_sock_col.s);
	ds_dest_state_col.len = strlen(ds_dest_state_col.s);
	ds_dest_weight_col.len = strlen(ds_dest_weight_col.s);
	ds_dest_attrs_col.len = strlen(ds_dest_attrs_col.s);

	if (fetch_freeswitch_stats) {
		if (load_fs_api(&fs_api) == -1) {
			LM_ERR("failed to load the FS API!\n");
			return -1;
		}
	}

	if(hash_pvar_param.s && (hash_pvar_param.len=strlen(hash_pvar_param.s))>0){
		if(pv_parse_format(&hash_pvar_param, &hash_param_model) < 0
				|| hash_param_model==NULL) {
			LM_ERR("malformed PV string: %s\n", hash_pvar_param.s);
			return -1;
		}
	} else {
		hash_param_model = NULL;
	}

	if(ds_setid_pvname.s && (ds_setid_pvname.len=strlen(ds_setid_pvname.s))>0){
		if(pv_parse_spec(&ds_setid_pvname, &ds_setid_pv)==NULL
				|| !pv_is_w(&ds_setid_pv))
		{
			LM_ERR("[%s]- invalid setid_pvname\n", ds_setid_pvname.s);
			return -1;
		}
	}

	pvar_algo_param.len = strlen(pvar_algo_param.s);
	if (pvar_algo_param.len)
		ds_pvar_parse_pattern(pvar_algo_param);


	if (init_ds_bls()!=0) {
		LM_ERR("failed to init DS blacklists\n");
		return E_CFG;
	}

	/* Creating partitions from head */
	ds_db_head_t *head_it = ds_db_heads;
	while (head_it){
		if (inherit_from_default_head(head_it) != 0)
			return -1;

		ds_partition_t *partition = shm_malloc (sizeof(ds_partition_t));
		if (partition_init(head_it, partition) != 0)
			return -1;
		partition->next = partitions;
		partitions = partition;

		if (init_ds_data(partition)!=0) {
			LM_ERR("failed to init DS data holder\n");
			return -1;
		}

		/* open DB connection to load provisioning data */
		if (init_ds_db(partition)!= 0) {
			LM_ERR("failed to init database support\n");
			return -1;
		}

		/* do the actual data load */
		if (ds_reload_db(partition)!=0) {
			LM_ERR("failed to load data from DB\n");
			return -1;
		}

		/* close DB connection */
		ds_disconnect_db(partition);
		ds_db_head_t *aux = head_it;

		/* We keep track of corespondig default parition */
		if (head_it == &default_db_head)
			default_partition = partition;

		head_it = head_it->next;
		if (aux != &default_db_head)
			pkg_free(aux);
	}

	/* Only, if the Probing-Timer is enabled the TM-API needs to be loaded: */
	if (ds_ping_interval > 0)
	{
		load_tm_f load_tm;
		str host;
		int port,proto;

		if (ds_ping_from.s)
			ds_ping_from.len = strlen(ds_ping_from.s);
		if (ds_ping_method.s)
			ds_ping_method.len = strlen(ds_ping_method.s);
		/* parse the list of reply codes to be counted as success */
		if(options_reply_codes_str.s) {
			options_reply_codes_str.len = strlen(options_reply_codes_str.s);
			if(parse_reply_codes(&options_reply_codes_str,&options_reply_codes,
			&options_codes_no )< 0) {
				LM_ERR("Bad format for options_reply_code parameter"
						" - Need a code list separated by commas\n");
				return -1;
			}
		}
		/* parse and look for the socket to ping from */
		if (probing_sock_s && probing_sock_s[0]!=0 ) {
			if (parse_phostport( probing_sock_s, strlen(probing_sock_s),
			&host.s, &host.len, &port, &proto)!=0 ) {
				LM_ERR("socket description <%s> is not valid\n",
					probing_sock_s);
				return -1;
			}
			probing_sock = grep_sock_info( &host, port, proto);
			if (probing_sock==NULL) {
				LM_ERR("socket <%s> is not local to opensips (we must listen "
					"on it\n", probing_sock_s);
				return -1;
			}
		}
		/* TM-Bindings */
		load_tm=(load_tm_f)find_export("load_tm", 0, 0);
		if (load_tm==NULL) {
			LM_ERR("failed to bind to the TM-Module - required for probing\n");
			return -1;
		}
		/* let the auto-loading function load all TM stuff */
		if (load_tm( &tmb ) == -1) {
			LM_ERR("could not load the TM-functions - disable DS ping\n");
			return -1;
		}
		/* Register the PING-Timer */
		if (register_timer("ds-pinger", ds_check_timer, NULL,
		ds_ping_interval, TIMER_FLAG_DELAY_ON_DELAY)<0) {
			LM_ERR("failed to register timer for probing!\n");
			return -1;
		}

		/* Register the weight-recalculation timer */
		if (fetch_freeswitch_stats &&
		    register_timer("ds-update-weights", ds_update_weights, NULL,
		                   FS_HEARTBEAT_ITV, TIMER_FLAG_SKIP_ON_DELAY)<0) {
			LM_ERR("failed to register timer for weight recalc!\n");
			return -1;
		}
	}

	/* register timer to flush the state of destination back to DB */
	if (ds_persistent_state && register_timer("ds-flusher", ds_flusher_routine,
			NULL, 30 , TIMER_FLAG_SKIP_ON_DELAY)<0) {
		LM_ERR("failed to register timer for DB flushing!\n");
		return -1;
	}

	dispatch_evi_id = evi_publish_event(dispatcher_event);
	if (dispatch_evi_id == EVI_ERROR)
		LM_ERR("cannot register dispatcher event\n");

	return 0;
}


/*
 * Per process init function
 */
#include "../../pt.h"
static int ds_child_init(int rank)
{
	/* we need DB connection from the worker procs (for the flushing)
	 * and from the main proc (for final flush on shutdown) */
	if ( rank>=PROC_MAIN ) {

		ds_partition_t *partition_it;

		for (partition_it = partitions; partition_it;
				partition_it = partition_it->next){

			if (partition_it->db_url.s)
				if (ds_connect_db(partition_it) != 0) {
					LM_ERR("failed to do DB connect\n");
					return -1;
				}
		}

	}
	return 0;
}


static int mi_child_init(void)
{
	ds_partition_t *partition_it;

	for (partition_it = partitions; partition_it;
			partition_it = partition_it->next)

		if (partition_it->db_url.s)
			if (ds_connect_db(partition_it) != 0)
				return -1;

	return 0;
}


/**
 * destroy function
 */
static void destroy(void)
{
	LM_DBG("destroying module ...\n");

	/* flush the state of the destinations */
	if (ds_persistent_state)
		ds_flusher_routine(0, NULL);

	ds_partition_t *part_it = partitions, *aux;

	while (part_it) {
		ds_destroy_data(part_it);
		aux = part_it;
		part_it = part_it->next;

		ds_disconnect_db(aux);
		pkg_free(aux->db_handle);
		shm_free(aux);
	}

	/* destroy blacklists */
	destroy_ds_bls();

        /* destroy probing list */
        if (ds_probing_list)
            free_int_list(ds_probing_list, NULL);
}

#define CHECK_AND_EXPAND_LIST(_list_) \
	do{\
		if (_list_->type == GPARAM_TYPE_PVS) { \
			_list_ ## _exp_end = _list_->next; \
			_list_ ## _exp_start = set_list_from_pvs(msg, _list_->v.pvs,\
					_list_->next);\
			if (_list_ ## _exp_start == NULL) {\
				LM_ERR("error when expanding " #_list_ " variable\n");\
				return -1;\
			}\
			_list_ = _list_ ## _exp_start;\
		}\
	} while (0)

#define TRY_FREE_EXPANDED_LIST(_list_) \
	do {\
		if (_list_ ## _exp_start && _list_ == _list_ ## _exp_end) {\
			free_int_list(_list_ ## _exp_start, _list_ ## _exp_end);\
			_list_ ## _exp_start = NULL; \
		}\
	} while (0)

/**
 *
 */
static int w_ds_select(struct sip_msg* msg, char* part_set, char* alg,
											char* max_results_flags, int mode)
{
	int ret = -1;
	int _ret;
	int run_prev_ds_select = 0;
	ds_select_ctl_t prev_ds_select_ctl, ds_select_ctl;
	ds_selected_dst selected_dst;

	if(msg==NULL)
		return -1;

	ds_select_ctl.mode = mode;
	ds_select_ctl.max_results = 1000;
	ds_select_ctl.reset_AVP = 1;
	ds_select_ctl.set_destination = 1;
	ds_select_ctl.ds_flags = 0;

	memset(&selected_dst, 0, sizeof(ds_selected_dst));

	/* Retrieve dispatcher set */
	ds_param_t *part_set_param = (ds_param_t*)part_set;

	if (fixup_get_partition(msg, &part_set_param->partition,
			&ds_select_ctl.partition) != 0 ||ds_select_ctl.partition == NULL) {
		LM_ERR("unknown partition\n");
		return -1;
	}

	int_list_t *set_list = part_set_param->sets;
	int_list_t *set_list_exp_start = NULL, *set_list_exp_end = NULL;

	/* Retrieve dispatcher algorithm */
	int_list_t *alg_list = (int_list_t *)alg;
	int_list_t *alg_list_exp_start = NULL, *alg_list_exp_end = NULL;

	/* In case this parameter is not specified */
	max_list_param_p max_param = (max_list_param_p)max_results_flags;
	str max_list_str;

	int_list_t *max_list=NULL, *max_list_free;
	if (max_param && max_param->type == MAX_LIST_TYPE_STR) {
		max_list = (int_list_t*)max_param->lst.list;
	} else if (max_param && max_param->type == MAX_LIST_TYPE_PV) {
		if (pv_printf_s(msg, max_param->lst.elem, &max_list_str) != 0) {
			LM_ERR("cannot get max list from pv\n");
			return -1;
		}

		if (set_list_from_string(max_list_str, &max_list) != 0
				|| max_list == NULL)
			return -1;
	}

	/* Avoid compiler warning */
	memset(&prev_ds_select_ctl, 0, sizeof(ds_select_ctl_t));

	ds_select_ctl.set_destination = 0;

	/* Parse the params in reverse order.
	 * We need to runt the first entry last to properly populate ds_select_dst
	 *  AVPs.
	 * On the first ds_select_dst run we need to reset AVPs.
	 * On the last ds_select_dst run we need to set destination.  */
	do {
		CHECK_AND_EXPAND_LIST(set_list);
		ds_select_ctl.set = set_list->v.ival;

		CHECK_AND_EXPAND_LIST(alg_list);
		ds_select_ctl.alg = alg_list->v.ival;

		if (max_results_flags) {
			ds_select_ctl.max_results = max_list->v.ival;
			ds_select_ctl.ds_flags    = max_list->flags;
		}

		if (run_prev_ds_select) {
			LM_DBG("ds_select: %d %d %d %d %d\n",
				prev_ds_select_ctl.set, prev_ds_select_ctl.alg,
				prev_ds_select_ctl.max_results,
				prev_ds_select_ctl.reset_AVP,
				prev_ds_select_ctl.set_destination);
			_ret = ds_select_dst(msg, &prev_ds_select_ctl, &selected_dst,
				prev_ds_select_ctl.ds_flags);
			if (_ret>=0) ret = _ret;
			/* stop resetting AVPs. */
			ds_select_ctl.reset_AVP = 0;
		} else {
			/* Enable running ds_select_dst on next loop. */
			run_prev_ds_select = 1;
		}
		prev_ds_select_ctl = ds_select_ctl;

		set_list = set_list->next;
		alg_list = alg_list->next;
		if (max_results_flags) {
			max_list_free = max_list;
			max_list = max_list->next;

			if (max_param->type == MAX_LIST_TYPE_PV)
				pkg_free(max_list_free);
		}

		TRY_FREE_EXPANDED_LIST(set_list);
		TRY_FREE_EXPANDED_LIST(alg_list);

	} while (set_list && alg_list &&
			(max_results_flags ? max_list : set_list));

	if (max_results_flags &&  max_list != NULL) {
		LM_ERR("extra max slot(s) and/or flag(s)\n");
		ret = -2;
		goto error;
	}

	if (set_list != NULL) {
		LM_ERR("extra set(s)\n");
		ret = -2;
		goto error;
	}

	if (alg_list != NULL) {
		LM_ERR("extra algorithm(s)\n");
		ret = -2;
		goto error;
	}

	/* last ds_select_dst run: setting destination. */
	ds_select_ctl.set_destination = 1;
	LM_DBG("ds_select: %d %d %d %d %d\n",
		ds_select_ctl.set, ds_select_ctl.alg, ds_select_ctl.max_results,
		ds_select_ctl.reset_AVP, ds_select_ctl.set_destination);
	_ret = ds_select_dst(msg, &ds_select_ctl, &selected_dst,
		ds_select_ctl.ds_flags);
	if (_ret>=0) {
		ret = _ret;
	}
	else {
		if (selected_dst.uri.s != NULL) {
			if (ds_update_dst(msg, &selected_dst.uri, selected_dst.socket,
			ds_select_ctl.mode) != 0) {
				LM_ERR("cannot set dst addr\n");
				ret = -3;
				goto error;
			}
		}
		else {
			ret = -1;
			goto error;
		}
	}

error:
	if (selected_dst.uri.s != NULL) pkg_free(selected_dst.uri.s);
	return ret;
}

/**
 *
 */
static int w_ds_select_all(struct sip_msg* msg, char* set, char* alg, int mode)
{
	return w_ds_select(msg, set, alg, NULL, mode);
}

/**
 * max_results can also mean the flags parameter
 */
static int w_ds_select_limited(struct sip_msg* msg, char* set, char* alg,
												char* max_results, int mode)
{
	return w_ds_select(msg, set, alg, max_results, mode);
}

/**
 *
 */
static int w_ds_select_dst(struct sip_msg* msg, char* set, char* alg)
{
	return w_ds_select_all(msg, set, alg, 0);
}

/**
 * same wrapper as w_ds_select_dst, but it allows cutting down the result set
 * max_results can also mean flags
 */
static int w_ds_select_dst_limited(struct sip_msg* msg, char* set, char* alg,
															char* max_results)
{
	return w_ds_select_limited(msg, set, alg, max_results, 0);
}

/**
 *
 */
static int w_ds_select_domain(struct sip_msg* msg, char* set, char* alg)
{
	return w_ds_select_all(msg, set, alg, 1);
}

/**
 * same wrapper as w_ds_select_domain, but it allows cutting down the
 *   result set
 * max_results can also mean the flags parameter
 */
static int w_ds_select_domain_limited(struct sip_msg* msg, char* set,
												char* alg, char* max_results)
{
	return w_ds_select_limited(msg, set, alg, max_results, 1);
}

#define GET_AND_CHECK_PARTITION(_param_, _part_) \
	do {\
		if (_param_ == NULL) \
			_part_ = default_partition; \
		else \
			if(fixup_get_partition(msg, (gpartition_t *)_param_, &_part_)!=0) \
			return -1; \
		if (_part_ == NULL) { \
			LM_ERR("Unknown partition\n"); \
			return -1; \
		} \
	} while (0)

/**
 *
 */
static int w_ds_next_dst(struct sip_msg *msg, char *part_param)
{
	ds_partition_t *partition;

	GET_AND_CHECK_PARTITION(part_param, partition);
	return ds_next_dst(msg, 0, partition);
}


/**
 *
 */
static int w_ds_next_domain(struct sip_msg *msg, char *part_param)
{
	ds_partition_t *partition;

	GET_AND_CHECK_PARTITION(part_param, partition);
	return ds_next_dst(msg, 1, partition);
}


/**
 *
 */
static int w_ds_mark_dst(struct sip_msg *msg, char *str1, char *str2)
{
	str arg = {NULL, 0};
	ds_partition_t *partition = default_partition;

	if (str2 != NULL) {
		/* We have two args */
		if (str1 != NULL)
			GET_AND_CHECK_PARTITION(str1, partition);

		if (fixup_get_svalue(msg, (gparam_p)str2, &arg) != 0)
			goto error;
	}
	else {
		if (str1 != NULL && fixup_get_svalue(msg, (gparam_p)str1, &arg) != 0)
				goto error;
	}

	if (arg.len > 1) {
		LM_ERR ("unknown option %.*s\n", arg.len, arg.s);
		return -1;
	}

	if (partition == NULL) {
		LM_ERR ("unknown partition\n");
		return -1;
	}

	if((arg.s == NULL || arg.s[0]=='i' || arg.s[0]=='I' || arg.s[0]=='0'))
		return ds_mark_dst(msg, 0, partition);
	else if(arg.s && (arg.s[0]=='p' || arg.s[0]=='P' || arg.s[0]=='2'))
		return ds_mark_dst(msg, 2, partition);
	else if(arg.s && (arg.s[0]=='a' || arg.s[0]=='A' || arg.s[0]=='1'))
		return ds_mark_dst(msg, 1, partition);
	else {
		LM_ERR ("unknown option %.*s\n", arg.len, arg.s);
		return -1;
	}

error:
	LM_ERR("wrong arguments\n");
	return -1;
}


static int w_ds_mark_dst1(struct sip_msg *msg, char *flags)
{
	return w_ds_mark_dst(msg, flags, NULL);
}



/************************** MI STUFF ************************/

#define MI_ERR_RELOAD 			"ERROR Reloading data"
#define MI_NOT_SUPPORTED		"DB mode not configured"
#define MI_UNK_PARTITION		"ERROR Unknown partition"

static struct mi_root* ds_mi_set(struct mi_root* cmd_tree, void* param)
{
	str sp, partition_name;
	int ret;
	unsigned int group, state;
	struct mi_node* node;
	ds_partition_t *partition;

	node = cmd_tree->node.kids;
	if(node == NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);
	sp = node->value;
	if(sp.len<=0 || !sp.s)
	{
		LM_ERR("bad state value\n");
		return init_mi_tree( 500, MI_SSTR("Bad state value") );
	}

	if(sp.s[0]=='0' || sp.s[0]=='I' || sp.s[0]=='i')
		state = 0;
	else if(sp.s[0]=='p' || sp.s[0]=='P' || sp.s[0]=='2')
		state = 2;
	else if(sp.s[0]=='a' || sp.s[0]=='A' || sp.s[0]=='1')
		state = 1;
	else
		return init_mi_tree( 500, MI_SSTR("Bad state value") );

	node = node->next;
	if(node == NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);
	sp = node->value;
	if(sp.s == NULL)
	{
		return init_mi_tree(500, MI_SSTR("group not found"));
	}

	if (split_partition_argument(&sp, &partition_name) != 0) {
		LM_ERR("bad group format\n");
		return init_mi_tree(500, MI_SSTR("bad group format"));
	}

	partition = find_partition_by_name(&partition_name);
	if (partition == NULL) {
		LM_ERR("partition does not exist\n");
		return init_mi_tree(404, MI_SSTR(MI_UNK_PARTITION) );
	}

	if(str2int(&sp, &group))
	{
		LM_ERR("bad group value\n");
		return init_mi_tree( 500, MI_SSTR("bad group value"));
	}

	node= node->next;
	if(node == NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	sp = node->value;
	if(sp.s == NULL)
	{
		return init_mi_tree(500, MI_SSTR("address not found"));
	}

	if (state==1) {
		/* set active */
		ret = ds_set_state(group, &sp, DS_INACTIVE_DST|DS_PROBING_DST,
			0, partition);
	} else if (state==2) {
		/* set probing */
		ret = ds_set_state(group, &sp, DS_PROBING_DST, 1, partition);
		if (ret==0)
			ret = ds_set_state(group, &sp, DS_INACTIVE_DST, 0, partition);
	} else {
		/* set inactive */
		ret = ds_set_state(group, &sp, DS_INACTIVE_DST, 1, partition);
		if (ret == 0)
			ret = ds_set_state(group, &sp, DS_PROBING_DST, 0, partition);
	}

	if(ret!=0)
		return init_mi_tree(404, MI_SSTR("destination not found"));

	return init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
}


static struct mi_root* ds_mi_list(struct mi_root* cmd_tree, void* param)
{
	struct mi_root* rpl_tree;
	struct mi_node* part_node;
	int flags = 0;

	if (cmd_tree->node.kids){
		if(cmd_tree->node.kids->value.len == 4 && memcmp(cmd_tree->node.kids->value.s,"full",4)==0)
			flags  |= MI_FULL_LISTING;
		else
			return init_mi_tree(400, MI_SSTR(MI_BAD_PARM_S));

	}

	rpl_tree = init_mi_tree(200, MI_OK_S, MI_OK_LEN);
	if (rpl_tree==NULL)
		return 0;
	rpl_tree->node.flags |= MI_IS_ARRAY;

	ds_partition_t *part_it;
	for (part_it = partitions; part_it; part_it = part_it->next) {
		part_node = add_mi_node_child(&rpl_tree->node, MI_IS_ARRAY,"PARTITION",
				9, part_it->name.s, part_it->name.len);

		if (part_node == NULL
			|| ds_print_mi_list(part_node, part_it, flags) < 0) {
		LM_ERR("failed to add node\n");
		free_mi_tree(rpl_tree);
		return 0;
		}
	}

	return rpl_tree;
}


static struct mi_root* ds_mi_reload(struct mi_root* cmd_tree, void* param)
{
	struct mi_node* node = cmd_tree->node.kids;
	if(node != NULL){
		ds_partition_t *partition = find_partition_by_name(&node->value);
		if (partition == NULL)
			return init_mi_tree(500, MI_SSTR(MI_UNK_PARTITION) );
		if (ds_reload_db(partition) < 0)
			return init_mi_tree(500, MI_SSTR(MI_ERR_RELOAD));
		else
			return init_mi_tree(200, MI_SSTR(MI_OK_S) );
	}

	ds_partition_t *part_it;
	for (part_it = partitions; part_it; part_it = part_it->next)
		if (ds_reload_db(part_it)<0)
			return init_mi_tree(500, MI_SSTR(MI_ERR_RELOAD));

	return init_mi_tree(200, MI_SSTR(MI_OK_S));
}


static int w_ds_is_in_list(struct sip_msg *msg,char *ip,char *port,char *set,
															char *active_only)
{
	ds_partition_t *partition = default_partition;
	int i_set = -1;

	if (set != NULL) {
		ds_param_t *setparam = (ds_param_t*)set;
		if (fixup_get_partition(msg, &setparam->partition, &partition) != 0)
			goto wrong_set_arg;

		if (setparam->sets == NULL)
			i_set = -1;
		else
			if (setparam->sets->type == GPARAM_TYPE_INT) {
				if (setparam->sets->next == NULL)
					i_set = setparam->sets->v.ival;
				else {
					LM_ERR("Only one set is allowed\n");
					return -1;
				}
			}
			else {
				int_list_t *tmp_lst =
					set_list_from_pvs(msg, setparam->sets->v.pvs, NULL);
				if (tmp_lst == NULL){
					LM_ERR("Wrong set var value\n");
					return -1;
				}
				if (tmp_lst->next != NULL) {
					LM_ERR("Only one set is allowed\n");
					return -1;
				}
				i_set = tmp_lst->v.ival;
				free_int_list(tmp_lst, NULL);
			}
	}
	if (partition == NULL) {
		LM_ERR ("unknown partition\n");
		return -1;
	}

	return ds_is_in_list(msg, (gparam_t *)ip, (gparam_t *)port, i_set,
			active_only ? *(int *)active_only : 0, partition);

wrong_set_arg:
		LM_ERR("wrong format for set argument\n");
		return -1;
}


static int w_ds_count(struct sip_msg* msg, char *set, const char *cmp,
																	char *res)
{
	unsigned int s = 0;
	gparam_p ret = (gparam_p) res;
	ds_partition_t *partition;

	if (fixup_get_partition_set(msg, (ds_param_t*)set, &partition, &s) != 0){
		LM_ERR("wrong format for set argument. Only one set is accepted\n");
		return -1;
	}

	if (ret->type != GPARAM_TYPE_PVS && ret->type != GPARAM_TYPE_PVE)
	{
		LM_ERR("Result must be a pvar!\n");
		return -1;
	}

	return ds_count(msg, s, cmp, ret->v.pvs, partition);
}


int check_options_rplcode(int code)
{
	int i;

	for (i =0; i< options_codes_no; i++)
	{
		if(options_reply_codes[i] == code)
			return 1;
	}

	return 0;
}


