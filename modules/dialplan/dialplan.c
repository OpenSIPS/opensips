/*
 * Copyright (C)  2007-2008 Voice Sistem SRL
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */


#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include "../../sr_module.h"
#include "../../db/db.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../ut.h"
#include "../../action.h"
#include "../../pvar.h"
#include "../../script_var.h"
#include "../../dset.h"
#include "../../mem/mem.h"
#include "../../mi/mi.h"
#include "../../parser/parse_to.h"
#include "../../mod_fix.h"
#include "../../ipc.h"
#include "dialplan.h"
#include "dp_db.h"



#define DEFAULT_PARAM      "$ruri.user"
#define DEFAULT_PARTITION  "default"
#define PARAM_URL	   "db_url"
#define PARAM_TABLE	   "table_name"
#define DP_CHAR_COLON      ':'
#define DP_CHAR_SLASH      '/'
#define DP_CHAR_EQUAL      '='
#define DP_CHAR_SCOLON     ';'
#define DP_TYPE_URL 	    0
#define DP_TYPE_TABLE 	    1

static int mod_init(void);
static int child_init(int rank);
static int mi_child_init(void);
static void mod_destroy();

static mi_response_t *mi_reload_rules(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_reload_rules_1(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_translate2(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_translate3(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_show_partition(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_show_partition_1(const mi_params_t *params,
								struct mi_handler *async_hdl);


static int dp_translate_f(struct sip_msg *m, int* dpid, str *in_str,
		pv_spec_t *out_var, pv_spec_t *attr_var, dp_connection_list_t *part);
static int fix_partition(void** param);

static int dp_set_partition(modparam_t type, void* val);
static void dp_print_list(void);

static str default_param_s = str_init(DEFAULT_PARAM);
static str default_dp_partition = {NULL, 0};
dp_param_p default_par2 = NULL;
static str database_url = {NULL, 0};


static param_export_t mod_params[]={
	{ "partition",		STR_PARAM|USE_FUNC_PARAM,
				(void*)dp_set_partition},
	{ "db_url",		STR_PARAM,	&default_dp_db_url.s},
	{ "table_name",		STR_PARAM,	&default_dp_table.s },
	{ "dpid_col",		STR_PARAM,	&dpid_column.s },
	{ "pr_col",		STR_PARAM,	&pr_column.s },
	{ "match_op_col",	STR_PARAM,	&match_op_column.s },
	{ "match_exp_col",	STR_PARAM,	&match_exp_column.s },
	{ "match_flags_col",	STR_PARAM,	&match_flags_column.s },
	{ "subst_exp_col",	STR_PARAM,	&subst_exp_column.s },
	{ "repl_exp_col",	STR_PARAM,	&repl_exp_column.s },
	{ "attrs_col",		STR_PARAM,	&attrs_column.s },
	{ "timerec_col",        STR_PARAM,      &timerec_column.s },
	{ "disabled_col",	STR_PARAM,	&disabled_column.s},
	{0,0,0}
};

static mi_export_t mi_cmds[] = {
	{ "dp_reload", 0, 0, mi_child_init, {
		{mi_reload_rules, {0}},
		{mi_reload_rules_1, {"partition", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "dp_translate", 0, 0, 0, {
		{mi_translate2, {"dpid", "input", 0}},
		{mi_translate3, {"partition", "dpid", "input", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "dp_show_partition", 0, 0, mi_child_init, {
		{mi_show_partition, {0}},
		{mi_show_partition_1, {"partition", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};

static cmd_export_t cmds[]={
	{"dp_translate", (cmd_function)dp_translate_f,
		{ {CMD_PARAM_INT, NULL, NULL},
		  {CMD_PARAM_STR, NULL, NULL},
		  {CMD_PARAM_VAR|CMD_PARAM_OPT, NULL, NULL},
		  {CMD_PARAM_VAR|CMD_PARAM_OPT, NULL, NULL},
		  {CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_FIX_NULL, fix_partition,NULL},
		  {0 , 0, 0}
		},
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE|BRANCH_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE
	},
	{0,0,{{0,0,0}},0}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_SQLDB, NULL, DEP_WARN },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

struct module_exports exports= {
	"dialplan",     /* module's name */
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	&deps,           /* OpenSIPS module dependencies */
	cmds,            /* exported functions */
	0,               /* exported async functions */
	mod_params,     /* param exports */
	0,				/* exported statistics */
	mi_cmds,		/* exported MI functions */
	0,				/* exported pseudo-variables */
	0,			 	/* exported transformations */
	0,				/* additional processes */
	0,				/* module pre-initialization function */
	mod_init,		/* module initialization function */
	0,				/* reply processing function */
	mod_destroy,
	child_init,		/* per-child init function */
	0               /* reload confirm function */
};

static dp_head_p dp_get_head(str part_name){

	dp_head_p start;

	for (start = dp_hlist; start &&
				str_strcmp(&part_name, &start->partition);
							  start = start->next);

	return start;

}


/*Inserts table_name/db url into the list of heads*/
static int dp_head_insert(int dp_insert_type, str *content,
				 str *partition)
{
#define h_insert(type, url_str, table_str, ins_str )    \
	do{                                                 \
		if( type == DP_TYPE_URL ) {                     \
			url_str = ins_str;                          \
		} else {                                        \
			table_str = ins_str;                        \
		}                                               \
	}while(0);

	dp_head_p start = dp_hlist;
	dp_head_p tmp = NULL;

	if ((!content && (!content->s || !content->len)) ||
		(!partition && (!partition->s || !partition->len))) {
		LM_ERR("invalid insert in partition!\n");
		return -1;
	}

	/*First Insertion*/
	if (!dp_hlist) {
		dp_hlist = pkg_malloc(sizeof *dp_hlist);
		if (!dp_hlist) {
			LM_ERR("No more pkg mem\n");
			return -1;
		}
		memset(dp_hlist, 0, sizeof *dp_hlist);

		dp_hlist->partition = *partition;

		h_insert( dp_insert_type, dp_hlist->dp_db_url,
				 dp_hlist->dp_table_name, *content);
		return 0;
	}


	/* start can't be null here, should exit on first IF instruction
	 * if null*/
	do {
		if (!str_strcmp(partition, &start->partition)) {
			h_insert( dp_insert_type, start->dp_db_url,
					 start->dp_table_name, *content);
			return 0;
		}
	/* always want second condition to be true since only the
	 * first condition is valid; the second is just an assignment
	 * in case the first one succeeds */
	} while (start->next != NULL && (start=start->next,1));

	tmp = pkg_malloc(sizeof(dp_head_t));

	if (!tmp) {
		LM_ERR("No more pkg mem\n");
		return -1;
	}
	memset(tmp, 0, sizeof(dp_head_t));

	tmp->partition = *partition;

	h_insert( dp_insert_type, tmp->dp_db_url,
			 tmp->dp_table_name, *content);
	start->next = tmp;
	return 0;
#undef h_insert

}

static int dp_create_head(str part_desc)
{

	str tmp;
	str partition;
	str param_type, param_value;

	char* end, *start;
	int ulen = strlen(PARAM_URL), tlen = strlen(PARAM_TABLE);

	tmp.s = part_desc.s;
	end = q_memchr(part_desc.s, DP_CHAR_COLON, part_desc.len);
	if (end == NULL) {
		LM_ERR("[[%s]]\n", tmp.s);
		goto out_err;
	}

	tmp.len = end - tmp.s;
	str_trim_spaces_lr(tmp);

	partition = tmp;

	do {
		start = ++end;

		end = q_memchr(start, DP_CHAR_SCOLON,
				part_desc.s + part_desc.len - start);
		if (end == NULL)
			break;

		param_type.s = start;
		param_value.s = q_memchr(start, DP_CHAR_EQUAL,
				part_desc.len + part_desc.s - start);

		if (param_value.s == 0) {
			LM_ERR("[[%s]]!\n", param_value.s);
			goto out_err;
		}

		param_type.len = param_value.s - param_type.s;
		param_value.len = end - (++param_value.s);

		str_trim_spaces_lr(param_type);
		str_trim_spaces_lr(param_value);

		if (param_type.len == ulen &&
				!memcmp(param_type.s, PARAM_URL, ulen)) {
			dp_head_insert( DP_TYPE_URL, &param_value,
								&partition);
		} else if ( param_type.len == tlen &&
				!memcmp( param_type.s, PARAM_TABLE, tlen)) {
			dp_head_insert( DP_TYPE_TABLE, &param_value,
								&partition);
		} else {
			LM_ERR("Invalid parameter type definition [[%.*s]]\n",
					param_type.len, param_type.s);
			return -1;
		}
	} while(1);

	return 0;

out_err:
	LM_ERR("invalid partition param definition\n");
	return -1;
}


static int dp_set_partition(modparam_t type, void* val)
{

	str p;
	p.s   = (char *)val;
	p.len = strlen(val);

	if (dp_create_head(p)) {
		LM_ERR("Error creating head!\n");
		return -1;
	}

	return 0;
}


static void dp_print_list(void)
{
	dp_head_p start = dp_hlist;

	if (!start)
		LM_DBG("List is empty\n");

	while (start != NULL) {
		LM_DBG("Partition=[%.*s] url=[%.*s] table=[%.*s] next=[%p]\n",
			start->partition.len, start->partition.s,
			start->dp_db_url.len, start->dp_db_url.s,
			start->dp_table_name.len, start->dp_table_name.s, start->next);
		start = (dp_head_p)start->next;
	}
}


static int mod_init(void)
{

	str def_str = str_init(DEFAULT_PARTITION);
	dp_head_p el = dp_get_head(def_str);

	LM_INFO("initializing module...\n");

	dpid_column.len     	= strlen(dpid_column.s);
	pr_column.len       	= strlen(pr_column.s);
	match_op_column.len 	= strlen(match_op_column.s);
	match_exp_column.len	= strlen(match_exp_column.s);
	match_flags_column.len	= strlen(match_flags_column.s);
	subst_exp_column.len	= strlen(subst_exp_column.s);
	repl_exp_column.len 	= strlen(repl_exp_column.s);
	attrs_column.len    	= strlen(attrs_column.s);
	timerec_column.len      = strlen(timerec_column.s);
	disabled_column.len 	= strlen(disabled_column.s);

	if (default_dp_db_url.s) {
		default_dp_db_url.len = strlen(default_dp_db_url.s);

		if (!el) {
			default_dp_partition.len = sizeof(DEFAULT_PARTITION) - 1;
			default_dp_partition.s = pkg_malloc(default_dp_partition.len);

			if (!default_dp_partition.s) {
				LM_ERR("No more pkg memory\n");
				return -1;
			}
			memcpy(default_dp_partition.s, DEFAULT_PARTITION,
							 default_dp_partition.len);
		} else {
			default_dp_partition.s = el->partition.s;
			default_dp_partition.len = el->partition.len;
		}

		dp_head_insert( DP_TYPE_URL, &default_dp_db_url,
							 &default_dp_partition);
	}

	if (default_dp_table.s) {
		if (!default_dp_partition.s) {
			if (!el) {
				LM_ERR("DB URL not defined for default partition!\n");
				return -1;
			} else {
				default_dp_partition.s = el->partition.s;
				default_dp_partition.len = el->partition.len;
			}
		}

		default_dp_table.len = strlen(default_dp_table.s);
		dp_head_insert( DP_TYPE_TABLE, &default_dp_table,
							 &default_dp_partition);
	}

	el = dp_hlist;

	for (el = dp_hlist; el ; el = el->next) {
		//db_url must be set
		if (!el->dp_db_url.s) {
			LM_ERR("DB URL is not defined for partition %.*s!\n",
						el->partition.len,el->partition.s);
			return -1;
		}

		if (!el->dp_table_name.s) {
			el->dp_table_name.len = sizeof(DP_TABLE_NAME) - 1;
			el->dp_table_name.s = pkg_malloc(el->dp_table_name.len);
			if(!el->dp_table_name.s){
				LM_ERR("No more pkg mem\n");
				return -1;
			}
			memcpy(el->dp_table_name.s, DP_TABLE_NAME,
							 el->dp_table_name.len);
		}

	}

	default_par2 = (dp_param_p)shm_malloc(sizeof(dp_param_t));
	if(default_par2 == NULL){
		LM_ERR("no shm more memory\n");
		return -1;
	}
	memset(default_par2, 0, sizeof(dp_param_t));

	default_param_s.len = strlen(default_param_s.s);
	if (pv_parse_spec( &default_param_s, &default_par2->v.sp[0])==NULL) {
		LM_ERR("input pv is invalid\n");
		return -1;
	}

	default_param_s.len = strlen(default_param_s.s);
	if (pv_parse_spec( &default_param_s, &default_par2->v.sp[1])==NULL) {
		LM_ERR("output pv is invalid\n");
		return -1;
	}

	dp_print_list();
	if(init_data() != 0) {
		LM_ERR("could not initialize data\n");
		return -1;
	}

	return 0;
#undef init_db_url_part
}


/* RPC function for (re)loading (no db init) data for all partitions;
 * This is fired from child_init(child==1) only once, so close connections
 * when done */
static void dp_rpc_data_load(int sender_id, void *unused)
{
	if(dp_load_all_db() != 0){
		LM_ERR("failed to reload database\n");
		return;
	}
	dp_disconnect_all_db();
}


static int child_init(int rank)
{
	dp_connection_list_p el;

	/* only process with rank 1 loads data */
	if (rank != 1)
		return 0;

	/* Connect to DBs.... */
	for(el = dp_conns; el; el = el->next){
		if (dp_connect_db(el) != 0) {
			/* all el shall be freed in mod destroy */
			LM_ERR("Unable to init/connect db connection\n");
			return -1;
		}
	}

	/* ...and fire the RPC to perform the data load in the
	 * same process, but after child_init is done */
	if (ipc_send_rpc( process_no, dp_rpc_data_load, NULL)<0) {
		LM_ERR("failed to fire RPC for data load\n");
		return -1;
	}

	return 0;
}


static int mi_child_init(void)
{
	static int mi_child_initialized = 0;
	dp_connection_list_p el;

	if (mi_child_initialized)
		return 0;

	/* Connect to DB s */
	for(el = dp_conns; el; el = el->next){
		if (dp_connect_db(el) != 0) {
			/* all el shall be freed in mod destroy */
			LM_ERR("Unable to init/connect db connection\n");
			return -1;
		}
	}

	mi_child_initialized = 1;
	return 0;
}



static void mod_destroy(void)
{
	/*destroy shared memory*/
	if(default_par2){
		shm_free(default_par2);
		default_par2 = NULL;
	}

	destroy_data();
}


static int dp_update(struct sip_msg * msg, pv_spec_t * src, pv_spec_t * dest,
					 str * repl)
{
	pv_value_t val;

	if (repl->s && repl->len) {
		val.flags = PV_VAL_STR;
		val.rs = *repl;
		if (pv_set_value( msg, dest, 0, &val)!=0) {
			LM_ERR("falied to set the output value!\n");
			return -1;
		}
	}

	return 0;
}


static int fix_partition(void** param)
{
	str def_str = str_init(DEFAULT_PARTITION);
	str *s=(str*)*param;

	/* handle the special case when the fix is triggered for 
	   missing parameter */
	if (s==NULL)
		s = &def_str;

	*param = (void*)dp_get_connection( s );
	if (*param==NULL) {
		LM_ERR("partition <%.*s> not found\n", s->len, s->s);
		return -1;
	}

	return 0;
}


#define verify_par_type(_spec)\
	do{\
		if( ( ((_spec).type==PVT_NULL) || ((_spec).type==PVT_EMPTY) \
		|| ((_spec).type==PVT_NONE) )) { \
			LM_ERR("NULL/EMPTY Parameter TYPE\n");\
				return E_UNSPEC;\
		}\
	}while(0);


static int dp_translate_f(struct sip_msg *msg, int* dpid, str *in_str,
		pv_spec_t *out_var, pv_spec_t *attr_var, dp_connection_list_t *part)
{

	dpl_id_p idp;
	str out_str, attrs;
	pv_value_t pval;

	if (!msg)
		return -1;

	LM_DBG("dpid is %i partition is %.*s\n", *dpid,
		part->partition.len, part->partition.s);

	LM_DBG("input is %.*s\n", in_str->len, in_str->s);

	/* ref the data for reading */
	lock_start_read( part->ref_lock );

	if ((idp = select_dpid(part, *dpid, part->crt_index)) == 0) {
		LM_DBG("no information available for dpid %i\n", *dpid);
		goto error;
	}
	LM_DBG("checking with dpid %i\n", idp->dp_id);

	if (translate(msg, *in_str, &out_str, idp, attr_var?&attrs:NULL) != 0) {
		LM_DBG("could not translate\n");
		goto error;
	}

	LM_DBG("input %.*s with dpid %i => output %.*s\n",
			in_str->len, in_str->s, idp->dp_id, out_str.len, out_str.s);

	if (out_var) {
		verify_par_type(*out_var);
		/* set the output */
		if (dp_update( msg, NULL, out_var, &out_str) != 0) {
			LM_ERR("cannot set the output\n");
			goto error;
		}
	}

	/* we are done reading -> unref the data */
	lock_stop_read( part->ref_lock );

	if (attr_var && attrs.s && attrs.len) {
		verify_par_type(*attr_var);
		pval.flags = PV_VAL_STR;
		pval.rs = attrs;

		if (pv_set_value(msg, attr_var, 0, &pval) != 0) {
			LM_ERR("failed to set value '%.*s' for the attr pvar!\n",
					attrs.len, attrs.s);
			goto error;
		}
	}

	return 1;

error:
	/* we are done reading -> unref the data */
	lock_stop_read( part->ref_lock );

	return -1;
}


/* creates an url string without password field*/
static void db_get_url(const str* url){
	struct db_id* id = new_db_id(url);
	static str scheme_delimiter={"://",3};
	static str port_delimiter={":",1};
	static str host_delimiter={"@",1};
	static str database_delimiter={"/",1};
	str port;

	/* allocate memory for the database url if necessary*/
	database_url.len = 0;

	/* sanity checks */
	if (id == NULL)
		return;

	database_url.s = pkg_realloc(database_url.s, url->len * sizeof(char));

	if (database_url.s == NULL) {
		free_db_id(id);
		return;
	}

	/* shortest database_url is s://a/b so we always need the scheme delimiter*/
	if (id->scheme != NULL) {
		memcpy(database_url.s + database_url.len, id->scheme, strlen(id->scheme));
		database_url.len += strlen(id->scheme);
		memcpy(database_url.s + database_url.len, scheme_delimiter.s, scheme_delimiter.len);
		database_url.len += scheme_delimiter.len;
	}

	if (id->username != NULL) {
		memcpy(database_url.s + database_url.len, id->username, strlen(id->username));
		database_url.len += strlen(id->username);
	}

	if (id->host != NULL) {
		memcpy(database_url.s + database_url.len, host_delimiter.s, host_delimiter.len);
		database_url.len += host_delimiter.len;
		memcpy(database_url.s + database_url.len, id->host, strlen(id->host));
		database_url.len += strlen(id->host);
	}

	if (id->port > 0) {
		port.s = int2str(id->port,&port.len);
		memcpy(database_url.s + database_url.len, port_delimiter.s, port_delimiter.len);
		database_url.len += port_delimiter.len;
		memcpy(database_url.s + database_url.len, port.s, port.len);
		database_url.len += port.len;
	}

	if (id->database != NULL){
		memcpy(database_url.s + database_url.len,
			database_delimiter.s, database_delimiter.len);
		database_url.len += database_delimiter.len;
		memcpy(database_url.s + database_url.len, id->database, strlen(id->database));
		database_url.len += strlen(id->database);
	}

	/* free alocated memory */
	free_db_id(id);
}

static mi_response_t *mi_show_partition(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	mi_item_t *parts_arr, *part_item;
	dp_connection_list_t *el;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	parts_arr = add_mi_array(resp_obj, MI_SSTR("Partitions"));
	if (parts_arr)
		goto error;

	el = dp_get_connections();
	while (el) {
		part_item = add_mi_object(parts_arr, NULL, 0);
		if (!part_item)
			goto error;

		if (add_mi_string(part_item, MI_SSTR("name"),
			el->partition.s, el->partition.len) < 0)
			goto error;

		if (add_mi_string(resp_obj, MI_SSTR("Table"),
				el->table_name.s, el->table_name.len) < 0)
				goto error;

		db_get_url(&el->db_url);
		if(database_url.len == 0) goto error;

		if (add_mi_string(resp_obj, MI_SSTR("db_url"),
			database_url.s, database_url.len) < 0)
			goto error;

		el = el->next;
	}

	return resp;

error:
	free_mi_response(resp);
	return 0;
}

static mi_response_t *mi_show_partition_1(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	str part;
	dp_connection_list_t *el;

	if (get_mi_string_param(params, "partition", &part.s, &part.len) < 0)
		return init_mi_param_error();

	el = dp_get_connection(&part);
	if (!el)
		return 0;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if (add_mi_string(resp_obj, MI_SSTR("Partition"),
		el->partition.s, el->partition.len) < 0)
		goto error;

	if (add_mi_string(resp_obj, MI_SSTR("Table"),
		el->table_name.s, el->table_name.len) < 0)
		goto error;

	db_get_url(&el->db_url);
	if(database_url.len == 0) goto error;

	if (add_mi_string(resp_obj, MI_SSTR("db_url"),
		database_url.s, database_url.len) < 0)
		goto error;

	return resp;

error:
	free_mi_response(resp);
	return 0;
}

static mi_response_t *mi_reload_rules(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	if(dp_load_all_db() != 0){
			LM_ERR("failed to reload database\n");
			return 0;
	}

	return init_mi_result_ok();
}

static mi_response_t *mi_reload_rules_1(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	dp_connection_list_t *el;
	str table;

	if (get_mi_string_param(params, "partition", &table.s, &table.len) < 0)
		return init_mi_param_error();

	el = dp_get_connection(&table);
	if (!el)
			return init_mi_error( 400, MI_SSTR("Partition not found"));
	/* Reload rules from specified  partition */
	LM_DBG("Reloading rules from partition %.*s\n", table.len, table.s);
	if(dp_load_db(el) != 0){
			LM_ERR("failed to reload database data\n");
			return 0;
	}

	return init_mi_result_ok();
}

/*
 *  mi cmd:  dp_translate
 *			<dialplan id>
 *			<input>
 *		* */

static mi_response_t *mi_translate(const mi_params_t *params,
												dp_connection_list_t *part)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	dpl_id_p idp;
	str dpid_str;
	str input;
	int dpid;
	str attrs;
	str output= {0, 0};

	if (get_mi_string_param(params, "dpid", &dpid_str.s, &dpid_str.len) < 0)
		return init_mi_param_error();

	if(dpid_str.s == NULL || dpid_str.len== 0)	{
		LM_ERR( "empty dpid parameter\n");
		return init_mi_error(404, MI_SSTR("Empty id parameter"));
	}

	if(str2sint(&dpid_str, &dpid) != 0)	{
		LM_ERR("Wrong id parameter - should be an integer\n");
		return init_mi_error(404, MI_SSTR("Wrong id parameter"));
	}

	if (get_mi_string_param(params, "input", &input.s, &input.len) < 0)
		return init_mi_param_error();

	if(input.s == NULL || input.len== 0) {
		LM_ERR( "empty input parameter\n");
		return init_mi_error(404, MI_SSTR("Empty input parameter"));
	}

	/* ref the data for reading */
	lock_start_read( part->ref_lock );

	if ((idp = select_dpid(part, dpid, part->crt_index)) ==0 ){
		LM_ERR("no information available for dpid %i\n", dpid);
		lock_stop_read( part->ref_lock );
		return init_mi_error(404, MI_SSTR("No information available for dpid"));
	}

	if (translate(NULL, input, &output, idp, &attrs)!=0){
		LM_DBG("could not translate %.*s with dpid %i\n",
			input.len, input.s, idp->dp_id);
		lock_stop_read( part->ref_lock );
		return init_mi_error(404, MI_SSTR("No translation"));
	}
	/* we are done reading -> unref the data */
	lock_stop_read( part->ref_lock );

	LM_DBG("input %.*s with dpid %i => output %.*s\n",
			input.len, input.s, idp->dp_id, output.len, output.s);

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if (add_mi_string(resp_obj, MI_SSTR("Output"), output.s, output.len) < 0)
		goto error;
	
	if (add_mi_string(resp_obj, MI_SSTR("ATTRIBUTES"), attrs.s, attrs.len) < 0)
		goto error;

	return resp;

error:
	free_mi_response(resp);
	return 0;
}


static mi_response_t *mi_translate2(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str def_str = str_init(DEFAULT_PARTITION);
	dp_connection_list_t *part;

	part = dp_get_connection(&def_str);
	if (part==NULL){
		LM_ERR("translating without partition, but no default defined\n");
		return init_mi_error(400, MI_SSTR("Default partition not found"));
	}
	return mi_translate( params, part);
}


static mi_response_t *mi_translate3(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	dp_connection_list_t *part;
	str name;

	if (get_mi_string_param(params, "partition", &name.s, &name.len) < 0)
		return init_mi_param_error();

	part = dp_get_connection(&name);
	if (part==NULL) {
		LM_ERR("Unable to find partition <%.*s>\n",name.len,name.s);
		return init_mi_error(400, MI_SSTR("Partition not found"));
	}

	return mi_translate( params, part);
}


void * wrap_shm_malloc(size_t size)
{
	return shm_malloc(size);
}

void  wrap_shm_free(void * p )
{
	shm_free(p);
}


pcre * wrap_pcre_compile(char *  pattern, int flags)
{
		pcre * ret ;
		func_malloc old_malloc ;
		func_free old_free;
		const char * error;
		int erroffset;
		int pcre_flags = 0;


		old_malloc = pcre_malloc;
		old_free = pcre_free;

		pcre_malloc = wrap_shm_malloc;
		pcre_free = wrap_shm_free;

		if (flags & DP_CASE_INSENSITIVE)
			pcre_flags |= PCRE_CASELESS;

		ret = pcre_compile(
				pattern,			/* the pattern */
				pcre_flags,			/* default options */
				&error,				/* for error message */
				&erroffset,			/* for error offset */
				NULL);

		pcre_malloc = old_malloc;
		pcre_free = old_free;

		return ret;
}

void wrap_pcre_free( pcre* re)
{
	shm_free(re);

}
