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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * --------
 *  2007-08-01 initial version (ancuta onofrei)
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
#define is_space(p) (*(p) == ' ' || *(p) == '\t' || \
					 *(p) == '\r' || *(p) == '\n')

static int mod_init(void);
static int child_init(int rank);
static int mi_child_init(void);
static void mod_destroy();

static struct mi_root * mi_reload_rules(struct mi_root *cmd_tree,void *param);
static struct mi_root * mi_translate(struct mi_root *cmd_tree, void *param);
static struct mi_root * mi_show_partition(struct mi_root *cmd_tree, void *param);
static int dp_translate_f(struct sip_msg *m, char *id, char *out, char *attrs);
static int dp_trans_fixup(void ** param, int param_no);
static int dp_set_partition(modparam_t type, void* val);
static void dp_print_list(void);

str default_param_s = str_init(DEFAULT_PARAM);
str default_dp_partition = {NULL, 0};
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
	{ "dp_reload",  0, mi_reload_rules,   0,       0,  mi_child_init},
	{ "dp_translate",  0, mi_translate,   0,       0,              0},
	{ "dp_show_partition",  0, mi_show_partition,   0,       0,              0},
	{ 0, 0, 0, 0, 0, 0}
};

static cmd_export_t cmds[]={
	{"dp_translate",(cmd_function)dp_translate_f,	3,	dp_trans_fixup,  0,
			REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE|BRANCH_ROUTE|
			STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"dp_translate",(cmd_function)dp_translate_f,	2,	dp_trans_fixup,  0,
			REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE|BRANCH_ROUTE|
			STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"dp_translate",(cmd_function)dp_translate_f,	1,	dp_trans_fixup,  0,
			REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE|BRANCH_ROUTE|
			STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{0,0,0,0,0,0}
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
	&deps,           /* OpenSIPS module dependencies */
	cmds,            /* exported functions */
	0,               /* exported async functions */
	mod_params,     /* param exports */
	0,				/* exported statistics */
	mi_cmds,		/* exported MI functions */
	0,				/* exported pseudo-variables */
	0,			 	/* exported transformations */
	0,				/* additional processes */
	mod_init,		/* module initialization function */
	0,				/* reply processing function */
	mod_destroy,
	child_init		/* per-child init function */
};

static inline char* strchrchr(char* str, char c1, char c2)
{

	char* ret = NULL;

	if (!str)
		return NULL;

	for (ret = str; (ret = *ret == '\0' ? NULL : ret)
			&& *ret !=  c1 && *ret != c2; ret++);

	return ret;
}

static inline char* memchrchr(char* str, char c1, char c2, int len)
{

	int i;

	if (len == 0)
		return NULL;

	for (i = 0; i < len; i++) {
		register char c = *(str + i);
		if(c == c1 || c == c2)
			return str + i;
	}

	return NULL;

}


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

static int child_init(int rank)
{
	dp_connection_list_p el;

	/* only process with rank 1 loads data */
	if (rank != 1)
		return 0;

	/*Connect to DB s and get rules*/
	for(el = dp_conns; el; el = el->next){
		if (init_db_data(el) != 0) {
			/* all el shall be freed in mod destroy */
			LM_ERR("Unable to init db data\n");
			return -1;
		}
	}

	dp_disconnect_all_db();

	return 0;
}
static int mi_child_init(void)
{

	dp_connection_list_p el;

	/*Connect to DB s and get rules*/
	for(el = dp_conns; el; el = el->next){
		if (dp_connect_db(el) != 0) {
			/* all el shall be freed in mod destroy */
			LM_ERR("Unable to init db data\n");
			return -1;
		}
	}

	return 0;
}



static void mod_destroy(void)
{
	dp_connection_list_p el;
	/*destroy shared memory*/
	if(default_par2){
		shm_free(default_par2);
		default_par2 = NULL;
	}

	LM_DBG("Disconnecting from all databases\n");
	for(el = dp_conns; el ; el = el->next){
		dp_disconnect_db(el);

		LM_DBG("Successfully disconnected from DB %.*s\n" ,
						 el->db_url.len, el->db_url.s);
	}


	destroy_data();
}


static int dp_get_ivalue(struct sip_msg* msg, dp_param_p dp, int *val)
{
	pv_value_t value;

	switch (dp->type) {
		case DP_VAL_STR :
			*val = dp->v.id;
			return 0;
		case DP_VAL_INT :
			*val = dp->v.pv_id.id;
			return 0;
		default :
			break;
	}

	LM_DBG("searching %d\n",dp->v.sp[0].type);

	if (pv_get_spec_value( msg, &dp->v.sp[0], &value)!=0) {
		LM_ERR("no PV found (error in script)\n");
		return -1;
	}

	if (value.flags&(PV_VAL_NULL|PV_VAL_EMPTY)) {
		LM_ERR("NULL or empty val found (error in script)\n");
		return -1;
	}

	if (value.flags&PV_VAL_INT) {
		*val = value.ri;
	} else if (value.flags&PV_VAL_STR) {
		if (str2sint(&value.rs, val) != 0) {
			LM_ERR("Unbale to convert to INT [%.*s]\n", value.rs.len, value.rs.s);
			return -1;
		}
	} else {
		LM_ERR("non-INT/STR val found (error in script)\n");
		return -1;
	}

	return 0;
}


static int dp_get_svalue(struct sip_msg * msg, pv_spec_t spec, str* val)
{
	pv_value_t value;

	LM_DBG("searching %d \n", spec.type);

	if ( pv_get_spec_value(msg,&spec,&value)!=0 || value.flags&PV_VAL_NULL
	|| value.flags&PV_VAL_EMPTY || !(value.flags&PV_VAL_STR)){
			LM_ERR("no PV or NULL or non-STR val found (error in script)\n");
			return -1;
	}

	*val = value.rs;
	return 0;
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

static int dp_translate_f(struct sip_msg *msg, char *str1, char *str2,
						  char *attr_spec)
{

	int dpid;
	str input, output;
	dpl_id_p idp;
	dp_param_p id_par, repl_par;
	str attrs, *attrs_par;
	dp_connection_list_p connection;
	pv_value_t pval;
	str partition_name;

	if (!msg)
		return -1;

	/* verify first param's value */
	id_par = (dp_param_p) str1;

	if (dp_get_ivalue(msg, id_par, &dpid) != 0){
		LM_ERR("no dpid value\n");
		return -1;
	}

	switch( id_par->type ) {
		case DP_VAL_INT :
			if (dp_get_svalue(msg, id_par->v.pv_id.partition,
								&partition_name)) {
				LM_ERR("invalid partition\n");
				return -1;
			}
			goto GET_CONN;
		case DP_VAL_SPEC :
			if (dp_get_svalue(msg, id_par->v.sp[1],
								&partition_name)) {
				LM_ERR("invalid partition\n");
				return -1;
			}
		GET_CONN:
			if (!(id_par->hash = dp_get_connection(&partition_name))) {
				LM_ERR("invalid partition\n");
				return -1;
			}

			break;
		default :
			break;
	}

	LM_DBG("dpid is %i partition is %.*s\n", dpid,
			id_par->hash->partition.len, id_par->hash->partition.s);

	repl_par = (str2!=NULL) ? ((dp_param_p)str2) : default_par2;
	if (dp_get_svalue(msg, repl_par->v.sp[0], &input)!=0){
		LM_ERR("invalid param 2\n");
		return -1;
	}

	LM_DBG("input is %.*s\n", input.len, input.s);
	connection = id_par->hash;

	/* ref the data for reading */
	lock_start_read( connection->ref_lock );

	if ((idp = select_dpid(connection, dpid, connection->crt_index)) == 0) {
		LM_DBG("no information available for dpid %i\n", dpid);
		goto error;
	}

	LM_DBG("Checking with dpid %i\n", idp->dp_id);

	attrs_par =  attr_spec ? &attrs : NULL;
	if (translate(msg, input, &output, idp, attrs_par) != 0) {
		LM_DBG("could not translate %.*s "
			"with dpid %i\n", input.len, input.s, idp->dp_id);
		goto error;
	}

	LM_DBG("input %.*s with dpid %i => output %.*s\n",
			input.len, input.s, idp->dp_id, output.len, output.s);

	/* set the output */
	if (dp_update(msg, &repl_par->v.sp[0], &repl_par->v.sp[1], &output) != 0) {
		LM_ERR("cannot set the output\n");
		goto error;
	}

	/* we are done reading -> unref the data */
	lock_stop_read( connection->ref_lock );

	if (attr_spec && attrs.s && attrs.len) {
		pval.flags = PV_VAL_STR;
		pval.rs = attrs;

		if (pv_set_value(msg, (pv_spec_p)attr_spec, 0, &pval) != 0) {
			LM_ERR("failed to set value '%.*s' for the attr pvar!\n",
					attrs.len, attrs.s);
			goto error;
		}
	}

	return 1;

error:
	/* we are done reading -> unref the data */
	lock_stop_read( connection->ref_lock );

	return -1;
}

#define verify_par_type(_spec)\
	do{\
		if( ( ((_spec).type==PVT_NULL) || ((_spec).type==PVT_EMPTY) \
		|| ((_spec).type==PVT_NONE) )) { \
			LM_ERR("NULL/EMPTY Parameter TYPE\n");\
				return E_UNSPEC;\
		}\
	}while(0);

/**
 * Parses a dp command of the type "table_name/dpid". Skips all whitespaces.
 */

static char *parse_dp_command(char * p, int len, str * partition_name)
{
	char *s, *q;

	while (is_space(p)) {
		p++;
		len--;
	}

	if (len <= 0) {
		s = strchrchr(p, DP_CHAR_SLASH, DP_CHAR_COLON);
	} else {
		s = memchrchr(p, DP_CHAR_SLASH, DP_CHAR_COLON, len);
	}
	if (s != 0) {
		q = s+1;

		while (s > p && is_space(s-1))
			s--;

		if (s == p || (*q == '\0'))
			return NULL;

		partition_name->s = p;
		partition_name->len = s-p;

		p = q;

		while (is_space(p))
			p++;

	} else {
		partition_name->s = 0;
		partition_name->len = 0;
	}

	return p;
}

#undef is_space

/* first param: DPID: type: INT, AVP, SVAR
 * second param: SRC/DST type: RURI, RURI_USERNAME, AVP, SVAR
 * default value for the second param: $ru.user/$ru.user
 */
static int dp_trans_fixup(void ** param, int param_no){

	int dpid;
	dp_param_p dp_par= NULL;
	char *p, *s = NULL;
	str lstr, partition_name;
	dp_connection_list_t *list = NULL;

	if (param_no < 1 || param_no > 3)
		return 0;

	p = (char*)*param;
	if(!p || (*p == '\0')){
		LM_DBG("null param %i\n", param_no);
		return E_CFG;
	}

	dp_par = (dp_param_p)pkg_malloc(sizeof(dp_param_t));
	if(dp_par == NULL){
		LM_ERR("no more pkg memory\n");
		return E_OUT_OF_MEM;
	}
	memset(dp_par, 0, sizeof(dp_param_t));

	switch (param_no) {
	case 1:
		p = parse_dp_command(p, -1, &partition_name);

		if (p == NULL) {
			LM_ERR("Invalid dp command\n");
			return E_CFG;
		}

		if (!partition_name.s && !partition_name.len) {
			partition_name.s = DEFAULT_PARTITION;
			partition_name.len = sizeof(DEFAULT_PARTITION) - 1;
		}

		if (*partition_name.s != PV_MARKER) {
			list = dp_get_connection(&partition_name);

			if(!list){
				LM_ERR("Partition with name [%.*s] is not defined\n",
						partition_name.len, partition_name.s );
				return -1;
			}
			dp_par->type = DP_VAL_STR;

		} else {
			dp_par->type = DP_VAL_SPEC;
		}

		if (*p != PV_MARKER) {
			lstr.s = p; lstr.len = strlen(p);
			if(str2sint(&lstr, &dpid) != 0) {
				LM_ERR("bad number <%s>\n",(char *)(*param));
				pkg_free(dp_par);
				return E_CFG;
			}

			if(dp_par->type == DP_VAL_SPEC){
				/*int dpid and pv partition_name*/
				dp_par->type = DP_VAL_INT;
				dp_par->v.pv_id.id = dpid;
				if( !pv_parse_spec( &partition_name,
						&dp_par->v.pv_id.partition))
					goto error;
			} else {
				/*DP_VAL_STR remains DP_VAL_STR
					   ( int dpid and str partition_name)*/
				dp_par->v.id = dpid;
			}
		} else {
			if (dp_par->type == DP_VAL_STR) {
				/*pv dpid and str partition_name*/
				dp_par->type = DP_VAL_STR_SPEC;
			} else {
				/*DP_VAL_SPEC remains DP_VAL_SPEC
						( pv dpid and pv partition_name) */
				if( !pv_parse_spec( &partition_name,
							 &dp_par->v.sp[1]))
					goto error;
			}

			lstr.s = p; lstr.len = strlen(p);
			if (pv_parse_spec( &lstr, &dp_par->v.sp[0])==NULL)
				goto error;

			verify_par_type(dp_par->v.sp[0]);
		}

		dp_par->hash = list;
		break;

	case 2:
		if( ((s = strchr(p, '/')) == 0) ||( *(s+1)=='\0'))
				goto error;
		*s = '\0'; s++;

		lstr.s = p; lstr.len = strlen(p);
		if(pv_parse_spec( &lstr, &dp_par->v.sp[0])==NULL)
			goto error;

		verify_par_type(dp_par->v.sp[0]);

		lstr.s = s; lstr.len = strlen(s);
		if (pv_parse_spec( &lstr, &dp_par->v.sp[1] )==NULL)
			goto error;

		verify_par_type(dp_par->v.sp[1]);
		if (dp_par->v.sp[1].setf==NULL) {
			LM_ERR("the output PV is read-only!!\n");
			return E_CFG;
		}

		dp_par->type = DP_VAL_SPEC;
		break;

	case 3:
		return fixup_pvar(param);
	}

	*param = (void *)dp_par;

	return 0;

error:
	LM_ERR("failed to parse param %i\n", param_no);
	return E_INVALID_PARAMS;
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

static struct mi_root * mi_show_partition(struct mi_root *cmd_tree, void *param)
{
	struct mi_node *node = NULL;
	struct mi_root *rpl_tree = NULL;
	struct mi_node* root= NULL;
	struct mi_attr* attr;
	dp_connection_list_t *el;


	rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
	if (rpl_tree==NULL) return NULL;

	if (cmd_tree) node = cmd_tree->node.kids;
	if (node == NULL) {
		el = dp_get_connections();
		root = &rpl_tree->node;
		while (el) {
			node = add_mi_node_child(root, 0, "Partition", 9, el->partition.s, el->partition.len);
			if( node == NULL) goto error;
			attr = add_mi_attr(node, 0, "table", 5, el->table_name.s, el->table_name.len);
			if(attr == NULL) goto error;
			db_get_url(&el->db_url);
			if(database_url.len == 0) goto error;
			attr = add_mi_attr(node, MI_DUP_VALUE, "db_url", 6, database_url.s, database_url.len);
			if(attr == NULL) goto error;
			el = el->next;
		}
	} else {
		el = dp_get_connection(&node->value);
		if (!el) goto error;
		root = &rpl_tree->node;
		node = add_mi_node_child(root, 0, "Partition", 9, el->partition.s, el->partition.len);
		if( node == NULL) goto error;
		attr = add_mi_attr(node, 0, "table", 5, el->table_name.s, el->table_name.len);
		if(attr == NULL) goto error;
		db_get_url(&el->db_url);
		if(database_url.len == 0) goto error;
		attr = add_mi_attr(node, MI_DUP_VALUE, "db_url", 6, database_url.s, database_url.len);
		if(attr == NULL) goto error;
	}

	return rpl_tree;

error:
	if(rpl_tree) free_mi_tree(rpl_tree);
	return NULL;
}

static struct mi_root * mi_reload_rules(struct mi_root *cmd_tree, void *param)
{
	struct mi_node *node = NULL;
	struct mi_root *rpl_tree = NULL;
	dp_connection_list_t *el;


	if (cmd_tree)
		node = cmd_tree->node.kids;

	if (node == NULL) {
			/* Reload rules from all partitions */
			if(dp_load_all_db() != 0){
					LM_ERR("failed to reload database\n");
					return 0;
			}
	} else if (node->value.s == NULL || node->value.len == 0) {
			return init_mi_tree( 400, MI_BAD_PARM_S, MI_BAD_PARM_LEN);
	} else {
			el = dp_get_connection(&node->value);
			if (!el)
					return init_mi_tree( 400, MI_BAD_PARM_S, MI_BAD_PARM_LEN);
			/* Reload rules from specified  partition */
			LM_DBG("Reloading rules from table %.*s\n", node->value.len, node->value.s);
			if(dp_load_db(el) != 0){
					LM_ERR("failed to reload database data\n");
					return 0;
			}
	}

	rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
	if (rpl_tree==0)
		return 0;

	return rpl_tree;
}

/*
 *  mi cmd:  dp_translate
 *			<dialplan id>
 *			<input>
 *		* */

static struct mi_root * mi_translate(struct mi_root *cmd, void *param)
{
	struct mi_root* rpl= NULL;
	struct mi_node* root, *node;
	char *p;
	dpl_id_p idp;
	str dpid_str, partition_str;
	str input;
	int dpid;
	str attrs;
	str output= {0, 0};
	dp_connection_list_p connection = NULL;

	node = cmd->node.kids;
	if(node == NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	/* Get the id parameter */
	dpid_str = node->value;
	if(dpid_str.s == NULL || dpid_str.len== 0)	{
		LM_ERR( "empty idp parameter\n");
		return init_mi_tree(404, "Empty id parameter", 18);
	}

	p = parse_dp_command(dpid_str.s, dpid_str.len, &partition_str);

	if (p == NULL) {
		LM_ERR("Invalid dp command\n");
		return init_mi_tree(404, "Invalid dp command", 18);
	}

	if (partition_str.s == NULL || partition_str.len == 0) {
		partition_str.s = DEFAULT_PARTITION;
		partition_str.len = sizeof(DEFAULT_PARTITION) - 1;
	}

	connection = dp_get_connection(&partition_str);

	dpid_str.len -= (p - dpid_str.s);
	dpid_str.s = p;

	if (!connection) {
		LM_ERR("Unable to get connection\n");
		return init_mi_tree(400, "Wrong db connection parameter", 24);
	}

	if(str2sint(&dpid_str, &dpid) != 0)	{
		LM_ERR("Wrong id parameter - should be an integer\n");
		return init_mi_tree(404, "Wrong id parameter", 18);
	}
	node = node->next;
	if(node == NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	if(node->next!= NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	input = node->value;
	if(input.s == NULL || input.len== 0)	{
		LM_ERR( "empty input parameter\n");
		return init_mi_tree(404, "Empty input parameter", 21);
	}

	/* ref the data for reading */
	lock_start_read( connection->ref_lock );

	if ((idp = select_dpid(connection, dpid, connection->crt_index)) ==0 ){
		LM_ERR("no information available for dpid %i\n", dpid);
		lock_stop_read( connection->ref_lock );
		return init_mi_tree(404, "No information available for dpid", 33);
	}

	if (translate(NULL, input, &output, idp, &attrs)!=0){
		LM_DBG("could not translate %.*s with dpid %i\n",
			input.len, input.s, idp->dp_id);
		lock_stop_read( connection->ref_lock );
		return init_mi_tree(404, "No translation", 14);
	}
	/* we are done reading -> unref the data */
	lock_stop_read( connection->ref_lock );

	LM_DBG("input %.*s with dpid %i => output %.*s\n",
			input.len, input.s, idp->dp_id, output.len, output.s);

	rpl = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
	if (rpl==0)
		goto error;

	root= &rpl->node;

	node = add_mi_node_child(root, 0, "Output", 6, output.s, output.len );
	if( node == NULL)
		goto error;

	node = add_mi_node_child(root, 0, "ATTRIBUTES", 10, attrs.s, attrs.len);
	if( node == NULL)
		goto error;

	return rpl;

error:
	if(rpl)
		free_mi_tree(rpl);
	return 0;
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
