/*
 *  $Id$
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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



#define DEFAULT_PARAM    "$ruri.user"

static int mod_init(void);
static int child_init(int rank);
static void mod_destroy();
static int mi_child_init();

static struct mi_root * mi_reload_rules(struct mi_root *cmd_tree,void *param);
static struct mi_root * mi_translate(struct mi_root *cmd_tree, void *param);
static int dp_translate_f(struct sip_msg *m, char *id, char *out, char *attrs);
static int dp_trans_fixup(void ** param, int param_no);

str default_param_s = str_init(DEFAULT_PARAM);
dp_param_p default_par2 = NULL;

static param_export_t mod_params[]={
	{ "db_url",			STR_PARAM,	&dp_db_url.s },
	{ "table_name",		STR_PARAM,	&dp_table_name.s },
	{ "dpid_col",		STR_PARAM,	&dpid_column.s },
	{ "pr_col",			STR_PARAM,	&pr_column.s },
	{ "match_op_col",	STR_PARAM,	&match_op_column.s },
	{ "match_exp_col",	STR_PARAM,	&match_exp_column.s },
	{ "match_flags_col",STR_PARAM,	&match_flags_column.s },
	{ "subst_exp_col",	STR_PARAM,	&subst_exp_column.s },
	{ "repl_exp_col",	STR_PARAM,	&repl_exp_column.s },
	{ "attrs_col",		STR_PARAM,	&attrs_column.s },
	{ "disabled_col",	STR_PARAM,	&disabled_column.s},
	{0,0,0}
};

static mi_export_t mi_cmds[] = {
	{ "dp_reload",  0, mi_reload_rules,   MI_NO_INPUT_FLAG,  0,  mi_child_init},
	{ "dp_translate",  0, mi_translate,   0,                 0,  0},
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

struct module_exports exports= {
	"dialplan",     /* module's name */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	cmds,      	    /* exported functions */
	mod_params,     /* param exports */
	0,				/* exported statistics */
	mi_cmds,		/* exported MI functions */
	0,				/* exported pseudo-variables */
	0,				/* additional processes */
	mod_init,		/* module initialization function */
	0,				/* reply processing function */
	mod_destroy,
	child_init		/* per-child init function */
};


static int mod_init(void)
{
	LM_INFO("initializing module...\n");

	init_db_url( dp_db_url , 0 /*cannot be null*/);
	dp_table_name.len   	= strlen(dp_table_name.s);
	dpid_column.len     	= strlen( dpid_column.s);
	pr_column.len       	= strlen(pr_column.s);
	match_op_column.len 	= strlen(match_op_column.s);
	match_exp_column.len	= strlen(match_exp_column.s);
	match_flags_column.len	= strlen(match_flags_column.s);
	subst_exp_column.len	= strlen(subst_exp_column.s);
	repl_exp_column.len 	= strlen(repl_exp_column.s);
	attrs_column.len    	= strlen(attrs_column.s);
	disabled_column.len 	= strlen(disabled_column.s);

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

	if(init_data() != 0) {
		LM_ERR("could not initialize data\n");
		return -1;
	}

	return 0;
}


static int child_init(int rank)
{
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


static int mi_child_init(void)
{
	return dp_connect_db();
}


static int dp_get_ivalue(struct sip_msg* msg, dp_param_p dp, int *val)
{
	pv_value_t value;

	if(dp->type==DP_VAL_INT) {
		*val = dp->v.id;
		return 0;
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
	dp_table_list_p table;
	pv_value_t pval;

	if (!msg)
		return -1;

	/* verify first param's value */
	id_par = (dp_param_p) str1;
	if (dp_get_ivalue(msg, id_par, &dpid) != 0){
		LM_ERR("no dpid value\n");
		return -1;
	}
	LM_DBG("dpid is %i\n", dpid);

	repl_par = (str2!=NULL)? ((dp_param_p)str2):default_par2;
	if (dp_get_svalue(msg, repl_par->v.sp[0], &input)!=0){
		LM_ERR("invalid param 2\n");
		return -1;
	}

	LM_DBG("input is %.*s\n", input.len, input.s);
	table = id_par->hash ? id_par->hash : dp_get_default_table();

	/* ref the data for reading */
	lock_start_read( table->ref_lock );

	if ((idp = select_dpid(table, dpid, table->crt_index)) == 0) {
		LM_DBG("no information available for dpid %i\n", dpid);
		goto error;
	}

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
	lock_stop_read( table->ref_lock );

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
	lock_stop_read( table->ref_lock );

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
static char *parse_dp_command(char * p, int len, str * table_name)
{
	#define is_space(p) (*(p) == ' ' || *(p) == '\t' || \
			             *(p) == '\r' || *(p) == '\n')
	char *s, *q;

	while (is_space(p)) {
		p++;
		len--;
	}

	if (len <= 0) {
		s = strchr(p, '/');
	} else {
		s = memchr(p, '/', len);
	}

	if (s != 0) {
		q = s+1;

		while (s > p && is_space(s-1))
			s--;

		if (s == p || (*q == '\0'))
			return NULL;

		table_name->s = p;
		table_name->len = s-p;

		p = q;

		while (is_space(p))
			p++;

	} else {
		table_name->s = 0;
		table_name->len = 0;
	}

	return p;
}

/* first param: DPID: type: INT, AVP, SVAR
 * second param: SRC/DST type: RURI, RURI_USERNAME, AVP, SVAR
 * default value for the second param: $ru.user/$ru.user
 */
static int dp_trans_fixup(void ** param, int param_no){

	int dpid;
	dp_param_p dp_par= NULL;
	char *p, *s = NULL;
	str lstr, table_name;
	dp_table_list_t *list = NULL;

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
		p = parse_dp_command(p, -1, &table_name);

		if (p == NULL) {
			LM_ERR("Invalid dp command\n");
			return E_CFG;
		}

		if (table_name.s && table_name.len) {
			list = dp_add_table(&table_name);

			if (list == NULL) {
				LM_ERR("Unable to alloc table entry\n");
				return E_OUT_OF_MEM;
			}
		}

		if (*p != PV_MARKER) {
			dp_par->type = DP_VAL_INT;
			lstr.s = p; lstr.len = strlen(p);
			if(str2sint(&lstr, &dpid) != 0) {
				LM_ERR("bad number <%s>\n",(char *)(*param));
				pkg_free(dp_par);
				return E_CFG;
			}

			dp_par->type = DP_VAL_INT;
			dp_par->v.id = dpid;

		} else {
			lstr.s = p; lstr.len = strlen(p);
			if (pv_parse_spec( &lstr, &dp_par->v.sp[0])==NULL)
				goto error;

			verify_par_type(dp_par->v.sp[0]);
			dp_par->type = DP_VAL_SPEC;
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


static struct mi_root * mi_reload_rules(struct mi_root *cmd_tree, void *param)
{
	struct mi_node *node = NULL;
	struct mi_root *rpl_tree = NULL;
	dp_table_list_t *el;


	if (cmd_tree)
		node = cmd_tree->node.kids;

	if (node == NULL) {
			/* Reload rules from all tables */
			if(dp_load_all_db() != 0){
					LM_ERR("failed to reload database\n");
					return 0;
			}
	} else if (node->value.s == NULL || node->value.len == 0) {
			return init_mi_tree( 400, MI_BAD_PARM_S, MI_BAD_PARM_LEN);
	} else {
			el = dp_get_table(&node->value);
			if (!el)
					return init_mi_tree( 400, MI_BAD_PARM_S, MI_BAD_PARM_LEN);
			/* Reload rules from specified table */
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
	str dpid_str, table_str;
	str input;
	int dpid;
	str attrs;
	str output= {0, 0};
	dp_table_list_p table = NULL;

	node = cmd->node.kids;
	if(node == NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	/* Get the id parameter */
	dpid_str = node->value;
	if(dpid_str.s == NULL || dpid_str.len== 0)	{
		LM_ERR( "empty idp parameter\n");
		return init_mi_tree(404, "Empty id parameter", 18);
	}

	p = parse_dp_command(dpid_str.s, dpid_str.len, &table_str);

	if (p == NULL) {
		LM_ERR("Invalid dp command\n");
		return init_mi_tree(404, "Invalid dp command", 18);
	}

	if (table_str.s == NULL || table_str.len == 0) {
		table = dp_get_default_table();
	} else {
		table = dp_get_table(&table_str);
	}

	dpid_str.len -= (p - dpid_str.s);
	dpid_str.s = p;

	if (!table) {
		LM_ERR("Unable to get table\n");
		return init_mi_tree(400, "Wrong db table parameter", 24);
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
	lock_start_read( table->ref_lock );

	if ((idp = select_dpid(table, dpid, table->crt_index)) ==0 ){
		LM_ERR("no information available for dpid %i\n", dpid);
		lock_stop_read( table->ref_lock );
		return init_mi_tree(404, "No information available for dpid", 33);
	}

	if (translate(NULL, input, &output, idp, &attrs)!=0){
		LM_DBG("could not translate %.*s with dpid %i\n",
			input.len, input.s, idp->dp_id);
		lock_stop_read( table->ref_lock );
		return init_mi_tree(404, "No translation", 14);
	}
	/* we are done reading -> unref the data */
	lock_stop_read( table->ref_lock );

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
