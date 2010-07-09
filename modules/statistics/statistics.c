/*
 * $Id$
 *
 * statistics module - script interface to internal statistics manager
 *
 * Copyright (C) 2006 Voice Sistem S.R.L.
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
 *  2006-03-14  initial version (bogdan)
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../ut.h"
#include "../../mod_fix.h"
#include "../../statistics.h"
#include "../../mem/mem.h"
#include "stats_funcs.h"



static int reg_param_stat( modparam_t type, void* val);
static int mod_init(void);
static int w_update_stat(struct sip_msg* msg, char* stat, char* n);
static int w_reset_stat(struct sip_msg* msg, char* stat, char* foo);
static int fixup_stat(void** param, int param_no);

int pv_parse_name(pv_spec_p sp, str *in);
int pv_set_stat(struct sip_msg* msg, pv_param_t *param, int op,
													pv_value_t *val);
int pv_get_stat(struct sip_msg *msg,  pv_param_t *param, pv_value_t *res);


struct stat_or_pv {
	stat_var   *stat;
	pv_spec_t  *pv;
};



static cmd_export_t cmds[]={
	{"update_stat",  (cmd_function)w_update_stat,  2, fixup_stat, 0,
		REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|
		LOCAL_ROUTE|STARTUP_ROUTE|TIMER_ROUTE},
	{"reset_stat",   (cmd_function)w_reset_stat,    1, fixup_stat, 0,
		REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|
		LOCAL_ROUTE|STARTUP_ROUTE|TIMER_ROUTE},
	{0,0,0,0,0,0}
};

static param_export_t mod_params[]={
	{ "variable",  STR_PARAM|USE_FUNC_PARAM, (void*)reg_param_stat },
	{ 0,0,0 }
};


static pv_export_t mod_items[] = {
	{ {"stat",     sizeof("stat")-1},      1100, pv_get_stat,
		pv_set_stat,    pv_parse_name, 0, 0, 0},
	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};



struct module_exports exports= {
	"statistics",		/* module's name */
	MODULE_VERSION,	
	DEFAULT_DLFLAGS,	/* dlopen flags */
	cmds,				/* exported functions */
	mod_params,			/* param exports */
	0,					/* exported statistics */
	0,					/* exported MI functions */
	mod_items,			/* exported pseudo-variables */
	0,					/* extra processes */
	mod_init,			/* module initialization function */
	0,					/* reply processing function */
	0,					/* module destroy function */
	0					/* per-child init function */
};



static int reg_param_stat( modparam_t type, void* val)
{
	return reg_statistic( (char*)val);
}



static int mod_init(void)
{
	LM_INFO("initializing\n");

	if (register_all_mod_stats()!=0) {
		LM_ERR("failed to register statistic variables\n");
		return E_UNSPEC;
	}
	return 0;
}



static int fixup_stat(void** param, int param_no)
{
	struct stat_or_pv *sopv;
	str s;
	long n;
	int err;

	s.s = (char*)*param;
	s.len = strlen(s.s);
	if (param_no==1) {
		/* var name - string or pv */
		sopv = (struct stat_or_pv *)pkg_malloc(sizeof(struct stat_or_pv));
		if (sopv==NULL) {
			LM_ERR("no more pkg mem\n");
			return E_OUT_OF_MEM;
		}
		memset( sopv, 0 , sizeof(struct stat_or_pv) );
		/* is it pv? */
		if (s.s[0]=='$') {
			if (fixup_pvar(param)!=0) {
				LM_ERR("invalid pv %.s as parameter\n",s.s);
				return E_CFG;
			}
			sopv->pv = (pv_spec_t*)(*param);
		} else {
			/* it is string */
			sopv->stat = get_stat( &s );
			if (sopv->stat==0) {
				LM_ERR("variable <%s> not defined\n", s.s);
				return E_CFG;
			}
		}
		pkg_free(s.s);
		*param=(void*)sopv;
		return 0;
	} else if (param_no==2) {
		/* update value - integer */
		if (s.s[0]=='-' || s.s[0]=='+') {
			n = str2s( s.s+1, s.len-1, &err);
			if (s.s[0]=='-')
				n = -n;
		} else {
			n = str2s( s.s, s.len, &err);
		}
		if (err==0){
			if (n==0) {
				LM_ERR("update with 0 has no sense\n");
				return E_CFG;
			}
			pkg_free(*param);
			*param=(void*)n;
			return 0;
		}else{
			LM_ERR("bad update number <%s>\n",(char*)(*param));
			return E_CFG;
		}
	}
	return 0;
}


static int w_update_stat(struct sip_msg *msg, char *stat_p, char *n)
{
	struct stat_or_pv *sopv = (struct stat_or_pv *)stat_p;
	pv_value_t pv_val;
	stat_var *stat;

	if (sopv->stat) {
		update_stat( sopv->stat, (long)n);
	} else {
		if (pv_get_spec_value(msg, sopv->pv, &pv_val)!=0 ||
		(pv_val.flags & PV_VAL_STR)==0 ) {
			LM_ERR("failed to get pv string value\n");
			return -1;
		}
		stat = get_stat( &(pv_val.rs) );
		if ( stat == 0 ) {
			LM_ERR("variable <%.*s> not defined\n",
				pv_val.rs.len, pv_val.rs.s);
			return -1;
		}
		update_stat( stat, (long)n);
	}

	return 1;
}


static int w_reset_stat(struct sip_msg *msg, char* stat_p, char *foo)
{
	struct stat_or_pv *sopv = (struct stat_or_pv *)stat_p;
	pv_value_t pv_val;
	stat_var *stat;

	if (sopv->stat) {
		reset_stat( sopv->stat );
	} else {
		if (pv_get_spec_value(msg, sopv->pv, &pv_val)!=0 ||
		(pv_val.flags & PV_VAL_STR)==0 ) {
			LM_ERR("failed to get pv string value\n");
			return -1;
		}
		stat = get_stat( &(pv_val.rs) );
		if ( stat == 0 ) {
			LM_ERR("variable <%.*s> not defined\n",
				pv_val.rs.len, pv_val.rs.s);
			return -1;
		}
		reset_stat( stat );
	}


	return 1;
}

stat_var* get_stat_p(pv_param_t *param)
{
	stat_var *stat = NULL;

	if (param==NULL || param->pvn.u.isname.name.s.s == NULL)
	{
		LM_CRIT("BUG - bad parameters\n");
		return NULL;
	}

	if (param->pvn.type == PV_NAME_INTSTR)
	{
		if (param->pvn.u.isname.type == AVP_NAME_STR)
		{
			/* if this is the first call of the function */
			stat = get_stat( &param->pvn.u.isname.name.s );

			if (stat == NULL)
			{
				param->pvn.u.dname = NULL;
				param->pvn.u.isname.type = AVP_VAL_STR;
				LM_ERR("%.*s doesn't exist\n", param->pvn.u.isname.name.s.len,
						param->pvn.u.isname.name.s.s );
				return NULL;
			}

			param->pvn.u.dname = stat;
			param->pvn.type = PV_NAME_PVAR;
		}
		else
		if (param->pvn.u.isname.type == AVP_VAL_STR)
		{
			/* if stat wasn't found */
			LM_ERR("%.*s doesn't exist\n", param->pvn.u.isname.name.s.len,
					param->pvn.u.isname.name.s.s );
			return NULL;
		}
		else
		{
			LM_ERR("BUG - error in getting stat value\n");
			return NULL;
		}
	}
	else
	if (param->pvn.type == PV_NAME_PVAR)
	{
		/* if stat was already found */
		stat = (stat_var *)param->pvn.u.dname;

		if (stat == NULL)
		{
			LM_CRIT("BUG - error in setting stat value\n");
			return NULL;
		}
	}
	else
	{
		LM_ERR("BUG - error in getting stat value\n");
		return NULL;
	}

	return stat;
}

int pv_parse_name(pv_spec_p sp, str *in)
{
	
	sp->pvp.pvn.type = PV_NAME_INTSTR;
	sp->pvp.pvn.u.isname.type = AVP_NAME_STR;
	sp->pvp.pvn.u.isname.name.s = *in;

	return 0;
}

int pv_set_stat(struct sip_msg* msg, pv_param_t *param, int op,
													pv_value_t *val)
{
	stat_var *stat = get_stat_p(param);

	if (stat == NULL)
		return -1;

	if (val != 0)
		LM_WARN("non-zero value - setting value to 0\n");
	
	reset_stat( stat );

	return 0;
}


int pv_get_stat(struct sip_msg *msg,  pv_param_t *param, pv_value_t *res)
{

	stat_var *stat = get_stat_p(param);

	if (stat == NULL)
		return -1;

	res->ri = get_stat_val( stat );
	res->rs.s = int2str( (unsigned long)res->ri, &res->rs.len);
	res->flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;

	return 0;
}
