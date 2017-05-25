/*
 * Route & Record-Route module
 *
 * Copyright (C) 2009-2014 OpenSIPS Solutions
 * Copyright (C) 2001-2003 FhG Fokus
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
 *  2003-03-11  updated to the new module interface (andrei)
 *  2003-03-16  flags export parameter added (janakj)
 *  2003-03-19  all mallocs/frees replaced w/ pkg_malloc/pkg_free (andrei)
 *  2003-04-01  Added record_route with ip address parameter (janakj)
 *  2003-04-14  enable_full_lr parameter introduced (janakj)
 *  2005-04-10  add_rr_param() and check_route_param() added (bogdan)
 *  2006-02-14  record_route may take as param a string to be used as RR param;
 *              record_route and record_route_preset accept pseudo-variables in
 *              parameters; add_rr_param may be called from BRANCH and FAILURE
 *              routes (bogdan)
 */
/*!
 * \file
 * \brief Route & Record-Route module
 * \ingroup rr
 */


#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <regex.h>

#include "../../sr_module.h"
#include "../../ut.h"
#include "../../error.h"
#include "../../pvar.h"
#include "../../mem/mem.h"
#include "../../mod_fix.h"
#include "../../context.h"
#include "loose.h"
#include "record.h"
#include "rr_cb.h"
#include "api.h"

#ifdef ENABLE_USER_CHECK
#include <string.h>
#include "../../str.h"
str i_user;
char *ignore_user = NULL;
#endif

int ctx_rrdone_idx = -1;
#define ctx_rrdone_set(_val) \
	context_put_int(CONTEXT_GLOBAL,current_processing_ctx,ctx_rrdone_idx,_val)
#define ctx_rrdone_get() \
	context_get_int(CONTEXT_GLOBAL, current_processing_ctx, ctx_rrdone_idx)

/* module parameters */
int append_fromtag = 1;
int enable_double_rr = 1; /* Enable using of 2 RR by default */
int add_username = 0;     /* Do not add username by default */
int enable_socket_mismatch_warning = 1; /* Enable socket mismatch warning */

static int  mod_init(void);
static void mod_destroy(void);
/* fixup functions */
static int direction_fixup(void** param, int param_no);
static int it_list_fixup(void** param, int param_no);
/* wrapper functions */
static int w_record_route(struct sip_msg *,char *, char *);
static int w_record_route_preset(struct sip_msg *,char *, char *);
static int w_add_rr_param(struct sip_msg *,char *, char *);
static int w_check_route_param(struct sip_msg *,char *, char *);
static int w_is_direction(struct sip_msg *,char *, char *);

static int pv_get_rr_params(struct sip_msg *msg, pv_param_t *param,
	pv_value_t *res);


/*! \brief
 * Exported functions
 */
static cmd_export_t cmds[] = {
	{"loose_route",          (cmd_function)loose_route,           0,
			0, 0,
			REQUEST_ROUTE},
	{"record_route",         (cmd_function)w_record_route,        0,
			0, 0,
			REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE},
	{"record_route",         (cmd_function)w_record_route,        1,
			it_list_fixup, 0,
			REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE},
	{"record_route_preset",  (cmd_function)w_record_route_preset, 1,
			it_list_fixup, 0,
			REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE},
	{"record_route_preset",  (cmd_function)w_record_route_preset, 2,
			it_list_fixup, 0,
			REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE},
	{"add_rr_param",         (cmd_function)w_add_rr_param,        1,
			it_list_fixup, 0,
			REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE},
	{"check_route_param",    (cmd_function)w_check_route_param,   1,
			fixup_regexp_null, fixup_free_regexp_null,
			REQUEST_ROUTE},
	{"is_direction",         (cmd_function)w_is_direction,        1,
			direction_fixup, 0,
			REQUEST_ROUTE},
	{"load_rr",              (cmd_function)load_rr, 0, 0, 0, 0},
	{0, 0, 0, 0, 0, 0}
};


/*! \brief
 * Exported parameters
 */
static param_export_t params[] ={
	{"append_fromtag",                 INT_PARAM, &append_fromtag                },
	{"enable_double_rr",               INT_PARAM, &enable_double_rr              },
#ifdef ENABLE_USER_CHECK
	{"ignore_user",                    STR_PARAM, &ignore_user                   },
#endif
	{"add_username",                   INT_PARAM, &add_username                  },
	{"enable_socket_mismatch_warning", INT_PARAM, &enable_socket_mismatch_warning},
	{0, 0, 0 }
};


/**
 * pseudo-variables exported by RR module
 */
static pv_export_t mod_items[] = {
	{ {"rr_params", sizeof("rr_params")-1}, 900, pv_get_rr_params, 0,
		0, 0, 0, 0 },
	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};


#ifdef STATIC_RR
struct module_exports rr_exports = {
#else
struct module_exports exports = {
#endif
	"rr",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /*!< dlopen flags */
	NULL,            /* OpenSIPS module dependencies */
	cmds,        /*!< Exported functions */
	0,           /*!< Exported async functions */
	params,      /*!< Exported parameters */
	0,           /*!< exported statistics */
	0,           /*!< exported MI functions */
	mod_items,   /*!< exported pseudo-variables */
	0,			 /*!< exported transformations */
	0,           /*!< extra processes */
	mod_init,    /*!< initialize module */
	0,           /*!< response function*/
	mod_destroy, /*!< destroy function */
	0            /*!< per-child init function */
};


static int mod_init(void)
{
	LM_INFO("rr - initializing\n");

	ctx_rrparam_idx = context_register_str(CONTEXT_GLOBAL, NULL);
	ctx_routing_idx = context_register_int(CONTEXT_GLOBAL, NULL);
	ctx_rrdone_idx  = context_register_int(CONTEXT_GLOBAL, NULL);

#ifdef ENABLE_USER_CHECK
	if(ignore_user)
	{
		i_user.s = ignore_user;
		i_user.len = strlen(ignore_user);
	}
	else
	{
		i_user.s = 0;
		i_user.len = 0;
	}
#endif
	return 0;
}


static void mod_destroy(void)
{
	destroy_rrcb_lists();
}


static int it_list_fixup(void** param, int param_no)
{
	pv_elem_t *model;
	str s;
	if(*param)
	{
		s.s = (char*)(*param); s.len = strlen(s.s);
		if(pv_parse_format(&s, &model)<0)
		{
			LM_ERR("wrong format[%s]\n",(char*)(*param));
			return E_UNSPEC;
		}
		*param = (void*)model;
	}
	return 0;
}


static int direction_fixup(void** param, int param_no)
{
	char *s;
	int n;

	if (!append_fromtag) {
		LM_ERR("usage of \"is_direction\" function requires parameter"
				"\"append_fromtag\" enabled!!");
		return E_CFG;
	}
	if (param_no==1) {
		n = 0;
		s = (char*) *param;
		if ( strcasecmp(s,"downstream")==0 ) {
			n = RR_FLOW_DOWNSTREAM;
		} else if ( strcasecmp(s,"upstream")==0 ) {
			n = RR_FLOW_UPSTREAM;
		} else {
			LM_ERR("unknown direction '%s'\n",s);
			return E_CFG;
		}
		/* free string */
		pkg_free(*param);
		/* replace it with the flag */
		*param = (void*)(unsigned long)n;
	}
	return 0;
}


static int pv_get_rr_params(struct sip_msg *msg, pv_param_t *param,
															pv_value_t *res)
{
	str val;

	if(msg==NULL || res==NULL)
		return -1;

	/* obtain routed params */
	if (get_route_params(msg, &val) < 0 )
		return -1;

	res->rs.s = val.s;
	res->rs.len = val.len;

	res->flags = PV_VAL_STR;

	return 0;
}


static int w_record_route(struct sip_msg *msg, char *key, char *bar)
{
	str s;

	if (ctx_rrdone_get()==1) {
		LM_ERR("Double attempt to record-route\n");
		return -1;
	}

	if (key && pv_printf_s(msg, (pv_elem_t*)key, &s)<0) {
		LM_ERR("failed to print the format\n");
		return -1;
	}
	if ( record_route( msg, key?&s:0 )<0 )
		return -1;

	ctx_rrdone_set(1);
	return 1;
}


static int w_record_route_preset(struct sip_msg *msg, char *key, char *key2)
{
	str s;

	if (ctx_rrdone_get()==1) {
		LM_ERR("Double attempt to record-route\n");
		return -1;
	}
	if (key2 && !enable_double_rr) {
		LM_ERR("Attempt to double record-route while 'enable_double_rr' "
			"param is disabled\n");
		return -1;
	}

	if (pv_printf_s(msg, (pv_elem_t*)key, &s)<0) {
		LM_ERR("failed to print the format\n");
		return -1;
	}
	if ( record_route_preset( msg, &s)<0 )
		return -1;

	if (!key2)
		goto done;

	if (pv_printf_s(msg, (pv_elem_t*)key2, &s)<0) {
		LM_ERR("failed to print the format\n");
		return -1;
	}
	if ( record_route_preset( msg, &s)<0 )
		return -1;

done:
	ctx_rrdone_set(1);
	return 1;
}


static int w_add_rr_param(struct sip_msg *msg, char *key, char *foo)
{
	str s;

	if (pv_printf_s(msg, (pv_elem_t*)key, &s)<0) {
		LM_ERR("failed to print the format\n");
		return -1;
	}
	return ((add_rr_param( msg, &s)==0)?1:-1);
}



static int w_check_route_param(struct sip_msg *msg,char *re, char *foo)
{
	return ((check_route_param(msg,(regex_t*)re)==0)?1:-1);
}



static int w_is_direction(struct sip_msg *msg,char *dir, char *foo)
{
	return ((is_direction(msg,(int)(long)dir)==0)?1:-1);
}


