/*
 * Accounting module
 *
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2006 Voice Sistem SRL
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
 * -------
 * 2003-03-06: aligned to change in callback names (jiri)
 * 2003-03-06: fixed improper sql connection, now from
 * 	           child_init (jiri)
 * 2003-03-11: New module interface (janakj)
 * 2003-03-16: flags export parameter added (janakj)
 * 2003-04-04  grand acc cleanup (jiri)
 * 2003-04-06: Opens database connection in child_init only (janakj)
 * 2003-04-24  parameter validation (0 t->uas.request) added (jiri)
 * 2003-11-04  multidomain support for mysql introduced (jiri)
 * 2003-12-04  global TM callbacks switched to per transaction callbacks
 *             (bogdan)
 * 2004-06-06  db cleanup: static db_url, calls to acc_db_{bind,init,close)
 *             (andrei)
 * 2005-05-30  acc_extra patch commited (ramona)
 * 2005-06-28  multi leg call support added (bogdan)
 * 2006-01-13  detect_direction (for sequential requests) added (bogdan)
 * 2006-09-08  flexible multi leg accounting support added (bogdan)
 * 2006-09-19  final stage of a masive re-structuring and cleanup (bogdan)
 */

#include <stdio.h>
#include <string.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../tm/tm_load.h"
#include "../rr/api.h"

#include "../../aaa/aaa.h"
#include "../dialog/dlg_load.h"

#include "acc.h"
#include "acc_mod.h"
#include "acc_extra.h"
#include "acc_logic.h"
#include "acc_vars.h"

struct dlg_binds dlg_api;
struct tm_binds tmb;
struct rr_binds rrb;

static int mod_init(void);
static void destroy(void);
static int child_init(int rank);


/* ----- General purpose variables ----------- */
/* array of extra parameter tags */
int    extra_tgs_len=0;
tag_t* extra_tags=0;
/* array of leg parameter tags */
int    leg_tgs_len=0;
tag_t* leg_tags=0;

/* what would you like to report on */
/* should early media replies (183) be logged ? default==no */
int early_media = 0;
/* would you like us to report CANCELs from upstream too? */
int report_cancels = 0;
/* detect and correct direction in the sequential requests */
int detect_direction = 0;


/* ----- SYSLOG acc variables ----------- */
/* noisiness level logging facilities are used */
int acc_log_level = L_NOTICE;
/* log facility that is used */
int acc_log_facility = LOG_DAEMON;
static char * log_facility_str = 0;
/* log extra variables */
struct acc_extra *log_extra_tags = 0;
struct acc_extra *log_leg_tags = 0;


/* ----- AAA PROTOCOL acc variables ----------- */
static int service_type = -1;
char *aaa_proto_url = NULL;
aaa_prot proto;
aaa_conn *conn;


/*  aaa extra variables */
struct acc_extra *aaa_extra_tags = 0;
struct acc_extra *aaa_leg_tags = 0;

/* ----- SQL acc variables ----------- */
/* db extra variables */
struct acc_extra *db_extra_tags = 0;
struct acc_extra *db_leg_tags = 0;

/* Database url */
static str db_url = {NULL, 0};
/* name of database tables */
str db_table_acc = str_init("acc");
static str db_table_avp = {0,0};
int db_table_name = -1;
unsigned short db_table_name_type = -1;
str db_table_mc = str_init("missed_calls");
/* names of columns in tables acc/missed calls*/
str acc_method_col     = str_init("method");
str acc_fromtag_col    = str_init("from_tag");
str acc_totag_col      = str_init("to_tag");
str acc_callid_col     = str_init("callid");
str acc_sipcode_col    = str_init("sip_code");
str acc_sipreason_col  = str_init("sip_reason");
str acc_time_col       = str_init("time");
str acc_duration_col   = str_init("duration");
str acc_ms_duration_col= str_init("ms_duration");
str acc_setuptime_col  = str_init("setuptime");
str acc_created_col    = str_init("created");

/* ----- Event Interface acc variables ----------- */
/* event extra variables */
struct acc_extra *evi_extra_tags = 0;
struct acc_extra *evi_leg_tags = 0;

/* db avp variables */
str acc_created_avp_name = str_init("accX_created");
int acc_created_avp_id = -1;

/* acc context position */
int acc_flags_ctx_idx;
int acc_tm_flags_ctx_idx;

/* ------------- fixup function --------------- */
static int acc_fixup(void** param, int param_no);
static int free_acc_fixup(void** param, int param_no);


/**
 * pseudo-variables exported by acc module
 */
static pv_export_t mod_items[] = {
	{ {"acc_extra", sizeof("acc_extra") - 1}, 2001, pv_get_acc_extra,
		pv_set_acc_extra, pv_parse_acc_extra_name,
		0 /* parse index(won't use here) */, 0, 0},
	{ {"acc_leg", sizeof("acc_leg") - 1}, 2002, pv_get_acc_leg,
		pv_set_acc_leg, pv_parse_acc_leg_name,
		pv_parse_acc_leg_index, 0, 0},
	{ {"acc_current_leg", sizeof("acc_current_leg") - 1}, 2003,
		pv_get_acc_current_leg, 0, 0, 0, 0, 0},
	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};

static cmd_export_t cmds[] = {
	{"acc_log_request", (cmd_function)w_acc_log_request, 1,
		acc_fixup, free_acc_fixup,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"acc_db_request",  (cmd_function)w_acc_db_request,  2,
		acc_fixup, free_acc_fixup,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"acc_aaa_request", (cmd_function)w_acc_aaa_request, 1,
		acc_fixup, free_acc_fixup,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"acc_evi_request", (cmd_function)w_acc_evi_request, 1,
		acc_fixup, free_acc_fixup,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},

	/* only the type of acc(db,evi...) */
	{"do_accounting", (cmd_function)w_do_acc_1, 1,
		do_acc_fixup, NULL,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},

	/* type of acc(db,evi...) and flags(log cdr, log missed) */
	{"do_accounting", (cmd_function)w_do_acc_2, 2,
		do_acc_fixup, NULL,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},

	/* type of acc(db,evi...) and flags(log cdr, log missed)
	 * and db table */
	{"do_accounting", (cmd_function)w_do_acc_3, 3,
		do_acc_fixup, NULL,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},

	{"drop_accounting", (cmd_function)w_drop_acc_0, 0, 0, NULL,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},

	/* we use the same fixup function since the parameters
	 * have the same meanining as for do_accounting  */
	{"drop_accounting", (cmd_function)w_drop_acc_1, 1,
		do_acc_fixup, NULL,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},

	{"drop_accounting", (cmd_function)w_drop_acc_2, 2,
		do_acc_fixup, NULL,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},

	{"acc_new_leg", (cmd_function)w_new_leg, 0, 0, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},

	{0, 0, 0, 0, 0, 0}
};



static param_export_t params[] = {
	{"early_media",             INT_PARAM, &early_media               },
	{"report_cancels",          INT_PARAM, &report_cancels            },
	{"detect_direction",        INT_PARAM, &detect_direction          },
	/* syslog specific */
	{"log_level",            INT_PARAM, &acc_log_level        },
	{"log_facility",         STR_PARAM, &log_facility_str     },
	/* aaa specific */
	{"aaa_url",   		     STR_PARAM, &aaa_proto_url        },
	{"service_type",         INT_PARAM, &service_type         },
	/* event interface specific */

	{"extra_fields",		 STR_PARAM|USE_FUNC_PARAM, parse_acc_extra},
	{"leg_fields",			 STR_PARAM|USE_FUNC_PARAM, parse_acc_leg},

	/* db-specific */
	{"db_url",               STR_PARAM, &db_url.s             },
	{"db_table_acc",         STR_PARAM, &db_table_acc.s       },
	{"db_table_missed_calls",STR_PARAM, &db_table_mc.s        },
	{"db_table_avp",         STR_PARAM, &db_table_avp.s       },
	{"acc_method_column",    STR_PARAM, &acc_method_col.s     },
	{"acc_from_tag_column",  STR_PARAM, &acc_fromtag_col.s    },
	{"acc_to_tag_column",    STR_PARAM, &acc_totag_col.s      },
	{"acc_callid_column",    STR_PARAM, &acc_callid_col.s     },
	{"acc_sip_code_column",  STR_PARAM, &acc_sipcode_col.s    },
	{"acc_sip_reason_column",STR_PARAM, &acc_sipreason_col.s  },
	{"acc_time_column",      STR_PARAM, &acc_time_col.s       },
	{"acc_created_avp_name", STR_PARAM, &acc_created_avp_name.s},
	{0,0,0}
};

static module_dependency_t *get_deps_aaa_url(param_export_t *param)
{
	char *aaa_url = *(char **)param->param_pointer;

	if (!aaa_url || strlen(aaa_url) == 0)
		return NULL;

	return alloc_module_dep(MOD_TYPE_AAA, NULL, DEP_WARN);
}

static module_dependency_t *get_deps_detect_dir(param_export_t *param)
{
	if (*(int *)param->param_pointer == 0)
		return NULL;

	return alloc_module_dep(MOD_TYPE_DEFAULT, "rr", DEP_ABORT);
}

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "tm", DEP_ABORT  },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ "db_url",           get_deps_sqldb_url  },
		{ "aaa_url",          get_deps_aaa_url    },
		{ "detect_direction", get_deps_detect_dir },
		{ NULL, NULL },
	},
};

struct module_exports exports= {
	"acc",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,  /* module version */
	DEFAULT_DLFLAGS, /* dlopen flags */
	&deps,           /* OpenSIPS module dependencies */
	cmds,       /* exported functions */
	0,          /* exported async functions */
	params,     /* exported params */
	0,          /* exported statistics */
	0,          /* exported MI functions */
	mod_items,  /* exported pseudo-variables */
	0,          /* extra processes */
	mod_init,   /* initialization module */
	0,          /* response function */
	destroy,    /* destroy function */
	child_init  /* per-child init function */
};



/************************** FIXUP functions ****************************/


static int acc_fixup(void** param, int param_no)
{
	str s;

	pv_elem_t *model = NULL;

	s.s = (char*)(*param);

	if (s.s==0 || s.s[0]==0) {
		LM_ERR("first parameter is empty\n");
		return E_SCRIPT;
	}

	if (param_no == 1) {
		if (s.s==NULL) {
			LM_ERR("null format in P%d\n",
					param_no);
		}

		s.len = strlen(s.s);

		if(pv_parse_format(&s, &model)<0) {
			LM_ERR("wrong format[%s]\n", s.s);
			return E_UNSPEC;
		}

		*param = (void*)model;
		return 0;
	} else if (param_no == 2) {
		/* only for db acc - the table name */
		if (db_url.s==0) {
			pkg_free(s.s);
			*param = 0;
		}
	}
	return 0;
}

static int free_acc_fixup(void** param, int param_no)
{
	if(*param)
	{
		pkg_free(*param);
		*param = 0;
	}
	return 0;
}



/************************** INTERFACE functions ****************************/

static int mod_init( void )
{
	LM_INFO("initializing...\n");

	if (db_url.s)
		db_url.len = strlen(db_url.s);
	db_table_acc.len = strlen(db_table_acc.s);
	db_table_mc.len = strlen(db_table_mc.s);
	acc_method_col.len = strlen(acc_method_col.s);
	acc_fromtag_col.len = strlen(acc_fromtag_col.s);
	acc_totag_col.len = strlen(acc_totag_col.s);
	acc_callid_col.len = strlen(acc_callid_col.s);
	acc_sipcode_col.len = strlen(acc_sipcode_col.s);
	acc_sipreason_col.len = strlen(acc_sipreason_col.s);
	acc_time_col.len = strlen(acc_time_col.s);
	acc_created_avp_name.len = strlen(acc_created_avp_name.s);

	if (log_facility_str) {
		int tmp = str2facility(log_facility_str);
		if (tmp != -1)
			acc_log_facility = tmp;
		else {
			LM_ERR("invalid log facility configured");
			return -1;
		}
	}

	/* load the TM API */
	if (load_tm_api(&tmb)!=0) {
		LM_ERR("can't load TM API\n");
		return -1;
	}

	/* if detect_direction is enabled, load rr also */
	if (detect_direction) {
		if (load_rr_api(&rrb)!=0) {
			LM_ERR("can't load RR API\n");
			return -1;
		}
		/* we need the append_fromtag on in RR */
		if (!rrb.append_fromtag) {
			LM_ERR("'append_fromtag' RR param is not enabled!"
				" - required by 'detect_direction'\n");
			return -1;
		}
	}

	/* init the extra engine */
	init_acc_extra();

	/* ----------- SYSLOG INIT SECTION ----------- */
	acc_log_init();

	/* ----------- DATABASE INIT SECTION ----------- */
	if (db_url.s) {
		if (acc_db_init(&db_url)<0){
			LM_ERR("failed! bad db url / missing db module ?\n");
			return -1;
		}
	}


	/* ------------ AAA PROTOCOL INIT SECTION ----------- */
	if (aaa_proto_url && aaa_proto_url[0]) {
		if (init_acc_aaa(aaa_proto_url, service_type)!=0 ) {
			LM_ERR("failed to init radius\n");
			return -1;
		}
	} else {
		aaa_proto_url = NULL;
	}


	/* ----------- EVENT INTERFACE INIT SECTION ----------- */
	if (init_acc_evi() < 0) {
		LM_ERR("cannot init acc events\n");
		return -1;
	}

	acc_flags_ctx_idx = context_register_ptr(CONTEXT_GLOBAL, free_processing_acc_ctx);
	acc_tm_flags_ctx_idx = tmb.t_ctx_register_ptr(NULL);

	return 0;
}


static int child_init(int rank)
{
	if(db_url.s && acc_db_init_child(&db_url)<0) {
		LM_ERR("could not open database connection");
		return -1;
	}

	return 0;
}


static void destroy(void)
{
	if (log_extra_tags)
		destroy_extras( log_extra_tags);
	if (log_leg_tags)
		destroy_extras( log_leg_tags);
	acc_db_close();
	if (db_extra_tags)
		destroy_extras( db_extra_tags);
	if (db_leg_tags)
		destroy_extras( db_leg_tags);

	if (aaa_extra_tags)
		destroy_extras( aaa_extra_tags);
	if (aaa_leg_tags)
		destroy_extras( aaa_leg_tags);

	if (evi_extra_tags)
		destroy_extras( evi_extra_tags);
	if (evi_leg_tags)
		destroy_extras( evi_leg_tags);
}

