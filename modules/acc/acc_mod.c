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

#ifdef DIAM_ACC
#include "diam_dict.h"
#include "diam_tcp.h"
#endif

#include "acc.h"
#include "acc_mod.h"
#include "acc_extra.h"
#include "acc_logic.h"

struct dlg_binds dlg_api;
struct tm_binds tmb;
struct rr_binds rrb;

static int mod_init(void);
static void destroy(void);
static int child_init(int rank);


/* ----- General purpose variables ----------- */

/* what would you like to report on */
/* should early media replies (183) be logged ? default==no */
int early_media = 0;
/* would you like us to report CANCELs from upstream too? */
int report_cancels = 0;
/* detect and correct direction in the sequential requests */
int detect_direction = 0;
/* should failed replies (>=3xx) be logged ? default==no */
/* multi call-leg support */
static char* leg_info_str = 0;
static char* leg_bye_info_str = 0;
struct acc_extra *leg_info = 0;
struct acc_extra *leg_bye_info = 0;


/* ----- SYSLOG acc variables ----------- */
/* noisiness level logging facilities are used */
int acc_log_level = L_NOTICE;
/* log facility that is used */
int acc_log_facility = LOG_DAEMON;
static char * log_facility_str = 0;
/* log extra variables */
static char *log_extra_str = 0;
struct acc_extra *log_extra = 0;
static char *log_extra_bye_str = 0;
struct acc_extra *log_extra_bye = 0;


/* ----- AAA PROTOCOL acc variables ----------- */
static int service_type = -1;
char *aaa_proto_url = NULL;
aaa_prot proto;
aaa_conn *conn;


/*  aaa extra variables */
static char *aaa_extra_str = 0;
struct acc_extra *aaa_extra = 0;
static char *aaa_extra_bye_str = 0;
struct acc_extra *aaa_extra_bye = 0;

/* ----- DIAMETER acc variables ----------- */

#ifdef DIAM_ACC
/* diameter extra variables */
static char *dia_extra_str = 0;
struct acc_extra *dia_extra = 0;
/* buffer used to read from TCP connection*/
rd_buf_t *rb;
char* diameter_client_host="localhost";
int diameter_client_port=3000;
#endif


/* ----- SQL acc variables ----------- */
/* db extra variables */
static char *db_extra_str = 0;
struct acc_extra *db_extra = 0;
static char *db_extra_bye_str = 0;
struct acc_extra *db_extra_bye = 0;
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
static char *evi_extra_str = 0;
struct acc_extra *evi_extra = 0;
static char *evi_extra_bye_str = 0;
struct acc_extra *evi_extra_bye = 0;

/* db avp variables */
str acc_created_avp_name = str_init("accX_created");
int acc_created_avp_id = -1;

/* acc context position */
int acc_flags_ctx_idx;
int acc_tm_flags_ctx_idx;

/* ------------- fixup function --------------- */
static int acc_fixup(void** param, int param_no);
static int free_acc_fixup(void** param, int param_no);


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
#ifdef DIAM_ACC
	{"acc_diam_request",(cmd_function)w_acc_diam_request,1,
		acc_fixup, free_acc_fixup,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
#endif
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

	{0, 0, 0, 0, 0, 0}
};



static param_export_t params[] = {
	{"early_media",             INT_PARAM, &early_media               },
	{"report_cancels",          INT_PARAM, &report_cancels            },
	{"multi_leg_info",          STR_PARAM, &leg_info_str              },
	{"multi_leg_bye_info",      STR_PARAM, &leg_bye_info_str          },
	{"detect_direction",        INT_PARAM, &detect_direction          },
	/* syslog specific */
	{"log_level",            INT_PARAM, &acc_log_level        },
	{"log_facility",         STR_PARAM, &log_facility_str     },
	{"log_extra",            STR_PARAM, &log_extra_str        },
	{"log_extra_bye",        STR_PARAM, &log_extra_bye_str    },
	/* aaa specific */
	{"aaa_url",   		     STR_PARAM, &aaa_proto_url        },
	{"service_type",         INT_PARAM, &service_type         },
	{"aaa_extra",            STR_PARAM, &aaa_extra_str        },
	{"aaa_extra_bye",        STR_PARAM, &aaa_extra_bye_str    },
	/* event interface specific */
	{"evi_extra",            STR_PARAM, &evi_extra_str        },
	{"evi_extra_bye",        STR_PARAM, &evi_extra_bye_str    },

	/* DIAMETER specific */
#ifdef DIAM_ACC
	{"diameter_client_host", STR_PARAM, &diameter_client_host   },
	{"diameter_client_port", INT_PARAM, &diameter_client_port   },
	{"diameter_extra",       STR_PARAM, &dia_extra_str          },
#endif
	/* db-specific */
	{"db_extra",             STR_PARAM, &db_extra_str         },
	{"db_extra_bye",         STR_PARAM, &db_extra_bye_str     },
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
	0,          /* exported pseudo-variables */
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

	/* configure multi-leg accounting */
	if (leg_info_str && (leg_info=parse_acc_leg(leg_info_str))==0 ) {
		LM_ERR("failed to parse multi_leg_info param\n");
		return -1;
	}
	if (leg_bye_info_str && (leg_bye_info=parse_acc_leg(leg_bye_info_str))==0 ) {
		LM_ERR("failed to parse multi_leg_bye_info param\n");
		return -1;
	}

	/* ----------- SYSLOG INIT SECTION ----------- */

	/* parse the extra string, if any */
	if (log_extra_str && (log_extra=parse_acc_extra(log_extra_str, 1))==0 ) {
		LM_ERR("failed to parse log_extra param\n");
		return -1;
	}
	if (log_extra_bye_str &&
			(log_extra_bye=parse_acc_extra(log_extra_bye_str, 0))==0 ) {
		LM_ERR("failed to parse log_extra_bye param\n");
		return -1;
	}

	acc_log_init();

	/* ------------ SQL INIT SECTION ----------- */

	if (db_url.s) {
		/* parse the extra string, if any */
		if (db_extra_str && (db_extra=parse_acc_extra(db_extra_str, 1))==0 ) {
			LM_ERR("failed to parse db_extra param\n");
			return -1;
		}
		if (db_extra_bye_str &&
				(db_extra_bye=parse_acc_extra(db_extra_bye_str, 0))==0 ) {
			LM_ERR("failed to parse db_extra_bye param\n");
			return -1;
		}

		if (acc_db_init(&db_url)<0){
			LM_ERR("failed! bad db url / missing db module ?\n");
			return -1;
		}
	}

	/* ------------ AAA PROTOCOL INIT SECTION ----------- */

	if (aaa_proto_url && aaa_proto_url[0]) {
		/* parse the extra string, if any */
		if (aaa_extra_str && (aaa_extra = parse_acc_extra(aaa_extra_str, 1))==0) {
			LM_ERR("failed to parse aaa_extra param\n");
			return -1;
		}
		if (aaa_extra_bye_str &&
				(aaa_extra_bye = parse_acc_extra(aaa_extra_bye_str, 0))==0) {
			LM_ERR("failed to parse aaa_extra_bye param\n");
			return -1;
		}

		if (init_acc_aaa(aaa_proto_url, service_type)!=0 ) {
			LM_ERR("failed to init radius\n");
			return -1;
		}
	} else {
		aaa_proto_url = NULL;
	}

	/* ------------ DIAMETER INIT SECTION ----------- */

#ifdef DIAM_ACC
	/* parse the extra string, if any */
	if (dia_extra_str && (dia_extra=parse_acc_extra(dia_extra_str))==0 ) {
		LM_ERR("failed to parse dia_extra param\n");
		return -1;
	}

	if (acc_diam_init()!=0) {
		LM_ERR("failed to init diameter engine\n");
		return -1;
	}

#endif

	/* ----------- EVENT INTERFACE INIT SECTION ----------- */

	if (evi_extra_str && (evi_extra = parse_acc_extra(evi_extra_str, 1))==0) {
		LM_ERR("failed to parse evi_extra param\n");
		return -1;
	}
	if (evi_extra_bye_str &&
			(evi_extra_bye = parse_acc_extra(evi_extra_bye_str, 0))==0) {
		LM_ERR("failed to parse evi_extra_bye param\n");
		return -1;
	}

	if (init_acc_evi() < 0) {
		LM_ERR("cannot init acc events\n");
		return -1;
	}

	acc_flags_ctx_idx = context_register_ptr(CONTEXT_GLOBAL, NULL);
	acc_tm_flags_ctx_idx = tmb.t_ctx_register_ptr(NULL);

	return 0;
}


static int child_init(int rank)
{
	if(db_url.s && acc_db_init_child(&db_url)<0) {
		LM_ERR("could not open database connection");
		return -1;
	}

	/* DIAMETER */
#ifdef DIAM_ACC
	/* open TCP connection */
	LM_DBG("initializing TCP connection\n");

	sockfd = init_mytcp(diameter_client_host, diameter_client_port);
	if(sockfd==-1)
	{
		LM_ERR("TCP connection not established\n");
		return -1;
	}

	LM_DBG("a TCP connection was established on sockfd=%d\n", sockfd);

	/* every child with its buffer */
	rb = (rd_buf_t*)pkg_malloc(sizeof(rd_buf_t));
	if(!rb)
	{
		LM_DBG("no more pkg memory\n");
		return -1;
	}
	rb->buf = 0;

#endif

	return 0;
}


static void destroy(void)
{
	if (log_extra)
		destroy_extras( log_extra);
	if (log_extra_bye)
		destroy_extras( log_extra_bye);
	acc_db_close();
	if (db_extra)
		destroy_extras( db_extra);
	if (db_extra_bye)
		destroy_extras( db_extra_bye);

	if (aaa_extra)
		destroy_extras( aaa_extra);
	if (aaa_extra_bye)
		destroy_extras( aaa_extra_bye);

#ifdef DIAM_ACC
	close_tcp_connection(sockfd);
	if (dia_extra)
		destroy_extras( dia_extra);
#endif
}

