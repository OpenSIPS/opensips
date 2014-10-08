/*
 * $Id$
 *
 * dialog module - basic support for dialog tracking
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 *  2006-04-14 initial version (bogdan)
 *  2006-11-28 Added statistic support for the number of early and failed
 *              dialogs. (Jeffrey Magder - SOMA Networks)
 *  2007-04-30 added dialog matching without DID (dialog ID), but based only
 *              on RFC3261 elements - based on an original patch submitted
 *              by Michel Bensoussan <michel@extricom.com> (bogdan)
 *  2007-05-15 added saving dialogs' information to database (ancuta)
 *  2007-07-04 added saving dialog cseq, contact, record route
 *              and bind_addresses(sock_info) for caller and callee (ancuta)
 *  2008-04-14 added new type of callback to be triggered when dialogs are
 *              loaded from DB (bogdan)
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>

#include "../../sr_module.h"
#include "../../db/db.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../ut.h"
#include "../../pvar.h"
#include "../../mod_fix.h"
#include "../../script_cb.h"
#include "../../script_var.h"
#include "../../mem/mem.h"
#include "../../mi/mi.h"
#include "../tm/tm_load.h"
#include "../rr/api.h"
#include "../../bin_interface.h"

#include "dlg_hash.h"
#include "dlg_timer.h"
#include "dlg_handlers.h"
#include "dlg_load.h"
#include "dlg_cb.h"
#include "dlg_db_handler.h"
#include "dlg_req_within.h"
#include "dlg_profile.h"
#include "dlg_vals.h"
#include "dlg_tophiding.h"
#include "dlg_replication.h"

static int mod_init(void);
static int child_init(int rank);
static void mod_destroy(void);

/* module parameter */
int log_profile_hash_size = 4;
str rr_param = {"did",3};
static int dlg_hash_size = 4096;
static str timeout_spec = {NULL, 0};
static int default_timeout = 60 * 60 * 12;  /* 12 hours */
static int ping_interval = 30; /* seconds */
static char* profiles_wv_s = NULL;
static char* profiles_nv_s = NULL;

int dlg_have_own_timer_proc=0;	/* by default use the global timer proc */
void *dlg_own_timer_proc=NULL;	/* point to the own timer proc, if used*/

int dlg_bulk_del_no = 1; /* delete one by one */
int seq_match_mode = SEQ_MATCH_STRICT_ID;
str dlg_extra_hdrs = {NULL,0};

/* statistic variables */
int dlg_enable_stats = 1;
int active_dlgs_cnt = 0;
int early_dlgs_cnt = 0;
int db_flush_vp = 0;
stat_var *active_dlgs = 0;
stat_var *processed_dlgs = 0;
stat_var *expired_dlgs = 0;
stat_var *failed_dlgs = 0;
stat_var *early_dlgs  = 0;
stat_var *create_sent  = 0;
stat_var *update_sent  = 0;
stat_var *delete_sent  = 0;
stat_var *create_recv  = 0;
stat_var *update_recv  = 0;
stat_var *delete_recv  = 0;

struct tm_binds d_tmb;
struct rr_binds d_rrb;

/* db stuff */
static str db_url = {NULL,0};
static unsigned int db_update_period = DB_DEFAULT_UPDATE_PERIOD;

extern int last_dst_leg;

/* cachedb stuff */
str cdb_url = {0,0};

/* dialog replication using the bpi interface */
int accept_replicated_dlg=0;
struct replication_dest *replication_dests=NULL;

static int pv_get_dlg_count( struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);

static int add_replication_dest(modparam_t type, void *val);

/* commands wrappers and fixups */
static int fixup_profile(void** param, int param_no);
static int fixup_get_profile2(void** param, int param_no);
static int fixup_get_profile3(void** param, int param_no);
static int w_create_dialog(struct sip_msg*);
static int w_create_dialog2(struct sip_msg*,char *);
static int w_match_dialog(struct sip_msg*);
static int fixup_create_dlg2(void **param,int param_no);
static int w_validate_dialog(struct sip_msg*);
static int w_fix_route_dialog(struct sip_msg*);
static int w_set_dlg_profile(struct sip_msg*, char*, char*);
static int w_unset_dlg_profile(struct sip_msg*, char*, char*);
static int w_is_in_profile(struct sip_msg*, char*, char*);
static int w_get_profile_size(struct sip_msg*, char*, char*, char*);
static int fixup_dlg_flag(void** param, int param_no);
static int w_set_dlg_flag(struct sip_msg*, char*);
static int w_reset_dlg_flag(struct sip_msg*, char*);
static int w_is_dlg_flag_set(struct sip_msg*, char*);
static int fixup_dlg_sval(void** param, int param_no);
static int fixup_dlg_fval(void** param, int param_no);
static int w_store_dlg_value(struct sip_msg*, char*, char*);
static int w_fetch_dlg_value(struct sip_msg*, char*, char*);
static int fixup_get_info(void** param, int param_no);
static int w_get_dlg_info(struct sip_msg*, char*, char*, char*, char*);
static int w_tsl_dlg_flag(struct sip_msg *msg, char *_idx, char *_val);

/* item/pseudo-variables functions */
int pv_get_dlg_lifetime(struct sip_msg *msg,pv_param_t *param,pv_value_t *res);
int pv_get_dlg_status(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
int pv_get_dlg_flags(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
int pv_get_dlg_timeout(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
int pv_get_dlg_dir(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
int pv_get_dlg_did(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
int pv_get_dlg_end_reason(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
int pv_set_dlg_flags(struct sip_msg *msg, pv_param_t *param, int op,
		pv_value_t *val);
int pv_set_dlg_timeout(struct sip_msg *msg, pv_param_t *param, int op,
		pv_value_t *val);

static cmd_export_t cmds[]={
	{"create_dialog", (cmd_function)w_create_dialog,      0,NULL,
			0, REQUEST_ROUTE},
	{"create_dialog", (cmd_function)w_create_dialog2,     1,fixup_create_dlg2,
			0, REQUEST_ROUTE},
	{"set_dlg_profile", (cmd_function)w_set_dlg_profile,  1,fixup_profile,
			0, REQUEST_ROUTE| FAILURE_ROUTE | ONREPLY_ROUTE | BRANCH_ROUTE },
	{"set_dlg_profile", (cmd_function)w_set_dlg_profile,  2,fixup_profile,
			0, REQUEST_ROUTE| FAILURE_ROUTE | ONREPLY_ROUTE | BRANCH_ROUTE },
	{"unset_dlg_profile", (cmd_function)w_unset_dlg_profile,1,fixup_profile,
			0, FAILURE_ROUTE | ONREPLY_ROUTE | BRANCH_ROUTE },
	{"unset_dlg_profile", (cmd_function)w_unset_dlg_profile,2,fixup_profile,
			0, FAILURE_ROUTE | ONREPLY_ROUTE | BRANCH_ROUTE },
	{"is_in_profile", (cmd_function)w_is_in_profile,      1,fixup_profile,
			0, REQUEST_ROUTE| FAILURE_ROUTE | ONREPLY_ROUTE |
			BRANCH_ROUTE | LOCAL_ROUTE },
	{"is_in_profile", (cmd_function)w_is_in_profile,      2,fixup_profile,
			0, REQUEST_ROUTE| FAILURE_ROUTE | ONREPLY_ROUTE |
			BRANCH_ROUTE | LOCAL_ROUTE },
	{"get_profile_size",(cmd_function)w_get_profile_size, 2,fixup_get_profile2,
			0, REQUEST_ROUTE| FAILURE_ROUTE | ONREPLY_ROUTE |
			BRANCH_ROUTE | LOCAL_ROUTE },
	{"get_profile_size",(cmd_function)w_get_profile_size, 3,fixup_get_profile3,
			0, REQUEST_ROUTE| FAILURE_ROUTE | ONREPLY_ROUTE |
			BRANCH_ROUTE | LOCAL_ROUTE},
	{"set_dlg_flag",(cmd_function)w_set_dlg_flag,         1,fixup_dlg_flag,
			0, REQUEST_ROUTE| FAILURE_ROUTE | ONREPLY_ROUTE |
			BRANCH_ROUTE | LOCAL_ROUTE},
	{"test_and_set_dlg_flag",(cmd_function)w_tsl_dlg_flag,2,fixup_uint_uint,
			0, REQUEST_ROUTE| FAILURE_ROUTE | ONREPLY_ROUTE |
			BRANCH_ROUTE | LOCAL_ROUTE },
	{"reset_dlg_flag",(cmd_function)w_reset_dlg_flag,     1,fixup_dlg_flag,
			0, REQUEST_ROUTE| FAILURE_ROUTE | ONREPLY_ROUTE |
			BRANCH_ROUTE | LOCAL_ROUTE },
	{"is_dlg_flag_set",(cmd_function)w_is_dlg_flag_set,   1,fixup_dlg_flag,
			0, REQUEST_ROUTE| FAILURE_ROUTE | ONREPLY_ROUTE |
			BRANCH_ROUTE | LOCAL_ROUTE },
	{"store_dlg_value",(cmd_function)w_store_dlg_value,   2,fixup_dlg_sval,
			0, REQUEST_ROUTE| FAILURE_ROUTE | ONREPLY_ROUTE |
			BRANCH_ROUTE | LOCAL_ROUTE },
	{"fetch_dlg_value",(cmd_function)w_fetch_dlg_value,   2,fixup_dlg_fval,
			0, REQUEST_ROUTE| FAILURE_ROUTE | ONREPLY_ROUTE |
			BRANCH_ROUTE | LOCAL_ROUTE },
	{"validate_dialog",(cmd_function)w_validate_dialog,   0,         NULL,
			0, REQUEST_ROUTE},
	{"fix_route_dialog",(cmd_function)w_fix_route_dialog,0,NULL,
			0, REQUEST_ROUTE},
	{"get_dialog_info",(cmd_function)w_get_dlg_info,      4,fixup_get_info,
			0, REQUEST_ROUTE| FAILURE_ROUTE | ONREPLY_ROUTE |
			BRANCH_ROUTE | LOCAL_ROUTE },
	{"topology_hiding",(cmd_function)w_topology_hiding,0,NULL,
			0, REQUEST_ROUTE},
	{"topology_hiding",(cmd_function)w_topology_hiding1,1,fixup_create_dlg2,
			0, REQUEST_ROUTE},
	{"match_dialog",  (cmd_function)w_match_dialog,       0,NULL,
			0, REQUEST_ROUTE},
	{"load_dlg",  (cmd_function)load_dlg,   0, 0, 0, 0},
	{0,0,0,0,0,0}
};

static param_export_t mod_params[]={
	{ "enable_stats",          INT_PARAM, &dlg_enable_stats         },
	{ "hash_size",             INT_PARAM, &dlg_hash_size            },
	{ "log_profile_hash_size", INT_PARAM, &log_profile_hash_size    },
	{ "rr_param",              STR_PARAM, &rr_param.s               },
	{ "default_timeout",       INT_PARAM, &default_timeout          },
	{ "ping_interval",         INT_PARAM, &ping_interval            },
	{ "dlg_extra_hdrs",        STR_PARAM, &dlg_extra_hdrs.s         },
	{ "dlg_match_mode",        INT_PARAM, &seq_match_mode           },
	{ "db_url",                STR_PARAM, &db_url.s                 },
	{ "db_mode",               INT_PARAM, &dlg_db_mode              },
	{ "table_name",            STR_PARAM, &dialog_table_name        },
	{ "dlg_id_column",         STR_PARAM, &dlg_id_column.s          },
	{ "call_id_column",        STR_PARAM, &call_id_column.s         },
	{ "from_uri_column",       STR_PARAM, &from_uri_column.s        },
	{ "from_tag_column",       STR_PARAM, &from_tag_column.s        },
	{ "to_uri_column",         STR_PARAM, &to_uri_column.s          },
	{ "to_tag_column",         STR_PARAM, &to_tag_column.s          },
	{ "state_column",          STR_PARAM, &state_column.s           },
	{ "start_time_column",     STR_PARAM, &start_time_column.s      },
	{ "timeout_column",        STR_PARAM, &timeout_column.s         },
	{ "to_cseq_column",        STR_PARAM, &to_cseq_column.s         },
	{ "from_cseq_column",      STR_PARAM, &from_cseq_column.s       },
	{ "to_route_column",       STR_PARAM, &to_route_column.s        },
	{ "from_route_column",     STR_PARAM, &from_route_column.s      },
	{ "to_contact_column",     STR_PARAM, &to_contact_column.s      },
	{ "from_contact_column",   STR_PARAM, &from_contact_column.s    },
	{ "to_sock_column",        STR_PARAM, &to_sock_column.s         },
	{ "from_sock_column",      STR_PARAM, &from_sock_column.s       },
	{ "profiles_column",       STR_PARAM, &profiles_column.s        },
	{ "vars_column",           STR_PARAM, &vars_column.s            },
	{ "sflags_column",         STR_PARAM, &sflags_column.s          },
	{ "flags_column",          STR_PARAM, &flags_column.s           },
	{ "db_update_period",      INT_PARAM, &db_update_period         },
	{ "profiles_with_value",   STR_PARAM, &profiles_wv_s            },
	{ "profiles_no_value",     STR_PARAM, &profiles_nv_s            },
	{ "db_flush_vals_profiles",INT_PARAM, &db_flush_vp              },
	{ "own_timer_proc",        INT_PARAM, &dlg_have_own_timer_proc  },
	{ "timer_bulk_del_no",     INT_PARAM, &dlg_bulk_del_no          },
	/* distributed profiles stuff */
	{ "cachedb_url",           STR_PARAM, &cdb_url.s                },
	{ "profile_value_prefix",    STR_PARAM, &cdb_val_prefix.s       },
	{ "profile_no_value_prefix", STR_PARAM, &cdb_noval_prefix.s     },
	{ "profile_size_prefix",     STR_PARAM, &cdb_size_prefix.s      },
	{ "profile_timeout",         INT_PARAM, &profile_timeout        },
	/* dialog replication through UDP binary packets */
	{ "accept_replicated_dialogs",INT_PARAM, &accept_replicated_dlg },
	{ "replicate_dialogs_to",     STR_PARAM|USE_FUNC_PARAM,
								(void *)add_replication_dest        },
	{ 0,0,0 }
};


static stat_export_t mod_stats[] = {
	{"active_dialogs" ,     STAT_NO_RESET,  &active_dlgs       },
	{"early_dialogs",       STAT_NO_RESET,  &early_dlgs        },
	{"processed_dialogs" ,  0,              &processed_dlgs    },
	{"expired_dialogs" ,    0,              &expired_dlgs      },
	{"failed_dialogs",      0,              &failed_dlgs       },
	{"create_sent",         0,              &create_sent       },
	{"update_sent",         0,              &update_sent       },
	{"delete_sent",         0,              &delete_sent       },
	{"create_recv",         0,              &create_recv       },
	{"update_recv",         0,              &update_recv       },
	{"delete_recv",         0,              &delete_recv       },
	{0,0,0}
};


static mi_export_t mi_cmds[] = {
	{ "dlg_list",           0, mi_print_dlgs,         0,  0,  0},
	{ "dlg_list_ctx",       0, mi_print_dlgs_ctx,     0,  0,  0},
	{ "dlg_end_dlg",        0, mi_terminate_dlg,      0,  0,  0},
	{ "dlg_db_sync",        0, mi_sync_db_dlg,        0,  0,  0},
	{ "dlg_restore_db",     0, mi_restore_dlg_db,     0,  0,  0},
	{ "profile_get_size",   0, mi_get_profile,        0,  0,  0},
	{ "profile_list_dlgs",  0, mi_profile_list,       0,  0,  0},
	{ "profile_get_values", 0, mi_get_profile_values, 0,  0,  0},
	{ "list_all_profiles",  0, mi_list_all_profiles,  0,  0,  0},
	{ 0, 0, 0, 0, 0, 0}
};


static pv_export_t mod_items[] = {
	{ {"DLG_count",  sizeof("DLG_count")-1},     1000, pv_get_dlg_count,
		0,                 0, 0, 0, 0 },
	{ {"DLG_lifetime",sizeof("DLG_lifetime")-1}, 1000, pv_get_dlg_lifetime,
		0,                 0, 0, 0, 0 },
	{ {"DLG_status",  sizeof("DLG_status")-1},   1000, pv_get_dlg_status,
		0,                 0, 0, 0, 0 },
	{ {"DLG_dir",     sizeof("DLG_dir")-1},      1000, pv_get_dlg_dir,
		0,                 0, 0, 0, 0},
	{ {"DLG_flags",   sizeof("DLG_flags")-1},    1000, pv_get_dlg_flags,
		pv_set_dlg_flags,  0, 0, 0, 0 },
	{ {"dlg_val",     sizeof("dlg_val")-1},      1000, pv_get_dlg_val,
		pv_set_dlg_val,    pv_parse_name, 0, 0, 0},
	{ {"DLG_did",     sizeof("DLG_did")-1},      1000, pv_get_dlg_did,
		0,                 0, 0, 0, 0},
	{ {"DLG_end_reason",     sizeof("DLG_end_reason")-1},      1000,
		pv_get_dlg_end_reason,0,0, 0, 0, 0},
	{ {"DLG_timeout",        sizeof("DLG_timeout")-1},       1000, 
		pv_get_dlg_timeout, pv_set_dlg_timeout,  0, 0, 0, 0 },
	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};

struct module_exports exports= {
	"dialog",        /* module's name */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	cmds,            /* exported functions */
	mod_params,      /* param exports */
	mod_stats,       /* exported statistics */
	mi_cmds,         /* exported MI functions */
	mod_items,       /* exported pseudo-variables */
	0,               /* extra processes */
	mod_init,        /* module initialization function */
	0,               /* reply processing function */
	mod_destroy,
	child_init       /* per-child init function */
};


static int fixup_profile(void** param, int param_no)
{
	struct dlg_profile_table *profile;
	pv_elem_t *model=NULL;
	str s;

	s.s = (char*)(*param);
	s.len = strlen(s.s);
	if(s.len==0) {
		LM_ERR("param %d is empty string!\n", param_no);
		return E_CFG;
	}

	if (param_no==1) {
		profile = search_dlg_profile( &s );
		if (profile==NULL) {
			LM_CRIT("profile <%s> not defined\n",s.s);
			return E_CFG;
		}
		pkg_free(*param);
		*param = (void*)profile;
		return 0;
	} else if (param_no==2) {
		if(pv_parse_format(&s ,&model) || model==NULL) {
			LM_ERR("wrong format [%s] for value param!\n", s.s);
			return E_CFG;
		}
		*param = (void*)model;
	}
	return 0;
}



static int fixup_get_profile2(void** param, int param_no)
{
	pv_spec_t *sp;
	int ret;
	action_elem_t * p;


	if (param_no==1) {
		return fixup_profile(param, 1);
	} else if (param_no==2) {


		ret = fixup_pvar(param);
		if (ret<0) return ret;
		sp = (pv_spec_t*)(*param);
		if (sp->type!=PVT_AVP && sp->type!=PVT_SCRIPTVAR) {
			LM_ERR("return must be an AVP or SCRIPT VAR!\n");
			return E_SCRIPT;
		}

		p = list_entry(param, action_elem_t, u.data);
		p++;
		p->u.data = *param;

		*param = NULL;


	}
	return 0;
}


static int fixup_get_profile3(void** param, int param_no)
{
	int ret;
	pv_spec_t *sp;

	if (param_no==1) {
		return fixup_profile(param, 1);
	} else if (param_no==2) {
		return fixup_profile(param, 2);
	} else if (param_no==3) {

		ret = fixup_pvar(param);
		if (ret<0) return ret;
		sp = (pv_spec_t*)(*param);
		if (sp->type!=PVT_AVP && sp->type!=PVT_SCRIPTVAR) {
			LM_ERR("return must be an AVP or SCRIPT VAR!\n");
			return E_SCRIPT;
		}


	}
	return 0;
}


static int fixup_dlg_flag(void** param, int param_no)
{
	unsigned int ui;
	str s;

	s.s = (char*)*param;
	s.len = strlen(s.s);
	if (str2int(&s, &ui)!=0) {
		LM_ERR("flag index must be a number <%s>\n", (char *)(*param));
		return E_CFG;
	}
	if ( ui>=8*sizeof(unsigned int) ) {
		LM_ERR("flag index too high <%u> (max=%u)\n",
			ui, (unsigned int)(8*sizeof(unsigned int)-1) );
		return E_CFG;
	}
	pkg_free(*param);
	*param=(void *)(unsigned long)(1<<ui);
	return 0;
}

static int fixup_create_dlg2(void **param, int param_no)
{
	return fixup_sgp(param);
}

static int fixup_dlg_sval(void** param, int param_no)
{
	pv_elem_t *model=NULL;
	str s;

	s.s = (char*)*param;
	s.len = strlen(s.s);
	if (param_no==1) {
		/* name of the value */
		return fixup_str(param);
	} else if (param_no==2) {
		/* value */
		if(pv_parse_format(&s ,&model) || model==NULL) {
			LM_ERR("wrong format [%s] for value param!\n", s.s);
			return E_CFG;
		}
		*param = (void*)model;
	}

	return 0;
}


static int fixup_dlg_fval(void** param, int param_no)
{
	pv_spec_t *sp;
	int ret;

	if (param_no==1) {
		/* name of the value */
		return fixup_str(param);
	} else if (param_no==2) {
		/* var to store the value */
		ret = fixup_pvar(param);
		if (ret<0) return ret;
		sp = (pv_spec_t*)(*param);
		if (sp->type!=PVT_AVP && sp->type!=PVT_SCRIPTVAR) {
			LM_ERR("return must be an AVP or SCRIPT VAR!\n");
			return E_SCRIPT;
		}
	}

	return 0;
}


static int fixup_get_info(void** param, int param_no)
{
	pv_elem_t *model=NULL;
	pv_spec_t *sp;
	str s;
	int ret;

	if (param_no==1) {
		/* name of the dlg val to be returned  */
		return fixup_str(param);
	} else if (param_no==2) {
		/* var to store the dlg_val value */
		ret = fixup_pvar(param);
		if (ret<0) return ret;
		sp = (pv_spec_t*)(*param);
		if (sp->type!=PVT_AVP && sp->type!=PVT_SCRIPTVAR) {
			LM_ERR("return must be an AVP or SCRIPT VAR!\n");
			return E_SCRIPT;
		}
	} else if (param_no==3) {
		/* name of the dlg val to identify the dialog */
		return fixup_str(param);
	} else if (param_no==4) {
		/* var to hold the value of the indeification dlg val */
		s.s = (char*)*param;
		s.len = strlen(s.s);
		if(pv_parse_format(&s ,&model) || model==NULL) {
			LM_ERR("wrong format [%s] for value param!\n", s.s);
			return E_CFG;
		}
		*param = (void*)model;
	}

	return 0;
}

static int create_dialog_wrapper(struct sip_msg *req,int flags)
{
	struct cell *t;
	struct dlg_cell *dlg;

	/* is the dialog already created? */
	if ((dlg = get_current_dialog())!=NULL) {
		dlg->flags |= flags;
		return 1;
	}

	t = d_tmb.t_gett();
	if (dlg_create_dialog( (t==T_UNDEFINED)?NULL:t, req,flags)!=0)
		return -1;

	return 1;
}

int load_dlg( struct dlg_binds *dlgb )
{
	dlgb->register_dlgcb = register_dlgcb;
	dlgb->create_dlg = create_dialog_wrapper;
	dlgb->get_dlg = get_current_dialog;
	dlgb->add_profiles = add_profile_definitions;
	dlgb->search_profile = search_dlg_profile;
	dlgb->set_profile = set_dlg_profile;
	dlgb->unset_profile = unset_dlg_profile;
	dlgb->get_profile_size = get_profile_size;
	dlgb->store_dlg_value = store_dlg_value;
	dlgb->fetch_dlg_value = fetch_dlg_value;
	dlgb->terminate_dlg = terminate_dlg;

	dlgb->match_dialog = w_match_dialog;
	dlgb->fix_route_dialog = fix_route_dialog;
	dlgb->validate_dialog = dlg_validate_dialog;

	return 1;
}


static int pv_get_dlg_count(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	int n;
	int l;
	char *ch;

	if(res==NULL)
		return -1;

	n = active_dlgs ? get_stat_val(active_dlgs) : 0;
	l = 0;
	ch = int2str( n, &l);

	res->rs.s = ch;
	res->rs.len = l;

	res->ri = n;
	res->flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;

	return 0;
}


static int mod_init(void)
{
	unsigned int n;

	LM_INFO("Dialog module - initializing\n");

	if (timeout_spec.s)
		timeout_spec.len = strlen(timeout_spec.s);

	init_db_url( db_url , 1 /*can be null*/);
	dlg_id_column.len = strlen(dlg_id_column.s);
	call_id_column.len = strlen(call_id_column.s);
	from_uri_column.len = strlen(from_uri_column.s);
	from_tag_column.len = strlen(from_tag_column.s);
	to_uri_column.len = strlen(to_uri_column.s);
	to_tag_column.len = strlen(to_tag_column.s);
	state_column.len = strlen(state_column.s);
	start_time_column.len = strlen(start_time_column.s);
	timeout_column.len = strlen(timeout_column.s);
	to_cseq_column.len = strlen(to_cseq_column.s);
	from_cseq_column.len = strlen(from_cseq_column.s);
	to_route_column.len = strlen(to_route_column.s);
	from_route_column.len = strlen(from_route_column.s);
	to_contact_column.len = strlen(to_contact_column.s);
	from_contact_column.len = strlen(from_contact_column.s);
	to_sock_column.len = strlen(to_sock_column.s);
	from_sock_column.len = strlen(from_sock_column.s);
	profiles_column.len = strlen(profiles_column.s);
	vars_column.len = strlen(vars_column.s);
	sflags_column.len = strlen(sflags_column.s);
	flags_column.len = strlen(flags_column.s);
	dialog_table_name.len = strlen(dialog_table_name.s);

	/* param checkings */

	if( log_profile_hash_size <= 0)
	{
		LM_ERR("invalid value for log_profile_hash_size:%d!!\n",
			log_profile_hash_size);
		return -1;
	}

	if (rr_param.s==0 || rr_param.s[0]==0) {
		LM_ERR("empty rr_param!!\n");
		return -1;
	}
	rr_param.len = strlen(rr_param.s);
	if (rr_param.len>MAX_DLG_RR_PARAM_NAME) {
		LM_ERR("rr_param too long (max=%d)!!\n", MAX_DLG_RR_PARAM_NAME);
		return -1;
	}

	if (default_timeout<=0) {
		LM_ERR("0 default_timeout not accepted!!\n");
		return -1;
	}


	if (ping_interval<=0) {
		LM_ERR("Non-positive ping interval not accepted!!\n");
		return -1;
	}

	/* update the len of the extra headers */
	if (dlg_extra_hdrs.s)
		dlg_extra_hdrs.len = strlen(dlg_extra_hdrs.s);

	if (seq_match_mode!=SEQ_MATCH_NO_ID &&
	seq_match_mode!=SEQ_MATCH_FALLBACK &&
	seq_match_mode!=SEQ_MATCH_STRICT_ID ) {
		LM_ERR("invalid value %d for seq_match_mode param!!\n",seq_match_mode);
		return -1;
	}

	/* if statistics are disabled, prevent their registration to core */
	if (dlg_enable_stats==0)
		exports.stats = 0;

	/* we are only interested in these parameters if the cachedb url was defined */
	if (cdb_url.s) {
		cdb_url.len = strlen(cdb_url.s);
		if (init_cachedb_utils() <0) {
			LM_ERR("cannot init cachedb utils\n");
			return -1;
		}

		cdb_val_prefix.len = strlen(cdb_val_prefix.s);
		cdb_noval_prefix.len = strlen(cdb_noval_prefix.s);
		cdb_size_prefix.len = strlen(cdb_size_prefix.s);
	}

	/* create profile hashes */
	if (add_profile_definitions( profiles_nv_s, 0)!=0 ) {
		LM_ERR("failed to add profiles without value\n");
		return -1;
	}
	if (add_profile_definitions( profiles_wv_s, 1)!=0 ) {
		LM_ERR("failed to add profiles with value\n");
		return -1;
	}


	/* load the TM API */
	if (load_tm_api(&d_tmb)!=0) {
		LM_ERR("can't load TM API\n");
		return -1;
	}

	/* load RR API also */
	if (load_rr_api(&d_rrb)!=0) {
		LM_ERR("can't load RR API\n");
		return -1;
	}

	/* register callbacks*/
	/* listen for all incoming requests  */
	if ( d_tmb.register_tmcb( 0, 0, TMCB_REQUEST_IN, dlg_onreq, 0, 0 ) <=0 ) {
		LM_ERR("cannot register TMCB_REQUEST_IN callback\n");
		return -1;
	}

	/* listen for all routed requests  */
	if ( d_rrb.register_rrcb( dlg_onroute, 0, 1 ) <0 ) {
		LM_ERR("cannot register RR callback\n");
		return -1;
	}

	if (register_script_cb( dialog_cleanup, POST_SCRIPT_CB|REQ_TYPE_CB,0)<0) {
		LM_ERR("cannot regsiter script callback");
		return -1;
	}

	if (accept_replicated_dlg &&
		bin_register_cb("dialog", receive_binary_packet) < 0) {
		LM_ERR("Cannot register binary packet callback!\n");
		return -1;
	}

	if (dlg_have_own_timer_proc) {
		LM_INFO("Running with dedicated dialog timer process\n");
		dlg_own_timer_proc = register_timer_process( "dlg-timer",
			dlg_timer_routine, NULL,1,TIMER_PROC_INIT_FLAG );
		if (dlg_own_timer_proc == NULL) {
			LM_ERR("Failed to init dialog own timer proc\n");
			return -1;
		}
		if (append_timer_to_process("dlg-pinger", dlg_ping_routine, NULL,
							ping_interval,dlg_own_timer_proc) < 0) {
				LM_ERR("Failed to append ping timer \n");
				return -1;
		}
	}
	else {
		if ( register_timer( "dlg-timer", dlg_timer_routine, NULL, 1)<0 ) {
			LM_ERR("failed to register timer \n");
			return -1;
		}

		if ( register_timer( "dlg-pinger", dlg_ping_routine, NULL,
		ping_interval)<0) {
			LM_ERR("failed to register timer 2 \n");
			return -1;
		}
	}

	/* init handlers */
	init_dlg_handlers(default_timeout);

	/* init timer */
	if (init_dlg_timer(dlg_ontimeout)!=0) {
		LM_ERR("cannot init timer list\n");
		return -1;
	}

	if (init_dlg_ping_timer()!=0) {
		LM_ERR("cannot init ping timer\n");
		return -1;
	}

	/* initialized the hash table */
	for( n=0 ; n<(8*sizeof(n)) ; n++) {
		if (dlg_hash_size==(1<<n))
			break;
		if (dlg_hash_size<(1<<n)) {
			LM_WARN("hash_size is not a power "
				"of 2 as it should be -> rounding from %d to %d\n",
				dlg_hash_size, 1<<(n-1));
			dlg_hash_size = 1<<(n-1);
			break;
		}
	}

	if ( init_dlg_table(dlg_hash_size)<0 ) {
		LM_ERR("failed to create hash table\n");
		return -1;
	}

	/* if a database should be used to store the dialogs' information */
	if (dlg_db_mode==DB_MODE_NONE) {
		db_url.s = 0; db_url.len = 0;
	} else {
		if (dlg_db_mode!=DB_MODE_REALTIME &&
		dlg_db_mode!=DB_MODE_DELAYED && dlg_db_mode!=DB_MODE_SHUTDOWN ) {
			LM_ERR("unsupported db_mode %d\n", dlg_db_mode);
			return -1;
		}
		if ( !db_url.s || db_url.len==0 ) {
			LM_ERR("db_url not configured for db_mode %d\n", dlg_db_mode);
			return -1;
		}
		if (init_dlg_db(&db_url, dlg_hash_size, db_update_period)!=0) {
			LM_ERR("failed to initialize the DB support\n");
			return -1;
		}
		run_load_callbacks();
	}

	mark_dlg_loaded_callbacks_run();
	destroy_cachedb(0);

	return 0;
}




static int child_init(int rank)
{
	if (rank==1) {
		if_update_stat(dlg_enable_stats, active_dlgs, active_dlgs_cnt);
		if_update_stat(dlg_enable_stats, early_dlgs, early_dlgs_cnt);
	}

	if ( (dlg_db_mode==DB_MODE_REALTIME &&
		(rank>=0 || rank==PROC_TIMER || rank==PROC_MODULE)) ||
	(dlg_db_mode==DB_MODE_SHUTDOWN && (rank==(dont_fork?1:PROC_MAIN) ||
		rank==PROC_MODULE) ) ||
	(dlg_db_mode==DB_MODE_DELAYED && (rank==PROC_MAIN || rank==PROC_MODULE ||
		rank==PROC_TIMER || rank>0) )){
		if ( dlg_connect_db(&db_url) ) {
			LM_ERR("failed to connect to database (rank=%d)\n",rank);
			return -1;
		}
	}

	if (cdb_url.s && cdb_url.len && init_cachedb() < 0) {
		LM_ERR("cannot init cachedb feature\n");
		return -1;
	}

	return 0;
}

static void mod_destroy(void)
{
	if (dlg_db_mode != DB_MODE_NONE) {
		dialog_update_db(0, 0);
		destroy_dlg_db();
	}
	/* no DB interaction from now on */
	dlg_db_mode = DB_MODE_NONE;
	destroy_dlg_table();
	destroy_dlg_timer();
	destroy_ping_timer();
	destroy_dlg_callbacks( DLGCB_CREATED|DLGCB_LOADED );
	destroy_dlg_handlers();
	destroy_dlg_profiles();

	destroy_cachedb(1);
}


static int w_create_dialog(struct sip_msg *req)
{
	struct cell *t;
	/* is the dialog already created? */
	if (get_current_dialog()!=NULL)
		return 1;

	t = d_tmb.t_gett();
	if (dlg_create_dialog( (t==T_UNDEFINED)?NULL:t, req,0)!=0)
		return -1;

	return 1;
}

static int w_create_dialog2(struct sip_msg *req,char *param)
{
	struct cell *t;
	str res = {0,0};
	int flags;

	if (fixup_get_svalue(req, (gparam_p)param, &res) !=0)
	{
		LM_ERR("no create dialog flags\n");
		return -1;
	}

	flags = parse_create_dlg_flags(res);

	/* is the dialog already created? */
	if (current_dlg_pointer!=NULL)
	{
		/*Clear current flags before setting new ones*/
		current_dlg_pointer->flags &= ~(DLG_FLAG_PING_CALLER | DLG_FLAG_PING_CALLEE | DLG_FLAG_BYEONTIMEOUT);
		current_dlg_pointer->flags |= flags;
		return 1;
	}

	t = d_tmb.t_gett();
	if (dlg_create_dialog( (t==T_UNDEFINED)?NULL:t, req,flags)!=0)
		return -1;

	return 1;
}


static int w_match_dialog(struct sip_msg *msg)
{
	int backup,i;
	void *match_param = NULL;
	struct sip_uri *r_uri;


	/* dialog already found ? */
	if (get_current_dialog()!=NULL)
		return 1;

	/* small trick to force SIP-wise matching */
	backup = seq_match_mode;
	seq_match_mode = SEQ_MATCH_FALLBACK;

	/* See if we can force DID matching, for the case of topo
	 * hiding, where we have the DID as param of the contact */
	if (parse_sip_msg_uri(msg)<0) {
		LM_ERR("Failed to parse request URI\n");
		goto sipwise;
	}

	if (parse_headers(msg, HDR_ROUTE_F, 0) == -1) {
		LM_ERR("failed to parse route headers\n");
		goto sipwise;
	}

	r_uri = &msg->parsed_uri;

	if (check_self(&r_uri->host,r_uri->port_no ? r_uri->port_no : SIP_PORT, 0) == 1 &&
		msg->route == NULL) {
		/* Seems we are in the topo hiding case :
		 * we are in the R-URI and there are no other route headers */
		for (i=0;i<r_uri->u_params_no;i++)
			if (r_uri->u_name[i].len == rr_param.len &&
				memcmp(rr_param.s,r_uri->u_name[i].s,rr_param.len)==0) {
				LM_DBG("We found DID param in R-URI with value of %.*s \n",
					r_uri->u_val[i].len,r_uri->u_val[i].s);
				/* pass the param value to the matching funcs */
				match_param = (void *)(&r_uri->u_val[i]);
			}
	}

sipwise:
	dlg_onroute( msg, NULL, match_param);

	seq_match_mode = backup;

	return (current_dlg_pointer==NULL)?-1:1;
}


static int w_validate_dialog(struct sip_msg *req)
{
	struct dlg_cell *dlg;
	int ret;

	dlg = get_current_dialog();
	if (dlg==NULL)
	{
		LM_ERR("null dialog\n");
		return -4;
	}

	ret = dlg_validate_dialog(req,dlg);

	if (ret == 0)
		ret = 1;

	return ret;
}


static int w_fix_route_dialog(struct sip_msg *req)
{
	struct dlg_cell *dlg;

	dlg = get_current_dialog();
	if (dlg==NULL)
		return -1;

	if (fix_route_dialog( req, dlg )!=0)
		return -1;

	return 1;
}


static int w_set_dlg_profile(struct sip_msg *msg, char *profile, char *value)
{
	pv_elem_t *pve;
	str val_s;

	pve = (pv_elem_t *)value;

	if (((struct dlg_profile_table*)profile)->has_value) {
		if ( pve==NULL || pv_printf_s(msg, pve, &val_s)!=0 ||
		val_s.len == 0 || val_s.s == NULL) {
			LM_WARN("cannot get string for value\n");
			return -1;
		}
		if ( set_dlg_profile( msg, &val_s,
		(struct dlg_profile_table*)profile, 0) < 0 ) {
			LM_ERR("failed to set profile\n");
			return -1;
		}
	} else {
		if ( set_dlg_profile( msg, NULL,
		(struct dlg_profile_table*)profile, 0) < 0 ) {
			LM_ERR("failed to set profile\n");
			return -1;
		}
	}
	return 1;
}


static int w_unset_dlg_profile(struct sip_msg *msg, char *profile, char *value)
{
	pv_elem_t *pve;
	str val_s;

	pve = (pv_elem_t *)value;

	if (((struct dlg_profile_table*)profile)->has_value) {
		if ( pve==NULL || pv_printf_s(msg, pve, &val_s)!=0 ||
		val_s.len == 0 || val_s.s == NULL) {
			LM_WARN("cannot get string for value\n");
			return -1;
		}
		if ( unset_dlg_profile( msg, &val_s,
		(struct dlg_profile_table*)profile) < 0 ) {
			LM_ERR("failed to unset profile\n");
			return -1;
		}
	} else {
		if ( unset_dlg_profile( msg, NULL,
		(struct dlg_profile_table*)profile) < 0 ) {
			LM_ERR("failed to unset profile\n");
			return -1;
		}
	}
	return 1;
}


static int w_is_in_profile(struct sip_msg *msg, char *profile, char *value)
{
	pv_elem_t *pve;
	str val_s;

	pve = (pv_elem_t *)value;

	if ( pve!=NULL && ((struct dlg_profile_table*)profile)->has_value) {
		if ( pv_printf_s(msg, pve, &val_s)!=0 ||
		val_s.len == 0 || val_s.s == NULL) {
			LM_WARN("cannot get string for value\n");
			return -1;
		}
		return is_dlg_in_profile( msg, (struct dlg_profile_table*)profile,
			&val_s);
	} else {
		return is_dlg_in_profile( msg, (struct dlg_profile_table*)profile,
			NULL);
	}
}


static int w_get_profile_size(struct sip_msg *msg, char *profile,
													char *value, char *result)
{
	pv_elem_t *pve;
	str val_s;
	pv_spec_t *sp_dest;
	unsigned int size;
	int_str res;
	int avp_name;
	unsigned short avp_type;
	script_var_t * sc_var;

	pve = (pv_elem_t *)value;
	sp_dest = (pv_spec_t *)result;

	if ( pve!=NULL && ((struct dlg_profile_table*)profile)->has_value) {
		if ( pv_printf_s(msg, pve, &val_s)!=0 ||
		val_s.len == 0 || val_s.s == NULL) {
			LM_WARN("cannot get string for value\n");
			return -1;
		}
		size = get_profile_size( (struct dlg_profile_table*)profile ,&val_s );
	} else {
		size = get_profile_size( (struct dlg_profile_table*)profile, NULL );
	}

	switch (sp_dest->type) {
		case PVT_AVP:
			if (pv_get_avp_name( msg, &(sp_dest->pvp), &avp_name,
			&avp_type)!=0){
				LM_CRIT("BUG in getting AVP name\n");
				return -1;
			}
			res.n = size;
			if (add_avp(avp_type, avp_name, res)<0){
				LM_ERR("cannot add AVP\n");
				return -1;
			}
			break;

		case PVT_SCRIPTVAR:
			if(sp_dest->pvp.pvn.u.dname == 0){
				LM_ERR("cannot find svar name\n");
				return -1;
			}
			res.n = size;
			sc_var = (script_var_t *)sp_dest->pvp.pvn.u.dname;
			if(!set_var_value(sc_var, &res, 0)){
				LM_ERR("cannot set svar\n");
				return -1;
			}
			break;

		default:
			LM_CRIT("BUG: invalid pvar type\n");
			return -1;
	}

	return 1;
}


static int w_set_dlg_flag(struct sip_msg *msg, char *mask)
{
	struct dlg_cell *dlg;

	if ( (dlg=get_current_dialog())==NULL )
		return -1;

	dlg->user_flags |= (unsigned int)(unsigned long)mask;
	dlg->flags |= DLG_FLAG_VP_CHANGED;
	return 1;
}


static int w_reset_dlg_flag(struct sip_msg *msg, char *mask)
{
	struct dlg_cell *dlg;

	if ( (dlg=get_current_dialog())==NULL )
		return -1;

	dlg->user_flags &= ~((unsigned int)(unsigned long)mask);
	return 1;
}


static int w_is_dlg_flag_set(struct sip_msg *msg, char *mask)
{
	struct dlg_cell *dlg;

	if ( (dlg=get_current_dialog())==NULL )
		return -1;

	return (dlg->user_flags&((unsigned int)(unsigned long)mask))?1:-1;
}

static int w_tsl_dlg_flag(struct sip_msg *msg, char *_idx, char *_val)
{
	struct dlg_cell *dlg;

	if ( (dlg=get_current_dialog())==NULL )
		return -2;

	return test_and_set_dlg_flag(dlg, (unsigned long)(void *)_idx,
			(unsigned long)(void *) _val);
}


int w_store_dlg_value(struct sip_msg *msg, char *name, char *val)
{
	struct dlg_cell *dlg;
	pv_elem_t *pve = (pv_elem_t *)val;
	str val_s;

	if ( (dlg=get_current_dialog())==NULL )
		return -1;

	if ( pve==NULL || pv_printf_s(msg, pve, &val_s)!=0 ||
	val_s.len == 0 || val_s.s == NULL) {
		LM_WARN("cannot get string for value\n");
		return -1;
	}

	return (store_dlg_value( dlg, (str*)name, &val_s)==0)?1:-1;
}


int w_fetch_dlg_value(struct sip_msg *msg, char *name, char *result)
{
	struct dlg_cell *dlg;
	str val;

	pv_spec_t *sp_dest;
	int_str res;
	int avp_name;
	unsigned short avp_type;
	script_var_t * sc_var;

	sp_dest = (pv_spec_t *)result;

	if ( (dlg=get_current_dialog())==NULL )
		return -1;

	if (fetch_dlg_value( dlg, (str*)name, &val, 0) ) {
		LM_DBG("failed to fetch dialog value <%.*s>\n",
			((str*)name)->len, ((str*)name)->s);
		return -1;
	}

	switch (sp_dest->type) {
		case PVT_AVP:
			if (pv_get_avp_name( msg, &(sp_dest->pvp), &avp_name,
			&avp_type)!=0){
				LM_CRIT("BUG in getting AVP name\n");
				return -1;
			}
			res.s = val;
			if (add_avp(avp_type|AVP_VAL_STR, avp_name, res)<0){
				LM_ERR("cannot add AVP\n");
				return -1;
			}
			break;

		case PVT_SCRIPTVAR:
			if(sp_dest->pvp.pvn.u.dname == 0){
				LM_ERR("cannot find svar name\n");
				return -1;
			}
			res.s = val;
			sc_var = (script_var_t *)sp_dest->pvp.pvn.u.dname;
			if(!set_var_value(sc_var, &res, VAR_VAL_STR)){
				LM_ERR("cannot set svar\n");
				return -1;
			}
			break;

		default:
			LM_CRIT("BUG: invalid pvar type\n");
			return -1;
	}

	return 1;
}


static int w_get_dlg_info(struct sip_msg *msg, char *attr, char *attr_val,
													char *key, char *key_val)
{
	struct dlg_cell *dlg;
	pv_elem_t *pve = (pv_elem_t *)key_val;
	pv_spec_t *dst = (pv_spec_t *)attr_val;
	pv_value_t val;
	str val_s;
	int n;

	if ( pve==NULL || pv_printf_s(msg, pve, &val_s)!=0 ||
	val_s.len == 0 || val_s.s == NULL) {
		LM_WARN("cannot get string for value\n");
		return -1;
	}

	dlg = get_dlg_by_val( (str*)key, &val_s);

	if (dlg==NULL) {
		/* nothing found */
		LM_DBG("no dialog found\n");
		return -1;
	}

	/* dlg found - NOTE you have a ref! */
	LM_DBG("dialog found, fetching variable\n");

	if (fetch_dlg_value( dlg, (str*)attr, &val.rs, 0) ) {
		LM_DBG("failed to fetch dialog value <%.*s>\n",
			((str*)attr)->len, ((str*)attr)->s);
		n = -1 ;
	} else {
		val.flags = PV_VAL_STR;
		n = (dst->setf( msg, &dst->pvp, 0, &val )==0)?1:-1;
	}

	unref_dlg(dlg, 1);

	return n;
}


/* item/pseudo-variables functions */
int pv_get_dlg_lifetime(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	int l = 0;
	char *ch = NULL;
	struct dlg_cell *dlg;

	if(res==NULL)
		return -1;

	if ( (dlg=get_current_dialog())==NULL )
		return pv_get_null( msg, param, res);

	res->ri = (unsigned int)(dlg->state>2?((time(0))-dlg->start_ts):0);
	ch = int2str( (unsigned long)res->ri, &l);

	res->rs.s = ch;
	res->rs.len = l;

	res->flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;

	return 0;
}


int pv_get_dlg_status(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	int l = 0;
	char *ch = NULL;
	struct dlg_cell *dlg;

	if(res==NULL)
		return -1;

	if ( (dlg=get_current_dialog())==NULL )
		return pv_get_null( msg, param, res);

	res->ri = dlg->state;
	ch = int2str( (unsigned long)res->ri, &l);

	res->rs.s = ch;
	res->rs.len = l;

	res->flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;

	return 0;
}


int pv_get_dlg_flags(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	int l = 0;
	char *ch = NULL;
	struct dlg_cell *dlg;

	if(res==NULL)
		return -1;

	if ( (dlg=get_current_dialog())==NULL )
		return pv_get_null( msg, param, res);

	res->ri = dlg->user_flags;
	ch = int2str( (unsigned long)res->ri, &l);

	res->rs.s = ch;
	res->rs.len = l;

	res->flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;

	return 0;
}


int pv_get_dlg_timeout(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	int l = 0;
	char *ch = NULL;
	struct dlg_cell *dlg;

	if(res==NULL)
		return -1;

	if ( (dlg=get_current_dialog())!=NULL ) {

		dlg_lock_dlg(dlg);
		if (dlg->state < DLG_STATE_CONFIRMED_NA)
			l = dlg->lifetime;
		else
			l = dlg->tl.timeout - get_ticks();
		dlg_unlock_dlg(dlg);

	} else if (msg->id == dlg_tmp_timeout_id && dlg_tmp_timeout != -1) {
		l = dlg_tmp_timeout;
	} else {
		return pv_get_null( msg, param, res);
	}

	res->ri = l;

	ch = int2str( (unsigned long)res->ri, &l);
	res->rs.s = ch;
	res->rs.len = l;

	res->flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;

	return 0;
}

int pv_get_dlg_dir(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	struct dlg_cell *dlg;

	if(res==NULL)
		return -1;

	if ( (dlg=get_current_dialog())==NULL || last_dst_leg<0)
		return pv_get_null( msg, param, res);

	if (last_dst_leg==0) {
		res->rs.s = "upstream";
		res->rs.len = 8;
	} else {
		res->rs.s = "downstream";
		res->rs.len = 10;
	}

	res->flags = PV_VAL_STR;

	return 0;
}

/* the maximum value we can have is 2 ints + ':' */
static char buf_get_did[2 * INT2STR_MAX_LEN];
int pv_get_dlg_did(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	struct dlg_cell *dlg;
	str aux;

	if(res==NULL)
		return -1;

	if ( (dlg=get_current_dialog())==NULL )
		return pv_get_null( msg, param, res);

	res->rs.s = buf_get_did;

	aux.s = int2str( (unsigned long)dlg->h_entry, &aux.len);
	if (!aux.s || !aux.len) {
		LM_ERR("invalid hash entry\n");
		return -1;
	}

	memcpy(buf_get_did, aux.s, aux.len);
	buf_get_did[aux.len] = ':';
	res->rs.len = aux.len + 1;

	aux.s = int2str( (unsigned long)dlg->h_id, &aux.len);
	if (!aux.s || !aux.len) {
		LM_ERR("invalid hash id\n");
		return -1;
	}

	memcpy(buf_get_did + res->rs.len, aux.s, aux.len);
	res->rs.len += aux.len;

	res->flags = PV_VAL_STR;

	return 0;
}

int pv_get_dlg_end_reason(struct sip_msg *msg, pv_param_t *param, pv_value_t *res)
{
	struct dlg_cell *dlg;

	if(res==NULL)
		return -1;

	if ( (dlg=get_current_dialog())==NULL || dlg->terminate_reason.s == NULL) {
		return pv_get_null( msg, param, res);
	}

	res->rs = dlg->terminate_reason;
	res->flags = PV_VAL_STR;

	return 0;
}

int pv_set_dlg_flags(struct sip_msg *msg, pv_param_t *param,
		int op, pv_value_t *val)
{
	struct dlg_cell *dlg;

	if ( (dlg=get_current_dialog())==NULL )
		return -1;

	if (val==NULL) {
		dlg->user_flags = 0;
		return 0;
	}

	if (!(val->flags&PV_VAL_INT)){
		LM_ERR("assigning non-int value to dialog flags\n");
		return -1;
	}

	dlg->user_flags = val->ri;

	return 0;
}

int pv_set_dlg_timeout(struct sip_msg *msg, pv_param_t *param,
		int op, pv_value_t *val)
{
	struct dlg_cell *dlg;
	int timeout, db_update = 0, timer_update = 0;

	if (val==NULL || val->flags & PV_VAL_NULL) {
		LM_ERR("cannot assign dialog timeout to NULL\n");
		return -1;
	}

	if (!(val->flags&PV_VAL_INT)){
		/* try parsing the string */
		if (str2sint(&val->rs, &timeout) < 0) {
			LM_ERR("assigning non-int value to dialog flags\n");
			return -1;
		}
	} else {
		timeout = val->ri;
	}

	if (timeout < 0) {
		LM_ERR("cannot set a negative timeout\n");
		return -1;
	}
	if ((dlg = get_current_dialog()) != NULL) {

		dlg_lock_dlg(dlg);
		dlg->lifetime = timeout;
		/* update now only if realtime and the dialog is confirmed */
		if (dlg->state >= DLG_STATE_CONFIRMED && dlg_db_mode == DB_MODE_REALTIME)
			db_update = 1;
		else
			dlg->flags |= DLG_FLAG_CHANGED;
		if (dlg->state >= DLG_STATE_CONFIRMED_NA)
			timer_update = 1;
		dlg_unlock_dlg(dlg);

		if (db_update)
			update_dialog_timeout_info(dlg);

		if (replication_dests)
			replicate_dialog_updated(dlg);

		/* make sure we don't update it again later */
		dlg_tmp_timeout = -1;
		dlg_tmp_timeout_id = -1;

		if (timer_update && update_dlg_timer(&dlg->tl, timeout) < 0) {
			LM_ERR("failed to update timer\n");
			return -1;
		}
	} else {
		/* store it until we match the dialog */
		dlg_tmp_timeout = timeout;
		dlg_tmp_timeout_id = msg->id;
	}

	return 0;
}

static int add_replication_dest(modparam_t type, void *val)
{
	struct replication_dest *rd;
	char *host;
	int hlen, port;
	int proto;
	struct hostent *he;
	str st;

	rd = pkg_malloc(sizeof(*rd));
	memset(rd, 0, sizeof(*rd));

	if (parse_phostport(val, strlen(val), &host, &hlen, &port, &proto) < 0) {
		LM_ERR("Bad replication destination IP!\n");
		return -1;
	}

	if (proto == PROTO_NONE)
		proto = PROTO_UDP;

	if (proto != PROTO_UDP) {
		LM_ERR("Dialog replication only supports UDP packets!\n");
		return -1;
	}

	st.s = host;
	st.len = hlen;
	he = sip_resolvehost(&st, (unsigned short *)&port,
							  (unsigned short *)&proto, 0, 0);
	if (!he) {
		LM_ERR("Cannot resolve host: %.*s\n", hlen, host);
		return -1;
	}

	hostent2su(&rd->to, he, 0, port);

	rd->next = replication_dests;
	replication_dests = rd;

	return 1;
}

