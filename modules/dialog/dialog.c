/*
 * dialog module - basic support for dialog tracking
 *
 * Copyright (C) 2008-2020 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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
#include "../../pt.h"
#include "../../pvar.h"
#include "../../context.h"
#include "../../script_cb.h"
#include "../../script_var.h"
#include "../../mem/mem.h"
#include "../../mi/mi.h"
#include "../rr/api.h"
#include "../../bin_interface.h"
#include "../clusterer/api.h"
#include "../../lib/container.h"

#include "dlg_ctx.h"
#include "dlg_hash.h"
#include "dlg_timer.h"
#include "dlg_handlers.h"
#include "dlg_load.h"
#include "dlg_cb.h"
#include "dlg_db_handler.h"
#include "dlg_req_within.h"
#include "dlg_profile.h"
#include "dlg_vals.h"
#include "dlg_replication.h"
#include "dlg_repl_profile.h"

static int mod_init(void);
static int child_init(int rank);
static void mod_destroy(void);

/* module parameter */
int log_profile_hash_size = 4;
str rr_param = {"did",3};
static int dlg_hash_size = 4096;
static str timeout_spec = {NULL, 0};
static int default_timeout = 60 * 60 * 12;  /* 12 hours */
static char* profiles_wv_s = NULL;
static char* profiles_nv_s = NULL;

int dlg_bulk_del_no = 1; /* delete one by one */
int seq_match_mode = SEQ_MATCH_FALLBACK;
int options_ping_interval = 30;      /* seconds */
int reinvite_ping_interval = 300;    /* seconds */
str dlg_extra_hdrs = {NULL,0};
int race_condition_timeout = 5; /* seconds until call termination is triggered,
					after 200OK -> CANCEL race detection */

/* statistic variables */
int dlg_enable_stats = 1;
int active_dlgs_cnt = 0;
int early_dlgs_cnt = 0;
int db_flush_vp = 0;
int dlg_event_id_format = 0;
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

/* cachedb stuff */
str cdb_url = {0,0};

/* dialog replication using clusterer */
int dialog_repl_cluster = 0;
int profile_repl_cluster = 0;
str dlg_repl_cap = str_init("dialog-dlg-repl");
str prof_repl_cap = str_init("dialog-prof-repl");

static int pv_get_dlg_count( struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);

/* commands wrappers and fixups */
static int w_create_dialog(struct sip_msg*, str *flags_str);
static int w_match_dialog(struct sip_msg *msg, void *seq_match_mode_val);
static int api_match_dialog(struct sip_msg *msg, int _seq_match_mode);
static int w_validate_dialog(struct sip_msg*);
static int w_fix_route_dialog(struct sip_msg*);
static int w_set_dlg_profile(struct sip_msg *msg, str *prof_name, str *value);
static int w_unset_dlg_profile(struct sip_msg *msg, str *prof_name, str *value);
static int w_is_in_profile(struct sip_msg *msg, str *prof_name, str *value);
static int w_get_profile_size(struct sip_msg *msg, str *prof_name,
							str *value, pv_spec_t *result);
static int fixup_mmode(void **param);
static int fixup_dlg_flag(void** param);
static int fixup_check_avp(void** param);
static int fixup_check_var(void** param);
static int fixup_lmode(void **param);
static int fixup_leg(void **param);
static int w_set_dlg_flag(struct sip_msg *msg, void *mask);
static int w_reset_dlg_flag(struct sip_msg *msg, void *mask);
static int w_is_dlg_flag_set(struct sip_msg *msg, void *mask);
static int w_store_dlg_value(struct sip_msg *msg, str *name, str *val);
int w_fetch_dlg_value(struct sip_msg *msg, str *name, pv_spec_t *result);
static int w_get_dlg_info(struct sip_msg *msg, str *attr, pv_spec_t *attr_val,
		str *key, str *key_val, pv_spec_t *number_val);
static int w_get_dlg_jsons_by_val(struct sip_msg *msg,
		str *attr, str *attr_val, pv_spec_t *out, pv_spec_t *number_val);
static int w_get_dlg_jsons_by_profile(struct sip_msg *msg,
		str *attr, str *attr_val, pv_spec_t *out, pv_spec_t *number_val);
static int w_get_dlg_vals(struct sip_msg *msg, pv_spec_t *v_name,
		pv_spec_t *v_val, str *callid);
static int w_tsl_dlg_flag(struct sip_msg *msg, int *_idx, int *_val);
static int w_set_dlg_shtag(struct sip_msg *msg, str *shtag);
static int load_dlg_ctx(struct sip_msg *msg, str *callid, void* lmode);
static int unload_dlg_ctx(struct sip_msg *msg);

static int fixup_route(void** param);
static int dlg_on_timeout(struct sip_msg* msg, void *route_id);
static int dlg_on_answer(struct sip_msg* msg, void *route_id);
static int dlg_on_hangup(struct sip_msg* msg, void *route_id);
static int dlg_send_sequential(struct sip_msg* msg, str *method, int leg,
		str *body, str *ct, str *headers);


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
int pv_get_dlg_json(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);
int pv_get_dlg_ctx_json(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);

static cmd_export_t cmds[]={
	{"create_dialog", (cmd_function)w_create_dialog, {
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, {0,0,0}},
		REQUEST_ROUTE},
	{"set_dlg_profile", (cmd_function)w_set_dlg_profile, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, {0,0,0}},
		REQUEST_ROUTE| FAILURE_ROUTE | ONREPLY_ROUTE | BRANCH_ROUTE},
	{"unset_dlg_profile", (cmd_function)w_unset_dlg_profile, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, {0,0,0}},
		REQUEST_ROUTE| FAILURE_ROUTE | ONREPLY_ROUTE | BRANCH_ROUTE},
	{"is_in_profile", (cmd_function)w_is_in_profile, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, {0,0,0}},
		REQUEST_ROUTE| FAILURE_ROUTE | ONREPLY_ROUTE | BRANCH_ROUTE},
	{"get_profile_size", (cmd_function)w_get_profile_size, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_VAR,fixup_check_var,0}, {0,0,0}},
		REQUEST_ROUTE| FAILURE_ROUTE | ONREPLY_ROUTE | BRANCH_ROUTE},
	{"set_dlg_flag", (cmd_function)w_set_dlg_flag, {
		{CMD_PARAM_INT,fixup_dlg_flag,0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"test_and_set_dlg_flag",(cmd_function)w_tsl_dlg_flag, {
		{CMD_PARAM_INT,0,0},
		{CMD_PARAM_INT,0,0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"reset_dlg_flag", (cmd_function)w_reset_dlg_flag, {
		{CMD_PARAM_INT,fixup_dlg_flag,0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"is_dlg_flag_set",(cmd_function)w_is_dlg_flag_set, {
		{CMD_PARAM_INT,fixup_dlg_flag,0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"store_dlg_value",(cmd_function)w_store_dlg_value, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR,0,0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"fetch_dlg_value",(cmd_function)w_fetch_dlg_value, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_VAR,fixup_check_var,0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"validate_dialog",(cmd_function)w_validate_dialog, {{0,0,0}},
		REQUEST_ROUTE},
	{"fix_route_dialog",(cmd_function)w_fix_route_dialog, {{0,0,0}},
		REQUEST_ROUTE},
	{"get_dialog_info",(cmd_function)w_get_dlg_info, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_VAR,fixup_check_avp,0},
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_VAR,fixup_check_var,0}, {0,0,0}},
		ALL_ROUTES},
	{"get_dialog_vals",(cmd_function)w_get_dlg_vals, {
		{CMD_PARAM_VAR,fixup_check_avp,0},
		{CMD_PARAM_VAR,fixup_check_avp,0},
		{CMD_PARAM_STR,0,0}, {0,0,0}},
		ALL_ROUTES},
	{"get_dialogs_by_val",(cmd_function)w_get_dlg_jsons_by_val, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_VAR,fixup_check_avp,0},
		{CMD_PARAM_VAR,fixup_check_var,0}, {0,0,0}},
		ALL_ROUTES},
	{"get_dialogs_by_profile",(cmd_function)w_get_dlg_jsons_by_profile, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_VAR,fixup_check_avp,0},
		{CMD_PARAM_VAR,fixup_check_var,0}, {0,0,0}},
		ALL_ROUTES},
	{"match_dialog",  (cmd_function)w_match_dialog, {
		{CMD_PARAM_STR|CMD_PARAM_OPT,fixup_mmode,0}, {0,0,0}},
		REQUEST_ROUTE},
	{"set_dlg_sharing_tag", (cmd_function)w_set_dlg_shtag, {
		{CMD_PARAM_STR,0,0}, {0,0,0}},
		REQUEST_ROUTE},
	{"load_dialog_ctx",(cmd_function)load_dlg_ctx, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,fixup_lmode,0}, {0,0,0}},
		ALL_ROUTES},
	{"unload_dialog_ctx",(cmd_function)unload_dlg_ctx,
		{{0,0,0}}, ALL_ROUTES},
	{"dlg_on_timeout", (cmd_function)dlg_on_timeout, {
		{CMD_PARAM_STR|CMD_PARAM_OPT, fixup_route, 0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE},
	{"dlg_on_answer", (cmd_function)dlg_on_answer, {
		{CMD_PARAM_STR|CMD_PARAM_OPT, fixup_route, 0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE},
	{"dlg_on_hangup", (cmd_function)dlg_on_hangup, {
		{CMD_PARAM_STR|CMD_PARAM_OPT, fixup_route, 0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE},
	{"dlg_send_sequential", (cmd_function)dlg_send_sequential, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, fixup_leg, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{"load_dlg", (cmd_function)load_dlg, {{0,0,0}}, 0},
	{0,0,{{0,0,0}},0}
};

static param_export_t mod_params[]={
	{ "enable_stats",          INT_PARAM, &dlg_enable_stats         },
	{ "hash_size",             INT_PARAM, &dlg_hash_size            },
	{ "log_profile_hash_size", INT_PARAM, &log_profile_hash_size    },
	{ "rr_param",              STR_PARAM, &rr_param.s               },
	{ "default_timeout",       INT_PARAM, &default_timeout          },
	{ "options_ping_interval", INT_PARAM, &options_ping_interval    },
	{ "reinvite_ping_interval",INT_PARAM, &reinvite_ping_interval   },
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
	{ "mflags_column",         STR_PARAM, &mflags_column.s          },
	{ "flags_column",          STR_PARAM, &flags_column.s           },
	{ "db_update_period",      INT_PARAM, &db_update_period         },
	{ "profiles_with_value",   STR_PARAM, &profiles_wv_s            },
	{ "profiles_no_value",     STR_PARAM, &profiles_nv_s            },
	{ "db_flush_vals_profiles",INT_PARAM, &db_flush_vp              },
	{ "timer_bulk_del_no",     INT_PARAM, &dlg_bulk_del_no          },
	{ "race_condition_timeout",INT_PARAM, &race_condition_timeout	},
	/* distributed profiles stuff */
	{ "cachedb_url",           	 STR_PARAM, &cdb_url.s              },
	{ "profile_value_prefix",    STR_PARAM, &cdb_val_prefix.s       },
	{ "profile_no_value_prefix", STR_PARAM, &cdb_noval_prefix.s     },
	{ "profile_size_prefix",     STR_PARAM, &cdb_size_prefix.s      },
	{ "profile_timeout",         INT_PARAM, &profile_timeout        },
	/* dialog replication through clusterer using TCP binary packets */
	{ "dialog_replication_cluster",     INT_PARAM, &dialog_repl_cluster  },
	{ "profile_replication_cluster",	INT_PARAM, &profile_repl_cluster },
	{ "replicate_profiles_timer", INT_PARAM, &repl_prof_utimer      },
	{ "replicate_profiles_check", INT_PARAM, &repl_prof_timer_check },
	{ "replicate_profiles_buffer",INT_PARAM, &repl_prof_buffer_th   },
	{ "replicate_profiles_expire",INT_PARAM, &repl_prof_timer_expire},
	{ "event_id_format",          INT_PARAM, &dlg_event_id_format},
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
	{ "dlg_list", 0, MI_NAMED_PARAMS_ONLY, 0, {
		{mi_print_dlgs, {0}},
		{mi_print_dlgs_1, {"callid", 0}},
		{mi_print_dlgs_2, {"callid", "from_tag", 0}},
		{mi_print_dlgs_cnt, {"index", "counter", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "dlg_list_ctx", 0, MI_NAMED_PARAMS_ONLY, 0, {
		{mi_print_dlgs_ctx, {0}},
		{mi_print_dlgs_1_ctx, {"callid", 0}},
		{mi_print_dlgs_2_ctx, {"callid", "from_tag", 0}},
		{mi_print_dlgs_cnt_ctx, {"index", "counter", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "dlg_end_dlg", 0, 0, 0, {
		{mi_terminate_dlg_1, {"dialog_id", 0}},
		{mi_terminate_dlg_2, {"dialog_id", "extra_hdrs", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "dlg_db_sync", 0, 0, 0, {
		{mi_sync_db_dlg, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "dlg_restore_db", 0, 0, 0, {
		{mi_restore_dlg_db, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "dlg_cluster_sync", 0, 0, 0, {
		{mi_sync_cl_dlg, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "profile_get_size", 0, 0, 0, {
		{mi_get_profile_1, {"profile", 0}},
		{mi_get_profile_2, {"profile", "value", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "profile_list_dlgs", 0, 0, 0, {
		{mi_profile_list_1, {"profile", 0}},
		{mi_profile_list_2, {"profile", "value", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "profile_get_values", 0, 0, 0, {
		{mi_get_profile_values, {"profile", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "list_all_profiles", 0, 0, 0, {
		{mi_list_all_profiles, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "profile_end_dlgs", 0, 0, 0, {
		{mi_profile_terminate_1, {"profile", 0}},
		{mi_profile_terminate_2, {"profile", "value", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "dlg_push_var", 0, 0, 0, {
		{mi_push_dlg_var, {"dlg_val_name", "dlg_val_value", "DID", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "dlg_send_sequential",
		"send sequential request within dialog",
		MI_ASYNC_RPL_FLAG|MI_NAMED_PARAMS_ONLY, 0, {
		{mi_send_sequential_dlg, {"callid", 0}},
		{mi_send_sequential_dlg, {"callid", "mode", 0}},
		{mi_send_sequential_dlg, {"callid", "method", 0}},
		{mi_send_sequential_dlg, {"callid", "body", 0}},
		{mi_send_sequential_dlg, {"callid", "mode", "method", 0}},
		{mi_send_sequential_dlg, {"callid", "mode", "body", 0}},
		{mi_send_sequential_dlg, {"callid", "method", "body", 0}},
		{mi_send_sequential_dlg, {"callid", "method", "body", "mode", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
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
	{ {"DLG_end_reason",     sizeof("DLG_end_reason")-1},    1000,
		pv_get_dlg_end_reason,0,0, 0, 0, 0},
	{ {"DLG_timeout",        sizeof("DLG_timeout")-1},       1000,
		pv_get_dlg_timeout, pv_set_dlg_timeout,  0, 0, 0, 0 },
	{ {"DLG_json",        sizeof("DLG_json")-1},       1000,
		pv_get_dlg_json, 0,  0, 0, 0, 0 },
	{ {"DLG_ctx_json",        sizeof("DLG_ctx_json")-1},       1000,
		pv_get_dlg_ctx_json, 0,  0, 0, 0, 0 },
	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};

static module_dependency_t *get_deps_db_mode(param_export_t *param)
{
	int db_mode = *(int *)param->param_pointer;

	if (db_mode == DB_MODE_NONE ||
		(db_mode != DB_MODE_REALTIME &&
		 db_mode != DB_MODE_DELAYED &&
		 db_mode != DB_MODE_SHUTDOWN))
		return NULL;

	return alloc_module_dep(MOD_TYPE_SQLDB, NULL, DEP_ABORT);
}

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "tm", DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ "db_mode",			get_deps_db_mode	},
		{ "cachedb_url",		get_deps_cachedb_url	},
		{ "dialog_replication_cluster",	get_deps_clusterer	},
		{ "profile_replication_cluster",	get_deps_clusterer	},
		{ NULL, NULL },
	},
};

struct module_exports exports= {
	"dialog",        /* module's name */
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	&deps,           /* OpenSIPS module dependencies */
	cmds,            /* exported functions */
	0,               /* exported async functions */
	mod_params,      /* param exports */
	mod_stats,       /* exported statistics */
	mi_cmds,         /* exported MI functions */
	mod_items,       /* exported pseudo-variables */
	0,			 	 /* exported transformations */
	0,               /* extra processes */
	0,               /* module pre-initialization function */
	mod_init,        /* module initialization function */
	0,               /* reply processing function */
	mod_destroy,
	child_init,      /* per-child init function */
	0                /* reload confirm function */
};


static int fixup_check_var(void** param)
{
	if (!pv_is_w((pv_spec_t *)*param)) {
		LM_ERR("the return parameter must be a writable pseudo-variable\n");
		return E_SCRIPT;
	}

	return 0;
}

static int fixup_check_avp(void** param)
{
	if (((pv_spec_t *)*param)->type!=PVT_AVP) {
		LM_ERR("the return parameter must be an AVP\n");
		return E_SCRIPT;
	}

	return 0;
}

static int fixup_dlg_flag(void** param)
{
	int val = *(int*)*param;

	if (val<0) {
		LM_ERR("Negative index\n");
		return E_CFG;
	}
	if (val>=8*sizeof(unsigned int) ) {
		LM_ERR("flag index too high <%u> (max=%u)\n",
			val, (unsigned int)(8*sizeof(unsigned int)-1) );
		return E_CFG;
	}

	*param=(void *)(1UL<<val);
	return 0;
}

static int fixup_mmode(void **param)
{
	*param = (void*)(unsigned long)dlg_match_mode_str_to_int((str*)*param);

	return 0;
}


static int fixup_route(void** param)
{
	int rt;

	rt = get_script_route_ID_by_name_str( (str*)*param,
		sroutes->request, RT_NO);
	if (rt==-1) {
		LM_ERR("route <%.*s> does not exist\n",
			((str*)*param)->len, ((str*)*param)->s);
		return -1;
	}

	*param = (void*)(unsigned long int)rt;

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

static void set_mod_flag_wrapper (struct dlg_cell *dlg, unsigned int flags)
{
	dlg->mod_flags |= flags;
}

static int is_mod_flag_set_wrapper (struct dlg_cell *dlg, unsigned int flags)
{
	return (dlg->mod_flags & flags) > 0;
}

static str* get_rr_param(void)
{
	return &rr_param;
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

	dlgb->match_dialog = api_match_dialog;
	dlgb->fix_route_dialog = fix_route_dialog;
	dlgb->validate_dialog = dlg_validate_dialog;

	dlgb->set_mod_flag = set_mod_flag_wrapper;
	dlgb->is_mod_flag_set = is_mod_flag_set_wrapper;

	dlgb->dlg_ref = _ref_dlg;
	dlgb->dlg_unref = unref_dlg_destroy_safe;

	dlgb->get_direction = get_dlg_direction;
	dlgb->get_dlg_did = dlg_get_did;
	dlgb->get_dlg_by_did = get_dlg_by_did;
	dlgb->get_dlg_by_callid = get_dlg_by_callid;
	dlgb->send_indialog_request = send_indialog_request;

	dlgb->get_rr_param = get_rr_param;

	/* dlg context functions */
	dlgb->dlg_ctx_register_int = dlg_ctx_register_int;
	dlgb->dlg_ctx_register_str = dlg_ctx_register_str;
	dlgb->dlg_ctx_register_ptr = dlg_ctx_register_ptr;

	dlgb->dlg_ctx_put_int = dlg_ctx_put_int;
	dlgb->dlg_ctx_put_str = dlg_ctx_put_str;
	dlgb->dlg_ctx_put_ptr = dlg_ctx_put_ptr;

	dlgb->dlg_ctx_get_int = dlg_ctx_get_int;
	dlgb->dlg_ctx_get_str = dlg_ctx_get_str;
	dlgb->dlg_ctx_get_ptr = dlg_ctx_get_ptr;

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

static void ctx_dlg_idx_destroy(void *v)
{
	unref_dlg((struct dlg_cell*)v, 1);
	/* reset the pointer to make sure no-one is trying to free it anymore */
	if (current_processing_ctx)
		ctx_dialog_set(NULL);
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
	mflags_column.len = strlen(mflags_column.s);
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


	if (options_ping_interval<=0 || reinvite_ping_interval<=0) {
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
		cdb_val_prefix.len = strlen(cdb_val_prefix.s);
		cdb_noval_prefix.len = strlen(cdb_noval_prefix.s);
		cdb_size_prefix.len = strlen(cdb_size_prefix.s);
		cdb_url.len = strlen(cdb_url.s);

		if (init_cachedb_utils() <0) {
			LM_ERR("cannot init cachedb utils\n");
			return -1;
		}
	}

	/* allocate a slot in the processing context */
	ctx_dlg_idx = context_register_ptr(CONTEXT_GLOBAL, ctx_dlg_idx_destroy);
	ctx_timeout_idx = context_register_int(CONTEXT_GLOBAL, NULL);
	ctx_lastdstleg_idx = context_register_int(CONTEXT_GLOBAL, NULL);

	/* create dialog state changed event */
	if (state_changed_event_init() < 0) {
		LM_ERR("cannot create dialog state changed event\n");
		return -1;
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

	/* register callbacks*/
	/* listen for all incoming requests  */
	if ( d_tmb.register_tmcb( 0, 0, TMCB_REQUEST_IN, dlg_onreq, 0, 0 ) <=0 ) {
		LM_ERR("cannot register TMCB_REQUEST_IN callback\n");
		return -1;
	}

	/* load RR API */
	if (load_rr_api(&d_rrb)!=0) {
		/* make it null to use it as marker for "RR not loaded" */
		memset( &d_rrb, 0, sizeof(d_rrb));
	} else {
		/* listen for all routed requests  */
		if ( d_rrb.register_rrcb( dlg_onroute, 0, 1 ) <0 ) {
			LM_ERR("cannot register RR callback\n");
			return -1;
		}
	}

	if (register_script_cb( dialog_cleanup,
	POST_SCRIPT_CB|REQ_TYPE_CB|RPL_TYPE_CB,0)<0) {
		LM_ERR("cannot register script callback\n");
		return -1;
	}

	/* check params and register to clusterer for dialogs and
	 * profiles replication */
	if (dialog_repl_cluster < 0) {
		LM_ERR("Invalid dialog_replication_cluster, must be 0 or "
			"a positive cluster id\n");
		return -1;
	}
	if (profile_repl_cluster < 0) {
		LM_ERR("Invalid profile_repl_cluster, must be 0 or "
			"a positive cluster id\n");
		return -1;
	}

	if ((dialog_repl_cluster || profile_repl_cluster) &&
		(load_clusterer_api(&clusterer_api) < 0)) {
		LM_DBG("failed to load clusterer API - is clusterer module loaded?\n");
		return -1;
	}

	if (profile_repl_cluster && clusterer_api.register_capability(
		&prof_repl_cap, receive_prof_repl, NULL, profile_repl_cluster, 0,
		NODE_CMP_ANY) < 0) {
		LM_ERR("Cannot register clusterer callback for profile replication!\n");
		return -1;
	}

	if (dialog_repl_cluster) {
		if (clusterer_api.register_capability(&dlg_repl_cap, receive_dlg_repl,
				rcv_cluster_event, dialog_repl_cluster, 1, NODE_CMP_ANY) < 0) {
			LM_ERR("Cannot register clusterer callback for dialog replication!\n");
			return -1;
		}

		if (clusterer_api.request_sync(&dlg_repl_cap, dialog_repl_cluster) < 0)
			LM_ERR("Sync request failed\n");
	}

	if ( register_timer( "dlg-timer", dlg_timer_routine, NULL, 1,
	TIMER_FLAG_DELAY_ON_DELAY)<0 ) {
		LM_ERR("failed to register timer\n");
		return -1;
	}

	if ( register_timer( "dlg-options-pinger", dlg_options_routine, NULL,
	1 /* check every second if we need to ping */, TIMER_FLAG_DELAY_ON_DELAY)<0) {
		LM_ERR("failed to register timer 2\n");
		return -1;
	}

	if ( register_timer( "dlg-reinvite-pinger", dlg_reinvite_routine, NULL,
	1 /* check every second if we need to ping */, TIMER_FLAG_DELAY_ON_DELAY)<0) {
		LM_ERR("failed to register timer 2\n");
		return -1;
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

	if (init_dlg_reinvite_ping_timer()!=0) {
		LM_ERR("cannot init ping timer\n");
		return -1;
	}

	/* initialized the hash table */
	for( n=0 ; n<(8*sizeof(n)) ; n++) {
		if (dlg_hash_size==(1<<n))
			break;
		if (dlg_hash_size<(1<<n)) {
			/* make sure n does not go underflow - this is only possible if
			 * hash_size is declared to 0, and we "fix" it to 1 */
			if (n == 0)
				n = 1;
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

	if (repl_prof_init() < 0) {
		LM_ERR("cannot initialize profile replication\n");
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
	}

	destroy_cachedb(0);
	
	return 0;
}




static int child_init(int rank)
{
	if (rank==1) {
		if_update_stat(dlg_enable_stats, active_dlgs, active_dlgs_cnt);
		if_update_stat(dlg_enable_stats, early_dlgs, early_dlgs_cnt);
	}

	if ( (dlg_db_mode==DB_MODE_REALTIME || dlg_db_mode==DB_MODE_DELAYED ) &&
	(rank>=1 || rank==PROC_MODULE) ) {
		if ( dlg_connect_db(&db_url)<0 ) {
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
		if ( dlg_connect_db(&db_url)<0 ) {
			LM_ERR("failed to connect to database\n");
		} else {
			dialog_update_db(0, 0/*do not do locking*/);
			destroy_dlg_db();
		}
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

	/* free DLG_STATE_CHANGED event */
	state_changed_event_destroy();
}


static int w_create_dialog(struct sip_msg *req, str *flags_str)
{
	struct cell *t;
	int flags;

	flags = flags_str? parse_create_dlg_flags(flags_str): 0;

	/* don't allow both Re-INVITE and OPTIONS pinging */
	if ((flags & (DLG_FLAG_PING_CALLER|DLG_FLAG_REINVITE_PING_CALLER)) ==
		(DLG_FLAG_PING_CALLER|DLG_FLAG_REINVITE_PING_CALLER))
		flags &= ~DLG_FLAG_PING_CALLER;
	if ((flags & (DLG_FLAG_PING_CALLEE|DLG_FLAG_REINVITE_PING_CALLEE)) ==
		(DLG_FLAG_PING_CALLEE|DLG_FLAG_REINVITE_PING_CALLEE))
		flags &= ~DLG_FLAG_PING_CALLEE;

	t = d_tmb.t_gett();
	if (dlg_create_dialog( (t==T_UNDEFINED)?NULL:t, req, flags)!=0)
		return -1;

	return 1;
}


static int w_match_dialog(struct sip_msg *msg, void *seq_match_mode_val)
{
	int mm;

	if (!seq_match_mode_val)
		mm = SEQ_MATCH_DEFAULT;
	else
		mm = (int)(long)seq_match_mode_val;

	return api_match_dialog(msg, mm);
}

static int api_match_dialog(struct sip_msg *msg, int _seq_match_mode)
{
	int backup,i;
	void *match_param = NULL;
	struct sip_uri *r_uri;
	str s;
	char *p;

	/* dialog already found ? */
	if (get_current_dialog()!=NULL)
		return 1;

	backup = seq_match_mode;
	if (_seq_match_mode != SEQ_MATCH_DEFAULT)
		seq_match_mode = _seq_match_mode;

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
				LM_DBG("We found DID param in R-URI with value of %.*s\n",
					r_uri->u_val[i].len,r_uri->u_val[i].s);
				/* pass the param value to the matching funcs */
				match_param = (void *)(&r_uri->u_val[i]);
				break;
			}
		if (match_param==NULL) {
			/* looking for ".did.hash.label" in the USERNAME */
			s = r_uri->user;
			while( (p=q_memchr(s.s,DLG_SEPARATOR,s.len))!=NULL ) {
				if ( s.s+s.len-p-1 > rr_param.len+2 ) {
					if (strncmp( p+1, rr_param.s, rr_param.len)==0 &&
					p[rr_param.len+1]==DLG_SEPARATOR ) {
						p += rr_param.len+2;
						s.len = s.s+s.len-p;
						s.s = p;
						match_param = (void*)(&s);
						break;
					}
				}
				if (p+1<s.s+s.len) {
					s.len = s.s+s.len-p-1;
					s.s = p+1;
				} else
					break;
			}
		}
	}

sipwise:
	dlg_onroute( msg, NULL, match_param);

	seq_match_mode = backup;

	return (get_current_dialog()==NULL)?-1:1;
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


static int w_set_dlg_profile(struct sip_msg *msg, str *prof_name, str *value)
{
	struct dlg_cell *dlg;
	struct dlg_profile_table *profile;

	profile = search_dlg_profile(prof_name);
	if (!profile) {
		LM_ERR("profile <%.*s> not defined\n", prof_name->len, prof_name->s);
		return -1;
	}

	if ( (dlg=get_current_dialog())==NULL ) {
		LM_CRIT("BUG - setting profile from script, but no dialog found\n");
		return -1;
	}

	if (profile->has_value) {
		if (!value) {
			LM_WARN("missing value\n");
			return -1;	
		}
		if ( set_dlg_profile( dlg, value, profile, 0) < 0 ) {
			LM_ERR("failed to set profile\n");
			return -1;
		}
	} else {
		if ( set_dlg_profile( dlg, NULL, profile, 0) < 0 ) {
			LM_ERR("failed to set profile\n");
			return -1;
		}
	}
	return 1;
}


static int w_unset_dlg_profile(struct sip_msg *msg, str *prof_name, str *value)
{
	struct dlg_cell *dlg;
	struct dlg_profile_table *profile;

	profile = search_dlg_profile(prof_name);
	if (!profile) {
		LM_ERR("profile <%.*s> not defined\n", prof_name->len, prof_name->s);
		return -1;
	}

	if ( (dlg=get_current_dialog())==NULL ) {
		LM_CRIT("BUG - setting profile from script, but no dialog found\n");
		return -1;
	}

	if (profile->has_value) {
		if (!value) {
			LM_WARN("missing value\n");
			return -1;	
		}
		if ( unset_dlg_profile( dlg, value, profile) < 0 ) {
			LM_ERR("failed to unset profile\n");
			return -1;
		}
	} else {
		if ( unset_dlg_profile( dlg, NULL, profile) < 0 ) {
			LM_ERR("failed to unset profile\n");
			return -1;
		}
	}
	return 1;
}


static int w_is_in_profile(struct sip_msg *msg, str *prof_name, str *value)
{
	struct dlg_cell *dlg;
	struct dlg_profile_table *profile;

	profile = search_dlg_profile(prof_name);
	if (!profile) {
		LM_ERR("profile <%.*s> not defined\n", prof_name->len, prof_name->s);
		return -1;
	}

	if ( (dlg=get_current_dialog())==NULL ) {
		LM_CRIT("BUG - setting profile from script, but no dialog found\n");
		return -1;
	}

	if (value && profile->has_value) {
		return is_dlg_in_profile(dlg, profile, value);
	} else {
		return is_dlg_in_profile(dlg, profile, NULL);
	}
}


static int w_get_profile_size(struct sip_msg *msg, str *prof_name,
							str *value, pv_spec_t *result)
{
	pv_value_t size;
	struct dlg_profile_table *profile;

	profile = search_dlg_profile(prof_name);
	if (!profile) {
		LM_ERR("profile <%.*s> not defined\n", prof_name->len, prof_name->s);
		return -1;
	}

	if (value && profile->has_value) {
		size.ri = get_profile_size(profile, value);
	} else {
		size.ri = get_profile_size(profile, NULL);
	}

	size.flags = PV_TYPE_INT|PV_VAL_INT;
	if (pv_set_value(msg, result, 0, &size) != 0) {
		LM_ERR("failed to set the output profile size!\n");
		return -1;
	}

	return 1;
}


static int w_set_dlg_flag(struct sip_msg *msg, void *mask)
{
	struct dlg_cell *dlg;

	if ( (dlg=get_current_dialog())==NULL )
		return -1;

	dlg->user_flags |= (unsigned int)(unsigned long)mask;
	dlg->flags |= DLG_FLAG_VP_CHANGED;
	return 1;
}


static int w_reset_dlg_flag(struct sip_msg *msg, void *mask)
{
	struct dlg_cell *dlg;

	if ( (dlg=get_current_dialog())==NULL )
		return -1;

	dlg->user_flags &= ~((unsigned int)(unsigned long)mask);
	return 1;
}


static int w_is_dlg_flag_set(struct sip_msg *msg, void *mask)
{
	struct dlg_cell *dlg;

	if ( (dlg=get_current_dialog())==NULL )
		return -1;

	return (dlg->user_flags&((unsigned int)(unsigned long)mask))?1:-1;
}

static int w_tsl_dlg_flag(struct sip_msg *msg, int *_idx, int *_val)
{
	struct dlg_cell *dlg;

	if ( (dlg=get_current_dialog())==NULL )
		return -2;

	return test_and_set_dlg_flag(dlg, *_idx, *_val);
}


static int w_store_dlg_value(struct sip_msg *msg, str *name, str *val)
{
	struct dlg_cell *dlg;

	if ( (dlg=get_current_dialog())==NULL )
		return -1;

	return (store_dlg_value( dlg, name, val)==0)?1:-1;
}


int w_fetch_dlg_value(struct sip_msg *msg, str *name, pv_spec_t *result)
{
	struct dlg_cell *dlg;
	pv_value_t value;

	if ( (dlg=get_current_dialog())==NULL )
		return -1;

	if (fetch_dlg_value( dlg, name, &value.rs, 0) ) {
		LM_DBG("failed to fetch dialog value <%.*s>\n",
			((str*)name)->len, ((str*)name)->s);
		return -1;
	}

	value.flags = PV_VAL_STR;
	if (pv_set_value(msg, result, 0, &value) != 0) {
		LM_ERR("failed to set the fetched dlg value!\n");
		return -1;
	}

	return 1;
}


static int w_get_dlg_info(struct sip_msg *msg, str *attr, pv_spec_t *attr_val,
			str *key, str *key_val, pv_spec_t *number_val)
{
	struct dlg_cell *dlg;
	struct dlg_entry *d_entry;
	pv_value_t val;
	int n;
	unsigned int h;
	unsigned short aux;

	/* go through all hash entries (entire table) */

	n=0;

	for ( h=0 ; h<d_table->size ; h++ ) {

		d_entry = &(d_table->entries[h]);
		dlg_lock( d_table, d_entry);

		/* go through all dialogs on entry */
		for( dlg = d_entry->first ; dlg ; dlg = dlg->next ) {
			LM_DBG("dlg in state %d to check\n",dlg->state);
			if ( dlg->state>DLG_STATE_CONFIRMED )
				continue;

			if (check_dlg_value_unsafe( dlg, key, key_val)==0) {
				LM_DBG("dialog found, fetching variable\n");

				/* XXX - in lack of an unsafe version of fetch_dlg_value */ 
				aux = dlg->locked_by;
				dlg->locked_by = process_no;
				
				if (fetch_dlg_value( dlg, attr, &val.rs, 0) ) {
					dlg->locked_by = aux;
					dlg_unlock( d_table, d_entry);
					LM_ERR("failed to fetch dialog value <%.*s>\n",
						(attr)->len, (attr)->s);
					return -1;
				} else {
					val.flags = PV_VAL_STR;
					if (attr_val->setf( msg, &attr_val->pvp, 0, &val )!=0) {
						LM_ERR("Failed to set out pvar \n");
						dlg->locked_by = aux;
						dlg_unlock( d_table, d_entry);
						return -1;
					} else
						n++; 
				}
	
				dlg->locked_by = aux;
			}
		}

		dlg_unlock( d_table, d_entry);
	}

	if (n==0) {
		LM_DBG("No matched dialogs\n");
		return -1;
	}

	val.flags = PV_VAL_INT | PV_TYPE_INT;
	val.ri = n;
	val.rs.len=0;
	val.rs.s=NULL;

	if (number_val->setf( msg, &number_val->pvp, 0, &val )!=0) {
		LM_ERR("Failed to set dlg_no pvar to %d \n",n);
		return -1;
	}

	return n;
}

static int w_get_dlg_vals(struct sip_msg *msg, pv_spec_t *v_name,
						pv_spec_t *v_val, str *callid)
{
	struct dlg_cell *dlg;
	struct dlg_val *dv;
	pv_value_t val;

	dlg = get_dlg_by_callid(callid, 1);

	if (dlg==NULL) {
		/* nothing found */
		LM_DBG("no dialog found\n");
		return -1;
	}

	/* dlg found - NOTE you have a ref! */
	LM_DBG("dialog found, fetching all variable\n");

	/* iterate the list with all the dlg variables */
	for( dv=dlg->vals ; dv ; dv=dv->next) {

		/* add name to AVP */
		val.flags = PV_VAL_STR;
		val.rs = dv->name;
		if ( pv_set_value( msg, v_name, 0, &val)<0 ) {
			LM_ERR("failed to add new name in dlg val list, ignoring\n");
		} else {
			/* add value to AVP */
			val.flags = PV_VAL_STR;
			val.rs = dv->val;
			if ( pv_set_value( msg, v_val, 0, &val)<0 ) {
				LM_ERR("failed to add new value in dlg val list, ignoring\n");
				/* better exit here, as we will desync the lists */
				unref_dlg(dlg, 1);
				return -1;
			}
		}

	}

	unref_dlg(dlg, 1);

	return 1;
}

static int w_set_dlg_shtag(struct sip_msg *msg, str *shtag)
{
	struct dlg_cell *dlg;

	if (!dialog_repl_cluster) {
		LM_DBG("Dialog replication not configured\n");
		return 1;
	}

	if ((dlg = get_current_dialog()) == NULL) {
		LM_ERR("Unable to fetch dialog\n");
		return -1;
	}

	if (set_dlg_shtag(dlg, shtag) < 0) {
		LM_ERR("Unable to set sharing tag\n");
		return -1;
	}

	return 1;
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
		if (dlg->state == DLG_STATE_DELETED)
			l = 0;
		else if (dlg->state < DLG_STATE_CONFIRMED_NA)
			l = dlg->lifetime;
		else
			l = dlg->tl.timeout - get_ticks();
		dlg_unlock_dlg(dlg);

	} else if (current_processing_ctx) {
		if ((l=ctx_timeout_get())==0)
			return pv_get_null( msg, param, res);
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
	int dir;

	if(res==NULL)
		return -1;

	dir = get_dlg_direction();
	switch (dir) {
		case DLG_DIR_NONE:
			return pv_get_null( msg, param, res);
		case DLG_DIR_UPSTREAM:
			res->rs.s = "upstream";
			res->rs.len = 8;
			break;
		case DLG_DIR_DOWNSTREAM:
			res->rs.s = "downstream";
			res->rs.len = 10;
			break;
		default:
			LM_BUG("unknwn dlg direction %d!\n", dir);
			return -1;
	}

	res->flags = PV_VAL_STR;

	return 0;
}

int pv_get_dlg_did(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	struct dlg_cell *dlg;
	str *did;

	if(res==NULL)
		return -1;

	if ( (dlg=get_current_dialog())==NULL )
		return pv_get_null( msg, param, res);

	did = dlg_get_did(dlg);
	if (!did)
		return pv_get_null( msg, param, res);
	res->rs = *did;
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
		if (!(dlg->flags & DLG_FLAG_END_ON_RACE_CONDITION) ||
		!(dlg->flags & DLG_FLAG_WAS_CANCELLED)) {
			dlg_lock_dlg(dlg);
			dlg->lifetime = timeout;
			/* update now only if realtime and the dialog is confirmed */
			if (dlg->state >= DLG_STATE_CONFIRMED && dlg_db_mode == DB_MODE_REALTIME)
				db_update = 1;
			else
				dlg->flags |= DLG_FLAG_CHANGED;

			if (dlg->state == DLG_STATE_CONFIRMED_NA ||
			dlg->state == DLG_STATE_CONFIRMED)
				timer_update = 1;

			dlg_unlock_dlg(dlg);

			if (timer_update) {
				switch ( update_dlg_timer(&dlg->tl, timeout) ) {
				case -1:
					LM_ERR("failed to update timer\n");
					return -1;
				case 1:
					/* dlg inserted in timer list with new expire (reference it)*/
					ref_dlg(dlg,1);
				case 0:
					/* timeout value was updated */
					break;
				}
			}

			if (db_update)
				update_dialog_timeout_info(dlg);
			if (dialog_repl_cluster)
				replicate_dialog_updated(dlg);

		} else {
			LM_DBG("Set timeout for race condition dlg %.*s - ignoring\n",
			dlg->callid.len,dlg->callid.s);
		}

	} else if (current_processing_ctx) {
		/* store it until we match the dialog */
		ctx_timeout_set( timeout );
	} else {
		LM_CRIT("BUG - no processing context found!\n");
		return -1;
	}

	return 0;
}

#define DLG_CTX_JSON_BUFF_SIZE 8192
#define DEC_AND_CHECK_LEN(_curr,_size)			\
	 do {						\
		_curr-=_size; 				\
		if (_curr < 0) { 			\
			LM_ERR("No more buf size \n"); 	\
			return NULL; 			\
		}					\
	} while(0)					\
		
static char *dlg_get_json_out(struct dlg_cell *dlg,int ctx,int *out_len)
{
	static char dlg_info[DLG_CTX_JSON_BUFF_SIZE];
	struct dlg_profile_link *dl,*dl2;
	struct dlg_val* dv;
	char *p;
	int i,j,k,len;

	/* I know, this sucks.

	Until we find a better way to push MI 
	output straight to the script level,
	this will have to do :( */

	memset(dlg_info,0,DLG_CTX_JSON_BUFF_SIZE);
	len = DLG_CTX_JSON_BUFF_SIZE;

	p=dlg_info;
	i=snprintf(dlg_info,len,"{\"ID\":\"%llu\",\"state\":\"%d\",\"user_flags\":\"%d\",\"callid\":\"%.*s\",\"timestart\":\"%d\",\"timeout\":\"%d\",\"from_uri\":\"%.*s\",\"to_uri\":\"%.*s\"",
		(((long long unsigned)dlg->h_entry)<<(8*sizeof(int)))+dlg->h_id,
		dlg->state,
		dlg->user_flags,
		dlg->callid.len,dlg->callid.s,
		dlg->start_ts,
		dlg->tl.timeout?((unsigned int)time(0) + dlg->tl.timeout - get_ticks()):0,
		dlg->from_uri.len,dlg->from_uri.s,
		dlg->to_uri.len,dlg->to_uri.s);

	if (i<0) {
		LM_ERR("Failed to print dlg json \n");		
		return NULL;
	}
	
	DEC_AND_CHECK_LEN(len,i);
	p+=i;

	if (dlg->legs_no[DLG_LEGS_USED]>0) {
		/* minimum caller leg guaranteed to be here */
		i=snprintf(p,len,",\"caller\":{\"tag\":\"%.*s\",\"contact\":\"%.*s\",\"cseq\":\"%.*s\",\"route_set\":\"%.*s\",\"bind_addr\":\"%.*s\",\"sdp\":\"%.*s\"}",
		dlg->legs[DLG_CALLER_LEG].tag.len,dlg->legs[DLG_CALLER_LEG].tag.s,
		dlg->legs[DLG_CALLER_LEG].contact.len,dlg->legs[DLG_CALLER_LEG].contact.s,
		dlg->legs[DLG_CALLER_LEG].r_cseq.len,dlg->legs[DLG_CALLER_LEG].r_cseq.s,
		dlg->legs[DLG_CALLER_LEG].route_set.len,dlg->legs[DLG_CALLER_LEG].route_set.s,
		dlg->legs[DLG_CALLER_LEG].bind_addr->sock_str.len,dlg->legs[DLG_CALLER_LEG].bind_addr->sock_str.s,
		dlg->legs[DLG_CALLER_LEG].out_sdp.len,dlg->legs[DLG_CALLER_LEG].out_sdp.s);
		
		if (i<0) {
			LM_ERR("Failed to print dlg json \n");		
			return NULL;
		}

		DEC_AND_CHECK_LEN(len,i);
		p+=i;
	}

	memcpy(p,",\"callees\":[",12);
	p+=12;
	DEC_AND_CHECK_LEN(len,12);
	
	for( j=1 ; j < dlg->legs_no[DLG_LEGS_USED] ; j++  ) {
		if (j != 1) {
			*p++=',';
			DEC_AND_CHECK_LEN(len,1);
		}
			
		i=snprintf(p,len,"{\"tag\":\"%.*s\",\"contact\":\"%.*s\",\"cseq\":\"%.*s\",\"route_set\":\"%.*s\",\"bind_addr\":\"%.*s\",\"sdp\":\"%.*s\"}",
		dlg->legs[j].tag.len,dlg->legs[j].tag.s,
		dlg->legs[j].contact.len,dlg->legs[j].contact.s,
		dlg->legs[j].r_cseq.len,dlg->legs[j].r_cseq.s,
		dlg->legs[j].route_set.len,dlg->legs[j].route_set.s,
		dlg->legs[j].bind_addr?dlg->legs[j].bind_addr->sock_str.len:0,
		dlg->legs[j].bind_addr?dlg->legs[j].bind_addr->sock_str.s:NULL,
		dlg->legs[j].out_sdp.len,dlg->legs[j].out_sdp.s);

		if (i<0) {
			LM_ERR("Failed to print dlg json \n");
			return NULL;
		}
		
		p+=i;
		DEC_AND_CHECK_LEN(len,i);
	}
	*p++=']';
	DEC_AND_CHECK_LEN(len,1);

	if (ctx && dlg->vals) {
		memcpy(p,",\"values\":{",11);
		p+=11;
		DEC_AND_CHECK_LEN(len,11);

		k=0;
		for( dv=dlg->vals ; dv ; dv=dv->next) {
			for (i = 0, j = 0; i < dv->val.len; i++) {
				if (dv->val.s[i] < 0x20 || dv->val.s[i] >= 0x7F) {
					goto next_val;
				}
			}
			
			if (k!=0) {
				*p++ = ','; 
				DEC_AND_CHECK_LEN(len,1);
			}
			k++;

			*p++='\"';
			len--;
			memcpy(p,dv->name.s,dv->name.len);
			p+=dv->name.len;
			len-=dv->name.len;

			*p++='\"';
			*p++=':';
			*p++='\"';
			DEC_AND_CHECK_LEN(len,3);
			memcpy(p,dv->val.s,dv->val.len);
			p+=dv->val.len;
			DEC_AND_CHECK_LEN(len,dv->val.len);
			*p++='\"';
			DEC_AND_CHECK_LEN(len,1);
next_val:
			;
		}

		*p++='}';
		DEC_AND_CHECK_LEN(len,1);
	}

	if (ctx && dlg->profile_links) {
		memcpy(p,",\"profiles\":{",13);
		p+=13;
		DEC_AND_CHECK_LEN(len,13);
		for (dl=dlg->profile_links ; dl ; dl=dl->next)
			dl->it_marker= 0;

		for( dl=dlg->profile_links ; dl ; dl=dl->next) {
			if (dl->it_marker != 0)
				continue;

			dl->it_marker=1;

			if (dl!=dlg->profile_links) {
				*p++ = ','; 
				DEC_AND_CHECK_LEN(len,1);
			}

			*p++='\"';
			DEC_AND_CHECK_LEN(len,1);
			memcpy(p,dl->profile->name.s,dl->profile->name.len);
			p+=dl->profile->name.len;
			DEC_AND_CHECK_LEN(len,dl->profile->name.len);

			*p++='\"';
			DEC_AND_CHECK_LEN(len,1);
			*p++=':';	
			DEC_AND_CHECK_LEN(len,1);

			*p++='[';
			DEC_AND_CHECK_LEN(len,1);

			*p++='\"';
			DEC_AND_CHECK_LEN(len,1);
			memcpy(p,ZSW(dl->value.s),dl->value.len);
			p+=dl->value.len;
			DEC_AND_CHECK_LEN(len,dl->value.len);
			*p++='\"';
			DEC_AND_CHECK_LEN(len,1);

			for (dl2=dlg->profile_links; dl2; dl2=dl2->next) {
				if (dl2->it_marker != 0)
					continue;

				if (dl->profile->name.len == dl2->profile->name.len &&
				memcmp(dl->profile->name.s,dl2->profile->name.s,dl->profile->name.len) == 0) {
					/* found another member of the same profile */

					*p++=',';
					DEC_AND_CHECK_LEN(len,1);
					*p++='\"';
					DEC_AND_CHECK_LEN(len,1);
					
					memcpy(p,ZSW(dl2->value.s),dl2->value.len);
					p+=dl2->value.len;
					DEC_AND_CHECK_LEN(len,dl2->value.len);
					*p++='\"';
					DEC_AND_CHECK_LEN(len,1);

					dl2->it_marker=1;
				}
			}

			*p++=']';
			DEC_AND_CHECK_LEN(len,1);
		}

		*p++='}';
		DEC_AND_CHECK_LEN(len,1);
	}

	*p++='}';
	DEC_AND_CHECK_LEN(len,1);

	*out_len = (int)(p-dlg_info);
	return dlg_info;	
}

int pv_get_dlg_json(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	struct dlg_cell *dlg;
	int len;
	char *out;

	if(res==NULL)
		return -1;

	if ( (dlg=get_current_dialog())==NULL )
		return pv_get_null( msg, param, res);
	
	dlg_lock_dlg(dlg);

	if ((out = dlg_get_json_out(dlg,0,&len)) == NULL) {
		LM_ERR("Failed to build pvar content \n");
		dlg_unlock_dlg(dlg);
		return pv_get_null( msg, param, res);
	}

	dlg_unlock_dlg(dlg);

	res->rs.s=out;
	res->rs.len=len;
	res->flags = PV_VAL_STR;

	return 0;
}

int pv_get_dlg_ctx_json(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	struct dlg_cell *dlg;
	int len;
	char *out;

	if(res==NULL)
		return -1;

	if ( (dlg=get_current_dialog())==NULL )
		return pv_get_null( msg, param, res);

	dlg_lock_dlg(dlg);

	if ((out = dlg_get_json_out(dlg,1,&len)) == NULL) {
		LM_ERR("Failed to build pvar content \n");
		dlg_unlock_dlg(dlg);
		return pv_get_null( msg, param, res);
	}

	dlg_unlock_dlg(dlg);

	res->rs.s=out;
	res->rs.len=len;
	res->flags = PV_VAL_STR;

	return 0;
}

static int w_get_dlg_jsons_by_val(struct sip_msg *msg, str *attr, str *attr_val,
			pv_spec_t *out, pv_spec_t *number_val)
{
	struct dlg_cell *dlg;
	struct dlg_entry *d_entry;
	pv_value_t val;
	int n;
	unsigned int h;
	char *out_json;
	int out_len;

	/* go through all hash entries (entire table) */

	n=0;

	for ( h=0 ; h<d_table->size ; h++ ) {

		d_entry = &(d_table->entries[h]);
		dlg_lock( d_table, d_entry);

		/* go through all dialogs on entry */
		for( dlg = d_entry->first ; dlg ; dlg = dlg->next ) {
			LM_DBG("dlg in state %d to check\n",dlg->state);
			if ( dlg->state>DLG_STATE_CONFIRMED )
				continue;

			if (check_dlg_value_unsafe( dlg, attr, attr_val)==0) {
				LM_DBG("dialog found, fetching variable\n");

				if ((out_json = dlg_get_json_out(dlg,1,&out_len)) == NULL) {
					dlg_unlock( d_table, d_entry);
					LM_ERR("failed to get a dlg json \n");
					return -1;
				} else {
					val.rs.s=out_json;
					val.rs.len=out_len;
					val.flags = PV_VAL_STR;

					if (out->setf( msg, &out->pvp, 0, &val )!=0) {
						LM_ERR("Failed to set out pvar \n");
						dlg_unlock( d_table, d_entry);
						return -1;
					} else
						n++; 
				}
			}
		}

		dlg_unlock( d_table, d_entry);
	}

	if (n==0) {
		LM_DBG("No matched dialogs\n");
		return -1;
	}

	val.flags = PV_VAL_INT | PV_TYPE_INT;
	val.ri = n;
	val.rs.len=0;
	val.rs.s=NULL;

	if (number_val->setf( msg, &number_val->pvp, 0, &val )!=0) {
		LM_ERR("Failed to set dlg_no pvar to %d \n",n);
		return -1;
	}

	return n;
}

static int w_get_dlg_jsons_by_profile(struct sip_msg *msg, str *attr, str *attr_val,
				pv_spec_t *out, pv_spec_t *number_val)
{
	struct dlg_cell *dlg;
	struct dlg_entry *d_entry;
	pv_value_t val;
	int n,out_len,found;
	unsigned int h;
	char *out_json;
	struct dlg_profile_table *profile;
	struct dlg_profile_link *cur_link;

	/* search for the profile */
	profile = search_dlg_profile(attr);
	if (profile==NULL) {
		LM_ERR("NO such profile <%.*s> \n",attr->len,attr->s);
		return -1;
	}
	

	/* go through all hash entries (entire table) */

	n=0;

	for ( h=0 ; h<d_table->size ; h++ ) {

		d_entry = &(d_table->entries[h]);
		dlg_lock( d_table, d_entry);

		/* go through all dialogs on entry */
		for( dlg = d_entry->first ; dlg ; dlg = dlg->next ) {
			LM_DBG("dlg in state %d to check\n",dlg->state);
			if ( dlg->state>DLG_STATE_CONFIRMED )
				continue;

			found=0;
			cur_link=dlg->profile_links;

			while(cur_link) {
				if (cur_link->profile == profile &&
				( !attr_val || !profile->has_value ||
				( attr_val->len == cur_link->value.len && 
				!strncmp(attr_val->s,cur_link->value.s, attr_val->len)))) {
					found = 1;
					break;
				}
				cur_link = cur_link->next;
			}

			if(found) {
				if ((out_json = dlg_get_json_out(dlg,1,&out_len)) == NULL) {
					dlg_unlock( d_table, d_entry);
					LM_ERR("failed to get a dlg json \n");
					return -1;
				} else {
					val.rs.s=out_json;
					val.rs.len=out_len;
					val.flags = PV_VAL_STR;

					if (out->setf( msg, &out->pvp, 0, &val )!=0) {
						LM_ERR("Failed to set out pvar \n");
						dlg_unlock( d_table, d_entry);
						return -1;
					} else
						n++; 
				}
			}
		}

		dlg_unlock( d_table, d_entry);
	}

	if (n==0) {
		LM_DBG("No matched dialogs\n");
		return -1;
	}

	val.flags = PV_VAL_INT | PV_TYPE_INT;
	val.ri = n;
	val.rs.len=0;
	val.rs.s=NULL;

	if (number_val->setf( msg, &number_val->pvp, 0, &val )!=0) {
		LM_ERR("Failed to set dlg_no pvar to %d \n",n);
		return -1;
	}

	return n;
}


#define DLG_CTX_LOAD_BY_CALLID  0
#define DLG_CTX_LOAD_BY_DID     1

static struct dlg_cell *load_ctx_backup = NULL;
static int dlg_ctx_loaded = 0;

static int fixup_lmode(void **param)
{
	str *s = (str*)*param;

	if (s->len==6 && strncasecmp( s->s, "callid", 6)==0) {
		*param = (void*)(unsigned long)DLG_CTX_LOAD_BY_CALLID;
	} else
	if (s->len==3 && strncasecmp( s->s, "did", 3)==0) {
		*param = (void*)(unsigned long)DLG_CTX_LOAD_BY_DID;
	} else {
		LM_ERR("unsupported dialog indetifier <%.*s>\n",
			s->len, s->s);
		return -1;
	}

	return 0;
}

static int fixup_leg(void **param)
{
	str *s = (str*)*param;
	if (s->len == 6) {
		if (strncasecmp(s->s, "caller", 6) == 0) {
			*param = (void*)(unsigned long)DLG_CALLER_LEG;
			return 0;
		} else if (strncasecmp(s->s, "callee", 6) == 0) {
			*param = (void*)(unsigned long)DLG_FIRST_CALLEE_LEG;
			return 0;
		}
	}

	LM_ERR("unsupported dialog indetifier <%.*s>\n",
		s->len, s->s);
	return -1;
}


static int load_dlg_ctx(struct sip_msg *msg, str *callid, void *lmode)
{
	struct dlg_cell *dlg = NULL;
	int mode;

	if (lmode)
		mode = (int)(long)lmode;
	else
		mode = DLG_CTX_LOAD_BY_CALLID;

	if (dlg_ctx_loaded) {
		LM_ERR("nested call of load dlg ctx\n");
		return -1;
	}

	switch (mode) {
		case DLG_CTX_LOAD_BY_CALLID:
			/* callid */
			dlg = get_dlg_by_callid( callid, 0 );
			break;

		case DLG_CTX_LOAD_BY_DID:
			/* did */
			dlg = get_dlg_by_did( callid, 0);
			break;
	}

	if (dlg==NULL) {
		/* nothing found */
		LM_DBG("no dialog found\n");
		return -1;
	}

	/* this will 'inherit' the ref, no need to add a new one */
	load_ctx_backup = ctx_dialog_get();

	/* the dlg is already ref'ed by the lookup function */
	ctx_dialog_set(dlg);
	dlg_ctx_loaded = 1;

	return 1;
}


static int unload_dlg_ctx(struct sip_msg *msg)
{
	struct dlg_cell *dlg;

	if (!dlg_ctx_loaded)
		return -1;

	if ( (dlg=ctx_dialog_get())!=NULL )
		unref_dlg(dlg,1);

	ctx_dialog_set(load_ctx_backup);
	load_ctx_backup = NULL;
	dlg_ctx_loaded = 0;

	return 1;
}


static int dlg_on_timeout(struct sip_msg* msg, void *route_id)
{
	struct dlg_cell *dlg;

	if ( (dlg=get_current_dialog())==NULL ) {
		LM_WARN("no current dialog found. Have you created one?\n");
		return -1;
	}

	dlg_lock_dlg(dlg);

	if (dlg->state > DLG_STATE_EARLY) {
		LM_WARN("too late to set the route, dialog already established\n");
		dlg_unlock_dlg(dlg);
		return -1;
	}

	/* if the parameter was missing, we get a NULL route_id, which
	 * translate into a 0 rt_on_timeout, which translates into a reset */

	dlg->rt_on_timeout = (unsigned int)(unsigned long)route_id;

	dlg_unlock_dlg(dlg);
	return 1;
}


static int dlg_on_answer(struct sip_msg* msg, void *route_id)
{
	struct dlg_cell *dlg;

	if ( (dlg=get_current_dialog())==NULL ) {
		LM_WARN("no current dialog found. Have you created one?\n");
		return -1;
	}

	dlg_lock_dlg(dlg);

	if (dlg->state > DLG_STATE_EARLY) {
		LM_WARN("too late to set the route, dialog already established\n");
		dlg_unlock_dlg(dlg);
		return -1;
	}

	/* if the parameter was missing, we get a NULL route_id, which
	 * translate into a 0 rt_on_timeout, which translates into a reset */

	dlg->rt_on_answer = (unsigned int)(unsigned long)route_id;

	dlg_unlock_dlg(dlg);
	return 1;
}


static int dlg_on_hangup(struct sip_msg* msg, void *route_id)
{
	struct dlg_cell *dlg;

	if ( (dlg=get_current_dialog())==NULL ) {
		LM_WARN("no current dialog found. Have you created one?\n");
		return -1;
	}

	dlg_lock_dlg(dlg);

	if (dlg->state > DLG_STATE_EARLY) {
		LM_WARN("too late to set the route, dialog already established\n");
		dlg_unlock_dlg(dlg);
		return -1;
	}

	/* if the parameter was missing, we get a NULL route_id, which
	 * translate into a 0 rt_on_timeout, which translates into a reset */

	dlg->rt_on_hangup = (unsigned int)(unsigned long)route_id;

	dlg_unlock_dlg(dlg);
	return 1;
}


static int dlg_send_sequential(struct sip_msg* msg, str *method, int leg,
		str *body, str *ct, str *headers)
{
	struct dlg_cell *dlg = get_current_dialog();
	str invite = str_init("INVITE");

	if (!dlg) {
		LM_WARN("no current dialog found. Make sure you call this "
				"function inside a dialog  context\n");
		return -1;
	}
	if (!method)
		method = &invite;

	if (body && !ct)
		LM_WARN("body without content type! This request might be rejected by uac!\n");

	return send_indialog_request(dlg, method, (leg == DLG_CALLER_LEG?leg:callee_idx(dlg)),
			body, ct, headers, NULL, NULL) == 0?1:-1;

}
