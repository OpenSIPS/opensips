/**
 * Fraud Detection Module
 *
 * Copyright (C) 2014 OpenSIPS Foundation
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
 *  2014-09-26  initial version (Andrei Datcu)
*/

#include "../../ut.h"
#include "../../db/db.h"
#include "../../time_rec.h"
#include "../../mod_fix.h"
#include "../drouting/dr_api.h"
#include "../dialog/dlg_load.h"

#include "frd_stats.h"
#include "frd_load.h"
#include "frd_events.h"

extern str db_url;
extern str table_name;

extern str rid_col;
extern str pid_col;
extern str prefix_col;
extern str start_h_col;
extern str end_h_col;
extern str days_col;
extern str cpm_thresh_warn_col;
extern str cpm_thresh_crit_col;
extern str calldur_thresh_warn_col;
extern str calldur_thresh_crit_col;
extern str totalc_thresh_warn_col;
extern str totalc_thresh_crit_col;
extern str concalls_thresh_warn_col;
extern str concalls_thresh_crit_col;
extern str seqcalls_thresh_warn_col;
extern str seqcalls_thresh_crit_col;

#define DEF_PARAM_STR_NAME(pname, strname)\
	static str pname ## _name = str_init(strname)

DEF_PARAM_STR_NAME(cpm, "calls per minute");
DEF_PARAM_STR_NAME(total_calls, "total calls");
DEF_PARAM_STR_NAME(concurrent_calls, "concurrent calls");
DEF_PARAM_STR_NAME(seq_calls, "sequential calls");
#undef DEF_PARAM_STR_NAME


dr_head_p *dr_head;
struct dr_binds drb;
rw_lock_t *frd_data_lock;
gen_lock_t *frd_seq_calls_lock;

struct dlg_binds dlgb;

static int mod_init(void);
static int child_init(int);
static void destroy(void);

static int check_fraud(struct sip_msg *msg, char *user, char *number, char *pid);
static int fixup_check_fraud(void **param, int param_no);
static struct mi_root* mi_show_stats(struct mi_root *cmd_tree, void *param);
static struct mi_root* mi_reload(struct mi_root *cmd_tree, void *param);

static cmd_export_t cmds[]={
	{"check_fraud", (cmd_function)check_fraud, 3, fixup_check_fraud, 0,
		REQUEST_ROUTE | ONREPLY_ROUTE},
	{0,0,0,0,0,0}
};

static param_export_t params[]={
	{"db_url",                      STR_PARAM, &db_url.s},
	{"table_name",                  STR_PARAM, &table_name.s},
	{"rid_col",                     STR_PARAM, &rid_col.s},
	{"pid_col",                     STR_PARAM, &pid_col.s},
	{"prefix_col",                  STR_PARAM, &prefix_col.s},
	{"start_h_col",                 STR_PARAM, &start_h_col.s},
	{"end_h_col",                   STR_PARAM, &end_h_col.s},
	{"days_col",                    STR_PARAM, &days_col.s},
	{"cpm_thresh_warn_col",         STR_PARAM, &cpm_thresh_warn_col.s},
	{"cpm_thresh_crit_col",         STR_PARAM, &cpm_thresh_crit_col.s},
	{"calldur_thresh_warn_col",     STR_PARAM, &calldur_thresh_warn_col.s},
	{"calldur_thresh_crit_col",     STR_PARAM, &calldur_thresh_crit_col.s},
	{"totalc_thresh_warn_col",      STR_PARAM, &totalc_thresh_warn_col.s},
	{"totalc_thresh_crit_col",      STR_PARAM, &totalc_thresh_crit_col.s},
	{"concalls_thresh_warn_col",    STR_PARAM, &concalls_thresh_warn_col.s},
	{"concalls_thresh_crit_col",    STR_PARAM, &concalls_thresh_crit_col.s},
	{"seqcalls_thresh_warn_col",    STR_PARAM, &seqcalls_thresh_warn_col.s},
	{"seqcalls_thresh_crit_col",    STR_PARAM, &seqcalls_thresh_crit_col.s},
	{0,0,0}
};

static mi_export_t mi_cmds[] = {
	//{ "get_maps","return all mappings",mi_get_maps,MI_NO_INPUT_FLAG,0,0},
	{"show_fraud_stats", "print current stats for a particular user",
		mi_show_stats, 0, 0, 0},
	{"fraud_reload", "reload fraud profiles from db", mi_reload, 0, 0, 0},
	{0,0,0,0,0,0}
};

static dep_export_t deps = {
	{
		{MOD_TYPE_SQLDB, NULL, DEP_ABORT},
		{MOD_TYPE_DEFAULT, "drouting", DEP_ABORT},
		{MOD_TYPE_DEFAULT, "dialog", DEP_ABORT},
		{MOD_TYPE_NULL, NULL, 0},
	},
	{
		{NULL, NULL},
	},
};

/** module exports */
struct module_exports exports= {
	"fraud_detection",               /* module name */
	MOD_TYPE_DEFAULT,
	MODULE_VERSION,
	DEFAULT_DLFLAGS,            /* dlopen flags */
	&deps,
	cmds,                       /* exported functions */
	0,                          /* exported async functions */
	params,                     /* exported parameters */
	0,                          /* exported statistics */
	mi_cmds,                    /* exported MI functions */
	0,                          /* exported pseudo-variables */
	0,			 				/* exported transformations */
	0,                          /* extra processes */
	mod_init,                   /* module initialization function */
	(response_function) 0,      /* response handling function */
	(destroy_function)destroy,  /* destroy function */
	child_init                  /* per-child init function */
};


static void set_lengths(void)
{
	table_name.len = strlen(table_name.s);
	rid_col.len = strlen(rid_col.s);
	pid_col.len = strlen(pid_col.s);
	prefix_col.len = strlen(prefix_col.s);
	start_h_col.len = strlen(start_h_col.s);
	end_h_col.len = strlen(end_h_col.s);
	days_col.len = strlen(days_col.s);
	cpm_thresh_warn_col.len = strlen(cpm_thresh_warn_col.s);
	cpm_thresh_crit_col.len = strlen(cpm_thresh_crit_col.s);
	calldur_thresh_warn_col.len = strlen(calldur_thresh_warn_col.s);
	calldur_thresh_crit_col.len = strlen(calldur_thresh_crit_col.s);
	totalc_thresh_warn_col.len = strlen(totalc_thresh_warn_col.s);
	totalc_thresh_crit_col.len = strlen(totalc_thresh_crit_col.s);
	concalls_thresh_warn_col.len = strlen(concalls_thresh_warn_col.s);
	concalls_thresh_crit_col.len = strlen(concalls_thresh_crit_col.s);
	seqcalls_thresh_warn_col.len = strlen(seqcalls_thresh_warn_col.s);
	seqcalls_thresh_crit_col.len = strlen(seqcalls_thresh_crit_col.s);
}

static int mod_init(void)
{
	LM_INFO("Initializing module\n");
	init_db_url(db_url, 0);

	if ((frd_data_lock = lock_init_rw()) == NULL) {
		LM_CRIT("failed to init reader/writer lock\n");
		return -1;
	}

	if ((frd_seq_calls_lock = lock_alloc()) == NULL) {
		LM_ERR("cannot alloc seq_calls lock\n");
		return -1;
	}
	if (lock_init(frd_seq_calls_lock) == NULL) {
		LM_ERR ("cannot init seq_calls lock\n");
		return -1;
	}

	if (load_dlg_api(&dlgb) != 0) {
		LM_ERR("failed to load dialog binds\n");
		return -1;
	}

	if (frd_event_init() != 0) {
		LM_ERR("cannot register events\n");
		return -1;
	}

	if (load_dr_api(&drb) != 0) {
		LM_ERR("cannot load dr_api\n");
		return -1;
	}

	dr_head = shm_malloc(sizeof(dr_head_p));
	if (dr_head == NULL) {
		LM_ERR("no more shm memory\n");
		return -1;
	}
	*dr_head = NULL;

	set_lengths();
	if (init_stats_table() != 0)
		return -1;

	/* Check if table version is ok */
	frd_init_db();
	frd_disconnect_db();

	return 0;
}

static int child_init(int rank)
{
	if (rank == 1) {

		if (frd_connect_db() != 0 || frd_reload_data() != 0) {
			LM_ERR ("cannot load data from db\n");
			return -1;
		}
		frd_disconnect_db();
	}
	return 0;
}

/*
 * destroy function
 */
static void destroy(void)
{
	free_stats_table();
	frd_destroy_data();
}

static int fixup_check_fraud(void **param, int param_no)
{
	switch (param_no) {

		case 1:
		case 2:
			return fixup_spve(param);

		case 3:
			return fixup_igp(param);

		default:
			LM_CRIT ("Too many parameters for check_fraud\n");
			return -1;
	}
}

static int check_fraud(struct sip_msg *msg, char *_user, char *_number, char *_pid)
{

	static const int rc_error = -3, rc_critical_thr = -2, rc_warning_thr = -1,
				 rc_ok_thr = 1, rc_no_rule = 2;
	str user, number;
	unsigned int pid;
	frd_dlg_param *param;
	extern unsigned int frd_data_rev;

	if (*dr_head == NULL) {
		/* No data, probably still loading */
		LM_INFO("rules are not available yet!\n");
		return rc_ok_thr;
	}

	/* Get the actual params */

	if (fixup_get_svalue(msg, (gparam_p) _user, &user) != 0) {
		LM_ERR("Cannot get user value\n");
		return rc_error;
	}
	if (fixup_get_svalue(msg, (gparam_p) _number, &number) != 0) {
		LM_ERR("Cannot get number value\n");
		return rc_error;
	}
	if (fixup_get_ivalue(msg, (gparam_p)_pid, (int*)&pid) != 0) {
		LM_ERR("Cannot get the profile-id value\n");
		return rc_error;
	}

	/* Find a rule */

	unsigned int matched_len;
	lock_start_read(frd_data_lock);
	rt_info_t *rule = drb.match_number(*dr_head, pid, &number, &matched_len);

	if (rule == NULL) {
		/* No match */
		LM_DBG("No rule matched for number=<%.*s>, pid=<%d>\n",
				number.len, number.s, pid);

		lock_stop_read(frd_data_lock);
		return rc_no_rule;
	}

	/* We matched a rule */
	str prefix = number;
	prefix.len = matched_len;
	str shm_user;
	frd_stats_entry_t *se = get_stats(user, prefix, &shm_user);

	/* Check if we need to reset the stats */

	struct tm now, then;
	time_t nowt = time(NULL);

	/* We lock all the stats values */
	lock_get(&se->lock);
	if (gmtime_r(&se->stats.last_matched_time, &then) == NULL
			|| gmtime_r(&nowt, &now) == NULL) {
		LM_ERR ("Cannot use gmtime function. Will exit\n");
		lock_release(&se->lock);
		return rc_ok_thr;
	}

	if (se->stats.last_matched_time == 0 || se->stats.last_matched_rule != rule->id
			|| then.tm_yday != now.tm_yday || then.tm_year != now.tm_year) {
		se->stats.cpm = 0;
		se->stats.total_calls = 0;
		se->stats.concurrent_calls = 0;
	}

	/* Update the stats */

	lock_get(frd_seq_calls_lock);
	if (se->stats.last_called_prefix.len == matched_len &&
			memcmp(se->stats.last_called_prefix.s, number.s, matched_len) == 0) {

		/* We have called the same number last time */
		++se->stats.seq_calls;
	}
	else {
		if (shm_str_extend(&se->stats.last_called_prefix, matched_len) != 0) {
			LM_ERR("oom\n");
			return rc_error;
		}
		memcpy(se->stats.last_called_prefix.s, number.s, matched_len);
		se->stats.seq_calls = 1;
	}
	lock_release(frd_seq_calls_lock);

	se->stats.last_matched_rule = rule->id;
	++se->stats.total_calls;

	/* Calls per FRD_SECS_PER_WINDOW */
	if (nowt - se->stats.last_matched_time >= 2 * FRD_SECS_PER_WINDOW) {
		/* outside the range of t0 + 2*WINDOW_SIZE; we can't use any of the
		 * data since they are too old */
		se->stats.cpm = 0;
		memset(se->stats.calls_window, 0,
				sizeof(unsigned short) * FRD_SECS_PER_WINDOW);
		se->stats.calls_window[nowt % FRD_SECS_PER_WINDOW] = 1;
		se->stats.last_matched_time = nowt;
	}
	else if (nowt - se->stats.last_matched_time >= FRD_SECS_PER_WINDOW) {
		/* more than t0 + WINDOW_SIZE but less than 2 * WINDOW_SIZE
		 * we can consider calls from t0 + (now - WINDOW_SIZE)
		 * all cals from t0 to t0 + (now - WINDOW_SIZE) shall be invalidated */
		unsigned int old_matched_time = se->stats.last_matched_time;

		se->stats.last_matched_time = nowt - FRD_SECS_PER_WINDOW + 1;

		/*interval [old_last_matched_time; current_last_matched_time) shall
		 * be invalidated */
		unsigned int i = (se->stats.last_matched_time - 1) % FRD_SECS_PER_WINDOW;
		unsigned int j = (old_matched_time - 1) % FRD_SECS_PER_WINDOW;
		for (;i != j; i = (i - 1 + FRD_SECS_PER_WINDOW) % FRD_SECS_PER_WINDOW) {
			se->stats.cpm -= se->stats.calls_window[i];
			se->stats.calls_window[i] = 0;
		}
		se->stats.calls_window[nowt%FRD_SECS_PER_WINDOW]++;
	} else {
		/* less than t0 + WINDOW_SIZE; all we need to do is to increase
		 * the number of calls for nowt */
		se->stats.calls_window[nowt%FRD_SECS_PER_WINDOW]++;
	}

	++se->stats.cpm;
	++se->stats.concurrent_calls;

	/* Check the thresholds */
	int rc = rc_ok_thr;

	frd_thresholds_t *thr = (frd_thresholds_t*)rule->attrs.s;

#define CHECK_AND_RAISE(pname, type) \
	(se->stats.pname >= thr->pname ## _thr.type) { \
		raise_ ## type ## _event(&pname ## _name, &se->stats.pname,\
				&thr->pname ## _thr.type, &user, &number, &rule->id);\
		rc = rc_ ## type ## _thr;\
	}

	if CHECK_AND_RAISE(cpm, critical)
	else if CHECK_AND_RAISE(total_calls, critical)
	else if CHECK_AND_RAISE(concurrent_calls, critical)
	else if CHECK_AND_RAISE(seq_calls, critical)
	else if CHECK_AND_RAISE(cpm, warning)
	else if CHECK_AND_RAISE(total_calls, warning)
	else if CHECK_AND_RAISE(concurrent_calls, warning)
	else if CHECK_AND_RAISE(seq_calls, warning);

#undef CHECK_AND_RAISE

	lock_release(&se->lock);

	/* Set dialog callback to check call duration */
	struct dlg_cell *dlgc = dlgb.get_dlg();
	if (dlgc == NULL) {
		if (dlgb.create_dlg(msg, 0) < 0) {
			LM_ERR ("cannot create new_dlg\n");
			rc = rc_error;
		} else if ( (dlgc = dlgb.get_dlg()) == NULL) {
			LM_ERR("cannot get the new dlg\n");
			rc = rc_error;
		}
	}

	param = shm_malloc(sizeof(frd_dlg_param));
	if (!param) {
		LM_ERR("no more shm memory");
	} else if (shm_str_dup(&param->number, &number) == 0) {
		param->stats = se;
		param->thr = thr;
		param->user = shm_user;
		param->ruleid = rule->id;
		param->data_rev = frd_data_rev;

		if (dlgb.register_dlgcb(dlgc, DLGCB_TERMINATED|DLGCB_FAILED|DLGCB_EXPIRED,
					dialog_terminate_CB, param, NULL) != 0) {
			LM_ERR("failed to register dialog terminated callback\n");
			lock_stop_read(frd_data_lock);
			shm_free(param->number.s);
			shm_free(param);
			return rc_error;
		}
	} else {
		shm_free(param);
	}

	lock_stop_read(frd_data_lock);
	return rc;
}

static struct mi_root* mi_show_stats(struct mi_root *cmd_tree, void *param)
{
	/* User, number, pid */

	struct mi_node *node = cmd_tree->node.kids;
	str user, prefix;
	unsigned int pid;

	if (node == NULL)
		return init_mi_tree(400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	user = node->value;
	node = node->next;

	if (node == NULL)
		return init_mi_tree(400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	prefix = node->value;
	node = node->next;

	if (node == NULL)
		return init_mi_tree(400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	if (str2int(&node->value, &pid) != 0) {
		LM_WARN("Wrong value for profile id. Token <%.*s>\n", node->value.len,
				node->value.s);
		return init_mi_tree(400, MI_BAD_PARM_S, MI_BAD_PARM_LEN);
	}

	if (!stats_exist(user, prefix)) {
		LM_WARN("There is no data for user<%.*s> and prefix=<%.*s>\n",
				user.len, user.s, prefix.len, prefix.s);
		return init_mi_tree(400, MI_BAD_PARM_S, MI_BAD_PARM_LEN);
	}


	struct mi_root* rpl_tree = init_mi_tree(200, MI_OK_S, MI_OK_LEN);
	if (rpl_tree == NULL)
		return 0;
	rpl_tree->node.flags |= MI_IS_ARRAY;

	frd_stats_entry_t *se = get_stats(user, prefix, NULL);
	lock_get(&se->lock);

#define ADD_STAT_CHILD(pname, pval) do {\
	int val_len;\
	char *cval = int2str(pval, &val_len);\
	if (add_mi_node_child(&rpl_tree->node, MI_DUP_VALUE,\
			pname ## _name.s, pname ## _name.len, cval, val_len) == 0)\
		goto add_error;\
} while (0)

	ADD_STAT_CHILD(cpm, se->stats.cpm);
	ADD_STAT_CHILD(total_calls, se->stats.total_calls);
	ADD_STAT_CHILD(concurrent_calls, se->stats.concurrent_calls);
	ADD_STAT_CHILD(seq_calls, se->stats.seq_calls);

#undef ADD_STAT_CHILD

	lock_release(&se->lock);
	return rpl_tree;

add_error:
	lock_release(&se->lock);
	LM_ERR("failed to add node\n");
	free_mi_tree(rpl_tree);
	return 0;
}

static struct mi_root* mi_reload(struct mi_root *cmd_tree, void *param)
{
	if (frd_connect_db() != 0 || frd_reload_data() != 0) {
			LM_ERR ("cannot load data from db\n");
			return init_mi_tree(500, MI_INTERNAL_ERR_S, MI_INTERNAL_ERR_LEN);
	}
	else {
		frd_disconnect_db();
		return init_mi_tree(200, MI_OK_S, MI_OK_LEN);
	}
}
