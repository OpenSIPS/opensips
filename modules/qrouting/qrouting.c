/*
 * Copyright (C) 2014 OpenSIPS Foundation
 * Copyright (C) 2020 OpenSIPS Solutions
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
 */

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>

#include "../../sr_module.h"
#include "../../str.h"
#include "../../timer.h"
#include "../../lib/csv.h"

#include "qrouting.h"
#include "qr_stats.h"
#include "qr_sort.h"
#include "qr_acc.h"
#include "qr_load.h"
#include "qr_mi.h"
#include "qr_event.h"

#define T_PROC_LABEL "qrouting-sampling"

#define QR_PARAM_PART     "partition"
#define QR_PARAM_RULE_ID  "rule_id"
#define QR_PARAM_DST_NAME "dst_name"

#define QR_TABLE_VER 1

/* modparam */
static int history_span = 30; /* the history span in minutes */
static int sampling_interval = 5; /* the sampling interval in seconds */
static char *event_bad_dst_threshold_s;
double event_bad_dst_threshold;

str db_url;

qr_algo_t qr_algorithm = QR_ALGO_DYNAMIC_WEIGHTS;
static char *qr_algorithm_s;

qr_xstat_desc_t *qr_xstats;
int qr_xstats_n;
static char *qr_xstats_s;

qr_partitions_t **qr_main_list; /* the history itself */
rw_lock_t *qr_main_list_rwl; /* protection during dr_reload */

qr_profile_t **qr_profiles;
int *qr_profiles_n;
rw_lock_t *qr_profiles_rwl; /* protection during qr_reload */

int qr_min_samples_asr = 30;
int qr_min_samples_ccr = 30;
int qr_min_samples_pdd = 10;
int qr_min_samples_ast = 10;
int qr_min_samples_acd = 20;

/* the amount of decimal digits to use in logging or MI output */
int qr_decimal_digits = 2;

int qr_interval_list_sz; /* the maximum number of kept intervals (samples) */

/* DB connection - useful for runtime reloads */
db_func_t qr_dbf;
db_con_t *qr_db_hdl;

/* avps */
str avp_invite_time_name_pdd = str_init("$avp(qr_invite_time_pdd)");
str avp_invite_time_name_ast = str_init("$avp(qr_invite_time_ast)");

/* event/MI parameters */
str qr_param_part = str_init(QR_PARAM_PART);
str qr_param_rule_id = str_init(QR_PARAM_RULE_ID);
str qr_param_dst_name = str_init(QR_PARAM_DST_NAME);


static int qr_init(void);
static int qr_child_init(int rank);
static int qr_exit(void);
static int qr_init_globals(void);
static int qr_check_db(void);
static int qr_init_dr_cb(void);

static timer_function qr_rotate_samples;

static int w_qr_set_xstat(struct sip_msg *_, int *rule_id, str *gw_name,
                    void *stat_name, str *_inc_by, str *part, int *_inc_total);
static int w_qr_disable_dst(struct sip_msg *_,
                            int *rule_id, str *dst_name, str *part);
static int w_qr_enable_dst(struct sip_msg *_,
                           int *rule_id, str *dst_name, str *part);

static int qr_fix_xstat(void **param);

static cmd_export_t cmds[] = {
	{"qr_set_xstat", (cmd_function)w_qr_set_xstat,
		{ {CMD_PARAM_INT, NULL, NULL},
		  {CMD_PARAM_STR, NULL, NULL},
		  {CMD_PARAM_STR, qr_fix_xstat, NULL},
		  {CMD_PARAM_STR, NULL, NULL},
		  {CMD_PARAM_STR|CMD_PARAM_OPT, NULL, NULL},
		  {CMD_PARAM_INT|CMD_PARAM_OPT, NULL, NULL},
		  {0, 0, 0}
		},
		ALL_ROUTES & (~STARTUP_ROUTE)
	},
	{"qr_disable_dst", (cmd_function)w_qr_disable_dst,
		{ {CMD_PARAM_INT, NULL, NULL},
		  {CMD_PARAM_STR, NULL, NULL},
		  {CMD_PARAM_STR|CMD_PARAM_OPT, NULL, NULL},
		  {0, 0, 0}
		},
		ALL_ROUTES & (~STARTUP_ROUTE)
	},
	{"qr_enable_dst", (cmd_function)w_qr_enable_dst,
		{ {CMD_PARAM_INT, NULL, NULL},
		  {CMD_PARAM_STR, NULL, NULL},
		  {CMD_PARAM_STR|CMD_PARAM_OPT, NULL, NULL},
		  {0, 0, 0}
		},
		ALL_ROUTES & (~STARTUP_ROUTE)
	},
	{0,0,{{0,0,0}},0}
};

static param_export_t params[] = {
	{"db_url",                  STR_PARAM, &db_url.s},
	{"table_name",              STR_PARAM, &qr_profiles_table.s},
	{"algorithm",               STR_PARAM, &qr_algorithm_s},
	{"history_span",            INT_PARAM, &history_span},
	{"sampling_interval",       INT_PARAM, &sampling_interval},
	{"extra_stats",             STR_PARAM, &qr_xstats_s},
	{"min_samples_asr",         INT_PARAM, &qr_min_samples_asr},
	{"min_samples_ccr",         INT_PARAM, &qr_min_samples_ccr},
	{"min_samples_pdd",         INT_PARAM, &qr_min_samples_pdd},
	{"min_samples_ast",         INT_PARAM, &qr_min_samples_ast},
	{"min_samples_acd",         INT_PARAM, &qr_min_samples_acd},
	{"event_bad_dst_threshold", STR_PARAM, &event_bad_dst_threshold_s},
	{"decimal_digits",          INT_PARAM, &qr_decimal_digits},
	{0, 0, 0}
};

#define HLP1 "Params: [partition [, rule_id [, dst_name]]]; List QR statistics"
#define HLP2 "Params: [partition] rule_id dst_name; Remove a gateway/carrier from routing"
#define HLP3 "Params: [partition] rule_id dst_name; Re-introduce a gateway/carrier into routing"
static mi_export_t mi_cmds[] = {
	{ "qr_status", HLP1, 0, NULL, {
		{mi_qr_status_0, {NULL}},
		{mi_qr_status_1, {QR_PARAM_PART, NULL}},
		{mi_qr_status_2, {QR_PARAM_PART, QR_PARAM_RULE_ID, NULL}},
		{mi_qr_status_3, {QR_PARAM_PART, QR_PARAM_RULE_ID,
		                  QR_PARAM_DST_NAME, NULL}},
		{EMPTY_MI_RECIPE}}
	},
	{ "qr_reload", NULL, 0, NULL, {
		{mi_qr_reload_0, {NULL}},
		{EMPTY_MI_RECIPE}}
	},
	{ "qr_disable_dst", HLP2, MI_NAMED_PARAMS_ONLY, NULL, {
		{mi_qr_disable_dst_2, {QR_PARAM_RULE_ID, QR_PARAM_DST_NAME, NULL}},
		{mi_qr_disable_dst_3, {QR_PARAM_PART, QR_PARAM_RULE_ID,
		                       QR_PARAM_DST_NAME, NULL}},
		{EMPTY_MI_RECIPE}}
	},
	{ "qr_enable_dst", HLP3, MI_NAMED_PARAMS_ONLY, NULL, {
		{mi_qr_disable_dst_2, {QR_PARAM_RULE_ID, QR_PARAM_DST_NAME, NULL}},
		{mi_qr_disable_dst_3, {QR_PARAM_PART, QR_PARAM_RULE_ID,
		                       QR_PARAM_DST_NAME, NULL}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_SQLDB, NULL, DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "tm", DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "dialog", DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

struct module_exports exports = {
	"qrouting",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,               /* load function */
	&deps,           /* OpenSIPS module dependencies */
	cmds,            /* Exported functions */
	0,               /* Exported async functions */
	params,          /* Exported parameters */
	0,               /* exported statistics */
	mi_cmds,         /* exported MI functions */
	0,               /* exported pseudo-variables */
	0,               /* exported transformations */
	0,               /* additional processes */
	0,               /* Module pre-initialization function */
	qr_init,         /* Module initialization function */
	(response_function) 0,
	(destroy_function) qr_exit,
	(child_init_function) qr_child_init, /* per-child init function */
	0                /* reload confirm function */
};


static int qr_init(void)
{
	LM_INFO("qrouting module - initializing\n");
	LM_DBG("history_span = %d, sampling_interval = %d\n", history_span,
			sampling_interval);

	if (qr_init_globals() != 0) {
		LM_ERR("failed to init global structures\n");
		return -1;
	}

	if (qr_init_events() != 0) {
		LM_ERR("failed to init events\n");
		return -1;
	}

	register_timer(T_PROC_LABEL, qr_rotate_samples, NULL,
	               sampling_interval, TIMER_FLAG_SKIP_ON_DELAY);

	if (qr_check_db() != 0) {
		LM_ERR("DB check failed\n");
		return -1;
	}

	if (load_tm_api(&tmb) != 0) {
		LM_ERR("failed to load tm functions. Tm module loaded?\n");
		return -1;
	}

	if (load_dlg_api(&dlgcb) != 0) {
		LM_ERR("failed to load dlg functions. Dialog module loaded?\n");
		return -1;
	}

	if (qr_init_dr_cb() != 0) {
		LM_ERR("failed to register drouting callbacks\n");
		return -1;
	}

	return 0;
}

static int qr_child_init(int rank)
{
	/* re-connect to the db */
	if (db_bind_mod(&db_url, &qr_dbf)) {
		LM_CRIT("cannot bind to database module! "
				"Did you forget to load a database module ? (%.*s)\n",
				db_url.len, db_url.s);
		return -1;
	}

	if (!(qr_db_hdl = qr_dbf.init(&db_url)))
		LM_ERR("failed to load db url %.*s\n", db_url.len, db_url.s);

	if (rank == 1 && qr_reload(&qr_dbf, qr_db_hdl) < 0)
		LM_ERR("failed to load data from db\n");

	return 0;
}

static int qr_exit(void)
{
	free_qr_list(*qr_main_list);

	/* free the thresholds */
	*qr_profiles_n = 0;
	shm_free(*qr_profiles);
	shm_free(qr_profiles);
	shm_free(qr_profiles_n);
	qr_profiles = QR_PTR_POISON;
	return 0;
}

static void qr_rotate_samples(unsigned int ticks, void *param)
{
	qr_rule_t *it;
	int i, j;

	LM_DBG("rotating samples for all (prefix, destination) pairs...\n");

	lock_start_read(qr_main_list_rwl);

	if (*qr_main_list) {
		/* for every partition, rule and destination */
		for (j = 0; j < (*qr_main_list)->n_parts; j++) {
			for (it = (*qr_main_list)->qr_rules_start[j]; it; it = it->next) {
				for (i = 0; i < it->n; i++) {
					if (it->dest[i].type == QR_DST_GW)
						update_gw_stats(it->dest[i].gw);
					else
						update_grp_stats(it->dest[i].grp);
				}
			}
		}
	}

	lock_stop_read(qr_main_list_rwl);

	LM_DBG("done!\n");
}

static int qr_init_dr_cb(void)
{
	dr_cb sort_cb;

	if (load_dr_api(&drb) != 0) {
		LM_ERR("failed to load dr API.  Is the drouting module loaded?\n");
		return -1;
	}

	/* 1. dr_reload callbacks */

	if (drb.register_drcb(DRCB_RLD_PREPARE_PART, &qr_rld_prepare_part,
				NULL, NULL) < 0) {
		LM_ERR("failed to register DRCB_RLD_PREPARE_PART callback to DR\n");
		return -1;
	}

	if (drb.register_drcb(DRCB_RLD_INIT_RULE, &qr_rld_create_rule, NULL, NULL) < 0) {
		LM_ERR("failed to register DRCB_RLD_INIT_RULE callback to DR\n");
		return -1;
	}
	if (drb.register_drcb(DRCB_RLD_GW, &qr_rld_dst_is_gw, NULL, NULL) < 0) {
		LM_ERR("failed to register DRCB_RLD_GW callback to DR\n");
		return -1;
	}
	if (drb.register_drcb(DRCB_RLD_CR, &qr_rld_dst_is_grp, NULL, NULL) < 0) {
		LM_ERR("failed to register DRCB_RLD_CR callback to DR\n");
		return -1;
	}
	if (drb.register_drcb(DRCB_RLD_LINK_RULE, &qr_rld_link_rule, NULL, NULL) < 0) {
		LM_ERR("failed to register DRCB_RLD_LINK_RULE callback to DR\n");
		return -1;
	}

	if (drb.register_drcb(DRCB_RLD_FINALIZE, &qr_rld_finalize, NULL, NULL) < 0) {
		LM_ERR("failed to register DRCB_RLD_FINALIZE callback to DR\n");
		return -1;
	}

	/* 2. other callbacks */

	if (drb.register_drcb(DRCB_ACC_CALL, &qr_acc, NULL, NULL) < 0) {
		LM_ERR("failed to register DRCB_ACC_CALL callback to DR\n");
		return -1;
	}

	if (qr_algorithm == QR_ALGO_BEST_DEST_FIRST)
		sort_cb = &qr_sort_best_dest_first;
	else
		sort_cb = &qr_sort_dynamic_weights;

	if (drb.register_drcb(DRCB_SORT_DST, sort_cb, (void*)QR_BASED_SORT, NULL) < 0) {
		LM_ERR("failed to register DRCB_SORT_DST callback to DR\n");
		return -1;
	}

	LM_DBG("initialized drouting callbacks\n");
	return 0;
}

static int qr_parse_extra_stats(void)
{
	csv_record *stats, *stat;
	qr_xstat_desc_t *desc;
	char *p;
	str samples;

	if (!qr_xstats_s)
		return 0;

	stats = __parse_csv_record(_str(qr_xstats_s), 0, ';');
	for (stat = stats; stat; stat = stat->next) {
		if (ZSTR(stat->s))
			continue;

		qr_xstats = pkg_realloc(qr_xstats, (qr_xstats_n + 1) * sizeof *qr_xstats);
		if (!qr_xstats) {
			LM_ERR("oom\n");
			return -1;
		}

		desc = &qr_xstats[qr_xstats_n];
		memset(desc, 0, sizeof *desc);

		if (stat->s.s[0] == '-') {
			stat->s.s++;
			stat->s.len--;
		} else if (stat->s.s[0] == '+') {
			stat->s.s++;
			stat->s.len--;
			desc->increasing = 1;
		} else {
			desc->increasing = 1;
		}

		trim(&stat->s);
		p = memchr(stat->s.s, '/', stat->s.len);
		if (!p) {
			desc->min_samples = QR_MIN_XSTAT_SAMPLES;
		} else {
			samples.s = p + 1;
			samples.len = stat->s.s + stat->s.len - samples.s;
			trim(&samples);
			if (samples.len == 0 || str2int(&samples, &desc->min_samples)) {
				LM_ERR("bad 'min_samples' part: '%.*s'\n",
				       samples.len, samples.s);
				return -1;
			}

			stat->s.len = p - stat->s.s;
			trim(&stat->s);
		}

		if (ZSTR(stat->s)) {
			continue;
		} else if (stat->s.len > QR_MAX_STAT_NAME_LEN) {
			LM_ERR("stat name too long (%.*s), use max %lu chars\n",
			       stat->s.len, stat->s.s, QR_MAX_STAT_NAME_LEN);
			return -1;
		}

		desc->name.s = pkg_malloc(stat->s.len + 1);
		if (!desc->name.s) {
			LM_ERR("oom\n");
			return -1;
		}

		str_cpy(&desc->name, &stat->s);
		desc->name.s[desc->name.len] = '\0';

		qr_xstats_n++;

		LM_DBG("parsed extra stat '%s%s/%d'\n", desc->increasing ? "+" : "-",
		       desc->name.s, desc->min_samples);
	}

	free_csv_record(stats);
	return 0;
}

static int qr_init_globals(void)
{
	if (event_bad_dst_threshold_s)
		event_bad_dst_threshold = strtod(event_bad_dst_threshold_s, NULL);

	if (qr_algorithm_s && \
	        (qr_algorithm = qr_str2algo(qr_algorithm_s)) == QR_ALGO_INVALID) {
		LM_ERR("invalid algorithm: '%s'\n", qr_algorithm_s);
		return -1;
	}

	if (qr_parse_extra_stats() != 0) {
		LM_ERR("failed to parse extra stats\n");
		return -1;
	}

	if (!(qr_main_list_rwl = lock_init_rw())) {
		LM_ERR("oom\n");
		return -1;
	}

	if (!(qr_profiles_rwl = lock_init_rw())) {
		LM_ERR("oom\n");
		return -1;
	}

	qr_main_list = shm_malloc(sizeof *qr_main_list);
	if (!qr_main_list) {
		LM_ERR("oom\n");
		return -1;
	}
	*qr_main_list = NULL;

	qr_profiles = shm_malloc(sizeof *qr_profiles);
	if (!qr_profiles) {
		LM_ERR("oom\n");
		return -1;
	}
	*qr_profiles = NULL;

	qr_profiles_n = shm_malloc(sizeof *qr_profiles_n);
	if (!qr_profiles_n) {
		LM_ERR("oom\n");
		return -1;
	}
	*qr_profiles_n = 0;

	qr_interval_list_sz = history_span * 60 / sampling_interval;

	return 0;
}

static int qr_check_db(void)
{
	db_func_t qr_dbf;
	db_con_t *qr_db_hdl;

	init_db_url(db_url, 0);
	qr_profiles_table.len = strlen(qr_profiles_table.s);

	/* test the db */
	if (db_bind_mod(&db_url, &qr_dbf)) {
		LM_CRIT("cannot bind to database module! "
				"Did you forget to load a database module ? (%.*s)\n",
				db_url.len, db_url.s);
		return -1;
	}

	if (!(qr_db_hdl = qr_dbf.init(&db_url))) {
		LM_ERR("failed to load db url %.*s\n", db_url.len, db_url.s);
		return -1;
	}

	if (!DB_CAPABILITY(qr_dbf, DB_CAP_QUERY)) {
		LM_ERR("database module does not provide"
				" query functions required by qrouting\n");
		return -1;
	}

	if (db_check_table_version(&qr_dbf, qr_db_hdl, &qr_profiles_table,
	                           QR_TABLE_VER) != 0) {
		LM_ERR("bad version for <%.*s> table (need %d)\n",
		       qr_profiles_table.len, qr_profiles_table.s, QR_TABLE_VER);
		return -1;
	}

	/* close the connection to the db */
	qr_dbf.close(qr_db_hdl);

	return 0;
}

static int w_qr_set_dst_state(int rule_id, str *dst_name, str *part, int state)
{
	qr_rule_t *rules;
	int rc;

	if (!part) {
		lock_start_read(qr_main_list_rwl);
		rc = qr_set_dst_state((*qr_main_list)->qr_rules_start[0], rule_id,
		                      dst_name, state, NULL);
		lock_stop_read(qr_main_list_rwl);
	} else {
		lock_start_read(qr_main_list_rwl);

		rules = qr_get_rules(part);
		if (!rules) {
			LM_DBG("partition not found: %.*s\n", part->len, part->s);
			lock_stop_read(qr_main_list_rwl);
			return -2;
		}

		rc = qr_set_dst_state(rules, rule_id, dst_name, state, NULL);
		lock_stop_read(qr_main_list_rwl);
	}

	return rc == 0 ? 1 : -1;
}

static int w_qr_disable_dst(struct sip_msg *_,
                            int *rule_id, str *dst_name, str *part)
{
	return w_qr_set_dst_state(*rule_id, dst_name, part, 0);
}

static int w_qr_enable_dst(struct sip_msg *_,
                           int *rule_id, str *dst_name, str *part)
{
	return w_qr_set_dst_state(*rule_id, dst_name, part, 1);
}


static int qr_set_xstat(qr_rule_t *rules, int rule_id, str *gw_name,
                        int stat_idx, double inc_by, int inc_total)
{
	qr_rule_t *rule;
	qr_gw_t *gw;

	rule = qr_search_rule(rules, rule_id);
	if (!rule) {
		LM_ERR("failed to locate rule %d, "
		       "perhaps you forgot to dr_reload?\n", rule_id);
		return -1;
	}

	gw = qr_search_gw(rule, gw_name);
	if (!gw) {
		LM_ERR("failed to locate gw %.*s within rule %d, "
		       "perhaps you forgot to dr_reload?\n",
		       gw_name->len, gw_name->s, rule_id);
		return -1;
	}

	lock_get(gw->acc_lock);
	gw->current_interval.n.xtot[stat_idx] += inc_total;
	gw->current_interval.stats.xsum[stat_idx] += inc_by;
	lock_release(gw->acc_lock);

	LM_DBG("successfully updated (rule %d, gw %.*s)\n", rule_id,
	       gw_name->len, gw_name->s);

	return 0;
}


static int w_qr_set_xstat(struct sip_msg *_, int *rule_id, str *gw_name,
                    void *stat_name, str *_inc_by, str *part, int *_inc_total)
{
	qr_rule_t *rules;
	int rc, stat_idx = (int)(long)stat_name;
	int inc_total = _inc_total ? *_inc_total : 1;
	double inc_by = strtod(_inc_by->s, NULL);

	LM_DBG("rule=%d, gw=%.*s, stat=%s, inc_by=%lf, part=%s, inc_tot=%d\n",
	       *rule_id, gw_name->len, gw_name->s, qr_xstats[stat_idx].name.s,
	       inc_by, part ? part->s : NULL, inc_total);

	if (!part) {
		lock_start_read(qr_main_list_rwl);
		if (!*qr_main_list) {
			lock_stop_read(qr_main_list_rwl);
			LM_BUG("main partition not available\n");
			return -2;
		}

		rc = qr_set_xstat((*qr_main_list)->qr_rules_start[0], *rule_id,
		                      gw_name, stat_idx, inc_by, inc_total);
		lock_stop_read(qr_main_list_rwl);
	} else {
		lock_start_read(qr_main_list_rwl);

		rules = qr_get_rules(part);
		if (!rules) {
			lock_stop_read(qr_main_list_rwl);
			LM_DBG("partition not found: %.*s\n", part->len, part->s);
			return -2;
		}

		rc = qr_set_xstat(rules, *rule_id, gw_name, stat_idx, inc_by, inc_total);
		lock_stop_read(qr_main_list_rwl);
	}

	return rc == 0 ? 1 : -1;
}


static int qr_fix_xstat(void **param)
{
	str *stat = (str *)*param;
	int i;

	for (i = 0; i < qr_xstats_n; i++) {
		if (!strcmp(qr_xstats[i].name.s, stat->s)) {
			LM_DBG("located stat %s on pos %d\n", stat->s, i);
			*param = (void *)(long)i;
			return 0;
		}
	}

	LM_ERR("failed to locate stat %s, define it via extra_stats!\n", stat->s);
	return -1;
}
