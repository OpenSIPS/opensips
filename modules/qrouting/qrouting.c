/*
 * Copyright (C) 2004-2005 FhG Fokus
 * Copyright (C) 2006-2010 Voice Sistem SRL
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

#include "qr_stats.h"
#include "qr_sort.h"
#include "qr_acc.h"
#include "qr_load.h"
#include "qr_mi.h"

#define T_PROC_LABEL "qrouting-sampling"
#define MAX_HISTORY 1000 /* TODO:*/

#define QR_TABLE_VER 1

/* modparam */
static int history = 30; /* the history span in minutes */
static int sampling_interval = 5; /* the sampling interval in seconds */

str db_url;

qr_partitions_t **qr_main_list; /* the history itself */
rw_lock_t **rw_lock_qr; /* protects qr_main_list */

qr_thresholds_t **qr_profiles;
int *qr_profiles_n;
rw_lock_t *qr_profiles_rwl; /* protection during qr_reload */

int qr_n;
int *n_sampled;

/* DB connection - useful for runtime reloads */
db_func_t qr_dbf;
db_con_t *qr_db_hdl;

/* avps */
str avp_invite_time_name_pdd = str_init("$avp(qr_invite_time_pdd)");
str avp_invite_time_name_ast = str_init("$avp(qr_invite_time_ast)");

static int qr_init(void);
static int qr_child_init(int rank);
static int qr_exit(void);
static int qr_init_globals(void);
static int qr_check_db(void);
static int qr_init_dr_cb(void);

static timer_function qr_rotate_samples;


static cmd_export_t cmds[] = {
	{0,0,{{0,0,0}},0}
};

static param_export_t params[] = {
	{"history", INT_PARAM, &history},
	{"sampling_interval", INT_PARAM, &sampling_interval},
	{"db_url", STR_PARAM, &db_url.s},
	{0, 0, 0}
};

#define HLP1 "Params: [partition_name [, rule_id [, dst_id]]]; List QR statistics"
static mi_export_t mi_cmds[] = {
	{ "qr_status", HLP1, 0, NULL, {
		{mi_qr_status_0, {NULL}},
		{mi_qr_status_1, {"partition_name", NULL}},
		{mi_qr_status_2, {"partition_name", "rule_id", NULL}},
		{mi_qr_status_3, {"partition_name", "rule_id", "dst_id", NULL}},
		{EMPTY_MI_RECIPE}}
	},
	{ "qr_reload", NULL, 0, NULL, {
		{mi_qr_reload_0, {NULL}},
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
	LM_DBG("history = %d, sampling_interval = %d\n", history,
			sampling_interval);

	if (qr_init_globals() != 0) {
		LM_ERR("oom\n");
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
	if (rank == PROC_TCP_MAIN)
		return 0;

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

	if (*n_sampled < qr_n)
		++(*n_sampled); /* the number of intervals sampled */

	lock_start_read(*rw_lock_qr);
	if(*qr_main_list != NULL) { /* if there is a list */
		for(j = 0; j < (*qr_main_list)->n_parts; j++) { /* for every partition */
			for(it = (*qr_main_list)->qr_rules_start[j];
					it != NULL; it = it->next) { /* for every rule */
				for(i = 0; i < it->n; i++) { /* for every destination */
					if(it->dest[i].type == QR_DST_GW) {
						update_gw_stats(it->dest[i].dst.gw);
					} else {
						update_grp_stats(it->dest[i].dst.grp);
					}
				}
			}
		}
	}
	lock_stop_read(*rw_lock_qr);
}

static int qr_init_dr_cb(void)
{
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

	if (drb.register_drcb(DRCB_RLD_INIT_RULE, &qr_create_rule, NULL, NULL) < 0) {
		LM_ERR("failed to register DRCB_RLD_INIT_RULE callback to DR\n");
		return -1;
	}
	if (drb.register_drcb(DRCB_RLD_GW, &qr_dst_is_gw, NULL, NULL) < 0) {
		LM_ERR("failed to register DRCB_RLD_REG_GW callback to DR\n");
		return -1;
	}
	if (drb.register_drcb(DRCB_RLD_CR, &qr_dst_is_grp, NULL, NULL) < 0) {
		LM_ERR("failed to register DRCB_RLD_REG_GW callback to DR\n");
		return -1;
	}
	if (drb.register_drcb(DRCB_RLD_ADD_RULE, &qr_add_rule_to_list, NULL, NULL) < 0) {
		LM_ERR("failed to register DRCB_RLD_ADD_RULE callback to DR\n");
		return -1;
	}

	if (drb.register_drcb(DRCB_RLD_FINALIZE, &qr_rld_finalize, NULL, NULL) < 0) {
		LM_ERR("failed to register DRCB_RLD_FREE_LIST callback to DR\n");
		return -1;
	}

	/* 2. other callbacks */

	if (drb.register_drcb(DRCB_ACC_CALL, &qr_acc, NULL, NULL) < 0) {
		LM_ERR("failed to register DRCB_ACC_CALL callback to DR\n");
		return -1;
	}

	if (drb.register_drcb(DRCB_SORT_DST, &qr_sort, (void*)QR_BASED_SORT, NULL) < 0) {
		LM_ERR("failed to register DRCB_SORT_DST callback to DR\n");
		return -1;
	}

	LM_DBG("initialized drouting callbacks\n");
	return 0;
}

static int qr_init_globals(void)
{
	/* TODO: should become obsolete */
	/* lock to protect from reloading */
	rw_lock_qr = shm_malloc(sizeof *rw_lock_qr);
	if (!rw_lock_qr || !(*rw_lock_qr = lock_init_rw())) {
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

	/* TODO history in minutes */
	qr_n = (history * 60) / sampling_interval; /* the number of sampling
												  intervals in history */

	n_sampled = shm_malloc(sizeof *n_sampled);
	if (!n_sampled) {
		LM_ERR("oom\n");
		return -1;
	}
	*n_sampled = 0;

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

	return 0;
}

static int qr_check_db(void)
{
	db_func_t qr_dbf;
	db_con_t *qr_db_hdl;

	init_db_url(db_url, 0);

	/* test the db */
	if (db_bind_mod(&db_url, &qr_dbf)) {
		LM_CRIT("cannot bind to database module! "
				"Did you forget to load a database module ? (%.*s)\n",
				db_url.len, db_url.s);
		return -1;
	}

	if (!(qr_db_hdl = qr_dbf.init(&db_url))) {
		LM_ERR("failed to load db url %.*s", db_url.len, db_url.s);
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
