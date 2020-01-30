/**
 *
 * qrouting module: qrouting.c
 *
 * Copyright (C) 2004-2005 FhG Fokus
 * Copyright (C) 2006-2010 Voice Sistem SRL
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History
 * -------
 *  2014-08-28  initial version (Mihai Tiganus)
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

#define T_PROC_LABEL "qrouting-sampling"
#define MAX_HISTORY 1000 /* TODO:*/

/* modparam */
rw_lock_t **rw_lock_qr; /* used to protect the qr_main_list */
static int history = 30; /* the history span in minutes */
static int sampling_interval = 5; /* the sampling interval in seconds */
str db_url;
int *n_qr_profiles = 0;
qr_partitions_t **qr_main_list; /* the history itself */
qr_thresholds_t **qr_profiles = 0;
int * qr_n;
int * n_sampled;

/* avps */
str avp_invite_time_name_pdd = str_init("$avp(qr_invite_time_pdd)");
str avp_invite_time_name_ast = str_init("$avp(qr_invite_time_ast)");

static int qr_init(void);
static int qr_child_init(int rank);
static int qr_exit(void);

static void timer_func(void);
static mi_response_t *mi_qr_status_0(const mi_params_t *params,
									struct mi_handler *async_hdl);
static mi_response_t *mi_qr_status_1(const mi_params_t *params,
									struct mi_handler *async_hdl);
static mi_response_t *mi_qr_status_2(const mi_params_t *params,
									struct mi_handler *async_hdl);
static mi_response_t *mi_qr_status_3(const mi_params_t *params,
									struct mi_handler *async_hdl);


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
	{ "qr_status", HLP1, 0, 0, {
		{mi_qr_status_0, {0}},
		{mi_qr_status_1, {"partition_name", 0}},
		{mi_qr_status_2, {"partition_name", "rule_id", 0}},
		{mi_qr_status_3, {"partition_name", "rule_id", "dst_id", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};


struct module_exports exports = {
	"qrouting",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,               /* load function */
	0,               /* OpenSIPS module dependencies */
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

static int qr_init(void){
	LM_INFO("QR module\n");
	LM_DBG("history = %d, sampling_interval = %d\n", history,
			sampling_interval);
	db_func_t qr_dbf;
	db_con_t *qr_db_hdl = 0;

	/* TODO: should become obsolete */
	/* lock to protect from reloading */
	rw_lock_qr = (rw_lock_t**)shm_malloc(sizeof(rw_lock_t*));
	if ((*rw_lock_qr = lock_init_rw()) == NULL) {
		LM_ERR("failed to init rw lock\n");
	}

	qr_main_list = (qr_partitions_t**)shm_malloc(sizeof(qr_partitions_t*));

	if(qr_main_list == NULL) {
		LM_ERR("no more shm memory\n");
		return -1;
	}

	*qr_main_list = NULL; /* mark main list as empty */

	register_timer(T_PROC_LABEL, (void*)timer_func, NULL,
			sampling_interval, TIMER_FLAG_SKIP_ON_DELAY);

	qr_n = (int*)shm_malloc(sizeof(int));
	/*TODO history in minutes */
	*qr_n = (history*60)/sampling_interval; /* the number of sampling
												intervals in history */

	n_sampled = (int*)shm_malloc(sizeof(int));
	*n_sampled = 0;

	if(db_url.s != NULL) {
		db_url.len = strlen(db_url.s);
	} else {
		LM_ERR("db_url param not provided for qr module\n");
		return -1;
	}

	/* test the db */
	if(db_bind_mod(&db_url, &qr_dbf)) {
		LM_CRIT("cannot bind to database module! "
				"Did you forget to load a database module ? (%.*s)\n",
				db_url.len, db_url.s);
		return -1;

	}

	if((qr_db_hdl = qr_dbf.init(&db_url)) == 0) {
		LM_ERR("failed to load db url %.*s", db_url.len, db_url.s);

	}

	if(!DB_CAPABILITY(qr_dbf, DB_CAP_QUERY)) {
		LM_ERR("database modules does not provide"\
				" QUERY functions needed by QRouting\n");
	}

	if(db_check_table_version(&qr_dbf, qr_db_hdl, &qr_profiles_table, 1) != 0) {
		LM_ERR("Not the expected table version for table <%.*s>\n",
				qr_profiles_table.len, qr_profiles_table.s);
		return -1;
	}

	/* close the connection to the db */
	qr_dbf.close(qr_db_hdl);
	qr_db_hdl = 0;

	if(load_tm_api(&tmb) == -1) {
		LM_ERR("failed to load tm functions. Tm module loaded?\n");
		return -1;
	}
	if(load_dlg_api(&dlgcb) == -1) {
		LM_ERR("failed to load dlg functions. Dialog module loaded?\n");
		return -1;
	}
	if(load_dr_api(&drb) == -1) {
		LM_ERR("Failed to load dr functions. DR modules loaded?\n");
		return -1;
	}

	qr_rules_start = (qr_rule_t **)shm_malloc(sizeof(qr_rule_t*));
	if(qr_rules_start == NULL) {
		LM_ERR("no more shm memory\n");
		return -1;
	}
	*qr_rules_start = NULL;


	if(drb.register_drcb(DRCB_REG_INIT_RULE, &qr_create_rule, NULL, NULL) < 0) {
		LM_ERR("[QR] failed to register DRCB_REG_INIT_RULE callback to DR\n");
		return -1;
	}
	if(drb.register_drcb(DRCB_REG_GW, &qr_dst_is_gw, NULL, NULL) < 0) {
		LM_ERR("[QR] failed to register DRCB_REG_REG_GW callback to DR\n");
		return -1;
	}
	if(drb.register_drcb(DRCB_REG_CR, &qr_dst_is_grp, NULL, NULL) < 0) {
		LM_ERR("[QR] failed to register DRCB_REG_REG_GW callback to DR\n");
		return -1;
	}
	if(drb.register_drcb(DRCB_REG_ADD_RULE, &qr_add_rule_to_list, NULL, NULL) < 0) {
		LM_ERR("[QR] failed to register DRCB_REG_ADD_RULE callback to DR\n");
		return -1;
	}
	if(drb.register_drcb(DRCB_ACC_CALL, &qr_acc, NULL, NULL) < 0) {
		LM_ERR("[QR] failed to register DRCB_ACC_CALL callback to DR\n");
		return -1;
	}

	if(drb.register_drcb(DRCB_SORT_DST, &qr_sort, (void*)QR_BASED_SORT, NULL) < 0) {
		LM_ERR("[QR] failed to register DRCB_SORT_DST callback to DR\n");
		return -1;
	}

	if(drb.register_drcb(DRCB_SET_PROFILE, &qr_search_profile, NULL, NULL) < 0) {
		LM_ERR("[QR] failed to register DRCB_SET_PROFILE callback to DR\n");
		return -1;
	}

	if(drb.register_drcb(DRCB_REG_MARK_AS_RULE_LIST, &qr_mark_as_main_list, NULL, NULL) < 0) {
		LM_ERR("[QR] failed to register DRCB_MARK_AS_QR_RULE_LIST callback to DR\n");
		return -1;
	}

	if(drb.register_drcb(DRCB_REG_LINK_LISTS, &qr_link_rule_list, NULL, NULL) < 0) {
		LM_ERR("[QR] failed to register DRCB_LINK_QR_LISTS callback to DR\n");
		return -1;
	}

	if(drb.register_drcb(DRCB_REG_FREE_LIST, &free_qr_cb, NULL, NULL) < 0) {
		LM_ERR("[QR] failed to register DRCB_REG_FREE_LIST callback to DR\n");
		return -1;
	}

	if(drb.register_drcb(DRCB_REG_CREATE_PARTS_LIST, &qr_create_partition_list,
				NULL, NULL) < 0) {
		LM_ERR("[QR] failed to register DRCB_REG_CREATE_PARTS_LIST callback to DR\n");
		return -1;
	}

	LM_DBG("[QR] callbacks in DR were registered\n");

	qr_profiles = (qr_thresholds_t**) shm_malloc(sizeof(qr_thresholds_t *));

	if(qr_profiles == NULL) {
		LM_ERR("no more shm memory\n");
		return -1;
	}

	*qr_profiles = 0;

	n_qr_profiles = (int*)shm_malloc(sizeof(int));

	if(n_qr_profiles == NULL) {
		LM_ERR("no more shm memory\n");
		return -1;
	}
	*n_qr_profiles = 0;

	return 0;
}

static int qr_child_init(int rank) {
	db_func_t qr_dbf;
	db_con_t *qr_db_hdl = 0;

	if(rank == PROC_TCP_MAIN)
		return 0;

	/* re-connect to the db */
	if(db_bind_mod(&db_url, &qr_dbf)) {
		LM_CRIT("cannot bind to database module! "
				"Did you forget to load a database module ? (%.*s)\n",
				db_url.len, db_url.s);
		return -1;

	}

	if((qr_db_hdl = qr_dbf.init(&db_url)) == 0) {
		LM_ERR("failed to load db url %.*s\n", db_url.len, db_url.s);

	}

	/* do not change the rank of the process loading
	 * the db, because it must match the rank of the
	 * corespoding drouting process to ensure the qr db
	 * is loaded before the dr db */
	if(rank == 1 && qr_load(&qr_dbf, qr_db_hdl) < 0) {
		LM_ERR("failed to load data from db\n");
	}

	return 0;
}

static int qr_exit(void) {
	free_qr_list(*qr_main_list);

	/* free the thresholds */
	*n_qr_profiles = 0;
	shm_free(*qr_profiles);
	shm_free(qr_profiles);
	shm_free(n_qr_profiles);
	qr_profiles = NULL;
	return 0;
}

static void timer_func(void) {
	qr_rule_t *it;
	int i, j;

	if(*n_sampled < *qr_n) {
		++(*n_sampled); /* the number of intervals sampled */
	}



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

/* returns the linked list of rules for a certain partition */
static qr_rule_t *qr_search_partition(str *part_name)
{
	int i;

	for (i = 0; i < (*qr_main_list)->n_parts; i++)
		if (!str_strcmp(part_name, &(*qr_main_list)->part_name[i]))
			return (*qr_main_list)->qr_rules_start[i];

	return NULL;
}

/* searches for a given rule in the QR list */
static qr_rule_t *qr_search_rule(qr_rule_t *list, int r_id)
{
	qr_rule_t *rule_it;

	LM_DBG("searching for rule_id %d\n", r_id);

	for (rule_it = list; rule_it; rule_it = rule_it->next)
		if (rule_it->r_id == r_id)
			return rule_it;

	return NULL;
}

static str * qr_get_dst_name(qr_dst_t * dst) {
	if(dst->type == QR_DST_GW) {
		return drb.get_gw_name(dst->dst.gw->dr_gw);
	} else {
		return drb.get_cr_name(dst->dst.grp.dr_cr);
	}
}

/* searches for a given gw inside a rule */
static qr_dst_t *qr_search_dst(qr_rule_t *rule, str *dst_name)
{
	int i;
	str *cur_dst_name;

	if (!dst_name)
		return NULL;

	for (i = 0; i < rule->n; i++) {
		cur_dst_name = qr_get_dst_name(&rule->dest[i]);
		/* TODO: cur_dst_name != NULL because no dr_api */
		if (!str_strcmp(cur_dst_name, dst_name))
			return &rule->dest[i];
	}

	return NULL;
}

static void qr_gw_attr(mi_item_t *node, qr_gw_t *gw)
{
	mi_item_t *gw_node = NULL;
	str tmp, *p_tmp;

	tmp.s = pkg_malloc(20);
	if (!tmp.s)
		return;

	p_tmp = drb.get_gw_name(gw->dr_gw);
	gw_node = add_mi_object(node, MI_SSTR("Gw"));
	if (!gw_node)
		goto out;

	if (add_mi_string(gw_node, MI_SSTR("GWID"), p_tmp->s, p_tmp->len) != 0)
		goto out;

	tmp.len = sprintf(tmp.s, "%lf", asr(gw));
	if (add_mi_string(gw_node, MI_SSTR("ASR"), tmp.s, tmp.len) != 0)
		goto out;

	memset(tmp.s, 0, 20 * sizeof *tmp.s);
	tmp.len = sprintf(tmp.s, "%lf", ccr(gw));
	if (add_mi_string(gw_node, MI_SSTR("CCR"), tmp.s, tmp.len) != 0)
		goto out;

	memset(tmp.s, 0, 20 * sizeof *tmp.s);
	tmp.len = sprintf(tmp.s, "%lf", pdd(gw));
	if (add_mi_string(gw_node, MI_SSTR("PDD"), tmp.s, tmp.len) != 0)
		goto out;

	memset(tmp.s, 0, 20 * sizeof *tmp.s);
	tmp.len = sprintf(tmp.s, "%lf", ast(gw));
	if (add_mi_string(gw_node, MI_SSTR("AST"), tmp.s, tmp.len) != 0)
		goto out;

	memset(tmp.s, 0, 20 * sizeof *tmp.s);
	tmp.len = sprintf(tmp.s, "%lf", acd(gw));
	if (add_mi_string(gw_node, MI_SSTR("ACD"), tmp.s, tmp.len) != 0)
		goto out;

out:
	pkg_free(tmp.s);
}

static void qr_grp_attr(mi_item_t *node, qr_grp_t * grp, str *group_name)
{
	mi_item_t *grp_node;
	int i;

	grp_node = add_mi_object(node, MI_SSTR("Carrier"));
	if (!grp_node)
		return;

	if (add_mi_string(grp_node, MI_SSTR("CRID"),
	                  group_name->s, group_name->len) != 0)
		return;

	for (i = 0; i < grp->n; i++)
		qr_gw_attr(grp_node, grp->gw[i]);
}

static void qr_dst_attr(mi_item_t *node, qr_dst_t *dst)
{
	if(dst->type == QR_DST_GW) {
		qr_gw_attr(node, dst->dst.gw);
	} else {
		qr_grp_attr(node, &dst->dst.grp, qr_get_dst_name(dst));
	}
}

int qr_fill_mi_partition(mi_item_t *part, const str *part_name,
                         qr_rule_t *rules)
{
	mi_item_t *rule_arr, *mi_rule;
	qr_rule_t *rule;
	int i;

	if (add_mi_string(part, MI_SSTR("Name"), part_name->s, part_name->len) < 0)
		return -1;

	rule_arr = add_mi_array(part, MI_SSTR("Rules"));
	if (!rule_arr)
		return -1;

	for (rule = rules; rule; rule = rule->next) {
		mi_rule = add_mi_object(rule_arr, NULL, 0);
		if (!mi_rule)
			return -1;

		if (add_mi_number(mi_rule, MI_SSTR("Id"), rule->r_id) != 0)
			return -1;

		for (i = 0; i < rule->n; i++)
			qr_dst_attr(mi_rule, &rule->dest[i]);
	}

	return 0;
}

mi_response_t *mi_qr_status_0(const mi_params_t *params,
							struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj, *part_arr, *part;
	int i;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return NULL;
	part_arr = add_mi_array(resp_obj, MI_SSTR("Partitions"));
	if (!part_arr)
		goto error;

	for (i = 0; i < (*qr_main_list)->n_parts; i++) {/* for every partition */
		part = add_mi_object(part_arr, NULL, 0);
		if (!part)
			goto error;

		qr_fill_mi_partition(part, &(*qr_main_list)->part_name[i],
		                     (*qr_main_list)->qr_rules_start[i]);
	}

	return resp;

error:
	free_mi_response(resp);
	return NULL;
}

mi_response_t *mi_qr_status_1(const mi_params_t *params,
							struct mi_handler *async_hdl)
{
	qr_rule_t *qr_part;
	mi_response_t *resp, *err_resp = NULL;
	mi_item_t *resp_obj;
	str part_name;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return NULL;

	if ((*qr_main_list)->n_parts > 1) { /*=> the first parameter should be
										 the partition */
		if (get_mi_string_param(params, "partition_name",
			&part_name.s, &part_name.len) < 0)
			return init_mi_param_error();
		qr_part = qr_search_partition(&part_name);

	} else {
		qr_part = (*qr_main_list)->qr_rules_start[0]; /* use the default
														 partition */
		part_name = (*qr_main_list)->part_name[0];
	}

	if (!qr_part) {
		err_resp = init_mi_error(404, MI_SSTR("Partition Not Found\n"));
		goto error;
	}

	qr_fill_mi_partition(resp_obj, &part_name, qr_part);
	return resp;

error:
	free_mi_response(resp);
	if (!err_resp)
		err_resp = init_mi_error(500, MI_SSTR("Server Internal Error\n"));
	return err_resp;
}

mi_response_t *mi_qr_status_2(const mi_params_t *params,
							struct mi_handler *async_hdl)
{
	qr_rule_t *qr_part, *rule;
	mi_response_t *resp, *err_resp = NULL;
	mi_item_t *resp_obj;
	str part_name;
	unsigned int rule_id, i;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return NULL;

	if ((*qr_main_list)->n_parts > 1) { /*=> the first parameter should be
										 the partition */
		if (get_mi_string_param(params, "partition_name",
			&part_name.s, &part_name.len) != 0)
			return init_mi_param_error();
		qr_part = qr_search_partition(&part_name);

	} else {
		qr_part = (*qr_main_list)->qr_rules_start[0]; /* use the default
														 partition */
		part_name = (*qr_main_list)->part_name[0];
	}

	if (!qr_part) {
		err_resp = init_mi_error(404, MI_SSTR("Partition Not Found\n"));
		goto error;
	}

	if (get_mi_int_param(params, "rule_id", (int *)&rule_id) != 0)
		return init_mi_param_error();

	rule = qr_search_rule(qr_part, rule_id);
	if (!rule) {
		err_resp = init_mi_error(404, MI_SSTR("Rule Not Found\n"));
		goto error;
	}

	for (i = 0; i < rule->n; i++)
		qr_dst_attr(resp_obj, &rule->dest[i]);

	return resp;

error:
	free_mi_response(resp);
	if (!err_resp)
		err_resp = init_mi_error(500, MI_SSTR("Server Internal Error\n"));
	return err_resp;
}

mi_response_t *mi_qr_status_3(const mi_params_t *params,
							struct mi_handler *async_hdl)
{
	qr_rule_t *qr_part, *rule;
	qr_dst_t *dst;
	mi_response_t *resp, *err_resp = NULL;
	mi_item_t *resp_obj;
	str part_name, gw_name;
	unsigned int rule_id;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return NULL;

	if ((*qr_main_list)->n_parts > 1) { /*=> the first parameter should be
										 the partition */
		if (get_mi_string_param(params, "partition_name",
			&part_name.s, &part_name.len) != 0)
			return init_mi_param_error();
		qr_part = qr_search_partition(&part_name);

	} else {
		qr_part = (*qr_main_list)->qr_rules_start[0]; /* use the default
														 partition */
		part_name = (*qr_main_list)->part_name[0];
	}

	if (!qr_part) {
		err_resp = init_mi_error(404, MI_SSTR("Partition Not Found\n"));
		goto error;
	}

	if (get_mi_int_param(params, "rule_id", (int *)&rule_id) != 0)
		return init_mi_param_error();

	rule = qr_search_rule(qr_part, rule_id);
	if (!rule) {
		err_resp = init_mi_error(404, MI_SSTR("Rule Not Found\n"));
		goto error;
	}

	if (get_mi_string_param(params, "dst_id", &gw_name.s, &gw_name.len) != 0)
		return init_mi_param_error();

	dst = qr_search_dst(rule, &gw_name);
	if (!dst) {
		err_resp = init_mi_error(404, MI_SSTR("GW/Carrier Not Found\n"));
		goto error;
	}

	qr_dst_attr(resp_obj, dst);
	return resp;

error:
	free_mi_response(resp);
	if (!err_resp)
		err_resp = init_mi_error(500, MI_SSTR("Server Internal Error\n"));
	return err_resp;
}
