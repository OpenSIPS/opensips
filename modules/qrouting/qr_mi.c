/*
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

#include "qr_stats.h"
#include "qr_acc.h"
#include "qr_sort.h"

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

mi_response_t *mi_qr_status_0(const mi_params_t *_, struct mi_handler *__)
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

mi_response_t *mi_qr_status_1(const mi_params_t *params, struct mi_handler *_)
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

mi_response_t *mi_qr_status_2(const mi_params_t *params, struct mi_handler *_)
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

mi_response_t *mi_qr_status_3(const mi_params_t *params, struct mi_handler *_)
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

mi_response_t *mi_qr_reload_0(const mi_params_t *_, struct mi_handler *__)
{
	if (qr_reload(&qr_dbf, qr_db_hdl) < 0)
		LM_ERR("failed to load data from db\n");

	return init_mi_result_ok();
}
