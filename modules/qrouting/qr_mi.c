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

static inline str *qr_get_dst_name(qr_dst_t *dst)
{
	if (dst->type == QR_DST_GW)
		return drb.get_gw_name(dst->gw->dr_gw);
	else
		return drb.get_cr_name(dst->grp.dr_cr);
}

/* searches for a given gw inside a rule */
static qr_dst_t *qr_search_dst(qr_rule_t *rule, str *dst_name)
{
	int i;

	if (!dst_name)
		return NULL;

	for (i = 0; i < rule->n; i++)
		if (str_match(qr_get_dst_name(&rule->dest[i]), dst_name))
			return &rule->dest[i];

	return NULL;
}

static void qr_gw_attr(mi_item_t *gw_node, qr_gw_t *gw)
{
	int i, samples, buf_sz = QR_MAX_STAT_NAME_LEN + 1 + INT2STR_MAX_LEN + 1;
	str tmp, *p_tmp;
	double val;

	tmp.s = pkg_malloc(buf_sz);
	if (!tmp.s)
		return;

	p_tmp = drb.get_gw_name(gw->dr_gw);

	if (add_mi_string(gw_node, MI_SSTR("GWID"), p_tmp->s, p_tmp->len) != 0)
		goto out;

	val = asr(gw, &samples);
	tmp.len = sprintf(tmp.s, "%0.*lf/%d", qr_decimal_digits, val, samples);
	if (add_mi_string(gw_node, MI_SSTR("ASR"), tmp.s, tmp.len) != 0)
		goto out;

	val = ccr(gw, &samples);
	tmp.len = sprintf(tmp.s, "%0.*lf/%d", qr_decimal_digits, val, samples);
	if (add_mi_string(gw_node, MI_SSTR("CCR"), tmp.s, tmp.len) != 0)
		goto out;

	val = pdd(gw, &samples);
	tmp.len = sprintf(tmp.s, "%0.*lf/%d", qr_decimal_digits, val, samples);
	if (add_mi_string(gw_node, MI_SSTR("PDD"), tmp.s, tmp.len) != 0)
		goto out;

	val = ast(gw, &samples);
	tmp.len = sprintf(tmp.s, "%0.*lf/%d", qr_decimal_digits, val, samples);
	if (add_mi_string(gw_node, MI_SSTR("AST"), tmp.s, tmp.len) != 0)
		goto out;

	val = acd(gw, &samples);
	tmp.len = sprintf(tmp.s, "%0.*lf/%d", qr_decimal_digits, val, samples);
	if (add_mi_string(gw_node, MI_SSTR("ACD"), tmp.s, tmp.len) != 0)
		goto out;

	for (i = 0; i < qr_xstats_n; i++) {
		val = get_xstat(gw, i, &samples);
		tmp.len = sprintf(tmp.s, "%0.*lf/%d", qr_decimal_digits, val, samples);
		if (add_mi_string(gw_node, qr_xstats[i].name.s, qr_xstats[i].name.len,
		                  tmp.s, tmp.len) != 0)
			goto out;
	}

out:
	pkg_free(tmp.s);
}

static void qr_grp_attr(mi_item_t *node, qr_grp_t * grp, str *group_name)
{
	mi_item_t *grp_node, *gw_arr, *gw;
	int i;

	grp_node = add_mi_object(node, MI_SSTR("Carrier"));
	if (!grp_node)
		return;

	if (add_mi_string(grp_node, MI_SSTR("CRID"),
	                  group_name->s, group_name->len) != 0)
		return;

	gw_arr = add_mi_array(grp_node, MI_SSTR("Gateways"));
	if (!gw_arr)
		return;

	for (i = 0; i < grp->n; i++) {
		gw = add_mi_object(gw_arr, NULL, 0);
		qr_gw_attr(gw, grp->gw[i]);
	}
}

static void qr_dst_attr(mi_item_t *node, qr_dst_t *dst)
{
	mi_item_t *gw;

	if (dst->type == QR_DST_GW) {
		gw = add_mi_object(node, MI_SSTR("Gateway"));
		qr_gw_attr(gw, dst->gw);
	} else {
		qr_grp_attr(node, &dst->grp, qr_get_dst_name(dst));
	}
}

int qr_fill_mi_partition(mi_item_t *part, const str *part_name,
                         qr_rule_t *rules)
{
	mi_item_t *rule_arr, *mi_rule, *dst_arr, *dst;
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

		dst_arr = add_mi_array(mi_rule, MI_SSTR("Destinations"));
		if (!dst_arr)
			return -1;

		for (i = 0; i < rule->n; i++) {
			dst = add_mi_object(dst_arr, NULL, 0);
			if (!dst)
				return -1;

			qr_dst_attr(dst, &rule->dest[i]);
		}
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

	lock_start_read(qr_main_list_rwl);

	for (i = 0; i < (*qr_main_list)->n_parts; i++) {/* for every partition */
		part = add_mi_object(part_arr, NULL, 0);
		if (!part) {
			lock_stop_read(qr_main_list_rwl);
			goto error;
		}

		qr_fill_mi_partition(part, &(*qr_main_list)->part_name[i],
		                     (*qr_main_list)->qr_rules_start[i]);
	}

	lock_stop_read(qr_main_list_rwl);
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

	lock_start_read(qr_main_list_rwl);

	if ((*qr_main_list)->n_parts > 1) { /*=> the first parameter should be
										 the partition */
		if (get_mi_string_param(params, qr_param_part.s,
			&part_name.s, &part_name.len) < 0) {
			lock_stop_read(qr_main_list_rwl);
			return init_mi_param_error();
		}
		qr_part = qr_get_rules(&part_name);

	} else {
		qr_part = (*qr_main_list)->qr_rules_start[0]; /* use the default
														 partition */
		part_name = (*qr_main_list)->part_name[0];
	}

	if (!qr_part) {
		err_resp = init_mi_error(404, MI_SSTR("Partition Not Found"));
		goto error;
	}

	qr_fill_mi_partition(resp_obj, &part_name, qr_part);
	lock_stop_read(qr_main_list_rwl);

	return resp;

error:
	lock_stop_read(qr_main_list_rwl);

	free_mi_response(resp);
	if (!err_resp)
		err_resp = init_mi_error(500, MI_SSTR("Server Internal Error"));
	return err_resp;
}

mi_response_t *mi_qr_status_2(const mi_params_t *params, struct mi_handler *_)
{
	qr_rule_t *qr_part, *rule;
	mi_response_t *resp, *err_resp = NULL;
	mi_item_t *resp_obj, *dst_arr, *dst;
	str part_name;
	unsigned int rule_id, i;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return NULL;

	lock_start_read(qr_main_list_rwl);

	if ((*qr_main_list)->n_parts > 1) { /*=> the first parameter should be
										 the partition */
		if (get_mi_string_param(params, qr_param_part.s,
			&part_name.s, &part_name.len) != 0) {
			lock_stop_read(qr_main_list_rwl);
			return init_mi_param_error();
		}
		qr_part = qr_get_rules(&part_name);

	} else {
		qr_part = (*qr_main_list)->qr_rules_start[0]; /* use the default
														 partition */
		part_name = (*qr_main_list)->part_name[0];
	}

	if (!qr_part) {
		err_resp = init_mi_error(404, MI_SSTR("Partition Not Found"));
		goto error;
	}

	if (get_mi_int_param(params, qr_param_rule_id.s, (int *)&rule_id) != 0) {
		lock_stop_read(qr_main_list_rwl);
		return init_mi_param_error();
	}

	rule = qr_search_rule(qr_part, rule_id);
	if (!rule) {
		err_resp = init_mi_error(404, MI_SSTR("Rule Not Found"));
		goto error;
	}

	dst_arr = add_mi_array(resp_obj, MI_SSTR("Destinations"));
	if (!dst_arr)
		goto error;

	for (i = 0; i < rule->n; i++) {
		dst = add_mi_object(dst_arr, NULL, 0);
		if (!dst)
			goto error;

		qr_dst_attr(dst, &rule->dest[i]);
	}

	lock_stop_read(qr_main_list_rwl);

	return resp;

error:
	lock_stop_read(qr_main_list_rwl);

	free_mi_response(resp);
	if (!err_resp)
		err_resp = init_mi_error(500, MI_SSTR("Server Internal Error"));
	return err_resp;
}

mi_response_t *mi_qr_status_3(const mi_params_t *params, struct mi_handler *_)
{
	qr_rule_t *qr_part, *rule;
	qr_dst_t *dst;
	mi_response_t *resp, *err_resp = NULL;
	mi_item_t *resp_obj;
	str part_name, dst_name;
	int rule_id;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return NULL;

	lock_start_read(qr_main_list_rwl);

	if ((*qr_main_list)->n_parts > 1) { /*=> the first parameter should be
										 the partition */
		if (get_mi_string_param(params, qr_param_part.s,
			&part_name.s, &part_name.len) != 0) {
			lock_stop_read(qr_main_list_rwl);
			return init_mi_param_error();
		}
		qr_part = qr_get_rules(&part_name);

	} else {
		qr_part = (*qr_main_list)->qr_rules_start[0]; /* use the default
														 partition */
		part_name = (*qr_main_list)->part_name[0];
	}

	if (!qr_part) {
		err_resp = init_mi_error(404, MI_SSTR("Partition Not Found"));
		goto error;
	}

	if (get_mi_int_param(params, qr_param_rule_id.s, &rule_id) != 0) {
		lock_stop_read(qr_main_list_rwl);
		return init_mi_param_error();
	}

	rule = qr_search_rule(qr_part, rule_id);
	if (!rule) {
		err_resp = init_mi_error(404, MI_SSTR("Rule Not Found"));
		goto error;
	}

	if (get_mi_string_param(params, qr_param_dst_name.s,
	                        &dst_name.s, &dst_name.len) != 0) {
		lock_stop_read(qr_main_list_rwl);
		return init_mi_param_error();
	}

	dst = qr_search_dst(rule, &dst_name);
	if (!dst) {
		err_resp = init_mi_error(404, MI_SSTR("GW/Carrier Not Found"));
		goto error;
	}

	qr_dst_attr(resp_obj, dst);
	lock_stop_read(qr_main_list_rwl);

	return resp;

error:
	lock_stop_read(qr_main_list_rwl);

	free_mi_response(resp);
	if (!err_resp)
		err_resp = init_mi_error(500, MI_SSTR("Server Internal Error"));
	return err_resp;
}

mi_response_t *mi_qr_reload_0(const mi_params_t *_, struct mi_handler *__)
{
	if (qr_reload(&qr_dbf, qr_db_hdl) < 0)
		LM_ERR("failed to load data from db\n");

	return init_mi_result_ok();
}

int qr_set_dst_state(qr_rule_t *rules, int rule_id, str *dst_name,
                     int active, mi_response_t **err_resp)
{
	qr_rule_t *rule;
	qr_dst_t *dst;

	rule = qr_search_rule(rules, rule_id);
	if (!rule) {
		if (err_resp)
			*err_resp = init_mi_error(404, MI_SSTR("Rule Not Found"));
		return -1;
	}

	dst = qr_search_dst(rule, dst_name);
	if (!dst) {
		if (err_resp)
			*err_resp = init_mi_error(404, MI_SSTR("GW/Carrier Not Found"));
		return -1;
	}

	lock_start_write(dst->gw->ref_lock);

	if (dst->type == QR_DST_GW)
		if (active) {
			dst->gw->state &= ~QR_STATUS_DSBL;
		} else {
			dst->gw->state |= QR_STATUS_DSBL;
		}
	else
		if (active) {
			dst->grp.state &= ~QR_STATUS_DSBL;
		} else {
			dst->grp.state |= QR_STATUS_DSBL;
		}

	lock_stop_write(dst->gw->ref_lock);

	return 0;
}

static mi_response_t *mi_qr_set_dst_state_2(const mi_params_t *params, int active)
{
	int rule_id, rc;
	str dst_name;
	mi_response_t *err_resp = NULL;

	if (get_mi_int_param(params, qr_param_rule_id.s, &rule_id) != 0)
		return init_mi_param_error();

	if (get_mi_string_param(params, qr_param_dst_name.s,
	                        &dst_name.s, &dst_name.len) != 0)
		return init_mi_param_error();

	lock_start_read(qr_main_list_rwl);
	rc = qr_set_dst_state((*qr_main_list)->qr_rules_start[0], rule_id, &dst_name,
	                      active, &err_resp);
	lock_stop_read(qr_main_list_rwl);

	if (rc != 0)
		return err_resp;

	return init_mi_result_ok();
}

mi_response_t *mi_qr_enable_dst_2(const mi_params_t *params, struct mi_handler *_)
{
	return mi_qr_set_dst_state_2(params, 1);
}

mi_response_t *mi_qr_disable_dst_2(const mi_params_t *params, struct mi_handler *_)
{
	return mi_qr_set_dst_state_2(params, 0);
}

static mi_response_t *mi_qr_set_dst_state_3(const mi_params_t *params, int active)
{
	qr_rule_t *rules;
	mi_response_t *err_resp = NULL;
	int rule_id, rc;
	str part_name, dst_name;

	if (get_mi_string_param(params, qr_param_part.s,
	        &part_name.s, &part_name.len))
		return init_mi_param_error();

	if (get_mi_int_param(params, qr_param_rule_id.s, &rule_id) != 0)
		return init_mi_param_error();

	if (get_mi_string_param(params, qr_param_dst_name.s,
	                        &dst_name.s, &dst_name.len) != 0)
		return init_mi_param_error();

	lock_start_read(qr_main_list_rwl);

	rules = qr_get_rules(&part_name);
	if (!rules) {
		LM_DBG("partition not found: %.*s\n", part_name.len, part_name.s);
		lock_stop_read(qr_main_list_rwl);
		return init_mi_error(404, MI_SSTR("Partition Not Found"));
	}

	rc = qr_set_dst_state(rules, rule_id, &dst_name, active, &err_resp);
	lock_stop_read(qr_main_list_rwl);

	if (rc != 0)
		return err_resp;

	return init_mi_result_ok();
}

mi_response_t *mi_qr_enable_dst_3(const mi_params_t *params, struct mi_handler *_)
{
	return mi_qr_set_dst_state_3(params, 1);
}

mi_response_t *mi_qr_disable_dst_3(const mi_params_t *params, struct mi_handler *_)
{
	return mi_qr_set_dst_state_3(params, 0);
}
