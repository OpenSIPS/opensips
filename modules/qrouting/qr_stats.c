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

#include "../../str.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"

#include "../drouting/dr_cb.h"

#include "qrouting.h"
#include "qr_stats.h"
#include "qr_acc.h"

/* temporary list of 1+ reloaded partitions, during dr_reload */
static qr_partitions_t *qr_rld_list;

/* create the samples for a gateway's history */
qr_sample_t *create_history(void)
{
	qr_sample_t *history, *tmp;
	int i;

	history = shm_malloc(sizeof *history);
	if (!history) {
		LM_ERR("oom\n");
		return NULL;
	}
	memset(history, 0, sizeof *history);

	for (tmp = history, i=0; i < qr_interval_list_sz-1; tmp = tmp->next, ++i) {
		tmp->next = shm_malloc(sizeof *tmp->next);
		if (!tmp->next)
			goto error;
		memset(tmp->next, 0, sizeof *tmp->next);
	}

	tmp->next = history;
	return history;
error:
	shm_free_all(history);
	return NULL;
}

qr_gw_t *qr_create_gw(void *dst)
{
	qr_gw_t *gw; /* internal gw for qr */
	str *gw_name;
	gw_name = drb.get_gw_name(dst);

	LM_DBG("creating gw '%.*s'\n", gw_name->len, gw_name->s);

	if (!(gw = shm_malloc(sizeof *gw))) {
		LM_ERR("oom\n");
		goto error;
	}
	memset(gw, 0, sizeof *gw);

	gw->acc_lock = lock_alloc();
	if (!lock_init(gw->acc_lock)) {
		LM_ERR("failed to init lock\n");
		goto error;
	}
	if (!(gw->ref_lock = lock_init_rw())) {
		LM_ERR("failed to init RW lock\n");
		goto error;
	}

	if (!(gw->lru_interval = create_history())) {
		LM_ERR("failed to create history\n");
		goto error;
	}

	gw->dr_gw = dst; /* save the pointer to the dr gateway */
	return gw;
error:
	if (gw)
		qr_free_gw(gw);
	return NULL;
}

/* free gateway information */
void qr_free_gw(qr_gw_t * gw)
{
	shm_free_all(gw->lru_interval);

	if (gw->acc_lock) {
		lock_destroy(gw->acc_lock);
		lock_dealloc(gw->acc_lock);
	}

	if (gw->ref_lock)
		lock_destroy_rw(gw->ref_lock);

	shm_free(gw);
}

void qr_free_grp(qr_grp_t *grp)
{
	int i;

	for (i = 0; i < grp->n; i++)
		qr_free_gw(grp->gw[i]);

	shm_free(grp->gw);

	if (grp->ref_lock)
		lock_destroy_rw(grp->ref_lock);
}

void qr_free_dst(qr_dst_t *dst)
{
	if (dst->type & QR_DST_GW)
		qr_free_gw(dst->gw);
	else
		qr_free_grp(&dst->grp);
}

void qr_free_rule(qr_rule_t *rule)
{
	int i;

	for (i = 0; i < rule->n; i++)
		qr_free_dst(&rule->dest[i]);

	shm_free(rule->dest);
	shm_free(rule);
}

void qr_free_rules(qr_rule_t *rules)
{
	qr_rule_t *aux;

	while (rules) {
		aux = rules;
		rules = rules->next;
		qr_free_rule(aux);
	}
}

void free_qr_list(qr_partitions_t *qr_parts)
{
	int i;

	if (!qr_parts)
		return;

	for (i = 0; i < qr_parts->n_parts; i++)
		qr_free_rules(qr_parts->qr_rules_start[i]);

	if (qr_parts->rw_lock)
		lock_destroy_rw(qr_parts->rw_lock);

	shm_free(qr_parts->qr_rules_start);
	shm_free(qr_parts->part_name);
	shm_free(qr_parts);
}

/* returns the linked list of rules for a certain partition */
qr_rule_t *qr_get_rules(str *part_name)
{
	int i;

	if (!*qr_main_list)
		return NULL;

	for (i = 0; i < (*qr_main_list)->n_parts; i++)
		if (str_match(part_name, &(*qr_main_list)->part_name[i]))
			return (*qr_main_list)->qr_rules_start[i];

	return NULL;
}

/* searches for a given rule in the QR list */
qr_rule_t *qr_search_rule(qr_rule_t *rules, int r_id)
{
	qr_rule_t *rule;

	LM_DBG("searching for rule_id %d\n", r_id);

	for (rule = rules; rule; rule = rule->next)
		if (rule->r_id == r_id)
			return rule;

	return NULL;
}

qr_gw_t *qr_search_gw(qr_rule_t *rule, str *gw_name)
{
	int i, j;
	str *name;
	qr_dst_t *dst;

	for (i = 0; i < rule->n; i++) {
		dst = &rule->dest[i];

		if (dst->type == QR_DST_GW) {
			name = drb.get_gw_name(dst->gw->dr_gw);
			if (str_match(name, gw_name))
				return dst->gw;
		} else {
			for (j = 0; j < dst->grp.n; j++) {
				name = drb.get_gw_name(dst->grp.gw[j]->dr_gw);
				if (str_match(name, gw_name))
					return dst->grp.gw[j];
			}
		}
	}

	return NULL;
}

int qr_set_profile(qr_rule_t *rule, unsigned int prof_id)
{
	unsigned int current_id;
	int m, left, right;

	left = 0;
	right = *qr_profiles_n - 1;

	lock_start_read(qr_profiles_rwl);

	while (left<=right) {
		m = left + (right-left)/2;
		current_id = ((*qr_profiles)[m]).id;
		if(current_id == prof_id) {
			rule->profile = &(*qr_profiles)[m];
			lock_stop_read(qr_profiles_rwl);
			LM_DBG("found profile %d\n", prof_id);
			return 0;
		} else if(current_id > prof_id) {
			right = m-1;
		} else {
			left = m+1;
		}
	}

	lock_stop_read(qr_profiles_rwl);

	LM_WARN("profile '%d' not found\n", prof_id);
	return -1;
}

/* creates a rule n_dest destinations (by default marked as gws) */
void qr_rld_create_rule(void *param)
{
	qr_rule_t *new;
	int r_id;
	struct dr_reg_init_rule_params *irp =
		(struct dr_reg_init_rule_params *)param;

	r_id = irp->r_id;

	if (!(new = shm_malloc(sizeof *new))) {
		LM_ERR("oom\n");
		return;
	}
	memset(new, 0, sizeof *new);

	/* prepare an array for adding gateways */
	if (!(new->dest = shm_malloc(irp->n_dst * sizeof *new->dest))) {
		LM_ERR("oom\n");
		shm_free(new);
		return;
	}

	new->n = irp->n_dst; /* save the number of destinations for
										 this rule, as rcvd from dr*/
	new->r_id = r_id;
	irp->rule = new; /* send the rule to the dr */

	if (qr_set_profile(new, irp->qr_profile) != 0)
		LM_ERR("failed to set profile %d for rule %d\n",
		       irp->qr_profile, r_id);

	LM_DBG("rule %d created\n", r_id);
}

/* make gateway a given destination - to be registered as callback */
void qr_rld_dst_is_gw(void *param)
{
	void *dst; /* pgw_t received from dr */
	qr_rule_t *rule; /* qr_rule that was initialised with the qr callback from dr */
	int   n_dst; /* the number of the destination within the dr rule */
	struct dr_reg_param *drp = (struct dr_reg_param *)param;

	/* extract the parameters from dr */
	rule = drp->rule;
	dst = drp->cr_or_gw;
	n_dst = drp->n_dst;

	LM_DBG("adding gw to rule %d\n", rule->r_id);

	if(rule != NULL) {
		rule->dest[n_dst].type = QR_DST_GW;
		rule->dest[n_dst].gw = qr_create_gw(dst);
	} else {
		LM_ERR("no rule to add the gateway to\n");
	}
}

/* marks index_grp destination from the rule as group and creates the gw array */
void qr_rld_dst_is_grp(void *param)
{
	struct dr_reg_param *drp = (struct dr_reg_param *)param;
	qr_rule_t *rule = drp->rule;
	int i, n_dst = drp->n_dst;
	void *dr_gw, *grp = drp->cr_or_gw;
	int n_gws = drb.get_cr_n_gw(grp);
	str *gw_name, *cr_name = drb.get_cr_name(grp);

	if (!rule) {
		LM_ERR("null rule\n");
		return;
	}

	LM_DBG("carrier '%.*s' with %d gateways added to rule %d\n",
	       cr_name->len, cr_name->s, n_gws, rule->r_id);

	rule->dest[n_dst].type = QR_DST_GRP;
	memset(&rule->dest[n_dst].grp, 0, sizeof (qr_grp_t));
	rule->dest[n_dst].grp.state |= QR_STATUS_DIRTY;

	rule->dest[n_dst].grp.gw = shm_malloc(n_gws * sizeof (qr_gw_t *));
	if (!rule->dest[n_dst].grp.gw) {
		LM_ERR("oom\n");
		goto error;
	}

	if (!(rule->dest[n_dst].grp.ref_lock = lock_init_rw())) {
		LM_ERR("failed to init RW lock\n");
		goto error;
	}

	rule->dest[n_dst].grp.n = n_gws;
	rule->dest[n_dst].grp.dr_cr = grp;

	for (i = 0; i < n_gws; i++) {
		dr_gw = (void*)drb.get_gw_from_cr(grp, i); /* get the gateway
													  as pgw_t from dr */
		rule->dest[n_dst].grp.gw[i] = qr_create_gw(dr_gw);
		gw_name = drb.get_gw_name(rule->dest[n_dst].grp.gw[i]->dr_gw);
		LM_DBG("gw '%.*s' added to carrier '%.*s' from rule %d\n",
				gw_name->len, gw_name->s, cr_name->len, cr_name->s,
				rule->r_id);
	}

	return;
error:
	if (rule->dest[n_dst].grp.gw)
		shm_free(rule->dest[n_dst].grp.gw);
}

/* link a rule into the current partition */
void qr_rld_link_rule(void *param)
{
	struct dr_link_rule_params *lrp = (struct dr_link_rule_params *)param;
	qr_rule_t *new = lrp->qr_rule;
	qr_rule_t **rule_list =
		&qr_rld_list->qr_rules_start[qr_rld_list->n_parts - 1];
	str *part_name = &qr_rld_list->part_name[qr_rld_list->n_parts - 1];

	if (!new)
		return;

	new->part_name = part_name;

	if (!*rule_list) {
		*rule_list = new;
	} else {
		new->next = *rule_list;
		*rule_list = new;
	}

	LM_DBG("rule '%d' added to qr rule list for partition '%.*s' \n",
			new->r_id, part_name->len, part_name->s);
}

void qr_rld_prepare_part(void *param)
{
	struct dr_prepare_part_params *pp = (struct dr_prepare_part_params *)param;
	qr_partitions_t *pl;

	if (!qr_rld_list) {
		pl = shm_malloc(sizeof *pl);
		if (!pl) {
			LM_ERR("oom\n");
			return;
		}
		memset(pl, 0, sizeof *pl);

		if (!(pl->rw_lock = lock_init_rw())) {
			LM_ERR("failed to init rw lock\n");
			goto error;
		}

		qr_rld_list = pl;
	} else {
		pl = qr_rld_list;
	}

	pl->n_parts++;

	pl->qr_rules_start = shm_realloc(pl->qr_rules_start,
	                                 pl->n_parts * sizeof (qr_rule_t *));
	if (!pl->qr_rules_start) {
		LM_ERR("oom\n");
		goto error;
	}
	pl->qr_rules_start[pl->n_parts - 1] = NULL;

	pl->part_name = shm_realloc(pl->part_name,
	                            pl->n_parts * sizeof (str));
	if (!pl->part_name) {
		LM_ERR("oom\n");
		goto error;
	}
	pl->part_name[pl->n_parts - 1] = pp->part_name;

	LM_DBG("new partition (%.*s) ready for reload\n",
	       pp->part_name.len, pp->part_name.s);
	return;

error:
	if (pl->rw_lock)
		lock_destroy_rw(pl->rw_lock);

	if (pl->qr_rules_start)
		shm_free(pl->qr_rules_start);

	shm_free(pl);
	qr_rld_list = NULL;
}

void qr_rld_finalize(void *param)
{
	qr_partitions_t *old_list;
	str part_name;
	qr_rule_t *old_rules = NULL;
	int i;

	LM_DBG("finalizing reload, qr_main_list: %p\n", *qr_main_list);

	/* may happen if we ran OOM while preparing a new part */
	if (!qr_rld_list)
		return;

	part_name = qr_rld_list->part_name[0];

	/* save old list so it can be freed */
	old_list = *qr_main_list;

	lock_start_write(qr_main_list_rwl);
	if (!old_list || qr_rld_list->n_parts == (*qr_main_list)->n_parts) {
		*qr_main_list = qr_rld_list;
	} else {
		for (i = 0; i < (*qr_main_list)->n_parts; i++) {
			if (str_match(&part_name, &(*qr_main_list)->part_name[i])) {
				old_rules = (*qr_main_list)->qr_rules_start[i];
				(*qr_main_list)->qr_rules_start[i] = *qr_rld_list->qr_rules_start;
				*qr_rld_list->qr_rules_start = old_rules;
				old_list = qr_rld_list;
				break;
			}
		}
	}

	lock_stop_write(qr_main_list_rwl);

	LM_DBG("new qr_main_list: %p\n", *qr_main_list);

	free_qr_list(old_list);
	qr_rld_list = NULL;
}
