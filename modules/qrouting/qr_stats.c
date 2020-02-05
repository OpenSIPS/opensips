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

#include "../../str.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"

#include "../drouting/dr_cb.h"

#include "qr_stats.h"
#include "qr_acc.h"


qr_rule_t **qr_rules_start;


/* create the samples for a gateway's history */
qr_sample_t * create_history(void) {
	qr_sample_t * history, *tmp;
	int i;

	history = (qr_sample_t*)shm_malloc(sizeof(qr_sample_t));
	if(history == NULL) {
		LM_ERR("no more shm_memory\n");
		return NULL;
	}
	for(tmp = history, i = 0; i < qr_n-1; tmp = tmp->next, ++i) {
		tmp->next = (qr_sample_t*)shm_malloc(sizeof(qr_sample_t));
		if(tmp->next == NULL)
			return NULL;
	}
	tmp->next = history;
	return history;
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

	if (!(gw->next_interval = create_history())) {
		LM_ERR("failed to create history\n");
		goto error;
	}

	gw->dr_gw = dst; /* save the pointer to the dr gateway */

	/* save gateway to rule */
	//rule->dest[n_dst].type = QR_DST_GW;
	//rule->dest[n_dst].dst.gw = gw;
	return gw;
error:
	if (gw)
		qr_free_gw(gw);
	return NULL;
}

/* make gateway a given destination - to be registered as callback */
void qr_dst_is_gw(void *param)
{
	void *dst; /* pgw_t received from dr */
	qr_rule_t *rule; /* qr_rule that was initialised with the qr callback from dr */
	int   n_dst; /* the number of the destination within the dr rule */
	struct dr_cb_params *cbp = (struct dr_cb_params *)param;

	/* extract the parameters from dr */
	rule = (qr_rule_t*)((struct dr_reg_param *)*cbp->param)->rule;
	dst = ((struct dr_reg_param *)*cbp->param)->cr_or_gw;
	n_dst = ((struct dr_reg_param *)*cbp->param)->n_dst;
	LM_DBG("Adding gw to rule %d\n", rule->r_id);

	if(rule != NULL) {
		rule->dest[n_dst].type = QR_DST_GW;
		rule->dest[n_dst].dst.gw = qr_create_gw(dst);
	} else {
		LM_ERR("no rule to add the gateway to\n");
	}
}

/* free gateway information */
void qr_free_gw(qr_gw_t * gw)
{
	shm_free_all(gw->next_interval);

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
		qr_free_gw(dst->dst.gw);
	else
		qr_free_grp(&dst->dst.grp);
}

void qr_free_rule(qr_rule_t *rule)
{
	int i;

	for (i = 0; i < rule->n; i++)
		qr_free_dst(&rule->dest[i]);

	shm_free(rule->dest);
	shm_free(rule);
}

void free_qr_list(qr_partitions_t *qr_parts)
{
	qr_rule_t *rule_it, *next;
	int i;

	if (!qr_parts)
		return;

	for (i = 0; i < qr_parts->n_parts; i++) {
		rule_it = qr_parts->qr_rules_start[i];
		while (rule_it) {
			next = rule_it->next;
			qr_free_rule(rule_it);
			rule_it = next;
		}
	}

	if (qr_parts->rw_lock)
		lock_destroy_rw(qr_parts->rw_lock);

	shm_free(qr_parts->qr_rules_start);
	shm_free(qr_parts);
}

void free_qr_cb(void *param)
{
	struct dr_cb_params *cbp = (struct dr_cb_params *)param;
	struct dr_free_qr_list_params * free_params = (struct dr_free_qr_list_params *)
		*cbp->param;
	LM_DBG("freeing the old rules...\n");

	qr_partitions_t * old_list = free_params->old_list;
	free_qr_list(old_list);
}

int qr_set_profile(qr_rule_t *rule, unsigned int qrp)
{
	unsigned int current_id;
	int m, left, right;

	left = 0;
	right = *n_qr_profiles - 1;
	while (left<=right) {
		m = left + (right-left)/2;
		current_id = ((*qr_profiles)[m]).id;
		if(current_id == qrp) {
			rule->thresholds = &(*qr_profiles)[m];
			return 0;
		} else if(current_id > qrp) {
			right = m-1;
		} else {
			left = m+1;
		}
	}

	if (left > right)
		LM_WARN("profile '%d' not found\n", qrp);

	return -1;
}

/* TODO: thresholds must be freed separatley */

/* creates a rule n_dest destinations (by default marked as gws) */
void qr_create_rule(void *param)
{
	qr_rule_t *new;
	int r_id;
	struct dr_cb_params *cbp = (struct dr_cb_params *)param;
	struct dr_reg_init_rule_params *irp =
		(struct dr_reg_init_rule_params *)*cbp->param;

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

/* marks index_grp destination from the rule as group and creates the gw array */
void qr_dst_is_grp(void *param)
{
	struct dr_cb_params *cbp = (struct dr_cb_params *)param;
	qr_rule_t *rule = (qr_rule_t*)((struct dr_reg_param *)*cbp->param)
		->rule;
	void * dr_gw;
	str *cr_name, *gw_name;
	int i;
	int n_dst = ((struct dr_reg_param*)*cbp->param)->n_dst;
	int n_gws ;
	void *grp = ((struct dr_reg_param*)*cbp->param)->cr_or_gw;
	n_gws = drb.get_cr_n_gw(grp);
	cr_name = drb.get_cr_name(grp);
	LM_DBG("Carrier '%.*s' with  %d gateways added to rule %d\n", cr_name->len,
			cr_name->s, n_gws, rule->r_id);


	if(rule != NULL) {
		rule->dest[n_dst].type = QR_DST_GRP;
		memset(&rule->dest[n_dst].dst.grp, 0, sizeof(qr_grp_t));
		rule->dest[n_dst].dst.grp.state |= QR_STATUS_DIRTY;
		rule->dest[n_dst].dst.grp.gw = (qr_gw_t**)shm_malloc(n_gws *
				sizeof(qr_gw_t*));
		if(rule->dest[n_dst].dst.grp.gw == NULL) {
			LM_ERR("no more shm memory\n");
			goto error;
		}
		if ((rule->dest[n_dst].dst.grp.ref_lock = lock_init_rw()) == NULL) {
			LM_ERR("failed to init RW lock\n");
			goto error;
		}

		rule->dest[n_dst].dst.grp.n = n_gws;
		rule->dest[n_dst].dst.grp.dr_cr = grp;
		for(i = 0; i < n_gws; i++) {
			dr_gw = (void*)drb.get_gw_from_cr(grp, i); /* get the gateway
														  as pgw_t from dr */
			rule->dest[n_dst].dst.grp.gw[i] = qr_create_gw(dr_gw);
			gw_name = drb.get_gw_name(rule->dest[n_dst].dst.grp.gw[i]->dr_gw);
			LM_DBG("Gw '%.*s' added to carrier '%.*s' from rule %d\n",
					gw_name->len, gw_name->s, cr_name->len, cr_name->s,
					rule->r_id);
		}
	} else {
		LM_ERR("bad rule\n");
	}
	return ;
error:
	if(rule->dest[n_dst].dst.grp.gw != NULL)
		shm_free(rule->dest[n_dst].dst.grp.gw);
}

void qr_create_partition_list(void *param)
{
	struct dr_cb_params *cbp = (struct dr_cb_params *)param;
	struct dr_create_partition_list_params *partition_list_params;
	partition_list_params = (struct dr_create_partition_list_params*)*cbp->param;
	qr_partitions_t **part_list =
		(qr_partitions_t**)partition_list_params->part_list;
	int n_partitions = partition_list_params->n_parts;

	*part_list = (qr_partitions_t*)shm_malloc(sizeof(qr_partitions_t));
	memset(*part_list, 0, sizeof(qr_partitions_t));
	if (part_list == NULL) {
		LM_ERR("no more shm memory");
		return;
	}
	if(((*part_list)->rw_lock = lock_init_rw()) == NULL) {
		LM_ERR("failed to init rw lock");
		goto error;
	}
	(*part_list)->qr_rules_start = (qr_rule_t**)shm_malloc(
			n_partitions * sizeof(qr_rule_t*));
	if((*part_list)->qr_rules_start == NULL) {
		LM_ERR("no more shm memory");
		goto error;
	}

	(*part_list)->part_name = (str*)shm_malloc(n_partitions*sizeof(str));
	(*part_list)->n_parts = n_partitions;

	memset((*part_list)->part_name, 0, n_partitions*sizeof(str));
	memset((*part_list)->qr_rules_start, 0,n_partitions*sizeof(qr_rule_t*));

	return ;
error:
	if((*part_list)->rw_lock != NULL) {
		lock_destroy_rw((*part_list)->rw_lock);

	}

	if((*part_list)->qr_rules_start) {
		shm_free((*part_list)->qr_rules_start);
	}

	if(part_list != NULL) {
		shm_free(part_list);
		part_list = NULL;
	}

}

/* add rule to list. if the list is NULL a new list is created */
void qr_add_rule_to_list(void *param)
{
	struct dr_cb_params *cbp = (struct dr_cb_params *)param;
	struct dr_add_rule_params  *add_rule_params =
		(struct dr_add_rule_params*)*cbp->param;
	qr_partitions_t *qr_parts = (qr_partitions_t*)add_rule_params->qr_parts;
	qr_rule_t *new = add_rule_params->qr_rule;
	int part_index = add_rule_params->part_index;
	qr_rule_t **rule_list = &qr_parts->qr_rules_start[part_index];
	str part_name = add_rule_params->part_name;

	if(new != NULL) {
		if(*rule_list == NULL) {
			*rule_list = new;
			qr_parts->part_name[part_index] = part_name;
		} else {
			new->next = *rule_list;
			*rule_list = new;
		}
		LM_DBG("rule '%d' added to qr rule list for partition index '%d' \n",
				new->r_id, part_index);
	}
}

/* TODO: add lock */
/* saves rule list rcvd as parameter, to the main rule list used
 * by the QR module */
void qr_mark_as_main_list(void *param)
{
	struct dr_cb_params *cbp = (struct dr_cb_params *)param;
	struct dr_mark_as_main_list_params * mark_as_main_list =
		(struct dr_mark_as_main_list_params*) *cbp->param;
	qr_partitions_t *qr_parts_new = (qr_partitions_t*)mark_as_main_list
		->qr_parts_new_list;

	LM_DBG("Mark main QR rule list\n");
	*mark_as_main_list->qr_parts_old_list = *qr_main_list; /* save old list so it can be freed */
	lock_start_write(*rw_lock_qr);
	*qr_main_list = qr_parts_new; /* the new list that the QR will work with */
	lock_stop_write(*rw_lock_qr);
}

/* copy link two rule lists together => used for dr_reload and partitions
 * (every partition will create a separate list) */
void qr_link_rule_list(void *param)
{
	struct dr_cb_params *cbp = (struct dr_cb_params *)param;
	struct dr_link_rule_list_params * rule_lists =
		(struct dr_link_rule_list_params *)*cbp->param;
	qr_rule_t **first_list = (qr_rule_t**)rule_lists->first_list,
	           *second_list = (qr_rule_t*)rule_lists->second_list;

	add_last(second_list, *first_list);
}

