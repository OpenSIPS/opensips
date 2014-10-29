/**
 *
 * qrouting module: qr_stats.c
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

#include "../../str.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"

#include "../drouting/dr_cb.h"

#include "qr_stats.h"
#include "qr_acc.h"


qr_rule_t ** qr_rules_start = NULL;


/* create the samples for a gateway's history */
qr_sample_t * create_history(void) {
	qr_sample_t * history, *tmp;
	int i;

	history = (qr_sample_t*)shm_malloc(sizeof(qr_sample_t));
	if(history == NULL) {
		LM_ERR("no more shm_memory\n");
		return NULL;
	}
	for(tmp = history, i = 0; i < *qr_n-1; tmp = tmp->next, ++i) {
		tmp->next = (qr_sample_t*)shm_malloc(sizeof(qr_sample_t));
		if(tmp->next == NULL)
			return NULL;
	}
	tmp->next = history;
	return history;
}

qr_gw_t * qr_create_gw(void *dst) {
	qr_gw_t *gw = NULL; /* internal gw for qr */
	str *gw_name;
	gw_name = drb.get_gw_name(dst);

	LM_DBG("Creating gw '%.*s'\n", gw_name->len, gw_name->s);

	if ((gw = (qr_gw_t*)shm_malloc(sizeof(qr_gw_t))) == NULL) {
		LM_ERR("no more shm memory\n");
		goto error;
	}
	memset(gw, 0, sizeof(qr_gw_t));
	gw->acc_lock = (gen_lock_t*)lock_alloc();
	if (!lock_init(gw->acc_lock)) {
		LM_ERR("failed to init lock\n");
		goto error;
	}
	if ((gw->ref_lock = lock_init_rw()) == NULL) {
		LM_ERR("failed to init RW lock\n");
		goto error;
	}

	if( (gw->next_interval = create_history()) == NULL) {
		LM_ERR("failed to create history\n");
		goto error;
	}

	gw->dr_gw = dst; /* save the pointer to the dr gateway */

	/* save gateway to rule */
	//rule->dest[n_dst].type = QR_DST_GW;
	//rule->dest[n_dst].dst.gw = gw;
	return gw;
error:
	if(gw)
		qr_free_gw(gw);
	return NULL;

}

/* make gateway a given destination - to be registered as callback */
void qr_dst_is_gw(int type, struct dr_cb_params *param){
	void *dst; /* pgw_t received from dr */
	qr_rule_t *rule; /* qr_rule that was initialised with the qr callback from dr */
	int   n_dst; /* the number of the destination within the dr rule */

	/* extract the parameters from dr */
	rule = (qr_rule_t*)((struct dr_reg_param *)(*param->param))->rule;
	dst = ((struct dr_reg_param *)*param->param)->cr_or_gw;
	n_dst = ((struct dr_reg_param *)*param->param)->n_dst;
	LM_DBG("Adding gw to rule %d\n", rule->r_id);

	if(rule != NULL) {
		rule->dest[n_dst].type = QR_DST_GW;
		rule->dest[n_dst].dst.gw = qr_create_gw(dst);
	} else {
		LM_ERR("no rule to add the gateway to\n");
	}
}

/* free all the samples in a gateway's history */
void free_history(qr_sample_t * history) {
	qr_sample_t *tmp;
	while(history) {
		tmp = history;
		history = history->next;
		shm_free(tmp);
	}
}

/* free gateway information */
void qr_free_gw(qr_gw_t * gw) {
	free_history(gw->next_interval);
	if(gw->acc_lock) {
		lock_destroy(gw->acc_lock);
		lock_dealloc(gw->acc_lock);
	}
	if(gw->ref_lock) {
		lock_destroy_rw(gw->ref_lock);
	}
	shm_free(gw);
}

/* creates a rule n_dest destinations (by default marked as gws) */
void qr_create_rule(int type, struct dr_cb_params * param) {
	qr_rule_t *new = NULL;
	int r_id;
	struct dr_reg_init_rule_params *init_rule_params = NULL;
	init_rule_params = (struct dr_reg_init_rule_params *)*param->param;

	r_id = init_rule_params->r_id;

	if((new = (qr_rule_t*)shm_malloc(sizeof(qr_rule_t))) == NULL) {
		LM_ERR("no more shm memory\n");
	}
	memset(new, 0, sizeof(qr_rule_t));

	/* prepare an array for adding gateways */
	if((new->dest = (qr_dst_t*)shm_malloc(init_rule_params->n_dst*
					sizeof(qr_dst_t))) == NULL) {
		LM_ERR("no more shm memory\n");
		shm_free(new);
	}
	new->n = init_rule_params->n_dst; /* save the number of destinations for
										 this rule, as rcvd from dr*/
	new->r_id = r_id;
	init_rule_params->rule = new; /* send the rule to the dr */
	LM_DBG("Rule %d created\n", r_id);
}

/* marks index_grp destination from the rule as group and creates the gw array */
void qr_dst_is_grp(int type, struct dr_cb_params *params) {
	qr_rule_t *rule = (qr_rule_t*)((struct dr_reg_param *)*params->param)
		->rule;
	void * dr_gw;
	str *cr_name, *gw_name;
	int i;
	int n_dst = ((struct dr_reg_param*)*params->param)->n_dst;
	int n_gws ;
	void *grp = ((struct dr_reg_param*)*params->param)->cr_or_gw;
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

/* add rule to internal rule list */
void qr_add_rule(int type, struct dr_cb_params * param) {
	qr_rule_t *new = (qr_rule_t*)*param->param;

	if(new != NULL) {
		if(*qr_rules_start == NULL) {
			*qr_rules_start = new;
		} else {
			new->next = *qr_rules_start;
			*qr_rules_start = new;
		}
		LM_DBG("rule '%d' added to qr rule list\n", new->r_id);
	}
}

void qr_search_profile(int type, struct dr_cb_params *param) {
	qr_rule_t *rule = (qr_rule_t*)
		((struct dr_set_profile_params *)*param->param)->qr_rule;
	unsigned int profile = ((struct dr_set_profile_params*)*param->param)
		->profile;
	unsigned int current_id;
	int m, left,right, found = 0;
	left = 0;
	right = *n_qr_profiles - 1;
	while(left<=right && !found) {
		m = left + (right-left)/2;
		current_id = ((*qr_profiles)[m]).id;
		if(current_id == profile) {
			rule->thresholds = &(*qr_profiles)[m];
			found = 1;
		} else if(current_id > profile) {
			right = m-1;
		} else {
			left = m+1;
		}

	}
	if(left>right) {
		LM_WARN("profile '%d' not found\n", profile);
	}
}
