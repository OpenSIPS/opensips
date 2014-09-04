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

#include "qr_stats.h"

qr_rule_t * qr_rules_end = NULL; /* used when adding rules */
qr_rule_t * qr_rules_start = NULL; /* used when updating statistics */

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

/* create a gateway */
qr_gw_t * qr_create_gw(void){
	qr_gw_t *gw;
	if ((gw = shm_malloc(sizeof(qr_gw_t))) == NULL) {
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
	return gw;
error:
	if(gw)
		qr_free_gw(gw);
	return NULL;
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
void * qr_create_rule(int n_dest) {
	qr_rule_t *new;
	int i;

	if((new = (qr_rule_t*)shm_malloc(sizeof(qr_rule_t))) == NULL) {
		LM_ERR("no more shm memory\n");
		goto error;
	}
	memset(new, 0, sizeof(qr_rule_t));

	/* prepare an array for adding gateways */
	if((new->dest = (qr_dst_t*)shm_malloc(n_dest*sizeof(qr_dst_t))) == NULL) {
		LM_ERR("no more shm memory\n");
		goto error;
	}

	for(i=0; i<n_dest; i++) {
		new->dest[i].type |= QR_DST_GW;
	}
	return new;
error:
	if(new != NULL) {
		if(new->dest != NULL)
			shm_free(new->dest);
		shm_free(new);
	}
	return NULL;
}

/* marks index_grp destination from the rule as group and creates the gw array */
int qr_dst_is_grp(void *rule_v, int index_grp, int n_gw) {
	qr_rule_t *rule = (qr_rule_t*)rule_v;

	if(rule == NULL) {
		LM_ERR("bad rule\n");
		return -1;
	}
	rule->dest[index_grp].type = 0;
	rule->dest[index_grp].type |= QR_DST_GRP;

	rule->dest[index_grp].dst.grp.gw = (qr_gw_t**)shm_malloc(n_gw *
			sizeof(qr_gw_t*));
	if(rule->dest[index_grp].dst.grp.gw == NULL) {
		LM_ERR("no more shm memory\n");
		goto error;
	}

	return 0;
error:
	if(rule->dest[index_grp].dst.grp.gw != NULL)
		shm_free(rule->dest[index_grp].dst.grp.gw);
	return -1;

}

/* add rule to internal rule list */
void qr_add_rule(void *rule) {
	/*TODO: lock per rule */
	qr_rule_t *new = (qr_rule_t*)rule;

	if(qr_rules_end == NULL) {
		qr_rules_start = new;
	} else {
		qr_rules_end->next = new;
	}
	qr_rules_end = new;
}

