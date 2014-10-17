/**
 *
 * qrouting module:qr_sort.c
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
 *  2014-09-29  initial version (Mihai Tiganus)
 */
#include "qr_sort.h"
#include "qr_acc.h"

#define QR_PENALTY_THRESHOLD_1 1
#define QR_PENALTY_THRESHOLD_2 1
/* the number of elements for the hashmap used by the sorting */
#define QR_N_SORTED_LIST 2*(QR_PENALTY_THRESHOLD_1+QR_PENALTY_THRESHOLD_2)+1


int qr_add_dst_to_list(qr_sorted_list_t **sorted_list, int dst_id, int score) {
	qr_sorted_list_t *new_elem = (qr_sorted_list_t*)pkg_malloc(
			sizeof(qr_sorted_list_t));
	if(new_elem == NULL) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}
	memset(new_elem, 0, sizeof(qr_sorted_list_t));

	new_elem->next = sorted_list[score];
	new_elem->dst_id = dst_id;
	sorted_list[score] = new_elem;

	return 0;

}


void free_qr_sorted_list(qr_sorted_list_t **sorted_list) {
	qr_sorted_list_t *sorted_list_to_free, *sorted_list_cur;
	int i;
	for(i = 0; i < QR_N_SORTED_LIST; i++) {
		sorted_list_to_free = sorted_list[i];
		while(sorted_list_to_free) {
			sorted_list_cur = sorted_list_to_free->next;
			pkg_free(sorted_list_to_free);
			sorted_list_to_free = sorted_list_cur;
		}

	}

	pkg_free(sorted_list);
}
/* compute answer seizure ratio for gw */
inline double asr(qr_gw_t *gw) {
	double asr;
	lock_start_read(gw->ref_lock);
	if(gw->history_stats.n.ok == 0) {
		lock_stop_read(gw->ref_lock);
		return -1;
	}
	asr = (double)gw->history_stats.stats.as/gw->history_stats.n.ok;
	lock_stop_read(gw->ref_lock);
	return asr;
}

/* compute completed calls ratio for gw */
inline double ccr(qr_gw_t *gw) {
	double ccr;
	lock_start_read(gw->ref_lock);
	if(gw->history_stats.n.ok == 0) {
		lock_stop_read(gw->ref_lock);
		return -1;
	}
	ccr = (double)gw->history_stats.stats.cc/gw->history_stats.n.ok;
	lock_stop_read(gw->ref_lock);
	return ccr;
}

/* compute post dial delay for gw */
inline double pdd(qr_gw_t *gw) {
	double pdd;
	lock_start_read(gw->ref_lock);
	if(gw->history_stats.n.pdd == 0) {
		lock_stop_read(gw->ref_lock);
		return -1;
	}
	pdd = (double)gw->history_stats.stats.pdd/gw->history_stats.n.pdd;
	lock_stop_read(gw->ref_lock);
	return pdd;
}

/* compute average setup time for gw */
inline double ast(qr_gw_t *gw) {
	double ast;
	lock_start_read(gw->ref_lock);
	if(gw->history_stats.n.setup == 0) {
		lock_stop_read(gw->ref_lock);
		return -1;
	}
	ast = (double)gw->history_stats.stats.st/gw->history_stats.n.setup;
	lock_stop_read(gw->ref_lock);
	return ast;
}

/* compute average call duration for gw */
inline double acd(qr_gw_t *gw) {
	double acd;
	lock_start_read(gw->ref_lock);
	if(gw->history_stats.n.cd == 0) {
		lock_stop_read(gw->ref_lock);
		return -1;
	}
	acd = (double)gw->history_stats.stats.cd/gw->history_stats.n.cd;
	lock_stop_read(gw->ref_lock);
	return acd;
}

static inline void qr_mark_gw_dsbl(qr_gw_t *gw) {
	lock_start_write(gw->ref_lock);
	gw->state |= QR_STATUS_DSBL; /* mark the gateway as disabled */
	lock_stop_write(gw->ref_lock);
}
/*
 * computes the score of the gateway using the warning
 * thresholds
 */
int qr_score_gw(qr_gw_t *gw, qr_thresholds_t * thresholds) {
	int score = 0, asr_v, ccr_v, pdd_v, ast_v, acd_v;
	/* FIXME: might be better under a single lock
	 * because of possible changes between lock ( a
	 * new sampling interval might bring new statistics)
	 */
	asr_v = asr(gw);
	if(asr_v < thresholds->asr1 && asr_v != -1) {
		score += QR_PENALTY_THRESHOLD_2;
		if(asr_v < thresholds->asr2) {
			score += QR_PENALTY_THRESHOLD_2;
			qr_mark_gw_dsbl(gw);
		}
	}
	ccr_v = ccr(gw);
	if(ccr_v < thresholds->ccr1 && ccr_v != -1) {
		score += QR_PENALTY_THRESHOLD_1;
		if(ccr_v < thresholds->ccr2) {
			score += QR_PENALTY_THRESHOLD_2;
			qr_mark_gw_dsbl(gw);
		}
	}
	pdd_v = pdd(gw);
	if(pdd_v > thresholds->pdd1 && pdd_v != -1) {
		score += QR_PENALTY_THRESHOLD_1;
		if(pdd_v > thresholds->pdd2) {
			score += QR_PENALTY_THRESHOLD_2;
			qr_mark_gw_dsbl(gw);
		}
	}
	ast_v = ast(gw);
	if(ast_v > thresholds->ast1 && ast_v != -1) {
		score += QR_PENALTY_THRESHOLD_1;
		if(ast_v > thresholds->ast2) {
			score +=QR_PENALTY_THRESHOLD_2;
			qr_mark_gw_dsbl(gw);
		}
	}
	acd_v = acd(gw);
	if(acd_v < thresholds->acd1 && acd_v != -1) {
		score += QR_PENALTY_THRESHOLD_1;
		if(ast_v < thresholds->acd2) {
			score += QR_PENALTY_THRESHOLD_2;
			qr_mark_gw_dsbl(gw);
		}
	}

	/* update gw score and status */
	lock_start_write(gw->ref_lock);
	gw->score = score;
	gw->state &= ~QR_STATUS_DIRTY;
	lock_stop_write(gw->ref_lock);

	return 0;
}

int qr_score_grp(qr_grp_t *grp, qr_thresholds_t * thresholds) {
	int i;
	int mean = 0;

	for(i = 0; i < grp->n; i++) {
		lock_start_read(grp->gw[i]->ref_lock);
		if(grp->gw[i]->state & QR_STATUS_DIRTY) {
			lock_stop_read(grp->gw[i]->ref_lock);
			mean += qr_score_gw(grp->gw[i], thresholds);

		} else {
			lock_stop_read(grp->gw[i]->ref_lock);
		}
	}
	mean /= grp->n;
	lock_start_write(grp->ref_lock);
	grp->score = mean;
	grp->state &= ~QR_STATUS_DIRTY;
	lock_stop_write(grp->ref_lock);

	return mean;

}
/*
 * inserts destination in sorted list
 */
int qr_insert_dst(qr_sorted_list_t **sorted, qr_rule_t *rule,
		int dst_id) {
	int cur_dst_score;
	if(rule->dest[dst_id].type & QR_DST_GRP) {
		lock_start_read(rule->dest[dst_id].dst.grp.ref_lock);
		if(rule->dest[dst_id].dst.grp.state & QR_STATUS_DIRTY) {
			lock_stop_read(rule->dest[dst_id].dst.grp.ref_lock);
			cur_dst_score = qr_score_grp(&rule->dest[dst_id].dst.grp, rule->thresholds);
		} else {
			cur_dst_score = rule->dest[dst_id].dst.grp.score;
			lock_stop_read(rule->dest[dst_id].dst.grp.ref_lock);
		}
	} else {
		lock_start_read(rule->dest[dst_id].dst.gw->ref_lock);
		if(rule->dest[dst_id].dst.gw->state & QR_STATUS_DIRTY) {
			lock_stop_read(rule->dest[dst_id].dst.gw->ref_lock);
			cur_dst_score = qr_score_gw(rule->dest[dst_id].dst.gw, rule->thresholds); /* compute the
																						  score */
		} else {
			cur_dst_score = rule->dest[dst_id].dst.gw->score;
			lock_stop_read(rule->dest[dst_id].dst.gw->ref_lock);
		}
		lock_start_read(rule->dest[dst_id].dst.gw->ref_lock);
		if(rule->dest[dst_id].dst.gw->state & QR_STATUS_DSBL) {
			lock_stop_read(rule->dest[dst_id].dst.gw->ref_lock);
			return 0;
		}
		lock_stop_read(rule->dest[dst_id].dst.gw->ref_lock);

	}

	if(qr_add_dst_to_list(sorted, dst_id, cur_dst_score) < 0) { /* insert
																   into sorted
																   list */
		LM_ERR("failed to insert destination id in qr sorted list\n");
		return -1;
	}


	return 0;
}


void qr_sort(int type, struct dr_cb_params *params) {
	qr_rule_t *rule;
	int dst_id;
	int i,j;
	unsigned short *us_sorted_dst;
	qr_sorted_list_t **sorted_list = NULL, *sorted_list_it = NULL;

	rule = (qr_rule_t*)drb.get_qr_rule_handle(((struct dr_sort_params *)
				*params->param)->dr_rule);
	if(rule == NULL) {
		LM_ERR("No qr rule provided for sorting (qr_handle needed)\n");
		goto error;
	}
	us_sorted_dst = ((struct dr_sort_params *)*params->param)->sorted_dst;

	dst_id = ((struct dr_sort_params *)*params->param)->dst_id;

	sorted_list = (qr_sorted_list_t **)pkg_malloc(QR_N_SORTED_LIST *
			sizeof(qr_sorted_list_t) );
	if(sorted_list == NULL) {
		LM_ERR("no more pkg memory\n");
		goto error;
	}
	if(us_sorted_dst == NULL) {
		LM_ERR("no array provided to save destination indexes to\n");
		goto error;
	}
	memset(sorted_list, 0, QR_N_SORTED_LIST*sizeof(qr_sorted_list_t*));


	if(dst_id == -1) { /* sorting for the rule */
		for(i = 0; i < rule->n; i++) {
			us_sorted_dst[i] = -1;
			if(qr_insert_dst(sorted_list, rule, i) < 0)
				goto error;
		}
	} else { /* sorting for a given carrier */
		/* TODO: init array with -1 */

	}

	/* saving the sorted list to the provided array */
	j = 0;
	for(i = 0; i < QR_N_SORTED_LIST; i++) {
		sorted_list_it = sorted_list[i];

		while(sorted_list_it != NULL) {
			us_sorted_dst[j++] = sorted_list_it->dst_id;
			sorted_list_it = sorted_list_it->next;
		}

	}

	free_qr_sorted_list(sorted_list);

	((struct dr_sort_params *)*params->param)->dst_id = 0;
	return ;
error:
	if(sorted_list != NULL) {
		free_qr_sorted_list(sorted_list);
	}
	((struct dr_sort_params *)*params->param)->dst_id = -1;
}


