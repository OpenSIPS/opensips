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

#include "qr_sort.h"
#include "qr_acc.h"
#include "qr_stats.h"
#include "qr_event.h"

int qr_add_dst_to_list(qr_sorted_list_t **sorted_list, int dst_idx, int score) {
	qr_sorted_list_t *new_elem = (qr_sorted_list_t*)pkg_malloc(
			sizeof(qr_sorted_list_t));
	if(new_elem == NULL) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}
	memset(new_elem, 0, sizeof(qr_sorted_list_t));

	new_elem->next = sorted_list[score];
	new_elem->dst_idx = dst_idx;
	sorted_list[score] = new_elem;

	return 0;

}


void empty_qr_sorted_list(qr_sorted_list_t **sorted_list) {
	qr_sorted_list_t *sorted_list_to_free, *sorted_list_cur;
	int i;
	for(i = 0; i < QR_N_SORTED_LIST; i++) {
		sorted_list_to_free = sorted_list[i];
		while(sorted_list_to_free) {
			sorted_list_cur = sorted_list_to_free->next;
			pkg_free(sorted_list_to_free);
			sorted_list_to_free = sorted_list_cur;
		}
		sorted_list[i] = NULL;

	}
}

#define log_warn_thr(thr) \
	LM_WARN("warn "thr" threshold exceeded, gwid: %.*s\n", \
	        gw_name->len, gw_name->s)

#define log_crit_thr(thr) \
	LM_WARN("crit "thr" threshold exceeded, gwid: %.*s\n", \
	        gw_name->len, gw_name->s)

/*
 * computes the score of the gateway using the warning
 * thresholds
 */
int qr_score_gw(qr_gw_t *gw, qr_thresholds_t *thresholds,
                str *part, int rule_id)
{
	extern int event_bad_dst_threshold;
	double score = 0;
	double asr_v, ccr_v, pdd_v, ast_v, acd_v;
	str *gw_name = drb.get_gw_name(gw->dr_gw);

	/* the corresponding dr_rule points to an invalid qr_profile */
	if (!thresholds)
		goto set_score;

	/* FIXME: might be better under a single lock
	 * because of possible changes between lock ( a
	 * new sampling interval might bring new statistics)
	 */
	asr_v = asr(gw);
	if (asr_v < thresholds->asr1 && asr_v != -1) {
		score += thresholds->weight_asr * QR_PENALTY_THRESHOLD_1;
		log_warn_thr("ASR");
		if(asr_v < thresholds->asr2) {
			score += thresholds->weight_asr * QR_PENALTY_THRESHOLD_2;
			log_crit_thr("ASR");
		}
	}

	ccr_v = ccr(gw);
	if (ccr_v < thresholds->ccr1 && ccr_v != -1) {
		score += thresholds->weight_ccr * QR_PENALTY_THRESHOLD_1;
		log_warn_thr("CCR");
		if(ccr_v < thresholds->ccr2) {
			score += thresholds->weight_ccr * QR_PENALTY_THRESHOLD_2;
			log_crit_thr("CCR");
		}
	}

	pdd_v = pdd(gw);
	if (pdd_v > thresholds->pdd1 && pdd_v != -1) {
		score += thresholds->weight_pdd * QR_PENALTY_THRESHOLD_1;
		log_warn_thr("PDD");
		if(pdd_v > thresholds->pdd2) {
			score += thresholds->weight_pdd * QR_PENALTY_THRESHOLD_2;
			log_crit_thr("PDD");
		}
	}

	ast_v = ast(gw);
	if (ast_v > thresholds->ast1 && ast_v != -1) {
		score += thresholds->weight_ast * QR_PENALTY_THRESHOLD_1;
		log_warn_thr("AST");
		if(ast_v > thresholds->ast2) {
			score += thresholds->weight_ast * QR_PENALTY_THRESHOLD_2;
			log_crit_thr("AST");
		}
	}

	acd_v = acd(gw);
	if (acd_v < thresholds->acd1 && acd_v != -1) {
		score += thresholds->weight_acd * QR_PENALTY_THRESHOLD_1;
		log_warn_thr("ACD");
		if(acd_v < thresholds->acd2) {
			score += thresholds->weight_acd * QR_PENALTY_THRESHOLD_2;
			log_crit_thr("ACD");
		}
	}

set_score:
	if (score > event_bad_dst_threshold)
		qr_raise_event_bad_dst(rule_id, part, gw_name);

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
			mean += qr_score_gw(grp->gw[i], thresholds, NULL, -1); /* TODO */

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
 * inserts gw in sorted list
 */
int qr_insert_dst(qr_sorted_list_t **sorted, qr_rule_t *rule,
		int cr_id, int gw_id)
{
	qr_thresholds_t thr;
	int cur_dst_score;
	qr_gw_t *gw;

	if (cr_id == -1) { /* the gw is within a rule */
		gw = rule->dest[gw_id].gw;
	} else { /* the gw is within a carrier */
		gw = rule->dest[cr_id].grp.gw[gw_id];
	}

	lock_start_read(gw->ref_lock);
	if (gw->state & QR_STATUS_DIRTY) {
		lock_stop_read(gw->ref_lock);

		lock_start_read(qr_profiles_rwl);
		thr = *rule->thresholds;
		lock_stop_read(qr_profiles_rwl);

		LM_DBG("evaluating score for:cr_id = %d gw_id = %d\n", cr_id, gw_id);
		cur_dst_score = qr_score_gw(gw, &thr, rule->part_name, rule->r_id);
	} else {
		cur_dst_score = gw->score;
		lock_stop_read(gw->ref_lock);
	}

	lock_start_read(gw->ref_lock);
	if (gw->state & QR_STATUS_DSBL) {
		lock_stop_read(gw->ref_lock);
		LM_DBG("gw is disabled cr_id = %d gw_id = %d\n", cr_id, gw_id);
		return 0;
	}
	lock_stop_read(gw->ref_lock);

	/* insert into sorted list */
	if (qr_add_dst_to_list(sorted, gw_id, cur_dst_score) < 0) {
		LM_ERR("failed to insert destination id in qr sorted list\n");
		return -1;
	}

	return 0;
}


void qr_sort(void *param)
{
	struct dr_sort_params *srp = (struct dr_sort_params *)param;
	qr_rule_t *rule;
	unsigned short dst_idx;
	int i,j,k;
	int n_gw_list;
	unsigned short *sorted_dst;
	qr_sorted_list_t **sorted_list = NULL, *sorted_list_it = NULL;

	rule = drb.get_qr_rule_handle(srp->dr_rule);
	if (!rule) {
		LM_ERR("No qr rule provided for sorting (qr_handle needed)\n");
		goto error;
	}

	sorted_dst = srp->sorted_dst;
	dst_idx = srp->dst_idx;

	if (!sorted_dst) {
		LM_ERR("no array provided to save destination indexes to\n");
		goto error;
	}

	if (*n_sampled < qr_n) { /* we don't have enough statistics to sort */
		if (dst_idx == (unsigned short)-1) {
			for (i = 0; i < rule->n ; i++)
				sorted_dst[i] = i; /* return the gws in DB order */
		} else {
			for (i = 0; i < rule->dest[dst_idx].grp.n; i++)
				sorted_dst[i] = i; /* maintain DB order */
		}

		return;
	}

	sorted_list = pkg_malloc(QR_N_SORTED_LIST * sizeof *sorted_list);
	if (!sorted_list) {
		LM_ERR("oom\n");
		goto error;
	}
	memset(sorted_list, 0, QR_N_SORTED_LIST * sizeof *sorted_list);

	j = 0;
	if (dst_idx == (unsigned short)-1) { /* sorting for the rule */
		for (i = 0; i < rule->n; i++)
			sorted_dst[i] = -1;

		for (i = 0; i < rule->n; i++) {
			if(rule->dest[i].type & QR_DST_GW) {
				if(qr_insert_dst(sorted_list, rule, -1, i) < 0)
					goto error;
			} else {
				for(k = 0; k < QR_N_SORTED_LIST; k++) {
					sorted_list_it = sorted_list[k];

					while(sorted_list_it != NULL) {
						sorted_dst[j++] = sorted_list_it->dst_idx;
						sorted_list_it = sorted_list_it->next;
					}

				}
				sorted_dst[j++] = i; /* because some of the destinations might
										   have been disabled */
				empty_qr_sorted_list(sorted_list);

			}
		}
	} else { /* sorting for a given carrier */
		/* TODO: should contain a RW_lock per rule to protect data from reloading */
		lock_start_read(rule->dest[dst_idx].grp.ref_lock);
		n_gw_list = rule->dest[dst_idx].grp.n;
		for(i = 0; i < n_gw_list; i++)
			sorted_dst[i] = -1;
		for(i = 0; i < n_gw_list; i++) {
			if(qr_insert_dst(sorted_list, rule, dst_idx, i)) {
				goto error;
			}
		}
		lock_stop_read(rule->dest[dst_idx].grp.ref_lock);

	}

	/* saving the sorted list to the provided array */
	for (i = 0; i < QR_N_SORTED_LIST; i++) {
		sorted_list_it = sorted_list[i];

		while (sorted_list_it) {
			sorted_dst[j++] = sorted_list_it->dst_idx;
			sorted_list_it = sorted_list_it->next;
		}
	}

	empty_qr_sorted_list(sorted_list);
	pkg_free(sorted_list);

	srp->rc = 0;
	return;

error:
	if (sorted_list) {
		empty_qr_sorted_list(sorted_list);
		pkg_free(sorted_list);
	}

	srp->rc = -1;
}
