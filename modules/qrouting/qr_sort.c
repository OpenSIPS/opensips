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
static double _qr_score_gw(qr_gw_t *gw, qr_thresholds_t *thresholds,
                           str *part, int rule_id, int *disabled)
{
	extern int event_bad_dst_threshold;
	double score = 0;
	double asr_v, ccr_v, pdd_v, ast_v, acd_v;
	str *gw_name = drb.get_gw_name(gw->dr_gw);
	int skip_event = 0;

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
	/* update gw score and status */
	lock_start_write(gw->ref_lock);
	gw->score = score;
	gw->state &= ~QR_STATUS_DIRTY;

	if (gw->state & QR_STATUS_DSBL)
		skip_event = 1;
	lock_stop_write(gw->ref_lock);

	if (score > event_bad_dst_threshold && !skip_event)
		qr_raise_event_bad_dst(rule_id, part, gw_name);

	*disabled = skip_event;
	return score;
}


static inline double qr_score_gw(qr_gw_t *gw, const qr_rule_t *rule,
                                 qr_thresholds_t *thr)
{
	double cur_dst_score;
	int disabled = 0;

	lock_start_read(gw->ref_lock);
	if (gw->state & QR_STATUS_DIRTY) {
		lock_stop_read(gw->ref_lock);

		cur_dst_score = _qr_score_gw(gw, thr, rule->part_name,
		                             rule->r_id, &disabled);
	} else {
		cur_dst_score = gw->score;
		lock_stop_read(gw->ref_lock);
	}

	return disabled ? -1 : cur_dst_score;
}

static inline double qr_score_grp(qr_grp_t *grp, const qr_rule_t *rule,
                                  qr_thresholds_t *thr)
{
	qr_gw_t *gw;
	int i, valid_gws = 0, disabled;
	double mean = 0, score;

	/* can we get away by reading the previous score? */
	lock_start_read(grp->ref_lock);
	if (!(grp->state & QR_STATUS_DIRTY)) {
		mean = grp->score;
		lock_stop_read(grp->ref_lock);
		return mean;
	}
	lock_stop_read(grp->ref_lock);

	for (i = 0; i < grp->n; i++) {
		gw = grp->gw[i];

		lock_start_read(gw->ref_lock);
		if (gw->state & QR_STATUS_DIRTY) {
			lock_stop_read(gw->ref_lock);

			score = _qr_score_gw(gw, thr, rule->part_name,
			                     rule->r_id, &disabled);
			if (!disabled) {
				mean += score;
				valid_gws++;
			}

		} else if (!(gw->state & QR_STATUS_DSBL)) {
			mean += gw->score;
			valid_gws++;
			lock_stop_read(gw->ref_lock);
		}
	}

	if (!valid_gws)
		mean = -1;
	else
		mean /= valid_gws;

	lock_start_write(grp->ref_lock);
	grp->score = mean;
	grp->state &= ~QR_STATUS_DIRTY;
	lock_stop_write(grp->ref_lock);

	return mean;
}

static double *qr_scores;
static int qr_scores_sz;

static int qr_cmp_dst(const void *d1, const void *d2)
{
	double s1 = qr_scores[*(unsigned short *)d1],
	       s2 = qr_scores[*(unsigned short *)d2];

	if (s1 == -1) {
		if (s2 == -1)
			return 0;

		return 1;
	}

	if (s2 == -1)
		return -1;

	return s1 < s2 ? -1 : (s1 == s2 ? 0 : 1);
}

void qr_sort(void *param)
{
	struct dr_sort_params *srp = (struct dr_sort_params *)param;
	unsigned short dst_idx;
	int i, disabled = 0, ndst;
	unsigned short *sorted_dst;
	double *new_scores;
	qr_thresholds_t thr;
	qr_rule_t *rule;

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

	if (dst_idx == (unsigned short)-1)
		ndst = rule->n;
	else
		ndst = rule->dest[dst_idx].grp.n;

	for (i = 0; i < ndst; i++)
		sorted_dst[i] = i;

	if (*n_sampled < qr_n) /* we don't have enough statistics to sort */
		goto out;

	if (ndst > qr_scores_sz) {
		new_scores = pkg_realloc(qr_scores, ndst * sizeof *new_scores);
		if (!new_scores) {
			LM_ERR("oom\n");
			goto error;
		}

		qr_scores = new_scores;
		qr_scores_sz = ndst;
	}

	lock_start_read(qr_profiles_rwl);
	thr = *rule->thresholds;
	lock_stop_read(qr_profiles_rwl);

	/* compute the score of each destination.  A carrier's final score will be
	 * the average score of all of their active gateways */
	for (i = 0; i < ndst; i++) {
		if (rule->dest[i].type & QR_DST_GW)
			qr_scores[i] = qr_score_gw(rule->dest[i].gw, rule, &thr);
		else
			qr_scores[i] = qr_score_grp(&rule->dest[i].grp, rule, &thr);

		LM_DBG("score for dst type %d, i: %d is %lf\n",
		       rule->dest[i].type, i, qr_scores[i]);

		if (qr_scores[i] == -1)
			disabled++;
	}

	qsort(sorted_dst, ndst, sizeof *sorted_dst, qr_cmp_dst);

	/* mark the disabled destinations with -1 */
	memset(sorted_dst + ndst - disabled, -1, disabled * sizeof *sorted_dst);

out:
	srp->rc = 0;
	return;

error:
	srp->rc = -1;
}
