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

#include "qrouting.h"
#include "qr_sort.h"
#include "qr_acc.h"
#include "qr_stats.h"
#include "qr_event.h"

#define log_thr_exceeded(_thr, thr_name, _val, _cmp, _lim) \
	LM_WARN(_thr" %s threshold exceeded (%0.*lf %c %0.*lf, %d samples, " \
	       "rule: %d, gw: %.*s)\n", thr_name, qr_decimal_digits, _val, _cmp, \
	       qr_decimal_digits, _lim, samples, rule_id, gw_name->len, gw_name->s)

#define log_warn_thr(thr_name, _val, _cmp, _lim) \
	log_thr_exceeded("warn", thr_name, _val, _cmp, _lim)

#define log_crit_thr(thr_name, _val, _cmp, _lim) \
	log_thr_exceeded("crit", thr_name, _val, _cmp, _lim)


static inline void qr_weight_based_sort(unsigned short *dsts,
                                        const double *scores, int n);

static inline double _qr_score_gw(qr_gw_t *gw, qr_profile_t *prof,
                                  str *part, int rule_id, int *disabled)
{
	double score = 1, val;
	double asr_v, ccr_v, pdd_v, ast_v, acd_v;
	str *gw_name = drb.get_gw_name(gw->dr_gw);
	int i, samples, skip_event = 0;

	/* the corresponding dr_rule points to an invalid qr_profile */
	if (!prof)
		goto set_score;

	/* FIXME: might be better under a single lock
	 * because of possible changes between lock ( a
	 * new sampling interval might bring new statistics)
	 */
	asr_v = asr(gw, &samples);
	if (asr_v != -1) {
		if (asr_v < prof->asr2) {
			score *= prof->asr_pty2;
			log_crit_thr("ASR", asr_v, '<', prof->asr2);
		} else if (asr_v < prof->asr1) {
			score *= prof->asr_pty1;
			log_warn_thr("ASR", asr_v, '<', prof->asr1);
		}
	}

	ccr_v = ccr(gw, &samples);
	if (ccr_v != -1) {
		if (ccr_v < prof->ccr2) {
			score *= prof->ccr_pty2;
			log_crit_thr("CCR", ccr_v, '<', prof->ccr2);
		} else if (ccr_v < prof->ccr1) {
			score *= prof->ccr_pty1;
			log_warn_thr("CCR", ccr_v, '<', prof->ccr1);
		}
	}

	pdd_v = pdd(gw, &samples);
	if (pdd_v != -1) {
		if (pdd_v > prof->pdd2) {
			score *= prof->pdd_pty2;
			log_crit_thr("PDD", pdd_v, '>', prof->pdd2);
		} else if (pdd_v > prof->pdd1) {
			score *= prof->pdd_pty1;
			log_warn_thr("PDD", pdd_v, '>', prof->pdd1);
		}
	}

	ast_v = ast(gw, &samples);
	if (ast_v != -1) {
		if (ast_v > prof->ast2) {
			score *= prof->ast_pty2;
			log_crit_thr("AST", ast_v, '>', prof->ast2);
		} else if (ast_v > prof->ast1) {
			score *= prof->ast_pty1;
			log_warn_thr("AST", ast_v, '>', prof->ast1);
		}
	}

	acd_v = acd(gw, &samples);
	if (acd_v != -1) {
		if (acd_v < prof->acd2) {
			score *= prof->acd_pty2;
			log_crit_thr("ACD", acd_v, '<', prof->acd2);
		} else if (acd_v < prof->acd1) {
			score *= prof->acd_pty1;
			log_warn_thr("ACD", acd_v, '<', prof->acd1);
		}
	}

	/* extra stats */
	for (i = 0; i < qr_xstats_n; i++) {
		val = get_xstat(gw, i, &samples);
		if (val == -1)
			continue;

		if (qr_xstats[i].increasing) {
			if (val < prof->xstats[i].thr2) {
				score *= prof->xstats[i].pty2;
				log_crit_thr(qr_xstats[i].name.s,
				             val, '<', prof->xstats[i].thr2);
			} else if (val < prof->xstats[i].thr1) {
				score *= prof->xstats[i].pty1;
				log_warn_thr(qr_xstats[i].name.s,
				             val, '<', prof->xstats[i].thr1);
			}
		} else {
			if (val > prof->xstats[i].thr2) {
				score *= prof->xstats[i].pty2;
				log_crit_thr(qr_xstats[i].name.s,
				             val, '>', prof->xstats[i].thr2);
			} else if (val > prof->xstats[i].thr1) {
				score *= prof->xstats[i].pty1;
				log_warn_thr(qr_xstats[i].name.s,
				             val, '>', prof->xstats[i].thr1);
			}
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

	if (event_bad_dst_threshold && score < event_bad_dst_threshold
	        && !skip_event)
		qr_raise_event_bad_dst(rule_id, part, gw_name);

	*disabled = skip_event;
	return score;
}


static inline double qr_score_gw(qr_gw_t *gw, const qr_rule_t *rule,
                                    qr_profile_t *prof)
{
	double cur_dst_score;
	int disabled = 0;

	lock_start_read(gw->ref_lock);
	if (gw->state & QR_STATUS_DIRTY) {
		lock_stop_read(gw->ref_lock);

		cur_dst_score = _qr_score_gw(gw, prof, rule->part_name,
		                             rule->r_id, &disabled);
	} else {
		cur_dst_score = gw->score;
		lock_stop_read(gw->ref_lock);
	}

	return disabled ? -1 : cur_dst_score;
}

static inline double qr_score_grp(qr_grp_t *grp, const qr_rule_t *rule,
                                  qr_profile_t *prof)
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

			score = _qr_score_gw(gw, prof, rule->part_name,
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

/* a higher score (weight) is better */
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

	return s1 > s2 ? -1 : (s1 == s2 ? 0 : 1);
}

void qr_sort_best_dest_first(void *param)
{
	struct dr_sort_params *srp = (struct dr_sort_params *)param;
	unsigned short dst_idx;
	int i, disabled = 0, ndst;
	unsigned short *sorted_dst;
	double *new_scores;
	qr_profile_t prof;
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
	prof = *rule->profile;
	lock_stop_read(qr_profiles_rwl);

	/* compute the score of each destination.  A carrier's final score will be
	 * the average score of all of their active gateways */
	for (i = 0; i < ndst; i++) {
		if (rule->dest[i].type & QR_DST_GW)
			qr_scores[i] = qr_score_gw(rule->dest[i].gw, rule, &prof);
		else
			qr_scores[i] = qr_score_grp(&rule->dest[i].grp, rule, &prof);

		LM_DBG("score for dst type %d, i: %d is %lf\n",
		       rule->dest[i].type, i, qr_scores[i]);

		if (qr_scores[i] == -1)
			disabled++;
	}

	qsort(sorted_dst, ndst, sizeof *sorted_dst, qr_cmp_dst);

	/* mark the disabled destinations with -1 */
	memset(sorted_dst + ndst - disabled, -1, disabled * sizeof *sorted_dst);

	srp->rc = 0;
	return;

error:
	srp->rc = -1;
}

void qr_sort_dynamic_weights(void *param)
{
	struct dr_sort_params *srp = (struct dr_sort_params *)param;
	unsigned short dst_idx;
	int i, j, di, ndst, ndisabled;
	unsigned short *sorted_dst;
	double *new_scores;
	qr_profile_t prof;
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
	prof = *rule->profile;
	lock_stop_read(qr_profiles_rwl);

	/* compute the score of each destination.  A carrier's final score will be
	 * the average score of all of their active gateways */
	for (i = 0, j = 0, di = ndst - 1; i < ndst; i++, j++) {
		if (rule->dest[i].type & QR_DST_GW)
			qr_scores[j] = qr_score_gw(rule->dest[i].gw, rule, &prof);
		else
			qr_scores[j] = qr_score_grp(&rule->dest[i].grp, rule, &prof);

		LM_DBG("score for dst type %d, i: %d is %lf\n",
		       rule->dest[i].type, i, qr_scores[j]);

		/* if it's disabled, place it towards the end */
		if (qr_scores[j] == -1) {
			j--;
			sorted_dst[di--] = i;
		} else {
			sorted_dst[j] = i;
		}
	}

	ndisabled = ndst - 1 - di;

	qr_weight_based_sort(sorted_dst, qr_scores, ndst - ndisabled);

	/* mark the disabled destinations with -1 */
	memset(sorted_dst + ndst - ndisabled, -1, ndisabled * sizeof *sorted_dst);

	srp->rc = 0;
	return;

error:
	srp->rc = -1;
}

static inline void qr_weight_based_sort(unsigned short *dsts,
                                        const double *scores, int n)
{
	double running_sum[n], sum, rnd, aux;
	int i, first = 0;

	while (first < n - 1) {
		for (i = first, sum = 0; i < n; i++) {
			sum += scores[i];
			running_sum[i] = sum;
		}

		if (sum) {
			rnd = sum * ((float)rand() / RAND_MAX);

			for (i = first; i < n; i++)
				if (running_sum[i] > rnd)
					break;

			if (i == n) {
				LM_BUG("bug encountered during weight based sort!");
				return;
			}

		} else {
			i = first;
		}

		aux = dsts[first];
		dsts[first] = dsts[i];
		dsts[i] = aux;
		first++;
	}
}
