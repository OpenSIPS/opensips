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

#ifndef _QR_SORT_H_
#define _QR_SORT_H_

#include "../drouting/prefix_tree.h"
#include "../drouting/dr_cb.h"

#include "qrouting.h"
#include "qr_stats.h"

/* compute answer seizure ratio for gw */
static inline double asr(qr_gw_t *gw, int *samples)
{
	double asr;

	lock_start_read(gw->ref_lock);
	*samples = gw->summed_stats.n.ok;

	if (gw->summed_stats.n.ok == 0 ||
	        gw->summed_stats.n.ok < qr_min_samples_asr) {
		lock_stop_read(gw->ref_lock);
		return -1;
	}

	asr = (double)gw->summed_stats.stats.as / gw->summed_stats.n.ok;
	lock_stop_read(gw->ref_lock);

	return asr;
}

/* compute completed calls ratio for gw */
static inline double ccr(qr_gw_t *gw, int *samples)
{
	double ccr;

	lock_start_read(gw->ref_lock);
	*samples = gw->summed_stats.n.ok;

	if (gw->summed_stats.n.ok == 0 ||
	        gw->summed_stats.n.ok < qr_min_samples_ccr) {
		lock_stop_read(gw->ref_lock);
		return -1;
	}

	ccr = (double)gw->summed_stats.stats.cc / gw->summed_stats.n.ok;
	lock_stop_read(gw->ref_lock);

	return ccr;
}

/* compute post dial delay for gw */
static inline double pdd(qr_gw_t *gw, int *samples)
{
	double pdd;

	lock_start_read(gw->ref_lock);
	*samples = gw->summed_stats.n.pdd;

	if (gw->summed_stats.n.pdd == 0 ||
	        gw->summed_stats.n.pdd < qr_min_samples_pdd) {
		lock_stop_read(gw->ref_lock);
		return -1;
	}

	pdd = (double)gw->summed_stats.stats.pdd / gw->summed_stats.n.pdd;
	lock_stop_read(gw->ref_lock);

	return pdd;
}

/* compute average setup time for gw */
static inline double ast(qr_gw_t *gw, int *samples)
{
	double ast;

	lock_start_read(gw->ref_lock);
	*samples = gw->summed_stats.n.setup;

	if (gw->summed_stats.n.setup == 0 ||
	        gw->summed_stats.n.setup < qr_min_samples_ast) {
		lock_stop_read(gw->ref_lock);
		return -1;
	}

	ast = (double)gw->summed_stats.stats.st / gw->summed_stats.n.setup;
	lock_stop_read(gw->ref_lock);

	return ast;
}

/* compute average call duration for gw */
static inline double acd(qr_gw_t *gw, int *samples)
{
	double acd;

	lock_start_read(gw->ref_lock);
	*samples = gw->summed_stats.n.cd;

	if (gw->summed_stats.n.cd == 0 ||
	        gw->summed_stats.n.cd < qr_min_samples_acd) {
		lock_stop_read(gw->ref_lock);
		return -1;
	}

	acd = (double)gw->summed_stats.stats.cd / gw->summed_stats.n.cd;
	lock_stop_read(gw->ref_lock);

	return acd;
}

/* compute the value of an extra stat */
static inline double get_xstat(qr_gw_t *gw, int idx, int *samples)
{
	double val;

	lock_start_read(gw->ref_lock);
	*samples = gw->summed_stats.n.xtot[idx];

	if (gw->summed_stats.n.xtot[idx] == 0 ||
	        gw->summed_stats.n.xtot[idx] < qr_xstats[idx].min_samples) {
		lock_stop_read(gw->ref_lock);
		return -1;
	}

	val = (double)gw->summed_stats.stats.xsum[idx] /
	              gw->summed_stats.n.xtot[idx];
	lock_stop_read(gw->ref_lock);

	return val;
}

double _qr_score_gw_dw(qr_gw_t *gw, qr_profile_t *prof,
                       str *part, int rule_id, int *disabled);
double _qr_score_gw_bdf(qr_gw_t *gw, qr_profile_t *prof,
                        str *part, int rule_id, int *disabled);

void qr_sort_dynamic_weights(void *param);
void qr_sort_best_dest_first(void *param);
#endif
