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

#ifndef _QR_SORT_H_
#define _QR_SORT_H_

#include "../drouting/prefix_tree.h"
#include "qr_stats.h"


/*
 * dictionary-like-structure which contains
 * a sorted list of gateways
 */
typedef struct qr_sorted_list {
	int dst_id;
	struct qr_sorted_list *next;
}qr_sorted_list_t;

int qr_add_dst_to_list(qr_sorted_list_t **sorted_list, int dst_id, int score);

/* compute answer seizure ratio for gw */
static inline double asr(qr_gw_t *gw) {
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
static inline double ccr(qr_gw_t *gw) {
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
static inline double pdd(qr_gw_t *gw) {
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
static inline double ast(qr_gw_t *gw) {
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
static inline double acd(qr_gw_t *gw) {
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

/*
 * computes the score of the gateway using the warning
 * thresholds
 */
void qr_score(qr_gw_t *gw, qr_thresholds_t * thresholds);/*
 * inserts destination in sorted list
 */
void qr_sort(void *param);
int qr_insert_dst(qr_sorted_list_t **sorted, qr_rule_t *rule,
		int cr_id, int gw_id);
#endif
