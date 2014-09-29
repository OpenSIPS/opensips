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


int qr_add_gw_to_list(qr_sorted_list_t **sorted_list, qr_gw_t *gw) {
	qr_sorted_elem_t *new_elem = (qr_sorted_elem_t*)shm_malloc(
			sizeof(qr_sorted_elem_t));
	if(new_elem == NULL) {
		LM_ERR("no more shm memory\n");
		return -1;
	}


	memset(new_elem, 0, sizeof(qr_sorted_elem_t));
	new_elem->dr_gw = gw->dr_gw;

	if(sorted_list[gw->score]->start == NULL) { /* list was empty */
		sorted_list[gw->score]->start = new_elem;
	} else { /* list was not empty */
		sorted_list[gw->score]->end->next = new_elem;
	}

	sorted_list[gw->score]->end = new_elem;

	return 0;

}

/* compute answer seizure ratio for gw */
inline double asr(qr_gw_t *gw) {
	double asr;
	lock_start_read(gw->ref_lock);
	if(gw->history_stats.n.ok == 0) {
		lock_stop_read(gw->ref_lock);
		return 0;
	}
	asr = gw->history_stats.stats.as/gw->history_stats.n.ok;
	lock_stop_read(gw->ref_lock);
	return asr;
}

/* compute completed calls ratio for gw */
inline double ccr(qr_gw_t *gw) {
	double ccr;
	lock_start_read(gw->ref_lock);
	if(gw->history_stats.n.ok == 0) {
		lock_stop_read(gw->ref_lock);
		return 0;
	}
	ccr = gw->history_stats.stats.cc/gw->history_stats.n.ok;
	lock_stop_read(gw->ref_lock);
	return ccr;
}

/* compute post dial delay for gw */
inline double pdd(qr_gw_t *gw) {
	double pdd;
	lock_start_read(gw->ref_lock);
	if(gw->history_stats.n.pdd == 0) {
		lock_stop_read(gw->ref_lock);
		return 0;
	}
	pdd = gw->history_stats.stats.pdd/gw->history_stats.n.pdd;
	lock_stop_read(gw->ref_lock);
	return pdd;
}

/* compute average setup time for gw */
inline double ast(qr_gw_t *gw) {
	double ast;
	lock_start_read(gw->ref_lock);
	if(gw->history_stats.n.setup == 0) {
		lock_stop_read(gw->ref_lock);
		return 0;
	}
	ast = gw->history_stats.stats.st/gw->history_stats.n.setup;
	lock_stop_read(gw->ref_lock);
	return ast;
}

/* compute average call duration for gw */
inline double acd(qr_gw_t *gw) {
	double acd;
	lock_start_read(gw->ref_lock);
	if(gw->history_stats.n.cd == 0) {
		lock_stop_read(gw->ref_lock);
		return 0;
	}
	acd = gw->history_stats.stats.cd/gw->history_stats.n.cd;
	lock_stop_read(gw->ref_lock);
	return acd;
}
/*
 * computes the score of the gateway using the warning
 * thresholds
 */
void qr_score(qr_gw_t *gw, qr_thresholds_t * thresholds) {
	int score = 0;
	/* FIXME: might be better under a single lock
	 * because of possible changes between lock ( a
	 * new sampling interval might bring new statistics)
	 */
	if(asr(gw)<thresholds->asr1)
		++score;
	if(ccr(gw)<thresholds->ccr1)
		++score;
	if(pdd(gw)>thresholds->pdd1)
		++score;
	if(ast(gw)>thresholds->ast1)
		++score;
	if(acd(gw)>thresholds->acd1)
		++score;

	/* update gw score and status */
	lock_start_write(gw->ref_lock);
	gw->score = score;
	gw->state &= ~QR_STATUS_DIRTY;
	lock_stop_write(gw->ref_lock);
}
/*
 * inserts destination in sorted list
 */
inline int qr_insert_dst(qr_sorted_list_t **sorted, qr_rule_t *rule,
		int dst_id) {
	if(rule->dest[dst_id].type & QR_DST_GRP) {
		return -1; /* TODO group support
						should accept multiple
						sorting methods*/
	}
	lock_start_read(rule->dest[dst_id].dst.gw->ref_lock);
	if(rule->dest[dst_id].dst.gw->state & QR_STATUS_DIRTY) {
		lock_stop_read(rule->dest[dst_id].dst.gw->ref_lock);
		qr_score(rule->dest[dst_id].dst.gw, &rule->thresholds); /* compute the
																   score */
		rule->dest[dst_id].dst.gw->state &= ~QR_STATUS_DIRTY;
	} else {
		lock_stop_read(rule->dest[dst_id].dst.gw->ref_lock);
	}
	qr_add_gw_to_list(sorted,rule->dest[dst_id].dst.gw); /* insert into sorted
															list */


	return 0;
}


