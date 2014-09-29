/**
 *
 * qrouting module:qr_sort.h
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
#ifndef _QR_SORT_H_
#define _QR_SORT_H_

#include "../drouting/prefix_tree.h"
#include "qr_stats.h"


/*
 * dictionary-like-structure which contains
 * a sorted list of gateways
 */
typedef struct qr_sorted_elem {
	pgw_t *dr_gw; /* destination */
	struct qr_sorted_elem *next; /* next destination with the same score */
} qr_sorted_elem_t;

typedef struct qr_sorted_list {
	qr_sorted_elem_t *start, *end;
}qr_sorted_list_t;

int qr_add_gw_to_list(qr_sorted_list_t **sorted_list, qr_gw_t *gw);

/* compute answer seizure ratio for gw */
inline double asr(qr_gw_t *gw);

/* compute completed calls ratio for gw */
inline double ccr(qr_gw_t *gw);

/* compute post dial delay for gw */
inline double pdd(qr_gw_t *gw);

/* compute average setup time for gw */
inline double ast(qr_gw_t *gw);

/* compute average call duration for gw */
inline double acd(qr_gw_t *gw);
/*
 * computes the score of the gateway using the warning
 * thresholds
 */
void qr_score(qr_gw_t *gw, qr_thresholds_t * thresholds);/*
 * inserts destination in sorted list
 */
inline int qr_insert_dst(qr_sorted_list_t **sorted, qr_rule_t *rule,
		int dst_id);
#endif

