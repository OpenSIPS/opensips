/**
 *
 * qrouting module: qr_stats.h
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
#ifndef _QR_STATS_
#define _QR_STATS_

#include "../../rw_locking.h"
#include "../../locking.h"

/* type of destinations */
#define QR_DST_GW (1<<0)
#define QR_DST_GRP (1<<1) /* group more destinations together */
/* states for gateways */
#define QR_STATUS_DIRTY (1<<0)
#define QR_STATUS_DSBL (1<<1)
#define QR_STATUS_SKIP (1<<2)
#define MIN_DEST 4


int qr_n; /* number of intervals in history */

/* number of calls accounted for each statistic */
typedef struct qr_n_calls {
	int ok, pdd, setup, cd;
} qr_n_calls_t;

typedef struct qr_calls {
	int as; /* calls that returned 200OK */
	int cc; /* calls that returned 200OK + 4XX */
	int pdd; /* total post dial delay for sampled interval */
	int st; /* total setup time for sampled interval */
	int cd; /* total call duration for sampled interval */
} qr_calls_t;

typedef struct qr_stats {
	qr_n_calls_t n;
	qr_calls_t stats;
} qr_stats_t;

/* sample interval */
typedef struct qr_sample {
	qr_stats_t calls;
	struct qr_sample *next;
} qr_sample_t;

/* thresholds */
typedef struct qr_thresholds {
	int as1, as2;
	int cc1, cc2;
	int pdd1, pdd2;
	int st1, st2;
	int cd1, cd2;
} qr_thresholds_t;

/* history for gateway: sum of sampled intervals */
typedef struct qr_gw {
	qr_sample_t * next_interval;
	int n_sampled;
	qr_stats_t current_interval;
	qr_stats_t last_interval;
	qr_stats_t history_stats;
	char state;
	rw_lock_t *ref_lock;
	gen_lock_t *acc_lock;
} qr_gw_t;

/* destination that are grouped (e.g.: carriers) */
typedef struct qr_grp {
	qr_gw_t **gw;
} qr_grp_t;


/* two types of destination */
typedef struct qr_dst {
	union {
		qr_gw_t  * gw;
		qr_grp_t  grp;
	} dst;
	char type;
} qr_dst_t;

/* destinations associated with a rule */
typedef struct qr_rule {
	qr_dst_t *dest;
	qr_thresholds_t threshold;
	struct qr_rule *next;
} qr_rule_t;

qr_gw_t * qr_create_gw(void);
void qr_free_gw(qr_gw_t *);
int qr_dst_is_grp(void *, int, int);
void *qr_create_rule(int);
void qr_add_rule(void*);



#endif
