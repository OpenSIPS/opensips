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
#include "../drouting/prefix_tree.h"
#include "../drouting/dr_cb.h"

/* type of destinations */
#define QR_DST_GW (1<<0)
#define QR_DST_GRP (1<<1) /* group more destinations together */
/* states for gateways */
#define QR_STATUS_DIRTY (1<<0)
#define QR_STATUS_DSBL (1<<1)
#define QR_STATUS_SKIP (1<<2)
/* sort methods */
#define QR_SORT_QR (1<<0)
#define MIN_DEST 4


int qr_n; /* number of intervals in history */

/* number of calls accounted for each statistic */
typedef struct qr_n_calls {
	double ok, pdd, setup, cd;
} qr_n_calls_t;

typedef struct qr_calls {
	double as; /* calls that returned 200OK */
	double cc; /* calls that returned 200OK + 4XX */
	double pdd; /* total post dial delay for sampled interval */
	double st; /* total setup time for sampled interval */
	double cd; /* total call duration for sampled interval */
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
	double asr1, asr2;
	double ccr1, ccr2;
	double pdd1, pdd2;
	double ast1, ast2;
	double acd1, acd2;
} qr_thresholds_t;

/* history for gateway: sum of sampled intervals */
typedef struct qr_gw {
	qr_sample_t * next_interval; /* sampled intervals */
	int n_sampled; /* number of intervals sampled */
	void  *dr_gw; /* pointer to the gateway from drouting*/
	qr_stats_t current_interval; /* the current interval */
	qr_stats_t history_stats; /* the statistcs for all the intervals */
	char state; /* the state of the gateway: dirty/disabled */
	int score; /* the score of the gateway (based on thresholds) */
	rw_lock_t *ref_lock; /* lock for protecting the overall statistics (history) */
	gen_lock_t *acc_lock; /* lock for protecting the current interval */
} qr_gw_t;

/* destination that are grouped (e.g.: carriers) */
typedef struct qr_grp {
	qr_gw_t **gw;
	char sort_method; /* sorting for the group */
	str *id;
	int score;
	char state;
	rw_lock_t *ref_lock;
	int n;
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
	qr_thresholds_t thresholds;
	int r_id;/* rule_id */
	char sort_method; /* sorting for the rule */
	int n;
	struct qr_rule *next;
} qr_rule_t;

extern qr_rule_t ** qr_rules_start; /* used when updating statistics */

qr_gw_t *  qr_create_gw(void *);
void qr_free_gw(qr_gw_t *);
void qr_dst_is_grp(int, struct dr_cb_params*);
void qr_create_rule(int, struct dr_cb_params*);
void qr_add_rule(int , struct dr_cb_params*);
void test_callback(int types, struct dr_cb_params *param);
void qr_dst_is_gw(int type, struct dr_cb_params *param);


#endif
