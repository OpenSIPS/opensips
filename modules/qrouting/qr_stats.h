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


extern int qr_n; /* number of intervals in history */
extern int* n_sampled;

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
	int id;
	str name;
	double asr1, asr2;
	double ccr1, ccr2;
	double pdd1, pdd2;
	double ast1, ast2;
	double acd1, acd2;
} qr_thresholds_t;

/* history for gateway: sum of sampled intervals */
typedef struct qr_gw {
	qr_sample_t * next_interval; /* sampled intervals */
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
	void *dr_cr;
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
	qr_thresholds_t *thresholds;
	int r_id;/* rule_id */
	char sort_method; /* sorting for the rule */
	int n;
	struct qr_rule *next;
} qr_rule_t;

typedef struct qr_partitions {
	qr_rule_t **qr_rules_start; /* an array of partition - each partition
								   contains rules */
	int n_parts; /* the number of partitions */
	str *part_name;
	rw_lock_t *rw_lock; /* protect the partitions for reloading */
}qr_partitions_t;

extern qr_rule_t ** qr_rules_start; /* used when updating statistics */
extern rw_lock_t ** rw_lock_qr;
extern qr_thresholds_t **qr_profiles;/* profiles from db */
extern int *n_qr_profiles; /* the number of profiles from db */
extern qr_partitions_t **qr_main_list;

qr_gw_t *  qr_create_gw(void *);
void qr_free_gw(qr_gw_t *);
void qr_dst_is_grp(void *param);
void qr_create_rule(void *param);
void qr_add_rule_to_list(void *param);
void test_callback(int types, struct dr_cb_params *param);
void qr_dst_is_gw(void *param);
void qr_search_profile(void *param);
void qr_mark_as_main_list(void *param);
void qr_link_rule_list(void *param);
void qr_create_partition_list(void *param);
void free_qr_cb(void *param);
void free_qr_list(qr_partitions_t *qr_parts);

#endif
