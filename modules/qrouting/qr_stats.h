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

#ifndef _QR_STATS_
#define _QR_STATS_

#include "../../rw_locking.h"
#include "../../locking.h"
#include "../drouting/prefix_tree.h"
#include "../drouting/dr_cb.h"

#include "qr_load.h"

/* type of destinations */
#define QR_DST_GW (1<<0)
#define QR_DST_GRP (1<<1) /* group more destinations together */
/* states for gateways */
#define QR_STATUS_DIRTY (1<<0)
#define QR_STATUS_DSBL  (1<<1)
#define QR_STATUS_SKIP  (1<<2)
/* sort methods */
#define QR_SORT_QR (1<<0)
#define MIN_DEST 4

#define QR_PTR_POISON ((void *)0x10203040)

#define QR_MAX_XSTATS 5

/* number of calls accounted for each statistic */
typedef struct qr_n_calls {
	double ok, pdd, setup, cd;
	double xtot[QR_MAX_XSTATS]; /* "total" counters for each extra stat */
} qr_n_calls_t;

typedef struct qr_calls {
	double as; /* calls that returned 200OK */
	double cc; /* calls that returned 200OK + 4XX */
	double pdd; /* total post dial delay for sampled interval */
	double st; /* total setup time for sampled interval */
	double cd; /* total call duration for sampled interval */

	double xsum[QR_MAX_XSTATS]; /* sums for each extra stat */
} qr_calls_t;

typedef struct qr_stats {
	qr_n_calls_t n;
	qr_calls_t stats;
} qr_stats_t;

typedef struct qr_xstat {
	double thr1, thr2;
	double pty1, pty2;
} qr_xstat_t;

/* sample interval */
typedef struct qr_sample {
	qr_stats_t calls;
	struct qr_sample *next;
} qr_sample_t;

typedef struct qr_profile {
	int id;
	char name[QR_NAME_COL_SZ + 1];
	double asr1, asr_pty1, asr2, asr_pty2;
	double ccr1, ccr_pty1, ccr2, ccr_pty2;
	double pdd1, pdd_pty1, pdd2, pdd_pty2;
	double ast1, ast_pty1, ast2, ast_pty2;
	double acd1, acd_pty1, acd2, acd_pty2;

	qr_xstat_t xstats[QR_MAX_XSTATS];
} qr_profile_t;

/* history for gateway: sum of sampled intervals */
typedef struct qr_gw {
	/* circular list of sampled stats (constant size),
	 * always points to the least recently updated sample */
	qr_sample_t *lru_interval;

	void  *dr_gw; /* pointer to the gateway from drouting*/
	qr_stats_t current_interval; /* the current interval */
	qr_stats_t summed_stats; /* the sum of the @lru_interval list */
	char state;
	double score; /* score of the gateway, based on thresholds & penalties */
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
		qr_gw_t  *gw;
		qr_grp_t  grp;
	};
	char type;
} qr_dst_t;

/* destinations associated with a rule */
typedef struct qr_rule {
	qr_dst_t *dest;
	qr_profile_t *profile;
	int r_id;/* rule_id */
	char sort_method; /* sorting for the rule */
	int n;
	str *part_name; /* backpointer, don't free */
	struct qr_rule *next;
} qr_rule_t;

typedef struct qr_partitions {
	qr_rule_t **qr_rules_start; /* an array of partition - each partition
								   contains rules */
	int n_parts; /* the number of partitions */
	str *part_name; /* backpointer, don't free */
	rw_lock_t *rw_lock; /* protect the partitions for reloading */
} qr_partitions_t;

extern rw_lock_t *qr_main_list_rwl;
extern qr_profile_t **qr_profiles;
extern int *qr_profiles_n;
extern qr_partitions_t **qr_main_list;

extern str qr_param_part;
extern str qr_param_rule_id;
extern str qr_param_dst_name;

/* returns the linked list of rules for a certain partition */
qr_rule_t *qr_get_rules(str *part_name);
/* searches for a given rule in the QR list */
qr_rule_t *qr_search_rule(qr_rule_t *list, int r_id);
qr_gw_t *qr_search_gw(qr_rule_t *list, str *gw_name);

qr_gw_t *  qr_create_gw(void *);
void qr_free_gw(qr_gw_t *);
void free_qr_list(qr_partitions_t *qr_parts);

void qr_rld_prepare_part(void *param);
void qr_rld_create_rule(void *param);
void qr_rld_dst_is_gw(void *param);
void qr_rld_dst_is_grp(void *param);
void qr_rld_link_rule(void *param);
void qr_rld_finalize(void *param);

#endif
