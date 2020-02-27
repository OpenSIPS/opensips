/**
 *
 * drouting module sorting callbacks header
 *
 * Copyright (C) 2014-2020 OpenSIPS Solutions
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

#ifndef _DR_CB_SORTING_H_
#define _DR_CB_SORTING_H_

#include "prefix_tree.h"

struct rt_info_;

/* if new callbacks are added you must increase the N_MAX_SORT_CBS
 * constant accordingly, add the letter which will be provided in the db
 * to the sort_algs array, add the corresponding sorting algorithm id to the
 * enum an register the callback to the dr_sort_cbs in the appropriate position*/

typedef enum {
	NO_SORT,
	WEIGHT_BASED_SORT,
	QR_BASED_SORT,

	N_MAX_SORT_CBS = 3
} sort_cb_type;

/* used for mapping the db information (sort_alg = a letter) to an index
 * in the sort_cb_type enum */
extern unsigned char sort_algs[N_MAX_SORT_CBS];

static inline sort_cb_type dr_get_sort_alg(char alg) {
	unsigned char *p = memchr(sort_algs, alg, N_MAX_SORT_CBS);
	return !p ? NO_SORT : (sort_cb_type)(p - sort_algs);
}

/* parameters needed for the registration of a gw */
struct dr_reg_param {
	void *rule;
	int n_dst; /* the index of the destination within the rule */
	void *cr_or_gw;
};

struct dr_reg_init_rule_params {
	void *rule; /* created at qr, set to dr */

	int n_dst; /* the number of destination for the new rule;
				  sent by dr */
	int r_id; /* the rule id: sent by dr */
	int qr_profile; /* sent by dr */
};

struct dr_acc_call_params {
	struct sip_msg *msg;
	int cr_id; /* destination id */
	int gw_id; /* in the case the destination is a carrier */

	void *rule; /* qr_handler/rule */
	void *data; /* holder for module-specific information */
};

struct dr_sort_params {
	struct rt_info_ *dr_rule; /* dr_rule which contains the dst to be sorted */

	/* -1 for rule gwlist sort, carrier dst index for carrier gwlist sort */
	unsigned short dst_idx;

	/* output (pre-allocated): sorted array of dst indexes */
	unsigned short *sorted_dst;

	/* output: return code of the callback (0: success) */
	int rc;
};

struct dr_prepare_part_params {
	str part_name;
};

struct dr_link_rule_params {
	void *qr_rule; /* rule to be added to list */
};

typedef void (*dr_sort_cb) (void *param);
int run_dr_sort_cbs(sort_cb_type type, struct dr_sort_params *param);

#endif
