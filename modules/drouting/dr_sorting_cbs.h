/**
 *
 * drouting module sorting callbacks header
 *
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
 *  2014-10-10  initial version (Mihai Tiganus)
*/

#ifndef _DR_SORTING_CBS_H_
#define _DR_SORTING_CBS_H_
#include "dr_cb.h"

/* The maximum number of sorting functions provided by dr */
#define N_MAX_SORT_CBS 4

/* callback types used by QR*/
#define DRCB_REG_INIT_RULE (1<<0)
#define DRCB_REG_GW (1<<1)
#define DRCB_REG_CR (1<<2)
#define DRCB_REG_ADD_RULE (1<<3)
#define DRCB_ACC_CALL (1<<4)
#define DRCB_SORT_DST (1<<5)

struct dr_head_cbl *dr_reg_cbs, *dr_acc_cbs;

/* if new callbacks are added you must increase the N_MAX_SORT_CBS
 * constant accordingly, add the letter which will be provided in the db
 * to the sort_algs array, add the corresponding sorting algorithm id to the
 * enum an register the callback to the dr_sort_cbs in the appropriate position*/


/* used for mapping the db information (sort_alg = a letter) to an index
 * in the sort_cb_type enum */
extern unsigned char sort_algs[N_MAX_SORT_CBS];

typedef enum { NO_SORT = 1, WEIGHT_BASED_SORT = 2, QR_BASED_SORT = 3} sort_cb_type;

/* an array of sorting cbs registered by different modules */
struct dr_callback *dr_sort_cbs[N_MAX_SORT_CBS];

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
};

struct dr_acc_call_params {
	void *rule; /* qr_handler/rule */
	int cr_id; /* destination id */
	int gw_id; /* in the case the destination is a carrier */
	struct sip_msg *msg;
};

struct dr_sort_params {
	rt_info_t *dr_rule; /* dr_rule which contains the dst to be sorted */
	int dst_id; /* the size of pgwl */
	unsigned short *sorted_dst; /* returns an array with the indexes of the sorted dest */
	int rc; /* return code for the funciton */
};

#endif


