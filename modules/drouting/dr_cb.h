/**
 *
 * drouting module callbacks header
 *
 * Copyright (C) 2014-2106 OpenSIPS Foundation
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
 *  2014-09-24  initial version (Mihai Tiganus)
 *  2016-02-18  ported to 2.2 (bogdan)
 */


#ifndef _DR_CB_H_
#define _DR_CB_H_

/* callback types used on top of DRouting */
enum drcb_types {
	DRCB_REG_CREATE_PARTS_LIST /* create a partitions list */,
	/* params: */
	DRCB_REG_INIT_RULE,
	DRCB_REG_GW,
	DRCB_REG_CR,
	DRCB_REG_ADD_RULE,
	DRCB_REG_MARK_AS_RULE_LIST,
	DRCB_REG_LINK_LISTS,
	DRCB_REG_FREE_LIST,
	DRCB_ACC_CALL,
	DRCB_SORT_DST,
	DRCB_SET_PROFILE,
	DRCB_MAX /*keep this at the end*/
};

/* callback function prototype */
typedef void (dr_cb) (void *param);
/* function to free callback param */
typedef void(dr_param_free_cb) (void *param);

/* register callback function protoype */
typedef int (*register_drcb_f)(enum drcb_types, dr_cb f, void *param,
		dr_param_free_cb ff);
typedef int (*register_drcb_to_array_f)(enum drcb_types, dr_cb f,
		void *param, dr_param_free_cb ff);

struct dr_callback {
	dr_cb* callback;
	void *param;
	dr_param_free_cb* callback_param_free;
	struct dr_callback * next;
};


/* sorting related data */

/* if new callbacks are added you must increase the N_MAX_SORT_CBS
 * constant accordingly, add the letter which will be provided in the db
 * to the sort_algs array, add the corresponding sorting algorithm id to the
 * enum an register the callback to the dr_sort_cbs in the appropriate position*/

/* The maximum number of sorting functions provided by dr */
#define N_MAX_SORT_CBS 4

typedef enum { NO_SORT = 1, WEIGHT_BASED_SORT = 2, QR_BASED_SORT = 3}
	sort_cb_type;

/* used for mapping the db information (sort_alg = a letter) to an index
 * in the sort_cb_type enum */
extern unsigned char sort_algs[N_MAX_SORT_CBS];


int register_dr_cb(enum drcb_types type, dr_cb f, void *param,
		dr_param_free_cb ff);
int run_dr_cbs(enum drcb_types type, void *params);
int run_dr_sort_cbs( sort_cb_type type, void *params);
void destroy_dr_cbs(void);

#endif

