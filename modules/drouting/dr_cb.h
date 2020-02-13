/**
 *
 * drouting module callbacks header
 *
 * Copyright (C) 2014-2020 OpenSIPS Foundation
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

#ifndef _DR_CB_H_
#define _DR_CB_H_

/* callback types used on top of DRouting */
enum drcb_types {
	DRCB_RLD_PREPARE_PART /* prepare to reload a new partition */,
	DRCB_RLD_INIT_RULE,
	DRCB_RLD_GW,
	DRCB_RLD_CR,
	DRCB_RLD_LINK_RULE,
	DRCB_RLD_FINALIZE, /* finalize the entire reload (1+ partitions) */

	DRCB_ACC_CALL,

	DRCB_SORT_DST,

	DRCB_MAX /* keep this at the end */
};

#include "prefix_tree.h"
#include "dr_cb_sorting.h"

#define POINTER_CLOSED_MARKER  ((void *)(-1))

/* callback function prototype */
typedef void (*dr_cb) (void *param);
/* function to free callback param */
typedef void (*dr_param_free_cb) (void *param);

/* register callback function protoype */
typedef int (*register_drcb_f)(enum drcb_types, dr_cb f, void *param,
		dr_param_free_cb ff);
typedef int (*register_drcb_to_array_f)(enum drcb_types, dr_cb f,
		void *param, dr_param_free_cb ff);

struct dr_callback {
	dr_cb callback;
	void *param;
	dr_param_free_cb callback_param_free;
	struct dr_callback *next;
};

int register_dr_cb(enum drcb_types type, dr_cb f, void *param,
		dr_param_free_cb ff);
int run_dr_cbs(enum drcb_types type, void *param);
void destroy_dr_cbs(void);

#endif
