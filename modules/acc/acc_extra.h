/*
 * Copyright (C) 2004 Voice Sistem SRL
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *
 * History:
 * ---------
 *  2004-10-28  first version (ramona)
 *  2005-05-30  acc_extra patch commited (ramona)
 *  2005-07-13  acc_extra specification moved to use pseudo-variables (bogdan)
 *  2006-09-08  flexible multi leg accounting support added,
 *              code cleanup for low level functions (bogdan)
 *  2006-09-19  final stage of a masive re-structuring and cleanup (bogdan)
 */


#ifndef _ACC_EXTRA_H_
#define _ACC_EXTRA_H_

#include "../../str.h"
#include "../../pvar.h"
#include "../../parser/msg_parser.h"
#include "../../sr_module.h"
#include "acc_logic.h"

#define ACC_INT_VALUE (1 << 0)
#define ACC_STR_VALUE (1 << 1)


struct acc_extra {
	int tag_idx;

	str name; /* log value(column/avp etc. name) */

	struct acc_extra *next;    /* next extra value */
};

/*
 * this protects multiple processes from accessing
 * acc_leg/acc_extra values
 */
#define accX_lock(__S__) lock_get(__S__)
#define accX_unlock(__S__) lock_release(__S__)

/* the factor with which will realloc the tags array */
#define TAGS_FACTOR 5
typedef str tag_t;


#define MAX_ACC_EXTRA 64
#define MAX_ACC_LEG   16
#define MAX_ACC_BUFS  3


void init_acc_extra();

int parse_acc_extra(modparam_t type, void* val);

int build_acc_extra_array(int tags_len, extra_value_t** array_p);
int build_acc_extra_array_pkg(int tags_len, extra_value_t** array_p);

int push_leg(acc_ctx_t* ctx);

int parse_acc_leg(modparam_t type, void* val);

void destroy_extras( struct acc_extra *extra);

int extra2strar( extra_value_t* values, str *val_arr, int idx);

int extra2int( struct acc_extra *extra, int *attrs );

#include "../../aaa/aaa.h"
int extra2attrs( struct acc_extra *extra, aaa_map *attrs, int offset);
#endif

