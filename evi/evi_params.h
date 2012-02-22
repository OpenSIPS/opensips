/*
 * Copyright (C) 2011 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *
 * history:
 * ---------
 *  2011-05-xx  created (razvancrainea)
 */

#ifndef _EVI_PARAMS_H_
#define _EVI_PARAMS_H_

#include "../str.h"

#define EVI_INT_VAL		0x01	/* val is int */
#define EVI_STR_VAL		0x02	/* val is str */

#define EVI_FREE_LIST	(1<<31)	/* should free params list */

typedef struct evi_param_ {
	int flags;
	union {
		int n;
		str s;
	} val;
	str name;
	struct evi_param_ *next;
} evi_param_t, *evi_param_p;

/*
 * Remember to initilize this structure with 0
 * or use the functions below to alloc and free it
 */
typedef struct evi_params_ {
	int flags;
	evi_param_p first;
	evi_param_p last;
} evi_params_t, *evi_params_p;

/* used to build parameters list */
evi_params_p evi_get_params(void);
/* frees all parameters */
void evi_free_params(evi_params_p);

/* generic parameter add */
int evi_param_add(evi_params_p list, str *name, void *param, int flags);

/* adds an integer to the list */
#define evi_param_add_int(p_list, p_name, p_int) \
		evi_param_add(p_list, p_name, p_int, EVI_INT_VAL)

/* adds a string to the list */
#define evi_param_add_str(p_list, p_name, p_str) \
		evi_param_add(p_list, p_name, p_str, EVI_STR_VAL)

#endif
