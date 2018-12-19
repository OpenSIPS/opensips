/**
 * Copyright (C) 2012 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

#ifndef _LB_BL_H_
#define _LB_BL_H_

#include "../../blacklists.h"
#include "lb_data.h"
#include "../../parser/parse_uri.h"
#include "../../resolve.h"

#define LB_BL_MAX_SETS		32

extern struct lb_data **curr_data;

struct lb_bl {
	unsigned int no_groups;
	unsigned int groups[LB_BL_MAX_SETS];
	struct bl_head *bl;
	struct lb_bl *next;
};

int set_lb_bl(modparam_t type, void *val);

int init_lb_bls(void);

void destroy_lb_bls(void);

int populate_lb_bls(struct lb_dst *dst);

#endif /* _LB_BL_H_ */

