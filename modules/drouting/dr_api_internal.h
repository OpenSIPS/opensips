/**
 * drouting module developer api
 *
 * Copyright (C) 2014 OpenSIPS Foundation
 * Copyright (C) 2015-2020 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

#ifndef _DROUTING_INTERNAL_API_H_
#define _DROUTING_INTERNAL_API_H_

#include "dr_api.h"

int load_dr (struct dr_binds *drb);
rt_info_t* find_rule_by_prefix_unsafe(ptree_t *pt, ptree_node_t *noprefix,
		str prefix, unsigned int grp_id, unsigned int *matched_len);

#endif
