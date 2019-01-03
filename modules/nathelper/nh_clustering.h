/*
 * Copyright (C) 2019 OpenSIPS Project
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
 * Foundation Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

#ifndef _NATHELPER_CLUSTERING_H_
#define _NATHELPER_CLUSTERING_H_

#include "../../sr_module.h"
#include "../../bin_interface.h"
#include "../clusterer/api.h"

extern int nh_cluster_id;
extern str nh_cluster_shtag;

int nh_init_cluster(void);

/* checks if the sharing tag is on active */
int nh_cluster_shtag_is_active(void);

#endif
