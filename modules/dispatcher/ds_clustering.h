/*
 * Copyright (C) 2018 OpenSIPS Project
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

#ifndef _DISPATCHER_CLUSTERING_H_
#define _DISPATCHER_CLUSTERING_H_

#include "../../sr_module.h"
#include "../../bin_interface.h"
#include "../clusterer/api.h"

extern int ds_cluster_id;
extern str ds_cluster_shtag;

int ds_init_cluster(void);

/* checks if the sharing tag is on active */
int ds_cluster_shtag_is_active(void);

/* replicate the destination status via BIN */
void replicate_ds_status_event(str *partition, int group, str *address,
		int state, int type);

/* request sync of destinations states from cluster */
int ds_cluster_sync(void);

#endif
