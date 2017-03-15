/*
 * Copyright (C) 2017 OpenSIPS Project
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
 */

#ifndef _LB_REPLICATION_H_
#define _LB_REPLICATION_H_

#include "../../sr_module.h"
#include "../../bin_interface.h"
#include "../clusterer/api.h"

#define BIN_VERSION 1

#define REPL_LB_STATUS_UPDATE 1

extern str repl_lb_module_name;
extern struct clusterer_binds clusterer_api;

extern int accept_replicated_status;
extern int replicated_status_cluster;

/* replicate the LB status via BIN */
void replicate_lb_status(struct lb_dst *dst);

/* handler for incoming BIN packets */
int replicate_lb_status_update(bin_packet_t *packet, struct lb_data *data);

#endif
