/*
 * clusterer_controller - this node's identity, and the node id it proposes
 *
 * Copyright (C) 2026 Yury Kirsanov
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

#ifndef CL_CTR_IDENTITY_H
#define CL_CTR_IDENTITY_H

#include <stdint.h>

#define CL_CTR_IDENTITY_SZ  16

/* hash of the machine id (SMBIOS UUID, else first MAC, else random) and the
 * controller address: one per instance, stable across restarts */
extern unsigned char cl_ctr_identity[CL_CTR_IDENTITY_SZ];
extern const char   *cl_ctr_identity_src;   /* "smbios", "mac", "random" */

/* the node id this node asks for when it joins, or founds a cluster under:
 * my_node_id when set, else one taken from the identity (1..CL_CTR_MAX_PEERS) */
extern uint16_t      cl_ctr_proposal;

/* after my_ip is resolved; @configured is clusterer's my_node_id (<1: unset) */
void cl_ctr_identity_init(int configured);

/* the id an identity proposes: 1..@range, FNV-1a over its bytes */
uint16_t cl_ctr_identity_proposal(const unsigned char *id, int range);

#endif /* CL_CTR_IDENTITY_H */
