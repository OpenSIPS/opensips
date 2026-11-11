/*
 * clusterer_controller - module statistics: declarations
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

#ifndef CL_CTR_STATS_H
#define CL_CTR_STATS_H

#include "cl_ctr.h"

/* mod_init, once @cl's peer table and lock exist */
int  cl_ctr_stats_register(cl_ctr_cluster_t *cl);

/* called where cluster state changes: count it and queue its event; worker
 * only, peers lock held or not */

/* this node's own role changed (CL_CTR_ROLE_*) */
void cl_ctr_note_role(cl_ctr_cluster_t *cl, int old_role, int new_role);
/* the master changed to @master_ip, as this node sees it */
void cl_ctr_note_master(cl_ctr_cluster_t *cl, const char *master_ip,
                        uint16_t node_id);
/* a node entered (@joined) or left this node's peer table, for @reason */
void cl_ctr_note_member(cl_ctr_cluster_t *cl, const char *ip, uint16_t node_id,
                        int joined, const char *reason);
/* the master moved @ip to admission @state: "connecting", "online", "stuck" */
void cl_ctr_note_admission(cl_ctr_cluster_t *cl, const char *ip, uint16_t node_id,
                           const char *state);
/* this master refused @ip's JOIN_REQ */
void cl_ctr_note_join_refused(cl_ctr_cluster_t *cl, const char *ip,
                              const char *reason);
/* @ip advertises settings that differ from this node's */
void cl_ctr_note_config_mismatch(cl_ctr_cluster_t *cl, const char *ip);
void cl_ctr_note_auth_failure(cl_ctr_cluster_t *cl, const char *ip);
/* this node left its partition for @superior_ip's */
void cl_ctr_note_merge(cl_ctr_cluster_t *cl, const char *superior_ip,
                       int was_master);

#endif /* CL_CTR_STATS_H */
