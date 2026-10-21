/*
 * clusterer_controller - module statistics: declarations
 *
 * Copyright (C) 2026 Yury Kirsanov
 *                          VoIPLine Telecom
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

/* Register cluster @cl's statistics (mod_init). */
int  cl_ctr_stats_register(cl_ctr_cluster_t *cl);

/* Where cluster state changes, the code says so: each call counts for the
 * statistics.  Worker only, with or without the peers lock held. */
void cl_ctr_note_role(cl_ctr_cluster_t *cl, int old_role, int new_role);
void cl_ctr_note_master(cl_ctr_cluster_t *cl, const char *master_ip);
void cl_ctr_note_member(cl_ctr_cluster_t *cl, const char *ip, uint16_t node_id,
                        int joined, const char *reason);
void cl_ctr_note_join_refused(cl_ctr_cluster_t *cl, const char *ip,
                              const char *reason);
void cl_ctr_note_config_mismatch(cl_ctr_cluster_t *cl, const char *ip);
void cl_ctr_note_auth_failure(cl_ctr_cluster_t *cl, const char *ip);
void cl_ctr_note_merge(cl_ctr_cluster_t *cl, const char *superior_ip,
                       int was_master);

#endif /* CL_CTR_STATS_H */
