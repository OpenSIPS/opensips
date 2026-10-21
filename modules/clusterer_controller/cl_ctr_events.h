/*
 * clusterer_controller - events: declarations
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

#ifndef CL_CTR_EVENTS_H
#define CL_CTR_EVENTS_H

#include "cl_ctr.h"

/* Publish the cluster-state events (mod_init). */
int  cl_ctr_events_init(void);

/* Queue an event where the state changes - with the peers lock held or not;
 * the worker raises the queue with cl_ctr_events_flush() once its handler
 * returns, so an event_route that reads $cl_ctr_* cannot deadlock on the
 * lock its change was made under.  Worker only. */
void cl_ctr_ev_maintenance(cl_ctr_cluster_t *cl, int node_id, int st);
void cl_ctr_ev_role(cl_ctr_cluster_t *cl, int old_role, int new_role);
void cl_ctr_ev_master(cl_ctr_cluster_t *cl, const char *master_ip, int node_id);
void cl_ctr_ev_member(cl_ctr_cluster_t *cl, const char *ip, int node_id,
                      int joined, const char *reason);
void cl_ctr_ev_refused(cl_ctr_cluster_t *cl, const char *ip, const char *reason);
void cl_ctr_ev_merge(cl_ctr_cluster_t *cl, const char *master_ip, int was_master);

/* Raise every queued event, in order. */
void cl_ctr_events_flush(void);

#endif /* CL_CTR_EVENTS_H */
