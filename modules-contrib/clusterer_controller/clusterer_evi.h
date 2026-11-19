/*
 * Copyright (C) 2021 OpenSIPS Project
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 *
 */

#ifndef CLUSTERER_EVI_H
#define CLUSTERER_EVI_H

int gen_rcv_evs_init(void);
int node_state_ev_init(void);
int raise_node_state_ev(enum clusterer_event ev, int cluster_id, int node_id);
int raise_gen_msg_ev(int cluster_id, int source_id,
	int req_like, str *rcv_msg, str *rcv_tag);
void gen_rcv_evs_destroy(void);
void node_state_ev_destroy(void);

#endif  /* CLUSTERER_EVI_H */