/*
 * Copyright (C) 2020 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef _MEDIA_UTILS_H_
#define _MEDIA_UTILS_H_

#include "../../parser/sdp/sdp.h"
#include "../../bin_interface.h"

extern str content_type_sdp;
extern str content_type_sdp_hdr;

struct media_fork_info;

str *media_session_get_hold_sdp(struct media_session_leg *msl);

str *media_get_dlg_headers(struct dlg_cell *dlg, int dleg, int ct);

int media_fork_streams(struct media_session_leg *msl, struct media_fork_info *forks);

struct media_fork_info *media_sdp_match(struct dlg_cell *dlg,
		int leg, sdp_info_t *invite_sdp, int medianum);

struct media_fork_info *media_sdp_get(struct dlg_cell *dlg,
		int leg, int medianum, str *caller_body, str *callee_body);

str *media_sdp_buf_get(void);

int media_fork(struct dlg_cell *dlg, struct media_fork_info *mf);

void media_forks_free(struct media_fork_info *mf);

struct media_fork_info *media_fork_search(struct media_fork_info *mf, int search);

int media_forks_stop(struct media_session_leg *msl);

int media_fork_pause_resume(struct media_session_leg *msl, int medianum, int resume);

int media_fork_body_update(struct media_session_leg *ml, str *body, int leg);

int media_session_fork_update(struct media_session_leg *msl);

int media_fork_update(struct media_session_leg *msl,
		struct media_fork_info *mf, str *ip, str *port, int disabled);

int media_util_init_static(void);

void media_util_release_static(void);

void media_exchange_event_trigger(enum b2b_entity_type et, str *key,
		str *param, enum b2b_event_type event_type, bin_packet_t *store,
		int backend);
void media_exchange_event_received(enum b2b_entity_type et, str *key,
		str *param, enum b2b_event_type event_type, bin_packet_t *store,
		int backend);

#endif /* _MEDIA_UTILS_H_ */
