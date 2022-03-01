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

struct media_fork_info *media_get_fork_sdp(struct media_session_leg *leg,
		int medianum, str *body);

int media_fork_offer(struct media_session_leg *leg,
		struct media_fork_info *msl, str *body);
int media_fork_answer(struct media_session_leg *leg,
		struct media_fork_info *msl, str *body);

int media_forks_stop(struct media_session_leg *msl);
int media_fork_pause_resume(struct media_session_leg *msl,
		int medianum, int resume);

void media_exchange_event_trigger(enum b2b_entity_type et, str *key,
		str *logic_param, void *param, enum b2b_event_type event_type,
		bin_packet_t *store, int backend);
void media_exchange_event_received(enum b2b_entity_type et, str *key,
		str *logic_param, void *param, enum b2b_event_type event_type,
		bin_packet_t *store, int backend);

#endif /* _MEDIA_UTILS_H_ */
