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

str *media_session_get_hold_sdp(struct media_session_leg *msl);

int media_session_resume_dlg(struct media_session_leg *msl);

int media_session_reinvite(struct media_session_leg *msl, int leg, str *pbody);

int media_session_b2b_end(struct media_session_leg *msl);

int media_session_end(struct media_session *ms, int legs, int nohold);

#endif /* _MEDIA_UTILS_H_ */
