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

#ifndef _MEDIA_BRIDGING_H_
#define _MEDIA_BRIDGING_H_

#define MEDIA_LEG_UNSPEC	0
#define MEDIA_LEG_CALLER	1
#define MEDIA_LEG_CALLEE	2
#define MEDIA_LEG_BOTH		3

struct media_session_leg;

#include "../tm/tm_load.h"
extern struct tm_binds media_tm;
#include "../dialog/dlg_load.h"
extern struct dlg_binds media_dlg;
#include "../b2b_entities/b2be_load.h"
extern struct b2b_api media_b2b;
#include "../rtpproxy/rtpproxy_load.h"
extern struct rtpproxy_binds media_rtp;

int b2b_media_restore_callbacks(struct media_session_leg *msl);

#endif /* _MEDIA_BRIDGING_H_ */
