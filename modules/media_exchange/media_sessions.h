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

#ifndef _MEDIA_SESSION_H_
#define _MEDIA_SESSION_H_

#include "media_exchange.h"
#include "../dialog/dlg_load.h"

#define MEDIA_SESSION_TYPE_STREAM 0
#define MEDIA_SESSION_TYPE_FETCH 1

struct media_session;

enum media_session_state {
	MEDIA_SERVER_STATE_INIT,
	MEDIA_SERVER_STATE_ONGOING
};

struct media_session_leg {
	struct media_session *ms;
	enum media_session_state state;
	int nohold;
	int type;
	str b2b_key;
	enum b2b_entity_type b2b_entity;
};

struct media_session {
	int ref;
	gen_lock_t lock;
	struct dlg_cell *dlg;

	struct media_session_leg *legs[2];
};

#define MEDIA_SERVER_LOCK(_ms) lock_get(&(_ms)->lock)
#define MEDIA_SERVER_UNLOCK(_ms) lock_release(&(_ms)->lock)
#define MEDIA_SERVER_LEG(_ms, _leg) (_ms->legs[(_leg) - 1])

#define MEDIA_SERVER_REF_UNSAFE(_ms) \
	do { \
		(_ms)->ref++; \
	} while(0)

#define MEDIA_SERVER_REF(_ms) \
	do { \
		MEDIA_SERVER_LOCK(_ms); \
		MEDIA_SERVER_REF_UNSAFE(_ms); \
		MEDIA_SERVER_UNLOCK(_ms); \
	} while(0)

#define MEDIA_SERVER_UNREF(_ms) \
	do { \
		MEDIA_SERVER_LOCK(_ms); \
		(_ms)->ref--; \
		if ((_ms)->ref == 0) { \
			LM_DBG("destroying media session=%p\n", _ms); \
			MEDIA_SERVER_UNLOCK(_ms); \
			media_session_free(_ms); \
		} else { \
			if ((_ms)->ref < 0) \
				LM_BUG("invalid ref for media session=%p ref=%d (%s:%d)\n", \
						(_ms), (_ms)->ref, __func__, __LINE__); \
			MEDIA_SERVER_UNLOCK(_ms); \
		} \
	} while(0)

#define MEDIA_SERVER_UNREF_UNSAFE(_ms) \
	do { \
		(_ms)->ref--; \
		if ((_ms)->ref == 0) { \
			LM_DBG("destroying media session=%p\n", _ms); \
			media_session_free(_ms); \
		} else { \
			if ((_ms)->ref < 0) \
				LM_BUG("invalid ref for media session=%p ref=%d (%s:%d)\n", \
						(_ms), (_ms)->ref, __func__, __LINE__); \
		} \
	} while(0)

int init_media_sessions(void);
void media_session_free(struct media_session *ms);
void media_session_push_dlg(struct media_session *ms, struct dlg_cell *dlg);

struct media_session *media_session_get(struct dlg_cell *dlg);
struct media_session *media_session_create(struct dlg_cell *dlg);
struct media_session_leg *media_session_new_leg(struct dlg_cell *dlg,
		int type, int leg, int nohold);
void media_session_leg_free(struct media_session_leg *ms);

#endif /* _MEDIA_SESSION_H_ */
