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
	int type;
	int ref;
	str b2b_key;
	int nohold;
	enum b2b_entity_type b2b_entity;
};

struct media_session {
	gen_lock_t lock;
	struct dlg_cell *dlg;

	struct media_session_leg *legs[2];
};

#define MEDIA_SERVER_LOCK(_ms) lock_get(&(_ms)->lock)
#define MEDIA_SERVER_UNLOCK(_ms) lock_release(&(_ms)->lock)
#define MEDIA_SERVER_LEG(_ms, _leg) (_ms->legs[(_leg) - 1])
#define MEDIA_SERVER_FREE(_ms) (!_ms->legs[0] && !_ms->legs[1])

#define MSL_REF_UNSAFE(_msl) \
	do { \
		(_msl)->ref++; \
	} while(0)

#define MSL_REF(_msl) \
	do { \
		MEDIA_SERVER_LOCK(_msl->ms); \
		MSL_REF_UNSAFE(_msl); \
		MEDIA_SERVER_UNLOCK(_msl->ms); \
	} while(0)

#define MSL_UNREF(_msl) \
	do { \
		MEDIA_SERVER_LOCK(_msl->ms); \
		(_msl)->ref--; \
		if ((_msl)->ref == 0) { \
			struct media_session *__tmp_ms = _msl->ms; \
			LM_DBG("destroying media session leg=%p\n", _msl); \
			media_session_leg_free(_msl); \
			if (MEDIA_SERVER_FREE(__tmp_ms)) { \
				MEDIA_SERVER_UNLOCK(__tmp_ms); \
				media_session_free(__tmp_ms); \
			} else { \
				MEDIA_SERVER_UNLOCK(__tmp_ms); \
			} \
		} else if ((_msl)->ref < 0) { \
				LM_BUG("invalid ref for media session leg=%p ref=%d (%s:%d)\n", \
						(_msl), (_msl)->ref, __func__, __LINE__); \
			MEDIA_SERVER_UNLOCK(_msl->ms); \
		} \
	} while(0)

#define MSL_UNREF_UNSAFE(_msl) \
	do { \
		(_msl)->ref--; \
		if ((_msl)->ref == 0) { \
			struct media_session *__tmp_ms = _msl->ms; \
			LM_DBG("destroying media session leg=%p\n", _msl); \
			media_session_leg_free(_msl); \
			if (MEDIA_SERVER_FREE(__tmp_ms)) \
				media_session_free(__tmp_ms); \
		} else if ((_msl)->ref < 0) \
				LM_BUG("invalid ref for media session leg=%p ref=%d (%s:%d)\n", \
						(_msl), (_msl)->ref, __func__, __LINE__); \
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
