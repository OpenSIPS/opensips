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

#define MEDIA_SESSION_TYPE_FORK 0
#define MEDIA_SESSION_TYPE_EXCHANGE 1

struct media_session;

enum media_session_state {
	MEDIA_SESSION_STATE_INIT,
	MEDIA_SESSION_STATE_RUNNING,
	MEDIA_SESSION_STATE_PENDING,
	MEDIA_SESSION_STATE_UPDATING,
};

struct media_session_leg {
	struct media_session *ms;
	enum media_session_state state;
	int type;
	int ref;
	int leg;
	str b2b_key;
	int nohold;
	gen_lock_t lock;
	enum b2b_entity_type b2b_entity;
	struct media_session_leg *next;
	void *params;
};

struct media_session {
	gen_lock_t lock;
	struct dlg_cell *dlg;

	struct media_session_leg *legs;
};

#define MEDIA_SESSION_LOCK(_ms) lock_get(&(_ms)->lock)
#define MEDIA_SESSION_UNLOCK(_ms) lock_release(&(_ms)->lock)

#define MEDIA_LEG_LOCK(_msl) lock_get(&(_msl)->lock)
#define MEDIA_LEG_UNLOCK(_msl) lock_release(&(_msl)->lock)

#define MEDIA_LEG_STATE_SET_UNSAFE(_msl, _newstate) \
	do { \
		LM_DBG("msl=%p new_state=%d\n", (_msl), (_newstate)); \
		(_msl)->state = (_newstate); \
	} while (0)

#define MEDIA_LEG_STATE_SET(_msl, _newstate) \
	do { \
		MEDIA_LEG_LOCK(_msl); \
		MEDIA_LEG_STATE_SET_UNSAFE(_msl, _newstate); \
		MEDIA_LEG_UNLOCK(_msl); \
	} while (0)


#define MEDIA_LEG_LOCK(_msl) lock_get(&(_msl)->lock)
#define MEDIA_LEG_UNLOCK(_msl) lock_release(&(_msl)->lock)

#define DLG_MEDIA_SESSION_LEG(_dlg, _leg) \
	(_leg == MEDIA_LEG_CALLER?DLG_CALLER_LEG:callee_idx(_dlg))
#define MEDIA_SESSION_DLG_LEG(_msl) \
	DLG_MEDIA_SESSION_LEG(_msl->ms->dlg, _msl->leg)
#define MEDIA_SESSION_DLG_OTHER_LEG(_msl) \
	(other_leg(_msl->ms->dlg, MEDIA_SESSION_DLG_LEG(_msl)))

#define MSL_REF_UNSAFE(_msl) \
	do { \
		(_msl)->ref++; \
	} while(0)

#define MSL_REF(_msl) \
	do { \
		MEDIA_SESSION_LOCK(_msl->ms); \
		MSL_REF_UNSAFE(_msl); \
		MEDIA_SESSION_UNLOCK(_msl->ms); \
	} while(0)

#define MSL_UNREF(_msl) \
	do { \
		MEDIA_SESSION_LOCK(_msl->ms); \
		(_msl)->ref--; \
		if ((_msl)->ref == 0) { \
			struct media_session *__tmp_ms = _msl->ms; \
			media_session_leg_free(_msl); \
			media_session_release(__tmp_ms, 1/* release ms lock */); \
		} else { \
			if ((_msl)->ref < 0) \
				LM_BUG("invalid ref for media session leg=%p ref=%d (%s:%d)\n", \
						(_msl), (_msl)->ref, __func__, __LINE__); \
			MEDIA_SESSION_UNLOCK(_msl->ms); \
		} \
	} while(0)

#define MSL_UNREF_UNSAFE(_msl) \
	do { \
		(_msl)->ref--; \
		if ((_msl)->ref == 0) { \
			struct media_session *__tmp_ms = _msl->ms; \
			media_session_leg_free(_msl); \
			media_session_release(__tmp_ms, 0); \
		} else if ((_msl)->ref < 0) \
				LM_BUG("invalid ref for media session leg=%p ref=%d (%s:%d)\n", \
						(_msl), (_msl)->ref, __func__, __LINE__); \
	} while(0)

#define MSL_UNREF_NORELEASE(_msl) \
	do { \
		(_msl)->ref--; \
		if ((_msl)->ref == 0) \
			media_session_leg_free(_msl); \
		else if ((_msl)->ref < 0) \
				LM_BUG("invalid ref for media session leg=%p ref=%d (%s:%d)\n", \
						(_msl), (_msl)->ref, __func__, __LINE__); \
	} while(0)

int init_media_sessions(void);
void media_session_free(struct media_session *ms);
void media_session_release(struct media_session *ms, int unlock);
void media_session_push_dlg(struct media_session *ms, struct dlg_cell *dlg);

struct media_session *media_session_get(struct dlg_cell *dlg);
struct media_session *media_session_create(struct dlg_cell *dlg);
struct media_session_leg *media_session_new_leg(struct dlg_cell *dlg,
		int type, int leg, int nohold);
void media_session_leg_free(struct media_session_leg *ms);
struct media_session_leg *media_session_get_leg(struct media_session *ms,
		int leg);
struct media_session_leg *media_session_other_leg(
		struct media_session_leg *msl);

int media_session_resume_dlg(struct media_session_leg *msl);

int media_session_reinvite(struct media_session_leg *msl, int leg, str *pbody);

int media_session_ack(struct media_session_leg *msl);

int media_session_req(struct media_session_leg *msl, const char *method, str *body);

int media_session_rpl(struct media_session_leg *msl,
		int method, int code, str *reason, str *body);

int media_session_end(struct media_session *ms, int legs, int nohold, int proxied);

#endif /* _MEDIA_SESSION_H_ */
