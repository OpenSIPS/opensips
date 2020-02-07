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

#include "media_sessions.h"

static int media_session_dlg_idx;

void media_session_unref(void *param)
{
	struct media_session *ms = (struct media_session *)param;
	MEDIA_SERVER_UNREF(ms);
}

int init_media_sessions(void)
{
	media_session_dlg_idx =
		media_dlg.dlg_ctx_register_ptr(media_session_unref);
	if (media_session_dlg_idx < 0) {
		LM_ERR("could not register dialog ctx pointer!\n");
		return -1;
	}
	return 0;
}

void media_session_leg_free(struct media_session_leg *msl)
{
	MEDIA_SERVER_LOCK(msl->ms);
	if (msl->ms->legs[0] == msl)
		msl->ms->legs[0] = NULL;
	else
		msl->ms->legs[1] = NULL;
	MEDIA_SERVER_UNLOCK(msl->ms);
	MEDIA_SERVER_UNREF(msl->ms);
	if (msl->b2b_key.s) {
		media_b2b.entity_delete(msl->b2b_entity, &msl->b2b_key, NULL, 1);
		shm_free(msl->b2b_key.s);
		msl->b2b_key.s = NULL;
	}
	LM_DBG("releasing media_session_leg=%p\n", msl);
	shm_free(msl);
}

void media_session_free(struct media_session *ms)
{
	if (ms->dlg)
		media_dlg.dlg_ctx_put_ptr(ms->dlg, media_session_dlg_idx, NULL);
	lock_destroy(&ms->lock);
	LM_DBG("releasing media_session=%p\n", ms);
	shm_free(ms);
}

struct media_session *media_session_get(struct dlg_cell *dlg)
{
	return media_dlg.dlg_ctx_get_ptr(dlg, media_session_dlg_idx);
}

struct media_session *media_session_create(struct dlg_cell *dlg)
{
	struct media_session *ms;

	ms = shm_malloc(sizeof *ms);
	if (!ms) {
		LM_ERR("out of memory for media session!\n");
		return NULL;
	}
	memset(ms, 0, sizeof *ms);
	ms->ref = 1/* dlg */;
	ms->dlg = dlg;
	lock_init(&ms->lock);

	media_dlg.dlg_ref(dlg, 1);
	media_dlg.dlg_ctx_put_ptr(dlg, media_session_dlg_idx, ms);

	LM_DBG(" creating media_session=%p\n", ms);
	return ms;
}

struct media_session_leg *media_session_new_leg(struct dlg_cell *dlg,
		int type, int leg, int nohold)
{
	struct media_session *ms;
	struct media_session_leg *msl;
	int new = 0;

	ms = media_session_get(dlg);
	if (!ms) {
		/* create a new media session */
		ms = media_session_create(dlg);
		if (!ms) {
			LM_ERR("cannot create media session!\n");
			return NULL;
		}
		new  = 1;
		MEDIA_SERVER_LOCK(ms);
	} else {
		MEDIA_SERVER_LOCK(ms);
		if (MEDIA_SERVER_LEG(ms, leg) != NULL) {
			LM_WARN("media session already engaged for leg %d\n", leg);
			MEDIA_SERVER_UNLOCK(ms);
			return NULL;
		}
	}
	msl = shm_malloc(sizeof *msl);
	if (!msl) {
		LM_ERR("could not allocate new media session leg for %d\n", leg);
		MEDIA_SERVER_UNLOCK(ms);
		if (new) {
			/* remove the media session now */
			MEDIA_SERVER_UNREF(ms);
		}
		return NULL;
	}
	memset(msl, 0, sizeof *msl);
	msl->type = type;
	msl->ms = ms;
	msl->nohold = nohold;
	msl->state = MEDIA_SERVER_STATE_INIT;
	MEDIA_SERVER_REF_UNSAFE(ms); /* ref for media server leg */
	MEDIA_SERVER_LEG(ms, leg) = msl;
	MEDIA_SERVER_UNLOCK(ms);
	LM_DBG(" creating media_session_leg=%p\n", msl);
	return msl;
}
