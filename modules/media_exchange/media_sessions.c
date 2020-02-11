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
#include "media_utils.h"

static int media_session_dlg_idx;

void media_session_unref(void *param)
{
	struct media_session *ms = (struct media_session *)param;
	MEDIA_SESSION_LOCK(ms);
	if (ms->legs)
		LM_WARN("media session %p still in use %p!\n", ms, ms->legs);
	else
		media_session_release(ms, 1);
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

struct media_session_leg *media_session_get_leg(struct media_session *ms,
		int leg)
{
	struct media_session_leg *msl;
	for (msl = ms->legs; msl; msl = msl->next)
		if (msl->leg == leg || msl->leg == MEDIA_LEG_BOTH)
			return msl;
	return NULL;
}

/* assumes the media session lock is acquired */
void media_session_leg_free(struct media_session_leg *msl)
{
	struct media_session_leg *tmsl, *pmsl;

	/* unlink the media session */
	for (pmsl = NULL, tmsl = msl->ms->legs; tmsl; pmsl = tmsl, tmsl = tmsl->next)
		if (tmsl == msl)
			break;
	if (tmsl) {
		if (pmsl)
			pmsl->next = msl->next;
		else
			msl->ms->legs = msl->next;
	} else {
		LM_ERR("media session leg %p not found in media session %p\n",
				msl, msl->ms);
	}
	if (msl->b2b_key.s) {
		media_b2b.entity_delete(msl->b2b_entity, &msl->b2b_key, NULL, 1);
		shm_free(msl->b2b_key.s);
		msl->b2b_key.s = NULL;
	}
	LM_DBG("releasing media_session_leg=%p\n", msl);
	shm_free(msl);
}

void media_session_release(struct media_session *ms, int unlock)
{
	int existing_legs = (ms->legs != NULL);

	if (unlock)
		MEDIA_SESSION_UNLOCK(ms);
	if (existing_legs) {
		LM_DBG("media session %p has onhoing legs!\n", ms);
		return;
	}
	media_session_free(ms);
}

void media_session_free(struct media_session *ms)
{

	if (ms->dlg) {
		media_dlg.dlg_ctx_put_ptr(ms->dlg, media_session_dlg_idx, NULL);
		media_dlg.dlg_unref(ms->dlg, 1);
	}
	lock_destroy(&ms->lock);
	LM_DBG("releasing media_session=%p\n", ms);
	shm_free(ms);
}

struct media_session *media_session_get(struct dlg_cell *dlg)
{
	return media_dlg.dlg_ctx_get_ptr(dlg, media_session_dlg_idx);
}

static void media_session_end(struct dlg_cell *dlg, int type, struct dlg_cb_params *_params)
{
	/* dialog has terminated - we need to terminate all ongoing legs */
	struct media_session_leg *msl, *msln;
	struct media_session *ms = media_session_get(dlg);

	/* media server no longer exists, so it's been already handled */
	if (!ms)
		return;

	MEDIA_SESSION_LOCK(ms);
	for (msl = ms->legs; msl; msl = msln) {
		media_session_b2b_end(msl);
		msln = msl->next;
		/* leg might dissapear here */
		MSL_UNREF_NORELEASE(msl);
	}
	media_session_release(ms, 1/* unlock */);
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
	ms->dlg = dlg;
	lock_init(&ms->lock);

	media_dlg.dlg_ref(dlg, 1);
	media_dlg.dlg_ctx_put_ptr(dlg, media_session_dlg_idx, ms);

	if (media_dlg.register_dlgcb(dlg, DLGCB_TERMINATED|DLGCB_EXPIRED,
			media_session_end, NULL, NULL) < 0) {
		/* we are not storing media session in the dialog, as it might
		 * dissapear along the way, if the playback ends */
		LM_ERR("could not register media_session_termination!\n");
		media_session_free(ms);
		return NULL;
	}

	LM_DBG(" creating media_session=%p\n", ms);
	return ms;
}

struct media_session_leg *media_session_new_leg(struct dlg_cell *dlg,
		int type, int leg, int nohold)
{
	struct media_session *ms;
	struct media_session_leg *msl;

	ms = media_session_get(dlg);
	if (!ms) {
		/* create a new media session */
		ms = media_session_create(dlg);
		if (!ms) {
			LM_ERR("cannot create media session!\n");
			return NULL;
		}
		MEDIA_SESSION_LOCK(ms);
	} else {
		MEDIA_SESSION_LOCK(ms);
		if (media_session_get_leg(ms, leg)) {
			LM_WARN("media session already engaged for leg %d\n", leg);
			MEDIA_SESSION_UNLOCK(ms);
			return NULL;
		}
	}
	msl = shm_malloc(sizeof *msl);
	if (!msl) {
		LM_ERR("could not allocate new media session leg for %d\n", leg);
		media_session_release(ms, 1);
		return NULL;
	}
	memset(msl, 0, sizeof *msl);
	msl->type = type;
	msl->ms = ms;
	msl->leg = leg;
	msl->nohold = nohold;
	msl->state = MEDIA_SESSION_STATE_INIT;
	msl->ref = 1; /* creation */
	/* link it to the session */
	msl->next = ms->legs;
	ms->legs = msl;
	MEDIA_SESSION_UNLOCK(ms);
	LM_DBG(" creating media_session_leg=%p\n", msl);
	return msl;
}
