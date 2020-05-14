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
		media_b2b.entity_delete(msl->b2b_entity, &msl->b2b_key, NULL, 1, 1);
		shm_free(msl->b2b_key.s);
		msl->b2b_key.s = NULL;
	}
	LM_DBG("releasing media_session_leg=%p\n", msl);
	if (msl->params && msl->type == MEDIA_SESSION_TYPE_FORK)
		media_forks_free(msl->params);
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

static void media_session_dlg_end(struct dlg_cell *dlg, int type, struct dlg_cb_params *_params)
{
	/* dialog has terminated - we need to terminate all ongoing legs */
	struct media_session *ms = media_session_get(dlg);

	/* media server no longer exists, so it's been already handled */
	if (!ms)
		return;

	media_session_end(ms, MEDIA_LEG_BOTH, 0, 0);
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
			media_session_dlg_end, NULL, NULL) < 0) {
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
	lock_init(&msl->lock);
	MEDIA_LEG_STATE_SET_UNSAFE(msl, MEDIA_SESSION_STATE_INIT);
	msl->state = MEDIA_SESSION_STATE_INIT;
	msl->ref = 1; /* creation */
	/* link it to the session */
	msl->next = ms->legs;
	ms->legs = msl;
	MEDIA_SESSION_UNLOCK(ms);
	LM_DBG(" creating media_session_leg=%p\n", msl);
	return msl;
}

struct media_session_leg *media_session_other_leg(
		struct media_session_leg *msl)
{
	struct media_session_leg *it;
	for (it = msl->ms->legs; it; it = it->next)
		if (msl != it)
			return it;
	return NULL;
}


int media_session_resume_dlg(struct media_session_leg *msl)
{
	if (msl->type == MEDIA_SESSION_TYPE_FORK)
		return media_forks_stop(msl);

	int first_leg = MEDIA_SESSION_DLG_LEG(msl);
	if (media_session_reinvite(msl, first_leg, NULL) < 0)
		LM_ERR("could not resume call for leg %d\n", first_leg);
	if (!msl->nohold && media_session_reinvite(msl,
			other_leg(msl->ms->dlg, first_leg), NULL) < 0)
		LM_ERR("could not resume call for leg %d\n",
				other_leg(msl->ms->dlg, first_leg));
	return 0;
}

int media_session_reinvite(struct media_session_leg *msl, int leg, str *pbody)
{
	static str inv = str_init("INVITE");

	str body;
	if (pbody)
		body = *pbody;
	else
		body = dlg_get_out_sdp(msl->ms->dlg, leg);
	return media_dlg.send_indialog_request(msl->ms->dlg,
			&inv, leg, &body, &content_type_sdp, NULL, NULL, NULL);
}

int media_session_req(struct media_session_leg *msl, const char *method, str *body)
{
	struct b2b_req_data req;
	str m;
	init_str(&m, method);

	memset(&req, 0, sizeof(req));
	req.et = msl->b2b_entity;
	req.b2b_key = &msl->b2b_key;
	req.method = &m;
	req.body = body;
	if (body)
		req.extra_headers = &content_type_sdp_hdr;
	else
		req.no_cb = 1; /* no body - do not call callback */

	if (media_b2b.send_request(&req) < 0) {
		LM_ERR("Cannot send %s to b2b entity key %.*s\n", method,
				req.b2b_key->len, req.b2b_key->s);
		return -1;
	}
	return 0;
}

int media_session_rpl(struct media_session_leg *msl,
		int method, int code, str *reason, str *body)
{
	b2b_rpl_data_t reply_data;

	memset(&reply_data, 0, sizeof (reply_data));
	reply_data.et = msl->b2b_entity;
	reply_data.b2b_key = &msl->b2b_key;
	reply_data.method = method;
	reply_data.code = code;
	reply_data.text = reason;
	reply_data.body = body;
	if (body)
		reply_data.extra_headers = &content_type_sdp_hdr;

	return media_b2b.send_reply(&reply_data);
}

static int media_session_leg_end(struct media_session_leg *msl, int nohold, int proxied)
{
	int ret = 0;
	str *body = NULL;
	struct media_session_leg *omsl;

	/* end the leg towards media server */
	if (media_session_req(msl, BYE, NULL) < 0)
		ret = -1;

	if (msl->type == MEDIA_SESSION_TYPE_FORK) {
		media_forks_stop(msl);
		goto unref;
	}

	/* if the call is ongoing, we need to manipulate its participants too */
	if (msl->ms && msl->ms->dlg && msl->ms->dlg->state < DLG_STATE_DELETED) {
		if (!nohold) {
			/* we need to put on hold the leg, if there's a different
			 * media session going on on the other leg */
			omsl = media_session_other_leg(msl);
			if (omsl) {
				body = media_session_get_hold_sdp(omsl);
			} else if (!msl->nohold) {
				/* there's no other session going on there - check to see if
				 * the other leg has been put on hold */
				if (media_session_reinvite(msl, MEDIA_SESSION_DLG_OTHER_LEG(msl), NULL) < 0)
					ret = -2;
			}
		}

		if (!proxied && media_session_reinvite(msl, MEDIA_SESSION_DLG_LEG(msl), body) < 0)
			ret = -2;
		if (body)
			pkg_free(body->s);
	}
unref:
	MSL_UNREF_NORELEASE(msl);
	return ret;
}

int media_session_end(struct media_session *ms, int leg, int nohold, int proxied)
{
	int ret = 0;
	struct media_session_leg *msl, *nmsl;

	MEDIA_SESSION_LOCK(ms);
	if (leg == MEDIA_LEG_BOTH) {
		msl = ms->legs;
		nmsl = msl->next;
		if (nmsl) {
			/* we will end both legs, so there's no reason to put the other
			 * one on hold, if we're going to resume the sessions for both
			 */
			nohold = 1;
		} else if (proxied) {
			/* if there's no other session on the other leg, do not put this
			 * one on hold, as it is going to be resumed */
			nohold = 1;
		}
		if (media_session_leg_end(msl, nohold, proxied) < 0)
			ret = -1;
		if (nmsl && media_session_leg_end(nmsl, nohold, proxied) < 0)
			ret = -1;
		goto release;
	}
	/* only one leg - search for it */
	msl = media_session_get_leg(ms, leg);
	if (!msl) {
		MEDIA_SESSION_UNLOCK(ms);
		LM_DBG("could not find the %d leg!\n", leg);
		return -1;
	}
	if (media_session_leg_end(msl, nohold, proxied) < 0)
		ret = -1;
release:
	media_session_release(ms, 1/* unlock */);
	return ret;
}
