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

str media_exchange_name = str_init("media_exchange");
str content_type_sdp = str_init("application/sdp");
str content_type_sdp_hdr = str_init("Content-Type: application/sdp\r\n");

str *media_session_get_hold_sdp(struct media_session_leg *msl)
{
	static sdp_info_t sdp;
	sdp_session_cell_t *session;
	sdp_stream_cell_t *stream;
	str session_hdr;
	int attr_to_add = 0;
	int len, streamnum;
	static str new_body;
	/* NOTE: all the attributes have the same length as inactive */
	int leg = MEDIA_SESSION_DLG_OTHER_LEG(msl);
	str body = dlg_get_out_sdp(msl->ms->dlg, leg);

	if (parse_sdp_session(&body, 0, NULL, &sdp) < 0) {
		LM_ERR("could not parse SDP for leg %d\n", leg);
		return NULL;
	}

	/* we only have one session, so there's no need to iterate */
	streamnum = 0;
	session = sdp.sessions;
	session_hdr.s = session->body.s;
	session_hdr.len = session->body.len;
	for (stream = session->streams; stream; stream = stream->next) {
		/* first stream indicates where session header ends */
		if (session_hdr.len > stream->body.s - session->body.s)
			session_hdr.len = stream->body.s - session->body.s;
		if (stream->sendrecv_mode.len == 0)
			attr_to_add++;
		else if (strncasecmp(stream->sendrecv_mode.s, "inactive", 8) == 0)
			continue; /* do not disable already disabled stream */
		streamnum++;
	}

	new_body.s = pkg_malloc(body.len + attr_to_add * 12 /* a=inactive\r\n */);
	if (!new_body.s) {
		LM_ERR("oom for new body!\n");
		return NULL;
	}

	if (!streamnum) {
		/* duplicate the body as it is */
		memcpy(new_body.s, body.s, body.len);
		new_body.len = body.len;
		return &new_body;
	}

	/* copy everything until the first stream */
	memcpy(new_body.s, session_hdr.s, session_hdr.len);
	new_body.len = session_hdr.len;
	for (streamnum = 0; streamnum < session->streams_num; streamnum++) {
		for (stream = session->streams; stream; stream = stream->next) {
			/* make sure the streams are in the same order */
			if (stream->stream_num != streamnum)
				continue;
			if (stream->sendrecv_mode.len) {
				len = stream->sendrecv_mode.s - stream->body.s;
				memcpy(new_body.s + new_body.len, stream->body.s,
						stream->sendrecv_mode.s - stream->body.s);
				new_body.len += len;
				memcpy(new_body.s + new_body.len, "inactive", 8);
				new_body.len += 8;
				len += stream->sendrecv_mode.len;
				memcpy(new_body.s + new_body.len, stream->sendrecv_mode.s +
						stream->sendrecv_mode.len, stream->body.len - len);
				new_body.len += stream->body.len - len;
			} else {
				memcpy(new_body.s + new_body.len, stream->body.s, stream->body.len);
				new_body.len += stream->body.len;
				memcpy(new_body.s + new_body.len, "a=inactive\r\n", 12);
				new_body.len += 12;
			}
		}
	}

	return &new_body;
}

str *media_get_dlg_headers(struct dlg_cell *dlg, int dleg, int ct)
{
	static str contact_start = str_init("Contact: <");
	static str contact_end = str_init(">\r\n");
	static str hdrs;
	char *p;
	int sleg = other_leg(dlg, dleg);

	if (dlg->legs[dleg].adv_contact.len)
		hdrs.len =  dlg->legs[dleg].adv_contact.len;
	else
		hdrs.len = contact_start.len +
			dlg->legs[sleg].contact.len +
			contact_end.len;
	if (ct)
		hdrs.len += content_type_sdp_hdr.len;
	hdrs.s = pkg_malloc(hdrs.len);
	if (!hdrs.s) {
		LM_ERR("No more pkg for extra headers \n");
		return 0;
	}
	p = hdrs.s;
	if (dlg->legs[dleg].adv_contact.len) {
		memcpy(p, dlg->legs[dleg].adv_contact.s,
				dlg->legs[dleg].adv_contact.len);

		p += dlg->legs[dleg].adv_contact.len;
	} else {
		memcpy(p, contact_start.s, contact_start.len);
		p += contact_start.len;
		memcpy(p, dlg->legs[sleg].contact.s,
				dlg->legs[sleg].contact.len);

		p += dlg->legs[sleg].contact.len;
		memcpy(p, contact_end.s, contact_end.len);
		p += contact_end.len;
	}
	if (ct) {
		memcpy(p, content_type_sdp_hdr.s, content_type_sdp_hdr.len);
		p += content_type_sdp_hdr.len;
	}
	return &hdrs;
}


int media_forks_stop(struct media_session_leg *msl)
{
	if (media_rtp.copy_delete(msl->ms->rtp,
			&media_exchange_name, NULL) < 0) {
		LM_ERR("could not stop forking!\n");
		return -1;
	}
	shm_free(msl->params);
	msl->params = NULL;
	return 0;
}

struct media_fork_info {
	unsigned int flags;
	unsigned int streams;
	unsigned int paused;
};

static inline struct media_fork_info *media_fork_info(unsigned int flags, unsigned int streams)
{
	struct media_fork_info *mf;
	mf = shm_malloc(sizeof *mf);
	if (!mf) {
		LM_ERR("could not allocate new media fork!\n");
		return NULL;
	}
	memset(mf, 0, sizeof *mf);
	mf->flags = flags;
	mf->streams = streams;
	return mf;
}

struct media_fork_info *media_get_fork_sdp(struct media_session_leg *msl,
		int medianum, str *body)
{
	unsigned int flags;
	unsigned int streams;
	struct media_fork_info *mf;

	switch (msl->leg) {
		case MEDIA_LEG_BOTH:
			flags = RTP_COPY_LEG_BOTH;
			break;
		case MEDIA_LEG_CALLER:
			flags = RTP_COPY_LEG_CALLER;
			break;
		case MEDIA_LEG_CALLEE:
			flags = RTP_COPY_LEG_CALLEE;
			break;
		default:
			LM_BUG("unexpected msl->leg value: %d\n", msl->leg);
			return NULL;
	}

	if (medianum < 0)
		streams = -1;
	else
		streams = 1 << medianum;

	mf = media_fork_info(flags, streams);
	if (!mf)
		return NULL;

	if (media_fork_offer(msl, mf, body) < 0) {
		shm_free(mf);
		return NULL;
	}

	return mf;
}

int media_fork_answer(struct media_session_leg *msl,
		struct media_fork_info *mf, str *body)
{
	if (media_rtp.copy_answer(msl->ms->rtp,
			&media_exchange_name, NULL, body) < 0) {
		LM_ERR("could not start forking!\n");
		return -1;
	}
	return 0;
}

int media_fork_offer(struct media_session_leg *msl,
		struct media_fork_info *mf, str *body)
{
	if (media_rtp.copy_offer(msl->ms->rtp,
			&media_exchange_name, NULL, mf->flags,
			mf->streams, body, NULL) < 0) {
		LM_ERR("could not get copy SDP\n");
		return -1;
	}
	return 0;
}

int media_fork_pause_resume(struct media_session_leg *msl, int medianum, int resume)
{
	unsigned int flags = 0;
	struct media_fork_info *mf;
	unsigned int todo;
	int ret = 0;
	str body;

	if (msl->type != MEDIA_SESSION_TYPE_FORK) {
		LM_DBG("pausing/resuming is only available for media forks!\n");
		return 0;
	}

	MEDIA_LEG_LOCK(msl);
	if (msl->state != MEDIA_SESSION_STATE_RUNNING) {
		LM_DBG("media involved in a different exchange! state=%d\n", msl->state);
		MEDIA_LEG_UNLOCK(msl);
		return 0;
	}

	mf = msl->params;
	if (medianum < 0)
		todo = mf->streams;
	else
		todo = 1 << medianum;

	if (resume) {
		if ((todo & mf->paused) == 0) {
			LM_DBG("all streams are already resumed\n");
			MEDIA_LEG_UNLOCK(msl);
			return 0;
		}
	} else {
		if ((todo & mf->paused) == todo) {
			LM_DBG("all streams are already paused\n");
			MEDIA_LEG_UNLOCK(msl);
			return 0;
		}
	}

	MEDIA_LEG_STATE_SET_UNSAFE(msl, MEDIA_SESSION_STATE_PENDING);
	MEDIA_LEG_UNLOCK(msl);
	flags = mf->flags;

	if (!resume)
		flags |= RTP_COPY_MODE_DISABLE;

	if (media_rtp.copy_offer(msl->ms->rtp,
			&media_exchange_name, NULL, flags, todo, &body, NULL) < 0) {
		LM_ERR("could not get copy SDP\n");
		MEDIA_LEG_STATE_SET_UNSAFE(msl, MEDIA_SESSION_STATE_RUNNING);
		return -1;
	}

	if (media_session_req(msl, "INVITE", &body) < 0) {
		LM_ERR("could not challenge new SDP for re-INVITE - abort\n");
		MEDIA_LEG_STATE_SET(msl, MEDIA_SESSION_STATE_RUNNING);
		ret = -1;
	} else {
		if (resume)
			mf->paused &= ~todo;
		else
			mf->paused |= todo;
	}
	pkg_free(body.s);

	return ret;
}

static void media_exchange_event_create(struct media_session_leg *msl,
		bin_packet_t *store)
{
	struct media_fork_info *mf;

	bin_push_int(store, msl->type);
	bin_push_int(store, msl->nohold);

	/* if it is a fork, we also need to push the streamed media sessions */
	if (msl->type == MEDIA_SESSION_TYPE_FORK) {
		mf = msl->params;
		bin_push_int(store, mf->flags);
		bin_push_int(store, mf->streams);
		bin_push_int(store, mf->paused);
	}
}

static void media_exchange_event_update(struct media_session_leg *msl,
		bin_packet_t *store)
{
	struct media_fork_info *mf;

	/* we only need to update forked sessions */
	if (msl->type != MEDIA_SESSION_TYPE_FORK)
		return;

	mf = msl->params;
	bin_push_int(store, mf->flags);
	bin_push_int(store, mf->streams);
	bin_push_int(store, mf->paused);
}

void media_exchange_event_trigger(enum b2b_entity_type et, str *key,
		str *logic_param, void *param, enum b2b_event_type event_type,
		bin_packet_t *store, int backend)
{
	struct media_session_leg *msl = (struct media_session_leg *)param;

	/* we always need to identify the media session */
	bin_push_str(store, &msl->ms->dlg->callid);
	bin_push_int(store, msl->leg);

	switch (event_type) {
		case B2B_EVENT_CREATE:
			media_exchange_event_create(msl, store);
			break;
		case B2B_EVENT_ACK:
		case B2B_EVENT_UPDATE:
			media_exchange_event_update(msl, store);
			break;
		default:
			/* nothing else to do for delete */
			break;
	}
}

static void media_exchange_event_received_create(struct dlg_cell *dlg,
		int leg, enum b2b_entity_type et, str *key, bin_packet_t *store)
{

	int type, nohold;
	struct media_fork_info *mf = NULL;
	unsigned int flags, streams, paused;
	struct media_session_leg *msl;

	if (bin_pop_int(store, &type) != 0)
		return;
	if (bin_pop_int(store, &nohold) != 0)
		return;

	if (type == MEDIA_SESSION_TYPE_FORK) {
		bin_pop_int(store, &flags);
		bin_pop_int(store, &streams);
		bin_pop_int(store, &paused);
		mf = media_fork_info(flags, streams);
		if (mf)
			mf->paused = paused;
	}

	if (dlg) {
		msl = media_session_new_leg(dlg, type, leg, nohold);
		if (!msl)
			LM_ERR("cannot create new leg!\n");
	} else {
		msl = NULL;
	}

	/* if we do not have a dialog, the drain is completed */
	if (!msl)
		return;

	if (type == MEDIA_SESSION_TYPE_FORK)
		msl->params = mf;

	if (shm_str_dup(&msl->b2b_key, key) < 0) {
		LM_ERR("could not duplicate b2b key!\n");
		goto error;
	}

	msl->b2b_entity = et;
	if (b2b_media_restore_callbacks(msl) >= 0)
		return; /* success */
error:
	MSL_UNREF(msl);
	media_session_leg_free(msl);
}

static void media_exchange_event_received_update(struct dlg_cell *dlg,
		int leg, bin_packet_t *store)
{
	struct media_session_leg *msl = NULL;
	unsigned int flags, streams, paused;
	struct media_fork_info *mf = NULL;
	struct media_session *ms;

	if (dlg) {
		ms = media_session_get(dlg);
		if (ms) {
			msl = media_session_get_leg(ms, leg);
			if (!msl)
				LM_ERR("could not get media session leg!\n");
		} else {
			LM_ERR("could not get media session!\n");
		}
	}

	if (msl && msl->type != MEDIA_SESSION_TYPE_FORK)
		return;
	if (msl)
		mf = msl->params;

	bin_pop_int(store, &flags);
	bin_pop_int(store, &streams);
	bin_pop_int(store, &paused);
	if (!mf) {
		mf = media_fork_info(flags, streams);
		if (!mf) {
			LM_ERR("could not create media fork instance\n");
			return;
		}
		msl->params = mf;
	} else {
		mf->flags = flags;
		mf->streams = streams;
	}
	mf->paused = paused;
}

static void media_exchange_event_received_delete(struct dlg_cell *dlg, int leg)
{
	struct media_session *ms;
	struct media_session_leg *msl;

	if (!dlg)
		return; /* nothing to draing */

	ms = media_session_get(dlg);
	if (!ms) {
		LM_ERR("could not get media session!\n");
		return;
	}
	msl = media_session_get_leg(ms, leg);
	if (!msl) {
		LM_ERR("could not get media session leg!\n");
		return;
	}
	/* do not delete the key, as it's being deleted anyway */
	shm_free(msl->b2b_key.s);
	msl->b2b_key.s = NULL;
	MSL_UNREF(msl);
}

void media_exchange_event_received(enum b2b_entity_type et, str *key,
		str *logic_param, void *param, enum b2b_event_type event_type,
		bin_packet_t *store, int backend)
{
	struct dlg_cell *dlg;
	str callid;
	int leg;

	/* nothing to do */
	if (store == NULL)
		return;

	if (bin_pop_str(store, &callid) != 0)
		return;

	if (bin_pop_int(store, &leg) != 0)
		return;

	dlg = media_dlg.get_dlg_by_callid(&callid, 0);
	/* if dlg is null, each function will do the drain */

	switch (event_type) {
		case B2B_EVENT_CREATE:
			media_exchange_event_received_create(dlg, leg, et, key, store);
			break;
		case B2B_EVENT_ACK:
		case B2B_EVENT_UPDATE:
			media_exchange_event_received_update(dlg, leg, store);
			break;
		case B2B_EVENT_DELETE:
			media_exchange_event_received_delete(dlg, leg);
			break;
		default:
			LM_WARN("unhandled B2B event %d\n", event_type);
			break;
	}

	if (dlg)
		media_dlg.dlg_unref(dlg, 1);
	return;
}

str *media_exchange_get_offer_sdp(rtp_ctx ctx, struct dlg_cell *dlg,
		int leg, int *release)
{
	static str sbody;

	*release = 0;
	if (media_rtp.offer && ctx) {
		sbody = dlg->legs[leg].in_sdp;
		if (media_rtp.offer(ctx, &media_exchange_name,
				(leg == DLG_CALLER_LEG?
				 RTP_RELAY_CALLER:RTP_RELAY_CALLEE),
				&sbody) >= 0) {
			/* the body towards the leg has changed, so we should update it */
			if (shm_str_sync(&dlg->legs[leg].out_sdp, &sbody) < 0) {
				LM_ERR("could not update dialog's out_sdp\n");
				*release = 1;
				return &sbody;
			}
			/* otherwise we return what has already been sync'ed */
		}
	}

	sbody = dlg_get_out_sdp(dlg, leg);
	return &sbody;
}

str *media_exchange_get_answer_sdp(rtp_ctx ctx, struct dlg_cell *dlg, str *body,
		int leg, int *release)
{
	*release = 0;
	if (media_rtp.answer && ctx && media_rtp.answer(ctx, &media_exchange_name,
			(leg == DLG_CALLER_LEG?
			 RTP_RELAY_CALLEE:RTP_RELAY_CALLER),
			body) >= 0) {
		if (dlg)
			shm_str_sync(&dlg->legs[leg].out_sdp, body);
		*release = 1;
		return body;
	}
	return body;
}
