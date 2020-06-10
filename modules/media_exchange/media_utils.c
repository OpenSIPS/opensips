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

str content_type_sdp = str_init("application/sdp");
str content_type_sdp_hdr = str_init("Content-Type: application/sdp\r\n");

#define MEDIA_FORK_START (1<<0)
#define MEDIA_FORK_STOP (1<<1)
#define MEDIA_FORK_DIRTY (1<<2)

#define MEDIA_FORK_HAS_FLAG(_mf, _flag) \
	(((_mf)->flags & (_flag)) == (_flag))

#define MEDIA_FORK_SET_FLAG(_mf, _flag) \
	(_mf)->flags |= (_flag)

#define MEDIA_FORK_RESET_FLAG(_mf, _flag) \
	(_mf)->flags &= ~(_flag)

enum media_fork_state {
	MEDIA_FORK_ON,
	MEDIA_FORK_OFF,
};

struct media_fork_info {
	int leg;
	str ip;
	str port;
	int flags;
	int medianum;
	int fork_medianum;
	void *params;
	enum media_fork_state state;
	struct media_fork_info *next;
};

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


static sdp_info_t ms_util_sdp1, ms_util_sdp2;

static str ms_util_body_buf;
static int ms_util_body_len;
#define MS_UTIL_BUF_INC 128
#define MS_UTIL_BUF_RELEASE() \
	do { \
		if (ms_util_body_buf.s) { \
			pkg_free(ms_util_body_buf.s); \
			ms_util_body_buf.s = NULL; \
		} \
	} while(0)

#define MS_UTIL_BUF_RESET() \
	do { \
		ms_util_body_len = MS_UTIL_BUF_INC; \
		ms_util_body_buf.s = pkg_malloc(MS_UTIL_BUF_INC); \
		if (!ms_util_body_buf.s) \
			return -1; \
		ms_util_body_buf.len = 0; \
	} while(0)

#define MS_UTIL_BUF_EXTEND(_s) \
	do { \
		char *__ms_util_buf; \
		if (ms_util_body_len - ms_util_body_buf.len <  (_s)) { \
			do \
				ms_util_body_len += MS_UTIL_BUF_INC; \
			while (ms_util_body_len - ms_util_body_buf.len <  (_s)); \
		}\
		__ms_util_buf = pkg_realloc(ms_util_body_buf.s, ms_util_body_len); \
		if (!__ms_util_buf) { \
			MS_UTIL_BUF_RELEASE(); \
			return -1; \
		} \
		ms_util_body_buf.s = __ms_util_buf; \
	} while(0)

#define MS_UTIL_BUF_COPY(_s) \
	do { \
		MS_UTIL_BUF_EXTEND(_s.len); \
		memcpy(ms_util_body_buf.s + ms_util_body_buf.len, (_s).s, (_s).len); \
		ms_util_body_buf.len += (_s).len; \
	} while(0)
#define MS_UTIL_BUF_STR &ms_util_body_buf


int media_util_init_static(void)
{
	MS_UTIL_BUF_RESET();
	memset(&ms_util_sdp1, 0, sizeof(ms_util_sdp1));
	memset(&ms_util_sdp2, 0, sizeof(ms_util_sdp2));
	return 0;
}

void media_util_release_static(void)
{
	MS_UTIL_BUF_RELEASE();
	free_sdp_content(&ms_util_sdp1);
	free_sdp_content(&ms_util_sdp2);
}

int media_fork(struct dlg_cell *dlg, struct media_fork_info *mf)
{
	int ret;
	str destination;

	if (mf->state != MEDIA_FORK_OFF)
		return 0;

	destination.s = pkg_malloc(4 /* udp: */ +
		mf->ip.len + 1 /* : */ + mf->port.len);
	if (!destination.s)
		return -1;
	memcpy(destination.s, "udp:", 4);
	destination.len = 4;
	memcpy(destination.s + destination.len, mf->ip.s, mf->ip.len);
	destination.len += mf->ip.len;
	destination.s[destination.len++] = ':';
	memcpy(destination.s + destination.len, mf->port.s, mf->port.len);
	destination.len += mf->port.len;

	if (media_rtp.start_recording(&dlg->callid,
			&dlg->legs[mf->leg].tag, &dlg->legs[other_leg(dlg, mf->leg)].tag,
			NULL, NULL, &destination, mf->medianum + 1) < 0) {
		LM_ERR("cannot start forking for medianum %d\n", mf->medianum);
		ret = -2;
	} else {
		mf->state = MEDIA_FORK_ON;
		ret = 0;
	}
	pkg_free(destination.s);

	return ret;
}

static int media_nofork(struct dlg_cell *dlg, struct media_fork_info *mf)
{
	int ret;
	if (mf->state != MEDIA_FORK_ON)
		return 0;

	if (media_rtp.stop_recording(&dlg->callid,
			&dlg->legs[mf->leg].tag, &dlg->legs[other_leg(dlg, mf->leg)].tag,
			NULL, mf->medianum + 1) < 0) {
		LM_ERR("cannot stop forking for medianum %d\n", mf->medianum);
		ret = -2;
	} else {
		ret = 0;
		mf->state = MEDIA_FORK_OFF;
	}
	return ret;
}

int media_forks_stop(struct media_session_leg *msl)
{
	struct media_fork_info *mf;

	for (mf = msl->params; mf; mf = mf->next)
		media_nofork(msl->ms->dlg, mf);
	media_forks_free(msl->params);
	msl->params = NULL;
	return 0;
}

static int media_fork_stream_disable(sdp_stream_cell_t *stream)
{
	str tmp;
	static str port = str_init("0");
	/* here we copy the entire m= line, but set the port to 0 */
	tmp.s = stream->body.s;
	tmp.len = stream->port.s - stream->body.s;
	MS_UTIL_BUF_COPY(tmp);
	MS_UTIL_BUF_COPY(port);
	tmp.s = stream->port.s+ stream->port.len; /* skip the port */
	tmp.len = stream->payloads.len + stream->payloads.s - tmp.s;
	MS_UTIL_BUF_COPY(tmp);

	return 0;
}

int media_fork_pause_resume(struct media_session_leg *msl, int medianum, int resume)
{
	int flags;
	struct media_fork_info *mf;
	int ret = 0;

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
	MEDIA_LEG_STATE_SET_UNSAFE(msl, MEDIA_SESSION_STATE_PENDING);
	MEDIA_LEG_UNLOCK(msl);

	flags = (resume?MEDIA_FORK_START:MEDIA_FORK_STOP);

	for (mf = msl->params; mf; mf = mf->next) {
		if (medianum < 0 || medianum == mf->medianum) {
			if (!resume) {
				if (mf->state != MEDIA_FORK_ON)
					continue;
			} else {
				if (mf->state != MEDIA_FORK_OFF)
					continue;
			}
			MEDIA_FORK_SET_FLAG(mf, flags);
			ret++;
			if (medianum >= 0)
				break;
		}
	}

	if (ret != 0) {
		if (media_session_fork_update(msl) < 0) {
			LM_ERR("could not update media session leg!\n");
			ret = 0;
		}
	}
	return ret;
}

static int media_fork_prepare_body(void)
{
	str tmp;
	time_t now = time(NULL);
	static str sdp_header1 = str_init("v=0\r\no=- ");
	static str sdp_header2 = str_init(" 0 IN IP4 127.0.0.1\r\ns=-\r\n"
			"c=IN IP4 127.0.0.1\r\nt=0 0\r\n");

	MS_UTIL_BUF_RESET();
	MS_UTIL_BUF_COPY(sdp_header1);
	tmp.s = int2str(now, &tmp.len);
	MS_UTIL_BUF_COPY(tmp);
	MS_UTIL_BUF_COPY(sdp_header2);

	return 0;
}

int media_fork_streams(struct media_session_leg *msl, struct media_fork_info *mfork)
{
	int ret = 0;
	str reason;

	/* start recording for all streams */
	for (; mfork; mfork = mfork->next)
		if (media_fork(msl->ms->dlg, mfork) == 0)
			ret++;
	if (ret == 0) {
		reason.s = "OK";
		reason.len = strlen(reason.s);
		media_session_rpl(msl, METHOD_INVITE, 488, &reason, NULL);
		ret = -1;
	} else {
		reason.s = "OK";
		reason.len = strlen(reason.s);
		ret = media_session_rpl(msl, METHOD_INVITE, 200, &reason, MS_UTIL_BUF_STR);
	}
	return ret;
}

/* we are currently only saving top 3 matching payloads */
#define MEDIA_MAX_SDP_PAYLOAD 3

struct media_fork_info *media_fork_search(struct media_fork_info *mf, int search)
{
	for (; mf; mf = mf->next)
		if (mf->fork_medianum == search)
			return mf;
	return NULL;
}

struct media_fork_info *media_fork_search_param(struct media_fork_info *mf,
		void *search)
{
	for (; mf; mf = mf->next)
		if (mf->params == search)
			return mf;
	return NULL;
}


static struct media_fork_info *media_fork_get(struct media_fork_info *mf,
		int leg, int medianum)
{
	for (; mf; mf = mf->next)
		if (mf->leg == leg && mf->medianum == medianum)
			return mf;
	return NULL;
}

static int media_fork_stream_push(struct media_fork_info *mf,
		sdp_stream_cell_t *stream, sdp_stream_cell_t *search)
{
	sdp_payload_attr_t *attr, *sattr;
	int attr_matches, a;
	static str mline = str_init("m=");
	static str port = str_init(" 9 ");
	static str space = str_init(" ");
	static str slash = str_init("/");
	static str ptime = str_init("a=ptime:");
	static str rtpmap = str_init("a=rtpmap:");
	static str fmtp = str_init("a=fmtp:");
	static str crlf = str_init("\r\n");
	static str sendonly = str_init("a=sendonly\r\n");
	sdp_payload_attr_t *matched_attr[MEDIA_MAX_SDP_PAYLOAD];

	/* first, check if this stream is already reserved */
	if (media_fork_search_param(mf, search) != NULL)
		return 0;

	/* check if they have the same media type */
	if (str_strcmp(&search->media, &stream->media))
		return 0;
	/* check if the same transport */
	if (str_strcmp(&search->transport, &stream->transport))
		return 0;

	attr_matches = 0;

	for (attr = search->payload_attr;
			attr && attr_matches < MEDIA_MAX_SDP_PAYLOAD; attr = attr->next)
		for (sattr = stream->payload_attr;
				sattr && attr_matches < MEDIA_MAX_SDP_PAYLOAD; sattr = sattr->next)
			if (!str_strcmp(&attr->rtp_payload, &sattr->rtp_payload))
				/* we have a matching stream! */
				matched_attr[attr_matches++] = sattr;
	if (!attr_matches) {
		LM_DBG("no payload matching!\n");
		return 0;
	}

	MS_UTIL_BUF_COPY(mline);
	MS_UTIL_BUF_COPY(stream->media);
	MS_UTIL_BUF_COPY(port);
	MS_UTIL_BUF_COPY(stream->transport);
	for (a = attr_matches - 1; a >= 0; a--) {
		MS_UTIL_BUF_COPY(space);
		MS_UTIL_BUF_COPY(matched_attr[a]->rtp_payload);
	}
	MS_UTIL_BUF_COPY(crlf);
	for (a = attr_matches - 1; a >= 0; a--) {
		if (!matched_attr[a]->rtp_enc.len)
			continue;
		MS_UTIL_BUF_COPY(rtpmap);
		MS_UTIL_BUF_COPY(matched_attr[a]->rtp_payload);
		MS_UTIL_BUF_COPY(space);
		MS_UTIL_BUF_COPY(matched_attr[a]->rtp_enc);
		MS_UTIL_BUF_COPY(slash);
		MS_UTIL_BUF_COPY(matched_attr[a]->rtp_clock);
		MS_UTIL_BUF_COPY(crlf);
		if (matched_attr[a]->fmtp_string.len) {
			MS_UTIL_BUF_COPY(fmtp);
			MS_UTIL_BUF_COPY(matched_attr[a]->fmtp_string);
			MS_UTIL_BUF_COPY(crlf);
		}
	}

	if (stream->ptime.len) {
		MS_UTIL_BUF_COPY(ptime);
		MS_UTIL_BUF_COPY(stream->ptime);
		MS_UTIL_BUF_COPY(crlf);
	}
	MS_UTIL_BUF_COPY(sendonly);

	return attr_matches;
}

static inline int media_fork_add_stream(sdp_stream_cell_t *stream, int disabled)
{
	/* all good - create media forks info */
	static str sendonly = str_init("a=sendonly\r\n");
	static str inactive = str_init("a=inactive\r\n");
	static str port = str_init("9");
	str tmp;

	tmp.s = stream->body.s;
	tmp.len = stream->port.s - stream->body.s;
	/* copy everything to port */
	MS_UTIL_BUF_COPY(tmp);
	MS_UTIL_BUF_COPY(port);
	tmp.s = stream->port.s + stream->port.len;
	/* need to copy everything but c= and a=sendrecv line */
	if (stream->ip_addr.len && stream->sendrecv_mode.len) {
		/* both c= line and a=sendrecv */
		if (stream->ip_addr.len < stream->sendrecv_mode.len) {
			/* first one is the c= line */
			tmp.len = tmp.s - stream->ip_addr.s;
			MS_UTIL_BUF_COPY(tmp);
		} else {
			/* c= line is the second */
		}
	} else if (stream->ip_addr.len) {
		/* only c= line */
		tmp.len = stream->ip_addr.s - 9/* c=IN IP4  */ - tmp.s;
		MS_UTIL_BUF_COPY(tmp);
		tmp.s = stream->ip_addr.s + stream->ip_addr.len + 2/* \r\n */;
	} else if (stream->sendrecv_mode.len) {
		/* only a=sendrecv */
		tmp.len = stream->sendrecv_mode.s - 2/* a= */ - tmp.s;
		MS_UTIL_BUF_COPY(tmp);
		tmp.s = stream->sendrecv_mode.s + stream->sendrecv_mode.len + 2/* \r\n */;
	}
	/* last chunk */
	tmp.len = stream->body.s + stream->body.len - tmp.s;
	MS_UTIL_BUF_COPY(tmp);
	if (disabled)
		MS_UTIL_BUF_COPY(inactive);
	else
		MS_UTIL_BUF_COPY(sendonly);

	return 0;
}
#undef MS_UTIL_BUF_RESET
#undef MS_UTIL_BUF_EXTEND
#undef MS_UTIL_BUF_COPY

static inline sdp_stream_cell_t *media_fork_stream_match(struct media_fork_info *mf,
		sdp_info_t *sdp, sdp_stream_cell_t *search)
{
	sdp_session_cell_t *session;
	sdp_stream_cell_t *stream;

	if (!sdp->sessions)
		return NULL;

	/* find the media stream that has as many codecs as possible */
	for (session = sdp->sessions; session; session = session->next)
		for (stream = session->streams; stream; stream = stream->next)
			if (media_fork_stream_push(mf, stream, search))
				break;
	return stream;
}

static void media_fork_fill(struct media_fork_info *mf, str *ip, str *port)
{
	if (ip) {
		shm_free(mf->ip.s);
		shm_str_dup(&mf->ip, ip);
	}
	if (port) {
		shm_free(mf->port.s);
		shm_str_dup(&mf->port, port);
	}
}

static int media_fork_cmp(struct media_fork_info *mf, str *ip, str *port)
{
	if (!mf->ip.s || !mf->port.s)
		return 1;
	if (str_strcmp(&mf->ip, ip) != 0)
		return 1;
	if (str_strcmp(&mf->port, port) != 0)
		return 1;
	return 0;
}

static inline struct media_fork_info *media_fork_new(int leg, str *ip, str *port,
		int medianum, int fork_medianum)
{
	struct media_fork_info *mf;
	mf = shm_malloc(sizeof *mf);
	if (!mf) {
		LM_ERR("could not allocate new media fork!\n");
		return NULL;
	}
	memset(mf, 0, sizeof *mf);
	mf->leg = leg;
	media_fork_fill(mf, ip, port);
	mf->medianum = medianum;
	mf->fork_medianum = fork_medianum;
	mf->state = MEDIA_FORK_OFF;
	mf->flags = MEDIA_FORK_START;
	return mf;
}

static struct media_fork_info *media_fork_session(sdp_info_t *invite_sdp, int dlg_leg1, int dlg_leg2)
{
	struct media_fork_info *totalmf;
	struct media_fork_info *mf;
	sdp_session_cell_t *session;
	sdp_stream_cell_t *stream, *mstream;
	str *ip;
	int leg;
	int fork_medianum = 0;

	/* we start with empty media fork list */
	totalmf = NULL;

	/* we need to stream all legs */
	for (session = invite_sdp->sessions; session; session = session->next) {
		for (stream = session->streams; stream; stream = stream->next) {
			if ((mstream = media_fork_stream_match(totalmf, &ms_util_sdp1, stream))) {
				leg = dlg_leg1; /* matched in sdp of leg 1 */
			} else if (dlg_leg2 >= 0 &&
					(mstream = media_fork_stream_match(totalmf, &ms_util_sdp2, stream))) {
				leg = dlg_leg2; /* matched in sdp of leg 2 */
			} else {
				media_fork_stream_disable(stream);
				continue;
			}
			if (stream->ip_addr.len)
				ip = &stream->ip_addr;
			else
				ip = &session->ip_addr;
			mf = media_fork_new(leg, ip, &stream->port,
					mstream->stream_num, fork_medianum);
			if (!mf)
				continue;
			fork_medianum++;
			mf->params = mstream;
			/* link it to the total list */
			mf->next = totalmf;
			totalmf = mf;
		}
	}
	return totalmf;
}

static struct media_fork_info *media_fork_medianum(sdp_info_t *invite_sdp,
		int dlg_leg1, int dlg_leg2, int medianum)
{
	int leg;
	str *ip;
	int fork_medianum = 0;
	struct media_fork_info *totalmf, *mf;
	sdp_session_cell_t *session;
	sdp_stream_cell_t *stream, *mstream;
	sdp_stream_cell_t *dlg_stream1, *dlg_stream2;

	dlg_stream1 = dlg_stream2 = NULL;

	/* find the stream that we are going to fork */
	for (session = ms_util_sdp1.sessions; session; session = session->next)
		for (dlg_stream1 = session->streams; dlg_stream1;
				dlg_stream1 = dlg_stream1->next)
			if (dlg_stream1->stream_num == medianum)
				break;
	if (dlg_leg2 >= 0) {
		for (session = ms_util_sdp2.sessions; session; session = session->next)
			for (dlg_stream2 = session->streams; dlg_stream2;
					dlg_stream2 = dlg_stream2->next)
				if (dlg_stream2->stream_num == medianum)
					break;
	}
	if (!dlg_stream1 && !dlg_stream2) {
		LM_ERR("medianum %d not found!\n", medianum);
		return 0;
	}

	totalmf = NULL;
	/* now match it against the invite */
	for (session = invite_sdp->sessions; session; session = session->next)
		for (stream = session->streams; stream; stream = stream->next) {
			if (dlg_stream1 && ((mstream = media_fork_stream_match(totalmf, &ms_util_sdp1, stream)))) {
				leg = dlg_leg1;
			} else if (dlg_stream2 && ((mstream = media_fork_stream_match(totalmf, &ms_util_sdp2, stream)))) {
				leg = dlg_leg2;
			} else {
				media_fork_stream_disable(stream);
				continue;
			}
			if (stream->ip_addr.len)
				ip = &stream->ip_addr;
			else
				ip = &session->ip_addr;
			mf = media_fork_new(leg, ip, &stream->port,
					mstream->stream_num, fork_medianum);
			if (!mf)
				continue;
			fork_medianum++;
			mf->params = mstream;
			/* link it to the total list */
			mf->next = totalmf;
			totalmf = mf;
		}

	return totalmf;
}

static struct media_fork_info *media_fork_session_sdp(int dlg_leg1, int dlg_leg2)
{
	static unsigned long medianum_idx = 0;

	struct media_fork_info *mf, *totalmf = NULL;
	sdp_session_cell_t *session;
	sdp_stream_cell_t *stream;

	for (session = ms_util_sdp1.sessions; session; session = session->next)
		for (stream = session->streams; stream; stream = stream->next) {
			if (media_fork_add_stream(stream, 0) == 0 &&
					(mf = media_fork_new(dlg_leg1, NULL, NULL,
										 stream->stream_num, medianum_idx))) {
				mf->params = (void *)medianum_idx;
				mf->next = totalmf;
				totalmf = mf;
				medianum_idx++;
			}
		}
	if (dlg_leg2 >= 0) {
		for (session = ms_util_sdp2.sessions; session; session = session->next)
			for (stream = session->streams; stream; stream = stream->next) {
				if (media_fork_add_stream(stream, 0) == 0 &&
					(mf = media_fork_new(dlg_leg2, NULL, NULL,
										 stream->stream_num, medianum_idx))) {
					mf->params = (void *)medianum_idx;
					mf->next = totalmf;
					totalmf = mf;
					medianum_idx++;
				}
			}
	}
	return totalmf;
}

static struct media_fork_info *media_fork_medianum_sdp(int dlg_leg1, int dlg_leg2, int medianum)
{
	static unsigned long medianum_idx = 0;

	struct media_fork_info *mf, *totalmf = NULL;
	sdp_session_cell_t *session;
	sdp_stream_cell_t *stream;

	for (session = ms_util_sdp1.sessions; session; session = session->next)
		for (stream = session->streams; stream; stream = stream->next)
			if (stream->stream_num == medianum &&
					media_fork_add_stream(stream, 0) == 0 &&
					(mf = media_fork_new(dlg_leg1, NULL, NULL,
										 medianum, medianum_idx))) {
				mf->params = (void *)medianum_idx;
				mf->next = totalmf;
				totalmf = mf;
				medianum_idx++;
			}
	if (dlg_leg2 >= 0) {
		for (session = ms_util_sdp2.sessions; session; session = session->next)
			for (stream = session->streams; stream; stream = stream->next)
				if (stream->stream_num == medianum &&
						media_fork_add_stream(stream, 0) == 0 &&
						(mf = media_fork_new(dlg_leg2, NULL, NULL,
											medianum, medianum_idx))) {
					mf->params = (void *)medianum_idx;
					mf->next = totalmf;
					totalmf = mf;
					medianum_idx++;
				}
	}
	return totalmf;
}

static int media_sdp_parse(struct dlg_cell *dlg, int leg, int medianum,
		str *caller_body, str *callee_body)
{
	str body1, body2;
	int leg_streams = 0;

	if (!caller_body) {
		body1 = dlg_get_out_sdp(dlg, DLG_CALLER_LEG);
		caller_body = &body2;
	}
	if (!callee_body) {
		body2 = dlg_get_out_sdp(dlg, callee_idx(dlg));
		callee_body = &body1;
	}
	switch (leg) {
		case MEDIA_LEG_CALLER:
		case MEDIA_LEG_CALLEE:
			if (parse_sdp_session((leg == MEDIA_LEG_CALLER?caller_body:callee_body),
					0, NULL, &ms_util_sdp1) < 0) {
				LM_ERR("could not parse SDP within dialog!\n");
				goto error;
			}
			if (medianum >= 0 && medianum >= ms_util_sdp1.streams_num)
				LM_WARN("medianum %d does not exist in body for leg %d\n", medianum, leg);
			else
				leg_streams = ms_util_sdp1.streams_num;
			break;
		case MEDIA_LEG_BOTH:
			if (parse_sdp_session(caller_body, 0, NULL, &ms_util_sdp1) < 0) {
				LM_ERR("could not parse caller SDP within dialog!\n");
				goto error;
			}
			if (medianum >= 0 && medianum >= ms_util_sdp1.streams_num)
				LM_WARN("medianum %d does not exist in caller's body\n", medianum);
			else
				leg_streams = ms_util_sdp1.streams_num;
			if (parse_sdp_session(callee_body, 0, NULL, &ms_util_sdp2) < 0) {
				LM_ERR("could not parse callee SDP within dialog!\n");
				goto error;
			}
			if (medianum >= 0 && medianum >= ms_util_sdp2.streams_num)
				LM_WARN("medianum %d does not exist in callee's body\n", medianum);
			else
				leg_streams += ms_util_sdp2.streams_num;
			break;
	}
	return leg_streams;
error:
	return -1;
}

struct media_fork_info *media_sdp_match(struct dlg_cell *dlg,
		int leg, sdp_info_t *invite_sdp, int medianum)
{
	struct media_fork_info *mf;

	int leg_streams = media_sdp_parse(dlg, leg, medianum, NULL, NULL);
	if (!leg_streams) {
		LM_WARN("no stream to fork!\n");
		goto error;
	}
	if (medianum < 0) {
		/* if medianum is not specified, we need to stream everything */
		if (leg_streams > invite_sdp->streams_num) {
			LM_ERR("INVITE stream has %d streams, but we need to fork %d\n",
					invite_sdp->streams_num, leg_streams);
			goto error;
		}
	} else if (leg == MEDIA_LEG_BOTH) {
		if (invite_sdp->streams_num < 2) {
			LM_ERR("INVITE stream has %d streams, but we need to fork 2\n",
					invite_sdp->streams_num);
			goto error;
		}
	} /* else we have one leg to stream and at least one leg in the INVITE */

	/* this was the fast processing, now let's try to match each session in
	 * the call with the sessions we have in the invite */
	if (media_fork_prepare_body() < 0) {
		LM_ERR("could not prepare fork body!\n");
		goto error;
	}
	if (leg == MEDIA_LEG_BOTH) {
		if (medianum < 0)
			mf = media_fork_session(invite_sdp,
					DLG_CALLER_LEG, callee_idx(dlg));
		else
			mf = media_fork_medianum(invite_sdp,
					DLG_CALLER_LEG, callee_idx(dlg), medianum);
	} else {
		if (medianum < 0)
			mf = media_fork_session(invite_sdp,
					DLG_MEDIA_SESSION_LEG(dlg, leg), -1);
		else
			mf = media_fork_medianum(invite_sdp,
					DLG_MEDIA_SESSION_LEG(dlg, leg), -1, medianum);
	}
	return mf;
error:
	media_util_release_static();
	return NULL;
}

struct media_fork_info *media_sdp_get(struct dlg_cell *dlg,
		int leg, int medianum, str *caller_body, str *callee_body)
{
	struct media_fork_info *mf;

	int leg_streams = media_sdp_parse(dlg, leg, medianum, caller_body, callee_body);
	if (!leg_streams) {
		LM_WARN("no stream to fork!\n");
		goto error;
	}
	/* here it is very simple: add everythig in the SDP, but make sure we
	 * don't advertise a c= line, a port, or a sendrecv line */
	if (media_fork_prepare_body() < 0) {
		LM_ERR("could not prepare fork body!\n");
		goto error;
	}

	if (leg == MEDIA_LEG_BOTH) {
		if (medianum < 0)
			mf = media_fork_session_sdp(DLG_CALLER_LEG, callee_idx(dlg));
		else
			mf = media_fork_medianum_sdp(DLG_CALLER_LEG, callee_idx(dlg), medianum);
	} else {
		if (medianum < 0)
			mf = media_fork_session_sdp(DLG_MEDIA_SESSION_LEG(dlg, leg), 0);
		else
			mf = media_fork_medianum_sdp(DLG_MEDIA_SESSION_LEG(dlg, leg), 0, medianum);
	}
	return mf;
error:
	media_util_release_static();
	return NULL;
}



str *media_sdp_buf_get(void)
{
	return MS_UTIL_BUF_STR;
}

void media_forks_free(struct media_fork_info *mf)
{
	struct media_fork_info *mfork;

	for (mfork = mf; mfork; mfork = mf) {
		mf = mfork->next;
		if (mfork->ip.s)
			shm_free(mfork->ip.s);
		if (mfork->port.s)
			shm_free(mfork->port.s);
		shm_free(mfork);
	}
}
#undef MS_UTIL_BUF_RELEASE

int media_fork_update(struct media_session_leg *msl,
		struct media_fork_info *mf, str *ip, str *port, int disabled)
{
	if (disabled) {
		if (mf->state == MEDIA_FORK_OFF)
			return 0;
		if (media_nofork(msl->ms->dlg, mf) != 0)
			return 0;
		MEDIA_FORK_RESET_FLAG(mf, MEDIA_FORK_STOP);
		MEDIA_FORK_SET_FLAG(mf, MEDIA_FORK_DIRTY);
		return 1;
	}

	if (MEDIA_FORK_HAS_FLAG(mf, MEDIA_FORK_STOP)) {
		LM_WARN("media fork should be stopped, but media server didn't do it!\n");
		MEDIA_FORK_RESET_FLAG(mf, MEDIA_FORK_STOP);
	}

	if (mf->state == MEDIA_FORK_ON) {
		/* if we have an ongoing media fork, update it */
		if (media_fork_cmp(mf, ip, port)) {
			/* same thing - leave it like this */
			return 1;
		} else {
			/* disable previous forking */
			media_nofork(msl->ms->dlg, mf);
		}
	}
	media_fork_fill(mf, ip, port);
	if (media_fork(msl->ms->dlg, mf) != 0)
		return 0;

	MEDIA_FORK_RESET_FLAG(mf, MEDIA_FORK_START);
	MEDIA_FORK_SET_FLAG(mf, MEDIA_FORK_DIRTY);
	return 1;
}

int media_fork_body_update(struct media_session_leg *ml, str *body, int leg)
{
	int changed = 0;
	sdp_info_t sdp;
	sdp_session_cell_t *session;
	sdp_stream_cell_t *stream;
	struct media_fork_info *mf;

	memset(&sdp, 0, sizeof sdp);

	if (parse_sdp_session(body, 0, NULL, &sdp) < 0) {
		LM_ERR("could not parse SDP body!\n");
		return -1;
	}

	for (session = sdp.sessions; session; session = session->next)
		for (stream = session->streams; stream; stream = stream->next) {
			mf = media_fork_get(ml->params, leg, stream->stream_num);
			if (mf) {
				if (stream->is_on_hold) {
					if (mf->state == MEDIA_FORK_ON) {
						MEDIA_FORK_SET_FLAG(mf, MEDIA_FORK_STOP);
						changed++;
					} else {
						LM_DBG("media stream %d already OFF!\n", stream->stream_num);
					}
				} else {
					if (mf->state == MEDIA_FORK_OFF) {
						MEDIA_FORK_SET_FLAG(mf, MEDIA_FORK_START);
						changed++;
					} else {
						LM_DBG("media stream %d already ON!\n", stream->stream_num);
					}
				}
			} else {
				LM_DBG("media stream %d not found!\n", stream->stream_num);
			}
		}
	free_sdp_content(&sdp);
	return changed;
}

int media_session_fork_update(struct media_session_leg *msl)
{
	int ret = -1;
	struct media_fork_info *mf;
	media_util_init_static();
	int media_idx = 0;
	int media_disabled;
	sdp_session_cell_t *session;
	sdp_stream_cell_t *stream;
	sdp_info_t *sdp;

	/* let us prepare the SDPs */
	if (!media_sdp_parse(msl->ms->dlg, msl->leg, -1, NULL, NULL)) {
		LM_ERR("could not parse the dialog SDPs!\n");
		goto error;
	}

	if (media_fork_prepare_body() < 0) {
		LM_ERR("could not prepare fork body!\n");
		goto error;
	}
	/* go through each media fork and dump the stream */
	while (1) {
		for (mf = msl->params; mf; mf = mf->next)
			if (mf->fork_medianum == media_idx)
				break;
		if (!mf)
			break;
		media_idx++;
		/* check to see on which SDP we should look */
		if (mf->leg == DLG_CALLER_LEG)
			sdp = &ms_util_sdp1;
		else if (msl->leg == MEDIA_LEG_BOTH)
			sdp = &ms_util_sdp2;
		else
			sdp = &ms_util_sdp1;
		for (session = sdp->sessions; session; session = session->next)
			for (stream = session->streams; stream; stream = stream->next) {
				if (mf->state == MEDIA_FORK_OFF)
					media_disabled = 1;
				else
					media_disabled = 0;
				media_fork_add_stream(stream, media_disabled);
			}
	}
	if (media_idx != 0) {
		if (media_session_req(msl, "INVITE", MS_UTIL_BUF_STR) < 0) {
			LM_ERR("could not challenge media server!\n");
			ret = -3;
		}
	}
	ret = 0;
error:
	if (ret < 0) {
		/* leave the session in an updable state */
		MEDIA_LEG_STATE_SET(msl, MEDIA_SESSION_STATE_RUNNING);
	}
	media_util_release_static();
	return ret;
}

static void media_exchange_event_create(struct media_session_leg *msl,
		bin_packet_t *store)
{
	struct media_fork_info *mf;
	int count = 0;

	bin_push_int(store, msl->type);
	bin_push_int(store, msl->nohold);

	/* if it is a fork, we also need to push the streamed media sessions */
	if (msl->type == MEDIA_SESSION_TYPE_FORK) {
		count = 0; /* count to know how many we have */
		for (mf = msl->params; mf; mf = mf->next)
			count++;
		bin_push_int(store, count);
		for (mf = msl->params; mf; mf = mf->next) {
			/* we only need the dlg leg and medianum */
			bin_push_int(store, mf->leg);
			bin_push_int(store, mf->medianum);
			bin_push_int(store, mf->fork_medianum);
			bin_push_int(store, mf->state);
			bin_push_str(store, &mf->ip);
			bin_push_str(store, &mf->port);
		}
	}
}

static void media_exchange_event_update(struct media_session_leg *msl,
		bin_packet_t *store)
{
	struct media_fork_info *mf;
	int count = 0;

	/* we only need to update forked sessions */
	if (msl->type != MEDIA_SESSION_TYPE_FORK)
		return;

	count = 0; /* count how many forks have been updated */
	for (mf = msl->params; mf; mf = mf->next)
		if (MEDIA_FORK_HAS_FLAG(mf, MEDIA_FORK_DIRTY))
			count++;
	bin_push_int(store, count);
	for (mf = msl->params; mf; mf = mf->next) {
		if (!MEDIA_FORK_HAS_FLAG(mf, MEDIA_FORK_DIRTY))
			continue;
		bin_push_int(store, mf->fork_medianum);
		bin_push_int(store, mf->state);
		bin_push_str(store, &mf->ip);
		bin_push_str(store, &mf->port);
	}
}

void media_exchange_event_trigger(enum b2b_entity_type et, str *key,
		str *param, enum b2b_event_type event_type, bin_packet_t *store,
		int backend)
{
	struct media_session_leg *msl = *(struct media_session_leg **)((str *)param)->s;

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

	str ip, port;
	int type, nohold, medianum, fork_medianum;
	int mf_count = 0;
	struct media_fork_info *mf;
	struct media_session_leg *msl;
	enum media_fork_state state;

	if (bin_pop_int(store, &type) != 0)
		return;
	if (bin_pop_int(store, &nohold) != 0)
		return;

	if (type == MEDIA_SESSION_TYPE_FORK)
		bin_pop_int(store, &mf_count);

	if (dlg) {
		msl = media_session_new_leg(dlg, type, leg, nohold);
		if (!msl)
			LM_ERR("cannot create new leg!\n");
	} else {
		msl = NULL;
	}
	/* if we have any media forks, pop them */
	while (mf_count-- > 0) {
		bin_pop_int(store, &leg);
		bin_pop_int(store, &medianum);
		bin_pop_int(store, &fork_medianum);
		bin_pop_int(store, &state);
		bin_pop_str(store, &ip);
		bin_pop_str(store, &port);
		if (msl) {
			mf = media_fork_new(leg, (ip.len?&ip:NULL),
					(port.len?&port:NULL), medianum, fork_medianum);
			if (!mf)
				continue;
			mf->next = msl->params;
			mf->state = state;
			msl->params = mf;
		}
	}
	/* if we do not have a dialog, the drain is completed */
	if (!msl)
		return;

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
	struct media_fork_info *mf;
	struct media_session *ms;
	enum media_fork_state state;
	int fork_medianum;
	int mf_count = 0;
	str ip, port;

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

	bin_pop_int(store, &mf_count);
	while (mf_count-- > 0) {
		if (bin_pop_int(store, &fork_medianum) != 0)
			return;
		if (bin_pop_int(store, &state) != 0)
			return;
		if (bin_pop_str(store, &ip) != 0)
			return;
		if (bin_pop_str(store, &port) != 0)
			return;
		if (msl && (mf = media_fork_search(msl->params, fork_medianum))) {
			media_fork_fill(mf, &ip, &port);
			mf->state = state;
		}
	}
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
		str *param, enum b2b_event_type event_type, bin_packet_t *store,
		int backend)
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

	media_dlg.dlg_unref(dlg, 1);
	return;
}
