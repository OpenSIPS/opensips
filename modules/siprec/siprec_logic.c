/*
 * Copyright (C) 2017 OpenSIPS Project
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
 *
 *
 * History:
 * ---------
 *  2017-06-20  created (razvanc)
 */

#include "siprec_logic.h"
#include "siprec_body.h"
#include "../../mod_fix.h"
#include "../../error.h"

int srec_dlg_idx;
struct b2b_api srec_b2b;
struct rtp_relay_binds srec_rtp;
str skip_failover_codes = str_init("");
static regex_t skip_codes_regex;

static str mod_name = str_init("siprec");

#ifdef DBG_SIPREC_HIST
struct struct_hist_list *srec_hist;
#endif

static int srs_send_invite(struct src_sess *sess);

int src_init(void)
{
#ifdef DBG_SIPREC_HIST
	srec_hist = shl_init("SIPREC sessions", 1000, 1);
	if (!srec_hist) {
		LM_ERR("oom siprec hist\n");
		return -1;
	}
#endif

	if (srec_b2b.register_cb(src_event_received,
			B2BCB_RECV_EVENT, &mod_name) < 0) {
		LM_ERR("could not register SIPREC event receive callback!\n");
		return -1;
	}

	if (srec_b2b.register_cb(src_event_trigger,
			B2BCB_TRIGGER_EVENT, &mod_name) < 0) {
		LM_ERR("could not register SIPREC event trigger callback!\n");
		return -1;
	}

	skip_failover_codes.len = strlen(skip_failover_codes.s);
	if (!skip_failover_codes.len)
		return 0;

	/* here skip_failover_codes.s is always NULL terminated! */
	if (regcomp(&skip_codes_regex, skip_failover_codes.s, (REG_EXTENDED|REG_ICASE|REG_NOSUB))) {
		LM_ERR("cannot compile skip_failover_codes regex [%.*s]!\n",
				skip_failover_codes.len, skip_failover_codes.s);
		return -1;
	}

	return 0;
}

static int srs_skip_failover(str status)
{
	regmatch_t pmatch;
	char tmp_buff[4];

	if (skip_failover_codes.len == 0)
		return 0;
	if (status.len > 3) {
		LM_WARN("Unknown status %.*s\n", status.len, status.s);
		return 0;
	}
	memcpy(tmp_buff, status.s, status.len);
	tmp_buff[status.len] = 0;

	if (!regexec(&skip_codes_regex, tmp_buff, 1, &pmatch, 0))
		return 1;
	return 0;
}

static int srs_do_failover(struct src_sess *sess)
{
	struct srs_node *node;

	if (list_empty(&sess->srs)) {
		LM_BUG("failover without any destination!\n");
		return -1;
	}
	srec_logic_destroy(sess, 1);

	/* pop the first element */
	node = list_entry(sess->srs.next, struct srs_node, list);
	list_del(&node->list);
	shm_free(node);

	if (list_empty(&sess->srs)) {
		LM_INFO("no more SRS servers to use!\n");
		return -1;
	}

	return srs_send_invite(sess);
}

static void tm_update_recording(struct cell *t, int type, struct tmcb_params *ps);

static void srec_tm_unref(void *p)
{
	struct src_sess *ss = (struct src_sess *)p;
	srec_hlog(ss, SREC_UNREF, "update unref");
	SIPREC_UNREF(ss);
}

static void srec_dlg_end(struct dlg_cell *dlg, int type, struct dlg_cb_params *_params)
{
	struct src_sess *ss;
	struct b2b_req_data req;

	str bye = str_init(BYE);

	if (!_params) {
		LM_ERR("no parameter specified to dlg callback!\n");
		return;
	}
	ss = *_params->param;

	if ((ss->flags & SIPREC_STARTED) == 0) {
		LM_DBG("sess=%p no longer in progress\n", ss);
		/* the session was not started, or it had been deleted in the meantime */
		return;
	}

	memset(&req, 0, sizeof(req));
	req.et = B2B_CLIENT;
	req.b2b_key = &ss->b2b_key;
	req.method = &bye;
	req.dlginfo = ss->dlginfo;
	req.no_cb = 1; /* do not call callback */

	if (srec_b2b.send_request(&req) < 0)
		LM_ERR("Cannot end recording session for key %.*s\n",
				req.b2b_key->len, req.b2b_key->s);
	srec_rtp.copy_delete(ss->rtp, &mod_name, &ss->media);
	srec_logic_destroy(ss, 0);
}

static void srec_dlg_sequential(struct dlg_cell *dlg, int type, struct dlg_cb_params *_params)
{
	struct src_sess *ss;
	/* check which participant we are talking about */
	ss = *_params->param;

	if ((ss->flags & SIPREC_STARTED) == 0) {
		LM_DBG("sess=%p no longer pending\n", ss);
		return;
	}

	SIPREC_LOCK(ss);

	SIPREC_REF_UNSAFE(ss);
	if (srec_tm.register_tmcb(_params->msg, 0, TMCB_RESPONSE_OUT, tm_update_recording,
			ss, srec_tm_unref) <= 0) {
		LM_ERR("cannot register tm callbacks for reply\n");
		srec_hlog(ss, SREC_UNREF, "error updating recording");
		SIPREC_UNREF_UNSAFE(ss);
	}
	SIPREC_UNLOCK(ss);
}

static void dlg_src_unref_session(void *p)
{
	struct src_sess *ss = (struct src_sess *)p;
	/* if the dialog is not in termination state, we should not delete it */
	if (ss->dlg->state < DLG_STATE_DELETED)
		return;
	srec_hlog(ss, SREC_UNREF, "dlg recording unref");
	SIPREC_UNREF(ss);
}

int srec_register_callbacks(struct src_sess *sess)
{
	if (sess->flags & SIPREC_DLG_CBS)
		return 0;

	/* also, the b2b ref moves on the dialog */
	if (srec_dlg.register_dlgcb(sess->dlg, DLGCB_TERMINATED|DLGCB_EXPIRED|DLGCB_FAILED,
			srec_dlg_end, sess, dlg_src_unref_session)){
		LM_ERR("cannot register callback for dialog termination\n");
		return -1;
	}

	/* register handler for sequentials */
	if (srec_dlg.register_dlgcb(sess->dlg, DLGCB_REQ_WITHIN,
			srec_dlg_sequential, sess, NULL)){
		LM_ERR("cannot register callback for sequential messages\n");
		return -1;
	}

	/* store the session in the dialog */
	if (srec_dlg.register_dlgcb(sess->dlg, DLGCB_WRITE_VP,
			srec_dlg_write_callback, sess, NULL))
		LM_WARN("cannot register callback for session serialization! "
			"Will not be able to end siprec session in case of a restart!\n");

	if (srec_dlg.register_dlgcb(sess->dlg, DLGCB_PROCESS_VARS,
			srec_dlg_read_callback, sess, NULL))
		LM_WARN("cannot register callback for session de-serialization! "
			"Will not be able to handle in-dialog for replicated sessions!\n");
	LM_DBG("registered dialog callbacks for %p\n", sess);
	sess->flags |= SIPREC_DLG_CBS;
	return 0;
}

int srec_reply(struct src_sess *ss, int method, int code, str *body)
{
	static str content_type_sdp_hdr = str_init("Content-Type: application/sdp\r\n");
	b2b_rpl_data_t reply_data;
	str reason;

	init_str(&reason, error_text(code));

	memset(&reply_data, 0, sizeof (reply_data));
	reply_data.et = B2B_CLIENT;
	reply_data.b2b_key = &ss->b2b_key;
	reply_data.method = method;
	reply_data.code = code;
	reply_data.text = &reason;
	reply_data.body = body;
	reply_data.dlginfo = ss->dlginfo;
	if (body)
		reply_data.extra_headers = &content_type_sdp_hdr;

	return srec_b2b.send_reply(&reply_data);
}

static int srec_get_body(struct src_sess *sess, str *body)
{
	unsigned int flags = RTP_COPY_MODE_SIPREC|RTP_COPY_LEG_BOTH;
	struct rtp_relay_streams streams;
	struct rtp_relay_stream *stream;
	int s;

	if (sess->flags & SIPREC_PAUSED)
		flags |= RTP_COPY_MODE_DISABLE;

	if (srec_rtp.copy_offer(sess->rtp, &mod_name,
			&sess->media, flags, -1, body, &streams) < 0) {
		LM_ERR("could not start recording!\n");
		return -3;
	}
	for (s = 0; s < streams.count; s++) {
		stream = &streams.streams[s];
		srs_fill_sdp_stream(stream->label, stream->medianum,
				NULL, sess, &sess->participants[stream->leg]);
	}
	return 0;
}


static int srec_b2b_req(struct sip_msg *msg, struct src_sess *ss)
{
	str body = str_init("");
	int code = 405;

	if (get_body(msg, &body) != 0 || body.len==0) {
		if (msg->REQ_METHOD != METHOD_UPDATE)
			goto reply;
		code = 200;
	} else {
		if (srec_rtp.copy_answer(ss->rtp, &mod_name,
				&ss->media, &body) < 0) {
			LM_ERR("could not offer new SDP!\n");
			code = 488;
			goto reply;
		}
		if (srec_get_body(ss, &body) < 0) {
			LM_ERR("could not refresh recording!\n");
			goto reply;
		}
		code = 200;
	}

reply:
	srec_reply(ss, msg->REQ_METHOD, code, (body.len?&body:NULL));
	return 0;
}

static int srec_b2b_notify(struct sip_msg *msg, str *key, int type,
		str *logic_key, void *param, int flags)
{
	struct b2b_req_data req;
	struct src_sess *ss;
	int ret = -1;
	str ack = str_init(ACK);
	str bye = str_init(BYE);

	if (!param) {
		LM_ERR("no callback parameter specified!\n");
		return -1;
	}
	ss = (struct src_sess *)param;
	if (!ss) {
		LM_ERR("cannot find session in parameter!\n");
		return -1;
	}
	if ((ss->flags & SIPREC_STARTED) == 0) {
		LM_DBG("sess=%p no longer active\n", ss);
		return 0;
	}
	/* for now we only receive replies from SRS */
	if (type != B2B_REPLY)
		return srec_b2b_req(msg, ss);

	LM_DBG("received b2b reply with code %d\n", msg->REPLY_STATUS);

	ret = 0;
	/* check if the reply was successful */
	if (msg->REPLY_STATUS < 200) {
		/* wait for a final reply */
		return 0;
	} else if (msg->REPLY_STATUS > 300) {
		/* if this is a re-invite, it was simply declined - do not update
		 * ongoing media sessions */
		if (ss->flags & SIPREC_ONGOING)
			return 0;
		if (srs_skip_failover(msg->first_line.u.reply.status) ||
				srs_do_failover(ss) < 0) {
			LM_DBG("no more to failover!\n");
			goto no_recording;
		} else
			return 0;
	}
	ret = -1;

	if (ss->initial_sdp.s) {
		shm_free(ss->initial_sdp.s);
		ss->initial_sdp.s = NULL;
	}

	/* reply received - sending ACK */
	memset(&req, 0, sizeof(req));
	req.et = B2B_CLIENT;
	req.b2b_key = &ss->b2b_key;
	req.method = &ack;
	req.dlginfo = ss->dlginfo;
	req.no_cb = 1; /* do not call callback */

	if (srec_b2b.send_request(&req) < 0) {
		LM_ERR("Cannot ack recording session for key %.*s\n",
				req.b2b_key->len, req.b2b_key->s);
		goto no_recording;
	}

	if (ss->dlg->state > DLG_STATE_DELETED) {
		LM_ERR("dialog already in deleted state!\n");
		goto no_recording;
	}
	ss->flags |= SIPREC_ONGOING;

	if (srs_handle_media(msg, ss) < 0) {
		LM_ERR("cannot handle SRS media!\n");
		goto no_recording;
	}

	if (srec_register_callbacks(ss) < 0) {
		LM_ERR("cannot register callback for terminating session\n");
		goto no_recording;
	}

	return 0;
no_recording:
	if (ret != 0) {
		memset(&req, 0, sizeof(req));
		req.et = B2B_CLIENT;
		req.b2b_key = &ss->b2b_key;
		req.method = &bye;
		req.dlginfo = ss->dlginfo;
		req.no_cb = 1; /* do not call callback */

		if (srec_b2b.send_request(&req) < 0)
			LM_ERR("Cannot send bye for recording session with key %.*s\n",
					req.b2b_key->len, req.b2b_key->s);
	}
	srec_rtp.copy_delete(ss->rtp, &mod_name, &ss->media);
	srec_logic_destroy(ss, 0);

	if (!(ss->flags & SIPREC_DLG_CBS)) {
		/* if the dialog has already been engaged, then we need to keep the
		 * reference until the end of the dialog, where it will be cleaned up */
		srec_dlg.dlg_ctx_put_ptr(ss->dlg, srec_dlg_idx, NULL);
		srec_hlog(ss, SREC_UNREF, "no recording");
		SIPREC_UNREF(ss);
	}
	return ret;
}


int srec_restore_callback(struct src_sess *sess)
{
	if (srec_b2b.restore_logic_info(B2B_CLIENT, &sess->b2b_key,
			srec_b2b_notify, sess, NULL) < 0) {
		LM_ERR("cannot register notify callback for [%.*s]!\n",
				sess->b2b_key.len, sess->b2b_key.s);
		return -1;
	}
	if (srec_b2b.update_b2bl_param(B2B_CLIENT, &sess->b2b_key,
			&sess->dlg->callid, 1) < 0) {
		LM_ERR("cannot update param for [%.*s]!\n",
				sess->b2b_key.len, sess->b2b_key.s);
		return -1;
	}
	return 0;
}

static int srec_b2b_confirm(str* logic_key, str* entity_key, int src, b2b_dlginfo_t* info, void *param)
{
	struct src_sess *ss;

	ss = (struct src_sess *)param;
	if (!ss) {
		LM_ERR("cannot find session in key parameter [%.*s]!\n",
				entity_key->len, entity_key->s);
		return -1;
	}
	ss->dlginfo = b2b_dup_dlginfo(info);
	if (!ss->dlginfo) {
		LM_ERR("could not duplicate b2b dialog info!\n");
		return -1;
	}
	return 0;
}

static int srs_send_invite(struct src_sess *sess)
{
	client_info_t ci;
	str body;
	str *client;
	str hdrs;
	str ct, contact;

	static str extra_headers = str_init(
			"Require: siprec" CRLF
			"Content-Type: multipart/mixed;boundary=" OSS_BOUNDARY CRLF
		);

	memset(&ci, 0, sizeof ci);
	ci.method.s = INVITE;
	ci.method.len = INVITE_LEN;
	/* try the first srs_uri */
	ci.req_uri = SIPREC_SRS(sess);

	if (sess->from_uri.len)
		ci.from_uri = sess->from_uri;
	else
		ci.from_uri = ci.req_uri;
	if (sess->to_uri.len)
		ci.to_uri = sess->to_uri;
	else
		ci.to_uri = ci.req_uri;
	if (sess->headers.s) {
		hdrs.s = pkg_malloc(extra_headers.len + sess->headers.len);
		if (!hdrs.s) {
			LM_ERR("could not add extra headers to SRC request!\n");
			ci.extra_headers = &extra_headers;
		} else {
			memcpy(hdrs.s, sess->headers.s, sess->headers.len);
			hdrs.len = sess->headers.len;
			memcpy(hdrs.s + hdrs.len, extra_headers.s, extra_headers.len);
			hdrs.len += extra_headers.len;
			ci.extra_headers = &hdrs;
		}
	} else
		ci.extra_headers = &extra_headers;
	ci.send_sock = sess->socket;

	ct.s = contact_builder(sess->socket, &ct.len);

	if (srs_build_body(sess, &sess->initial_sdp, &body) < 0) {
		LM_ERR("cannot generate request body!\n");
		return -2;
	}
	ci.body = &body;

	contact.len = 1 /* < */ + ct.len + 10 /* >;+sip.src */;
	contact.s = pkg_malloc(contact.len);
	if (contact.s) {
		contact.s[0] = '<';
		memcpy(contact.s + 1, ct.s, ct.len);
		memcpy(contact.s + 1 + ct.len, ">;+sip.src", 10);
		ci.local_contact = contact;
	} else {
		LM_ERR("could not alloc buffer for adding contact param - sending without param!\n");
		ci.local_contact = ct;
	}

	client = srec_b2b.client_new(&ci, srec_b2b_notify, srec_b2b_confirm,
			&mod_name, &sess->dlg->callid, NULL, sess, NULL);
	pkg_free(body.s);
	if (contact.s)
		pkg_free(contact.s);
	if (ci.extra_headers != &extra_headers)
		pkg_free(ci.extra_headers->s);
	if (!client) {
		LM_ERR("cannot start recording with %.*s!\n",
				ci.req_uri.len, ci.req_uri.s);
		return -1;
	}

	sess->flags |= SIPREC_STARTED;

	/* store the key in the param */
	sess->b2b_key.s = shm_malloc(client->len);
	if (!sess->b2b_key.s) {
		LM_ERR("out of shm memory!\n");
		pkg_free(client);
		return -1;
	}
	memcpy(sess->b2b_key.s, client->s, client->len);
	sess->b2b_key.len = client->len;
	pkg_free(client);

	return 0;
}

/* starts the recording to the srs */
int src_start_recording(struct sip_msg *msg, struct src_sess *sess)
{
	union sockaddr_union tmp;
	int ret;
	str sdp;

	if (!sess->socket) {
		sess->socket = uri2sock(msg, &SIPREC_SRS(sess), &tmp, PROTO_NONE);
		if (!sess->socket) {
			LM_ERR("cannot get send socket for uri %.*s\n",
					SIPREC_SRS(sess).len, SIPREC_SRS(sess).s);
			return -3;
		}
	}

	if (srec_get_body(sess, &sdp) < 0) {
		LM_ERR("could not start recording!\n");
		return -3;
	}

	if (shm_str_dup(&sess->initial_sdp, &sdp) < 0) {
		pkg_free(sdp.s);
		srec_rtp.copy_delete(sess->rtp, &mod_name, &sess->media);
		return -3;
	}
	pkg_free(sdp.s);

	SIPREC_REF_UNSAFE(sess);
	srec_hlog(sess, SREC_REF, "started recording");
	ret = srs_send_invite(sess);
	if (ret < 0) {
		srec_hlog(sess, SREC_UNREF, "error while starting recording");
		SIPREC_UNREF_UNSAFE(sess);
		srec_rtp.copy_delete(sess->rtp, &mod_name, &sess->media);
		return ret;
	}

	return 1;
}

int srs_handle_media(struct sip_msg *msg, struct src_sess *sess)
{
	str *body;

	body = get_body_part(msg, TYPE_APPLICATION, SUBTYPE_SDP);
	if (!body || body->len == 0) {
		LM_ERR("no body to handle!\n");
		return -1;
	}
	if (srec_rtp.copy_answer(sess->rtp, &mod_name,
			&sess->media, body) < 0) {
		LM_ERR("could not start recording!\n");
		return -1;
	}
	return 0;
}


static void srs_send_update_invite(struct src_sess *sess, str *body)
{
	struct b2b_req_data req;
	str inv = str_init(INVITE);
	static str extra_headers = str_init(
			"Require: siprec" CRLF
			"Content-Type: multipart/mixed;boundary=" OSS_BOUNDARY CRLF
		);

	memset(&req, 0, sizeof(req));
	req.et = B2B_CLIENT;
	req.b2b_key = &sess->b2b_key;
	req.method = &inv;
	req.extra_headers = &extra_headers;
	req.dlginfo = sess->dlginfo;
	req.body = body;

	if (srec_b2b.send_request(&req) < 0)
		LM_ERR("Cannot end recording session for key %.*s\n",
				req.b2b_key->len, req.b2b_key->s);
}

static int src_update_recording(struct sip_msg *msg, struct src_sess *sess)
{
	str body, sdp;

	if (msg == FAKED_REPLY || (sess->flags & SIPREC_STARTED) == 0)
		return 0;

	if (srec_get_body(sess, &sdp) < 0) {
		LM_ERR("could not refresh recording!\n");
		goto error;
	}

	if (srs_build_body(sess, &sdp, &body) < 0) {
		LM_ERR("cannot generate request body!\n");
		pkg_free(sdp.s);
		goto error;
	}
	pkg_free(sdp.s);
	srs_send_update_invite(sess, &body);

	return 0;
error:
	return -1;
}

static void tm_update_recording(struct cell *t, int type, struct tmcb_params *ps)
{
	struct src_sess *ss;

	if (!is_invite(t) || ps->code < 200 || ps->code >= 300)
		return;

	ss = (struct src_sess *)*ps->param;
	/* engage only on successful calls */
	SIPREC_LOCK(ss);
	src_update_recording(ps->rpl, ss);
	SIPREC_UNLOCK(ss);
}

void tm_start_recording(struct cell *t, int type, struct tmcb_params *ps)
{
	struct src_sess *ss;

	if (!is_invite(t))
		return;
	ss = (struct src_sess *)*ps->param;
	if (ps->code >= 300)
		return;

	SIPREC_LOCK(ss);
	/* engage only on successful calls */
	/* if session has been started, do not start it again */
	if (ss->flags & SIPREC_STARTED)
		LM_DBG("Session %p (%s) already started!\n", ss, ss->uuid);
	else if (src_start_recording(ps->rpl, ss) < 0)
		LM_ERR("cannot start recording!\n");
	SIPREC_UNLOCK(ss);
}

void srec_logic_destroy(struct src_sess *sess, int keep_sdp)
{
	if (!sess->b2b_key.s)
		return;

	if (!keep_sdp && sess->initial_sdp.s) {
		shm_free(sess->initial_sdp.s);
		sess->initial_sdp.s = NULL;
	}

	srec_b2b.entity_delete(B2B_CLIENT, &sess->b2b_key, sess->dlginfo, 1, 1);
	if (sess->dlginfo) {
		shm_free(sess->dlginfo);
		sess->dlginfo = NULL;
	}

	shm_free(sess->b2b_key.s);
	sess->b2b_key.s = NULL;

	sess->flags &= ~(SIPREC_STARTED|SIPREC_ONGOING);
}

struct src_sess *src_get_session(void)
{
	struct dlg_cell *dlg;
	struct src_sess *sess;

	dlg = srec_dlg.get_dlg();
	if (!dlg) {
		LM_WARN("could not get ongoing dialog!\n");
		return NULL;
	}

	sess = (struct src_sess *)srec_dlg.dlg_ctx_get_ptr(dlg, srec_dlg_idx);
	if (!sess) {
		LM_WARN("could not get siprec session for this dialog!\n");
		return NULL;
	}
	return sess;
}

int src_pause_recording(void)
{
	int ret = 0;
	struct src_sess *sess = src_get_session();

	if (!sess)
		return -2;
	SIPREC_LOCK(sess);

	if (sess->flags & SIPREC_PAUSED) {
		LM_DBG("nothing to do - session already paused!\n");
		goto end;
	}

	/* mark the session as being paused */
	sess->flags |= SIPREC_PAUSED;
	ret = src_update_recording(NULL, sess);

end:
	SIPREC_UNLOCK(sess);
	return ret;
}

int src_resume_recording(void)
{
	int ret = 0;
	struct src_sess *sess = src_get_session();
	if (!sess)
		return -2;

	if (!sess->streams_no) {
		LM_DBG("nothing to do - no streams active!\n");
		goto end;
	}

	if (!(sess->flags & SIPREC_PAUSED)) {
		LM_DBG("nothing to do - recording not paused!\n");
		goto end;
	}
	sess->flags &= ~SIPREC_PAUSED;
	ret = src_update_recording(NULL, sess);

end:
	SIPREC_UNLOCK(sess);
	return ret;
}
