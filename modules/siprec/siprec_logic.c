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

struct b2b_api srec_b2b;
str skip_failover_codes = str_init("");
static regex_t skip_codes_regex;

static str mod_name = str_init("siprec");

static int srs_send_invite(struct src_sess *sess);

int src_init(void)
{
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
	srec_logic_destroy(sess);

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

struct _tm_src_param {
	struct src_sess *ss;
	int part_no;
};

static void _tmp_src_param_free(void *p)
{
	struct _tm_src_param *tmp = (struct _tm_src_param *)p;
	src_unref_session(tmp->ss);
	shm_free(tmp);
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

	memset(&req, 0, sizeof(req));
	req.et = B2B_CLIENT;
	req.b2b_key = &ss->b2b_key;
	req.method = &bye;
	req.no_cb = 1; /* do not call callback */

	if (srec_b2b.send_request(&req) < 0)
		LM_ERR("Cannot end recording session for key %.*s\n",
				req.b2b_key->len, req.b2b_key->s);
	srec_logic_destroy(ss);
}

static void srec_dlg_sequential(struct dlg_cell *dlg, int type, struct dlg_cb_params *_params)
{
	struct src_sess *ss;
	int part_no;
	int streams;
	struct _tm_src_param *tmp;
	/* check which participant we are talking about */
	part_no = (_params->direction == DLG_DIR_UPSTREAM ? 1 : 0);
	ss = *_params->param;

	SIPREC_LOCK(ss);
	streams = srs_fill_sdp_stream(_params->msg, ss, &ss->participants[part_no], 1);
	if (streams < 0) {
		LM_ERR("cannot add SDP for calle%c!\n",part_no == 0?'r':'e');
		goto unlock;
	}
	if (streams == 0)
		goto unlock;

	tmp = shm_malloc(sizeof *tmp);
	if (!tmp) {
		LM_ERR("cannot alloc temporary param!\n");
		goto unlock;
	}
	tmp->ss = ss;
	tmp->part_no = 1 - part_no;

	SIPREC_REF_UNSAFE(ss);
	if (srec_tm.register_tmcb(_params->msg, 0, TMCB_RESPONSE_OUT, tm_update_recording,
			tmp, _tmp_src_param_free) <= 0) {
		LM_ERR("cannot register tm callbacks for reply\n");
		SIPREC_UNREF_UNSAFE(ss);
	}
unlock:
	SIPREC_UNLOCK(ss);
}

int srec_register_callbacks(struct src_sess *sess)
{
	/* also, the b2b ref moves on the dialog */
	if (srec_dlg.register_dlgcb(sess->dlg, DLGCB_TERMINATED|DLGCB_EXPIRED|DLGCB_FAILED,
			srec_dlg_end, sess, src_unref_session)){
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
	sess->flags |= SIPREC_DLG_CBS;
	return 0;
}

static int srec_b2b_notify(struct sip_msg *msg, str *key, int type, void *param,
	int flags)
{
	struct b2b_req_data req;
	struct src_sess *ss;
	int ret = -1;
	str ack = str_init(ACK);
	str bye = str_init(BYE);

	/* for now we only receive replies from SRS */
	if (type != B2B_REPLY)
		return -1;

	if (!param) {
		LM_ERR("no callback parameter specified!\n");
		return -1;
	}
	ss = *(struct src_sess **)((str *)param)->s;
	if (!ss) {
		LM_ERR("cannot find session in parameter!\n");
		return -1;
	}

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

	/* reply received - sending ACK */
	memset(&req, 0, sizeof(req));
	req.et = B2B_CLIENT;
	req.b2b_key = &ss->b2b_key;
	req.method = &ack;
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

	if (!(ss->flags & SIPREC_DLG_CBS)) {
		if (srec_register_callbacks(ss) < 0) {
			LM_ERR("cannot register callback for terminating session\n");
			SIPREC_UNREF(ss);
			goto no_recording;
		}

		/* no need to keep ref on the dialog, since we rely on it from now on */
		srec_dlg.dlg_unref(ss->dlg, 1);
		/* also, the b2b ref moves on the dialog - so we avoid a ref-unref */
	}

	return 0;
no_recording:
	if (ret != 0) {
		memset(&req, 0, sizeof(req));
		req.et = B2B_CLIENT;
		req.b2b_key = &ss->b2b_key;
		req.method = &bye;
		req.no_cb = 1; /* do not call callback */

		if (srec_b2b.send_request(&req) < 0)
			LM_ERR("Cannot send bye for recording session with key %.*s\n",
					req.b2b_key->len, req.b2b_key->s);
	}
	srec_logic_destroy(ss);

	/* we finishd everything with the dialog, let it be! */
	srec_dlg.dlg_unref(ss->dlg, 1);
	ss->dlg = NULL;
	SIPREC_UNREF(ss);
	return ret;
}


int srec_restore_callback(struct src_sess *sess)
{
	if (srec_b2b.restore_logic_info(B2B_CLIENT, &sess->b2b_key,
			srec_b2b_notify) < 0) {
		LM_ERR("cannot register notify callback for [%.*s]!\n",
				sess->b2b_key.len, sess->b2b_key.s);
		return -1;
	}
	return 0;
}

static int srec_b2b_confirm(str* key, str* entity_key, int src, b2b_dlginfo_t* info)
{
	char *tmp;
	struct src_sess *ss;

	ss = *(struct src_sess **)key->s;
	if (!ss) {
		LM_ERR("cannot find session in key parameter [%.*s]!\n",
				entity_key->len, entity_key->s);
		return -1;
	}
	tmp = shm_malloc(info->fromtag.len);
	if (!tmp) {
		LM_ERR("cannot allocate dialog info fromtag!\n");
		return -1;
	}
	ss->b2b_fromtag.s = tmp;
	ss->b2b_fromtag.len = info->fromtag.len;
	memcpy(ss->b2b_fromtag.s, info->fromtag.s, ss->b2b_fromtag.len);

	tmp = shm_malloc(info->totag.len);
	if (!tmp) {
		LM_ERR("cannot allocate dialog info totag!\n");
		return -1;
	}
	ss->b2b_totag.s = tmp;
	ss->b2b_totag.len = info->totag.len;
	memcpy(ss->b2b_totag.s, info->totag.s, ss->b2b_totag.len);

	tmp = shm_malloc(info->callid.len);
	if (!tmp) {
		LM_ERR("cannot allocate dialog info callid!\n");
		return -1;
	}
	ss->b2b_callid.s = tmp;
	ss->b2b_callid.len = info->callid.len;
	memcpy(ss->b2b_callid.s, info->callid.s, ss->b2b_callid.len);
	return 0;
}

static int srs_send_invite(struct src_sess *sess)
{
	client_info_t ci;
	str param, body;
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
	/* TODO: fix uris */
	ci.to_uri = ci.req_uri;
	ci.from_uri = ci.to_uri;
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

	if (srs_build_body(sess, &body, SRS_BOTH) < 0) {
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

	/* XXX: hack to pass a parameter :( */
	param.s = (char *)&sess;
	param.len = sizeof(void *);
	client = srec_b2b.client_new(&ci, srec_b2b_notify, srec_b2b_confirm,
			&mod_name, (str *)&param);
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

	/* store the key in the param */
	sess->b2b_key.s = shm_malloc(client->len);
	if (!sess->b2b_key.s) {
		LM_ERR("out of shm memory!\n");
		return -1;
	}
	memcpy(sess->b2b_key.s, client->s, client->len);
	sess->b2b_key.len = client->len;

	return 0;
}

/* starts the recording to the srs */
int src_start_recording(struct sip_msg *msg, struct src_sess *sess)
{
	union sockaddr_union tmp;
	int streams, ret;

	if (!sess->socket) {
		sess->socket = uri2sock(msg, &SIPREC_SRS(sess), &tmp, PROTO_NONE);
		if (!sess->socket) {
			LM_ERR("cannot get send socket for uri %.*s\n",
					SIPREC_SRS(sess).len, SIPREC_SRS(sess).s);
			return -3;
		}
	}

	streams = srs_fill_sdp_stream(msg, sess, &sess->participants[1], 0);
	if (streams < 0) {
		LM_ERR("cannot add SDP for callee!\n");
		return -2;
	}
	if (streams == 0)
		return 0;

	SIPREC_REF_UNSAFE(sess);
	ret = srs_send_invite(sess);
	if (ret < 0) {
		SIPREC_UNREF_UNSAFE(sess);
		return ret;
	}

	sess->flags |= SIPREC_STARTED;

	return 1;
}

static int src_update_recording(struct sip_msg *msg, struct src_sess *sess, int part_no)
{
	str body;
	struct b2b_req_data req;
	str inv = str_init(INVITE);
	int streams;
	static str extra_headers = str_init(
			"Require: siprec" CRLF
			"Content-Type: multipart/mixed;boundary=" OSS_BOUNDARY CRLF
		);

	memset(&req, 0, sizeof(req));
	req.et = B2B_CLIENT;
	req.b2b_key = &sess->b2b_key;
	req.method = &inv;
	req.extra_headers = &extra_headers;

	streams = srs_fill_sdp_stream(msg, sess, &sess->participants[part_no], 1);
	if (streams < 0) {
		LM_ERR("cannot add SDP for calle%c!\n",part_no == 0?'r':'e');
		return -2;
	}
	if (streams == 0)
		return 0;

	if (srs_build_body(sess, &body, SRS_BOTH) < 0) {
		LM_ERR("cannot generate request body!\n");
		goto error;
	}
	req.body = &body;

	if (srec_b2b.send_request(&req) < 0)
		LM_ERR("Cannot end recording session for key %.*s\n",
				req.b2b_key->len, req.b2b_key->s);
	return 0;
error:
	return -1;
}

static void tm_update_recording(struct cell *t, int type, struct tmcb_params *ps)
{
	struct _tm_src_param *tmp;

	if (!is_invite(t) || ps->code < 200 || ps->code >= 300)
		return;

	tmp = (struct _tm_src_param *)*ps->param;
	/* engage only on successful calls */
	SIPREC_LOCK(tmp->ss);
	src_update_recording(ps->rpl, tmp->ss, tmp->part_no);
	SIPREC_UNLOCK(tmp->ss);
}

void tm_start_recording(struct cell *t, int type, struct tmcb_params *ps)
{
	str body;
	struct src_sess *ss;

	if (!is_invite(t) || ps->code >= 300)
		return;

	/* check if we have a reply with body */
	if (get_body(ps->rpl, &body) != 0 || body.len==0)
		return;

	ss = (struct src_sess *)*ps->param;
	/* engage only on successful calls */
	SIPREC_LOCK(ss);
	/* if session has been started, do not start it again */
	if (ss->flags & SIPREC_STARTED)
		LM_DBG("Session %p (%s) already started!\n", ss, ss->uuid);
	else if (src_start_recording(ps->rpl, ss) < 0)
		LM_ERR("cannot start recording!\n");
	SIPREC_UNLOCK(ss);
}

void srec_logic_destroy(struct src_sess *sess)
{
	b2b_dlginfo_t info;
	if (!sess->b2b_key.s)
		return;
	shm_free(sess->b2b_key.s);

	info.fromtag = sess->b2b_fromtag;
	info.totag = sess->b2b_totag;
	info.callid = sess->b2b_callid;
	srec_b2b.entity_delete(B2B_CLIENT, &sess->b2b_key,
			(info.callid.s ? &info: NULL), 1, 1);
	if (sess->b2b_fromtag.s)
		shm_free(sess->b2b_fromtag.s);
	if (sess->b2b_totag.s)
		shm_free(sess->b2b_totag.s);
	if (sess->b2b_callid.s)
		shm_free(sess->b2b_callid.s);
	sess->b2b_callid.s = sess->b2b_totag.s = sess->b2b_fromtag.s = NULL;
	sess->b2b_key.s = NULL;
}

