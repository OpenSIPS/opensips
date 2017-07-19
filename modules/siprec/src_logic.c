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

#include "src_logic.h"
#include "srs_body.h"

struct b2b_api srec_b2b;

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
	SIPREC_UNREF(ss);
}


static int srec_b2b_notify(struct sip_msg *msg, str *key, int type, void *param)
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
	/* check if the reply was successfully */
	if (msg->REPLY_STATUS < 200) {
		/* wait for a final reply */
		return 0;
	} else if (msg->REPLY_STATUS > 300) {
		LM_DBG("recording is not available!\n");
		goto no_recording;
	}


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
	ret = -1;

	if (srs_handle_media(msg, ss) < 0) {
		LM_ERR("cannot handle SRS media!\n");
		goto no_recording;
	}

	SIPREC_REF(ss);
	if (srec_dlg.register_dlgcb(ss->dlg, DLGCB_TERMINATED|DLGCB_EXPIRED,
			srec_dlg_end, ss, src_unref_session)){
		LM_ERR("cannot register callback for database accounting\n");
		SIPREC_UNREF(ss);
		goto no_recording;
	}

	/* wait for dialog termination */
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
	SIPREC_UNREF(ss);
	return ret;
}

/* TODO: delete
static int srec_b2b_add_info(str* key, str* entity_key, int src, b2b_dlginfo_t* info)
{
	return 0;
}
*/


/* starts the recording to the srs */
int src_start_recording(struct sip_msg *msg, struct src_sess *sess)
{
	str *client;
	str param, body;
	struct socket_info *send_sock = NULL /* TODO: take from sess */;
	union sockaddr_union tmp;
	client_info_t ci;
	static str extra_headers = str_init(
			"Require: siprec" CRLF
			"Content-Type: multipart/mixed;boundary=" OSS_BOUNDARY CRLF
		);

	memset(&ci, 0, sizeof ci);
	ci.method.s = INVITE;
	ci.method.len = INVITE_LEN;
	/* try the first srs_uri */
	ci.req_uri = sess->srs_uri;
	/* TODO: fix uris */
	ci.to_uri = ci.req_uri;
	ci.from_uri = ci.to_uri;
	ci.extra_headers = &extra_headers;

	if (!send_sock) {
		send_sock = uri2sock(msg, &ci.req_uri, &tmp, PROTO_NONE);
		if (!send_sock) {
			LM_ERR("cannot get send socket for uri %.*s\n",
					ci.req_uri.len, ci.req_uri.s);
			return -3;
		}
	}
	ci.local_contact.s = contact_builder(send_sock, &ci.local_contact.len);

	if (srs_add_sdp_streams(msg, sess, &sess->participants[1]) < 0) {
		LM_ERR("cannot add body!\n");
		return -2;
	}

	if (srs_build_body(sess, &body, SRS_BOTH) < 0) {
		LM_ERR("cannot generate request body!\n");
		return -2;
	}
	ci.body = &body;

	/* XXX: hack to pass a parameter :( */
	param.s = (char *)&sess;
	param.len = sizeof(void *);
	SIPREC_REF_UNSAFE(sess);
	client = srec_b2b.client_new(&ci, srec_b2b_notify, NULL, (str *)&param);
	if (!client) {
		LM_ERR("cannot start recording with %.*s!\n",
				ci.req_uri.len, ci.req_uri.s);
		pkg_free(body.s);
		goto unref;
	}
	/* release generated body */
	pkg_free(body.s);

	/* store the key in the param */
	sess->b2b_key.s = shm_malloc(client->len);
	if (!sess->b2b_key.s) {
		LM_ERR("out of shm memory!\n");
		goto unref;
	}
	memcpy(sess->b2b_key.s, client->s, client->len);
	sess->b2b_key.len = client->len;
	sess->started = 1;

	return 1;
unref:
	SIPREC_UNREF_UNSAFE(sess);
	return -1;
}

void tm_start_recording(struct cell *t, int type, struct tmcb_params *ps)
{
	struct src_sess *ss;

	if (!is_invite(t) || ps->code < 200 || ps->code >= 300)
		return;

	ss = (struct src_sess *)*ps->param;
	/* engage only on successfull calls */
	SIPREC_LOCK(ss);
	/* if session has been started, do not start it again */
	if (ss->started)
		LM_WARN("Session %p (%s) already started!\n", ss, ss->uuid);
	else if (src_start_recording(ps->rpl, ss) < 0)
		LM_ERR("cannot start recording!\n");
	SIPREC_UNLOCK(ss);
}
