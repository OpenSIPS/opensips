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
struct rtpproxy_binds srec_rtp;

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
	req.b2b_key = ss->b2b_key;
	req.method = &bye;
	req.no_cb = 1; /* do not call callback */

	if (srec_b2b.send_request(&req) < 0)
		LM_ERR("Cannot end recording session for key %.*s\n", 
				req.b2b_key->len, req.b2b_key->s);
	/* TODO: remove! */
}


static int srec_b2b_notify(struct sip_msg *msg, str *key, int type, void *param)
{
	struct b2b_req_data req;
	struct src_sess *ss;
	int ret = -1;
	str ack = str_init(ACK);

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

	/* reply received - sending ACK */
	memset(&req, 0, sizeof(req));
	req.et = B2B_CLIENT;
	req.b2b_key = ss->b2b_key;
	req.method = &ack;
	req.no_cb = 1; /* do not call callback */

	if (srec_b2b.send_request(&req) < 0) {
		LM_ERR("Cannot end recording session for key %.*s\n", 
				req.b2b_key->len, req.b2b_key->s);
		goto no_recording;
	}

	/* check if the reply was successfully */
	if (msg->REPLY_STATUS != 200) {
		ret = 0;
		goto no_recording;
	}

	/* TODO: parse to get SDP and ask rtpproxy to stream to it */

	if (srec_dlg.register_dlgcb(ss->dlg, DLGCB_TERMINATED|DLGCB_EXPIRED,
			srec_dlg_end, ss, 0)){
		LM_ERR("cannot register callback for database accounting\n");
		goto no_recording;
	}

	/* wait for dialog termination */
	return 0;
no_recording:
	if (ret != 0) {
		/* TODO: send BYE to the SRS */
	}
	/* TODO: cleanup */
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
	/* TODO: do a round robin or smth here */
	ci.req_uri = list_entry(sess->set->nodes.next, struct srs_node, list)->uri;
	/* TODO: fix uris */
	ci.to_uri = ci.req_uri;
	ci.from_uri = ci.to_uri;
	ci.extra_headers = &extra_headers;
	LM_INFO("XXX: started seesion with uri %.*s\n", ci.to_uri.len, ci.to_uri.s);

	if (!send_sock) {
		send_sock = uri2sock(msg, &ci.req_uri, &tmp, PROTO_NONE);
		if (!send_sock) {
			LM_ERR("cannot get send socket for uri %.*s\n",
					ci.req_uri.len, ci.req_uri.s);
			return -3;
		}
	}
	ci.local_contact.s = contact_builder(send_sock, &ci.local_contact.len);

	if (srs_add_sdp_streams(msg, &sess->sdp) < 0) {
		LM_ERR("cannot add body!\n");
		return -2;
	}
	/* TODO: hack - delete me - add twice to see how it behaves */
	srs_add_sdp_streams(msg, &sess->sdp);

	if (srs_get_body(sess, &sess->sdp, &body) < 0) {
		LM_ERR("cannot generate request body!\n");
		return -2;
	}
	ci.body = &body;

	/* hack to pass a parameter :( */
	param.s = (char *)&sess;
	param.len = sizeof(void *);
	client = srec_b2b.client_new(&ci, srec_b2b_notify, NULL, (str *)&param);
	if (!client) {
		LM_ERR("cannot start recording with %.*s!\n",
				ci.req_uri.len, ci.req_uri.s);
		pkg_free(body.s);
		/* TODO: try next server in the set */
		return -1;
		/* try next server in the set */
		return src_start_recording(msg, sess);
	}

	/* store the key in the param */
	/* TODO: make sure the session/key is not destroyed before this */
	sess->b2b_key = client;

	/* release generated body */
	pkg_free(body.s);
	return 1;
}
