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

static str ct_sdp = str_init("application/sdp");

str *media_session_get_hold_sdp(struct media_session_leg *msl)
{
	char *p;
	static str new_body;
	static str sendrecv = str_init("a=sendrecv");
	static str sendonly = str_init("a=sendonly");
	static str recvonly = str_init("a=recvonly");
	/* NOTE: all the attributes have the same length as inactive */
	static str inactive = str_init("a=inactive");
	int leg = MEDIA_SESSION_DLG_OTHER_LEG(msl);
	str body = dlg_get_out_sdp(msl->ms->dlg, leg);

	/* search for sendrecv */
	p = str_strstr(&body, &sendrecv);
	if (!p) {
		p = str_strstr(&body, &sendonly);
		if (!p)
			p = str_strstr(&body, &recvonly);
	}

	if (p && (p[inactive.len] == '\r' || p[inactive.len] == '\n')) {
		/* we have the attribute - copy everything but the label */
		new_body.s = pkg_malloc(body.len);
		if (!new_body.s)
			return NULL;
		memcpy(new_body.s, body.s, p - body.s);
		new_body.len = p - body.s;
		p += inactive.len;
		memcpy(new_body.s + new_body.len, inactive.s, inactive.len);
		new_body.len += inactive.len;
		memcpy(new_body.s + new_body.len, p, body.len - (p - body.s));
		new_body.len = body.len;
	} else {
		/* no indication found */
		if (str_strstr(&body, &inactive)) {
			new_body.s = pkg_malloc(body.len);
			if (!new_body.s)
				return NULL;
			memcpy(new_body.s, body.s, body.len);
			new_body.len = body.len;
		} else {
			new_body.s = pkg_malloc(body.len + inactive.len + 2/* \r\n */);
			if (!new_body.s)
				return NULL;
			memcpy(new_body.s, body.s, body.len);
			new_body.len = body.len;
			memcpy(new_body.s + new_body.len, inactive.s, inactive.len);
			new_body.len += inactive.len;
			new_body.s[new_body.len++] = '\r';
			new_body.s[new_body.len++] = '\n';
		}
	}
	return &new_body;
}

int media_session_resume_dlg(struct media_session_leg *msl)
{
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
			&inv, leg, &body, &ct_sdp, NULL, NULL);
}

int media_session_b2b_end(struct media_session_leg *msl)
{
	struct b2b_req_data req;
	str bye = str_init(BYE);

	memset(&req, 0, sizeof(req));
	req.et = msl->b2b_entity;
	req.b2b_key = &msl->b2b_key;
	req.method = &bye;
	req.no_cb = 1; /* do not call callback */

	if (media_b2b.send_request(&req) < 0) {
		LM_ERR("Cannot end recording session for key %.*s\n",
				req.b2b_key->len, req.b2b_key->s);
		return -1;
	}
	return 0;
}
