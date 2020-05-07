/*
 * utility functions for writing SIP tests
 *
 * Copyright (C) 2020 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "../dprint.h"
#include "../parser/msg_parser.h"

#include "ut.h"

int mk_sip_req(const char *method, const char *ruri, struct sip_msg *msg)
{
	static char msgbuf[BUF_SIZE];
	char *body =
		"v=0\r\n"
		"o=user1 53655765 2353687637 IN IP4 127.0.0.1\r\n"
		"s=-\r\n"
		"c=IN IP4 127.0.0.1\r\n"
		"t=0 0\r\n"
		"m=audio 47612 RTP/AVP 0\r\n"
		"a=rtpmap:0 PCMU/8000\r\n";
	int len;

	len = snprintf(msgbuf, BUF_SIZE,
		"%s %s SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK%x%x\r\n"
		"From: test <sip:test@localhost:5060>;tag=%x%x\r\n"
		"To: <%s>\r\n"
		"CSeq: 1 INVITE\r\n"
		"Call-ID: %x%x%x%x\r\n"
		"Max-Forwards: 70\r\n"
		"Subject: Testing\r\n"
		"User-Agent: test\r\n"
		"Content-Type: application/sdp\r\n"
		"Content-Length: %d\r\n"
		"\r\n"
		"%s", method, ruri, rand(), rand(),
		rand(), rand(),
		ruri, rand(), rand(), rand(), rand(), (int)strlen(body), body);

	memset(msg, 0, sizeof *msg);
	msg->buf = msgbuf;
	msg->len = len;
	msg->ruri_q = Q_UNSPECIFIED;

	if (parse_msg(msgbuf, len, msg) != 0) {
		LM_ERR("failed to parse test msg\n");
		return -1;
	}

	return 0;
}
