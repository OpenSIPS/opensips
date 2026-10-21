/*
 * Unit tests for graceful drain admission policy.
 *
 * Copyright (C) 2026 OpenSIPS Project
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

#include <tap.h>
#include <string.h>

#include "../../../parser/msg_parser.h"

int drain_test_should_reject(struct sip_msg *msg, int draining,
	int reject_invites, int reject_registers);

static int policy(const char *wire, int draining,
	int reject_invites, int reject_registers)
{
	char buf[2048];
	struct sip_msg msg;
	int len, rc;

	len = strlen(wire);
	if (len >= (int)sizeof(buf))
		return -99;
	memcpy(buf, wire, len + 1);
	memset(&msg, 0, sizeof(msg));
	msg.buf = buf;
	msg.len = len;
	if (parse_msg(buf, len, &msg) < 0)
		return -99;

	rc = drain_test_should_reject(&msg, draining,
		reject_invites, reject_registers);
	free_sip_msg(&msg);
	return rc;
}

static const char *initial_invite =
	"INVITE sip:bob@example.com SIP/2.0\r\n"
	"Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-one\r\n"
	"From: <sip:alice@example.com>;tag=from-a\r\n"
	"To: <sip:bob@example.com>\r\n"
	"Call-ID: drain-call-1\r\n"
	"CSeq: 1 INVITE\r\n"
	"Max-Forwards: 70\r\n"
	"Content-Length: 0\r\n\r\n";

static const char *reinvite =
	"INVITE sip:bob@example.com SIP/2.0\r\n"
	"Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-two\r\n"
	"From: <sip:alice@example.com>;tag=from-a\r\n"
	"To: <sip:bob@example.com>;tag=to-b\r\n"
	"Call-ID: drain-call-1\r\n"
	"CSeq: 2 INVITE\r\n"
	"Max-Forwards: 70\r\n"
	"Content-Length: 0\r\n\r\n";

static const char *register_req =
	"REGISTER sip:example.com SIP/2.0\r\n"
	"Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-three\r\n"
	"From: <sip:alice@example.com>;tag=from-a\r\n"
	"To: <sip:alice@example.com>\r\n"
	"Call-ID: drain-reg-1\r\n"
	"CSeq: 1 REGISTER\r\n"
	"Max-Forwards: 70\r\n"
	"Content-Length: 0\r\n\r\n";

static const char *bye_req =
	"BYE sip:bob@example.com SIP/2.0\r\n"
	"Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-four\r\n"
	"From: <sip:alice@example.com>;tag=from-a\r\n"
	"To: <sip:bob@example.com>;tag=to-b\r\n"
	"Call-ID: drain-call-1\r\n"
	"CSeq: 3 BYE\r\n"
	"Max-Forwards: 70\r\n"
	"Content-Length: 0\r\n\r\n";

static void test_policy(void)
{
	ok(policy(initial_invite, 1, 1, 1) == 1,
		"drain-reject-initial-invite");
	ok(policy(reinvite, 1, 1, 1) == 0,
		"drain-allow-reinvite");
	ok(policy(register_req, 1, 1, 1) == 1,
		"drain-reject-register");
	ok(policy(bye_req, 1, 1, 1) == 0,
		"drain-allow-bye");

	ok(policy(initial_invite, 0, 1, 1) == 0,
		"drain-off-allows-initial-invite");
	ok(policy(register_req, 0, 1, 1) == 0,
		"drain-off-allows-register");
	ok(policy(initial_invite, 1, 0, 1) == 0,
		"drain-invite-rejection-can-be-disabled");
	ok(policy(register_req, 1, 1, 0) == 0,
		"drain-register-rejection-can-be-disabled");
}

void mod_tests(void)
{
	test_policy();
}
