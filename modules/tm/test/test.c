/*
 * Copyright (C) 2026 OpenSIPS Project
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

#include <tap.h>
#include <string.h>

#include "../../../str.h"
#include "../t_lookup.h"
#include "../t_msgbuilder.h"

/* t_reply_by_callid() passes the Call-ID and CSeq number of the received
 * request to t_lookup_callid(), which prints them into MAX_HEADER sized
 * buffers before searching the transaction table */
static void test_lookup_callid_long(void)
{
	static char big[4 * MAX_HEADER];
	struct cell *t = NULL;
	str callid, cseq;

	memset(big, 'a', sizeof big);
	cseq.s = "1";
	cseq.len = 1;

	callid.s = big;
	callid.len = MAX_HEADER - CALLID_LEN - CRLF_LEN;
	ok(t_lookup_callid(&t, callid, cseq) < 0 && t == NULL,
		"callid filling the header buffer is looked up");

	callid.len = MAX_HEADER - CALLID_LEN - CRLF_LEN + 1;
	ok(t_lookup_callid(&t, callid, cseq) < 0 && t == NULL,
		"callid one byte over the header buffer is rejected");

	callid.len = sizeof big;
	ok(t_lookup_callid(&t, callid, cseq) < 0 && t == NULL,
		"long callid is rejected");

	callid.len = 8;
	cseq.s = big;
	cseq.len = sizeof big;
	ok(t_lookup_callid(&t, callid, cseq) < 0 && t == NULL,
		"long cseq number is rejected");
}

void mod_tests(void)
{
	test_lookup_callid_long();
}
