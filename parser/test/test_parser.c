/*
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

#include <tap.h>

#include "../parse_uri.h"

#include "test_parse_qop.h"
#include "test_parse_fcaps.h"
#include "test_parser.h"
#include "test_parse_authenticate_body.h"

void test_parse_uri(void)
{
	struct sip_uri u;
	str in;

	/* Basic URI parsing tests */

	ok(parse_uri(STR_L("sip:@atlanta.org"), &u) < 0, "puri-0");

	/* Notice how illegal user chars are allowed in these two tests!
	 * This is by design, since "quick parsing" != "full RFC syntax validation"
	 */
	ok(parse_uri(STR_L("sip:%@atlanta.org"), &u) == 0, "puri-0.1");
	ok(parse_uri(STR_L("sip:%4`@atlanta.org"), &u) == 0, "puri-0.2");

	ok(parse_uri(STR_L("sip:%40@atlanta.org"), &u) == 0, "puri-0.3");
	ok(parse_uri(STR_L("sip:atlanta.org"), &u) == 0, "puri-0.4");
	ok(!u.user.s, "puri-0.5");
	ok(u.user.len == 0, "puri-0.6");

	/* URI port parsing tests, with or w/o a username */
	ok(!parse_uri(STR_L("sip:localhost@atlanta.org:0"), &u), "puri-0.7");
	ok(!parse_uri(STR_L("sip:localhost@atlanta.org:65535"), &u), "puri-0.8");
	ok(parse_uri(STR_L("sip:localhost@atlanta.org:65536"), &u), "puri-0.9");
	ok(parse_uri(STR_L("sip:localhost@atlanta.org:55555555555555555555"), &u), "puri-0.10");
	ok(!parse_uri(STR_L("sip:localhost:0@atlanta.org"), &u), "puri-0.11");
	ok(!parse_uri(STR_L("sip:localhost:65535@atlanta.org"), &u), "puri-0.12");
	ok(!parse_uri(STR_L("sip:localhost:65536@atlanta.org"), &u), "puri-0.13");
	ok(!parse_uri(STR_L("sip:localhost:5555555555555@atlanta.org"), &u), "puri-0.14");
	ok(!parse_uri(STR_L("sip:localhost:0"), &u), "puri-0.15");
	ok(!parse_uri(STR_L("sip:localhost:65535"), &u), "puri-0.16");
	ok(parse_uri(STR_L("sip:localhost:65536"), &u), "puri-0.17");
	ok(parse_uri(STR_L("sip:localhost:55555555555"), &u), "puri-0.18");

	in = *_str("sip:alice@atlanta.org;user=phone");
	ok(parse_uri(in.s, in.len, &u) == 0, "puri-1");
	ok(str_match(&u.user_param, const_str("user=phone")), "puri-2");
	ok(str_match(&u.user_param_val, const_str("phone")), "puri-3");

	in = *_str("sip:alice@atlanta.org;user=phone;gr=x");
	ok(parse_uri(in.s, in.len, &u) == 0, "puri-4");
	ok(str_match(&u.user_param, const_str("user=phone")), "puri-5");
	ok(str_match(&u.user_param_val, const_str("phone")), "puri-6");
	ok(str_match(&u.gr, const_str("gr=x")), "puri-7");
	ok(str_match(&u.gr_val, const_str("x")), "puri-8");

	in = *_str("sip:alice@atlanta.org;transport=udp;user=phone;maddr=1.2.3.4;gr");
	ok(parse_uri(in.s, in.len, &u) == 0, "puri-9");
	ok(str_match(&u.user, const_str("alice")), "puri-10");
	ok(str_match(&u.host, const_str("atlanta.org")), "puri-11");
	ok(str_match(&u.transport, const_str("transport=udp")), "puri-12");
	ok(str_match(&u.transport_val, const_str("udp")), "puri-13");
	ok(str_match(&u.user_param, const_str("user=phone")), "puri-14");
	ok(str_match(&u.user_param_val, const_str("phone")), "puri-15");
	ok(str_match(&u.maddr, const_str("maddr=1.2.3.4")), "puri-16");
	ok(str_match(&u.maddr_val, const_str("1.2.3.4")), "puri-17");
	ok(str_match(&u.gr, const_str("gr")), "puri-18");
	ok(str_match(&u.gr_val, const_str("")), "puri-19");

	/* SIP PN (RFC 8599) URI param parsing tests */

	/* pn-provider value is optional */
	in = *_str("sip:alice@atlanta.org;pn-provider");
	ok(parse_uri(in.s, in.len, &u) == 0, "puri-20");
	ok(str_match(&u.pn_provider, const_str("pn-provider")), "puri-21");
	ok(str_match(&u.pn_provider_val, const_str("")), "puri-22");
	ok(!u.pn_provider_val.s, "puri-22-NULL");

	in = *_str("sip:alice@atlanta.org;pn-provider=");
	ok(parse_uri(in.s, in.len, &u) == 0, "puri-23");
	ok(str_match(&u.pn_provider, const_str("pn-provider=")), "puri-24");
	ok(str_match(&u.pn_provider_val, const_str("")), "puri-25");
	ok(!u.pn_provider_val.s, "puri-25-NULL");

	in = *_str("sip:alice@atlanta.org;pn-provider=x");
	ok(parse_uri(in.s, in.len, &u) == 0, "puri-26");
	ok(str_match(&u.pn_provider, const_str("pn-provider=x")), "puri-27");
	ok(str_match(&u.pn_provider_val, const_str("x")), "puri-28");

	/* pn-prid value is mandatory */
	in = *_str("sip:alice@atlanta.org;pn-prid=");
	ok(parse_uri(in.s, in.len, &u) != 0, "puri-29");
	in = *_str("sip:alice@atlanta.org;pn-prid");
	ok(parse_uri(in.s, in.len, &u) != 0, "puri-30-1");
	in = *_str("sip:alice@atlanta.org;pn-prid;foo=bar");
	ok(parse_uri(in.s, in.len, &u) != 0, "puri-30-2");

	/* pn-param value is mandatory */
	in = *_str("sip:alice@atlanta.org;pn-param=");
	ok(parse_uri(in.s, in.len, &u) != 0, "puri-31");
	in = *_str("sip:alice@atlanta.org;pn-param");
	ok(parse_uri(in.s, in.len, &u) != 0, "puri-32-1");
	in = *_str("sip:alice@atlanta.org;pn-param;foo=bar");
	ok(parse_uri(in.s, in.len, &u) != 0, "puri-32-2");

	/* pn-purr value is mandatory */
	in = *_str("sip:alice@atlanta.org;pn-purr=");
	ok(parse_uri(in.s, in.len, &u) != 0, "puri-33");
	in = *_str("sip:alice@atlanta.org;pn-purr");
	ok(parse_uri(in.s, in.len, &u) != 0, "puri-34-1");
	in = *_str("sip:alice@atlanta.org;pn-purr;foo=bar");
	ok(parse_uri(in.s, in.len, &u) != 0, "puri-34-2");

	in = *_str("sip:alice@atlanta.org;pn-provider=x;pn-prid=y;"
	                                 "pn-param=z;pn-purr=t");
	ok(parse_uri(in.s, in.len, &u) == 0, "puri-35");
	ok(str_match(&u.pn_provider, const_str("pn-provider=x")), "puri-36");
	ok(str_match(&u.pn_provider_val, const_str("x")), "puri-37");
	ok(str_match(&u.pn_prid, const_str("pn-prid=y")), "puri-38");
	ok(str_match(&u.pn_prid_val, const_str("y")), "puri-39");
	ok(str_match(&u.pn_param, const_str("pn-param=z")), "puri-40");
	ok(str_match(&u.pn_param_val, const_str("z")), "puri-41");
	ok(str_match(&u.pn_purr, const_str("pn-purr=t")), "puri-42");
	ok(str_match(&u.pn_purr_val, const_str("t")), "puri-43");
}

static const struct tts {
	const char *tmsg;
	int tres;
} tset[] = {
	{
		/* test for read overflows on EoH parsing */
		"e \xff\xff\xff\xff     \xff\n\xff\xff  ",
		-1,
	}, {
		/* test for read overflows on To header param parsing */
		"d  \x02\x80\0\nt\0:G;150=\"a8",
		-1,
	}, {
		/* test for read overflows on bad header body (no \n ending) */
		"m  r\nu:c \x1b\r   : ]",
		-1,
	},

	{"\0", 0},
};

void test_parse_msg(void)
{
	int i;

	for (i = 0; tset[i].tmsg[0]; i++) {
		struct sip_msg msg;

		memset(&msg, 0, sizeof msg);
		msg.buf = (char *)tset[i].tmsg;
		msg.len = strlen(msg.buf);

		ok(parse_msg(msg.buf, msg.len, &msg) == tset[i].tres, "parse-msg-t%d", i);
	}
}


void test_parser(void)
{
	test_parse_uri();
	test_parse_msg();
	test_parse_qop_val();
	test_parse_fcaps();
	test_parse_authenticate_body();
}
