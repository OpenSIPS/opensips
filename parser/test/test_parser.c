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

/*
 * Behavioural spec for trim_user_params() (parser/parse_uri.c).
 *
 * It drops the RFC 4904 user parameters (tgrp, trunk-context, isub, ...) that
 * parse_uri() folds into the URI userinfo (.user) along with the leading value,
 * by truncating the str in place at the first ';'.  Each case below reads as
 * given <a .user value> / when trimmed / then <expected result>.
 */
void test_trim_user_params(void)
{
	str tn;
	char *orig;

	/* given an E.164 number carrying RFC 4904 tgrp/trunk-context params, when
	 * trimmed, then only the leading number survives - and .s (the buffer
	 * pointer) is left unchanged, pinning the documented "in place" contract */
	tn = *_str("+33123456789;tgrp=grp1;trunk-context=example.com");
	orig = tn.s;
	trim_user_params(&tn);
	ok(str_match(&tn, const_str("+33123456789")) && tn.s == orig,
		"trim-up-rfc4904");

	/* given a single trailing parameter, when trimmed, then the value survives */
	tn = *_str("+15551234;isub=99");
	trim_user_params(&tn);
	ok(str_match(&tn, const_str("+15551234")), "trim-up-single-param");

	/* given a userinfo with no parameters, when trimmed, then it is untouched */
	tn = *_str("+441632960000");
	trim_user_params(&tn);
	ok(str_match(&tn, const_str("+441632960000")), "trim-up-noparam");

	/* given multiple parameters, when trimmed, then it cuts at the first ';' */
	tn = *_str("+1;a=1;b=2;c=3");
	trim_user_params(&tn);
	ok(str_match(&tn, const_str("+1")), "trim-up-multi-semi");

	/* given a userinfo whose first char is ';', when trimmed, then it is empty */
	tn = *_str(";tgrp=grp1");
	trim_user_params(&tn);
	ok(tn.len == 0, "trim-up-leading-semi");

	/* given a bare ';', when trimmed, then it is empty */
	tn = *_str(";");
	trim_user_params(&tn);
	ok(tn.len == 0, "trim-up-only-semi");

	/* given an empty userinfo, when trimmed, then it stays empty (no crash) */
	tn.s = NULL;
	tn.len = 0;
	trim_user_params(&tn);
	ok(tn.len == 0, "trim-up-empty");

	/* trimming is idempotent: re-trimming an already-clean value is a no-op */
	tn = *_str("+33123456789;tgrp=grp1");
	trim_user_params(&tn);
	trim_user_params(&tn);
	ok(str_match(&tn, const_str("+33123456789")), "trim-up-idempotent");

	/* --- backslashes and other special characters --------------------- */

	/* given a value containing a backslash before the params, when trimmed,
	 * then the backslash is preserved and only the params are dropped */
	tn = *_str("a\\b;tgrp=x");
	trim_user_params(&tn);
	ok(str_match(&tn, const_str("a\\b")), "trim-up-backslash");

	/* given a backslash immediately before the ';', when trimmed, then the
	 * ';' is NOT treated as escaped: this helper is escape-agnostic and still
	 * cuts at that first ';' (so "a\;b" -> "a\", not "a\;b") */
	tn = *_str("a\\;b");
	trim_user_params(&tn);
	ok(str_match(&tn, const_str("a\\")), "trim-up-backslash-no-escape");

	/* given a value full of special characters before the ';', when trimmed,
	 * then every one of them survives up to the first ';' */
	tn = *_str("+1*#!~&%\\'\";trunk-context=x");
	trim_user_params(&tn);
	ok(str_match(&tn, const_str("+1*#!~&%\\'\"")), "trim-up-special-chars");

	/* given userinfo with an embedded NUL before the ';', when trimmed, then
	 * the NUL is preserved and the cut still lands on the ';' after it -
	 * trim_user_params() is length-based (q_memchr), not NUL-terminated like
	 * strchr would be, which would stop at the NUL and never see the ';'.
	 * Use a writable buffer (not a read-only string literal) so the case stays
	 * valid even for a future implementation that writes through .s. */
	{
		static char nul_buf[] = { '+', '1', '\0', '9', ';', 'p', '=', '1' };

		tn.s = nul_buf;
		tn.len = sizeof nul_buf;   /* 8 bytes: + 1 \0 9 ; p = 1 */
		trim_user_params(&tn);
		ok(tn.len == 4 && tn.s[0] == '+' && tn.s[2] == '\0' && tn.s[3] == '9',
			"trim-up-embedded-nul");
	}

	/* --- end-to-end: parse_uri() + trim_user_params() compose correctly -----
	 * Pins the load-bearing premise of issue #3904: for a sip:...@host URI,
	 * parse_uri() folds the RFC 4904 userinfo params into uri.user (NOT into
	 * uri.user_param), so trimming uri.user yields the bare E.164 number. The
	 * isolated cases above would all stay green if parse_uri() ever routed the
	 * params elsewhere; these would not. */
	{
		struct sip_uri u;
		str in;

		in = *_str("sip:+33123456789;tgrp=grp1;trunk-context=example.com@host.example");
		ok(parse_uri(in.s, in.len, &u) == 0, "trim-up-e2e-sip-parse");
		ok(u.user_param.len == 0, "trim-up-e2e-sip-user_param-empty");
		trim_user_params(&u.user);
		ok(str_match(&u.user, const_str("+33123456789")), "trim-up-e2e-sip");

		in = *_str("sip:+15551234567;tgrp=grp1@host");
		ok(parse_uri(in.s, in.len, &u) == 0, "trim-up-e2e-sip2-parse");
		trim_user_params(&u.user);
		ok(str_match(&u.user, const_str("+15551234567")), "trim-up-e2e-sip2");

		/* a tel: URI already splits the params into uri.host/params, so uri.user
		 * is clean on arrival and the trim is a (correct) no-op */
		in = *_str("tel:+15551234567;tgrp=grp1;trunk-context=example.com");
		ok(parse_uri(in.s, in.len, &u) == 0, "trim-up-e2e-tel-parse");
		trim_user_params(&u.user);
		ok(str_match(&u.user, const_str("+15551234567")), "trim-up-e2e-tel");
	}
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
	}, {
		/* test for read overflow on Via header (the @end pointer) */
		"Q e  M\nV:SIP/2.0  /1P 4rr;TT;TT;TT;TT;TT;TT;T\xd2;TT;",
		-1,
	}, {
		/* test for read overflow on Via header param (the @end pointer) */
		"A  !\nV:SIP/2.0/? M;recEIVeD\n ",
		-1,
	}, {
		/* test for read overflow on Content-Length parsing error (@end) */
		"v D \xd7\r\xeeV:1\r\nl:5\r*",
		-1,
	}, {
		/* test for read overflow during Content-Length ws trimming (@end) */
		"abcde J    \x09:5\nL\x09:\x09\n",
		-1,
	},
};

void test_parse_msg(void)
{
	int i;

	for (i = 0; i < sizeof tset/sizeof *tset; i++) {
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
	test_trim_user_params();
	test_parse_msg();
	test_parse_qop_val();
	test_parse_fcaps();
	test_parse_authenticate_body();
}
