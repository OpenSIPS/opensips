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

	in = *_str("sip:alice@atlanta.org;user=phone");
	ok(parse_uri(in.s, in.len, &u) == 0, "puri-1");
	ok(str_match(&u.user_param, _str("user=phone")), "puri-2");
	ok(str_match(&u.user_param_val, _str("phone")), "puri-3");

	in = *_str("sip:alice@atlanta.org;user=phone;gr=x");
	ok(parse_uri(in.s, in.len, &u) == 0, "puri-4");
	ok(str_match(&u.user_param, _str("user=phone")), "puri-5");
	ok(str_match(&u.user_param_val, _str("phone")), "puri-6");
	ok(str_match(&u.gr, _str("gr=x")), "puri-7");
	ok(str_match(&u.gr_val, _str("x")), "puri-8");

	in = *_str("sip:alice@atlanta.org;transport=udp;user=phone;maddr=1.2.3.4;gr");
	ok(parse_uri(in.s, in.len, &u) == 0, "puri-9");
	ok(str_match(&u.user, _str("alice")), "puri-10");
	ok(str_match(&u.host, _str("atlanta.org")), "puri-11");
	ok(str_match(&u.transport, _str("transport=udp")), "puri-12");
	ok(str_match(&u.transport_val, _str("udp")), "puri-13");
	ok(str_match(&u.user_param, _str("user=phone")), "puri-14");
	ok(str_match(&u.user_param_val, _str("phone")), "puri-15");
	ok(str_match(&u.maddr, _str("maddr=1.2.3.4")), "puri-16");
	ok(str_match(&u.maddr_val, _str("1.2.3.4")), "puri-17");
	ok(str_match(&u.gr, _str("gr")), "puri-18");
	ok(str_match(&u.gr_val, _str("")), "puri-19");

	/* SIP PN (RFC 8599) URI param parsing tests */

	/* pn-provider value is optional */
	in = *_str("sip:alice@atlanta.org;pn-provider");
	ok(parse_uri(in.s, in.len, &u) == 0, "puri-20");
	ok(str_match(&u.pn_provider, _str("pn-provider")), "puri-21");
	ok(str_match(&u.pn_provider_val, _str("")), "puri-22");
	ok(!u.pn_provider_val.s, "puri-22-NULL");

	in = *_str("sip:alice@atlanta.org;pn-provider=");
	ok(parse_uri(in.s, in.len, &u) == 0, "puri-23");
	ok(str_match(&u.pn_provider, _str("pn-provider=")), "puri-24");
	ok(str_match(&u.pn_provider_val, _str("")), "puri-25");
	ok(!u.pn_provider_val.s, "puri-25-NULL");

	in = *_str("sip:alice@atlanta.org;pn-provider=x");
	ok(parse_uri(in.s, in.len, &u) == 0, "puri-26");
	ok(str_match(&u.pn_provider, _str("pn-provider=x")), "puri-27");
	ok(str_match(&u.pn_provider_val, _str("x")), "puri-28");

	/* pn-prid value is mandatory */
	in = *_str("sip:alice@atlanta.org;pn-prid=");
	ok(parse_uri(in.s, in.len, &u) != 0, "puri-29");
	in = *_str("sip:alice@atlanta.org;pn-prid");
	ok(parse_uri(in.s, in.len, &u) != 0, "puri-30");

	/* pn-param value is mandatory */
	in = *_str("sip:alice@atlanta.org;pn-param=");
	ok(parse_uri(in.s, in.len, &u) != 0, "puri-31");
	in = *_str("sip:alice@atlanta.org;pn-param");
	ok(parse_uri(in.s, in.len, &u) != 0, "puri-32");

	/* pn-purr value is mandatory */
	in = *_str("sip:alice@atlanta.org;pn-purr=");
	ok(parse_uri(in.s, in.len, &u) != 0, "puri-33");
	in = *_str("sip:alice@atlanta.org;pn-purr");
	ok(parse_uri(in.s, in.len, &u) != 0, "puri-34");

	in = *_str("sip:alice@atlanta.org;pn-provider=x;pn-prid=y;"
	                                 "pn-param=z;pn-purr=t");
	ok(parse_uri(in.s, in.len, &u) == 0, "puri-35");
	ok(str_match(&u.pn_provider, _str("pn-provider=x")), "puri-36");
	ok(str_match(&u.pn_provider_val, _str("x")), "puri-37");
	ok(str_match(&u.pn_prid, _str("pn-prid=y")), "puri-38");
	ok(str_match(&u.pn_prid_val, _str("y")), "puri-39");
	ok(str_match(&u.pn_param, _str("pn-param=z")), "puri-40");
	ok(str_match(&u.pn_param_val, _str("z")), "puri-41");
	ok(str_match(&u.pn_purr, _str("pn-purr=t")), "puri-42");
	ok(str_match(&u.pn_purr_val, _str("t")), "puri-43");
}

void test_parser(void)
{
	test_parse_qop_val();
	test_parse_fcaps();
	test_parse_uri();
	test_parse_authenticate_body();
}
