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

#include "../../../dprint.h"
#include "../../../test/ut.h"
#include "../../../parser/parse_methods.h"
#include "../../../parser/msg_parser.h"
#include "../../../lib/reg/pn.h"
#include "../../../lib/reg/regtime.h"

#include "../../usrloc/usrloc.h"
#include "../reg_mod.h"
#include "../lookup.h"


void fill_ucontact_info(ucontact_info_t *ci)
{
	static char cid_buf[9];
	static str callid = {cid_buf, 0};
	static str no_ua = str_init("n/a");

	update_act_time();

	memset(ci, 0, sizeof *ci);

	callid.len = sprintf(cid_buf, "%x", rand());
	ci->callid = &callid;
	ci->user_agent = &no_ua;
	ci->q = Q_UNSPECIFIED;
	ci->expires = get_act_time() + 120;
	ci->methods = ALL_METHODS;
}


void test_lookup(void)
{
	udomain_t *d;
	urecord_t *r;
	ucontact_t *c;
	ucontact_info_t ci;
	str aor = str_init("alice");
	str aor_ruri = str_init("sip:alice@localhost");
	str ct1 = str_init("sip:cell@127.0.0.1:44444;"
			"pn-provider=apns;"
			"pn-prid=ZTY4ZDJlMzODE1NmUgKi0K;"
			"pn-param=ezenSQIywP8:APA91bHFH7p41WUFljaUPM2PPEjQUEslb6NtIqN6Pyc"
			         "gN5eDCyzuomQMyWboTVum0MY8YL_3E8vFIZUur_B71DHVgXQVD6UfZJ"
			         "mAq9Px0UY8YjVmo2LnmCocmFRBU0gPMV2ebheGGWCc");
	str ct2 = str_init("sip:desk@127.0.0.2");
	struct sip_msg msg;

	ok(ul.register_udomain("location", &d) == 0, "get 'location' udomain");

	mk_sip_req("INVITE", "sip:alice@localhost", &msg);
	ok(reg_lookup(&msg, d, _str(""), NULL) == -1, "lookup: -1 (no contacts)");

	ul.lock_udomain(d, &aor);
	ok(ul.insert_urecord(d, &aor, &r, 0) == 0, "create AoR");

	fill_ucontact_info(&ci);
	ci.methods = METHOD_UNDEF;
	ok(ul.insert_ucontact(r, &ct2, &ci, &c, 0) == 0, "insert Contact");
	ul.unlock_udomain(d, &aor);

	ok(reg_lookup(&msg, d, _str(""), NULL) == 1, "lookup-1: 1 (success)");

	set_ruri(&msg, &aor_ruri);
	ok(reg_lookup(&msg, d, _str("m"), NULL) == -2, "lookup-2: -2 (bad method)");

	c->methods = ALL_METHODS;

	set_ruri(&msg, &aor_ruri);
	ok(reg_lookup(&msg, d, _str(""), NULL) == 1, "lookup-3: 1 (success)");

	set_ruri(&msg, &aor_ruri);
	ok(reg_lookup(&msg, d, _str("m"), NULL) == 1, "lookup-4: 1 (success)");

	ok(ul.delete_ucontact(r, c, 0) == 0, "delete ucontact");

	fill_ucontact_info(&ci);
	ok(ul.insert_ucontact(r, &ct1, &ci, &c, 0) == 0, "insert ct1 (PN)");

	set_ruri(&msg, &aor_ruri);
	ok(reg_lookup(&msg, d, _str(""), NULL) == 2, "lookup-5: 2 (success, PN)");

	fill_ucontact_info(&ci);
	ok(ul.insert_ucontact(r, &ct2, &ci, &c, 0) == 0, "insert ct2 (normal)");

	set_ruri(&msg, &aor_ruri);
	ok(reg_lookup(&msg, d, _str(""), NULL) == 1, "lookup-6: 1 (success)");

	/* the PN contact should just trigger a PN without becoming a branch */
	ok(str_match(&msg.new_uri, &ct2), "lookup-7: R-URI is ct2");
}


void mod_tests(void)
{
	test_lookup();
}
