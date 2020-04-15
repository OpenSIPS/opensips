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
#include "../../../lib/reg/pn.h"
#include "../../../lib/reg/regtime.h"

#include "../../usrloc/usrloc.h"
#include "../reg_mod.h"
#include "../lookup.h"


ucontact_t *create_contact(const char *ct_uri, const struct ct_match *cmatch,
                           urecord_t *r)
{
	ucontact_t *c;
	ucontact_info_t ci;
	char cid_buf[9];
	str callid = {cid_buf, 0};
	str no_ua = str_init("n/a");

	update_act_time();

	memset(&ci, 0, sizeof ci);

	callid.len = sprintf(cid_buf, "%x", rand());
	ci.callid = &callid;
	ci.user_agent = &no_ua;
	ci.q = Q_UNSPECIFIED;
	ci.expires = get_act_time() + 120;

	ok(ul.insert_ucontact(r, _str(ct_uri), &ci, &c, 0) == 0, "Insert Contact");
	return c;
}


void test_lookup(void)
{
	udomain_t *d;
	urecord_t *r;
	ucontact_t *c;
	struct ct_match cmatch;
	struct sip_msg msg;

	ok(ul.register_udomain("location", &d) == 0, "get 'location' udomain");
	ok(ul.insert_urecord(d, _str("alice"), &r, 0) == 0, "create AoR");

	cmatch.mode = CT_MATCH_PARAMS;
	cmatch.match_params = pn_ct_params;
	ok((c = create_contact("sip:cell@127.0.0.1:44444;"
			"pn-provider=apns;"
			"pn-prid=ZTY4ZDJlMzODE1NmUgKi0K;"
			"pn-param=ezenSQIywP8:APA91bHFH7p41WUFljaUPM2PPEjQUEslb6NtIqN6Pyc"
			         "gN5eDCyzuomQMyWboTVum0MY8YL_3E8vFIZUur_B71DHVgXQVD6UfZJ"
			         "mAq9Px0UY8YjVmo2LnmCocmFRBU0gPMV2ebheGGWCc", &cmatch, r))
		!= NULL, "create Contact 1");

	cmatch.mode = CT_MATCH_CONTACT_ONLY;
	ok((c = create_contact("sip:desk@127.0.0.2", &cmatch, r)) != NULL, "create Contact 2");

	mk_sip_req("INVITE", "sip:alice@localhost", &msg);

	lookup(&msg, d, _str(""), NULL);

	/* the PN contact should just trigger a PN without becoming a branch */
	ok(str_match(&msg.new_uri, _str("sip:desk@127.0.0.2")), "lookup R-URI");
}


int mod_tests(void)
{
	test_lookup();

	return 0;
}
