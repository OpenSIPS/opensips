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
#include "../../../dset.h"
#include "../../../data_lump_rpl.h"
#include "../../../test/ut.h"
#include "../../../parser/parse_methods.h"
#include "../../../parser/msg_parser.h"
#include "../../../lib/reg/common.h"

#include "../../usrloc/usrloc.h"
#include "../reg_mod.h"
#include "../lookup.h"
#include "../reply.h"


static int (*saved_t_wait_for_new_branches)(struct sip_msg *msg,
	unsigned int num_br);
static unsigned int pn_wait_branches;
static int pn_wait_calls;
static sig_send_reply_f saved_sig_reply;


static int test_t_wait_for_new_branches(struct sip_msg *msg,
	unsigned int num_br)
{
	pn_wait_calls++;
	pn_wait_branches = num_br;
	return 1;
}


static int test_sig_reply(struct sip_msg *msg, int code, const str *reason,
	str *tag)
{
	return 0;
}


static int mk_supported_register_req(struct sip_msg *msg)
{
	static char msgbuf[BUF_SIZE];
	int len;

	len = snprintf(msgbuf, BUF_SIZE,
		"REGISTER sip:registrar.example.org SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.0.2.4:5060;branch=z9hG4bK%x%x\r\n"
		"From: Alice <sip:alice@example.org>;tag=%x%x\r\n"
		"To: Alice <sip:alice@example.org>\r\n"
		"CSeq: 1 REGISTER\r\n"
		"Call-ID: %x%x%x%x\r\n"
		"Max-Forwards: 70\r\n"
		"Supported: gruu\r\n"
		"Contact: <sip:alice@192.0.2.4>\r\n"
		"Content-Length: 0\r\n"
		"\r\n", rand(), rand(), rand(), rand(),
		rand(), rand(), rand(), rand());

	memset(msg, 0, sizeof *msg);
	msg->buf = msgbuf;
	msg->len = len;
	msg->ruri_q = Q_UNSPECIFIED;

	if (parse_msg(msgbuf, len, msg) != 0) {
		LM_ERR("failed to parse test REGISTER msg\n");
		return -1;
	}

	return 0;
}


static int str_contains_cstr(const str *haystack, const char *needle)
{
	int needle_len = strlen(needle);
	int i;

	if (needle_len > haystack->len)
		return 0;

	for (i = 0; i <= haystack->len - needle_len; i++)
		if (!memcmp(haystack->s + i, needle, needle_len))
			return 1;

	return 0;
}


static void start_pn_wait_capture(void)
{
	saved_t_wait_for_new_branches = tmb.t_wait_for_new_branches;
	tmb.t_wait_for_new_branches = test_t_wait_for_new_branches;
	pn_wait_calls = 0;
	pn_wait_branches = 0;
}


static void stop_pn_wait_capture(void)
{
	tmb.t_wait_for_new_branches = saved_t_wait_for_new_branches;
}


static void start_sig_reply_capture(void)
{
	saved_sig_reply = sigb.reply;
	sigb.reply = test_sig_reply;
}


static void stop_sig_reply_capture(void)
{
	sigb.reply = saved_sig_reply;
}


static void fill_ucontact_info(ucontact_info_t *ci)
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


static void test_reply_sip_instance(void)
{
	int old_disable_gruu;
	struct sip_msg msg;
	struct socket_info sock;
	ucontact_t contact;
	struct lump_rpl *lump;
	str aor = str_init("alice");

	memset(&sock, 0, sizeof sock);
	sock.name = str_init("registrar.example.org");
	sock.port_no_str = str_init("5060");

	memset(&contact, 0, sizeof contact);
	contact.aor = &aor;
	contact.c = str_init("sip:alice@192.0.2.4");
	contact.expires = get_act_time() + 120;
	contact.q = Q_UNSPECIFIED;
	contact.instance = str_init("<urn:uuid:00000000-0000-1000-8000-000A95A0E128>");
	contact.callid = str_init("reg-callid");
	contact.sock = &sock;

	ok(mk_supported_register_req(&msg) == 0, "reply instance: parse REGISTER");

	old_disable_gruu = disable_gruu;
	disable_gruu = 0;
	start_sig_reply_capture();

	ok(build_contact(&contact, &msg) == 0, "reply instance: build Contact");
	rerrno = R_FINE;
	ok(send_reply(&msg, 0) == 0, "reply instance: send 200 OK");

	lump = get_lump_rpl(&msg, LUMP_RPL_HDR);
	ok(lump != NULL, "reply instance: Contact reply lump exists");
	ok(lump && str_contains_cstr(&lump->text,
		"Contact: <sip:alice@192.0.2.4>;expires=120;pub-gruu="
		"\"sip:alice@registrar.example.org:5060;gr="
		"urn:uuid:00000000-0000-1000-8000-000A95A0E128\""),
		"reply instance: pub-gruu keeps bare instance value");
	ok(lump && str_contains_cstr(&lump->text,
		";+sip.instance=\"<urn:uuid:00000000-0000-1000-8000-000A95A0E128>\""),
		"reply instance: +sip.instance keeps RFC 5626 angle brackets");
	ok(lump && !str_contains_cstr(&lump->text,
		";+sip.instance=\"urn:uuid:00000000-0000-1000-8000-000A95A0E128\""),
		"reply instance: +sip.instance is not stripped to the old value");

	if (lump) {
		unlink_lump_rpl(&msg, lump);
		free_lump_rpl(lump);
	}
	free_contact_buf();
	stop_sig_reply_capture();
	disable_gruu = old_disable_gruu;
}


static void test_lookup(void)
{
	udomain_t *d;
	urecord_t *r;
	ucontact_t *c;
	ucontact_info_t ci;
	str aor = str_init("alice");
	str aor_ruri = str_init("sip:alice@localhost");
	str extra_branch_uri = str_init("sip:parallel@127.0.0.3");
	str ct1 = str_init("sip:cell@127.0.0.1:44444;"
			"pn-provider=apns;"
			"pn-prid=ZTY4ZDJlMzODE1NmUgKi0K;"
			"pn-param=ezenSQIywP8:APA91bHFH7p41WUFljaUPM2PPEjQUEslb6NtIqN6Pyc"
			         "gN5eDCyzuomQMyWboTVum0MY8YL_3E8vFIZUur_B71DHVgXQVD6UfZJ"
			         "mAq9Px0UY8YjVmo2LnmCocmFRBU0gPMV2ebheGGWCc");
	str ct2 = str_init("sip:desk@127.0.0.2");
	struct sip_msg msg;
	struct lookup_flags flags;

	memset(&flags, 0, sizeof flags);

	ok(ul.register_udomain("location", &d) == 0, "get 'location' udomain");

	mk_sip_req("INVITE", "sip:alice@localhost", &msg);
	ok(reg_lookup(&msg, d, NULL, NULL) == LOOKUP_NO_RESULTS, "lookup-1");

	ul.lock_udomain(d, &aor);
	ok(ul.insert_urecord(d, &aor, &r, 0) == 0, "create AoR");

	fill_ucontact_info(&ci);
	ci.methods = METHOD_UNDEF;
	ok(ul.insert_ucontact(r, &ct2, &ci, NULL, 1, &c) == 0, "insert Contact");
	ul.unlock_udomain(d, &aor);

	ok(reg_lookup(&msg, d, NULL, NULL) == LOOKUP_OK, "lookup-2");

	set_ruri(&msg, &aor_ruri);
	flags.flags = REG_LOOKUP_METHODFILTER_FLAG;
	ok(reg_lookup(&msg, d, &flags, NULL) == LOOKUP_METHOD_UNSUP,
		"lookup-3");

	c->methods = ALL_METHODS;

	set_ruri(&msg, &aor_ruri);
	ok(reg_lookup(&msg, d, NULL, NULL) == LOOKUP_OK, "lookup-4");

	set_ruri(&msg, &aor_ruri);
	ok(reg_lookup(&msg, d, &flags, NULL) == LOOKUP_OK,
		"lookup-5");

	ok(ul.delete_ucontact(r, c, NULL, 0) == 0, "delete ucontact");

	fill_ucontact_info(&ci);
	ci.flags |= FL_PN_ON; /* this is needed until we rewrite to call save() */
	ok(ul.insert_ucontact(r, &ct1, &ci, NULL, 1, &c) == 0, "insert ct1 (PN)");

	set_ruri(&msg, &aor_ruri);
	start_pn_wait_capture();
	ok(reg_lookup(&msg, d, NULL, NULL) == LOOKUP_PN_SENT, "lookup-6");
	ok(pn_wait_calls == 1 && pn_wait_branches == 1,
		"lookup-6: waits for PN branch");
	stop_pn_wait_capture();

	fill_ucontact_info(&ci);
	ok(ul.insert_ucontact(r, &ct2, &ci, NULL, 1, &c) == 0, "insert ct2 (normal)");

	set_ruri(&msg, &aor_ruri);
	start_pn_wait_capture();
	ok(reg_lookup(&msg, d, NULL, NULL) == LOOKUP_OK, "lookup-7");
	ok(pn_wait_calls == 1 && pn_wait_branches == 2,
		"lookup-7: waits for PN and regular branch");
	stop_pn_wait_capture();

	/* the PN contact should just trigger a PN without becoming a branch */
	ok(str_match(&msg.new_uri, &ct2), "lookup-7: R-URI is ct2");

	{
		struct msg_branch branch;

		memset(&branch, 0, sizeof branch);
		branch.uri = extra_branch_uri;
		branch.q = Q_UNSPECIFIED;
		ok(append_msg_branch(&branch) == 1, "append extra branch");

		set_ruri(&msg, &aor_ruri);
		start_pn_wait_capture();
		ok(reg_lookup(&msg, d, NULL, NULL) == LOOKUP_OK, "lookup-7b");
		ok(pn_wait_calls == 1 && pn_wait_branches == 3,
			"lookup-7b: waits for existing, regular and PN branches");
		stop_pn_wait_capture();
		clear_dset();
	}

	/* test the "r" flag (branch lookup) */
	{
		str aor2 = str_init("bob"), aor3 = str_init("carol");
		struct msg_branch branch;

		clear_dset();

		ul.lock_udomain(d, &aor2);
		ok(ul.insert_urecord(d, &aor2, &r, 0) == 0, "create AoR 2");
		ul.unlock_udomain(d, &aor2);

		ul.lock_udomain(d, &aor3);
		ok(ul.insert_urecord(d, &aor3, &r, 0) == 0, "create AoR 3");
		fill_ucontact_info(&ci);
		ci.methods = METHOD_UNDEF;
		ok(ul.insert_ucontact(r, &ct2, &ci, NULL, 1, &c) == 0, "insert Contact for AoR 3");
		ul.unlock_udomain(d, &aor3);

		/* ensure the AoR expansion process doesn't stop on a non-existing AoR */
		memset(&branch, 0, sizeof branch);
		branch.uri = str_init("sip:FOOBAR@foobar.com");
		branch.q = 1;
		ok(append_msg_branch(&branch) == 1, "append AoR-2");

		branch.uri = str_init("sip:carol@foobar.com");
		ok(append_msg_branch(&branch) == 1, "append AoR-3");

		set_ruri(&msg, &aor_ruri);
		flags.flags = REG_BRANCH_AOR_LOOKUP_FLAG;
		ok(reg_lookup(&msg, d, &flags, NULL) == LOOKUP_OK, "lookup-8");
		ok(get_dset_size() == 1, "get-nr-branches");
	}
}


static void test_purr(void)
{
	ucontact_id id = 0UL;
	char *p;

	ok(!strcmp(pn_purr_pack(0UL), "000.00000.00000000"), "purr-1");
	ok(!strcmp(pn_purr_pack(18446744073709551615UL),
	           "fff.fffff.ffffffff"), "purr-2");

	/* tricky PURR formats (all bad) */
	ok(pn_purr_unpack(_str("000.00000.0000000"), &id) == -1, "purr-4");
	ok(pn_purr_unpack(_str("000.00000.000000000"), &id) == -1, "purr-5");
	ok(pn_purr_unpack(_str("00.000000.00000000"), &id) == -1, "purr-6");
	ok(pn_purr_unpack(_str("0000.0000.00000000"), &id) == -1, "purr-7");
	ok(pn_purr_unpack(_str("000.0000.000000000"), &id) == -1, "purr-8");
	ok(pn_purr_unpack(_str("000.000000.0000000"), &id) == -1, "purr-9");
	ok(pn_purr_unpack(_str("000000000.00000000"), &id) == -1, "purr-10");
	ok(pn_purr_unpack(_str("000.00000000000000"), &id) == -1, "purr-11");
	ok(pn_purr_unpack(_str("000000000000000000"), &id) == -1, "purr-12");
	ok(pn_purr_unpack(_str(".00.00000.00000000"), &id) == -1, "purr-13");
	ok(pn_purr_unpack(_str("000.00000.0000000."), &id) == -1, "purr-14");
	ok(pn_purr_unpack(_str(".................."), &id) == -1, "purr-15");

	ok(pn_purr_unpack(_str("000.00000.00000000"), &id) == 0, "purr-16");
	ok(id == 0UL, "purr-17");

	ok(pn_purr_unpack(_str("fff.fffff.ffffffff"), &id) == 0, "purr-18");
	ok(id == 18446744073709551615UL, "purr-19");

	p = pn_purr_pack(12345678901234567890UL);
	ok(pn_purr_unpack(_str(p), &id) == 0, "purr-20");
	ok(id == 12345678901234567890UL, "purr-21");
}


void mod_tests(void)
{
	test_lookup();
	test_purr();
	test_reply_sip_instance();
}
