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

#include "../../../str.h"
#include "../../../ut.h"
#include "../../../dprint.h"
#include "../../../pvar.h"
#include "../../../route_struct.h"
#include "../../../parser/msg_parser.h"

#include "../isup.h"
#include "../sip_i.h"

int pv_parse_isup_param_name(pv_spec_p sp, const str *in);
int pv_get_isup_param(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
int pv_set_isup_param(struct sip_msg* msg, pv_param_t *param, int op,
	pv_value_t *val);

#define TEST_BUF_SIZE 1024

/* IAM with the four mandatory fixed parameters, Called Party Number "1234"
 * and an optional Calling Party Number that is exactly PARAM_MAX_LEN long */
static int mk_iam(unsigned char *isup)
{
	int len = 0;

	isup[len++] = ISUP_IAM;
	isup[len++] = 0x00;	/* Nature of connection indicators */
	isup[len++] = 0x60;	/* Forward call indicators */
	isup[len++] = 0x01;
	isup[len++] = 0x0a;	/* Calling party's category */
	isup[len++] = 0x00;	/* Transmission medium requirement */
	isup[len++] = 0x02;	/* pointer to Called Party Number */
	isup[len++] = 0x06;	/* pointer to the optional part */
	isup[len++] = 0x04;	/* Called Party Number: "1234" */
	isup[len++] = 0x03;
	isup[len++] = 0x10;
	isup[len++] = 0x21;
	isup[len++] = 0x43;
	isup[len++] = ISUP_PARM_CALLING_PARTY_NUM;
	isup[len++] = PARAM_MAX_LEN;
	memset(isup + len, 0xab, PARAM_MAX_LEN);
	len += PARAM_MAX_LEN;
	isup[len++] = 0x00;	/* end of optional parameters */

	return len;
}

static int mk_isup_invite(struct sip_msg *msg, char *buf)
{
	unsigned char isup[TEST_BUF_SIZE];
	int isup_len, len;

	isup_len = mk_iam(isup);

	len = snprintf(buf, TEST_BUF_SIZE,
		"INVITE sip:1234@example.org SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.0.2.4:5060;branch=z9hG4bK1\r\n"
		"From: <sip:alice@example.org>;tag=1\r\n"
		"To: <sip:1234@example.org>\r\n"
		"CSeq: 1 INVITE\r\n"
		"Call-ID: sip-i-test\r\n"
		"Max-Forwards: 70\r\n"
		"Content-Type: application/ISUP;version=itu-t92+\r\n"
		"Content-Length: %d\r\n"
		"\r\n", isup_len);
	memcpy(buf + len, isup, isup_len);
	len += isup_len;

	memset(msg, 0, sizeof *msg);
	msg->buf = buf;
	msg->len = len;

	if (parse_msg(buf, len, msg) != 0) {
		LM_ERR("failed to parse test INVITE\n");
		return -1;
	}

	return 0;
}

static int isup_spec(pv_spec_t *sp, char *name)
{
	str s;

	s.s = name;
	s.len = strlen(name);

	memset(sp, 0, sizeof *sp);
	return pv_parse_isup_param_name(sp, &s);
}

static int set_str(struct sip_msg *msg, pv_spec_t *sp, char *s, int len)
{
	pv_value_t val;

	memset(&val, 0, sizeof val);
	val.flags = PV_VAL_STR;
	val.rs.s = s;
	val.rs.len = len;

	return pv_set_isup_param(msg, &sp->pvp, EQ_T, &val);
}

static int get_str(struct sip_msg *msg, pv_spec_t *sp, str *out)
{
	pv_value_t res;

	memset(&res, 0, sizeof res);
	if (pv_get_isup_param(msg, &sp->pvp, &res) < 0 ||
		!(res.flags & PV_VAL_STR))
		return -1;

	*out = res.rs;
	return 0;
}

static void test_isup_param_bounds(void)
{
	static char msgbuf[TEST_BUF_SIZE];
	struct sip_msg msg;
	pv_spec_t cdpn_num, cgpn, gn_num;
	char val[512];
	char expected[2 + 2 * PARAM_MAX_LEN];
	str res;
	int i;

	if (mk_isup_invite(&msg, msgbuf) < 0) {
		ok(0, "build a SIP-I INVITE");
		return;
	}

	ok(isup_spec(&cdpn_num, "Called Party Number|Address signal") == 0 &&
		isup_spec(&cgpn, "Calling Party Number") == 0 &&
		isup_spec(&gn_num, "Generic Number|Address signal") == 0,
		"parse the $isup_param names");

	ok(get_str(&msg, &cdpn_num, &res) == 0 && str_match(&res, const_str("1234")),
		"read the received Called Party Number");

	/* a received parameter of PARAM_MAX_LEN bytes is printed as hex */
	expected[0] = '0';
	expected[1] = 'x';
	for (i = 0; i < PARAM_MAX_LEN; i++) {
		expected[2 + 2 * i] = 'a';
		expected[3 + 2 * i] = 'b';
	}
	ok(get_str(&msg, &cgpn, &res) == 0 && res.len == sizeof expected &&
		!memcmp(res.s, expected, sizeof expected),
		"print a PARAM_MAX_LEN parameter as hex");

	ok(set_str(&msg, &cdpn_num, "98765", 5) == 0 &&
		get_str(&msg, &cdpn_num, &res) == 0 && str_match(&res, const_str("98765")),
		"set and read back an odd length Called Party Number");

	/* Address signal: 2 header bytes + up to 126 BCD bytes */
	memset(val, '5', sizeof val);
	ok(set_str(&msg, &cdpn_num, val, 2 * (PARAM_MAX_LEN - 2)) == 0,
		"set a Called Party Number that fills the parameter");
	ok(get_str(&msg, &cdpn_num, &res) == 0 &&
		res.len == 2 * (PARAM_MAX_LEN - 2),
		"read back a Called Party Number that fills the parameter");
	ok(set_str(&msg, &cdpn_num, val, 2 * (PARAM_MAX_LEN - 2) + 1) < 0,
		"reject a Called Party Number longer than the parameter");
	ok(set_str(&msg, &cdpn_num, val, 300) < 0,
		"reject a 300 digit Called Party Number");
	ok(get_str(&msg, &cdpn_num, &res) == 0 &&
		res.len == 2 * (PARAM_MAX_LEN - 2),
		"a rejected Called Party Number leaves the parameter as it was");

	/* new optional parameter, 3 header bytes + up to 125 BCD bytes */
	ok(set_str(&msg, &gn_num, val, 2 * (PARAM_MAX_LEN - 3) + 1) < 0,
		"reject a Generic Number longer than the parameter");
	ok(set_str(&msg, &gn_num, val, 2 * (PARAM_MAX_LEN - 3)) == 0,
		"set a Generic Number that fills the parameter");

	/* whole parameter as a hex string */
	val[0] = '0';
	val[1] = 'x';
	memset(val + 2, '0', sizeof val - 2);
	ok(set_str(&msg, &cgpn, val, 2 + 2 * PARAM_MAX_LEN) == 0,
		"set a PARAM_MAX_LEN parameter from a hex string");
	ok(set_str(&msg, &cgpn, val, 2 + 2 * (PARAM_MAX_LEN + 1)) < 0,
		"reject a hex string longer than PARAM_MAX_LEN");

	free_sip_msg(&msg);
}

void mod_tests(void)
{
	test_isup_param_bounds();
}
