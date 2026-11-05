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

#include "../../str.h"
#include "../../ut.h"

#include "../../parser/msg_parser.h"
#include "../../parser/parse_privacy.h"

#include "test_oob.h"
#include "test_parse_privacy.h"

static void test_parse_privacy_oob(const str *, enum oob_position where, void *);

static int parse_priv(const str *body, unsigned int *values)
{
	struct sip_msg msg;
	struct hdr_field hf;
	int res;

	memset(&msg, 0, sizeof msg);
	memset(&hf, 0, sizeof hf);
	hf.body = *body;
	msg.privacy = &hf;
	res = parse_privacy(&msg);
	if (values)
		*values = (unsigned int)(long)hf.parsed;
	return res;
}

void test_parse_privacy(void)
{
	unsigned int values;
	int i;
	const str tset[] = {
		str_init("id;        user"),
		str_init("header;        id"),
		str_init("none        "),
		{0, 0}
	};

	/* valid bodies parse to the expected privacy values */
	ok(parse_priv(_str("id"), &values) == 0 && values == PRIVACY_ID, "privacy-1");
	ok(parse_priv(_str("user; id"), &values) == 0 &&
		values == (PRIVACY_USER|PRIVACY_ID), "privacy-2");
	ok(parse_priv(_str("header;   session ; critical"), &values) == 0 &&
		values == (PRIVACY_HEADER|PRIVACY_SESSION|PRIVACY_CRITICAL), "privacy-3");
	ok(parse_priv(_str("id; xyz"), NULL) == -1, "privacy-4");

	/* whitespace between values must not stretch the length of the next one */
	for (i = 0; tset[i].s != NULL; i++)
		test_oob(&tset[i], test_parse_privacy_oob, NULL);
}

static void test_parse_privacy_oob(const str *tstr, enum oob_position where, void *farg)
{
	parse_priv(tstr, NULL);
	ok(1, OOB_CHECK_OK_MSG("parse_privacy", tstr, where));
}
