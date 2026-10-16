/*
 * Copyright (C) 2024 OpenSIPS Project
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#include <tap.h>

#include "../../str.h"
#include "../../ut.h"

#include "../../parser/parse_sst.h"

#include "test_oob.h"
#include "test_parse_sst.h"

static void test_parse_sst_oob(const str *, enum oob_position where, void *);

static enum parse_sst_result parse_se(const str *body, struct session_expires *out)
{
	struct hdr_field hf;
	enum parse_sst_result res;

	memset(&hf, 0, sizeof hf);
	hf.body = *body;
	res = parse_session_expires_body(&hf);
	if (hf.parsed) {
		if (out)
			*out = *(struct session_expires *)hf.parsed;
		free_session_expires(hf.parsed);
	}
	return res;
}

void test_parse_sst(void)
{
	struct session_expires se;
	int i;
	const str tset[] = {
		str_init("1;refresher=uac"),
		str_init("300;refresher=uas"),
		str_init("90;refresher=xxx"),
		str_init("1;refresher="),
		str_init("1;refr"),
		{0, 0}
	};

	/* valid bodies parse to the expected interval / refresher */
	memset(&se, 0, sizeof se);
	ok(parse_se(_str("1;refresher=uac"), &se) == parse_sst_success, "sst-1");
	ok(se.interval == 1 && se.refresher == sst_refresher_uac, "sst-2");

	memset(&se, 0, sizeof se);
	ok(parse_se(_str("300;refresher=uas"), &se) == parse_sst_success, "sst-3");
	ok(se.interval == 300 && se.refresher == sst_refresher_uas, "sst-4");

	memset(&se, 0, sizeof se);
	ok(parse_se(_str("3600"), &se) == parse_sst_success, "sst-5");
	ok(se.interval == 3600 && se.refresher == sst_refresher_unspecified, "sst-6");

	/* a body that ends inside the "refresher=" token must not over-read */
	for (i = 0; tset[i].s != NULL; i++)
		test_oob(&tset[i], test_parse_sst_oob, NULL);
}

static void test_parse_sst_oob(const str *tstr, enum oob_position where, void *farg)
{
	struct hdr_field hf;

	memset(&hf, 0, sizeof hf);
	hf.body = *tstr;
	parse_session_expires_body(&hf);
	if (hf.parsed)
		free_session_expires(hf.parsed);
	ok(1, OOB_CHECK_OK_MSG("parse_session_expires_body", tstr, where));
}
