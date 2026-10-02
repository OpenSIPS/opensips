/*
 * Copyright (C) 2026 Sahana Bogar
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

#include "../parse_supported.h"

#include "test_parse_supported.h"
#include "test_oob.h"

static void test_parse_supported_body_oob(const str *, enum oob_position, void *);

/* parse @hdr as a Supported header body and return the option tag flags */
static int parse_sup(const char *hdr, unsigned int *sup)
{
	str body;

	init_str(&body, hdr);
	return parse_supported_body(&body, sup);
}

/* each one is read with the body ending on a guard page, so any lookahead
 * stepping outside it faults: a recognized option tag flush against the end
 * of the body, an element too short to hold one, and a body made of nothing
 * but delimiters */
static const str oob_tset[] = {
	str_init("path"),
	str_init("gruu"),
	str_init("timer"),
	str_init("100rel"),
	str_init("eventlist"),
	str_init("path,gruu"),
	str_init("timer, path"),
	str_init("eventlist,100rel"),
	str_init("100rel,x"),
	str_init("foo"),
	str_init("x"),
	str_init(","),
	str_init(" \t"),
	{NULL, 0}
};

void test_parse_supported(void)
{
	unsigned int sup;
	int i;

	/* an option tag is recognized when it ends at the end of the body, with
	 * no delimiter of its own to close it */
	ok(parse_sup("path", &sup) == 0 &&
		sup == F_SUPPORTED_PATH, "sup-path");
	ok(parse_sup("gruu", &sup) == 0 &&
		sup == F_SUPPORTED_GRUU, "sup-gruu");
	ok(parse_sup("timer", &sup) == 0 &&
		sup == F_SUPPORTED_TIMER, "sup-timer");
	ok(parse_sup("100rel", &sup) == 0 &&
		sup == F_SUPPORTED_100REL, "sup-100rel");
	ok(parse_sup("eventlist", &sup) == 0 &&
		sup == F_SUPPORTED_EVENTLIST, "sup-eventlist");

	/* ... and when it is followed by a delimiter */
	ok(parse_sup("path,gruu", &sup) == 0 &&
		sup == (F_SUPPORTED_PATH|F_SUPPORTED_GRUU), "sup-path-gruu");
	ok(parse_sup("timer, 100rel , eventlist", &sup) == 0 &&
		sup == (F_SUPPORTED_TIMER|F_SUPPORTED_100REL|F_SUPPORTED_EVENTLIST),
		"sup-list");

	/* unknown or truncated option tags are skipped */
	ok(parse_sup("pat", &sup) == 0 && sup == 0, "sup-short");
	ok(parse_sup("paths", &sup) == 0 && sup == 0, "sup-prefix");
	ok(parse_sup("x,foo", &sup) == 0 && sup == 0, "sup-unknown");
	ok(parse_sup(",", &sup) == 0 && sup == 0, "sup-delim-only");
	ok(parse_sup("", &sup) == 0 && sup == 0, "sup-empty");
	ok(parse_sup("x,path", &sup) == 0 &&
		sup == F_SUPPORTED_PATH, "sup-unknown-then-path");

	for (i = 0; oob_tset[i].s != NULL; i++)
		test_oob(&oob_tset[i], test_parse_supported_body_oob, &sup);
}

static void test_parse_supported_body_oob(const str *tstr, enum oob_position where,
		void *farg)
{
	str body = *tstr;

	parse_supported_body(&body, (unsigned int *)farg);
	ok(1, OOB_CHECK_OK_MSG("parse_supported_body", tstr, where));
}
