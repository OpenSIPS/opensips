/*
 * Copyright (C) 2019 OpenSIPS Solutions
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

#include "../../parser/parse_authenticate.h"

#include "test_oob.h"

void test_parse_qop_oob(const str *, enum oob_position where, void *);

void test_parse_qop_val(void)
{
	struct authenticate_body auth;
	int i;
	struct tts {
		const str ts;
		int tres;
		int aflags;
	} tset[] = {
		{.ts = str_init("aut"), .tres = -1},
		{.ts = str_init("auth-inti"), .tres = -1},
		{.ts = str_init("auth,aut"), .tres = -1},
		{.ts = str_init("auth,auth-inti"), .tres = -1},
		{.ts = str_init("auth,,auth-int"), .tres = -1},
		{.ts = str_init("auth-int,"), .tres = -1},
		{.ts = str_init("auth,auth-int,"), .tres = -1},
		{.ts = str_init("auth,auth-int,aut"), .tres = -1},
		{.ts = str_init("auth-int  , \tauth "),  .tres = -1},
		{.ts = str_init(" auth-int,auth"),  .tres = -1},
		{.ts = str_init("auth "), .tres = 0, .aflags = QOP_AUTH},
		{.ts = str_init("auth-int"), .tres = 0, .aflags = QOP_AUTH_INT},
		{.ts = str_init("auth, auth-int"), .tres = 0, .aflags = QOP_AUTH | QOP_AUTH_INT},
		{.ts = str_init("auth-int , auth"), .tres = 0, .aflags = QOP_AUTH | QOP_AUTH_INT},
		{}
	};

	for (i = 0; tset[i].ts.s != NULL; i++) {
		memset(&auth, 0, sizeof(struct authenticate_body));
		ok(parse_qop_value(tset[i].ts, &auth) == tset[i].tres,
		    "parse_qop_value(\"%s\") == %d", tset[i].ts.s, tset[i].tres);
		if (tset[i].tres == 0)
			ok(auth.flags == tset[i].aflags, "auth.flags == %d", tset[i].aflags);
		test_oob(&tset[i].ts, test_parse_qop_oob, &auth);
	}
}

void test_parse_qop_oob(const str *tstr, enum oob_position where, void *farg)
{
	struct authenticate_body *ap = farg;

	parse_qop_value(*tstr, ap);
	ok(1, OOB_CHECK_OK_MSG("parse_qop_value", tstr, where));
}
