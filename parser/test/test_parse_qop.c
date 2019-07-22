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

void test_parse_qop_val(void)
{
	struct authenticate_body auth;

	memset(&auth, 0, sizeof(struct authenticate_body));
	ok(parse_qop_value(_str("aaa"), &auth));
	ok(parse_qop_value(_str("auth-init"), &auth));
	ok(parse_qop_value(_str("auth,aaa"), &auth));
	ok(parse_qop_value(_str("auth,auth-init"), &auth));

	memset(&auth, 0, sizeof(struct authenticate_body));
	ok(!parse_qop_value(_str("auth "), &auth));
	ok(auth.flags & QOP_AUTH);
	ok(!(auth.flags & QOP_AUTH_INT));

	memset(&auth, 0, sizeof(struct authenticate_body));
	ok(!parse_qop_value(_str("auth-int"), &auth));
	ok(!(auth.flags & QOP_AUTH));
	ok(auth.flags & QOP_AUTH_INT);

	memset(&auth, 0, sizeof(struct authenticate_body));
	ok(!parse_qop_value(_str("auth, auth-int"), &auth));
	ok(auth.flags & QOP_AUTH);
	ok(auth.flags & QOP_AUTH_INT);

	memset(&auth, 0, sizeof(struct authenticate_body));
	ok(!parse_qop_value(_str("auth-int , auth"), &auth));
	ok(auth.flags & QOP_AUTH);
	ok(auth.flags & QOP_AUTH_INT);
}
