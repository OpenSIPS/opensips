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
#include "../../../dprint.h"
#include "../../../sr_module.h"
#include "../auth_aka.h"

int aka_test_build_resync(str *nonce, str *auts, str *resync);

/* 16-byte RAND, base64 */
#define T_NONCE "AAECAwQFBgcICQoLDA0ODw=="
/* 14-byte AUTS, base64 */
#define T_AUTS  "EBESExQVFhcYGRobHB0="

static int resync(const char *nonce, const char *auts, str *out)
{
	str n = {(char *)nonce, strlen(nonce)};
	str a = {(char *)auts, strlen(auts)};

	return aka_test_build_resync(&n, &a, out);
}

static void test_aka_build_resync(void)
{
	str out = STR_NULL;

	ok(resync(T_NONCE, T_AUTS, &out) == 0 && out.len == 30
		&& out.s[0] == 0x00 && out.s[15] == 0x0f
		&& out.s[16] == 0x10 && out.s[29] == 0x1d, "RAND + AUTS");

	ok(resync(T_NONCE, "EBESExQV", &out) < 0, "short AUTS is rejected");

	/* an AUTS that decodes to more than 14 bytes must not be accepted */
	ok(resync(T_NONCE, "EBESExQVFhcYGRobHB0e", &out) < 0,
		"15-byte AUTS is rejected");
	ok(resync(T_NONCE, "EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIz",
		&out) < 0, "overlong AUTS is rejected");

	/* trailing data after a valid AUTS is dropped */
	ok(resync(T_NONCE, T_AUTS "ICEiIyQl", &out) == 0 && out.len == 30
		&& out.s[16] == 0x10 && out.s[29] == 0x1d, "AUTS tail is dropped");
}

void mod_tests(void)
{
	test_aka_build_resync();
}
