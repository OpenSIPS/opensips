/*
 * Copyright (C) 2026 OpenSIPS Solutions
 * Copyright (C) 2026 Norm Brandinger <n.brandinger@gmail.com>
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * cdbn_kv_encode_key() (cachedb_nats_json_ser.c): NATS-KV subject tokens
 * reject bytes outside [-./_=a-zA-Z0-9], and usrloc AoRs routinely carry
 * '@', so every other byte becomes "=HH"; '=' itself becomes "=3D" so the
 * encoding stays unambiguous.  Golden vectors on the real encoder.
 * Replaces tests/test_kv_key_encode.c, whose carried copy had drifted: it
 * still kept '\\' literal, which production now escapes (=5C).
 */

#include <tap.h>
#include <string.h>

#include "../../../mem/mem.h"
#include "../cachedb_nats_json_internal.h"

#include "cn_ut.h"

/* the bytes a NATS-KV key token may hold after encoding */
static int kv_token_byte(unsigned char c)
{
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') || c == '-' || c == '_' || c == '/' ||
		c == '.' || c == '=';
}

static void check(const char *label, const char *in, int in_len,
		const char *want)
{
	int n = -1, safe = 1, i;
	char *out = cdbn_kv_encode_key(in, in_len, &n);

	for (i = 0; out && i < n; i++)
		if (!kv_token_byte((unsigned char)out[i]))
			safe = 0;
	ok(out && n == (int)strlen(want) && !strcmp(out, want) && safe,
		"kv_key_encode: %s -> %s (got \"%s\", len %d, kv-safe %d)",
		label, want, out ? out : "<NULL>", n, safe);
	if (out)
		pkg_free(out);
}

void cn_ut_kv_key_encode(void)
{
	const char utf8[] = { 'a', (char)0xC3, (char)0xA9, 'b' };
	const char nul[] = { 'a', '\0', 'b' };

	check("A: SIP AoR '@'", "alice@example.com", 17, "alice=40example.com");
	check("B: alphanumeric passthrough", "alice", 5, "alice");
	check("C: '.' and '_' pass through", "alice_at_example.com", 20,
		"alice_at_example.com");
	check("D: ':' and '@' encoded", "user:pw@host", 12, "user=3Apw=40host");
	check("E: literal '='", "a=b", 3, "a=3Db");
	check("F: wildcards", "a*b>c", 5, "a=2Ab=3Ec");
	check("G: UTF-8 bytes", utf8, 4, "a=C3=A9b");
	check("H: empty input", "", 0, "");
	check("I: backslash escaped", "a\\b", 3, "a=5Cb");
	check("J: embedded NUL", nul, 3, "a=00b");
	check("K: '-' and '/' pass through", "a-b/c", 5, "a-b/c");
	check("L: space and '%'", "a b%", 4, "a=20b=25");
}
