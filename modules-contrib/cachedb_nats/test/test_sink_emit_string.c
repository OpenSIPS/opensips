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
 * cdbn_sink_emit_string(): a string field goes into the row document
 * quoted and JSON-escaped, untruncated, without tripping the sink's sticky
 * oom flag.  The original bug passed json_escape() the exact escaped
 * length as out_sz; json_escape reserves a byte for the NUL and rejects an
 * exact fit, so every non-empty string failed and truncated the JSON.
 * On the real sink (cachedb_nats_json_ser.c), golden outputs incl. the
 * house adversarial list and escaped lengths that land exactly on the
 * sink's capacity.
 * Replaces tests/test_sink_emit_string.c: its carried copies, the
 * buggy-form demonstration and the source grep on the esc_len + 1
 * argument are gone (the golden cases fail under the bug).
 */

#include <tap.h>
#include <string.h>

#include "../../../mem/mem.h"
#include "../cachedb_nats_json_internal.h"

#include "cn_ut.h"

static void emit_case(const char *label, const char *in, int n, int cap,
	const char *want)
{
	json_sink_t s;
	char *got = NULL;
	int rc = -2, len = -1, oom = -1;

	if (cdbn_sink_init(&s, cap) == 0) {
		rc = cdbn_sink_emit_string(&s, in, n);
		oom = s.oom;
		got = cdbn_sink_take(&s, &len);
	}
	ok(rc == 0 && !oom && got && len == (int)strlen(want) && !memcmp(got, want, len),
		"sink_emit_string: %s (rc %d, oom %d, len %d want %d)",
		label, rc, oom, len, (int)strlen(want));
	if (got)
		pkg_free(got);
}

void cn_ut_sink_emit_string(void)
{
	static const char tab[] = { 't', '\t', 'x' };
	static const char nul[] = { 'a', '\0', 'b' };
	char big[40];

	emit_case("plain", "hello", 5, 16, "\"hello\"");
	emit_case("quote", "he\"llo", 6, 16, "\"he\\\"llo\"");
	emit_case("tab", tab, 3, 16, "\"t\\tx\"");
	emit_case("empty", "", 0, 16, "\"\"");
	emit_case("backslash", "a\\b", 3, 16, "\"a\\\\b\"");
	emit_case("control 0x01", "\x01", 1, 16, "\"\\u0001\"");
	emit_case("embedded NUL", nul, 3, 16, "\"a\\u0000b\"");
	emit_case("ends at n, not at the NUL", "abcdef", 3, 16, "\"abc\"");

	/* the sink starts at 16 bytes: escaped length + 2 quotes + NUL on
	 * either side of it */
	memset(big, 'x', sizeof big);
	{
		char want[64];
		int n;
		for (n = 12; n <= 15; n++) {
			want[0] = '"';
			memset(want + 1, 'x', n);
			want[n + 1] = '"';
			want[n + 2] = '\0';
			emit_case(n == 13 ? "13 bytes: quotes + NUL fill 16 exactly" :
				"around the initial 16-byte capacity", big, n, 16, want);
		}
	}
	emit_case("escape doubling across the 16-byte capacity",
		"\"\"\"\"\"\"\"", 7, 16, "\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\"");
}
