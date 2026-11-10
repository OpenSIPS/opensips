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
 * Regression test: cachedb_nats_json.c::_json_set_field had
 * a JSON-injection bug -- field/value bytes were spliced into the
 * output document with hand-coded `"` quoting and no escaping.  An
 * input value containing `"` would close the value early and let the
 * tail bytes inject arbitrary JSON.
 *
 * The fix introduces a static helper `json_escape(in, in_len, out,
 * out_sz)` that writes the escaped form (without surrounding quotes)
 * of an input string and returns the number of bytes written, or -1
 * on output overflow.  The encoder follows RFC 8259 section 7:
 *   - "  -> \"
 *   - \  -> \\
 *   - \b \f \n \r \t -> short forms
 *   - other control bytes (< 0x20) -> \uXXXX
 *   - everything else passes through verbatim (including high bytes)
 *
 * On the real (static) json_escape through the UNIT_TESTS wrapper
 * cn_ut_json_escape_buf (cachedb_nats_json_ser.c); the carried copy is gone.
 */

#include <tap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cn_ut.h"

int cn_ut_json_escape_buf(const char *in, int in_len, char *out, int out_sz);
#define json_escape cn_ut_json_escape_buf

/* ─── tiny JSON validator: parse "..."contents..." and confirm it's
 *     a single well-formed RFC 8259 JSON string ─────────────────── */

static int looks_like_valid_json_string(const char *quoted, int qlen)
{
	int i;
	if (qlen < 2) return 0;
	if (quoted[0] != '"' || quoted[qlen - 1] != '"') return 0;
	for (i = 1; i < qlen - 1; i++) {
		unsigned char c = (unsigned char)quoted[i];
		if (c == '"') return 0;       /* unescaped quote -> invalid */
		if (c == '\\') {
			if (i + 1 >= qlen - 1) return 0;
			char n = quoted[i + 1];
			if (n == '"' || n == '\\' || n == '/' ||
			    n == 'b' || n == 'f' || n == 'n' ||
			    n == 'r' || n == 't') {
				i++;
			} else if (n == 'u') {
				if (i + 5 >= qlen - 1) return 0;
				i += 5;
			} else {
				return 0;
			}
		} else if (c < 0x20) {
			return 0;       /* unescaped control */
		}
	}
	return 1;
}

#define ESCAPED(in, expected, label) do { \
	char buf[256], quoted[260]; \
	int n = json_escape((in), (int)strlen(in), buf, sizeof(buf)); \
	ok(n >= 0 && strcmp(buf, (expected)) == 0 && n == (int)strlen(expected), \
		"json_escape: %s (n=%d)", (label), n); \
	snprintf(quoted, sizeof(quoted), "\"%s\"", n >= 0 ? buf : ""); \
	ok(looks_like_valid_json_string(quoted, (int)strlen(quoted)), \
		"json_escape: %s: the quoted result is a valid JSON string", (label)); \
} while (0)

void cn_ut_json_escape(void)
{
	/* simple */
	ESCAPED("hello",        "hello",        "plain ascii");
	ESCAPED("",             "",             "empty");
	ESCAPED("a/b",          "a/b",          "slash unescaped (allowed)");

	/* dangerous */
	ESCAPED("a\"b",         "a\\\"b",       "double quote");
	ESCAPED("a\\b",         "a\\\\b",       "backslash");
	ESCAPED("a\"b\"c",      "a\\\"b\\\"c",  "two quotes");

	/* injection attempt — value is closed and a key is appended */
	ESCAPED("\",\"injected\":\"yes",
		"\\\",\\\"injected\\\":\\\"yes",
		"injection attempt");

	/* control chars */
	ESCAPED("a\nb",         "a\\nb",        "newline");
	ESCAPED("a\rb",         "a\\rb",        "carriage return");
	ESCAPED("a\tb",         "a\\tb",        "tab");
	ESCAPED("a\bb",         "a\\bb",        "backspace");
	ESCAPED("a\fb",         "a\\fb",        "form feed");
	{
		const char in[] = {'a', 0x01, 'b', 0};
		ESCAPED(in, "a\\u0001b", "control 0x01 -> \\u0001");
	}

	/* high bytes (UTF-8 continuation) pass through */
	{
		const char in[] = {'a', (char)0xC3, (char)0xA9, 'b', 0}; /* "aéb" */
		const char ex[] = {'a', (char)0xC3, (char)0xA9, 'b', 0};
		ESCAPED(in, ex, "UTF-8 é passes through");
	}

	/* overflow */
	{
		char buf[3];
		int n = json_escape("abcdef", 6, buf, sizeof(buf));
		ok(n == -1, "json_escape: overflow returns -1 (n=%d)", n);
	}

	{
		/* a short escape at the boundary: "\n" needs 3 bytes with the NUL */
		char b2[2], b3[3];
		int n2 = json_escape("\n", 1, b2, sizeof b2);
		int n3 = json_escape("\n", 1, b3, sizeof b3);
		ok(n2 == -1 && n3 == 2 && !strcmp(b3, "\\n"),
			"json_escape: short escape at the exact boundary (n2=%d, n3=%d)", n2, n3);
		ok(json_escape("abc", 3, b3, 0) == -1, "json_escape: out_sz 0 refused");
	}

	/* #48: \u00xx escape at the exact buffer boundary must reject, not
	 * truncate-and-corrupt.  "" is 6 chars; with out_sz == 6 it
	 * needs the NUL too, so out_sz must be >= 7 to succeed. */
	{
		const char in[] = {0x01, 0};
		char b6[6], b7[7];
		int n6 = json_escape(in, 1, b6, sizeof(b6));   /* 6: NUL needs 7, too small */
		int n7 = json_escape(in, 1, b7, sizeof(b7));   /* 7: exact fit */
		ok(n6 == -1, "json_escape: \\u escape rejects too-small out_sz=6 (n=%d)", n6);
		ok(n7 == 6 && !strcmp(b7, "\\u0001"), "json_escape: \\u escape exact-fits out_sz=7 (n=%d)", n7);
	}
}
