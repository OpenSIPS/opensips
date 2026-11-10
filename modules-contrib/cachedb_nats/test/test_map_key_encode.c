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
 * Regression test: the map subject encoder.  Map ops emulate
 * hash-map semantics on flat NATS KV by composing a subject key
 *   enc(map_key) . enc(field)
 * where '.' is the structural separator.  To get exact server-side prefix
 * filtering ("enc(map_key).>") without cross-map aliasing, AND to let users
 * put any byte (including '.', ':', '=') in a map key/field, each component
 * is hex-escaped: every byte outside the NATS-subject-safe set
 * [0-9A-Za-z-_/\] is written as "=HH".  Crucially '.' and '=' are NOT in the
 * safe set, so an encoded component never contains a raw '.' (it is always a
 * single subject token) and the escape is unambiguous.
 *
 * This mirrors the proven =HH scheme of the PK key encoder
 * (test_kv_key_encode), but additionally escapes '.' (the map separator).
 *
 * On the real (static) nats_map_encode / nats_map_decode through the
 * UNIT_TESTS wrappers cn_ut_map_encode / _decode (native.c); the carried
 * copies and the source greps (definitions exist, separator is '.') are
 * gone -- map_ops round-trips through the separator.  It proves
 * round-trip on the full byte range + the tricky edge cases (empty,
 * backslash, NUL, all-reserved, '=', high bytes), plus the structural
 * invariant (encoded output contains no raw '.'), then asserts the
 * production wiring.
 */

#include <tap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "cn_ut.h"

#define ASSERT(cond, msg) do { \
	if (!(cond)) { fail("map_key_encode: %s", msg); } \
	else         { pass("map_key_encode: %s", msg);            } \
} while (0)

int cn_ut_map_encode(const char *in, int in_len, char *out, int out_size);
int cn_ut_map_decode(const char *in, int in_len, char *out, int out_size);
#define nats_map_encode cn_ut_map_encode
#define nats_map_decode cn_ut_map_decode

/* ─── tests ────────────────────────────────────────────────────── */

static int has_raw_dot(const char *s, int n)
{
	int i;
	for (i = 0; i < n; i++) if (s[i] == '.') return 1;
	return 0;
}

static void roundtrip(const char *in, int in_len, const char *label)
{
	/* worst case is 3x expansion (every byte escaped) + NUL */
	char enc[1024], dec[512];
	int elen = nats_map_encode(in, in_len, enc, sizeof(enc));
	int dlen;
	char m[128];

	snprintf(m, sizeof(m), "%s: encode ok", label);
	ASSERT(elen >= 0, m);
	if (elen < 0) return;

	/* structural invariant: encoded component is one subject token */
	snprintf(m, sizeof(m), "%s: encoded has no raw '.'", label);
	ASSERT(!has_raw_dot(enc, elen), m);

	dlen = nats_map_decode(enc, elen, dec, sizeof(dec));
	snprintf(m, sizeof(m), "%s: decode ok", label);
	ASSERT(dlen == in_len, m);
	snprintf(m, sizeof(m), "%s: round-trips byte-exact", label);
	ASSERT(dlen == in_len && memcmp(dec, in, in_len) == 0, m);
}

void cn_ut_map_key_encode(void)
{
	/* ---- round-trip the tricky cases --------------------------- */
	roundtrip("", 0, "empty");
	roundtrip("plainfield", 10, "plain");
	roundtrip("a.b.c", 5, "dots (separator char in data)");
	roundtrip("sub:field", 9, "colon (legacy sep in data)");
	roundtrip("100%=done", 9, "equals + percent");
	roundtrip("a\\b/c", 5, "backslash + slash (both safe, pass through)");
	roundtrip("user@host.com", 13, "SIP-ish at + dot");
	roundtrip("-_/\\", 4, "all-safe punctuation");
	roundtrip("*>? \t", 5, "wildcards + whitespace (must be escaped, not raw)");
	{
		/* embedded NUL + full high-byte range */
		char buf[3] = { 'a', '\0', 'z' };
		roundtrip(buf, 3, "embedded NUL");
	}
	{
		char all[256];
		int i;
		for (i = 0; i < 256; i++) all[i] = (char)i;
		roundtrip(all, 256, "every byte 0x00..0xff");
	}

	/* ---- structural: wildcards/whitespace never survive raw ----- */
	{
		char enc[64];
		int n = nats_map_encode("a*b>c d.e", 9, enc, sizeof(enc));
		ASSERT(n > 0, "mixed reserved encodes");
		ASSERT(!strchr(enc, '*') && !strchr(enc, '>') &&
		       !strchr(enc, ' ') && !strchr(enc, '.'),
			"no raw wildcard/space/dot in encoded subject token");
	}

	/* ---- decode rejects malformed escapes ----------------------- */
	{
		char out[16];
		ASSERT(nats_map_decode("=", 1, out, sizeof(out)) < 0,
			"truncated escape '=' rejected");
		ASSERT(nats_map_decode("=2", 2, out, sizeof(out)) < 0,
			"truncated escape '=2' rejected");
		ASSERT(nats_map_decode("=2G", 3, out, sizeof(out)) < 0,
			"non-hex escape '=2G' rejected");
		ASSERT(nats_map_decode("=2E", 3, out, sizeof(out)) == 1 && out[0] == '.',
			"valid escape '=2E' decodes to '.'");
	}

	/* ---- overflow guards ---------------------------------------- */
	{
		char tiny[2];
		ASSERT(nats_map_encode("...", 3, tiny, sizeof(tiny)) < 0,
			"encode reports overflow instead of truncating");
	}
}
