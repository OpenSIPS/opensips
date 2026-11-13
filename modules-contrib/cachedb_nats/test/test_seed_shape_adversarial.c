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
 * Regression lock: the seedless first
 * insert reuses the SAME cdbn_build_seed_doc output as the old write-the-seed
 * flow, now purely as the in-memory merge base.  If the builder's
 * serialization drifted, a first-insert row would silently differ from what
 * every pre-D2 deployment stored -- so its shape is locked here byte-for-byte
 * against golden strings, over adversarial filter values (the house list:
 * backslashes, quotes, control chars/NUL-adjacent, empty, boundary-length).
 *
 * This is a golden-output LOCK for behavior that must NOT change with D2
 * (no _CURRENT arm: there is no old-vs-new here, only drift detection).
 *
 * On the real cdbn_build_seed_doc (its carried copy and json_escape copy
 * are gone).  Added: escapes in the field name, and a value that ends at
 * vlen while its buffer goes on.
 */

#include <tap.h>
#include <stdio.h>
#include <string.h>

#include "../../../mem/mem.h"
#include "../cachedb_nats_json_internal.h"

#include "cn_ut.h"

static void lock_n(const char *label, const char *field, int flen,
	const char *val, int vlen, const char *golden)
{
	int len = 0;
	char *out = cdbn_build_seed_doc(field, flen, val, vlen, &len);

	ok(out && strcmp(out, golden) == 0 && len == (int)strlen(golden),
		"seed_shape_adversarial: %s (got len %d, golden len %d)",
		label, out ? len : -1, (int)strlen(golden));
	if (out)
		pkg_free(out);
}

static void lock(const char *label, const char *field, const char *val,
	const char *golden)
{
	lock_n(label, field, field ? (int)strlen(field) : 0,
		val, val ? (int)strlen(val) : 0, golden);
}

void cn_ut_seed_shape_adversarial(void)
{
	diag("merge-base seed shape is locked (golden):");

	lock("plain AoR", "aor", "alice@example.com",
	     "{\"aor\":\"alice@example.com\"}");
	lock("backslash in value", "aor", "do\\main",
	     "{\"aor\":\"do\\\\main\"}");
	lock("quote in value", "aor", "ev\"il",
	     "{\"aor\":\"ev\\\"il\"}");
	lock("both, adjacent", "aor", "\\\"",
	     "{\"aor\":\"\\\\\\\"\"}");
	lock("tab + newline control chars", "aor", "a\tb\nc",
	     "{\"aor\":\"a\\tb\\nc\"}");
	lock("0x01 control char (uXXXX path)", "aor", "a\x01" "b",
	     "{\"aor\":\"a\\u0001b\"}");
	lock("empty value", "aor", "",
	     "{\"aor\":\"\"}");
	lock("empty field -> empty object", NULL, "whatever",
	     "{}");

	/* boundary-length AoR: 255 'a's (the practical AoR ceiling) survives
	 * without truncation and round-trips its exact length. */
	{
		char big[256], golden[300];
		int len = 0;
		char *out;
		memset(big, 'a', 255); big[255] = '\0';
		snprintf(golden, sizeof(golden), "{\"aor\":\"%s\"}", big);
		out = cdbn_build_seed_doc("aor", 3, big, 255, &len);
		ok(out && strcmp(out, golden) == 0 && len == 255 + 10,
			"seed_shape_adversarial: 255-char AoR round-trips (len %d)", len);
		if (out)
			pkg_free(out);
	}

	/* NUL handling note: an embedded NUL never reaches the builder -- the
	 * update path rejects it earlier (cdbn_dict_has_nul_field,
	 * locked by test_update_nul_poison).  Locked here: a NUL-terminated
	 * prefix is serialized as-is, not silently extended. */
	lock("value stops at NUL (upstream guard owns rejection)", "aor", "ab",
	     "{\"aor\":\"ab\"}");

	lock("escapes in the field name", "a\"b\\c", "v",
	     "{\"a\\\"b\\\\c\":\"v\"}");
	lock("0x1f, the last control char", "aor", "\x1f",
	     "{\"aor\":\"\\u001f\"}");
	lock_n("value ends at vlen, not at the NUL", "aor", 3, "abcdef", 2,
	     "{\"aor\":\"ab\"}");
	lock_n("field ends at flen", "aorXX", 3, "v", 1,
	     "{\"aor\":\"v\"}");
	lock_n("zero flen -> empty object", "aor", 0, "v", 1, "{}");
}
