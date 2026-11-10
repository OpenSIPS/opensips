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
 * Fail-closed on a poison stored value.  A non-empty value that is not a
 * JSON object (null / a bare string / a number / an array / garbage planted
 * by an old node, a co-writer, or an attacker) is a hard integrity error
 * (alarm + poison_values_rejected), never a masked empty result -- that
 * would be a silent deregistration.  An EMPTY value (zero-length /
 * all-whitespace) is a legitimate server-side delete marker: absent.
 *
 * On the real cdbn_value_classify (cachedb_nats_json_rowmeta.c).  Replaces
 * tests/test_poison_value.c (its POISON_CURRENT '{'-gate model and enum
 * mirror are gone).  Added: a leading NUL or vertical tab is not
 * whitespace; the value ends at its length.
 */

#include <tap.h>

#include "../cachedb_nats_json_internal.h"

#include "cn_ut.h"

static const char *cls(int c)
{
	return c == NATS_VAL_EMPTY ? "EMPTY" : c == NATS_VAL_OBJECT ? "OBJECT" : "POISON";
}

#define EXPECT(data, len, want, msg) do { \
	int _g = cdbn_value_classify((data), (len)); \
	ok(_g == (want), "poison_value: %s (got %s want %s)", msg, cls(_g), cls(want)); \
} while (0)
#define EXPECTS(lit, want, msg) EXPECT((lit), (int)(sizeof(lit) - 1), (want), (msg))

void cn_ut_poison_value(void)
{
	diag("empty value == delete marker (absent, NOT poison):");
	EXPECT(NULL, 0, NATS_VAL_EMPTY, "NULL => EMPTY");
	EXPECTS("", NATS_VAL_EMPTY, "zero-length => EMPTY");
	EXPECTS("   ", NATS_VAL_EMPTY, "all-whitespace => EMPTY (marker)");
	EXPECTS("\t\n\r", NATS_VAL_EMPTY, "ws-only => EMPTY");

	diag("a JSON object parses normally:");
	EXPECTS("{}", NATS_VAL_OBJECT, "empty object => OBJECT");
	EXPECTS("{\"contacts\":{\"c1\":{\"expires\":9}}}", NATS_VAL_OBJECT, "real row => OBJECT");
	EXPECTS("  {\"x\":1}", NATS_VAL_OBJECT, "object with leading ws => OBJECT");

	diag("a non-empty non-object is POISON (hard error, not empty):");
	EXPECTS("null", NATS_VAL_POISON, "null => POISON");
	EXPECTS("\"a string\"", NATS_VAL_POISON, "bare string => POISON");
	EXPECTS("42", NATS_VAL_POISON, "bare number => POISON");
	EXPECTS("-1", NATS_VAL_POISON, "negative number => POISON");
	EXPECTS("true", NATS_VAL_POISON, "bool => POISON");
	EXPECTS("[1,2,3]", NATS_VAL_POISON, "array => POISON (not an object)");
	EXPECTS("garbage", NATS_VAL_POISON, "unparseable text => POISON");
	EXPECTS("}{", NATS_VAL_POISON, "starts with '}' => POISON");
	EXPECTS("x", NATS_VAL_POISON, "single non-{ char => POISON");
	EXPECTS("  null", NATS_VAL_POISON, "leading ws then non-object => POISON");
	EXPECT("\0{}", 3, NATS_VAL_POISON, "leading NUL byte => POISON (not whitespace)");
	EXPECTS("\v{}", NATS_VAL_POISON, "vertical tab is not JSON whitespace => POISON");
	EXPECTS("\\{}", NATS_VAL_POISON, "leading backslash => POISON");

	diag("the value ends at its length:");
	EXPECT("   {}", 3, NATS_VAL_EMPTY, "whitespace, then '{' past len => EMPTY");
	EXPECT("{}", 0, NATS_VAL_EMPTY, "len 0 over an object => EMPTY");
	EXPECT("{}", -1, NATS_VAL_EMPTY, "negative len => EMPTY");
}
