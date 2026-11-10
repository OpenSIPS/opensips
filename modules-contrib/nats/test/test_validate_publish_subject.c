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
 * Regression test: modules-contrib/nats/nats_validate_publish_subject.
 *
 * Background: event_nats's publish paths (nats_evi_raise and
 * w_nats_publish) currently copy the script-supplied subject directly
 * into the publish call with only a length-bound check.  A subject
 * containing NATS wildcards ('>', '*'), embedded NUL, control chars,
 * leading/trailing/consecutive dots, or empty tokens routes the
 * publish to unintended subscribers or breaks the wire format.
 *
 * Contract for nats_validate_publish_subject(s, len):
 *   - Returns 0 on valid; -1 on invalid.
 *   - Rejects: NULL, len <= 0, embedded NUL, control chars (< 0x20,
 *     0x7f), whitespace (' ', '\t'), wildcards ('>', '*'), leading
 *     dot, trailing dot, consecutive dots ("..").
 *   - Accepts: any other printable byte sequence with valid token
 *     structure (e.g. "call.123.event").
 *
 * Build:
 *   gcc -g -O0 -fsanitize=address -Wall -I.. -o test_validate_publish_subject \
 *       test_validate_publish_subject.c ../nats_validate.o
 */

#include <tap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nats_ut.h"

#include "../nats_validate.h"

#define EXPECT(want_rc, s, label) do { \
	/* volatile launder: the NULL-argument arms are DELIBERATE
	 * adversarial inputs; without it gcc's -Wnonnull rejects the
	 * compile-time NULL under -O2 (fires on gcc 13, not 14) */ \
	const char *volatile _s = (s); \
	cmp_ok(nats_validate_publish_subject(_s, _s ? (int)strlen(_s) : 0), \
		"==", (want_rc), "%s", (label)); \
} while (0)

#define EXPECT_LEN(want_rc, s, n, label) \
	cmp_ok(nats_validate_publish_subject((s), (n)), "==", (want_rc), "%s", (label))

void nats_ut_validate_publish_subject(void)
{
	/* --- valid cases --- */
	EXPECT(0,  "call.123.event", "single dotted subject");
	EXPECT(0,  "abc",            "single token");
	EXPECT(0,  "a.b.c.d",        "multi-token");
	EXPECT(0,  "_._-_.~",        "underscore/dash/tilde");
	EXPECT(0,  "ABC.123.xYz",    "mixed case + digits");

	/* --- empty / NULL --- */
	EXPECT(-1, NULL, "NULL pointer");
	EXPECT_LEN(-1, "", 0, "empty");
	EXPECT_LEN(-1, "x", 0, "len=0 with nonempty buf");

	/* --- wildcards (publish must reject) --- */
	EXPECT(-1, ">",          "single tail wildcard");
	EXPECT(-1, "*",          "single token wildcard");
	EXPECT(-1, "call.>",     "trailing tail wildcard");
	EXPECT(-1, "call.*",     "trailing token wildcard");
	EXPECT(-1, "a.*.b",      "embedded token wildcard");
	EXPECT(-1, "a.>.b",      "embedded tail wildcard (also illegal in pubsub)");

	/* --- whitespace / control --- */
	EXPECT(-1, "a b",        "space");
	EXPECT(-1, "a\tb",       "tab");
	EXPECT(-1, "a\nb",       "newline");
	EXPECT_LEN(-1, "a\0b", 3, "embedded NUL");
	EXPECT_LEN(-1, "a\x7f""b", 3, "DEL");

	/* --- dot structure --- */
	EXPECT(-1, ".a",         "leading dot");
	EXPECT(-1, "a.",         "trailing dot");
	EXPECT(-1, "..",         "double dot only");
	EXPECT(-1, "a..b",       "consecutive dots");
	EXPECT(-1, "a...b",      "three consecutive dots");
	EXPECT(-1, ".",          "single dot");

	/* --- pathological --- */
	{
		char big[513];
		memset(big, 'a', sizeof(big) - 1);
		big[sizeof(big) - 1] = '\0';
		/* validator is content-only; length bounds are caller's job */
		EXPECT_LEN(0, big, (int)sizeof(big) - 1,
			"512-char single token still valid");
	}

}
