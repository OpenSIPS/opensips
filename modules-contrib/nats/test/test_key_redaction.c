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
 * Regression test: modules-contrib/nats/nats_redact_key() must scrub AoR-bearing
 * KV row keys before they are written to logs.  usrloc row keys encode
 * the AoR ("usrloc.alice@example.com"), so error paths that log the
 * raw key (kvStore_Get/Put/Delete failures, CAS errors, purge refusals)
 * leak user-identifying data even when URL credentials are redacted.
 *
 * The helper is declared in modules-contrib/nats/nats_redact.h:
 *
 *   #include "../nats_redact.h"
 *
 * Contract:
 *   - Output is "<ns>.~<fnv1a32>/<len>" where <ns> is the leading
 *     '.'-terminated namespace token, shown ONLY if it is <= 12 chars
 *     of [A-Za-z0-9_-] (a configured prefix like "usrloc", never an
 *     AoR fragment); otherwise "~<fnv1a32>/<len>".
 *   - Same key -> same output (correlation); the AoR text itself never
 *     appears in the output.
 *   - NULL key -> "(null)"; empty key -> "(empty)".
 *   - Always NUL-terminates @out unless out_sz == 0; never overflows.
 *
 * Build:
 *   gcc -g -O0 -fsanitize=address -Wall -o test_key_redaction \
 *       test_key_redaction.c ../nats_redact.o
 */

#include <tap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nats_ut.h"

void nats_redact_key(const char *key, char *out, size_t out_sz);

#define ASSERT(cond, label) ok((cond), "%s", (label))

void nats_ut_key_redaction(void)
{
	char a[64], b[64];

	/* namespace prefix survives, AoR does not */
	nats_redact_key("usrloc.alice@example.com", a, sizeof(a));
	ASSERT(strncmp(a, "usrloc.~", 8) == 0, "safe namespace token kept");
	ASSERT(strstr(a, "alice") == NULL, "user part absent from output");
	ASSERT(strstr(a, "example") == NULL, "domain part absent from output");
	ASSERT(strstr(a, "/24") != NULL, "total key length appended");

	/* correlation: same key -> same output, different key -> different */
	nats_redact_key("usrloc.alice@example.com", b, sizeof(b));
	ASSERT(strcmp(a, b) == 0, "same key redacts identically");
	nats_redact_key("usrloc.bob@example.com", b, sizeof(b));
	ASSERT(strcmp(a, b) != 0, "different key redacts differently");

	/* a key whose first token is NOT a safe namespace must be fully
	 * hashed: "alice@example.com" has its first '.' inside the domain,
	 * so a naive prefix-until-dot would leak "alice@example." */
	nats_redact_key("alice@example.com", a, sizeof(a));
	ASSERT(a[0] == '~', "unsafe first token: hash-only form");
	ASSERT(strstr(a, "alice") == NULL && strstr(a, "example") == NULL,
		"unsafe first token leaks nothing");

	/* no dot at all */
	nats_redact_key("abcdef", a, sizeof(a));
	ASSERT(a[0] == '~' && strstr(a, "/6") != NULL, "dotless key: hash-only");

	/* first token too long (> 12) is not shown even if clean */
	nats_redact_key("aaaaaaaaaaaaaaaa.x", a, sizeof(a));
	ASSERT(a[0] == '~', "overlong first token: hash-only");

	/* adversarial: control char / backslash / '=' escape in first token */
	nats_redact_key("usr\x01loc.x", a, sizeof(a));
	ASSERT(a[0] == '~', "control char in token: hash-only");
	nats_redact_key("al\\ice.x", a, sizeof(a));
	ASSERT(a[0] == '~', "backslash in token: hash-only");
	nats_redact_key("us=65r.x", a, sizeof(a));
	ASSERT(a[0] == '~', "escape marker in token: hash-only");

	/* NULL / empty */
	nats_redact_key(NULL, a, sizeof(a));
	ASSERT(strcmp(a, "(null)") == 0, "NULL key");
	nats_redact_key("", a, sizeof(a));
	ASSERT(strcmp(a, "(empty)") == 0, "empty key");

	/* embedded NUL: C-string semantics, hash covers up to the NUL */
	nats_redact_key("a\0b", a, sizeof(a));
	nats_redact_key("a", b, sizeof(b));
	ASSERT(strcmp(a, b) == 0, "embedded NUL truncates as C string");

	/* long key, small buffers: never overflow, always terminated */
	{
		char big[2049];
		memset(big, 'k', sizeof(big) - 1);
		big[0] = 'u'; big[6] = '.';	/* clean-ish shape */
		big[sizeof(big) - 1] = '\0';
		nats_redact_key(big, a, sizeof(a));
		ASSERT(strlen(a) < sizeof(a), "2 KB key fits redacted");

		char tiny1[1], tiny2[2], tiny8[8];
		nats_redact_key("usrloc.alice@example.com", tiny1, sizeof(tiny1));
		ASSERT(tiny1[0] == '\0', "out_sz=1 yields empty string");
		nats_redact_key("usrloc.alice@example.com", tiny2, sizeof(tiny2));
		ASSERT(strlen(tiny2) <= 1, "out_sz=2 truncates safely");
		nats_redact_key("usrloc.alice@example.com", tiny8, sizeof(tiny8));
		ASSERT(strlen(tiny8) <= 7 && strstr(tiny8, "alice") == NULL,
			"out_sz=8 truncates safely, no leak");
		/* out_sz == 0 must not write at all (ASan would catch it) */
		nats_redact_key("usrloc.x", tiny1, 0);
	}

}
