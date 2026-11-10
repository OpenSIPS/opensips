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
 * Regression test: the four NATS subject/key/name validators
 * (publish subject, subscribe filter, stream/consumer name, KV key) were
 * consolidated into one modules-contrib/nats nats_validate(s, len, mode) with mode flags.
 * This locks in the per-mode rules so the consolidation can't drift:
 *
 *   PUBLISH_SUBJECT  concrete: no wildcards, no leading/trailing/empty tokens
 *   FILTER_SUBJECT   dots + wildcards ('*','>') allowed
 *   STREAM_NAME      single token: no '.', '*', '>', '/', '\'
 *   KV_KEY           the nats.c key alphabet only: letters, digits and
 *                    . _ - / \ =; no leading/trailing dot, no empty token
 * all reject NULL/empty/NUL/control/whitespace.
 *
 * Build:
 *   gcc -g -O0 -fsanitize=address -Wall -I.. -o test_validate_modes \
 *       test_validate_modes.c ../nats_validate.o
 */

#include <tap.h>
#include <stdio.h>
#include <string.h>

#include "nats_ut.h"

#include "../nats_validate.h"

#define V(want, mode, s, label) \
	cmp_ok(nats_validate((s), (s) ? (int)strlen(s) : 0, (mode)), "==", (want), \
		"%s", (label))

void nats_ut_validate_modes(void)
{
	/* common rejections (every mode) */
	nats_validate_mode_t modes[] = { NATS_VALIDATE_PUBLISH_SUBJECT,
		NATS_VALIDATE_FILTER_SUBJECT, NATS_VALIDATE_STREAM_NAME,
		NATS_VALIDATE_KV_KEY };
	int m;
	for (m = 0; m < 4; m++) {
		V(-1, modes[m], "", "empty rejected (all modes)");
		V(-1, modes[m], "a b", "whitespace rejected (all modes)");
		V(-1, modes[m], "a\x01""b", "control rejected (all modes)");
	}

	/* PUBLISH_SUBJECT */
	V(0,  NATS_VALIDATE_PUBLISH_SUBJECT, "call.123.evt", "pub: dotted ok");
	V(-1, NATS_VALIDATE_PUBLISH_SUBJECT, "call.*",       "pub: wildcard rejected");
	V(-1, NATS_VALIDATE_PUBLISH_SUBJECT, "a..b",         "pub: empty token rejected");
	V(-1, NATS_VALIDATE_PUBLISH_SUBJECT, ".a",           "pub: leading dot rejected");
	V(0,  NATS_VALIDATE_PUBLISH_SUBJECT, "a:b",          "pub: ':' allowed");

	/* FILTER_SUBJECT — wildcards + dots allowed */
	V(0,  NATS_VALIDATE_FILTER_SUBJECT, "usrloc.>",      "filter: tail wildcard ok");
	V(0,  NATS_VALIDATE_FILTER_SUBJECT, "a.*.c",         "filter: token wildcard ok");
	V(0,  NATS_VALIDATE_FILTER_SUBJECT, "a..b",          "filter: tolerant of dots");
	V(-1, NATS_VALIDATE_FILTER_SUBJECT, "a b",           "filter: whitespace rejected");

	/* STREAM_NAME — single token */
	V(0,  NATS_VALIDATE_STREAM_NAME, "MY-STREAM_1", "name: alnum/-/_ ok");
	V(-1, NATS_VALIDATE_STREAM_NAME, "a.b",         "name: dot rejected");
	V(-1, NATS_VALIDATE_STREAM_NAME, "a*",          "name: wildcard rejected");
	V(-1, NATS_VALIDATE_STREAM_NAME, "a/b",         "name: slash rejected");
	V(-1, NATS_VALIDATE_STREAM_NAME, "a\\b",        "name: backslash rejected");

	/* KV_KEY — exactly the key alphabet nats.c accepts (kv.c validKey):
	 * anything the module lets through must not fail later inside
	 * kvStore_* with a bare "Invalid Argument". */
	V(0,  NATS_VALIDATE_KV_KEY, "a/b=c",        "kv: slash/equals ok");
	V(0,  NATS_VALIDATE_KV_KEY, "Az09._-/=\\x", "kv: full allowed alphabet ok");
	V(0,  NATS_VALIDATE_KV_KEY, "k",            "kv: single char ok");
	V(0,  NATS_VALIDATE_KV_KEY, "json_alice=40example.com", "kv: encoded usrloc key ok");
	V(0,  NATS_VALIDATE_KV_KEY, "__cdbn_internal", "kv: underscore-prefixed key ok");
	V(-1, NATS_VALIDATE_KV_KEY, "user.1@host",  "kv: '@' rejected (Call-ID/AoR char)");
	V(-1, NATS_VALIDATE_KV_KEY, "+15551234",    "kv: '+' rejected (E.164)");
	V(-1, NATS_VALIDATE_KV_KEY, "a~b",          "kv: '~' rejected");
	V(-1, NATS_VALIDATE_KV_KEY, "a%b",          "kv: '%' rejected");
	V(-1, NATS_VALIDATE_KV_KEY, "a\"b",        "kv: quote rejected");
	V(-1, NATS_VALIDATE_KV_KEY, "caf\xc3\xa9",  "kv: non-ASCII rejected");
	V(-1, NATS_VALIDATE_KV_KEY, "a:b",          "kv: ':' rejected (map sep)");
	V(-1, NATS_VALIDATE_KV_KEY, "a*",           "kv: wildcard rejected");
	V(-1, NATS_VALIDATE_KV_KEY, "a>",           "kv: '>' rejected");
	V(-1, NATS_VALIDATE_KV_KEY, ".a",           "kv: leading dot rejected");
	V(-1, NATS_VALIDATE_KV_KEY, "a.",           "kv: trailing dot rejected");
	V(-1, NATS_VALIDATE_KV_KEY, ".",            "kv: lone dot rejected");
	V(-1, NATS_VALIDATE_KV_KEY, "a..b",         "kv: empty token rejected");
	{
		static const char nul[] = { 'a', '\0', 'b' };
		cmp_ok(nats_validate(nul, 3, NATS_VALIDATE_KV_KEY), "==", -1,
			"kv: embedded NUL rejected");
	}

}
