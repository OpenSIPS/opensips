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
 * nats_validate_publish_subject() contract test.
 *
 * History: the validator briefly carried a per-thread (pointer, length,
 * result) cache to skip re-scanning identical script-supplied subject
 * literals.  That cache was a security hole: OpenSIPS reuses pkg and
 * static str buffers at the same address across script invocations, so a
 * buffer that once held a valid subject could be refilled with
 * same-length attacker-influenced SIP data containing CRLF / wildcards /
 * spaces and be served a stale "valid" verdict — letting control bytes
 * reach the line-oriented NATS wire protocol (protocol injection via
 * "PUB <subject>\r\n").  The cache was removed; this test pins the
 * contract so it cannot come back.
 *
 * BDD contract asserted here:
 *   GIVEN any buffer, WHEN its contents change between calls — even at
 *   the same address with the same length — THEN the validator returns
 *   the verdict for the *current bytes*, never a remembered one.
 *
 * Plus the original correctness assertions: repeated validation,
 * alternation between subjects, prefix lengths, and NULL/zero-length.
 *
 * Build:
 *   gcc -g -O0 -fsanitize=address -Wall -I.. \
 *       -o test_validate_subject_cache test_validate_subject_cache.c \
 *       ../nats_validate.o
 */

#include <tap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nats_ut.h"

#include "../nats_validate.h"

#define EXPECT(want, label) cmp_ok(got, "==", (want), "%s", (label))

void nats_ut_validate_subject_cache(void)
{
	const char *good = "call.123.event";
	const char *bad  = "call..bad";
	int got;
	int i;

	/* Repeated validation of valid subject must always return 0. */
	for (i = 0; i < 5; i++) {
		got = nats_validate_publish_subject(good, (int)strlen(good));
		EXPECT(0, "valid subject repeated");
	}

	/* Repeated validation of invalid subject must always return -1. */
	for (i = 0; i < 5; i++) {
		got = nats_validate_publish_subject(bad, (int)strlen(bad));
		EXPECT(-1, "invalid subject repeated");
	}

	/* Alternating between two subjects must produce the correct result
	 * for the new input each time. */
	for (i = 0; i < 3; i++) {
		got = nats_validate_publish_subject(good, (int)strlen(good));
		EXPECT(0, "alternation: valid arm");
		got = nats_validate_publish_subject(bad, (int)strlen(bad));
		EXPECT(-1, "alternation: invalid arm");
	}

	/* Same buffer pointer, different length: the prefix has a different
	 * validation outcome and must be evaluated on its own. */
	got = nats_validate_publish_subject(good, (int)strlen(good));
	EXPECT(0, "full-length good baseline");
	got = nats_validate_publish_subject(good, 4); /* "call" — valid token */
	EXPECT(0, "prefix 'call' (len=4) validates as valid");
	got = nats_validate_publish_subject(good, 5); /* "call." — invalid */
	EXPECT(-1, "prefix 'call.' (len=5) validates as trailing-dot");

	/* NULL after a valid hit must not produce a stale pass. */
	got = nats_validate_publish_subject(good, (int)strlen(good));
	EXPECT(0, "valid baseline before NULL");
	got = nats_validate_publish_subject(NULL, 5);
	EXPECT(-1, "NULL after valid hit rejects");

	/* Zero-length after a valid hit. */
	got = nats_validate_publish_subject("ignored", 0);
	EXPECT(-1, "len<=0 after valid hit rejects");

	/*
	 * SECURITY — the core regression this file guards.
	 *
	 * GIVEN a single stack buffer (one stable address),
	 * WHEN its contents are rewritten in place with the same length,
	 * THEN every call must reflect the *current* bytes.
	 *
	 * A pointer-identity cache would answer from the first verdict and
	 * wave a CRLF-injection subject straight onto the wire.
	 */
	{
		char reuse[16];

		/* Benign content, same length (13) as the payloads below. */
		memcpy(reuse, "call.ok.evttt", 13);
		got = nats_validate_publish_subject(reuse, 13);
		EXPECT(0, "in-place buffer: benign content validates");

		/* Refill the SAME address with same-length CRLF-injection bytes. */
		memcpy(reuse, "x\r\nPUB inj 0\r", 13);
		got = nats_validate_publish_subject(reuse, 13);
		EXPECT(-1, "in-place buffer: CRLF injection re-scanned and rejected");

		/* Whitespace-injection (tab + space) at the same address. */
		memcpy(reuse, "ok\tbad subj42", 13);
		got = nats_validate_publish_subject(reuse, 13);
		EXPECT(-1, "in-place buffer: whitespace payload rejected");

		/* Wildcard-injection at the same address. */
		memcpy(reuse, "subj.>.inject", 13);
		got = nats_validate_publish_subject(reuse, 13);
		EXPECT(-1, "in-place buffer: wildcard payload rejected");

		/* Benign again at the same address must pass — proves the prior
		 * rejection was not itself cached into a stale -1. */
		memcpy(reuse, "good.clean.ev", 13);
		got = nats_validate_publish_subject(reuse, 13);
		EXPECT(0, "in-place buffer: benign after malicious validates");
	}

}
