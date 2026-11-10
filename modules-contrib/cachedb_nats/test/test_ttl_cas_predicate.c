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
 * /: marker-aware CAS
 * predicate for the raw publish.
 *
 *   - kvStore_Get returns an ENTRY (any value_len, including a 0-length
 *     server-side delete marker) -> ExpectLastSubjectSeq = kvEntry_Revision.
 *     An empty-value entry must NOT be treated as "absent".
 *   - kvStore_Get returns NOT_FOUND but the subject still has a head sequence
 *     (a DEL/PURGE marker that kvStore_Get filters out) -> ExpectLastSubjectSeq
 *     = head_seq, NOT ExpectNoMessage (the server rejects ExpectNoMessage over a
 *     marker -> 10071 lockout).
 *   - genuinely empty subject (NOT_FOUND, no head) -> ExpectNoMessage.
 *
 * necessary but not sufficient: this tests predicate SELECTION given a
 * fabricated entry/head; the authoritative "re-REGISTER after a real expiry
 * succeeds first-attempt" is the TTL e2e.
 *
 *                               absent => ExpectNoMessage => RED.
 *   gcc ...                  -> the FIXED marker-aware predicate => GREEN.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_ttl_cas_predicate test_ttl_cas_predicate.c
 */
#include <tap.h>
#include <stdio.h>
#include <stdint.h>
#include "../cachedb_nats_expiry.h"
#include "../cachedb_nats_json.h"

#include "cn_ut.h"



#define CHECK(cond, msg) do { if (!(cond)) { fail("ttl_cas_predicate: %s", msg); } \
	else pass("ttl_cas_predicate: %s", msg); } while (0)

void cn_ut_ttl_cas_predicate(void)
{
	uint64_t seq;

	diag("a non-empty entry => ExpectLastSubjectSeq=rev:");
	CHECK(cdbn_ttl_cas_predicate(1, 50, 7, 0, &seq) == TTL_CAS_LAST_SEQ && seq == 7,
	      "non-empty entry => LAST_SEQ at rev 7");

	diag("an EMPTY-value entry (marker) => LAST_SEQ, not NoMessage:");
	CHECK(cdbn_ttl_cas_predicate(1, 0, 7, 0, &seq) == TTL_CAS_LAST_SEQ && seq == 7,
	      "empty-value entry => LAST_SEQ at rev 7 (NOT ExpectNoMessage)");

	diag("NOT_FOUND with a head marker => LAST_SEQ at head:");
	CHECK(cdbn_ttl_cas_predicate(0, 0, 0, 9, &seq) == TTL_CAS_LAST_SEQ && seq == 9,
	      "NOT_FOUND + head seq 9 => LAST_SEQ at 9 (not ExpectNoMessage)");

	diag("genuinely empty subject => ExpectNoMessage:");
	CHECK(cdbn_ttl_cas_predicate(0, 0, 0, 0, &seq) == TTL_CAS_NO_MESSAGE && seq == 0,
	      "NOT_FOUND + no head => ExpectNoMessage, seq 0");

	diag("adversarial: rev/head at boundary values:");
	CHECK(cdbn_ttl_cas_predicate(1, 0, UINT64_MAX, 0, &seq) == TTL_CAS_LAST_SEQ && seq == UINT64_MAX,
	      "entry rev UINT64_MAX preserved");
	CHECK(cdbn_ttl_cas_predicate(1, 0, 1, 0, &seq) == TTL_CAS_LAST_SEQ && seq == 1,
	      "entry rev 1 (lowest real) => LAST_SEQ");
	CHECK(cdbn_ttl_cas_predicate(0, 0, 0, 1, &seq) == TTL_CAS_LAST_SEQ && seq == 1,
	      "marker at head seq 1 (lowest real) => LAST_SEQ, not NO_MESSAGE");

}
