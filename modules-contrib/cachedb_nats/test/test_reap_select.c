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
 * The reaper's row-selection and per-row
 * action decisions (the broker-less core of the reaper loop).
 *
 *   cdbn_reap_row_due(row_exp, now, grace): a row is a reap candidate iff
 *     row_exp != 0 && row_exp + grace <= now.  row_exp == 0 is PERMANENT and is
 *     NEVER due (a permanent contact must never be reaped); the +grace (= S, max
 *     skew) margin means the reaper never purges within S of an expiry.
 *
 *   cdbn_reap_row_action(n_live_survivors): after the reaper prunes the expired
 *     contacts of a due row, > 0 survivors => a CAS survivor-write through
 *     nats_kv_put_row (which RE-asserts the per-message TTL,, and
 *     preserves aorhash/schema_version); 0 survivors => a CAS-guarded
 *     publish-delete (never a revision-blind kvStore_Delete).
 *
 *                            row_exp==0 (would purge permanent contacts) => RED.
 *   gcc ...               -> the FIXED decisions => GREEN.
 *
 * Rule 6: the AUTHORITATIVE proofs are the reaper e2e (survivor re-asserts TTL;
 * a concurrent renew makes the CAS delete fail and the contact survives).
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_reap_select test_reap_select.c
 */
#include <tap.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include "../cachedb_nats_expiry.h"
#include "../cachedb_nats_json.h"

#include "cn_ut.h"



#define CHECK(cond, msg) do { if (!(cond)) { fail("reap_select: %s", msg); } \
	else pass("reap_select: %s", msg); } while (0)

void cn_ut_reap_select(void)
{
	const time_t now = 1000;
	const int S = 5;

	diag("row due selection (now=1000, S=5):");
	CHECK(cdbn_reap_row_due(900, now, S) == 1, "row_exp 900 +5 <= 1000 => due");
	CHECK(cdbn_reap_row_due(995, now, S) == 1, "row_exp 995 +5 == 1000 boundary => due");
	CHECK(cdbn_reap_row_due(996, now, S) == 0, "row_exp 996 +5 > 1000 => NOT due (within skew)");
	CHECK(cdbn_reap_row_due(2000, now, S) == 0, "future row_exp => not due");
	CHECK(cdbn_reap_row_due(0, now, S) == 0, "row_exp==0 (permanent) => NEVER due");
	CHECK(cdbn_reap_row_due(0, 9999999999LL, S) == 0, "permanent still not due far in the future");
	CHECK(cdbn_reap_row_due(5000000000LL, now, S) == 0, "post-2038 future row_exp => not due");

	diag("per-row action after pruning:");
	CHECK(cdbn_reap_row_action(3) == REAP_WRITE_SURVIVORS, "3 survivors => CAS survivor-write (re-assert TTL)");
	CHECK(cdbn_reap_row_action(1) == REAP_WRITE_SURVIVORS, "1 survivor => survivor-write");
	CHECK(cdbn_reap_row_action(0) == REAP_DELETE_EMPTY, "0 survivors => CAS-guarded publish-delete");

}
