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
 * Value-size / payload bound.
 *
 * All contacts of an AoR live in ONE KV value; NATS caps message size
 * (max_payload, default 1 MiB; a stream's max_msg_size may be lower).  SQL /
 * Cassandra store one row per contact and have no such cliff.  cachedb_nats MUST
 * detect an oversize merged value BEFORE the CAS write and fail the single
 * offending contact's save (return error) — never corrupt or silently truncate
 * the row, and leave the existing bindings intact.  (max_contacts is a separate
 * usrloc responsibility,; this is the independent value-size guard.)
 *
 * cdbn_value_size_ok(len, max): max <= 0 means "unbounded" (knob disabled); else the
 * serialized value must be <= max bytes.  The check runs on the FINAL merged doc
 * just before kvStore_Update, so an over-limit write fails fatally (not a CAS
 * retry) with the previous revision untouched.
 *
 * On the real cdbn_value_size_ok (the SIZE_CURRENT no-guard model is gone).
 *
 * Rule 6: the AUTHORITATIVE proof is the Tier-2 e2e that registers contacts to
 * the limit and asserts a clean bounded failure (no crash / silent truncation).
 */
#include <tap.h>
#include "../cachedb_nats_json_internal.h"

#include "cn_ut.h"

#define CHECK(cond, msg) do { if (!(cond)) { fail("oversize_row: %s", msg); } \
	else pass("oversize_row: %s", msg); } while (0)

void cn_ut_oversize_row(void)
{
	diag("within bound writes, over bound is rejected:");
	CHECK(cdbn_value_size_ok(100, 1048576) == 1, "100 B <= 1 MiB => ok");
	CHECK(cdbn_value_size_ok(1048576, 1048576) == 1, "exactly at limit => ok (<=)");
	CHECK(cdbn_value_size_ok(1048577, 1048576) == 0, "one over the limit => rejected");
	CHECK(cdbn_value_size_ok(5000000, 1048576) == 0, "5 MB value => rejected (would hit max_payload)");

	diag("the knob disabled (max<=0) means unbounded:");
	CHECK(cdbn_value_size_ok(5000000, 0) == 1, "max==0 => unbounded (no guard)");
	CHECK(cdbn_value_size_ok(5000000, -1) == 1, "max<0 => unbounded");

	diag("small / boundary / defensive:");
	CHECK(cdbn_value_size_ok(0, 1048576) == 1, "empty value => ok");
	CHECK(cdbn_value_size_ok(1, 1) == 1, "len==max==1 => ok");
	CHECK(cdbn_value_size_ok(2, 1) == 0, "2 > 1 => rejected");
	CHECK(cdbn_value_size_ok(0, 0) == 1, "0 len, unbounded => ok");
	CHECK(cdbn_value_size_ok(2147483647, 2147483646) == 0, "INT_MAX vs INT_MAX-1 => rejected");
	CHECK(cdbn_value_size_ok(2147483647, 2147483647) == 1, "INT_MAX at an INT_MAX limit => ok");
}
