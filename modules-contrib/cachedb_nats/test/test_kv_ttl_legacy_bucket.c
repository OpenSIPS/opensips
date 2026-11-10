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
 * Migration policy
 * for a PRE-EXISTING bucket whose backing stream already carries a non-zero
 * MaxAge.
 *
 * The guard `cdbn_kv_ttl_guard` (test_kv_ttl_zero_guard.c) refuses a non-zero
 * `kv_ttl` MODPARAM — it stops THIS module from CREATING a MaxAge bucket.  It
 * does NOT cover the migration case: on first deploy against an EXISTING bucket
 * created by an older deployment (or another tool), the bound stream may already
 * have MaxAge != 0.  A non-zero stream MaxAge expires EVERY key after that age,
 * including PERMANENT contacts (expires==0, row_exp==0) — silent registration
 * data loss.  The module binds to existing buckets (nats_pool.c js_KeyValue),
 * so without a check this is silent.
 *
 * `cdbn_kv_legacy_bucket_maxage_warn(maxage_ns)` is the policy decision: a bound
 * bucket with a non-zero MaxAge warrants a loud startup WARN naming the
 * permanent-contact-expiry risk + remediation (recreate the bucket MaxAge=0 /
 * kv_ttl=0).  This is the "documented policy, not a silent permanent-contact
 * expiry" the GATE requires; it WARNs rather than refusing start so a generic
 * (non-usrloc) cachedb_nats user who intends a TTL bucket is not broken.
 *
 *   gcc ...                        -> the FIXED policy           => GREEN.
 *
 * Rule 6: the authoritative proof is the Tier-2
 * run_legacy_maxage_bucket_warn_e2e.sh (plant a MaxAge bucket, boot, assert WARN).
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_kv_ttl_legacy_bucket test_kv_ttl_legacy_bucket.c
 */
#include <tap.h>
#include <stdio.h>
#include <stdint.h>
#include "../cachedb_nats_expiry.h"
#include "../cachedb_nats_json.h"

#include "cn_ut.h"

#define NATS_NS_PER_S  1000000000LL


#define CHECK(cond, msg) do { if (!(cond)) { fail("kv_ttl_legacy_bucket: %s", msg); } \
	else pass("kv_ttl_legacy_bucket: %s", msg); } while (0)

void cn_ut_kv_ttl_legacy_bucket(void)
{

	diag("MaxAge==0 is the ONLY safe config -> no warn:");
	CHECK(cdbn_kv_legacy_bucket_maxage_warn(0) == 0, "MaxAge=0 => clean (no warn)");

	diag("any non-zero MaxAge would expire permanent contacts -> WARN:");
	CHECK(cdbn_kv_legacy_bucket_maxage_warn(30LL * NATS_NS_PER_S) == 1, "MaxAge=30s => WARN");
	CHECK(cdbn_kv_legacy_bucket_maxage_warn(1) == 1, "MaxAge=1ns (sub-second) => WARN");
	CHECK(cdbn_kv_legacy_bucket_maxage_warn(86400LL * NATS_NS_PER_S) == 1, "MaxAge=1d => WARN");
	CHECK(cdbn_kv_legacy_bucket_maxage_warn(INT64_MAX) == 1, "MaxAge=INT64_MAX => WARN");
	/* defensive: a negative (corrupt) MaxAge is still non-zero => warn, never silent */
	CHECK(cdbn_kv_legacy_bucket_maxage_warn(-1) == 1, "MaxAge=-1 (corrupt) => WARN (never silent)");

}
