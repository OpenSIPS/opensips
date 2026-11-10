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
 * mod_init validation of the operator parameters: a bad value refuses
 * startup (fail loudly at boot, never misbehave silently at runtime).
 *
 *   cdbn_linger_guard(linger)   0 ok / -1 refuse.  Range 0..86400: negative
 *                               is meaningless; > 1 day is almost certainly a
 *                               typo'd epoch pasted into the config.
 *   cdbn_reap_interval_guard()  0 ok / -1 refuse: the reaper is the only
 *                               expiry mechanism, so it cannot be off.
 *
 * Replaces tests/test_modparam_guards.c on the real guards; its
 * _marker_ttl_guard half modelled kv_marker_ttl, which production no
 * longer has (RETIRED, approved model half).
 */

#include <tap.h>
#include <limits.h>

#include "../cachedb_nats_expiry.h"

#include "cn_ut.h"

#define CHECK(cond, msg) ok((cond), "modparam_guards: %s", (msg))

void cn_ut_modparam_guards(void)
{
	diag("nats_expired_linger range 0..86400:");
	CHECK(cdbn_linger_guard(0) == 0, "0 (default, reclaim ASAP) => ok");
	CHECK(cdbn_linger_guard(30) == 0, "30 => ok");
	CHECK(cdbn_linger_guard(86400) == 0, "86400 (1 day, the ceiling) => ok");
	CHECK(cdbn_linger_guard(-1) == -1, "-1 => refused");
	CHECK(cdbn_linger_guard(86401) == -1, "86401 => refused (typo'd epoch)");
	CHECK(cdbn_linger_guard(INT_MIN) == -1, "INT_MIN => refused");
	CHECK(cdbn_linger_guard(INT_MAX) == -1, "INT_MAX => refused");

	diag("the reaper cannot be turned off:");
	CHECK(cdbn_reap_interval_guard(30) == 0, "reaper on => ok");
	CHECK(cdbn_reap_interval_guard(1) == 0, "1 s => ok");
	CHECK(cdbn_reap_interval_guard(0) == -1, "reaper off => refused");
	CHECK(cdbn_reap_interval_guard(-1) == -1, "negative interval => refused");
	CHECK(cdbn_reap_interval_guard(INT_MIN) == -1, "INT_MIN => refused");
}
