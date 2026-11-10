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
 * The kv_ttl modparam guard (cdbn_kv_ttl_guard() in cachedb_nats_expiry.c):
 * a non-zero bucket TTL becomes the stream's MaxAge, which caps every
 * per-key TTL and silently expires permanent (expires == 0) contacts, so
 * mod_init refuses it.  Replaces the guard half of
 * tests/test_kv_ttl_zero_guard.c; its other half modelled a TTL-capability
 * latch with no production counterpart (retired, approved).
 */

#include <tap.h>

#include "../cachedb_nats_expiry.h"

#include "cn_ut.h"

void cn_ut_kv_ttl_zero_guard(void)
{
	ok(cdbn_kv_ttl_guard(0) == 0, "kv_ttl_zero_guard: kv_ttl==0 => accepted");
	ok(cdbn_kv_ttl_guard(30) == -1,
		"kv_ttl_zero_guard: kv_ttl==30 => REJECTED (bucket MaxAge expires permanent contacts)");
	ok(cdbn_kv_ttl_guard(1) == -1, "kv_ttl_zero_guard: kv_ttl==1 => rejected");
	ok(cdbn_kv_ttl_guard(-5) == -1, "kv_ttl_zero_guard: negative kv_ttl => rejected (invalid)");
}
