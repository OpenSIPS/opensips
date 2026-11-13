/*
 * Copyright (C) 2026 OpenSIPS Solutions
 * Copyright (C) 2026 Norm Brandinger <n.brandinger@gmail.com>
 *
 * This file is part of opensips, a free SIP server.
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
 */

/*
 * test_ack_token.c -- unit tests for the ack-token packing/unpacking
 * helpers in nats_ack.h.  Pure header-only; no shim required.
 */

#include <tap.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <assert.h>

#include "../nats_ack.h"

#include "nc_ut.h"


#define CHECK(cond) ok((cond), "ack_token:%d %s", __LINE__, #cond)

static void test_pack_roundtrip_basic(void)
{
	uint64_t t = nats_ack_token_pack(0x1234, 0xdeadbeefu, 0xc0de);
	CHECK(nats_ack_token_handle(t)     == 0x1234);
	CHECK(nats_ack_token_slot(t)       == 0xdeadbeefu);
	CHECK(nats_ack_token_generation(t) == 0xc0de);
}

static void test_pack_zero(void)
{
	uint64_t t = nats_ack_token_pack(0, 0, 0);
	CHECK(t == 0);
	CHECK(nats_ack_token_handle(t)     == 0);
	CHECK(nats_ack_token_slot(t)       == 0);
	CHECK(nats_ack_token_generation(t) == 0);
}

static void test_pack_max(void)
{
	uint64_t t = nats_ack_token_pack(0xFFFF, 0xFFFFFFFFu, 0xFFFF);
	CHECK(t == UINT64_C(0xFFFFFFFFFFFFFFFF));
	CHECK(nats_ack_token_handle(t)     == 0xFFFF);
	CHECK(nats_ack_token_slot(t)       == 0xFFFFFFFFu);
	CHECK(nats_ack_token_generation(t) == 0xFFFF);
}

static void test_pack_isolation(void)
{
	/* Fields don't overlap: changing one doesn't perturb the others. */
	uint64_t t1 = nats_ack_token_pack(0x0001, 0x00000000, 0x0000);
	uint64_t t2 = nats_ack_token_pack(0x0000, 0x00000001, 0x0000);
	uint64_t t3 = nats_ack_token_pack(0x0000, 0x00000000, 0x0001);
	CHECK(t1 != t2);
	CHECK(t2 != t3);
	CHECK(t1 != t3);
	CHECK(nats_ack_token_handle(t1)     == 1);
	CHECK(nats_ack_token_slot(t1)       == 0);
	CHECK(nats_ack_token_generation(t1) == 0);
	CHECK(nats_ack_token_slot(t2)       == 1);
	CHECK(nats_ack_token_generation(t3) == 1);
}

void nc_ut_ack_token(void)
{
	test_pack_roundtrip_basic();
	test_pack_zero();
	test_pack_max();
	test_pack_isolation();
}
