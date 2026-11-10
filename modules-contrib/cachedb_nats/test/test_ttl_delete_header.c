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
 * /: delete / purge expressed as a publish.
 *
 * A KV delete is a publish carrying the operation header — verified against
 * nats.go jetstream/kv.go: header name "KV-Operation", value "DEL" (tombstone,
 * keep history) or "PURGE" (drop history, rolled up).  Byte-exactness matters:
 * a wrong case / spelling is silently ignored by the server (the publish lands
 * as a normal value, NOT a delete), so the contact would never be removed.
 *
 *   gcc ...                 -> byte-exact "DEL"/"PURGE" => GREEN.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_ttl_delete_header test_ttl_delete_header.c
 */
#include <tap.h>
#include <stdio.h>
#include <string.h>
#include "../cachedb_nats_expiry.h"
#include "../cachedb_nats_json.h"

#include "cn_ut.h"

#define NATS_KV_OP_HDR   "KV-Operation"
#define NATS_KV_OP_DEL   "DEL"
#define NATS_KV_OP_PURGE "PURGE"


#define CHECK(cond, msg) do { if (!(cond)) { fail("ttl_delete_header: %s", msg); } \
	else pass("ttl_delete_header: %s", msg); } while (0)

void cn_ut_ttl_delete_header(void)
{

	diag("KV-Operation header name + values are byte-exact:");
	CHECK(strcmp(NATS_KV_OP_HDR, "KV-Operation") == 0, "header name == 'KV-Operation'");
	CHECK(strcmp(cdbn_ttl_delete_op(0), "DEL") == 0, "delete op == 'DEL' (tombstone)");
	CHECK(strcmp(cdbn_ttl_delete_op(1), "PURGE") == 0, "purge op == 'PURGE' (drop history)");

	diag("case-exact (a wrong case is silently ignored by the server):");
	CHECK(strcmp(cdbn_ttl_delete_op(0), "del") != 0, "not lowercase 'del'");
	CHECK(strcmp(cdbn_ttl_delete_op(0), "DELETE") != 0, "not 'DELETE'");
	CHECK(strcmp(cdbn_ttl_delete_op(1), "purge") != 0, "not lowercase 'purge'");

}
