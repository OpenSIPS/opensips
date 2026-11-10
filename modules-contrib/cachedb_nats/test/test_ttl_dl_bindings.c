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
 * The raw-publish path needs js_PublishMsg (synchronous CAS publish with
 * the jsPubAck and jsErrCode inline; the fire-and-forget js_PublishAsync
 * cannot return a CAS rejection, so it cannot drive the retry loop), and it
 * must be reachable THROUGH the module's dlopen table, not just a linked
 * libnats.  In the running module: the table cachedb_nats binds from the
 * nats module is there and has the entries resolved.
 * Replaces tests/test_ttl_dl_bindings.c (a grep of nats_dl_table.def plus
 * its own dlopen/dlsym).  LOST: "js_UpdateStream is no longer bound" (a
 * struct member's absence; compile-time only).
 */

#include <tap.h>

#include "../../nats/nats_bind.h"

#include "cn_ut.h"


void cn_ut_ttl_dl_bindings(void)
{
	ok(nats_api.dl != NULL, "ttl_dl_bindings: cachedb_nats bound the nats dl table");
	skip(!nats_api.dl, 3, "no dl table");
	ok(nats_dl.js_PublishMsg != NULL,
		"ttl_dl_bindings: js_PublishMsg resolved (the load-bearing sync publish)");
	ok(nats_dl.js_PublishAsync != NULL,
		"ttl_dl_bindings: js_PublishAsync still resolved alongside it");
	ok(nats_dl.js_GetStreamInfo != NULL,
		"ttl_dl_bindings: js_GetStreamInfo resolved");
	end_skip;
}
