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
 * What the loaded module exports and did in mod_init, read from the
 * running OpenSIPS.  Replaces three source greps:
 *  - tests/test_request_route_restriction.c: nats_request's route mask
 *    (sync nats_request blocks the process that runs it, so it is kept
 *    out of the SIP worker routes unless allow_sync_anywhere=1);
 *  - tests/test_bind_modparam.c: the declarative bind modparam, and the
 *    file persistence it replaced being gone;
 *  - tests/test_pool_self_register.c: the module registers the NATS pool
 *    itself, so it works loaded without event_nats or cachedb_nats.
 */

#include <tap.h>
#include <string.h>

#include "../../../sr_module.h"
#include "../../../cmds.h"
#include "../../../route.h"
#include "../../nats/nats_bind.h"
#include "../nats_handle_registry.h"

#include "nc_ut.h"

typedef int (*setter_f)(modparam_t type, void *val);

static void route_mask(void)
{
	const cmd_export_t *c = find_mod_cmd_export_t("nats_request", 0);
	cmd_export_t *w;
	setter_f widen;
	int saved;

	ok(c != NULL, "module: nats_request is exported");
	if (!c)
		return;
	ok(!(c->flags & REQUEST_ROUTE), "module: nats_request not in REQUEST_ROUTE");
	ok(!(c->flags & FAILURE_ROUTE), "module: nats_request not in FAILURE_ROUTE");
	ok(!(c->flags & BRANCH_ROUTE), "module: nats_request not in BRANCH_ROUTE");
	ok(!(c->flags & ERROR_ROUTE), "module: nats_request not in ERROR_ROUTE");
	ok((c->flags & STARTUP_ROUTE) && (c->flags & TIMER_ROUTE) &&
		(c->flags & LOCAL_ROUTE) && (c->flags & EVENT_ROUTE) &&
		(c->flags & ONREPLY_ROUTE),
		"module: nats_request in startup, timer, local, event and onreply routes");

	widen = (setter_f)find_param_export("nats_consumer",
		"allow_sync_anywhere", INT_PARAM | USE_FUNC_PARAM);
	ok(widen != NULL, "module: allow_sync_anywhere is a modparam");
	if (!widen)
		return;
	w = (cmd_export_t *)c;
	saved = w->flags;
	ok(widen(INT_PARAM, (void *)0L) == 0 && w->flags == saved,
		"module: allow_sync_anywhere=0 keeps the mask");
	ok(widen(INT_PARAM, (void *)2L) < 0 && w->flags == saved,
		"module: allow_sync_anywhere=2 is refused");
	ok(widen(STR_PARAM, (void *)"1") < 0 && w->flags == saved,
		"module: allow_sync_anywhere as a string is refused");
	ok(widen(INT_PARAM, (void *)1L) == 0 && w->flags == ALL_ROUTES,
		"module: allow_sync_anywhere=1 widens to all routes");
	w->flags = saved;
}

static void bind_modparam(void)
{
	str id = str_init("ut_bind");
	nats_handle_t *h;

	ok(find_param_export("nats_consumer", "bind",
		STR_PARAM | USE_FUNC_PARAM) != NULL,
		"module: bind is a modparam");
	h = nats_registry_lookup(&id);
	ok(h != NULL, "module: the cfg's bind is in the registry after mod_init");
	if (h)
		ok(h->stream.len == 9 && memcmp(h->stream.s, "UT_STREAM", 9) == 0 &&
			h->durable.len == 10 &&
			memcmp(h->durable.s, "ut_durable", 10) == 0,
			"module: the bound handle has the cfg's stream and durable");
	ok(!find_param_export("nats_consumer", "persist_handles", INT_PARAM) &&
		!find_param_export("nats_consumer", "persist_handles", STR_PARAM) &&
		!find_param_export("nats_consumer", "persist_path", STR_PARAM) &&
		!find_param_export("nats_consumer", "persist_path", INT_PARAM),
		"module: the persistence modparams are gone");
}

static void pool(void)
{
	ok(nc_ut_pool_registered(),
		"module: mod_init registered the pool itself (loaded alone)");
	ok(nats_api.pool_has_servers(),
		"module: the pool has the module's nats_url");
}

void nc_ut_module(void)
{
	route_mask();
	bind_modparam();
	pool();
}
