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
 * Bounds a bind and an async fetch enforce.  Replaces
 * tests/test_bind_bounds.c (greps): a ring_capacity above 65536 is
 * refused (each slot is ~17.7 KB of SHM), and the async fetch refuses a
 * timeout of 0 or less, which would set no deadline and hold the
 * handle's reference forever if no message came.
 */

#include <tap.h>
#include <string.h>

#include "../../../async.h"
#include "../nats_handle_registry.h"
#include "../nats_handle_parse.h"
#include "../nats_fetch.h"

#include "nc_ut.h"

static int parses(const char *bind, const char **err)
{
	str cfg = { (char *)bind, (int)strlen(bind) };
	nats_handle_t *h;

	*err = NULL;
	h = nats_handle_parse(&cfg, err);
	if (!h)
		return 0;
	nats_handle_free(h);
	return 1;
}

static void ring_capacity(void)
{
	const char *err;

	ok(parses("id=b;stream=S;durable=d;ring_capacity=65536", &err),
		"bind_bounds: ring_capacity=65536 is the largest accepted");
	ok(!parses("id=b;stream=S;durable=d;ring_capacity=131072", &err) && err,
		"bind_bounds: ring_capacity=131072 is refused");
	ok(!parses("id=b;stream=S;durable=d;ring_capacity=1073741824", &err) && err,
		"bind_bounds: a ring_capacity of 2^30 is refused");
}

/* the async fetch of the cfg's bound handle (empty ring, fake pool up) */
static int fetch_async(const char *id_s, int *tmo)
{
	str id = { (char *)id_s, (int)strlen(id_s) };
	int rc;

	nc_ut_begin();
	nf.connected = 1;
	async_status = ASYNC_NO_IO;
	rc = w_nats_fetch_async(NULL, NULL, &id, tmo);
	nc_ut_end();
	return rc;
}

static void async_timeout(void)
{
	str id = str_init("ut_bind");
	nats_handle_t *h = nats_registry_lookup(&id);
	int zero = 0, neg = -5, pending;

	ok(h != NULL, "bind_bounds: the cfg's handle is bound");
	if (!h)
		return;
	pending = __atomic_load_n(&h->pending_ops, __ATOMIC_SEQ_CST);

	ok(fetch_async("ut_bind", &zero) == -4 && async_status == ASYNC_NO_IO,
		"bind_bounds: an async fetch with timeout 0 is refused");
	ok(fetch_async("ut_bind", &neg) == -4,
		"bind_bounds: an async fetch with a negative timeout is refused");
	ok(fetch_async("ut_bind", NULL) == -4,
		"bind_bounds: an async fetch with no timeout is refused");
	ok(__atomic_load_n(&h->pending_ops, __ATOMIC_SEQ_CST) == pending,
		"bind_bounds: a refused async fetch releases its handle reference");
	ok(fetch_async("ut_no_such_handle", &zero) == -3,
		"bind_bounds: an async fetch of an unknown handle is refused");
}

void nc_ut_bind_bounds(void)
{
	ring_capacity();
	async_timeout();
}
