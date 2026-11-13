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
 * The consumer process's fetch: the per-fetch budget of a sweep over
 * many handles (fetch_budget_ms()) and the fetch it shapes
 * (proc_fetch_batch()), with a fake libnats fetch that records what it
 * was asked for.  Replaces tests/test_fetch_budget.c (a model of the
 * sweep plus greps): with N handles each fetch waits about
 * fetch_timeout / N, so a sweep over idle handles cannot hold acks and
 * async RPCs back for N * fetch_timeout.
 *
 * Also how a fetch's outcome is counted (tests/test_backpressure_stats.c,
 * pre-fetch half): a full ring skips the fetch (flow control, not a drop),
 * a vanished consumer has its subscription destroyed and its outstanding
 * messages purged before the recreate (a late ack would use the freed
 * subscription), and other errors are counted without a rebuild.
 */

#include <tap.h>
#include <string.h>

#include "../nats_handle_registry.h"
#include "../nats_handle_parse.h"
#include "../nats_ring.h"
#include "../nats_consumer_proc.h"
#include "../nats_consumer_proc_internal.h"
#include "../nats_handle_registry.h"

#include "nc_ut.h"

static void budget(void)
{
	ok(nc_ut_fetch_budget_ms(1000, 1) == 0,
		"fetch: one handle has no cap (its full timeout)");
	ok(nc_ut_fetch_budget_ms(1000, 0) == 0,
		"fetch: no handles has no cap");
	ok(nc_ut_fetch_budget_ms(1000, 10) == 100,
		"fetch: ten handles share one timeout");
	ok(10 * nc_ut_fetch_budget_ms(1000, 10) <= 1000,
		"fetch: a sweep of ten idle handles stays within one timeout");
	ok(nc_ut_fetch_budget_ms(1000, 1000) == 5,
		"fetch: a large sweep is floored at 5 ms per fetch");
	ok(nc_ut_fetch_budget_ms(3, 10) == 3,
		"fetch: the floor never exceeds the configured timeout");
}

/* Runs one fetch of a private handle bound with `bind`, whose ring of
 * `cap` slots holds nothing, under `budget_ms`. */
static int fetch(const char *bind, uint32_t cap, int budget_ms)
{
	str cfg = { (char *)bind, (int)strlen(bind) };
	const char *err = NULL;
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	proc_sub_state_t ss;
	natsMsgList list;
	int rc;

	if (!h)
		return -2;
	h->ring = nats_ring_create(cap);
	if (!h->ring) {
		nats_handle_free(h);
		return -2;
	}
	memset(&ss, 0, sizeof ss);
	ss.h_ref = h;
	ss.ring = h->ring;
	ss.sub = (natsSubscription *)&ss;   /* opaque to the fake */

	nc_ut_begin();
	rc = nc_ut_proc_fetch_batch(&ss, budget_ms, &list);
	nc_ut_end();
	nats_handle_free(h);
	return rc;
}

#define B "id=ut_fetch;stream=UT;durable=d;fetch_timeout_ms=1000"

static void shaped_fetch(void)
{
	fetch(B ";fetch_batch=4", 8, 0);
	ok(nf.n_fetch == 1 && nf.fetch_timeout == 1000,
		"fetch: no budget waits the handle's fetch_timeout_ms");
	fetch(B ";fetch_batch=4", 8, 100);
	ok(nf.fetch_timeout == 100,
		"fetch: a budget caps the wait");
	fetch(B ";fetch_batch=4", 8, 5000);
	ok(nf.fetch_timeout == 1000,
		"fetch: a budget above the timeout does not raise it");
	ok(nf.fetch_batch == 4,
		"fetch: the handle's fetch_batch is asked for when it fits");
	fetch(B ";fetch_batch=100", 8, 0);
	ok(nf.fetch_batch == 7,
		"fetch: the batch is clamped to the ring's free slots less one");
	ok(fetch(B, 8, 0) == 0,
		"fetch: a timeout (nothing to fetch) pushes nothing");
}

#define OIDX ((uint16_t)(NATS_REGISTRY_MAX_HANDLES - 4))

static void outcomes(void)
{
	str cfg = str_init("id=ut_fetch_out;stream=UT;durable=d;fetch_timeout_ms=100");
	const char *err = NULL;
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	proc_sub_state_t ss;
	natsMsgList list;
	char m1, m2;
	int ok_;
	uint64_t errors, skips;

	if (!h || !(h->ring = nats_ring_create(4))) {
		ok(0, "fetch: a private handle with a ring");
		if (h) nats_handle_free(h);
		return;
	}
	memset(&ss, 0, sizeof ss);
	ss.h_ref = h;
	ss.ring = h->ring;
	ss.handle_idx = OIDX;
	ss.id.s = "ut_fetch_out";
	ss.id.len = 12;
	ss.sub = (natsSubscription *)&ss;

	nc_ut_begin();
	skips = h->fetch_skips_full;
	nc_ut_ring_forge(ss.ring, 4, 0);
	ok(nc_ut_proc_fetch_batch(&ss, 0, &list) == 0 && nf.n_fetch == 0 &&
		h->fetch_skips_full == skips + 1,
		"fetch: a full ring skips the fetch, counted as a skip");
	nc_ut_ring_forge(ss.ring, 0, 0);

	errors = h->fetch_errors;
	nf.fetch_status = NATS_TIMEOUT;
	nc_ut_proc_fetch_batch(&ss, 0, &list);
	ok(h->fetch_errors == errors && !ss.dirty,
		"fetch: nothing to fetch (timeout) is not an error");

	nf.fetch_status = NATS_ERR;
	nc_ut_proc_fetch_batch(&ss, 0, &list);
	ok(h->fetch_errors == errors + 1 && !ss.dirty && nf.n_sub_destroy == 0,
		"fetch: another error is counted, the subscription kept");

	store_msg_ref(OIDX, 4, 0, (natsMsg *)&m1, &ok_);
	store_msg_ref(OIDX, 4, 0, (natsMsg *)&m2, &ok_);
	nf.n_msg_destroy = 0;
	nf.fetch_status = NATS_NOT_FOUND;
	nc_ut_proc_fetch_batch(&ss, 0, &list);
	ok(ss.dirty && ss.sub == NULL && nf.n_unsubscribe == 1 && nf.n_sub_destroy == 1,
		"fetch: a vanished consumer: subscription destroyed, marked for rebuild");
	ok(nf.n_msg_destroy == 2,
		"fetch: and its outstanding messages are purged before the recreate");
	ok(h->fetch_errors == errors + 2, "fetch: counted as an error");
	purge_msg_ref_row(OIDX);   /* with the fakes: these messages are fake */
	nc_ut_end();

	nats_handle_free(h);
}

void nc_ut_fetch(void)
{
	budget();
	shaped_fetch();
	outcomes();
}
