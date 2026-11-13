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
 * The reconcile step of the consumer process (reconcile_subs_cb() in
 * nats_sub_config.c) and its retry schedule.  Replaces
 * tests/test_ensure_backoff.c (the schedule, plus greps for its use):
 * a handle whose subscribe keeps failing is retried after 1, 2, 4 ... s,
 * capped at 60 s, is skipped until its retry time, and starts again at
 * 1 s once it recovers.
 *
 * The consumer process reconciles every registry handle on its own, in
 * parallel with this suite, so these scenarios use a private handle
 * (parsed, never bound) with a ring of its own.
 */

#include <tap.h>
#include <string.h>
#include <time.h>

#include "../nats_handle_registry.h"
#include "../nats_handle_parse.h"
#include "../nats_ring.h"
#include "../nats_consumer_proc.h"
#include "../nats_consumer_proc_internal.h"

#include "nc_ut.h"

#define CAP_S 60u

static void schedule(void)
{
	static const unsigned want[] = { 0, 1, 2, 4, 8, 16, 32, CAP_S };
	unsigned f, w, prev = 0;
	int monotonic = 1, capped = 1;

	for (f = 0; f < sizeof want / sizeof want[0]; f++)
		ok(nc_ut_ensure_backoff_seconds(f) == want[f],
			"reconcile: failure %u waits %u s", f, want[f]);
	for (f = 1; f <= 1000; f++) {
		w = nc_ut_ensure_backoff_seconds(f);
		if (w < prev) monotonic = 0;
		if (w > CAP_S) capped = 0;
		prev = w;
	}
	ok(monotonic, "reconcile: the wait never shrinks");
	ok(capped, "reconcile: the wait never exceeds 60 s");
	ok(nc_ut_ensure_backoff_seconds(0xFFFFFFFFu) == CAP_S,
		"reconcile: a huge failure count stays at the cap");
}

static nats_handle_t *private_handle(void)
{
	str cfg = str_init("id=ut_reconcile;stream=UT_RECONCILE;durable=d");
	const char *err = NULL;
	nats_handle_t *h = nats_handle_parse(&cfg, &err);

	if (!h)
		return NULL;
	h->ring = nats_ring_create(2);
	if (!h->ring) {
		nats_handle_free(h);
		return NULL;
	}
	return h;
}

static void backoff(void)
{
	nats_handle_t *h = private_handle();
	time_t before;
	int i, calls;

	ok(h != NULL, "reconcile: a private handle with a ring");
	if (!h)
		return;

	nc_ut_begin();
	nf.connected = 1;

	before = time(NULL);
	reconcile_subs_cb(h, NULL);
	ok(h->ensure_failures == 1, "reconcile: a failed ensure counts a failure");
	ok(h->ensure_next_retry_at >= before + 1 &&
		h->ensure_next_retry_at <= time(NULL) + 1,
		"reconcile: the first retry is 1 s away");
	calls = nf.n_pull_subscribe + nf.n_add_consumer;

	reconcile_subs_cb(h, NULL);
	ok(h->ensure_failures == 1 &&
		nf.n_pull_subscribe + nf.n_add_consumer == calls,
		"reconcile: a handle is skipped until its retry time");

	h->ensure_next_retry_at = 1;   /* long past */
	before = time(NULL);
	reconcile_subs_cb(h, NULL);
	ok(h->ensure_failures == 2 && h->ensure_next_retry_at >= before + 2 &&
		h->ensure_next_retry_at <= time(NULL) + 2,
		"reconcile: the second failure waits 2 s");

	__atomic_store_n(&h->retire, 1, __ATOMIC_SEQ_CST);
	h->ensure_next_retry_at = 1;
	reconcile_subs_cb(h, NULL);
	ok(h->ensure_failures == 2 && h->ensure_next_retry_at == 1,
		"reconcile: a retired handle is left alone");
	__atomic_store_n(&h->retire, 0, __ATOMIC_SEQ_CST);

	for (i = 0; i < 5; i++) {
		h->ensure_next_retry_at = 1;
		reconcile_subs_cb(h, NULL);
	}
	ok(h->ensure_failures == 7 &&
		h->ensure_next_retry_at >= time(NULL) + CAP_S - 1,
		"reconcile: the seventh failure waits the 60 s cap");
	ok(strstr(nc_ut_log(), "backoff now capped") != NULL,
		"reconcile: reaching the cap is logged");

	/* the pool is down: the subscribe is put off, which counts as fine */
	nf.connected = 0;
	h->ensure_next_retry_at = 1;
	reconcile_subs_cb(h, NULL);
	ok(h->ensure_failures == 0 && h->ensure_next_retry_at == 0,
		"reconcile: a successful pass resets the backoff");

	nc_ut_end();
	nats_handle_free(h);
}

void nc_ut_reconcile(void)
{
	schedule();
	backoff();
}
