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
 * How a SIP worker's waits end: the resume of an async nats_request
 * (resume_nats_request_slot() in nats_rpc_async.c), the sync nats_fetch
 * wait, and the async nats_fetch it hands to the reactor.  Replaces
 * tests/test_rpc_disconnect_cancel.c, tests/test_blocking_budget.c and
 * tests/test_fetch_async_timerfd.c (models plus greps).
 *
 *  - A request whose connection was lost cannot get its reply (its inbox
 *    died with the connection), so its next resume answers -2 at once
 *    instead of at the timeout; at the deadline it answers -1, or -2 if
 *    the connection was lost.  A reply the consumer is delivering at that
 *    moment is not dropped: the resume keeps waiting.  A delivery pinned
 *    past deadline + 5 s ends the wait with -2 without freeing the slot
 *    under the consumer's pin (the orphan reaper takes it back).
 *  - A sync fetch waiting in 100 ms slices re-checks the connection each
 *    slice and returns early once it is down.
 *  - An async fetch gives the reactor a timer fd of its own (the ring has
 *    no fd a worker could wait on: an fd made in another process means
 *    nothing in this one), and its resume finds a message that arrived or
 *    ends the wait at the deadline.
 *
 * Runs while the consumer process is held: the live slot and the cfg's
 * bound handle are this suite's.
 */

#include <tap.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

#include "../../../async.h"
#include "../nats_ring.h"
#include "../nats_rpc_slot.h"
#include "../nats_handle_registry.h"
#include "../nats_fetch.h"

#include "nc_ut.h"

#define CORR "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"
#define SEC 1000000LL

static int fd_r = -1, fd_w = -1;   /* a pipe: the resume reads its fd */

static int state(nats_rpc_slot_t *s)
{
	return atomic_load_explicit(&s->state, memory_order_acquire);
}

static uint32_t gen(nats_rpc_slot_t *s)
{
	return atomic_load_explicit(&s->generation, memory_order_relaxed);
}

/* a request in flight, sent while the pool was at epoch 5 */
static nats_rpc_slot_t *in_flight(void)
{
	nats_rpc_slot_t *s = nats_rpc_slot_claim();

	if (!s)
		return NULL;
	memcpy(s->corr_id, CORR, sizeof CORR - 1);
	s->corr_id_len = sizeof CORR - 1;
	s->epoch_at_start.seen = 5;
	if (nats_rpc_slot_publish(s) < 0) {
		nats_rpc_slot_free(s, gen(s));
		return NULL;
	}
	return s;
}

static int resume(nats_rpc_slot_t *s, int64_t deadline_from_now_us)
{
	return nc_ut_resume_request(s, gen(s), nc_ut_now_us() + deadline_from_now_us,
		fd_r);
}

static void request_resume(void)
{
	nats_rpc_slot_t *s;
	uint32_t g;
	int rc;

	nc_ut_begin();
	nf.connected = 1;
	nf.epoch = 5;

	s = in_flight();
	ok(s != NULL, "resume: a request in flight");
	if (!s) {
		nc_ut_end();
		return;
	}
	ok(resume(s, 10 * SEC) == 0 && async_status == ASYNC_CONTINUE,
		"resume: connected, before its deadline: it keeps waiting");

	nf.epoch = 6;   /* the pool reconnected: the request's inbox is gone */
	g = gen(s);
	rc = resume(s, 10 * SEC);
	ok(rc == -2 && async_status == ASYNC_DONE_CLOSE_FD,
		"resume: connection lost mid-flight: -2 on the next tick, not at the timeout");
	ok(state(s) == NATS_RPC_SLOT_FREE,
		"resume: and its slot is freed (the next claim bumps generation %u)", g);
	nf.epoch = 5;

	s = in_flight();
	if (s) {
		ok(resume(s, -1) == -1, "resume: deadline passed, connected: -1");
		ok(state(s) == NATS_RPC_SLOT_FREE, "resume: slot freed");
	}
	s = in_flight();
	if (s) {
		nf.connected = 0;
		ok(resume(s, -1) == -2, "resume: deadline passed, connection lost: -2");
		nf.connected = 1;
	}

	/* the consumer is copying the reply in right now */
	s = in_flight();
	if (s) {
		atomic_store(&s->state, NATS_RPC_SLOT_DELIVERING);
		nf.epoch = 6;
		ok(resume(s, -1) == 0 && async_status == ASYNC_CONTINUE &&
			state(s) == NATS_RPC_SLOT_DELIVERING,
			"resume: a reply being delivered is not dropped, even lost and late");
		nf.epoch = 5;
		ok(resume(s, -6 * SEC) == -2 && async_status == ASYNC_DONE_CLOSE_FD &&
			state(s) == NATS_RPC_SLOT_DELIVERING,
			"resume: pinned past deadline + 5 s: -2, the slot left to the reaper");
		atomic_store(&s->state, NATS_RPC_SLOT_INFLIGHT);
		nats_rpc_slot_abandon(s);
		nats_rpc_slot_free(s, gen(s));
	}

	s = in_flight();
	if (s) {
		memcpy(s->reply_data, "pong", 4);
		s->reply_data_len = 4;
		atomic_store(&s->state, NATS_RPC_SLOT_DELIVERED);
		ok(resume(s, 10 * SEC) == 1 && state(s) == NATS_RPC_SLOT_FREE,
			"resume: a delivered reply ends the wait with 1, slot freed");
	}
	s = in_flight();
	if (s) {
		nats_rpc_slot_abandon(s);
		ok(resume(s, 10 * SEC) == -1, "resume: an abandoned call, connected: -1");
	}
	nc_ut_end();
}

static void *drop_connection(void *arg)
{
	(void)arg;
	usleep(200 * 1000);
	__atomic_store_n(&nf.connected, 0, __ATOMIC_SEQ_CST);
	return NULL;
}

static long long ms_now(void)
{
	return nc_ut_now_us() / 1000;
}

static void sync_fetch(void)
{
	str id = str_init("ut_bind");
	pthread_t t;
	int tmo = 3000, rc;
	long long t0;

	nc_ut_begin();
	nf.connected = 1;
	pthread_create(&t, NULL, drop_connection, NULL);
	t0 = ms_now();
	rc = w_nats_fetch(NULL, &id, &tmo);
	pthread_join(t, NULL);
	ok(rc < 0 && ms_now() - t0 < 1000,
		"resume: a 3 s sync fetch returns within 1 s of the broker going down (%lld ms)",
		ms_now() - t0);
	nc_ut_end();
}

static int is_timerfd(int fd)
{
	char path[64], target[128];
	ssize_t n;

	snprintf(path, sizeof path, "/proc/self/fd/%d", fd);
	n = readlink(path, target, sizeof target - 1);
	if (n <= 0)
		return 0;
	target[n] = '\0';
	return strstr(target, "timerfd") != NULL;
}

static void async_fetch(void)
{
	str id = str_init("ut_bind");
	nats_handle_t *h = nats_registry_lookup(&id);
	int (*resume_f)(int, struct sip_msg *, void *);
	nats_ring_msg_t m;
	struct pollfd pfd;
	async_ctx ctx;
	int tmo, rc, tfd, pending;

	if (!h)
		return;
	pending = nats_handle_pending_get(h);
	nc_ut_begin();
	nf.connected = 1;

	memset(&ctx, 0, sizeof ctx);
	tmo = 5000;
	rc = w_nats_fetch_async(NULL, &ctx, &id, &tmo);
	tfd = async_status;
	ok(rc == 1 && tfd >= 0 && is_timerfd(tfd) && ctx.resume_f != NULL,
		"resume: an async fetch hands the reactor a timer fd of its own");
	pfd.fd = tfd;
	pfd.events = POLLIN;
	ok(tfd >= 0 && poll(&pfd, 1, 500) == 1,
		"resume: which fires within the poll interval");
	memset(&m, 0, sizeof m);
	m.subject = "ut.fetch";
	m.subject_len = 8;
	m.ack_token = 77;
	nats_ring_push(h->ring, &m);
	resume_f = ctx.resume_f;
	rc = resume_f ? resume_f(tfd, NULL, ctx.resume_param) : -100;
	ok(rc == 1 && async_status == ASYNC_DONE_CLOSE_FD,
		"resume: its resume picks up a message that arrived");
	if (tfd >= 0)
		close(tfd);

	memset(&ctx, 0, sizeof ctx);
	tmo = 1;
	rc = w_nats_fetch_async(NULL, &ctx, &id, &tmo);
	tfd = async_status;
	usleep(20 * 1000);
	resume_f = ctx.resume_f;
	rc = resume_f ? resume_f(tfd, NULL, ctx.resume_param) : -100;
	ok(rc == -1 && async_status == ASYNC_DONE_CLOSE_FD,
		"resume: with nothing by the deadline it ends with -1");
	if (tfd >= 0)
		close(tfd);
	ok(nats_handle_pending_get(h) == pending,
		"resume: and the handle's reference is given back each time");
	nc_ut_end();
}

void nc_ut_resume(void)
{
	int p[2];

	if (pipe(p) == 0) {
		fd_r = p[0];
		fd_w = p[1];
		fcntl(fd_r, F_SETFL, O_NONBLOCK);
	}
	request_resume();
	sync_fetch();
	async_fetch();
	close(fd_r);
	close(fd_w);
}
