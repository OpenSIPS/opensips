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
 * Async-RPC reply wake over core IPC: the consumer process
 * signals the claiming worker on DELIVERED via
 * ipc_send_rpc(owner_proc, nats_rpc_async_on_wake, pack(slot_idx, gen))
 * and the worker-side handler pokes the per-call guard timerfd to fire
 * immediately, so the reply is picked up at wire latency instead of on
 * the next coarse guard tick.  This test locks the wake TU's contract:
 *
 *   - register/unregister lifecycle of the per-worker wake registry,
 *   - on_wake with a matching (slot_idx, generation) makes the
 *     registered timerfd fire ~immediately while PRESERVING its
 *     periodic guard interval,
 *   - generation mismatch, unregistered slot, out-of-range index,
 *     pre-init and post-destroy calls are all silent no-ops (the
 *     coarse guard tick is the fallback -- a lost/stale wake must
 *     never fire another call's timer),
 *   - the consumer-side send helper refuses an unset owner (-1) and
 *     otherwise emits exactly one ipc_send_rpc with the right
 *     destination, handler identity and packed param.
 *
 * Runs in the nats_consumer unit test suite: the wake table is this
 * process's own, and the send goes to a recorder (UNIT_TESTS seam).
 */

#include <tap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <poll.h>
#include <unistd.h>
#include <sys/timerfd.h>

#include "../../../ipc.h"
#include "../nats_rpc_ipc.h"
#include "../nats_rpc_wake.h"

#include "nc_ut.h"

/* nats_rpc_wake.c's send, swapped for the recorder below (UNIT_TESTS) */
extern int (*nc_ut_wake_ipc_send)(int dst_proc, ipc_rpc_f *rpc, void *param);

#define CHECK(cond, label) ok((cond), "rpc_wake_ipc: %s", (label))

/* ── recording send ──────────────────────────────────────────── */

static int        ipc_calls;
static int        ipc_last_dst = -999;
static ipc_rpc_f *ipc_last_fn;
static void      *ipc_last_param;
static int        ipc_rc;

static int record_send(int dst_proc, ipc_rpc_f *rpc, void *param)
{
	ipc_calls++;
	ipc_last_dst   = dst_proc;
	ipc_last_fn    = rpc;
	ipc_last_param = param;
	return ipc_rc;
}

/* ── timerfd helpers ─────────────────────────────────────────── */

/* A guard timer as the production path arms it: first fire AND period
 * far away (10 s), so any near-term readability can only come from the
 * wake poke under test. */
static int make_guard_timer(void)
{
	struct itimerspec its;
	int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);

	if (fd < 0) return -1;
	memset(&its, 0, sizeof(its));
	its.it_value.tv_sec    = 10;
	its.it_interval.tv_sec = 10;
	if (timerfd_settime(fd, 0, &its, NULL) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

static int fires_within_ms(int fd, int ms)
{
	struct pollfd p = { .fd = fd, .events = POLLIN };
	uint64_t sink;
	int rc = poll(&p, 1, ms);

	if (rc == 1 && (p.revents & POLLIN)) {
		/* drain so a later poll on the same fd starts clean */
		(void)!read(fd, &sink, sizeof(sink));
		return 1;
	}
	return 0;
}

static long long interval_sec(int fd)
{
	struct itimerspec cur;

	if (timerfd_gettime(fd, &cur) < 0) return -1;
	return (long long)cur.it_interval.tv_sec;
}

static long long value_sec(int fd)
{
	struct itimerspec cur;

	if (timerfd_gettime(fd, &cur) < 0) return -1;
	return (long long)cur.it_value.tv_sec;
}

void nc_ut_rpc_wake_ipc(void)
{
	int tfd, tfd2;

	nc_ut_wake_ipc_send = record_send;

	/* ── pre-init: everything is a refusing / silent no-op ───── */
	nats_rpc_async_on_wake(0, nats_rpc_ipc_pack(0, 0));
	CHECK(1, "on_wake before init does not crash");
	CHECK(nats_rpc_wake_register(0, 1, 3) == -1,
		"register before init is refused");
	nats_rpc_wake_unregister(0);
	CHECK(1, "unregister before init does not crash");

	/* ── init / double init ──────────────────────────────────── */
	CHECK(nats_rpc_wake_init(4) == 0, "init(4) ok");
	CHECK(nats_rpc_wake_init(4) == 0, "double init is idempotent");

	tfd = make_guard_timer();
	CHECK(tfd >= 0, "guard timerfd created (10s/10s)");

	/* ── register + wake happy path ──────────────────────────── */
	CHECK(nats_rpc_wake_register(2, 7, tfd) == 0, "register(2, gen 7)");

	/* generation mismatch first: must NOT poke the timer */
	nats_rpc_async_on_wake(0, nats_rpc_ipc_pack(2, 8));
	CHECK(!fires_within_ms(tfd, 150), "gen-mismatch wake does not fire");
	CHECK(value_sec(tfd) >= 8, "gen-mismatch wake leaves it_value intact");

	/* matching wake: fires ~immediately, interval preserved */
	nats_rpc_async_on_wake(0, nats_rpc_ipc_pack(2, 7));
	CHECK(fires_within_ms(tfd, 500), "matching wake fires immediately");
	CHECK(interval_sec(tfd) == 10, "matching wake preserves the guard interval");

	/* ── junk indices / unregistered slots are silent no-ops ─── */
	nats_rpc_async_on_wake(0, nats_rpc_ipc_pack(4, 1));
	CHECK(1, "on_wake(idx == count) does not crash");
	nats_rpc_async_on_wake(0, nats_rpc_ipc_pack(0xFFFFFFFFu, 0));
	CHECK(1, "on_wake(idx = UINT32_MAX) does not crash");
	nats_rpc_async_on_wake(0, nats_rpc_ipc_pack(3, 0));
	CHECK(1, "on_wake on a never-registered slot does not crash");

	/* ── unregister stops wakes ──────────────────────────────── */
	nats_rpc_wake_unregister(2);
	nats_rpc_async_on_wake(0, nats_rpc_ipc_pack(2, 7));
	CHECK(!fires_within_ms(tfd, 150), "wake after unregister does not fire");
	nats_rpc_wake_unregister(2);
	CHECK(1, "double unregister does not crash");
	nats_rpc_wake_unregister(0xFFFFFFFFu);
	CHECK(1, "unregister(idx = UINT32_MAX) does not crash");

	/* ── slot reuse: re-register with a new generation ───────── */
	tfd2 = make_guard_timer();
	CHECK(tfd2 >= 0, "second guard timerfd created");
	CHECK(nats_rpc_wake_register(2, 9, tfd2) == 0, "re-register(2, gen 9)");
	nats_rpc_async_on_wake(0, nats_rpc_ipc_pack(2, 7));
	CHECK(!fires_within_ms(tfd2, 150), "stale-gen wake on a reused slot is dropped");
	nats_rpc_async_on_wake(0, nats_rpc_ipc_pack(2, 9));
	CHECK(fires_within_ms(tfd2, 500), "current-gen wake on a reused slot fires");

	/* register refusals */
	CHECK(nats_rpc_wake_register(4, 1, tfd) == -1,
		"register(idx == count) is refused");
	CHECK(nats_rpc_wake_register(0, 1, -1) == -1,
		"register with an invalid fd is refused");

	/* ── consumer-side send helper ───────────────────────────── */
	ipc_calls = 0; ipc_rc = 0;
	CHECK(nats_rpc_wake_send(-1, 1, 2) == -1 && ipc_calls == 0,
		"send with unset owner (-1) refuses without an IPC call");
	CHECK(nats_rpc_wake_send(5, 3, 0xABCDu) == 0 && ipc_calls == 1,
		"send emits exactly one ipc_send_rpc");
	CHECK(ipc_last_dst == 5, "send targets the owner proc");
	CHECK(ipc_last_fn == nats_rpc_async_on_wake,
		"send carries the on_wake handler identity");
	CHECK(ipc_last_param == nats_rpc_ipc_pack(3, 0xABCDu),
		"send packs (slot_idx, gen) into the param");
	ipc_rc = -1;
	CHECK(nats_rpc_wake_send(5, 3, 4) == -1 && ipc_calls == 2,
		"a refused ipc_send_rpc surfaces -1");

	/* ── destroy: back to silent no-ops ──────────────────────── */
	nats_rpc_wake_destroy();
	nats_rpc_async_on_wake(0, nats_rpc_ipc_pack(2, 9));
	CHECK(!fires_within_ms(tfd2, 150), "on_wake after destroy does not fire");
	CHECK(nats_rpc_wake_register(1, 1, tfd) == -1,
		"register after destroy is refused");
	nats_rpc_wake_destroy();
	CHECK(1, "double destroy does not crash");

	close(tfd);
	close(tfd2);

	nc_ut_wake_ipc_send = ipc_send_rpc;
}
