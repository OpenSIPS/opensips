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
 * What a ring does when the other side died midway, and how it wakes its
 * readers.  Replaces tests/test_ring_bounded_spin.c,
 * test_ring_push_bounded_spin.c, test_ring_force_unwedge.c,
 * test_ring_wake_one.c and test_ring_xproc_wakeup.c, which #included
 * nats_ring.c to reach its struct, used a SIGALRM watchdog, and grepped
 * the source.  Here UNIT_TESTS hooks in nats_ring.c forge the states, and
 * a thread with a timed join is the watchdog.
 *
 *  - A producer that reserved a slot and died before publishing it leaves
 *    head ahead of tail on an unpublished slot: pop must give up (-1, as
 *    if empty) instead of spinning on it forever.
 *  - A popper that took a slot and died before releasing it leaves the
 *    slot unconsumed: push must give up (-1, as if full), and once the
 *    same slot has been stuck for the unwedge wait (30 s; shortened
 *    here), force it free so delivery resumes -- JetStream redelivers
 *    the lost message.
 *  - One published message wakes one blocked reader, not all of them; a
 *    reader in another process is woken through the shared ring.
 */

#define _GNU_SOURCE   /* pthread_timedjoin_np */
#include <tap.h>
#include <pthread.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#include "../nats_ring.h"

#include "nc_ut.h"

static nats_ring_msg_t msg(uint64_t token)
{
	nats_ring_msg_t m;

	memset(&m, 0, sizeof m);
	m.subject = "ut.ring";
	m.subject_len = 7;
	m.data = "x";
	m.data_len = 1;
	m.ack_token = token;
	return m;
}

/* ── the watchdog: runs a ring call in a thread, gives it 2 s ───── */

struct call {
	nats_ring_t *r;
	int push;           /* 1: push, 0: pop */
	int rc;
};

static void *run_call(void *arg)
{
	struct call *c = arg;
	nats_ring_slot_t out;
	nats_ring_msg_t m = msg(7);

	c->rc = c->push ? nats_ring_push(c->r, &m) : nats_ring_pop(c->r, &out);
	return NULL;
}

/* 1 when the call returned within 2 s, its result in *rc; 0 when it
 * hangs (the thread is left behind, spinning, and the suite fails) */
static int returns(nats_ring_t *r, int push, int *rc)
{
	static struct call c;
	struct timespec until;
	pthread_t t;

	c.r = r;
	c.push = push;
	c.rc = -100;
	if (pthread_create(&t, NULL, run_call, &c) != 0)
		return 0;
	clock_gettime(CLOCK_REALTIME, &until);
	until.tv_sec += 2;
	if (pthread_timedjoin_np(t, NULL, &until) != 0) {
		pthread_detach(t);
		return 0;
	}
	*rc = c.rc;
	return 1;
}

static void dead_producer(void)
{
	nats_ring_t *r = nats_ring_create(4);
	nats_ring_slot_t out;
	nats_ring_msg_t m = msg(42);
	int rc;

	ok(r != NULL, "ring_spin: a ring");
	if (!r)
		return;
	nc_ut_ring_forge(r, 1, 0);   /* slot 0 reserved, never published */
	ok(nats_ring_depth(r) == 1, "ring_spin: it looks non-empty");
	ok(returns(r, 0, &rc) && rc == -1,
		"ring_spin: pop gives up on a slot a dead producer never published");
	nats_ring_destroy(r);

	r = nats_ring_create(4);
	if (!r)
		return;
	ok(nats_ring_push(r, &m) == 0 && returns(r, 0, &rc) && rc == 0,
		"ring_spin: a published slot still pops at once");
	ok(nats_ring_pop(r, &out) == -1, "ring_spin: an empty ring pops -1");
	nats_ring_destroy(r);
}

static void dead_popper(void)
{
	nats_ring_t *r = nats_ring_create(4);
	nats_ring_msg_t m = msg(1);
	nats_ring_slot_t out;
	int rc;

	ok(r != NULL, "ring_spin: a ring");
	if (!r)
		return;
	/* 4 pushed and 4 popped, but slot 0's popper never released it */
	nc_ut_ring_forge(r, 4, 4);
	ok(returns(r, 1, &rc) && rc == -1,
		"ring_spin: push gives up on a slot a dead popper never released");
	nats_ring_destroy(r);

	r = nats_ring_create(4);
	if (!r)
		return;
	ok(nats_ring_push(r, &m) == 0 && nats_ring_pop(r, &out) == 0 &&
		out.ack_token == 1, "ring_spin: a free slot still pushes and pops");
	nats_ring_destroy(r);
}

static void unwedge(void)
{
	nats_ring_t *r = nats_ring_create(4);
	nats_ring_slot_t out;
	long long saved = nc_ut_unwedge_us;
	int rc;

	if (!r)
		return;
	nc_ut_unwedge_us = 50 * 1000;
	nc_ut_ring_forge(r, 4, 4);

	nc_ut_begin();
	ok(returns(r, 1, &rc) && rc == -1 && nats_ring_forced_unwedges(r) == 0,
		"ring_spin: the first stuck push only notes the slot (full)");
	usleep(80 * 1000);
	ok(returns(r, 1, &rc) && rc == 0 && nats_ring_forced_unwedges(r) == 1,
		"ring_spin: past the unwedge wait the slot is forced free");
	ok(strstr(nc_ut_log(), "force-unwedged slot 0") != NULL,
		"ring_spin: and that is logged");
	nc_ut_end();

	nc_ut_ring_forge(r, 5, 4);   /* the forced push is now at tail */
	ok(nats_ring_pop(r, &out) == 0 && out.ack_token == 7,
		"ring_spin: the message pushed after the unwedge pops intact");
	ok(nats_ring_forced_unwedges(r) == 1,
		"ring_spin: one stuck slot is forced once");

	nc_ut_unwedge_us = saved;
	nats_ring_destroy(r);
}

/* ── wake-ups ───────────────────────────────────────────────────── */

#define WAITERS 8
static nats_ring_t *wake_ring;
static int woken;

static void *waiter(void *arg)
{
	(void)arg;
	if (nats_ring_wait(wake_ring, 3000) == 0)
		__atomic_add_fetch(&woken, 1, __ATOMIC_SEQ_CST);
	return NULL;
}

static int settle(uint32_t want_waiters)
{
	int i;

	for (i = 0; i < 200; i++) {
		if (nc_ut_ring_waiters(wake_ring) == want_waiters)
			return 1;
		usleep(5 * 1000);
	}
	return 0;
}

static void wake_one(void)
{
	pthread_t t[WAITERS];
	nats_ring_msg_t m = msg(5);
	nats_ring_slot_t out;
	int i, n = 0;

	wake_ring = nats_ring_create(16);
	if (!wake_ring)
		return;
	woken = 0;
	for (i = 0; i < WAITERS; i++)
		if (pthread_create(&t[i], NULL, waiter, NULL) == 0)
			n++;
	ok(n == WAITERS && settle(WAITERS),
		"ring_spin: %d readers wait on an empty ring", WAITERS);
	nats_ring_push(wake_ring, &m);
	usleep(100 * 1000);
	ok(__atomic_load_n(&woken, __ATOMIC_SEQ_CST) == 1,
		"ring_spin: one message wakes one reader, not all (%d woke)",
		__atomic_load_n(&woken, __ATOMIC_SEQ_CST));
	for (i = 1; i < WAITERS; i++)
		nats_ring_push(wake_ring, &m);
	for (i = 0; i < n; i++)
		pthread_join(t[i], NULL);
	ok(woken == WAITERS && nc_ut_ring_waiters(wake_ring) == 0,
		"ring_spin: one message each wakes them all");
	while (nats_ring_pop(wake_ring, &out) == 0)
		;
	nats_ring_destroy(wake_ring);
}

static void other_process(void)
{
	nats_ring_t *r = nats_ring_create(4);
	nats_ring_msg_t m = msg(77);
	int status = -1;
	pid_t pid;

	if (!r)
		return;
	pid = fork();
	if (pid == 0) {
		nats_ring_slot_t out;
		int got = nats_ring_wait(r, 3000) == 0 &&
			nats_ring_pop(r, &out) == 0 && out.ack_token == 77;
		_exit(got ? 0 : 1);
	}
	ok(pid > 0, "ring_spin: a reader process");
	if (pid > 0) {
		usleep(100 * 1000);   /* let it block */
		nats_ring_push(r, &m);
		waitpid(pid, &status, 0);
		ok(WIFEXITED(status) && WEXITSTATUS(status) == 0,
			"ring_spin: a push wakes a reader in another process, which pops it");
	}
	nats_ring_destroy(r);
}

void nc_ut_ring_spin(void)
{
	dead_producer();
	dead_popper();
	unwedge();
	wake_one();
	other_process();
}
