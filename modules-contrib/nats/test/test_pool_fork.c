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
 * A pool connection opened before fork() must not reach the children.
 *
 * nats.c is not fork-safe: its connection and library threads exist only
 * in the process that started them.  A module that uses NATS from
 * mod_init (b2b_entities restores its state there, through cachedb_nats)
 * makes the attendant connect; a forked worker would inherit a connection
 * handle without the threads behind it, and each request would time out.
 * The pool closes the connection and the library in the attendant right
 * before fork(), so a child connects on its own; a worker that forks
 * (the exec module) keeps its connection.
 *
 * The real pool (nats_pool.c) against the fake libnats of nats_ut_fake.c;
 * forks for real, from the attendant the tests run in.
 */

#include <tap.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#include "../../../globals.h"
#include "../../../pt.h"
#include "../nats_pool.h"

#include "nats_ut.h"
#include "nats_ut_fake.h"

/* a child that reports nothing: only the fork matters */
static void fork_and_wait(void)
{
	pid_t pid = fork();
	int st;

	if (pid == 0)
		_exit(0);
	if (pid > 0)
		waitpid(pid, &st, 0);
}

void nats_ut_pool_fork(void)
{
	natsConnection *nc;
	pid_t pid;
	int st = -1, epoch0;

	if (process_no != 0) {
		fail("the pre-fork teardown is the attendant's (process_no %d)",
			process_no);
		return;
	}

	nats_ut_begin();
	if (nats_pool_register("nats://127.0.0.1:4222", "test", 2000, 3) != 0) {
		nats_ut_end();
		fail("fork: pool setup");
		return;
	}

	/* a connection opened before fork (mod_init) */
	nc = nats_pool_get();
	ok(nc != NULL && nf.n_connect == 1 && nf.n_open == 1, "attendant connected");
	ok(nats_pool_get_js() != NULL, "attendant has a JetStream context");
	ok(nats_pool_get_kv("bucket", 1, 1, 0) != NULL, "...and a KV handle");
	epoch0 = nats_pool_get_reconnect_epoch();

	pid = fork();
	if (pid == 0) {
		/* the child: nothing inherited, connects on its own; it reports
		 * through its exit status, one bit per check */
		int bad = 0;

		nf.n_connect = 0;
		nf.n_open = 0;
		if (nats_pool_is_connected())
			bad |= 1;
		nc = nats_pool_get();
		if (!nc || nf.n_connect != 1)
			bad |= 2;
		if (nf.n_open != 1)      /* the library opened again in the child */
			bad |= 4;
		/* a worker (process_no > 0) that forks keeps its connection:
		 * only the attendant's pre-fork one is closed */
		process_no = 3;
		nf.n_conn_destroy = 0;
		nf.n_close = 0;
		fork_and_wait();
		if (nf.n_conn_destroy != 0 || nf.n_close != 0)
			bad |= 8;
		if (nats_pool_get() != nc || nf.n_connect != 1)
			bad |= 16;
		_exit(bad);
	}
	if (pid > 0)
		waitpid(pid, &st, 0);
	ok(pid > 0 && WIFEXITED(st), "the child ran to its end");
	ok(WIFEXITED(st) && (WEXITSTATUS(st) & 1) == 0,
		"child: not connected on arrival (no inherited connection)");
	ok(WIFEXITED(st) && (WEXITSTATUS(st) & 2) == 0,
		"child: nats_pool_get() opens its own connection");
	ok(WIFEXITED(st) && (WEXITSTATUS(st) & 4) == 0,
		"child: the nats.c library is opened again in the child");
	ok(WIFEXITED(st) && (WEXITSTATUS(st) & 8) == 0,
		"worker fork (process_no > 0): its connection is left alone");
	ok(WIFEXITED(st) && (WEXITSTATUS(st) & 16) == 0,
		"worker keeps using the same connection afterwards");
	ok(nf.n_conn_destroy == 1 && nf.n_js_destroy == 1 && nf.n_kv_destroy == 1,
		"attendant destroyed its connection, JetStream context and KV "
		"handle before fork");
	ok(nf.n_close == 1, "attendant closed the nats.c library before fork");
	ok(nf.seq_kv_destroy < nf.seq_js_destroy
		&& nf.seq_js_destroy < nf.seq_conn_destroy,
		"...the handles before what they depend on");
	ok(nats_pool_get_reconnect_epoch() == epoch0 + 1,
		"reconnect epoch bumped (cached KV handles get refreshed)");
	ok(!nats_pool_is_connected(), "attendant no longer connected");
	ok(nats_pool_is_registered(),
		"the registration stays: the servers are the children's too");

	/* a fork with nothing open does nothing */
	fork_and_wait();
	ok(nf.n_conn_destroy == 1 && nf.n_close == 1, "no second teardown");

	/* the attendant can connect again, and is torn down again */
	ok(nats_pool_get() != NULL && nf.n_connect == 2 && nf.n_open == 2,
		"attendant connects again when asked to");
	fork_and_wait();
	ok(nf.n_conn_destroy == 2 && nf.n_close == 2,
		"...and that connection is closed before the next fork");

	nats_ut_end();
}
