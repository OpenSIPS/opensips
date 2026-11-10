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
 * Life time of the shared pool: every module that registers holds it, and
 * it is closed when the last one unregisters -- not earlier, whichever
 * module goes first, and always.  On the way down the KV handles go first,
 * then the JetStream context -- after a bounded wait for the acks of the
 * messages published just before -- then the drained connection.
 *
 * The real pool (nats_pool.c) against the fake libnats of nats_ut_fake.c,
 * which numbers the teardown calls in the order they arrive.
 */

#include <tap.h>
#include <string.h>

#include "../../../sr_module.h"
#include "../nats_pool.h"

#include "nats_ut.h"
#include "nats_ut_fake.h"

static int reg(const char *module)
{
	return nats_pool_register("nats://127.0.0.1:4222", module, 2000, 3);
}

static int open_all(void)
{
	return reg("event_nats") == 0 && reg("cachedb_nats") == 0
		&& reg("nats_consumer") == 0
		&& nats_pool_get() != NULL && nats_pool_get_js() != NULL
		&& nats_pool_get_kv("bucket", 1, 1, 0) != NULL;
}

static int s_last_unregister_closes(void)
{
	if (!open_all())
		return 0;
	nats_pool_unregister();
	if (nf.n_conn_destroy || nf.n_js_destroy || nf.n_kv_destroy
	    || !nats_pool_is_registered() || nats_pool_get() == NULL)
		return 0;
	nats_pool_unregister();
	if (nf.n_conn_destroy || !nats_pool_is_registered()
	    || !nats_pool_is_connected())
		return 0;
	nats_pool_unregister();
	return nf.n_conn_destroy == 1 && nf.n_js_destroy == 1
		&& nf.n_kv_destroy == 1 && !nats_pool_is_registered()
		&& !nats_pool_is_connected();
}

static int s_one_module_alone(void)
{
	/* closed although no other NATS module is loaded */
	if (reg("cachedb_nats") != 0 || nats_pool_get() == NULL)
		return 0;
	nats_pool_unregister();
	return nf.n_conn_destroy == 1 && !nats_pool_is_registered();
}

static int s_unregister_once_too_often(void)
{
	if (reg("event_nats") != 0 || nats_pool_get() == NULL)
		return 0;
	nats_pool_unregister();
	nats_pool_unregister();
	nats_pool_unregister();
	if (nf.n_conn_destroy != 1)
		return 0;
	/* and a module can register again afterwards */
	return reg("event_nats") == 0 && nats_pool_get() != NULL
		&& nf.n_connect == 2;
}

static int s_unregister_without_register(void)
{
	nats_pool_unregister();
	nats_pool_destroy();
	return nf.n_conn_destroy == 0 && nf.seq == 0
		&& !nats_pool_is_registered();
}

static int s_failed_register_holds_nothing(void)
{
	/* the refused registration is not counted: one unregister closes */
	if (reg("event_nats") != 0
	    || nats_pool_register("", "cachedb_nats", 2000, 3) != -1
	    || nats_pool_get() == NULL)
		return 0;
	nats_pool_unregister();
	return nf.n_conn_destroy == 1;
}

static int s_teardown_order(void)
{
	if (!open_all())
		return 0;
	nats_pool_destroy();
	return nf.seq_kv_destroy == 1
		&& nf.seq_async_complete == 2
		&& nf.seq_js_destroy == 3
		&& nf.seq_drain == 4
		&& nf.seq_conn_destroy == 5;
}

static int s_teardown_waits_drain_timeout(void)
{
	if (nats_pool_drain_timeout_setter(INT_PARAM, (void *)(long)1234) != 0
	    || !open_all())
		return 0;
	nats_pool_destroy();
	return nf.async_complete_wait == 1234 && nf.drain_wait == 1234;
}

static int s_teardown_zero_timeout_bounded(void)
{
	/* 0 would be "wait for ever" to libnats: 5 s instead */
	if (nats_pool_drain_timeout_setter(INT_PARAM, (void *)(long)0) != 0
	    || !open_all())
		return 0;
	nats_pool_destroy();
	return nf.async_complete_wait == 5000 && nf.drain_wait == 5000;
}

static int s_no_jetstream_no_ack_wait(void)
{
	if (reg("cachedb_nats") != 0 || nats_pool_get() == NULL)
		return 0;
	nats_pool_destroy();
	return nf.seq_async_complete == 0 && nf.n_js_destroy == 0
		&& nf.n_drain == 1 && nf.n_conn_destroy == 1;
}

void nats_ut_pool_refcount(void)
{
	nats_ut_run("three modules: only the last unregister closes the pool",
		s_last_unregister_closes);
	nats_ut_run("a single module closes it as well", s_one_module_alone);
	nats_ut_run("unregistering too often closes once; registering again works",
		s_unregister_once_too_often);
	nats_ut_run("unregister / destroy with nothing registered: no libnats call",
		s_unregister_without_register);
	nats_ut_run("a refused registration is not counted",
		s_failed_register_holds_nothing);
	nats_ut_run("teardown: KV handles, ack wait, JetStream, drain, connection",
		s_teardown_order);
	nats_ut_run("teardown waits drain_timeout_ms for acks and for the drain",
		s_teardown_waits_drain_timeout);
	nats_ut_run("drain_timeout_ms=0: bounded to 5 s", s_teardown_zero_timeout_bounded);
	nats_ut_run("no JetStream context: no ack wait", s_no_jetstream_no_ack_wait);
}
