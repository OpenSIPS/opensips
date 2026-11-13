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
 * The first connect of the shared pool:
 *
 *   - with the broker down at startup the process does not sit in a retry
 *     loop: libnats is told to keep dialing in the background
 *     (natsOptions_SetRetryOnFailedConnect) and the pool continues
 *     degraded, to be marked connected by the first-connect callback;
 *   - libnats reports a refused password or TLS handshake the same way
 *     (it keeps dialing), so the warning names those causes too;
 *   - a failure no retry can cure that libnats does return (TLS
 *     material, credentials, malformed options) ends the attempt at
 *     once, any other one is retried
 *     max_reconnect times with a per-process jitter on the wait;
 *   - a dead link is noticed in about 20 s (ping interval, pings out) and
 *     the processes do not reconnect in lockstep (reconnect jitter);
 *   - JetStream and KV requests wait kv_op_timeout_ms (1 s by default).
 *
 * The real pool (nats_pool.c) against the fake libnats of nats_ut_fake.c.
 */

#include <tap.h>
#include <string.h>
#include <unistd.h>

#include "../nats_pool.h"

#include "nats_ut.h"
#include "nats_ut_fake.h"

static int reg(void)
{
	return nats_pool_register("nats://127.0.0.1:4222", "test", 2000, 3);
}

/* ── broker down at startup ─────────────────────────────────────── */

static int s_background_connect_asked(void)
{
	/* the first-connect callback is the reconnected one: it marks the
	 * pool connected, bumps the epoch and makes the KV handles stale */
	return reg() == 0 && nats_pool_get() != NULL
		&& nf.last_retry_on_failed == 1
		&& nf.retry_cb != NULL && nf.retry_cb == nf.reconnected_cb;
}

static int s_broker_down_degraded(void)
{
	nf.connect_status = NATS_NOT_YET_CONNECTED;
	return reg() == 0
		&& nats_pool_get() != NULL          /* the dialing connection */
		&& nf.n_connect == 1 && nf.n_sleep == 0
		&& !nats_pool_is_connected()
		&& strstr(nats_ut_log(), "continuing degraded") != NULL
		&& strstr(nats_ut_log(), "connection attempt") == NULL;
}

/* With SetRetryOnFailedConnect libnats answers NOT_YET_CONNECTED, and
 * reports nothing more, for a refused password or TLS handshake too
 * (checked against nats-server 2.11 with nats.c 3.15): the warning must
 * not claim the broker is unreachable. */
static int s_not_connected_names_both_causes(void)
{
	nf.connect_status = NATS_NOT_YET_CONNECTED;
	return reg() == 0 && nats_pool_get() != NULL
		&& strstr(nats_ut_log(), "not connected at startup") != NULL
		&& strstr(nats_ut_log(), "credentials") != NULL
		&& strstr(nats_ut_log(), "TLS") != NULL
		&& strstr(nats_ut_log(), "broker unreachable at startup") == NULL;
}

static int s_broker_down_not_redialed_by_get(void)
{
	nf.connect_status = NATS_NOT_YET_CONNECTED;
	if (reg() != 0 || nats_pool_get() == NULL)
		return 0;
	/* later calls hand out the same connection: libnats is dialing */
	return nats_pool_get() != NULL && nats_pool_get() != NULL
		&& nf.n_connect == 1;
}

static int s_broker_appears(void)
{
	int epoch;

	nf.connect_status = NATS_NOT_YET_CONNECTED;
	if (reg() != 0 || nats_pool_get() == NULL || nats_pool_is_connected())
		return 0;
	epoch = nats_pool_get_reconnect_epoch();
	nf.retry_cb(nats_pool_get(), NULL);
	return nats_pool_is_connected()
		&& nats_pool_get_reconnect_epoch() == epoch + 1;
}

static int s_connected_at_once(void)
{
	return reg() == 0 && nats_pool_get() != NULL
		&& nats_pool_is_connected() && nf.n_connect == 1;
}

/* ── failures of the first connect ──────────────────────────────── */

static int no_retry(natsStatus s)
{
	nf.connect_status = s;
	return reg() == 0 && nats_pool_get() == NULL
		&& nf.n_connect == 1 && nf.n_sleep == 0
		&& !nats_pool_is_connected()
		&& strstr(nats_ut_log(), "not retrying") != NULL;
}

static int s_tls_error_not_retried(void)
{ return no_retry(NATS_SSL_ERROR); }
static int s_auth_error_not_retried(void)
{ return no_retry(NATS_CONNECTION_AUTH_FAILED); }
static int s_invalid_arg_not_retried(void)
{ return no_retry(NATS_INVALID_ARG); }

static int s_other_error_retried_bounded(void)
{
	/* max_reconnect = 3: three attempts, a wait between them */
	nf.connect_status = NATS_IO_ERROR;
	return reg() == 0 && nats_pool_get() == NULL
		&& nf.n_connect == 3 && nf.n_sleep == 2
		&& strstr(nats_ut_log(), "connection attempt 3/3") != NULL
		&& strstr(nats_ut_log(), "giving up after 3 attempts") != NULL
		&& strstr(nats_ut_log(), "not retrying") == NULL;
}

static int s_retry_wait_has_process_jitter(void)
{
	/* reconnect_wait plus up to half of it, from the pid: processes
	 * started together do not retry together */
	long long each = 2000 + (long long)((unsigned)getpid() % 1001u);

	nf.connect_status = NATS_IO_ERROR;
	return reg() == 0 && nats_pool_get() == NULL
		&& nf.n_sleep == 2 && nf.slept_ms == 2 * each;
}

static int s_error_detail_logged(void)
{
	nf.connect_status = NATS_SSL_ERROR;
	nf.err_stack = "certificate verify failed";
	return reg() == 0 && nats_pool_get() == NULL
		&& strstr(nats_ut_log(), "certificate verify failed") != NULL;
}

/* ── liveness and reconnects ────────────────────────────────────── */

static int s_ping_liveness(void)
{
	/* 10 s x 2 missed pings: a black-holed broker is declared dead in
	 * about 20 s instead of the libnats 4 minutes */
	return reg() == 0 && nats_pool_get() != NULL
		&& nf.last_ping_interval == 10000 && nf.last_max_pings_out == 2;
}

static int s_reconnect_jitter(void)
{
	/* up to one reconnect_wait of jitter, with and without TLS */
	return nats_pool_register("nats://127.0.0.1:4222", "test", 1500, 3) == 0
		&& nats_pool_get() != NULL
		&& nf.last_reconnect_wait == 1500
		&& nf.last_jitter == 1500 && nf.last_jitter_tls == 1500;
}

static int s_reconnect_unlimited(void)
{
	/* max_reconnect bounds the startup attempts only: libnats drops a
	 * server for good after its own limit */
	return reg() == 0 && nats_pool_get() != NULL
		&& nf.last_max_reconnect == -1;
}

static int s_disconnect_reconnect(void)
{
	int epoch;

	if (reg() != 0 || nats_pool_get() == NULL || !nats_pool_is_connected())
		return 0;
	epoch = nats_pool_get_reconnect_epoch();
	nf.disconnected_cb(nats_pool_get(), NULL);
	if (nats_pool_is_connected() ||
	    nats_pool_get_reconnect_epoch() != epoch)
		return 0;
	nf.reconnected_cb(nats_pool_get(), NULL);
	return nats_pool_is_connected()
		&& nats_pool_get_reconnect_epoch() == epoch + 1;
}

/* ── request timeout ────────────────────────────────────────────── */

static int s_kv_op_timeout_default(void)
{
	/* two KV round trips per REGISTER: the libnats 5 s default would
	 * hold a SIP worker for 10 s */
	return nats_pool_kv_op_timeout_ms == 1000
		&& reg() == 0 && nats_pool_get_js() != NULL
		&& nf.js_wait == 1000;
}

static int s_kv_op_timeout_set(void)
{
	nats_pool_kv_op_timeout_ms = 250;
	return reg() == 0 && nats_pool_get_js() != NULL && nf.js_wait == 250;
}

static int s_kv_op_timeout_library_default(void)
{
	/* zero or below: libnats keeps its own default */
	nats_pool_kv_op_timeout_ms = 0;
	return reg() == 0 && nats_pool_get_js() != NULL && nf.js_wait == 0;
}

void nats_ut_pool_connect(void)
{
	/* broker down at startup */
	nats_ut_run("libnats is asked to keep dialing in the background",
		s_background_connect_asked);
	nats_ut_run("broker down: degraded start, no retry loop, no sleep",
		s_broker_down_degraded);
	nats_ut_run("not connected at startup: the warning names refused "
		"credentials or TLS as well as a down broker",
		s_not_connected_names_both_causes);
	nats_ut_run("broker down: later calls do not connect again",
		s_broker_down_not_redialed_by_get);
	nats_ut_run("broker appears: the first-connect callback marks the "
		"pool connected and bumps the epoch", s_broker_appears);
	nats_ut_run("broker up: connected by the first attempt",
		s_connected_at_once);

	/* failures of the first connect */
	nats_ut_run("TLS error: not retried", s_tls_error_not_retried);
	nats_ut_run("authentication failure: not retried",
		s_auth_error_not_retried);
	nats_ut_run("invalid argument: not retried", s_invalid_arg_not_retried);
	nats_ut_run("any other error: max_reconnect attempts, then give up",
		s_other_error_retried_bounded);
	nats_ut_run("the wait between attempts has a per-process jitter",
		s_retry_wait_has_process_jitter);
	nats_ut_run("the libnats error detail is logged", s_error_detail_logged);

	/* liveness and reconnects */
	nats_ut_run("ping interval 10 s, 2 pings out", s_ping_liveness);
	nats_ut_run("reconnect wait and jitter reach libnats", s_reconnect_jitter);
	nats_ut_run("reconnects after the first connect are unlimited",
		s_reconnect_unlimited);
	nats_ut_run("disconnect, then reconnect: connected flag and epoch",
		s_disconnect_reconnect);

	/* request timeout */
	nats_ut_run("kv_op_timeout_ms: 1000 ms by default, handed to libnats",
		s_kv_op_timeout_default);
	nats_ut_run("kv_op_timeout_ms: a set value reaches libnats",
		s_kv_op_timeout_set);
	nats_ut_run("kv_op_timeout_ms: 0 keeps the libnats default",
		s_kv_op_timeout_library_default);
}
