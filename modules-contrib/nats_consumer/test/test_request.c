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
 * The request/reply script functions, up to the point where they would
 * reach the broker.  Replaces tests/test_rpc_subject_validation.c,
 * tests/test_request_fastfail.c and tests/test_async_request_skeleton.c
 * (greps of the function bodies and the export table):
 *  - a subject is checked before it reaches the wire: CR/LF (protocol
 *    injection), whitespace and wildcards are refused, as are an empty or
 *    an over-long one -- for nats_request, the async form, and the
 *    reply-to nats_reply answers on (it came from the broker);
 *  - with the pool disconnected a request fails at once instead of
 *    blocking its process for the whole timeout, says so once per 30 s
 *    rather than per call, and the async form claims no RPC slot;
 *  - the async form is exported as an async command, for script routes.
 */

#include <tap.h>
#include <string.h>
#include <time.h>

#include "../../../async.h"
#include "../../../sr_module.h"
#include "../nats_ring.h"
#include "../nats_rpc.h"
#include "../nats_rpc_async.h"
#include "../nats_rpc_slot.h"

#include "nc_ut.h"

static char dummy_nc;

static long long ms_now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int request_on(const char *subject_s, int connected,
	natsConnection *nc)
{
	str subject = { (char *)subject_s, (int)strlen(subject_s) };
	str payload = str_init("ping");
	int tmo = 5000, rc;

	nf.connected = connected;
	nf.pool_nc = nc;
	rc = w_nats_request(NULL, &subject, &payload, &tmo);
	return rc;
}

static int request(const char *subject_s, int connected)
{
	return request_on(subject_s, connected, (natsConnection *)&dummy_nc);
}

static void sync_request(void)
{
	char longest[NATS_RING_SUBJECT_MAX + 2];
	long long t0;
	int rc;

	nc_ut_begin();
	ok(request("svc.a\r\nPUB evil 1", 1) == -4 && nf.n_request == 0,
		"request: a subject with CR/LF is refused");
	ok(request("svc a", 1) == -4, "request: a subject with a space is refused");
	ok(request("svc.*", 1) == -4 && request("svc.>", 1) == -4,
		"request: a wildcard subject is refused");
	ok(request("", 1) == -4, "request: an empty subject is refused");
	memset(longest, 'a', sizeof longest - 1);
	longest[sizeof longest - 1] = '\0';
	ok(request(longest, 1) == -4, "request: an over-long subject is refused");
	ok(nf.n_request == 0 && nf.n_msg_create == 0,
		"request: none of them got as far as building a message");

	t0 = ms_now();
	rc = request("svc.echo", 0);
	ok(rc == -3 && ms_now() - t0 < 1000 && nf.n_request == 0,
		"request: disconnected, it fails at once without the blocking request");
	ok(strstr(nc_ut_log(), "failing fast") != NULL,
		"request: and warns about it");
	nc_ut_log_clear();
	request("svc.echo", 0);
	ok(strstr(nc_ut_log(), "failing fast") == NULL,
		"request: the warning is not repeated within 30 s");
	ok(request_on("svc.echo", 1, NULL) == -3 && nf.n_request == 0,
		"request: no connection object is refused");
	nc_ut_end();
}

static void reply_to(void)
{
	nats_ring_slot_t slot;
	str payload = str_init("pong");

	memset(&slot, 0, sizeof slot);
	slot.has_reply = 1;
	memcpy(slot.reply_to, "_INBOX.x\r\nPUB evil", 18);
	slot.reply_to_len = 18;
	nc_ut_cur_set(0, &slot);
	nc_ut_begin();
	nf.pool_nc = (natsConnection *)&dummy_nc;
	ok(w_nats_reply(NULL, &payload) == -4 && nf.n_msg_create == 0,
		"request: nats_reply refuses a reply-to with CR/LF");

	memcpy(slot.reply_to, "_INBOX.ok.1", 11);
	slot.reply_to_len = 11;
	nc_ut_cur_set(0, &slot);
	w_nats_reply(NULL, &payload);
	ok(nf.n_msg_create == 1, "request: a clean reply-to reaches the publish");
	nc_ut_end();
}

void nc_ut_request(void)
{
	sync_request();
	reply_to();
}

static int request_async(const char *subject_s, int connected)
{
	str subject = { (char *)subject_s, (int)strlen(subject_s) };
	str payload = str_init("ping");
	int tmo = 5000;

	nf.connected = connected;
	nf.pool_nc = (natsConnection *)&dummy_nc;
	async_status = ASYNC_NO_IO;   /* as the core sets it before the call */
	return w_nats_request_async(NULL, NULL, &subject, &payload, &tmo);
}

void nc_ut_request_async(void)
{
	uint32_t inflight = nats_rpc_slot_inflight_count();
	long long t0;

	ok(find_mod_acmd_export_t("nats_request") != NULL,
		"request: nats_request is exported as an async command");

	nc_ut_begin();
	ok(request_async("svc.a\r\nPUB evil 1", 1) == -4 &&
		async_status == ASYNC_NO_IO,
		"request: async, a subject with CR/LF is refused");
	ok(request_async("svc.*", 1) == -4, "request: async, a wildcard is refused");
	t0 = ms_now();
	ok(request_async("svc.echo", 0) == -2 && ms_now() - t0 < 1000 &&
		async_status == ASYNC_NO_IO,
		"request: async, disconnected, it fails at once");
	ok(nats_rpc_slot_inflight_count() == inflight,
		"request: async, and claims no slot");
	nc_ut_end();
}
