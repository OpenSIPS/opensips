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
 * The publish counters of the module: one slot per process in shared
 * memory, each counter atomic -- a slot has two writers, the process and
 * the libnats thread that delivers the JetStream acks -- and summed over
 * the slots for the nats_stats MI command.
 *
 * The module's own table and bump macro, from the process the tests run
 * in and from threads of it.
 */

#include <tap.h>
#include <stdalign.h>
#include <string.h>
#include <pthread.h>

#include "../../../mi/mi.h"
#include "../../../lib/cJSON.h"
#include "../../nats/nats_bind.h"
#include "../../nats/nats_js_retry.h"
#include "../nats_stats.h"
#include "../event_nats.h"
#include "../event_nats_sub.h"

#include "en_ut.h"
#include "en_ut_stats.h"

/* a slot is whole cache lines, so no process writes on another's line */
_Static_assert(alignof(nats_stats_t) == 64, "a stats slot is cache-line aligned");
_Static_assert(sizeof(nats_stats_t) % 64 == 0, "a stats slot fills its cache lines");

#define THREADS 8
#define BUMPS   100000

static void *bump_published(void *arg)
{
	int i;

	(void)arg;
	for (i = 0; i < BUMPS; i++)
		NATS_STATS_BUMP(published);
	return NULL;
}

static void *bump_ack_ok(void *arg)
{
	int i;

	(void)arg;
	for (i = 0; i < BUMPS; i++)
		event_nats_test_js_ack_cb(NATS_PUB_ACK_OK);
	return NULL;
}

/* a member of the nats_stats MI reply, -1 if it is not a number */
static double mi_number(mi_response_t *resp, const char *name)
{
	cJSON *result = cJSON_GetObjectItem(resp, "result");
	cJSON *item = result ? cJSON_GetObjectItem(result, name) : NULL;

	return item && (item->type & cJSON_Number) ? item->valuedouble : -1;
}

static const char *mi_string(mi_response_t *resp, const char *name)
{
	cJSON *result = cJSON_GetObjectItem(resp, "result");
	cJSON *item = result ? cJSON_GetObjectItem(result, name) : NULL;

	return item && (item->type & cJSON_String) ? item->valuestring : "(none)";
}

void en_ut_stats(void)
{
	struct en_ut_counters c;
	pthread_t th[THREADS];
	mi_response_t *resp;
	nats_stats_t *slot = nats_stats_slot();
	int i, saved_no;

	ok(nats_stats != NULL, "the stats table exists");
	ok(slot == &nats_stats[process_no], "a process bumps its own slot");

	/* one bump, one count: in the slot and in the sum */
	c = en_ut_counters_now();
	NATS_STATS_BUMP(published);
	NATS_STATS_BUMP(failed);
	NATS_STATS_BUMP(failed);
	ok(en_ut_counters_added(c, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0),
		"a bump adds one to its counter and to no other");

	/* the sum is over every process */
	c = en_ut_counters_now();
	atomic_fetch_add(&nats_stats[NATS_STATS_MAX_PROCS - 1].js_retried, 5);
	atomic_fetch_add(&nats_stats[0].js_retried, 2);
	ok(en_ut_counters_added(c, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0),
		"the sum takes in the first and the last slot");
	atomic_fetch_sub(&nats_stats[NATS_STATS_MAX_PROCS - 1].js_retried, 5);
	atomic_fetch_sub(&nats_stats[0].js_retried, 2);

	/* a process past the table is not counted, and writes nowhere */
	saved_no = process_no;
	c = en_ut_counters_now();
	process_no = NATS_STATS_MAX_PROCS;
	ok(nats_stats_slot() == NULL, "no slot past the table");
	NATS_STATS_BUMP(published);
	process_no = -1;
	ok(nats_stats_slot() == NULL, "no slot for a negative process number");
	NATS_STATS_BUMP(published);
	process_no = saved_no;
	ok(en_ut_counters_added(c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
		"...and a bump from there changes nothing");

	/* two kinds of writer on one slot: nothing is lost */
	c = en_ut_counters_now();
	for (i = 0; i < THREADS; i++)
		if (pthread_create(&th[i], NULL,
		    i % 2 ? bump_published : bump_ack_ok, NULL) != 0)
			BAIL_OUT("pthread_create failed");
	for (i = 0; i < THREADS; i++)
		pthread_join(th[i], NULL);
	ok(en_ut_counters_added(c, (unsigned long)THREADS / 2 * BUMPS, 0, 0, 0,
		(unsigned long)THREADS / 2 * BUMPS, 0, 0, 0, 0, 0),
		"%d threads x %d bumps on one slot: every bump counted",
		THREADS, BUMPS);

	/* the JetStream ack outcomes */
	c = en_ut_counters_now();
	event_nats_test_js_ack_cb(NATS_PUB_ACK_OK);
	ok(en_ut_counters_added(c, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0),
		"ack stored: js_ack_ok");
	c = en_ut_counters_now();
	event_nats_test_js_ack_cb(NATS_PUB_ACK_DUPLICATE);
	ok(en_ut_counters_added(c, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0),
		"ack of a duplicate: js_ack_ok and js_duplicate");
	c = en_ut_counters_now();
	event_nats_test_js_ack_cb(NATS_PUB_ACK_RETRIED);
	ok(en_ut_counters_added(c, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0),
		"resent: js_retried only (the message is not failed yet)");
	c = en_ut_counters_now();
	event_nats_test_js_ack_cb(NATS_PUB_ACK_FAILED);
	ok(en_ut_counters_added(c, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0),
		"failed: js_ack_failed");
	c = en_ut_counters_now();
	event_nats_test_js_ack_cb(NATS_PUB_ACK_FAILED_BUFFER_FULL);
	ok(en_ut_counters_added(c, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0),
		"resend refused by the reconnect buffer: js_ack_failed and "
		"reconnect_buf_dropped");
	c = en_ut_counters_now();
	event_nats_test_js_ack_cb(NATS_PUB_ACK_FAILED_PENDING_FULL);
	ok(en_ut_counters_added(c, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1),
		"resend refused by the pending cap: js_ack_failed and "
		"js_pending_dropped");
	c = en_ut_counters_now();
	event_nats_test_js_ack_cb(9999);
	event_nats_test_js_ack_cb(-1);
	ok(en_ut_counters_added(c, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0),
		"an outcome the module does not know counts as failed");

	/* the MI commands report the sums, and the pool's reconnect count */
	en_ut_begin();
	ef.epoch = 3;
	ef.connected = 1;
	c = en_ut_counters_now();
	resp = mi_nats_stats(NULL, NULL);
	ok(resp != NULL, "nats_stats answers");
	if (resp) {
		ok(mi_number(resp, "published") == (double)c.published
			&& mi_number(resp, "failed") == (double)c.failed
			&& mi_number(resp, "evi_published") == (double)c.evi_published
			&& mi_number(resp, "script_published")
				== (double)c.script_published,
			"nats_stats: the publish counters");
		ok(mi_number(resp, "js_ack_ok") == (double)c.js_ack_ok
			&& mi_number(resp, "js_ack_failed") == (double)c.js_ack_failed
			&& mi_number(resp, "js_retried") == (double)c.js_retried
			&& mi_number(resp, "js_duplicate") == (double)c.js_duplicate
			&& mi_number(resp, "reconnect_buf_dropped")
				== (double)c.reconnect_buf_dropped
			&& mi_number(resp, "js_pending_dropped")
				== (double)c.js_pending_dropped,
			"nats_stats: the JetStream ack counters");
		ok(mi_number(resp, "reconnects") == 3,
			"nats_stats: reconnects is the pool's reconnect epoch");
		ok(mi_number(resp, "inbound_dropped_oversize")
				== (double)nats_inbound_dropped_oversize()
			&& mi_number(resp, "inbound_dropped_backpressure")
				== (double)nats_inbound_dropped_backpressure()
			&& mi_number(resp, "inbound_inflight")
				== (double)nats_inbound_inflight(),
			"nats_stats: the inbound drop counters and in-flight gauge");
		free_mi_response(resp);
	} else {
		skip(1, 4, "no nats_stats reply");
		end_skip;
	}

	resp = mi_nats_status(NULL, NULL);
	ok(resp != NULL, "nats_status answers");
	if (resp) {
		is(mi_string(resp, "connected"), "yes", "nats_status: connected");
		is(mi_string(resp, "server"), "nats://fake:4222",
			"nats_status: the server of the pool");
		is(mi_string(resp, "jetstream"),
			nats_jetstream ? "enabled" : "disabled",
			"nats_status: jetstream as configured");
		free_mi_response(resp);
	}
	ef.connected = 0;
	resp = mi_nats_status(NULL, NULL);
	if (resp) {
		is(mi_string(resp, "connected"), "no", "nats_status: not connected");
		free_mi_response(resp);
	} else {
		fail("nats_status: not connected");
	}
	en_ut_end();
}
