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
 * The module's health and statistics MI commands, called as an MI client
 * would.  Replaces tests/test_consumer_heartbeat.c (the stale arithmetic
 * carried over, plus greps) and tests/test_consumer_stats_mi.c (the
 * aggregation carried over, plus greps).
 *
 *  - nats_consumer_health reads the heartbeat the consumer process ticks
 *    every loop, so a watchdog can tell a wedged or dead consumer process
 *    (workers would wait on its ring forever) from a live one: stale when
 *    the last tick is more than 5 s old, or never came.
 *  - nats_consumer_stats sums the per-handle counters over the registry
 *    and adds the ack / RPC IPC and slot counters.
 */

#include <tap.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../../../mi/mi.h"
#include "../../../lib/cJSON.h"
#include "../../../pt.h"
#include "../nats_handle_registry.h"
#include "../nats_handle_parse.h"
#include "../nats_ring.h"
#include "../nats_mi.h"
#include "../nats_ack_ipc.h"
#include "../nats_consumer_proc.h"

#include "nc_ut.h"

static cJSON *field(mi_response_t *resp, const char *name)
{
	cJSON *result = resp ? cJSON_GetObjectItem(resp, "result") : NULL;

	return result ? cJSON_GetObjectItem(result, name) : NULL;
}

static double number(mi_response_t *resp, const char *name)
{
	cJSON *i = field(resp, name);

	return i && (i->type & cJSON_Number) ? i->valuedouble : -12345;
}

static const char *string(mi_response_t *resp, const char *name)
{
	cJSON *i = field(resp, name);

	return i && (i->type & cJSON_String) ? i->valuestring : "(none)";
}

static long long now_us(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000000LL + ts.tv_nsec / 1000;
}

static int consumer_pid(void)
{
	int i;

	for (i = 0; i < counted_max_processes; i++)
		if (pt[i].pid > 0 && strcmp(pt[i].desc, "NATS consumer") == 0)
			return pt[i].pid;
	return 0;
}

/* the health answer for a heartbeat block whose last tick was `ago_us`
 * ago (-1: never ticked; -2: no block at all) */
static mi_response_t *health_of(long long ago_us)
{
	static nats_consumer_heartbeat_t hb;
	nats_consumer_heartbeat_t *real = nats_consumer_hb;
	mi_response_t *resp;

	memset(&hb, 0, sizeof hb);
	atomic_store(&hb.consumer_pid, 4242);
	atomic_store(&hb.tick, 7);
	if (ago_us >= 0)
		atomic_store(&hb.last_tick_us, now_us() - ago_us);
	nats_consumer_hb = ago_us == -2 ? NULL : &hb;   /* this process only */
	resp = mi_consumer_health(NULL, NULL);
	nats_consumer_hb = real;
	return resp;
}

static void health(void)
{
	mi_response_t *r1, *r2;
	double t1, t2;
	int i;

	ok(lookup_mi_cmd("nats_consumer_health", 20) != NULL,
		"mi: nats_consumer_health is registered");
	r1 = mi_consumer_health(NULL, NULL);
	ok(number(r1, "consumer_pid") == consumer_pid() && consumer_pid() > 0,
		"mi: health names the running consumer process");
	ok(strcmp(string(r1, "stale"), "false") == 0 &&
		number(r1, "last_tick_ms_ago") >= 0 && number(r1, "last_tick_ms_ago") < 2000,
		"mi: its heartbeat is fresh");
	t1 = number(r1, "tick");
	free_mi_response(r1);
	/* the idle loop ticks at least once a second */
	for (i = 0, t2 = t1; i < 25 && t2 <= t1; i++) {
		usleep(100 * 1000);
		r2 = mi_consumer_health(NULL, NULL);
		t2 = number(r2, "tick");
		free_mi_response(r2);
	}
	ok(t2 > t1, "mi: and its tick advances (%.0f -> %.0f)", t1, t2);

	r1 = health_of(6000000LL);
	ok(strcmp(string(r1, "stale"), "true") == 0 &&
		number(r1, "last_tick_ms_ago") >= 6000 && number(r1, "tick") == 7 &&
		number(r1, "consumer_pid") == 4242,
		"mi: a tick 6 s old is stale");
	free_mi_response(r1);
	r1 = health_of(1000000LL);
	ok(strcmp(string(r1, "stale"), "false") == 0,
		"mi: a tick 1 s old is not");
	free_mi_response(r1);
	r1 = health_of(-1);
	ok(strcmp(string(r1, "stale"), "true") == 0 &&
		number(r1, "last_tick_ms_ago") == -1,
		"mi: a consumer that never ticked is stale");
	free_mi_response(r1);
	r1 = health_of(-2);
	ok(strcmp(string(r1, "error"), "(none)") != 0,
		"mi: no heartbeat block is reported as an error");
	free_mi_response(r1);
}

static nats_handle_t *bound(const char *id_s)
{
	char buf[96];
	str cfg;
	const char *err = NULL;
	nats_handle_t *h;

	snprintf(buf, sizeof buf, "id=%s;stream=S;durable=d;ring_capacity=4", id_s);
	cfg.s = buf;
	cfg.len = (int)strlen(buf);
	h = nats_handle_parse(&cfg, &err);
	if (h && nats_registry_bind(h) != 0) {
		nats_handle_free(h);
		h = NULL;
	}
	return h;
}

static void unbind(const char *id_s)
{
	str id = { (char *)id_s, (int)strlen(id_s) };
	nats_handle_t *h;

	nats_registry_unbind(&id);
	h = nats_registry_lookup_weak(&id);
	if (h)
		__atomic_store_n(&h->sub_torn_down, 1, __ATOMIC_SEQ_CST);
	nats_registry_reap();
}

static void stats(void)
{
	static const char *keys[] = { "handles", "ring_depth", "ring_capacity",
		"msgs_delivered", "acks", "terms", "poisoned", "fetch_skips_full",
		"backpressure_drops", "fetch_errors" };
	double before[10], after[10];
	nats_handle_t *a, *b;
	nats_ring_msg_t m;
	mi_response_t *resp;
	unsigned i;

	ok(lookup_mi_cmd("nats_consumer_stats", 19) != NULL,
		"mi: nats_consumer_stats is registered");
	resp = mi_consumer_stats(NULL, NULL);
	for (i = 0; i < 10; i++)
		before[i] = number(resp, keys[i]);
	free_mi_response(resp);

	a = bound("ut_mi_a");
	b = bound("ut_mi_b");
	ok(a && b, "mi: two handles bind");
	if (!a || !b)
		return;
	a->msgs_delivered = 5;     b->msgs_delivered = 7;
	a->acks = 2;               b->acks = 3;
	a->terms = 1;              b->terms = 4;
	a->poisoned = 1;
	a->fetch_skips_full = 6;
	b->backpressure_drops = 8;
	a->fetch_errors = 2;       b->fetch_errors = 1;
	memset(&m, 0, sizeof m);
	m.subject = "s";
	m.subject_len = 1;
	nats_ring_push(a->ring, &m);
	nats_ring_push(b->ring, &m);
	nats_ring_push(b->ring, &m);

	resp = mi_consumer_stats(NULL, NULL);
	for (i = 0; i < 10; i++)
		after[i] = number(resp, keys[i]);
	ok(after[0] - before[0] == 2, "mi: stats counts the two handles");
	ok(after[1] - before[1] == 3 && after[2] - before[2] == 8,
		"mi: and sums their ring depth (3) and capacity (8)");
	ok(after[3] - before[3] == 12 && after[4] - before[4] == 5 &&
		after[5] - before[5] == 5 && after[6] - before[6] == 1,
		"mi: delivered, acks, terms and poisoned are summed");
	ok(after[7] - before[7] == 6 && after[8] - before[8] == 8 &&
		after[9] - before[9] == 3,
		"mi: skips, back-pressure drops and fetch errors are summed apart");
	ok(number(resp, "ack_ipc_dropped") == (double)nats_ack_ipc_dropped_total() &&
		number(resp, "ack_ipc_depth") == (double)nats_ack_ipc_depth(),
		"mi: the ack IPC counters are the module's");
	free_mi_response(resp);

	unbind("ut_mi_a");
	unbind("ut_mi_b");
}

void nc_ut_mi(void)
{
	health();
}

void nc_ut_mi_stats(void)
{
	stats();
}
