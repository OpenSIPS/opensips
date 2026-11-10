/*
 * Copyright (C) 2026 OpenSIPS Solutions
 * Copyright (C) 2026 Norm Brandinger <n.brandinger@gmail.com>
 *
 * This file is part of opensips, a free SIP server.
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
 */

/*
 * test_parser.c -- unit tests for the bind-parameter parser.
 */

#include <tap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../nats_handle_registry.h"
#include "../nats_handle_parse.h"

#include "nc_ut.h"


#define CHECK(cond) ok((cond), "parser:%d %s", __LINE__, #cond)

static str mkstr(const char *s)
{
	str r;
	r.s = (char *)s;       /* borrowed literal -- parser only reads */
	r.len = (int)strlen(s);
	return r;
}

static int str_contains(const str *s, const char *needle)
{
	int nlen = (int)strlen(needle);
	int i;
	if (s->len < nlen) return 0;
	for (i = 0; i + nlen <= s->len; i++)
		if (memcmp(s->s + i, needle, nlen) == 0)
			return 1;
	return 0;
}

/* ── cases ────────────────────────────────────────────────────── */

static void test_minimal_durable(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;stream=S;durable=d");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h != NULL);
	CHECK(err == NULL);
	if (h) {
		CHECK(h->type == NATS_CONSUMER_DURABLE);
		CHECK(h->id.len == 1 && h->id.s[0] == 'x');
		CHECK(h->stream.len == 1 && h->stream.s[0] == 'S');
		CHECK(h->durable.len == 1 && h->durable.s[0] == 'd');
		CHECK(h->deliver_policy == NATS_DELIVER_ALL);
		CHECK(h->ack_policy == NATS_ACK_EXPLICIT);
		nats_handle_free(h);
	}
}

static void test_ephemeral(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;stream=S;ephemeral=1");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h != NULL);
	if (h) {
		CHECK(h->type == NATS_CONSUMER_EPHEMERAL);
		CHECK(h->durable.len == 0);
		nats_handle_free(h);
	}
}

static void test_full_matrix(void)
{
	const char *err = NULL;
	str cfg = mkstr(
		"id=billing;stream=CALLS;durable=biller;"
		"filter=call.ended;ack_wait=30s;max_deliver=5;"
		"max_ack_pending=256;backoff=1s,5s,30s;deliver_policy=new");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h != NULL);
	if (h) {
		CHECK(h->ack_wait_ms == 30000);
		CHECK(h->max_deliver == 5);
		CHECK(h->max_ack_pending == 256);
		CHECK(h->deliver_policy == NATS_DELIVER_NEW);
		CHECK(h->backoff_csv.len == (int)strlen("1s,5s,30s"));
		CHECK(memcmp(h->backoff_csv.s, "1s,5s,30s", 9) == 0);
		CHECK(h->filter.len == (int)strlen("call.ended"));
		nats_handle_free(h);
	}
}

static void test_multi_filter(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;stream=S;durable=d;filters=a.*,b.*");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h != NULL);
	if (h) {
		CHECK(h->filters_csv.len > 0);
		CHECK(str_contains(&h->filters_csv, "a.*,b.*"));
		nats_handle_free(h);
	}
}

static void test_unknown_key(void)
{
	/* Since the persist layer was deleted nothing
	 * consumes forward-compat extras: an unknown key is now a CONFIG
	 * ERROR, rejected at parse time with a message naming the key. */
	const char *err = NULL;
	str cfg = mkstr("id=x;stream=S;durable=d;foo=bar");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h == NULL);
	CHECK(err != NULL && strstr(err, "unknown") != NULL);
	if (h) nats_handle_free(h);
}

/* Negative counts must be rejected at parse time -- previously a
 * negative max_deliver/max_ack_pending/rate_limit parsed "successfully"
 * and was silently treated as unset downstream. */
static void test_negative_counts_rejected(void)
{
	const char *cases[] = {
		"id=x;stream=S;durable=d;max_deliver=-1",
		"id=x;stream=S;durable=d;max_ack_pending=-5",
		"id=x;stream=S;durable=d;rate_limit=-1024",
		"id=x;stream=S;durable=d;sample_freq=-1",
	};
	unsigned i;
	for (i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
		const char *err = NULL;
		str cfg = mkstr(cases[i]);
		nats_handle_t *h = nats_handle_parse(&cfg, &err);
		CHECK(h == NULL);
		CHECK(err != NULL);
		if (h) nats_handle_free(h);
	}
}

static void test_two_unknowns(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;stream=S;durable=d;foo=bar;baz=qux");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h == NULL);
	if (h) nats_handle_free(h);
}

static void test_missing_id(void)
{
	const char *err = NULL;
	str cfg = mkstr("stream=S;durable=d");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h == NULL);
	CHECK(err && strstr(err, "missing id") != NULL);
}

static void test_missing_stream(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;durable=d");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h == NULL);
	CHECK(err && strstr(err, "missing stream") != NULL);
}

static void test_durable_and_ephemeral(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;stream=S;durable=d;ephemeral=1");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h == NULL);
	CHECK(err && strstr(err, "mutually exclusive") != NULL);
}

static void test_neither_durable_nor_ephemeral(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;stream=S;filter=a.*");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h == NULL);
	CHECK(err != NULL);
}

static void test_bad_duration(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;stream=S;durable=d;ack_wait=notaduration");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h == NULL);
	CHECK(err && strstr(err, "invalid duration") != NULL);
}

static void test_bad_deliver_policy(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;stream=S;durable=d;deliver_policy=bogus");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h == NULL);
	CHECK(err && strstr(err, "invalid deliver_policy") != NULL);
}

static void test_duplicate_key(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;id=y;stream=S;durable=d");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h == NULL);
	CHECK(err && strstr(err, "duplicate key") != NULL);
}

static void test_duration_variants(void)
{
	struct { const char *cfg; int expected_ms; } cases[] = {
		{ "id=x;stream=S;durable=d;ack_wait=500ms", 500 },
		{ "id=x;stream=S;durable=d;ack_wait=5s",    5000 },
		{ "id=x;stream=S;durable=d;ack_wait=2m",    120000 },
		{ "id=x;stream=S;durable=d;ack_wait=1h",    3600000 },
	};
	size_t i;
	for (i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
		const char *err = NULL;
		str cfg = mkstr(cases[i].cfg);
		nats_handle_t *h = nats_handle_parse(&cfg, &err);
		CHECK(h != NULL);
		if (h) {
			CHECK(h->ack_wait_ms == cases[i].expected_ms);
			nats_handle_free(h);
		}
	}
}

static void test_by_start_seq_requires_seq(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;stream=S;durable=d;deliver_policy=by_start_seq");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h == NULL);
	CHECK(err && strstr(err, "start_seq required") != NULL);
}

static void test_by_start_seq_ok(void)
{
	const char *err = NULL;
	str cfg = mkstr(
		"id=x;stream=S;durable=d;deliver_policy=by_start_seq;start_seq=4242");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h != NULL);
	if (h) {
		CHECK(h->deliver_policy == NATS_DELIVER_BY_START_SEQ);
		CHECK(h->start_seq == 4242);
		nats_handle_free(h);
	}
}

/* ── Extended bind-matrix coverage ─────────────────────────────── */

static void test_replay_policy_instant_default(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;stream=S;durable=d");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h != NULL);
	if (h) {
		CHECK(h->replay_policy == NATS_REPLAY_INSTANT);
		nats_handle_free(h);
	}
}

static void test_replay_policy_original(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;stream=S;durable=d;replay_policy=original");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h != NULL);
	if (h) {
		CHECK(h->replay_policy == NATS_REPLAY_ORIGINAL);
		nats_handle_free(h);
	}
}

static void test_replay_policy_bogus(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;stream=S;durable=d;replay_policy=fast");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h == NULL);
	CHECK(err && strstr(err, "invalid replay_policy") != NULL);
}

static void test_by_start_time_ok(void)
{
	const char *err = NULL;
	str cfg = mkstr(
		"id=x;stream=S;durable=d;deliver_policy=by_start_time;"
		"start_time=2026-04-16T12:00:00Z");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h != NULL);
	if (h) {
		CHECK(h->deliver_policy == NATS_DELIVER_BY_START_TIME);
		CHECK(h->start_time_unix_ns > 0);
		nats_handle_free(h);
	}
}

static void test_by_start_time_requires_time(void)
{
	const char *err = NULL;
	str cfg = mkstr(
		"id=x;stream=S;durable=d;deliver_policy=by_start_time");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h == NULL);
	CHECK(err && strstr(err, "start_time required") != NULL);
}

static void test_start_time_malformed(void)
{
	const char *err = NULL;
	str cfg = mkstr(
		"id=x;stream=S;durable=d;deliver_policy=by_start_time;"
		"start_time=not-a-time");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h == NULL);
	CHECK(err && strstr(err, "RFC3339") != NULL);
}

static void test_inactive_threshold(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;stream=S;durable=d;inactive_threshold=90s");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h != NULL);
	if (h) {
		CHECK(h->inactive_threshold_ms == 90000);
		nats_handle_free(h);
	}
}

static void test_rate_limit(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;stream=S;durable=d;rate_limit=1048576");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h != NULL);
	if (h) {
		CHECK(h->rate_limit_bps == 1048576);
		nats_handle_free(h);
	}
}

static void test_sample_freq_ok(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;stream=S;durable=d;sample_freq=25");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h != NULL);
	if (h) {
		CHECK(h->sample_freq == 25);
		nats_handle_free(h);
	}
}

static void test_sample_freq_out_of_range(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;stream=S;durable=d;sample_freq=101");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h == NULL);
	CHECK(err && strstr(err, "sample_freq") != NULL);
}

static void test_headers_only(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;stream=S;durable=d;headers_only=1");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h != NULL);
	if (h) {
		CHECK(h->headers_only == 1);
		nats_handle_free(h);
	}
}

static void test_js_domain_api_prefix(void)
{
	const char *err = NULL;
	str cfg = mkstr(
		"id=x;stream=S;durable=d;js_domain=hub;api_prefix=JSH.API.");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h != NULL);
	if (h) {
		CHECK(h->js_domain.len == 3);
		CHECK(memcmp(h->js_domain.s, "hub", 3) == 0);
		CHECK(h->api_prefix.len == (int)strlen("JSH.API."));
		CHECK(memcmp(h->api_prefix.s, "JSH.API.",
			strlen("JSH.API.")) == 0);
		nats_handle_free(h);
	}
}

static void test_max_ack_pending(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;stream=S;durable=d;max_ack_pending=1024");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h != NULL);
	if (h) {
		CHECK(h->max_ack_pending == 1024);
		nats_handle_free(h);
	}
}

static void test_ring_capacity_ok(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;stream=S;durable=d;ring_capacity=256");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h != NULL);
	if (h) {
		CHECK(h->ring_capacity == 256);
		nats_handle_free(h);
	}
}

static void test_ring_capacity_zero_rejected(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;stream=S;durable=d;ring_capacity=0");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h == NULL);
	CHECK(err && strstr(err, "ring_capacity") != NULL);
}

static void test_ring_capacity_not_pow2(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;stream=S;durable=d;ring_capacity=100");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h == NULL);
	CHECK(err && strstr(err, "power of two") != NULL);
}

static void test_fetch_batch_ok(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;stream=S;durable=d;fetch_batch=128");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h != NULL);
	if (h) {
		CHECK(h->fetch_batch == 128);
		nats_handle_free(h);
	}
}

static void test_fetch_batch_zero_rejected(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;stream=S;durable=d;fetch_batch=0");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h == NULL);
	CHECK(err && strstr(err, "fetch_batch") != NULL);
}

static void test_fetch_batch_too_big(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;stream=S;durable=d;fetch_batch=8192");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h == NULL);
	CHECK(err && strstr(err, "fetch_batch") != NULL);
}

static void test_fetch_timeout_ms_ok(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;stream=S;durable=d;fetch_timeout_ms=250");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h != NULL);
	if (h) {
		CHECK(h->fetch_timeout_ms == 250);
		nats_handle_free(h);
	}
}

static void test_fetch_timeout_ms_too_big(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;stream=S;durable=d;fetch_timeout_ms=120000");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h == NULL);
	CHECK(err && strstr(err, "fetch_timeout_ms") != NULL);
}

static void test_fetch_defaults_zero_when_unset(void)
{
	const char *err = NULL;
	str cfg = mkstr("id=x;stream=S;durable=d");
	nats_handle_t *h = nats_handle_parse(&cfg, &err);
	CHECK(h != NULL);
	if (h) {
		CHECK(h->fetch_batch == 0);        /* "use module default" */
		CHECK(h->fetch_timeout_ms == 0);   /* "use module default" */
		nats_handle_free(h);
	}
}

void nc_ut_parser(void)
{
	test_minimal_durable();
	test_ephemeral();
	test_full_matrix();
	test_multi_filter();
	test_unknown_key();
	test_two_unknowns();
	test_negative_counts_rejected();
	test_missing_id();
	test_missing_stream();
	test_durable_and_ephemeral();
	test_neither_durable_nor_ephemeral();
	test_bad_duration();
	test_bad_deliver_policy();
	test_duplicate_key();
	test_duration_variants();
	test_by_start_seq_requires_seq();
	test_by_start_seq_ok();

	/* Extended bind-matrix coverage */
	test_replay_policy_instant_default();
	test_replay_policy_original();
	test_replay_policy_bogus();
	test_by_start_time_ok();
	test_by_start_time_requires_time();
	test_start_time_malformed();
	test_inactive_threshold();
	test_rate_limit();
	test_sample_freq_ok();
	test_sample_freq_out_of_range();
	test_headers_only();
	test_js_domain_api_prefix();
	test_max_ack_pending();
	test_ring_capacity_ok();
	test_ring_capacity_zero_rejected();
	test_ring_capacity_not_pow2();
	test_fetch_batch_ok();
	test_fetch_batch_zero_rejected();
	test_fetch_batch_too_big();
	test_fetch_timeout_ms_ok();
	test_fetch_timeout_ms_too_big();
	test_fetch_defaults_zero_when_unset();

}
