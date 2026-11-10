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
 * Publishing: the nats_publish() script function and the EVI transport
 * ("nats:<subject>" sockets), as core or as JetStream publishes.
 *
 *   - the subject is checked before libnats sees it, and never cut;
 *   - a refused publish is counted by its cause, never dropped silently;
 *   - a JetStream publish carries a Nats-Msg-Id -- given, built from the
 *     event's msg_id rule, or generated -- and waits js_ack_timeout_ms
 *     for its ack;
 *   - the transport reports the outcome to the event subscriber on every
 *     path.
 *
 * The module's own exported function and transport table, against the
 * fake libnats of en_ut_fake.c.
 */

#include <tap.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "../../../sr_module.h"
#include "../../../mem/shm_mem.h"
#include "../../../evi/evi_transport.h"
#include "../../../evi/evi_params.h"
#include "../../../evi/event_interface.h"
#include "../../nats/nats_bind.h"
#include "../nats_producer.h"
#include "../nats_stats.h"
#include "../nats_msg_id.h"
#include "../event_nats.h"

#include "en_ut.h"
#include "en_ut_stats.h"

extern struct module_exports exports;

/* nats_publish(subject, payload[, msg_id]) as the script calls it */
typedef int (*script_publish_f)(struct sip_msg *, str *, str *, str *);

static int script_publish(const char *subject, const char *payload,
	int payload_len, const char *msg_id)
{
	script_publish_f f = NULL;
	const cmd_export_t *c;
	str s, p, id;

	for (c = exports.cmds; c && c->name; c++)
		if (strcmp(c->name, "nats_publish") == 0)
			f = (script_publish_f)(void *)c->function;
	if (!f)
		return -99;
	s.s = (char *)subject;
	s.len = subject ? (int)strlen(subject) : 0;
	p.s = (char *)payload;
	p.len = payload_len;
	id.s = (char *)msg_id;
	id.len = msg_id ? (int)strlen(msg_id) : 0;
	return f(NULL, subject ? &s : NULL, payload ? &p : NULL,
		msg_id ? &id : NULL);
}

static int publish(const char *subject)
{
	return script_publish(subject, "x", 1, NULL);
}

static void connect_core(void)
{
	nats_producer_set_connection(en_ut_nc());
}

static void connect_js(void)
{
	nats_producer_set_connection(en_ut_nc());
	nats_producer_set_js(en_ut_js());
}

/* ── the script function, core publish ──────────────────────────── */

static int s_core_publish(void)
{
	struct en_ut_counters c = en_ut_counters_now();
	static const char payload[] = "{\"k\":\"a\\\\b\"}\0tail";

	connect_core();
	/* subject and payload as given, the payload by its length */
	return script_publish("ut.calls.new", payload, (int)sizeof payload - 1,
			NULL) == 1
		&& ef.n_publish == 1 && ef.n_js_publish == 0
		&& strcmp(ef.pub_subject, "ut.calls.new") == 0
		&& ef.pub_len == (int)sizeof payload - 1
		&& memcmp(ef.pub_data, payload, sizeof payload - 1) == 0
		&& en_ut_counters_added(c, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0);
}

/* the publish path does not drop a message while the pool reports a
 * disconnect: libnats appends it to its reconnect buffer and sends it after
 * the reconnect (a full buffer refuses it: s_core_refused_buffer_full).
 * Was tests/test_disconnected_fastfail.c in cachedb_nats (a source grep). */
static int s_disconnected_script_publish(void)
{
	connect_core();
	ef.connected = 0;
	return script_publish("ut.during.outage", "x", 1, NULL) == 1
		&& ef.n_publish == 1
		&& strcmp(ef.pub_subject, "ut.during.outage") == 0;
}
static int s_disconnected_evi_raise(void)
{
	str nats = str_init("nats"), ev = str_init("E_UT_OUTAGE");
	const evi_export_t *tm = get_trans_mod(&nats);
	evi_reply_sock sock;
	evi_params_t params;

	connect_core();
	ef.connected = 0;
	memset(&sock, 0, sizeof sock);
	sock.address.s = "ut.evi.outage";
	sock.address.len = 13;
	memset(&params, 0, sizeof params);
	return tm && tm->raise
		&& tm->raise(NULL, &ev, &sock, &params, NULL) == 0
		&& ef.n_publish == 1
		&& strcmp(ef.pub_subject, "ut.evi.outage") == 0;
}
static int s_core_refused_buffer_full(void)
{
	struct en_ut_counters c = en_ut_counters_now();

	connect_core();
	ef.publish_status = NATS_INSUFFICIENT_BUFFER;
	return publish("ut.subject") == -1 && ef.n_publish == 1
		&& en_ut_counters_added(c, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0);
}

static int s_core_refused_other(void)
{
	struct en_ut_counters c = en_ut_counters_now();

	connect_core();
	ef.publish_status = NATS_CONNECTION_CLOSED;
	if (publish("ut.subject") != -1
	    || !en_ut_counters_added(c, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0))
		return 0;
	/* a timeout is the pending cap only for a JetStream publish */
	c = en_ut_counters_now();
	ef.publish_status = NATS_TIMEOUT;
	return publish("ut.subject") == -1
		&& en_ut_counters_added(c, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0);
}

static int s_missing_arguments(void)
{
	struct en_ut_counters c = en_ut_counters_now();

	connect_core();
	return script_publish(NULL, "x", 1, NULL) == -1
		&& script_publish("", "x", 1, NULL) == -1
		&& script_publish("ut.subject", NULL, 0, NULL) == -1
		&& script_publish("ut.subject", "", 0, NULL) == -1
		&& ef.n_publish == 0
		&& en_ut_counters_added(c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
}

static int s_bad_subjects(void)
{
	static const char *bad[] = {
		"ut.*", "ut.>", ">", "ut..x", ".ut", "ut.", "ut x", "ut\tx",
		"ut\r\nPUB evil 1", "ut\x7f",
	};
	unsigned i;

	connect_core();
	for (i = 0; i < sizeof bad / sizeof bad[0]; i++)
		if (publish(bad[i]) != -1)
			return 0;
	return ef.n_publish == 0;
}

static int s_odd_but_valid_subjects(void)
{
	/* bytes that are data in a subject: published unchanged */
	static const char *good[] = {
		"ut.a\\b", "ut.\"q\"", "ut.100%", "ut.$x", "ut.caf\xc3\xa9", "U-t_1",
	};
	unsigned i;

	connect_core();
	for (i = 0; i < sizeof good / sizeof good[0]; i++)
		if (publish(good[i]) != 1 || strcmp(ef.pub_subject, good[i]) != 0)
			return 0;
	return ef.n_publish == (int)(sizeof good / sizeof good[0]);
}

static int s_subject_length(void)
{
	char subject[600];

	connect_core();
	/* 511 bytes fit; 512 would lose its last byte: refused, not cut */
	memset(subject, 's', sizeof subject);
	subject[511] = '\0';
	if (publish(subject) != 1 || strlen(ef.pub_subject) != 511)
		return 0;
	subject[511] = 's';
	subject[512] = '\0';
	return publish(subject) == -1 && ef.n_publish == 1
		&& strstr(en_ut_log(), "subject too long") != NULL;
}

/* ── the script function, JetStream publish ─────────────────────── */

static int saved_jetstream;
static void jetstream_on(void)  { saved_jetstream = nats_jetstream; nats_jetstream = 1; }
static void jetstream_off(void) { nats_jetstream = saved_jetstream; }

static int js_given_id(void)
{
	struct en_ut_counters c = en_ut_counters_now();

	connect_js();
	return script_publish("ut.orders", "{}", 2, "order-17") == 1
		&& ef.n_js_publish == 1 && ef.n_publish == 0
		&& strcmp(ef.js_subject, "ut.orders") == 0
		&& strcmp(ef.js_msg_id, "order-17") == 0
		/* the ack wait of the suite's opensips.cfg */
		&& ef.js_max_wait == 900
		&& en_ut_counters_added(c, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0);
}

/* "<16 hex digits>-<sequence>" */
static int generated_id(const char *id, char *prefix, unsigned long *seq)
{
	int i;

	for (i = 0; i < 16; i++)
		if (!isxdigit((unsigned char)id[i]))
			return 0;
	if (id[16] != '-' || sscanf(id + 17, "%lu", seq) != 1)
		return 0;
	memcpy(prefix, id, 16);
	prefix[16] = '\0';
	return 1;
}

static int js_generated_id(void)
{
	char p1[17], p2[17];
	unsigned long s1, s2;

	connect_js();
	if (publish("ut.orders") != 1 || !generated_id(ef.js_msg_id, p1, &s1))
		return 0;
	if (publish("ut.orders") != 1 || !generated_id(ef.js_msg_id, p2, &s2))
		return 0;
	/* one prefix per process, the sequence counts */
	return strcmp(p1, p2) == 0 && s2 == s1 + 1;
}

static int js_bad_ids(void)
{
	char too_long[300];

	connect_js();
	memset(too_long, 'i', sizeof too_long - 1);
	too_long[256] = '\0';
	return script_publish("ut.orders", "x", 1, "") == -1
		&& script_publish("ut.orders", "x", 1, "has space") == -1
		&& script_publish("ut.orders", "x", 1, "tab\there") == -1
		&& script_publish("ut.orders", "x", 1, "nl\n") == -1
		&& script_publish("ut.orders", "x", 1, "caf\xc3\xa9") == -1
		&& script_publish("ut.orders", "x", 1, too_long) == -1
		&& ef.n_js_publish == 0
		&& (too_long[255] = '\0', 1)
		&& script_publish("ut.orders", "x", 1, too_long) == 1
		&& strlen(ef.js_msg_id) == 255
		/* punctuation, a backslash and a quote are printable */
		&& script_publish("ut.orders", "x", 1, "a\\b:\"c\"%") == 1
		&& strcmp(ef.js_msg_id, "a\\b:\"c\"%") == 0;
}

static int js_refused_pending_full(void)
{
	struct en_ut_counters c = en_ut_counters_now();

	connect_js();
	ef.js_publish_status = NATS_TIMEOUT;
	return publish("ut.orders") == -1
		&& en_ut_counters_added(c, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1);
}

static int js_refused_buffer_full(void)
{
	struct en_ut_counters c = en_ut_counters_now();

	connect_js();
	ef.js_publish_status = NATS_INSUFFICIENT_BUFFER;
	return publish("ut.orders") == -1
		&& en_ut_counters_added(c, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0);
}

static int js_core_ignores_id(void)
{
	/* jetstream=0: the id is checked all the same, and not sent */
	nats_jetstream = 0;
	connect_js();
	return script_publish("ut.orders", "x", 1, "bad id") == -1
		&& script_publish("ut.orders", "x", 1, "good-id") == 1
		&& ef.n_publish == 1 && ef.n_js_publish == 0;
}

/* ── the EVI transport ──────────────────────────────────────────── */

static int status_calls, last_status;
static void *status_param;
static void status_cb(void *param, enum evi_status status)
{
	status_calls++;
	last_status = status;
	status_param = param;
}

static evi_async_ctx_t status_ctx = { status_cb, &status_calls };

static evi_reply_sock *parse(const char *subject)
{
	str s = { (char *)subject, subject ? (int)strlen(subject) : 0 };

	return event_nats_test_transport()->parse(s);
}

/* raise @event on @subject with the parameters call_id (a string, when
 * not NULL) and seq (an integer, when >= 0) */
static int raise_event(const char *subject, const char *event, const char *call_id,
	int seq, evi_async_ctx_t *ctx)
{
	const evi_export_t *t = event_nats_test_transport();
	static str n_call_id = str_init("call_id"), n_seq = str_init("seq");
	evi_reply_sock *sock = parse(subject);
	evi_params_p params = evi_get_params();
	str ev = { (char *)event, (int)strlen(event) }, v;
	int rc;

	if (!sock || !params)
		return -99;
	if (call_id) {
		v.s = (char *)call_id;
		v.len = (int)strlen(call_id);
		if (evi_param_add_str(params, &n_call_id, &v) < 0)
			return -99;
	}
	if (seq >= 0 && evi_param_add_int(params, &n_seq, &seq) < 0)
		return -99;
	status_calls = 0;
	rc = t->raise(NULL, &ev, sock, params, ctx);
	evi_free_params(params);
	t->free(sock);
	return rc;
}

static int evi_core_raise(void)
{
	struct en_ut_counters c = en_ut_counters_now();

	connect_core();
	return raise_event("ut.events.calls", "E_NATS_UT_PUB", "abc\\\"def", 7,
			&status_ctx) == 0
		&& ef.n_publish == 1
		&& strcmp(ef.pub_subject, "ut.events.calls") == 0
		/* the payload names the event and carries the parameters,
		 * the string one escaped for JSON */
		&& strstr(ef.pub_data, "E_NATS_UT_PUB") != NULL
		&& strstr(ef.pub_data, "\"call_id\"") != NULL
		&& strstr(ef.pub_data, "abc\\\\\\\"def") != NULL
		&& strstr(ef.pub_data, "\"seq\"") != NULL
		&& ef.pub_len == (int)strlen(ef.pub_data)
		&& en_ut_counters_added(c, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0)
		&& status_calls == 1 && last_status == EVI_STATUS_SUCCESS
		&& status_param == &status_calls;
}

static int evi_failure_reported(void)
{
	struct en_ut_counters c = en_ut_counters_now();

	connect_core();
	ef.publish_status = NATS_CONNECTION_CLOSED;
	return raise_event("ut.events.calls", "E_NATS_UT_PUB", "abc", 7,
			&status_ctx) == -1
		&& en_ut_counters_added(c, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0)
		&& status_calls == 1 && last_status == EVI_STATUS_FAIL;
}

static int evi_bad_subject_reported(void)
{
	connect_core();
	return raise_event("ut.events.*", "E_NATS_UT_PUB", "abc", 7, &status_ctx) == -1
		&& ef.n_publish == 0
		&& status_calls == 1 && last_status == EVI_STATUS_FAIL;
}

static int evi_no_socket_reported(void)
{
	const evi_export_t *t = event_nats_test_transport();
	evi_params_p params = evi_get_params();
	str ev = str_init("E_NATS_UT_PUB");
	int rc;

	connect_core();
	status_calls = 0;
	rc = t->raise(NULL, &ev, NULL, params, &status_ctx);
	evi_free_params(params);
	return rc == -1 && ef.n_publish == 0
		&& status_calls == 1 && last_status == EVI_STATUS_FAIL;
}

static int evi_no_status_callback(void)
{
	evi_async_ctx_t none = { NULL, NULL };

	connect_core();
	return raise_event("ut.events.calls", "E_NATS_UT_PUB", "abc", 7, NULL) == 0
		&& raise_event("ut.events.calls", "E_NATS_UT_PUB", "abc", 7, &none) == 0
		&& ef.n_publish == 2;
}

static int evi_js_rule_id(void)
{
	connect_js();
	/* the rule of the suite's opensips.cfg: "E_NATS_UT_PUB: call_id, seq" */
	return raise_event("ut.events.calls", "E_NATS_UT_PUB", "abc", 7, NULL) == 0
		&& ef.n_js_publish == 1
		&& strcmp(ef.js_msg_id, "E_NATS_UT_PUB:abc:7") == 0
		/* the same event again: the same id, so the server keeps one */
		&& raise_event("ut.events.calls", "E_NATS_UT_PUB", "abc", 7, NULL) == 0
		&& strcmp(ef.js_msg_id, "E_NATS_UT_PUB:abc:7") == 0
		&& raise_event("ut.events.calls", "E_NATS_UT_PUB", "abc", 8, NULL) == 0
		&& strcmp(ef.js_msg_id, "E_NATS_UT_PUB:abc:8") == 0
		&& ef.js_max_wait == 900;
}

static int evi_js_rule_id_encoded(void)
{
	connect_js();
	/* ':' in a value cannot run into the next one */
	return raise_event("ut.events.calls", "E_NATS_UT_PUB", "a:b c", 7, NULL) == 0
		&& strcmp(ef.js_msg_id, "E_NATS_UT_PUB:a%3Ab%20c:7") == 0;
}

static int evi_js_rule_param_missing(void)
{
	char prefix[17];
	unsigned long seq;

	connect_js();
	/* the event lacks "seq": published, with a generated id */
	return raise_event("ut.events.calls", "E_NATS_UT_PUB", "abc", -1, NULL) == 0
		&& ef.n_js_publish == 1
		&& generated_id(ef.js_msg_id, prefix, &seq)
		&& strstr(en_ut_log(), "lacks a parameter of the rule") != NULL;
}

static int evi_js_no_rule(void)
{
	char prefix[17];
	unsigned long seq;

	connect_js();
	return raise_event("ut.events.calls", "E_NATS_UT_OTHER", "abc", 7, NULL) == 0
		&& generated_id(ef.js_msg_id, prefix, &seq)
		&& en_ut_log()[0] == '\0';
}

static int evi_core_no_id(void)
{
	/* jetstream=0: the rule is not used */
	nats_jetstream = 0;
	connect_js();
	return raise_event("ut.events.calls", "E_NATS_UT_PUB", "abc", -1, NULL) == 0
		&& ef.n_publish == 1 && ef.n_js_publish == 0
		&& en_ut_log()[0] == '\0';
}

static int evi_sockets(void)
{
	const evi_export_t *t = event_nats_test_transport();
	evi_reply_sock *a = parse("ut.events.calls"),
		*b = parse("ut.events.calls"), *c = parse("ut.events.call"),
		*d = parse("ut.events.callS");
	str printed;
	int good;

	if (!a || !b || !c || !d)
		return 0;
	printed = t->print(a);
	good = t->match(a, b) == 1 && t->match(a, c) == 0 && t->match(a, d) == 0
		&& t->match(a, NULL) == 0 && t->match(NULL, a) == 0
		&& printed.len == 15 && memcmp(printed.s, "ut.events.calls", 15) == 0
		&& (a->flags & EVI_ADDRESS) && (a->flags & EVI_ASYNC_STATUS)
		&& parse("") == NULL && parse(NULL) == NULL;
	t->free(a);
	t->free(b);
	t->free(c);
	t->free(d);
	t->free(NULL);
	return good;
}

static int evi_transport_identity(void)
{
	const evi_export_t *t = event_nats_test_transport();

	return t->proto.len == 4 && memcmp(t->proto.s, "nats", 4) == 0
		&& t->flags == NATS_FLAG;
}

/* ── shutdown ───────────────────────────────────────────────────── */

static int s_destroy_order(void)
{
	nats_stats_t *live = nats_stats, *scratch;
	int good;

	/* mod_destroy() frees the stats table: give it one of its own */
	scratch = shm_malloc(NATS_STATS_MAX_PROCS * sizeof *scratch);
	if (!scratch)
		return 0;
	memset(scratch, 0, NATS_STATS_MAX_PROCS * sizeof *scratch);
	nats_stats = scratch;
	event_nats_test_mod_destroy();
	/* the ack callback is taken from the pool, then the pool is let go,
	 * and only then the table an ack would count in is freed */
	good = ef.n_set_pub_ack_cb == 1 && ef.pub_ack_cb == NULL
		&& ef.n_unregister == 1
		&& ef.seq_set_pub_ack_cb < ef.seq_unregister
		&& ef.stats_alive_at_unregister
		&& nats_stats == NULL;
	nats_stats = live;
	return good;
}

static void js_run(const char *name, en_ut_scenario_f f)
{
	jetstream_on();
	en_ut_run(name, f);
	jetstream_off();
}

void en_ut_publish(void)
{
	/* the script function, core publish */
	en_ut_run("nats_publish(): subject and payload reach libnats unchanged",
		s_core_publish);
	en_ut_run("nats_publish(): refused by a full reconnect buffer: counted",
		s_core_refused_buffer_full);
	en_ut_run("nats_publish(): a disconnected pool does not drop the publish "
		"(libnats buffers it)", s_disconnected_script_publish);
	en_ut_run("EVI raise: a disconnected pool does not drop the event",
		s_disconnected_evi_raise);
	en_ut_run("nats_publish(): any other refusal counts as failed",
		s_core_refused_other);
	en_ut_run("nats_publish(): missing or empty subject or payload",
		s_missing_arguments);
	en_ut_run("nats_publish(): wildcards, empty tokens, blanks and control "
		"bytes in the subject are refused", s_bad_subjects);
	en_ut_run("nats_publish(): backslash, quote, percent, UTF-8 in the "
		"subject are published as given", s_odd_but_valid_subjects);
	en_ut_run("nats_publish(): a 511-byte subject fits, 512 is refused",
		s_subject_length);

	/* the script function, JetStream publish */
	js_run("JetStream: the given msg_id and the ack wait reach libnats",
		js_given_id);
	js_run("JetStream: without a msg_id one is generated, prefix + sequence",
		js_generated_id);
	js_run("JetStream: a msg_id must be 1 to 255 printable bytes, no blanks",
		js_bad_ids);
	js_run("JetStream: refused by the pending cap: js_pending_dropped",
		js_refused_pending_full);
	js_run("JetStream: refused by a full reconnect buffer", js_refused_buffer_full);
	js_run("jetstream=0: a msg_id is checked but not sent", js_core_ignores_id);

	/* the EVI transport */
	en_ut_run("EVI: an event is published as JSON on the socket's subject",
		evi_core_raise);
	en_ut_run("EVI: a failed publish is reported to the subscriber",
		evi_failure_reported);
	en_ut_run("EVI: a refused subject is reported to the subscriber",
		evi_bad_subject_reported);
	en_ut_run("EVI: a missing socket is reported to the subscriber",
		evi_no_socket_reported);
	en_ut_run("EVI: no status callback is fine", evi_no_status_callback);
	js_run("EVI JetStream: the msg_id rule builds the id from the event",
		evi_js_rule_id);
	js_run("EVI JetStream: a ':' or a blank in a value is percent-encoded",
		evi_js_rule_id_encoded);
	js_run("EVI JetStream: a parameter of the rule is missing: generated id, "
		"warning", evi_js_rule_param_missing);
	js_run("EVI JetStream: an event without a rule: generated id",
		evi_js_no_rule);
	js_run("EVI, jetstream=0: no message id at all", evi_core_no_id);
	en_ut_run("EVI: sockets parse, match byte for byte, print and free",
		evi_sockets);
	en_ut_run("EVI: the transport is \"nats\", with its own flag",
		evi_transport_identity);

	/* shutdown */
	en_ut_run("mod_destroy: ack callback off, pool released, then stats freed",
		s_destroy_order);
}
