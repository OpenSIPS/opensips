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
 * The consumer process publishing a worker's async request
 * (publish_slot() in nats_rpc_consumer.c), and the header wire format the
 * request's headers travel in.  Replaces tests/test_dead_inbox_retry.c
 * and tests/test_header_propagation.c (models plus greps).
 *
 *  - The request's reply-to is the consumer's own inbox.  While that inbox
 *    subscription is down a reply could never come back, so the slot is
 *    abandoned at once (the worker fails fast) instead of published; the
 *    subscribe is retried until it is up.
 *  - Once up, the request is created with its subject, body and inbox
 *    reply-to, its staged headers are set on it BEFORE it is published,
 *    and the slot stays in flight for the reply.  A publish that fails, a
 *    slot with no corr_id (its reply could not be authenticated), or a
 *    slot re-claimed since (stale generation) is not published.
 *  - Headers: a count, then for each a 16-bit length and the name, a
 *    16-bit length and the value (little-endian), built from the staged
 *    headers by nats_rpc_staged_serialize() and applied to the outbound
 *    message by nats_rpc_hdr_deserialize_to_msg().
 *
 * Runs on the live one-slot pool while the consumer process is held.
 */

#include <tap.h>
#include <string.h>

#include "../nats_rpc.h"
#include "../nats_rpc_slot.h"
#include "../nats_rpc_consumer.h"

#include "nc_ut.h"

#define CORR "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"

static char fake_nc;
#define NC ((natsConnection *)&fake_nc)

static int state(nats_rpc_slot_t *s)
{
	return atomic_load_explicit(&s->state, memory_order_acquire);
}

static uint32_t gen(nats_rpc_slot_t *s)
{
	return atomic_load_explicit(&s->generation, memory_order_relaxed);
}

static void stage(const char *k, const char *v)
{
	str name = { (char *)k, (int)strlen(k) };
	str value = { (char *)v, (int)strlen(v) };

	nats_rpc_staged_set_if_absent(&name, &value);
}

/* a request in flight on the slot, with headers when `headers` */
static nats_rpc_slot_t *request(int with_corr, int headers)
{
	nats_rpc_slot_t *s = nats_rpc_slot_claim();
	int trunc, count, n;

	if (!s)
		return NULL;
	if (with_corr) {
		memcpy(s->corr_id, CORR, sizeof CORR - 1);
		s->corr_id_len = sizeof CORR - 1;
	}
	memcpy(s->out_subject, "svc.echo", 8);
	s->out_subject_len = 8;
	memcpy(s->out_data, "ping", 4);
	s->out_data_len = 4;
	s->out_headers_len = 0;
	if (headers) {
		nats_rpc_staged_clear();
		stage("X-Trace", "abc123");
		stage("X-Tenant", "t1");
		n = nats_rpc_staged_serialize(s->out_headers,
			(int)sizeof s->out_headers, &trunc, &count);
		s->out_headers_len = (uint16_t)(n > 0 ? n : 0);
		nats_rpc_staged_clear();
	}
	if (nats_rpc_slot_publish(s) < 0) {
		nats_rpc_slot_free(s, gen(s));
		return NULL;
	}
	return s;
}

static void dead_inbox(void)
{
	nats_rpc_slot_t *s;

	nc_ut_begin();
	nf.pool_nc = NC;
	ok(!nats_rpc_consumer_inbox_ready(),
		"rpc_publish: this process has no reply inbox yet");
	s = request(1, 0);
	ok(s != NULL, "rpc_publish: a request in flight");
	if (!s) {
		nc_ut_end();
		return;
	}
	nc_ut_publish_slot(s->slot_idx, gen(s), NC);
	ok(state(s) == NATS_RPC_SLOT_ABANDONED && nf.n_publish == 0 &&
		nf.n_msg_create == 0,
		"rpc_publish: inbox down: the slot is abandoned, nothing published");
	ok(strstr(nc_ut_log(), "reply inbox down") != NULL, "rpc_publish: and that is logged");
	nats_rpc_slot_free(s, gen(s));

	nf.subscribe_status = NATS_ERR;
	ok(nats_rpc_consumer_subscribe() < 0 && !nats_rpc_consumer_inbox_ready(),
		"rpc_publish: a failed inbox subscribe leaves it down");
	nf.subscribe_status = NATS_OK;
	ok(nats_rpc_consumer_subscribe() == 0 && nats_rpc_consumer_inbox_ready(),
		"rpc_publish: the retry brings it up");
	ok(nats_rpc_consumer_subscribe() == 0 && nf.n_subscribe == 2,
		"rpc_publish: once up, a further call subscribes nothing more");
	nc_ut_end();
}

static void published(void)
{
	nats_rpc_slot_t *s;

	nc_ut_begin();
	nf.msg_create_status = NATS_OK;
	s = request(1, 1);
	if (!s) {
		ok(0, "rpc_publish: a request in flight");
		nc_ut_end();
		return;
	}
	nc_ut_publish_slot(s->slot_idx, gen(s), NC);
	ok(nf.n_publish == 1 && strcmp(nf.created_subject, "svc.echo") == 0 &&
		strcmp(nf.created_data, "ping") == 0,
		"rpc_publish: the request is published with its subject and body");
	ok(strstr(nf.created_reply, CORR) != NULL && strstr(nf.created_reply, "_INBOX") != NULL,
		"rpc_publish: its reply-to is this process's inbox, with the corr_id");
	ok(nf.n_hdr_set == 2 && strcmp(nf.hdr_set_key[0], "X-Trace") == 0 &&
		strcmp(nf.hdr_set_val[0], "abc123") == 0 &&
		strcmp(nf.hdr_set_key[1], "X-Tenant") == 0,
		"rpc_publish: its staged headers are set on it");
	ok(nf.seq_last_hdr_set < nf.seq_publish,
		"rpc_publish: before it is published");
	ok(state(s) == NATS_RPC_SLOT_INFLIGHT, "rpc_publish: the slot waits for the reply");
	nats_rpc_slot_free(s, gen(s));

	nf.n_publish = 0;
	nf.publish_status = NATS_ERR;
	s = request(1, 0);
	if (s) {
		nc_ut_publish_slot(s->slot_idx, gen(s), NC);
		ok(nf.n_publish == 1 && state(s) == NATS_RPC_SLOT_ABANDONED,
			"rpc_publish: a failed publish abandons the slot");
		nats_rpc_slot_free(s, gen(s));
	}
	nf.publish_status = NATS_OK;

	nf.n_publish = 0;
	s = request(0, 0);
	if (s) {
		nc_ut_publish_slot(s->slot_idx, gen(s), NC);
		ok(nf.n_publish == 0 && state(s) == NATS_RPC_SLOT_ABANDONED,
			"rpc_publish: a slot with no corr_id is abandoned, not published");
		nats_rpc_slot_free(s, gen(s));
	}

	s = request(1, 0);
	if (s) {
		nc_ut_publish_slot(s->slot_idx, gen(s) - 1, NC);
		ok(nf.n_publish == 0 && state(s) == NATS_RPC_SLOT_INFLIGHT,
			"rpc_publish: a request of an earlier claim of the slot is not published");
		nats_rpc_slot_free(s, gen(s));
	}

	nats_rpc_consumer_unsubscribe();
	ok(!nats_rpc_consumer_inbox_ready(), "rpc_publish: the inbox is dropped again");
	nc_ut_end();
}

static void wire_format(void)
{
	char buf[256];
	int trunc = 0, count = 0, n;

	nats_rpc_staged_clear();
	stage("X-A", "1");
	stage("X-B", "two");
	stage("X-A", "replaced?");
	n = nats_rpc_staged_serialize(buf, (int)sizeof buf, &trunc, &count);
	ok(count == 2 && !trunc, "rpc_publish: two headers staged (set_if_absent kept the first X-A)");
	ok(n == 2 + (2 + 3 + 2 + 1) + (2 + 3 + 2 + 3) &&
		(unsigned char)buf[0] == 2 && buf[1] == 0 &&
		(unsigned char)buf[2] == 3 && memcmp(buf + 4, "X-A", 3) == 0 &&
		(unsigned char)buf[7] == 1 && buf[9] == '1',
		"rpc_publish: count, then length-prefixed name and value");

	nc_ut_begin();
	ok(nats_rpc_hdr_deserialize_to_msg(buf, n, (void *)&buf) == 2 &&
		nf.n_hdr_set == 2 && strcmp(nf.hdr_set_key[1], "X-B") == 0 &&
		strcmp(nf.hdr_set_val[1], "two") == 0,
		"rpc_publish: the buffer decodes back to the same headers");
	nf.n_hdr_set = 0;
	ok(nats_rpc_hdr_deserialize_to_msg(buf, n - 2, (void *)&buf) == -1,
		"rpc_publish: a cut buffer is refused");
	ok(nats_rpc_hdr_deserialize_to_msg(buf, 1, (void *)&buf) == 0 &&
		nats_rpc_hdr_deserialize_to_msg(NULL, n, (void *)&buf) == 0,
		"rpc_publish: no buffer applies nothing");
	nc_ut_end();

	n = nats_rpc_staged_serialize(buf, 12, &trunc, &count);
	ok(trunc && count == 1 && n == 10,
		"rpc_publish: a buffer too small keeps the headers that fit and says so");
	nats_rpc_staged_clear();
	n = nats_rpc_staged_serialize(buf, (int)sizeof buf, &trunc, &count);
	ok(n == 2 && count == 0, "rpc_publish: cleared, nothing is staged");
}

void nc_ut_rpc_publish(void)
{
	wire_format();
	dead_inbox();
	published();
}
