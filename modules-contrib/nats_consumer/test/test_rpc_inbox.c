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
 * Replies to async nats_request calls, as the consumer process's inbox
 * callback (on_inbox_reply() in nats_rpc_consumer.c) takes them, with a
 * fake libnats message.  Replaces tests/test_rpc_inbox_auth.c (a carried
 * copy of the accept decision) and tests/test_rpc_reply_pin.c (a model of
 * the delivery race plus greps).
 *
 * The reply subject is <prefix>.<slot>.<generation>.<corr_id>, under a
 * wildcard any broker peer can publish to.  A reply is delivered to its
 * slot only when the slot is in flight, the generation is the slot's
 * current one (else it is a late reply for an earlier claim of the same
 * slot) and the corr_id is the one the worker stored (else it is a
 * forgery: slot and generation are small and guessable).  Delivery pins
 * the slot (DELIVERING) before it writes the reply, so a mismatched reply
 * never leaves the slot DELIVERED with another call's payload.
 *
 * Runs on the live one-slot pool while the consumer process is held.
 */

#include <tap.h>
#include <string.h>

#include "../nats_rpc_slot.h"
#include "../nats_rpc_subject.h"

#include "nc_ut.h"

#define PREFIX "_INBOX.ut"
#define CORR "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"

static int state(nats_rpc_slot_t *s)
{
	return atomic_load_explicit(&s->state, memory_order_acquire);
}

static uint32_t gen(nats_rpc_slot_t *s)
{
	return atomic_load_explicit(&s->generation, memory_order_relaxed);
}

/* delivers a reply on `subject` with body `data`; returns the number of
 * messages the callback destroyed (it destroys every one it is given) */
static int reply(const char *subject, const char *data)
{
	static char fake_msg;
	int destroyed;

	nc_ut_begin();
	nf.msg_subject = subject;
	nf.msg_data = data;
	nf.msg_len = (int)strlen(data);
	nf.msg_reply = NULL;
	nc_ut_on_inbox_reply((natsMsg *)&fake_msg);
	destroyed = nf.n_msg_destroy;
	nc_ut_end();
	return destroyed;
}

static nats_rpc_slot_t *in_flight(void)
{
	nats_rpc_slot_t *s = nats_rpc_slot_claim();

	if (!s)
		return NULL;
	memcpy(s->corr_id, CORR, sizeof CORR - 1);
	s->corr_id_len = sizeof CORR - 1;
	if (nats_rpc_slot_publish(s) < 0) {
		nats_rpc_slot_free(s, gen(s));
		return NULL;
	}
	return s;
}

static void subject(char *buf, size_t size, nats_rpc_slot_t *s, uint32_t g,
	const char *corr)
{
	if (nats_rpc_subject_build(buf, size, PREFIX, s->slot_idx, g, corr,
			(int)strlen(corr)) < 0)
		buf[0] = '\0';
}

void nc_ut_rpc_inbox(void)
{
	char subj[160];
	nats_rpc_slot_t *s = in_flight();
	uint32_t g;

	ok(s != NULL, "rpc_inbox: a slot in flight with its corr_id");
	if (!s)
		return;
	g = gen(s);

	subject(subj, sizeof subj, s, g, "0190a1b2-c3d4-7e5f-8a9b-000000000000");
	ok(reply(subj, "forged") == 1 && state(s) == NATS_RPC_SLOT_INFLIGHT,
		"rpc_inbox: a reply with another corr_id is dropped (forgery)");
	subject(subj, sizeof subj, s, g + 1, CORR);
	ok(reply(subj, "late") == 1 && state(s) == NATS_RPC_SLOT_INFLIGHT,
		"rpc_inbox: a reply for another generation is dropped");
	ok(reply("_INBOX.ut.not-a-reply", "junk") == 1 &&
		state(s) == NATS_RPC_SLOT_INFLIGHT,
		"rpc_inbox: a malformed subject is dropped");
	subject(subj, sizeof subj, s, g, CORR);
	ok(reply(subj, "the answer") == 1 && state(s) == NATS_RPC_SLOT_DELIVERED,
		"rpc_inbox: the genuine reply is delivered");
	ok(s->reply_data_len == 10 && memcmp(s->reply_data, "the answer", 10) == 0,
		"rpc_inbox: with its body");
	ok(reply(subj, "again") == 1 && s->reply_data_len == 10 &&
		memcmp(s->reply_data, "the answer", 10) == 0,
		"rpc_inbox: a second reply for a delivered slot changes nothing");
	nats_rpc_slot_free(s, g);

	/* the slot is claimed again by another call: the first call's late
	 * reply must not land in it */
	s = in_flight();
	ok(s != NULL && gen(s) != g, "rpc_inbox: the slot is re-claimed, new generation");
	if (!s)
		return;
	subject(subj, sizeof subj, s, g, CORR);
	ok(reply(subj, "stale") == 1 && state(s) == NATS_RPC_SLOT_INFLIGHT &&
		s->reply_data_len != 5,
		"rpc_inbox: the previous claim's reply is not delivered to the new one");
	nats_rpc_slot_free(s, gen(s));
}
