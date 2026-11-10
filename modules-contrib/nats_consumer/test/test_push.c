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
 * What the consumer process does with each fetched message
 * (push_one_msg() in nats_consumer_proc.c): stash it under an ack token
 * and hand it to the worker ring, or say why not.  Replaces
 * tests/test_backpressure_stats.c and tests/test_poison_term.c (models of
 * the classification plus greps).
 *
 *  - Delivered: on the ring, counted, kept referenced until its ack.
 *  - Deferred (ring full, or ack-reference table full): not acked, so the
 *    broker redelivers it after ack_wait; counted as back-pressure.
 *  - Oversize (subject or payload larger than a ring slot): it can never
 *    be delivered, so it is terminated, counted as a Term and not as
 *    back-pressure, and logged at most once per interval.
 *  - Poison (delivered more times than poison_max_deliver): terminated
 *    instead of handed to a worker again.
 *  - A JetStream pull delivery has the $JS.ACK subject as its reply; the
 *    worker sees the publisher's Nats-Reply-To header instead.
 */

#define _GNU_SOURCE   /* memmem, which glibc < 2.39 declares only under it */
#include <tap.h>
#include <stdlib.h>
#include <string.h>

#include "../nats_ack.h"
#include "../nats_handle_registry.h"
#include "../nats_handle_parse.h"
#include "../nats_ring.h"
#include "../nats_consumer_proc.h"
#include "../nats_consumer_proc_internal.h"

#include "nc_ut.h"

#define IDX ((uint16_t)(NATS_REGISTRY_MAX_HANDLES - 3))
#define CAP 4

static nats_handle_t *h;
static proc_sub_state_t ss;
static char fake_msg[8];
#define MSG(i) ((natsMsg *)&fake_msg[i])

static int setup(void)
{
	str cfg = str_init("id=ut_push;stream=UT;durable=d");
	const char *err = NULL;

	h = nats_handle_parse(&cfg, &err);
	if (!h)
		return 0;
	h->ring = nats_ring_create(CAP);
	if (!h->ring)
		return 0;
	memset(&ss, 0, sizeof ss);
	ss.h_ref = h;
	ss.ring = h->ring;
	ss.handle_idx = IDX;
	ss.id.s = "ut_push";
	ss.id.len = 7;
	return 1;
}

static void teardown(void)
{
	nc_ut_begin();            /* any message left is a fake one */
	purge_msg_ref_row(IDX);
	nc_ut_end();
	if (h)
		nats_handle_free(h);
	h = NULL;
}

/* the fake message the next push sees */
static void message(const char *subject, const char *data, int len,
	const char *reply)
{
	nf.msg_subject = subject;
	nf.msg_data = data;
	nf.msg_len = len;
	nf.msg_reply = reply;
}

static void delivered(void)
{
	nats_ring_slot_t out;
	uint64_t before = h->msgs_delivered;

	nc_ut_begin();
	message("orders.new", "hello", 5, NULL);
	nf.has_md = 1;
	nf.md_delivered = 1;
	nf.md_stream_seq = 41;
	ok(nc_ut_push_one_msg(&ss, MSG(0)) == 1 && nats_ring_depth(ss.ring) == 1,
		"push: a message is delivered to the ring");
	ok(h->msgs_delivered == before + 1 && nf.n_msg_destroy == 0,
		"push: counted as delivered, and kept for its ack");
	ok(nats_ring_pop(ss.ring, &out) == 0 && out.subject_len == 10 &&
		memcmp(out.subject, "orders.new", 10) == 0 && out.data_len == 5 &&
		out.stream_seq == 41 && ss.last_stream_seq == 41,
		"push: the slot carries its subject, body and stream sequence");
	ok(release_msg_ref(out.ack_token) == MSG(0),
		"push: the slot's ack token redeems the message");

	before = h->redeliveries;
	nf.md_delivered = 3;
	nc_ut_push_one_msg(&ss, MSG(1));
	ok(h->redeliveries == before + 1, "push: a redelivery is counted as one");
	nats_ring_pop(ss.ring, &out);
	ok(out.delivered == 3, "push: the slot says how often it was delivered");
	release_msg_ref(out.ack_token);
	nc_ut_end();
}

static void app_reply(void)
{
	nats_ring_slot_t out;

	nc_ut_begin();
	message("orders.new", "x", 1, "$JS.ACK.S.c.1.2.3.4.5");
	nf.n_hdr = 2;
	nf.hdr_key[0] = "X-Trace";
	nf.hdr_val[0] = "abc123";
	nf.hdr_key[1] = "Nats-Reply-To";
	nf.hdr_val[1] = "app.reply.7";
	nc_ut_push_one_msg(&ss, MSG(2));
	ok(nats_ring_pop(ss.ring, &out) == 0 && out.has_reply &&
		out.reply_to_len == 11 && memcmp(out.reply_to, "app.reply.7", 11) == 0,
		"push: the worker sees the publisher's Nats-Reply-To, not $JS.ACK");
	ok(out.headers_len > 0 && memmem(out.headers, out.headers_len, "X-Trace", 7) &&
		memmem(out.headers, out.headers_len, "abc123", 6),
		"push: the message's headers reach the slot");
	release_msg_ref(out.ack_token);
	nc_ut_end();
}

static void deferred(void)
{
	uint64_t drops = h->backpressure_drops, terms = h->terms;
	int i, n, ok_;

	nc_ut_begin();
	message("orders.new", "x", 1, NULL);

	/* every ack reference of the row taken, the ring empty */
	for (i = 0; i < CAP; i++)
		store_msg_ref(IDX, CAP, 0, MSG(i), &ok_);
	ok(nc_ut_push_one_msg(&ss, MSG(5)) == 0 &&
		h->backpressure_drops == drops + 1 && h->terms == terms &&
		nf.n_term == 0 && nf.n_msg_destroy == 1 && nf.destroyed[0] == MSG(5) &&
		nats_ring_depth(ss.ring) == 0,
		"push: ack-reference table full: deferred (destroyed, not acked, not a Term)");
	purge_msg_ref_row(IDX);

	/* the ring full, the references free */
	nf.n_msg_destroy = 0;
	nc_ut_ring_forge(ss.ring, CAP, 0);
	ok(nc_ut_push_one_msg(&ss, MSG(6)) == 0 &&
		h->backpressure_drops == drops + 2 && nf.n_term == 0 &&
		nf.n_msg_destroy == 1,
		"push: ring full: deferred, counted as back-pressure");
	for (i = 0, n = 0; i < CAP; i++)
		if (store_msg_ref(IDX, CAP, 0, MSG(7), &ok_) && ok_)
			n++;
	ok(n == CAP, "push: and its ack reference was given back (all %d free)", CAP);
	nc_ut_ring_forge(ss.ring, 0, 0);
	purge_msg_ref_row(IDX);
	nc_ut_end();
}

static void oversize(void)
{
	static char big[NATS_RING_PAYLOAD_MAX + 10];
	uint64_t drops = h->backpressure_drops, terms = h->terms;

	nc_ut_begin();
	message("orders.new", big, (int)sizeof big, NULL);
	ok(nc_ut_push_one_msg(&ss, MSG(0)) == 0 && nf.n_term == 1 &&
		h->terms == terms + 1 && h->backpressure_drops == drops &&
		nf.n_msg_destroy == 1 && nats_ring_depth(ss.ring) == 0,
		"push: an oversize message is terminated, not counted as back-pressure");
	ok(strstr(nc_ut_log(), "oversize message") != NULL, "push: and logged");
	nc_ut_log_clear();
	nc_ut_push_one_msg(&ss, MSG(1));
	ok(nf.n_term == 2 && strstr(nc_ut_log(), "oversize message") == NULL,
		"push: a second one is terminated but not logged again so soon");
	nc_ut_end();
}

static void poison(void)
{
	nats_ring_slot_t out;
	int saved = nats_consumer_poison_max_deliver;
	uint64_t terms = h->terms, poisoned = h->poisoned;

	ok(saved == 20, "push: poison_max_deliver defaults to 20");
	nc_ut_begin();
	message("orders.new", "x", 1, NULL);
	nf.has_md = 1;
	nats_consumer_poison_max_deliver = 5;

	nf.md_delivered = 6;
	ok(nc_ut_push_one_msg(&ss, MSG(0)) == 0 && nf.n_term == 1 &&
		h->terms == terms + 1 && h->poisoned == poisoned + 1 &&
		nf.n_msg_destroy == 1 && nats_ring_depth(ss.ring) == 0,
		"push: delivered past the cap: terminated as poison");
	nf.md_delivered = 5;
	ok(nc_ut_push_one_msg(&ss, MSG(1)) == 1 && h->poisoned == poisoned + 1,
		"push: delivered exactly the cap times: still delivered");
	nf.md_delivered = 1;
	ok(nc_ut_push_one_msg(&ss, MSG(2)) == 1, "push: a first delivery is delivered");
	nats_consumer_poison_max_deliver = 0;
	nf.md_delivered = 1000;
	ok(nc_ut_push_one_msg(&ss, MSG(3)) == 1 && h->poisoned == poisoned + 1,
		"push: a cap of 0 disables the check");
	nats_consumer_poison_max_deliver = -1;
	ok(nc_ut_push_one_msg(&ss, MSG(4)) == 1 && h->poisoned == poisoned + 1,
		"push: a negative cap disables it too");
	while (nats_ring_pop(ss.ring, &out) == 0)
		;
	purge_msg_ref_row(IDX);
	nats_consumer_poison_max_deliver = saved;
	nc_ut_end();
}

void nc_ut_push(void)
{
	ok(setup(), "push: a private handle with a ring of %d", CAP);
	if (h && h->ring) {
		delivered();
		app_reply();
		deferred();
		oversize();
		poison();
	}
	teardown();
}
