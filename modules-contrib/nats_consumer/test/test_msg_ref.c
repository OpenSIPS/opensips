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
 * The consumer process's natsMsg ref table (nats_msg_ref.c): a fetched
 * message stays referenced there, keyed by the ack token handed to the
 * worker, until its ack.  Replaces tests/test_msg_ref_gen_epoch.c and
 * the purge half of tests/test_msg_ref_teardown.c, which modelled these
 * functions; here the real ones run, on this process's own table (the
 * consumer process has its own), with fake messages.
 *
 *  - An ack token packs a 16-bit generation that tells slot reuse apart
 *    within one row.  Unbinding frees the row, and a later bind of the
 *    same index makes a new one: a token still held from before must
 *    not redeem a message of the new row.
 *  - Purging a row (on every subscription teardown) destroys each
 *    message still referenced, once, and frees the row.
 *  - A message whose worker died before acking is reaped once it has been
 *    out longer than its TTL: 120 s, or twice the handle's ack_wait when
 *    that is longer, so a slow worker still inside ack_wait keeps it
 *    (tests/test_msg_ref_orphan_reap.c, test_orphan_ttl_ackwait.c).
 *  - The retire teardown of the consumer process (tear_down_retired_subs)
 *    purges the row of each subscription it tears down; it used to leak
 *    every outstanding message and the row.  It finds a subscription's
 *    handle by identity, not by id: unbind and rebind of the same id
 *    before the teardown leaves two handles with one id
 *    (tests/test_sub_identity_match.c), and here the retired and the live
 *    handle share their id.
 */

#include <tap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../nats_ack.h"
#include "../nats_handle_registry.h"
#include "../nats_handle_parse.h"
#include "../nats_consumer_proc_internal.h"

#include "nc_ut.h"

/* an index the module never binds in this suite */
#define IDX ((uint16_t)(NATS_REGISTRY_MAX_HANDLES - 1))
#define CAP 4

/* distinct fake messages: only their addresses are used */
static char m1, m2, m3, m4;
#define M(x) ((natsMsg *)&(x))

static uint64_t store_wait(natsMsg *m, int ack_wait_ms)
{
	int ok_;
	uint64_t t = store_msg_ref(IDX, CAP, ack_wait_ms, m, &ok_);

	return ok_ ? t : 0;
}

static uint64_t store(natsMsg *m)
{
	return store_wait(m, 30000);
}

/* moves the claim of token `t` `s` seconds into the past */
static void age(uint64_t t, long long s)
{
	g_msg_refs[nats_ack_token_handle(t)].slots[nats_ack_token_slot(t)]
		.claimed_at_us -= s * 1000000LL;
}

static void tokens(void)
{
	uint64_t t1, t2;

	t1 = store(M(m1));
	ok(t1 != 0 && nats_ack_token_handle(t1) == IDX,
		"msg_ref: a stored message gets a token of its handle");
	ok(release_msg_ref(t1) == M(m1), "msg_ref: its token redeems it");
	ok(release_msg_ref(t1) == NULL, "msg_ref: a token redeems once");

	t2 = store(M(m2));
	ok(t2 != 0 && t2 != t1, "msg_ref: the next message gets a new token");
	ok(release_msg_ref(nats_ack_token_pack(IDX,
		nats_ack_token_slot(t2), (uint16_t)(nats_ack_token_generation(t2) + 1)))
		== NULL, "msg_ref: a token of another generation is refused");
	ok(release_msg_ref(t2) == M(m2), "msg_ref: the right generation redeems");
	purge_msg_ref_row(IDX);
}

static void incarnations(void)
{
	uint64_t stale, fresh;
	int i;

	/* incarnation 1: one message is never acked (its worker held the
	 * token when the handle was unbound) */
	stale = store(M(m1));
	ok(stale != 0, "msg_ref: incarnation 1 stores a message");

	nc_ut_begin();
	purge_msg_ref_row(IDX);   /* unbind */
	nc_ut_end();

	/* incarnation 2 of the same index: fill every slot, so whichever
	 * slot the stale token names holds a new message */
	for (i = 0; i < CAP; i++)
		fresh = store(M(m2));
	ok(fresh != 0, "msg_ref: incarnation 2 fills its row");
	ok(release_msg_ref(stale) == NULL,
		"msg_ref: a token of incarnation 1 does not redeem incarnation 2's message");
	ok(release_msg_ref(fresh) == M(m2),
		"msg_ref: incarnation 2's own token redeems");

	nc_ut_begin();
	purge_msg_ref_row(IDX);
	nc_ut_end();
}

static void purge(void)
{
	uint64_t acked;

	acked = store(M(m1));
	store(M(m2));
	store(M(m3));
	ok(release_msg_ref(acked) == M(m1), "msg_ref: one of three is acked");

	nc_ut_begin();
	purge_msg_ref_row(IDX);
	ok(nf.n_msg_destroy == 2,
		"msg_ref: purge destroys the two messages still referenced");
	ok((nf.destroyed[0] == M(m2) || nf.destroyed[1] == M(m2)) &&
		(nf.destroyed[0] == M(m3) || nf.destroyed[1] == M(m3)),
		"msg_ref: and not the acked one");
	purge_msg_ref_row(IDX);
	ok(nf.n_msg_destroy == 2, "msg_ref: purging again destroys nothing");
	nc_ut_end();

	ok(release_msg_ref(acked) == NULL,
		"msg_ref: a token of a purged row is refused");
	store(M(m4));
	nc_ut_begin();
	purge_msg_ref_row(IDX);
	ok(nf.n_msg_destroy == 1 && nf.destroyed[0] == M(m4),
		"msg_ref: a row made again after a purge is purged again");
	nc_ut_end();
}

static void orphans(void)
{
	uint64_t old, fresh;
	int n;

	nc_ut_begin();
	old = store_wait(M(m1), 30000);
	fresh = store_wait(M(m2), 30000);
	age(old, 130);
	age(fresh, 60);
	n = reap_orphan_msg_refs();
	ok(n == 1 && nf.n_msg_destroy == 1 && nf.destroyed[0] == M(m1),
		"msg_ref: a message out 130 s (ack_wait 30 s) is reaped and destroyed");
	ok(release_msg_ref(old) == NULL,
		"msg_ref: the dead worker's late ack is refused");
	ok(strstr(nc_ut_log(), "reaped 1 orphaned msg-ref") != NULL,
		"msg_ref: the reap is logged");
	ok(release_msg_ref(fresh) == M(m2),
		"msg_ref: a message out 60 s is left to its worker");
	purge_msg_ref_row(IDX);

	nf.n_msg_destroy = 0;
	old = store_wait(M(m3), 90000);
	fresh = store_wait(M(m4), 90000);
	age(old, 200);
	age(fresh, 150);
	n = reap_orphan_msg_refs();
	ok(n == 1 && nf.n_msg_destroy == 1 && nf.destroyed[0] == M(m3),
		"msg_ref: with ack_wait 90 s a message out 200 s is reaped");
	ok(release_msg_ref(fresh) == M(m4),
		"msg_ref: with ack_wait 90 s a message out 150 s is kept (TTL 180 s)");
	purge_msg_ref_row(IDX);
	nc_ut_end();
}

/* a subscription state of the consumer process, on g_subs */
static proc_sub_state_t *sub_state(nats_handle_t *h, uint16_t idx)
{
	proc_sub_state_t *ss = calloc(1, sizeof *ss);

	if (!ss)
		return NULL;
	ss->id.s = strdup("ut_teardown");
	ss->id.len = ss->id.s ? 11 : 0;
	ss->h_ref = h;
	ss->handle_idx = idx;
	ss->sub = (natsSubscription *)ss;   /* opaque to the fake */
	ss->next = g_subs;
	g_subs = ss;
	g_subs_by_idx[idx] = ss;
	return ss;
}

static nats_handle_t *private_handle(const char *id)
{
	char buf[64];
	str cfg;
	const char *err = NULL;

	snprintf(buf, sizeof buf, "id=%s;stream=UT;durable=d", id);
	cfg.s = buf;
	cfg.len = (int)strlen(buf);
	return nats_handle_parse(&cfg, &err);
}

static void teardown(void)
{
	const uint16_t live_idx = (uint16_t)(IDX - 1);
	/* one id: the retired handle and its rebound successor */
	nats_handle_t *gone = private_handle("ut_same");
	nats_handle_t *live = private_handle("ut_same");
	proc_sub_state_t *ss_gone, *ss_live;
	natsSubscription *sub_gone;

	ok(gone && live && g_subs == NULL,
		"msg_ref: two private handles, and no subscription in this process");
	if (!gone || !live || g_subs)
		goto out;
	ss_live = sub_state(live, live_idx);
	ss_gone = sub_state(gone, IDX);
	if (!ss_live || !ss_gone)
		goto out;
	sub_gone = ss_gone->sub;
	store(M(m1));
	store(M(m2));
	__atomic_store_n(&gone->retire, 1, __ATOMIC_SEQ_CST);

	nc_ut_begin();
	nc_ut_tear_down_retired_subs();
	ok(nf.n_unsubscribe == 1 && nf.n_sub_destroy == 1 &&
		nf.sub_destroyed == sub_gone,
		"msg_ref: the retired subscription is unsubscribed and destroyed");
	ok(nf.n_msg_destroy == 2,
		"msg_ref: its two outstanding messages are destroyed");
	ok(__atomic_load_n(&gone->sub_torn_down, __ATOMIC_SEQ_CST) == 1,
		"msg_ref: its handle is marked torn down for the reaper");
	ok(g_subs == ss_live && ss_live->next == NULL &&
		g_subs_by_idx[IDX] == NULL && g_subs_by_idx[live_idx] == ss_live,
		"msg_ref: it leaves both lists, and the live one stays");
	nc_ut_end();

	/* the teardown must have left the live one; free it only if it did */
	if (g_subs == ss_live) {
		free(ss_live->id.s);
		free(ss_live);
	}
	g_subs = NULL;
	g_subs_by_idx[live_idx] = NULL;
out:
	if (gone) nats_handle_free(gone);
	if (live) nats_handle_free(live);
}

void nc_ut_msg_ref(void)
{
	tokens();
	incarnations();
	purge();
	orphans();
	teardown();
}
