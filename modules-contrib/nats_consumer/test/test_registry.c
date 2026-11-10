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
 * The handle registry (nats_handle_registry.c), in the module's live
 * shared-memory instance.  Replaces tests/test_registry.c, which built a
 * private registry with init/destroy under the test shim.  The consumer
 * process reconciles and reaps this registry every loop iteration, so
 * the scenarios run while it is held (nc_ut_hold_consumer()); they use
 * ids of their own and leave the registry as they found it.  The cfg's
 * own bind (ut_bind) stays in it, so counts are compared as deltas.
 *
 * Also replaces, each against the real registry instead of its own:
 *  - tests/test_registry_lookup_ref.c: lookup_ref() takes its reference
 *    under the bucket lock, so a handle borrowed by a fetch survives an
 *    unbind + reap until the reference is released (the plain lookup let
 *    the reaper free it under the caller);
 *  - tests/test_registry_index_recycle.c: indexes are taken only by a bind
 *    that succeeds and come back when a handle is reaped (a burnt index
 *    per duplicate bind used to disable binding for good after 256);
 *  - tests/test_retired_no_sub_reap.c and test_orphan_msg_ref_purge.c: a
 *    handle unbound before the consumer process ever subscribed it is
 *    marked torn down by mark_orphan_retired_handles(), so the reaper
 *    frees it and its ring, and any ref row presized for it is purged;
 *  - tests/test_registry_foreach_unlocked.c: the reconcile walk visits
 *    each live handle once, pinned, with no registry lock held, so a
 *    callback can unbind and reap (and a slow broker call in it stalls no
 *    worker's lookup);
 *  - tests/test_registry_ring_alloc_order.c: a refused bind allocates no
 *    ring (rings reach 1.2 GB, and MI can repeat a refused bind at will).
 */

#include <tap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../nats_handle_registry.h"
#include "../nats_handle_parse.h"
#include "../nats_ring.h"
#include "../nats_consumer_proc_internal.h"

#include "nc_ut.h"

/* Binds a handle with the smallest ring; returns bind's result, freeing
 * the handle when the registry did not take it. */
static int bind_as(const char *id, const char *stream, nats_handle_t **out)
{
	char buf[160];
	str cfg;
	const char *err = NULL;
	nats_handle_t *h;
	int rc;

	snprintf(buf, sizeof buf, "id=%s;stream=%s;durable=d;ring_capacity=2",
		id, stream);
	cfg.s = buf;
	cfg.len = (int)strlen(buf);
	h = nats_handle_parse(&cfg, &err);
	if (!h)
		return -100;
	rc = nats_registry_bind(h);
	if (rc != 0)
		nats_handle_free(h);
	else if (out)
		*out = h;
	return rc;
}

/* Unbinds `id` and reaps it as the consumer process would: marks the
 * subscription torn down, then reaps.  Returns 0 when it is gone. */
static int unbind_and_reap(const char *id_s)
{
	str id = { (char *)id_s, (int)strlen(id_s) };
	nats_handle_t *h;

	if (nats_registry_unbind(&id) != 0)
		return -1;
	h = nats_registry_lookup_weak(&id);
	if (h)
		__atomic_store_n(&h->sub_torn_down, 1, __ATOMIC_SEQ_CST);
	nats_registry_reap();
	return nats_registry_lookup_weak(&id) ? -1 : 0;
}

static int stream_is(const nats_handle_t *h, const char *s)
{
	return h && h->stream.len == (int)strlen(s) &&
		memcmp(h->stream.s, s, h->stream.len) == 0;
}

static nats_handle_t *lookup(const char *id_s)
{
	str id = { (char *)id_s, (int)strlen(id_s) };

	return nats_registry_lookup(&id);
}

static void bind_lookup(void)
{
	int base = nats_registry_count();
	nats_handle_t *h1 = NULL, *h2 = NULL;
	str nope = str_init("ut_reg_nope");

	ok(bind_as("ut_reg_alpha", "S1", &h1) == 0 &&
		bind_as("ut_reg_beta", "S2", &h2) == 0,
		"registry: two handles bind");
	ok(nats_registry_count() == base + 2, "registry: the count grows by two");
	ok(lookup("ut_reg_alpha") == h1 && stream_is(h1, "S1"),
		"registry: the first is found by its id");
	ok(lookup("ut_reg_beta") == h2 && stream_is(h2, "S2"),
		"registry: the second is found by its id");
	ok(h1 && h2 && h1->ring && h2->ring,
		"registry: bind gives each handle its ring");

	ok(bind_as("ut_reg_alpha", "S3", NULL) == -1 &&
		nats_registry_count() == base + 2 && stream_is(lookup("ut_reg_alpha"), "S1"),
		"registry: a duplicate id is refused and the first stays");
	ok(nats_registry_unbind(&nope) == -1 && nats_registry_count() == base + 2,
		"registry: unbinding an unknown id is refused");

	ok(unbind_and_reap("ut_reg_alpha") == 0 && lookup("ut_reg_alpha") == NULL &&
		nats_registry_count() == base + 1,
		"registry: an unbound handle is gone after its reap");
	ok(lookup("ut_reg_beta") == h2, "registry: the other one stays");
	ok(unbind_and_reap("ut_reg_beta") == 0 && nats_registry_count() == base,
		"registry: and goes too");
}

struct seen {
	int count, stop_after;
};

static int count_ours(nats_handle_t *h, void *arg)
{
	struct seen *s = arg;

	if (h->id.len < 7 || memcmp(h->id.s, "ut_reg_", 7) != 0)
		return 0;
	s->count++;
	return s->stop_after && s->count >= s->stop_after ? 42 : 0;
}

static void foreach(void)
{
	struct seen s;

	ok(bind_as("ut_reg_a", "S", NULL) == 0 && bind_as("ut_reg_b", "S", NULL) == 0 &&
		bind_as("ut_reg_c", "S", NULL) == 0, "registry: three handles bind");
	memset(&s, 0, sizeof s);
	ok(nats_registry_foreach(count_ours, &s) == 0 && s.count == 3,
		"registry: foreach visits each of them");
	memset(&s, 0, sizeof s);
	s.stop_after = 2;
	ok(nats_registry_foreach(count_ours, &s) == 42 && s.count == 2,
		"registry: foreach stops at a callback's non-zero answer and returns it");
	ok(unbind_and_reap("ut_reg_a") == 0 && unbind_and_reap("ut_reg_b") == 0 &&
		unbind_and_reap("ut_reg_c") == 0, "registry: they unbind");
}

static void indexes(void)
{
	nats_handle_t *a = NULL, *b = NULL, *c = NULL;

	ok(bind_as("ut_reg_x1", "S", &a) == 0 && bind_as("ut_reg_x2", "S", &b) == 0 &&
		bind_as("ut_reg_x3", "S", &c) == 0, "registry: three more bind");
	ok(a && b && c && a->index != b->index && b->index != c->index &&
		a->index != c->index, "registry: each has its own index");
	ok(a && b && c && a->index < NATS_REGISTRY_MAX_HANDLES &&
		b->index < NATS_REGISTRY_MAX_HANDLES && c->index < NATS_REGISTRY_MAX_HANDLES,
		"registry: every index is below the cap");
	unbind_and_reap("ut_reg_x1");
	unbind_and_reap("ut_reg_x2");
	unbind_and_reap("ut_reg_x3");
}

static void retire(void)
{
	nats_handle_t *h = NULL, *weak;
	str id = str_init("ut_reg_busy");

	ok(bind_as("ut_reg_busy", "S", &h) == 0, "registry: a handle binds");
	if (!h)
		return;
	nats_handle_pending_inc(h);   /* a worker is mid-operation */
	ok(nats_registry_unbind(&id) == 0, "registry: unbind succeeds while it is in use");
	ok(nats_registry_lookup(&id) == NULL, "registry: a retired handle is not found");
	weak = nats_registry_lookup_weak(&id);
	ok(weak == h && __atomic_load_n(&h->retire, __ATOMIC_SEQ_CST) == 1,
		"registry: it is parked, marked retired, for the consumer process");
	nats_registry_reap();
	ok(nats_registry_lookup_weak(&id) == h,
		"registry: reap leaves it while its subscription is not torn down");
	__atomic_store_n(&h->sub_torn_down, 1, __ATOMIC_SEQ_CST);
	nats_registry_reap();
	ok(nats_registry_lookup_weak(&id) == h,
		"registry: and while a worker still holds it");
	nats_handle_pending_dec(h);
	nats_registry_reap();
	ok(nats_registry_lookup_weak(&id) == NULL,
		"registry: torn down and released, reap frees it");
}

/* binds handles up to the cap; returns how many it bound */
static int fill(const char *prefix)
{
	char id[40];
	int i, n = 0, room = NATS_REGISTRY_MAX_HANDLES - nats_registry_count();

	for (i = 0; i < room; i++) {
		snprintf(id, sizeof id, "%s%d", prefix, i);
		if (bind_as(id, "S", NULL) == 0)
			n++;
	}
	return n;
}

static void empty(const char *prefix, int n)
{
	char id[40];
	int i;

	for (i = 0; i < n; i++) {
		snprintf(id, sizeof id, "%s%d", prefix, i);
		unbind_and_reap(id);
	}
}

static void cap(void)
{
	int i, n, rc, dups = 0, base = nats_registry_count();

	n = fill("ut_reg_cap");
	ok(n == NATS_REGISTRY_MAX_HANDLES - base &&
		nats_registry_count() == NATS_REGISTRY_MAX_HANDLES,
		"registry: binds fill it to its cap of %d", NATS_REGISTRY_MAX_HANDLES);
	rc = bind_as("ut_reg_one_more", "S", NULL);
	ok(rc == -3, "registry: one more is refused with -3 (got %d)", rc);
	empty("ut_reg_cap", n);
	ok(nats_registry_count() == base, "registry: back to where it was");

	ok(fill("ut_reg_again") == n,
		"registry: a full cap binds again once the last were reaped");
	empty("ut_reg_again", n);

	ok(bind_as("ut_reg_keep", "S", NULL) == 0, "registry: one handle binds");
	for (i = 0; i < 2 * NATS_REGISTRY_MAX_HANDLES; i++)
		if (bind_as("ut_reg_keep", "S", NULL) == -1)
			dups++;
	ok(dups == 2 * NATS_REGISTRY_MAX_HANDLES,
		"registry: %d binds of its id are refused as duplicates", dups);
	n = fill("ut_reg_after");
	ok(nats_registry_count() == NATS_REGISTRY_MAX_HANDLES,
		"registry: the duplicates used up no index: it still fills to the cap");
	empty("ut_reg_after", n);
	unbind_and_reap("ut_reg_keep");
	ok(nats_registry_count() == base, "registry: back to where it was");
}

static void borrowed(void)
{
	nats_handle_t *h = NULL, *b;
	str id = str_init("ut_reg_borrow");
	int before;

	ok(bind_as("ut_reg_borrow", "S", &h) == 0, "registry: a handle binds");
	if (!h)
		return;
	before = nats_handle_pending_get(h);
	b = nats_registry_lookup_ref(&id);
	ok(b == h && nats_handle_pending_get(h) == before + 1,
		"registry: lookup_ref returns it with a reference taken");
	ok(nats_registry_unbind(&id) == 0, "registry: it is unbound meanwhile");
	__atomic_store_n(&h->sub_torn_down, 1, __ATOMIC_SEQ_CST);
	nats_registry_reap();
	ok(nats_registry_lookup_weak(&id) == h &&
		__atomic_load_n(&h->retire, __ATOMIC_SEQ_CST) == 1,
		"registry: the borrowed handle survives unbind + reap");
	nats_handle_pending_dec(h);
	nats_registry_reap();
	ok(nats_registry_lookup_weak(&id) == NULL,
		"registry: it is freed once the reference is released");
	ok(nats_registry_lookup_ref(&id) == NULL,
		"registry: lookup_ref of an unbound id takes nothing");
}

static void never_subscribed(void)
{
	nats_handle_t *h = NULL, *subbed = NULL;
	str id = str_init("ut_reg_nosub"), id2 = str_init("ut_reg_subbed");
	proc_sub_state_t *ss;
	int ok_;
	char msg;

	ok(bind_as("ut_reg_nosub", "S", &h) == 0 &&
		bind_as("ut_reg_subbed", "S", &subbed) == 0,
		"registry: two handles bind");
	if (!h || !subbed)
		return;
	/* the consumer process subscribed the second one (it has a sub
	 * state); the first got only a presized ref row from a subscribe
	 * that failed */
	ss = calloc(1, sizeof *ss);
	if (!ss)
		return;
	g_subs_by_idx[subbed->index] = ss;
	store_msg_ref(h->index, 2, 30000, (natsMsg *)&msg, &ok_);

	nats_registry_unbind(&id);
	nats_registry_unbind(&id2);
	nc_ut_begin();
	nc_ut_mark_orphan_retired_handles();
	ok(__atomic_load_n(&h->sub_torn_down, __ATOMIC_SEQ_CST) == 1,
		"registry: a retired handle never subscribed is marked torn down");
	ok(nf.n_msg_destroy == 1 && nf.destroyed[0] == (natsMsg *)&msg,
		"registry: and the ref row presized for it is purged");
	ok(__atomic_load_n(&subbed->sub_torn_down, __ATOMIC_SEQ_CST) == 0,
		"registry: a retired handle with a subscription is left to its teardown");
	nc_ut_end();
	nats_registry_reap();
	ok(nats_registry_lookup_weak(&id) == NULL,
		"registry: the reaper frees the never-subscribed handle");

	g_subs_by_idx[subbed->index] = NULL;
	free(ss);
	__atomic_store_n(&subbed->sub_torn_down, 1, __ATOMIC_SEQ_CST);
	nats_registry_reap();
	ok(nats_registry_lookup_weak(&id2) == NULL, "registry: and the other one after it");
}

struct walk {
	int visits, pinned, unbound;
	nats_handle_t *seen[4];
};

static int walk_cb(nats_handle_t *h, void *arg)
{
	struct walk *w = arg;
	str victim = str_init("ut_reg_w2");

	if (h->id.len < 9 || memcmp(h->id.s, "ut_reg_w", 8) != 0)
		return 0;
	if (w->visits < 4)
		w->seen[w->visits] = h;
	w->visits++;
	if (nats_handle_pending_get(h) > 0)
		w->pinned++;
	/* a registry lock held here would deadlock this unbind and reap */
	if (h->id.len == 9 && memcmp(h->id.s, "ut_reg_w2", 9) == 0) {
		w->unbound = nats_registry_unbind(&victim) == 0;
		__atomic_store_n(&h->sub_torn_down, 1, __ATOMIC_SEQ_CST);
		nats_registry_reap();
	}
	return 0;
}

static void walk_unlocked(void)
{
	nats_handle_t *a = NULL, *b = NULL, *c = NULL;
	struct walk w;
	str id_b = str_init("ut_reg_w2");
	int pa, pc;

	ok(nats_registry_foreach_unlocked(NULL, NULL) == 0,
		"registry: foreach_unlocked with no callback does nothing");
	ok(bind_as("ut_reg_w1", "S", &a) == 0 && bind_as("ut_reg_w2", "S", &b) == 0 &&
		bind_as("ut_reg_w3", "S", &c) == 0, "registry: three handles bind");
	if (!a || !b || !c)
		return;
	pa = nats_handle_pending_get(a);
	pc = nats_handle_pending_get(c);
	memset(&w, 0, sizeof w);
	ok(nats_registry_foreach_unlocked(walk_cb, &w) == 0 && w.visits == 3,
		"registry: foreach_unlocked visits the three");
	ok(w.seen[0] != w.seen[1] && w.seen[1] != w.seen[2] && w.seen[0] != w.seen[2],
		"registry: each once");
	ok(w.pinned == 3, "registry: each pinned while its callback runs");
	ok(w.unbound && __atomic_load_n(&b->retire, __ATOMIC_SEQ_CST) == 1,
		"registry: a callback can unbind (no registry lock is held)");
	ok(nats_handle_pending_get(a) == pa && nats_handle_pending_get(c) == pc,
		"registry: every pin is released after the walk");
	nats_registry_reap();
	ok(nats_registry_lookup_weak(&id_b) == NULL,
		"registry: the handle unbound mid-walk is reaped once its pin is gone");
	unbind_and_reap("ut_reg_w1");
	unbind_and_reap("ut_reg_w3");
}

static void ring_order(void)
{
	char buf[] = "id=ut_reg_ring;stream=S;durable=d;ring_capacity=2";
	str cfg = { buf, (int)sizeof buf - 1 };
	const char *err = NULL;
	nats_handle_t *h;
	int made, freed, n;

	made = nc_ut_rings_created;
	ok(bind_as("ut_reg_ring", "S", NULL) == 0 && nc_ut_rings_created == made + 1,
		"registry: a successful bind makes one ring");
	made = nc_ut_rings_created;
	ok(bind_as("ut_reg_ring", "S", NULL) == -1 && nc_ut_rings_created == made,
		"registry: a refused duplicate makes no ring");

	h = nats_handle_parse(&cfg, &err);
	if (h) {
		h->id.len = 0;
		ok(nats_registry_bind(h) == -2 && nc_ut_rings_created == made,
			"registry: a bind refused for an empty id makes no ring");
		nats_handle_free(h);
	}

	n = fill("ut_reg_rcap");
	made = nc_ut_rings_created;
	ok(bind_as("ut_reg_ring_over", "S", NULL) == -3 && nc_ut_rings_created == made,
		"registry: a bind refused at the cap makes no ring");
	empty("ut_reg_rcap", n);

	freed = nc_ut_rings_destroyed;
	unbind_and_reap("ut_reg_ring");
	ok(nc_ut_rings_destroyed == freed + 1,
		"registry: reaping an unbound handle frees its ring");
}

void nc_ut_registry(void)
{
	walk_unlocked();
	ring_order();
	bind_lookup();
	foreach();
	indexes();
	retire();
	borrowed();
	never_subscribed();
	cap();
}
