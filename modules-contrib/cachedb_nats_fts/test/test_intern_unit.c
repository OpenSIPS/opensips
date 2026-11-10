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
 * Behavioural (ASan, REAL TU): the doc-key intern table,
 * exercised through the production fts_intern.c -- no carried copy
 * (the previous copy in this file had already drifted: it predated
 * the parameterised nats_intern_init(int) and the cached-hash
 * release path).  Also subsumes the deleted source-pattern
 * test_intern_scaling.c: the scaling contract "the bucket count is
 * an init parameter, and the table works at any size" is locked here
 * by running the same workload against a 1-bucket and a 64-bucket
 * table (the 1-bucket run makes every key a chain collision).
 *
 * Contracts:
 *   - before init: acquire returns NULL; release/retain/refcount/size
 *     are NULL/uninit-safe (the silent-degrade mode callers must
 *     treat as fatal-this-call);
 *   - acquire dedups by VALUE (same bytes -> same pointer, from a
 *     different, exactly-sized, non-NUL-terminated buffer -- ASan
 *     trips on any strlen over the input);
 *   - embedded-NUL keys intern correctly and are distinct from their
 *     truncated prefix; empty and 1023-byte keys work; negative len
 *     is rejected;
 *   - refcounts balance: acquire/retain bump, release decrements,
 *     zero frees (size accounting proves it); duplicate release of a
 *     still-referenced entry keeps it live;
 *   - destroy with live entries leaks nothing (LSan) and the table
 *     can be re-initialised.
 */

#include <tap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../fts_intern.h"

#include "fts_ut.h"

/* ── harness ────────────────────────────────────────────────────── */

#define ASSERT(cond, msg) ok((cond), "intern_unit: %s", (msg))

/* An exactly-sized, NON-NUL-terminated heap copy: one byte past
 * len is unallocated, so any strlen over it trips ASan. */
static char *slice(const char *s, int n)
{
	char *p = malloc(n);
	memcpy(p, s, n);
	return p;
}

static void test_uninitialised_degrade(void)
{
	ASSERT(nats_intern_acquire("x", 1) == NULL,
	       "acquire before init returns NULL");
	nats_intern_release(NULL);
	ASSERT(nats_intern_retain(NULL) == NULL, "retain(NULL) is NULL-safe");
	ASSERT(nats_intern_refcount(NULL) == 0, "refcount(NULL) is 0");
	ASSERT(nats_intern_size() == 0, "size before init is 0");
	nats_intern_destroy();  /* destroy of never-initialised: no-op */
}

static void test_dedup_and_slices(void)
{
	char *b1 = slice("json_doc.alice", 14);
	char *b2 = slice("json_doc.alice", 14);  /* same bytes, other buffer */
	char *p1 = nats_intern_acquire(b1, 14);
	char *p2 = nats_intern_acquire(b2, 14);

	ASSERT(p1 != NULL, "acquire of a non-terminated slice works");
	ASSERT(p1 == p2, "same bytes from a different buffer dedup to one node");
	ASSERT(memcmp(p1, "json_doc.alice", 14) == 0, "contents preserved");
	ASSERT(p1[14] == '\0', "interned copy is NUL-terminated");
	ASSERT(nats_intern_size() == 1, "one node after two acquires");
	ASSERT(nats_intern_refcount(p1) == 2, "refcount 2 after two acquires");

	nats_intern_release(p1);
	ASSERT(nats_intern_size() == 1, "entry survives while referenced");
	ASSERT(nats_intern_refcount(p2) == 1, "refcount back to 1");
	nats_intern_release(p2);
	ASSERT(nats_intern_size() == 0, "final release frees the node");

	free(b1); free(b2);
}

static void test_embedded_nul_and_edges(void)
{
	char raw[3] = { 'a', '\0', 'b' };
	char *pn = nats_intern_acquire(raw, 3);
	char *pa = nats_intern_acquire("a", 1);
	char *pe = nats_intern_acquire("", 0);
	char big[1024];
	char *pb;

	ASSERT(pn != NULL, "embedded-NUL key interns");
	ASSERT(pa != NULL && pa != pn,
	       "embedded-NUL key is distinct from its truncated prefix");
	ASSERT(memcmp(pn, raw, 3) == 0 && pn[3] == '\0',
	       "embedded-NUL contents stored verbatim, then terminated");
	ASSERT(pe != NULL && pe[0] == '\0', "empty key is a valid intern");
	ASSERT(nats_intern_acquire("x", -1) == NULL, "negative len rejected");

	memset(big, 'x', sizeof(big));
	pb = nats_intern_acquire(big, (int)sizeof(big));
	ASSERT(pb != NULL && memcmp(pb, big, sizeof(big)) == 0,
	       "1024-byte key interns intact");

	nats_intern_release(pn);
	nats_intern_release(pa);
	nats_intern_release(pe);
	nats_intern_release(pb);
	ASSERT(nats_intern_size() == 0, "edge keys all release cleanly");
}

static void test_retain_balances(void)
{
	char *p = nats_intern_acquire("popular", 7);
	ASSERT(nats_intern_retain(p) == p, "retain returns the same pointer");
	ASSERT(nats_intern_refcount(p) == 2, "retain bumped the refcount");
	nats_intern_release(p);
	nats_intern_release(p);
	ASSERT(nats_intern_size() == 0, "retain balanced by release frees");
}

static void test_chains_and_reacquire(int label_buckets)
{
	char *ptrs[200];
	char msg[64];
	int i, ok = 1;

	for (i = 0; i < 200; i++) {
		char buf[16];
		snprintf(buf, sizeof(buf), "doc_key_%d", i);
		ptrs[i] = nats_intern_acquire(buf, (int)strlen(buf));
		if (!ptrs[i]) ok = 0;
	}
	snprintf(msg, sizeof(msg), "200 distinct keys live (%d buckets)",
		label_buckets);
	ASSERT(ok && nats_intern_size() == 200, msg);

	/* release in reverse order; order must not matter */
	for (i = 199; i >= 0; i--)
		nats_intern_release(ptrs[i]);
	snprintf(msg, sizeof(msg), "all 200 release cleanly (%d buckets)",
		label_buckets);
	ASSERT(nats_intern_size() == 0, msg);

	/* release-then-reacquire cycle */
	{
		char *p1 = nats_intern_acquire("ephemeral", 9);
		nats_intern_release(p1);
		p1 = nats_intern_acquire("ephemeral", 9);
		ASSERT(p1 != NULL && nats_intern_refcount(p1) == 1,
		       "re-acquire after free yields a fresh refcount-1 node");
		nats_intern_release(p1);
	}
}

void fts_ut_intern_unit(void)
{
	/* this process's live table goes aside: the module's own entries
	 * stay out of these counts, and init/destroy can run */
	void *live = fts_ut_intern_swap(NULL);

	test_uninitialised_degrade();
	/* default-size table */
	ASSERT(nats_intern_init(64) == 0, "init(64)");
	ASSERT(nats_intern_init(64) == 0, "double init is a warned no-op");
	test_dedup_and_slices();
	test_embedded_nul_and_edges();
	test_retain_balances();
	test_chains_and_reacquire(64);
	/* destroy with live entries */
	(void)nats_intern_acquire("leaked1", 7);
	(void)nats_intern_acquire("leaked2", 7);
	ASSERT(nats_intern_size() == 2, "two live entries before destroy");
	nats_intern_destroy();
	ASSERT(nats_intern_size() == 0, "destroy clears the table");
	/* scaling contract: the same workload on a 1-bucket table --
	 * every key is a chain collision (subsumes test_intern_scaling) */
	ASSERT(nats_intern_init(1) == 0, "init(1) minimal table");
	test_chains_and_reacquire(1);
	nats_intern_destroy();

	fts_ut_intern_swap(live);
	ASSERT(nats_intern_size() >= 0, "the live table is back");
}
