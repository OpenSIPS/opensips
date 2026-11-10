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
 * test_srv_order.c -- DNS SRV server discovery done in the nats module
 * (nats_srv.c), so a nats+srv:// or tls+srv:// URL works with any libnats:
 *   - RFC 2782 order: priority ascending; inside a priority, a weighted
 *     random choice (weight-0 records keep a small chance); a target of
 *     "." means no service and is dropped;
 *   - with no_randomize: priority, then weight descending, then target
 *     name, then port -- the same list in every process;
 *   - the query name is _nats._tcp.<domain>;
 *   - each record becomes <scheme>://[userinfo@]<target>:<port>, with
 *     tls for tls+srv and nats for nats+srv, the trailing dot removed;
 *   - a server list expands each SRV URL in place, keeps plain URLs, stops
 *     at the cap and counts what it left out and what failed to resolve.
 */

#include <tap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../nats_srv.h"

#include "nats_ut.h"

#define ASSERT(cond, label) ok((cond), "%s", (label))

/* xorshift32: a reproducible random source for the weighted choice */
static unsigned int rnd_state = 2463534242u;
static unsigned int xrnd(void *ctx)
{
	unsigned int x = rnd_state;
	(void)ctx;
	x ^= x << 13; x ^= x >> 17; x ^= x << 5;
	return rnd_state = x;
}

static void rec(nats_srv_rec *r, int prio, int weight, int port, const char *t)
{
	r->priority = prio;
	r->weight = weight;
	r->port = port;
	snprintf(r->target, sizeof r->target, "%s", t);
}

static void test_priority(void)
{
	nats_srv_rec r[5];
	int n, i, ok = 1, trial;

	for (trial = 0; trial < 200; trial++) {
		rec(&r[0], 20, 10, 1, "c.example.test");
		rec(&r[1], 10, 10, 2, "a.example.test");
		rec(&r[2], 30, 10, 3, "d.example.test");
		rec(&r[3], 10, 90, 4, "b.example.test");
		rec(&r[4], 20, 0, 5, "e.example.test");
		n = nats_srv_order(r, 5, 0, xrnd, NULL);
		if (n != 5)
			ok = 0;
		for (i = 1; i < n; i++)
			if (r[i].priority < r[i - 1].priority)
				ok = 0;
	}
	ASSERT(ok, "randomized: every list is in ascending priority (200 draws)");
}

static void test_weights(void)
{
	nats_srv_rec r[3];
	int first[3] = {0, 0, 0}, trial, n;

	for (trial = 0; trial < 10000; trial++) {
		rec(&r[0], 1, 60, 1, "w60");
		rec(&r[1], 1, 30, 2, "w30");
		rec(&r[2], 1, 10, 3, "w10");
		n = nats_srv_order(r, 3, 0, xrnd, NULL);
		if (n == 3)
			first[r[0].port - 1]++;
	}
	diag("first choice of 10000: w60=%d w30=%d w10=%d",
		first[0], first[1], first[2]);
	ASSERT(first[0] > 5600 && first[0] < 6400, "weight 60 of 100 is first ~60% of the time");
	ASSERT(first[1] > 2600 && first[1] < 3400, "weight 30 of 100 is first ~30% of the time");
	ASSERT(first[2] > 700 && first[2] < 1300, "weight 10 of 100 is first ~10% of the time");
}

static void test_weight_zero(void)
{
	nats_srv_rec r[2];
	int zero_first = 0, trial;

	for (trial = 0; trial < 10000; trial++) {
		rec(&r[0], 1, 10, 1, "w10");
		rec(&r[1], 1, 0, 2, "w0");
		nats_srv_order(r, 2, 0, xrnd, NULL);
		if (r[0].port == 2)
			zero_first++;
	}
	diag("weight 0 first in %d of 10000", zero_first);
	ASSERT(zero_first > 300 && zero_first < 1500,
		"a weight-0 record keeps a small chance to be first (RFC 2782)");
}

static void test_no_randomize(void)
{
	nats_srv_rec r[5];
	int n;

	rec(&r[0], 20, 10, 4222, "c.example.test");
	rec(&r[1], 10, 10, 4222, "b.example.test");
	rec(&r[2], 10, 50, 4222, "z.example.test");
	rec(&r[3], 10, 10, 4222, "a.example.test");
	rec(&r[4], 10, 10, 4221, "a.example.test");
	n = nats_srv_order(r, 5, 1, NULL, NULL);
	ASSERT(n == 5 && !strcmp(r[0].target, "z.example.test"),
		"no_randomize: highest weight first inside the priority");
	ASSERT(!strcmp(r[1].target, "a.example.test") && r[1].port == 4221 &&
		!strcmp(r[2].target, "a.example.test") && r[2].port == 4222 &&
		!strcmp(r[3].target, "b.example.test"),
		"no_randomize: equal weights by target name, then port");
	ASSERT(!strcmp(r[4].target, "c.example.test"), "no_randomize: next priority last");
}

static void test_dot_target(void)
{
	nats_srv_rec r[3];

	rec(&r[0], 0, 0, 0, ".");
	ASSERT(nats_srv_order(r, 1, 1, NULL, NULL) == 0,
		"a single \".\" target means no service: nothing left");
	rec(&r[0], 10, 10, 4222, "a.example.test");
	rec(&r[1], 10, 10, 0, ".");
	rec(&r[2], 20, 10, 4222, "b.example.test");
	ASSERT(nats_srv_order(r, 3, 1, NULL, NULL) == 2 &&
		!strcmp(r[0].target, "a.example.test") && !strcmp(r[1].target, "b.example.test"),
		"a \".\" target among others is dropped");
	rec(&r[0], 10, 10, 4222, "");
	ASSERT(nats_srv_order(r, 1, 1, NULL, NULL) == 0, "an empty target is dropped");
	ASSERT(nats_srv_order(r, 1, 0, NULL, NULL) == -1,
		"randomized order without a random source is an error");
}

static void test_names(void)
{
	char q[300], u[600];
	nats_srv_rec r;

	ASSERT(nats_srv_query_name("nats+srv://example.test", q, sizeof q) == 0 &&
		!strcmp(q, "_nats._tcp.example.test"), "query name of nats+srv://example.test");
	ASSERT(nats_srv_query_name("tls+srv://u:p@example.test", q, sizeof q) == 0 &&
		!strcmp(q, "_nats._tcp.example.test"),
		"tls+srv with user information: same query name");
	ASSERT(nats_srv_query_name("TLS+SRV://tok@Example.Test", q, sizeof q) == 0 &&
		!strcmp(q, "_nats._tcp.Example.Test"), "scheme in any case");
	ASSERT(nats_srv_query_name("nats://example.test", q, sizeof q) < 0,
		"a plain URL has no query name");
	ASSERT(nats_srv_query_name("nats+srv://example.test", q, 10) < 0,
		"a buffer too small is an error");

	rec(&r, 10, 10, 4222, "n1.example.test.");
	ASSERT(nats_srv_url("nats+srv://example.test", &r, u, sizeof u) > 0 &&
		!strcmp(u, "nats://n1.example.test:4222"),
		"nats+srv record -> nats://target:port, trailing dot removed");
	ASSERT(nats_srv_url("tls+srv://example.test", &r, u, sizeof u) > 0 &&
		!strcmp(u, "tls://n1.example.test:4222"), "tls+srv record -> tls://");
	ASSERT(nats_srv_url("nats+srv://alice:s3cret@example.test", &r, u, sizeof u) > 0 &&
		!strcmp(u, "nats://alice:s3cret@n1.example.test:4222"),
		"the user information of the SRV URL is kept");
	ASSERT(nats_srv_url("nats+srv://a:b@c@example.test", &r, u, sizeof u) > 0 &&
		!strcmp(u, "nats://a:b@c@n1.example.test:4222"),
		"user information up to the LAST '@' (as libnats splits it)");
	ASSERT(nats_srv_url("nats+srv://example.test", &r, u, 12) < 0,
		"a buffer too small is an error");
}

/* fake resolver: answers by query name */
static int n_queries;
static int fake_resolve(const char *qname, nats_srv_rec *out, int max, void *ctx)
{
	(void)ctx;
	n_queries++;
	if (!strcmp(qname, "_nats._tcp.two.test") && max >= 2) {
		rec(&out[0], 20, 10, 4223, "n2.two.test.");
		rec(&out[1], 10, 10, 4222, "n1.two.test.");
		return 2;
	}
	if (!strcmp(qname, "_nats._tcp.many.test")) {
		int i;
		for (i = 0; i < max && i < 20; i++) {
			char t[32];
			snprintf(t, sizeof t, "m%02d.many.test", i);
			rec(&out[i], 10, 10, 4222, t);
		}
		return i;
	}
	if (!strcmp(qname, "_nats._tcp.none.test")) {
		rec(&out[0], 0, 0, 0, ".");
		return 1;
	}
	return -1;   /* lookup failed */
}

static void test_expand(void)
{
	char *in[4], *out[16];
	int n, capped, failed, i;

	in[0] = "nats://plain1:4222";
	in[1] = "nats+srv://u:p@two.test";
	in[2] = "nats://plain2:4222";
	n = nats_srv_expand(in, 3, out, 16, 1, fake_resolve, NULL, NULL, NULL,
		&capped, &failed);
	ASSERT(n == 4, "two plain URLs and an SRV URL with two targets: four servers");
	ASSERT(n == 4 && !strcmp(out[0], "nats://plain1:4222") &&
		!strcmp(out[1], "nats://u:p@n1.two.test:4222") &&
		!strcmp(out[2], "nats://u:p@n2.two.test:4223") &&
		!strcmp(out[3], "nats://plain2:4222"),
		"the targets replace the SRV URL in place, in priority order");
	ASSERT(capped == 0 && failed == 0, "nothing capped, nothing failed");
	nats_srv_free_list(out, n);

	in[0] = "nats+srv://broken.test";
	in[1] = "nats://plain1:4222";
	in[2] = "nats+srv://none.test";
	n = nats_srv_expand(in, 3, out, 16, 1, fake_resolve, NULL, NULL, NULL,
		&capped, &failed);
	ASSERT(n == 1 && !strcmp(out[0], "nats://plain1:4222"),
		"a failed lookup and a \"no service\" answer add no server; the rest stay");
	ASSERT(failed == 2, "both SRV URLs are counted as failed");
	nats_srv_free_list(out, n);

	in[0] = "nats://plain1:4222";
	in[1] = "nats+srv://many.test";
	n = nats_srv_expand(in, 2, out, 16, 1, fake_resolve, NULL, NULL, NULL,
		&capped, &failed);
	ASSERT(n == 16 && capped == 5,
		"21 servers for a cap of 16: 16 kept, 5 counted as left out");
	nats_srv_free_list(out, n);

	in[0] = "nats+srv://broken.test";
	n = nats_srv_expand(in, 1, out, 16, 1, fake_resolve, NULL, NULL, NULL,
		&capped, &failed);
	ASSERT(n == 0 && failed == 1, "only an unresolvable SRV URL: no server");

	n_queries = 0;
	in[0] = "nats://a:1";
	in[1] = "tls://b:2";
	n = nats_srv_expand(in, 2, out, 16, 0, fake_resolve, NULL, xrnd, NULL,
		&capped, &failed);
	ASSERT(n == 2 && n_queries == 0 && !strcmp(out[1], "tls://b:2"),
		"plain URLs only: copied, no lookup");
	for (i = 0; i < n; i++)
		ASSERT(out[i] != in[i], "the output is a copy, not the caller's string");
	nats_srv_free_list(out, n);
}

void nats_ut_srv_order(void)
{
	test_priority();
	test_weights();
	test_weight_zero();
	test_no_randomize();
	test_dot_target();
	test_names();
	test_expand();

}
