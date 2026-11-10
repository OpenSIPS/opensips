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
 */

/*
 * nats_srv.c -- DNS SRV server discovery (see nats_srv.h).  libc only.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "nats_srv.h"

static int target_usable(const nats_srv_rec *r)
{
	return r->target[0] != '\0' && strcmp(r->target, ".") != 0;
}

static int cmp_fixed(const void *a, const void *b)
{
	const nats_srv_rec *x = a, *y = b;
	int c;

	if (x->priority != y->priority)
		return x->priority < y->priority ? -1 : 1;
	if (x->weight != y->weight)
		return x->weight > y->weight ? -1 : 1;
	c = strcmp(x->target, y->target);
	if (c)
		return c;
	return x->port < y->port ? -1 : (x->port > y->port ? 1 : 0);
}

/* priority only, weight 0 before the others (stable insertion sort, so
 * the answer order is kept otherwise) */
static void sort_priority_zero_first(nats_srv_rec *r, int n)
{
	int i, j;
	nats_srv_rec t;

	for (i = 1; i < n; i++) {
		t = r[i];
		j = i - 1;
		while (j >= 0 && (r[j].priority > t.priority ||
		    (r[j].priority == t.priority && r[j].weight != 0 && t.weight == 0))) {
			r[j + 1] = r[j];
			j--;
		}
		r[j + 1] = t;
	}
}

int nats_srv_order(nats_srv_rec *r, int n, int no_randomize,
		nats_srv_rand_f rnd, void *rctx)
{
	int i, k = 0, g, end;

	if (!no_randomize && !rnd)
		return -1;
	if (n > NATS_SRV_MAX_RECORDS)
		n = NATS_SRV_MAX_RECORDS;
	for (i = 0; i < n; i++)
		if (target_usable(&r[i]))
			r[k++] = r[i];
	n = k;

	if (no_randomize) {
		qsort(r, n, sizeof *r, cmp_fixed);
		return n;
	}

	sort_priority_zero_first(r, n);
	/* RFC 2782 selection inside each priority group [g, end) */
	for (g = 0; g < n; g = end) {
		for (end = g; end < n && r[end].priority == r[g].priority; end++)
			;
		for (i = g; i < end - 1; i++) {
			unsigned long sum = 0, run = 0, pick;
			int j, sel = i;
			nats_srv_rec t;

			for (j = i; j < end; j++)
				sum += r[j].weight;
			pick = (unsigned long)rnd(rctx) % (sum + 1);
			for (j = i; j < end; j++) {
				run += r[j].weight;
				if (run >= pick) {
					sel = j;
					break;
				}
			}
			t = r[sel];
			memmove(&r[i + 1], &r[i], (size_t)(sel - i) * sizeof *r);
			r[i] = t;
		}
	}
	return n;
}

/* split an SRV URL: scheme is TLS?, the user information (up to the last
 * '@') and the domain */
static int split_srv(const char *u, int *tls, const char **ui, int *ui_len,
		const char **dom)
{
	const char *rest, *at;

	if (!u)
		return -1;
	if (strncasecmp(u, "nats+srv://", 11) == 0) {
		*tls = 0;
		rest = u + 11;
	} else if (strncasecmp(u, "tls+srv://", 10) == 0) {
		*tls = 1;
		rest = u + 10;
	} else {
		return -1;
	}
	at = strrchr(rest, '@');
	if (at) {
		*ui = rest;
		*ui_len = (int)(at - rest);
		*dom = at + 1;
	} else {
		*ui = NULL;
		*ui_len = 0;
		*dom = rest;
	}
	return **dom ? 0 : -1;
}

int nats_srv_query_name(const char *srv_url, char *out, size_t size)
{
	const char *ui, *dom;
	int tls, ui_len, n;

	if (split_srv(srv_url, &tls, &ui, &ui_len, &dom) < 0)
		return -1;
	n = snprintf(out, size, "_nats._tcp.%s", dom);
	return (n < 0 || (size_t)n >= size) ? -1 : 0;
}

int nats_srv_url(const char *srv_url, const nats_srv_rec *r, char *out,
		size_t size)
{
	const char *ui, *dom;
	int tls, ui_len, tlen, n;

	if (split_srv(srv_url, &tls, &ui, &ui_len, &dom) < 0 || !target_usable(r))
		return -1;
	tlen = (int)strlen(r->target);
	if (tlen > 1 && r->target[tlen - 1] == '.')
		tlen--;
	if (ui)
		n = snprintf(out, size, "%s://%.*s@%.*s:%u", tls ? "tls" : "nats",
			ui_len, ui, tlen, r->target, (unsigned)r->port);
	else
		n = snprintf(out, size, "%s://%.*s:%u", tls ? "tls" : "nats",
			tlen, r->target, (unsigned)r->port);
	return (n < 0 || (size_t)n >= size) ? -1 : n;
}

static int is_srv(const char *u)
{
	return u && (strncasecmp(u, "nats+srv://", 11) == 0 ||
		strncasecmp(u, "tls+srv://", 10) == 0);
}

int nats_srv_expand(char *const *in, int n_in, char **out, int max,
		int no_randomize, nats_srv_resolve_f resolve, void *res_ctx,
		nats_srv_rand_f rnd, void *rnd_ctx, int *n_capped, int *n_failed)
{
	nats_srv_rec recs[NATS_SRV_MAX_RECORDS];
	char q[320], url[1024];
	int i, j, n = 0, got, capped = 0, failed = 0;

	for (i = 0; i < n_in; i++) {
		if (!is_srv(in[i])) {
			if (n < max) {
				if (!(out[n] = strdup(in[i])))
					break;
				n++;
			} else {
				capped++;
			}
			continue;
		}
		got = -1;
		if (resolve && nats_srv_query_name(in[i], q, sizeof q) == 0)
			got = resolve(q, recs, NATS_SRV_MAX_RECORDS, res_ctx);
		if (got > 0)
			got = nats_srv_order(recs, got, no_randomize, rnd, rnd_ctx);
		if (got <= 0) {
			failed++;
			continue;
		}
		for (j = 0; j < got; j++) {
			if (nats_srv_url(in[i], &recs[j], url, sizeof url) < 0)
				continue;
			if (n >= max) {
				capped++;
				continue;
			}
			if (!(out[n] = strdup(url)))
				break;
			n++;
		}
	}
	if (n_capped)
		*n_capped = capped;
	if (n_failed)
		*n_failed = failed;
	return n;
}

void nats_srv_free_list(char **list, int n)
{
	int i;

	for (i = 0; i < n; i++) {
		free(list[i]);
		list[i] = NULL;
	}
}
