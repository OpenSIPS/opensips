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
 * nats_srv.h -- DNS SRV server discovery for the shared NATS connection.
 *
 * A nats+srv://[userinfo@]domain or tls+srv://[userinfo@]domain server URL
 * is resolved by the nats module itself (RFC 2782): the SRV records of
 * _nats._tcp.<domain> become plain nats:// or tls:// host:port URLs that
 * are handed to libnats with natsOptions_SetServers(), so any libnats
 * works; libnats resolves each target name at connect time.
 *
 * Pure functions (libc only), unit-tested by test/test_srv_order.c; the
 * DNS lookup itself is injected (nats_srv_resolve_f), the pool passes the
 * OpenSIPS core resolver.
 */

#ifndef NATS_SRV_H
#define NATS_SRV_H

#include <stddef.h>

/* most SRV records taken from one answer */
#define NATS_SRV_MAX_RECORDS 32

typedef struct nats_srv_rec {
	unsigned short priority;
	unsigned short weight;
	unsigned short port;
	char target[256];
} nats_srv_rec;

/* uniform 32-bit random number */
typedef unsigned int (*nats_srv_rand_f)(void *ctx);

/* Look up the SRV records of @qname into @out (at most @max).  Returns the
 * number of records, or -1 when the lookup failed. */
typedef int (*nats_srv_resolve_f)(const char *qname, nats_srv_rec *out,
		int max, void *ctx);

/*
 * Order @r in place (RFC 2782): priority ascending; inside a priority,
 * a weighted random choice (running sums over the weights, records of
 * weight 0 first so that they keep a small chance), or with
 * @no_randomize weight descending, then target name, then port.  Records
 * whose target is "." or empty (no service) are dropped.  Returns the
 * number of records left, or -1 when @no_randomize is 0 and @rnd is NULL.
 */
int nats_srv_order(nats_srv_rec *r, int n, int no_randomize,
		nats_srv_rand_f rnd, void *rctx);

/* "_nats._tcp.<domain>" of an SRV URL.  Returns 0, or -1 if @srv_url is
 * not an SRV URL or @size is too small. */
int nats_srv_query_name(const char *srv_url, char *out, size_t size);

/* "<tls|nats>://[userinfo@]<target>:<port>" for record @r of @srv_url,
 * the trailing dot of the target removed.  Returns the length, or -1. */
int nats_srv_url(const char *srv_url, const nats_srv_rec *r, char *out,
		size_t size);

/*
 * Expand the server list @in: each SRV URL is replaced, in place, by the
 * URLs of its ordered records; other URLs are copied.  At most @max
 * servers are written to @out (malloc'ed strings, freed with
 * nats_srv_free_list()); *@n_capped counts the URLs left out by the cap,
 * *@n_failed the SRV URLs that gave no server (lookup failed, no record,
 * or "no service").  Returns the number written.
 */
int nats_srv_expand(char *const *in, int n_in, char **out, int max,
		int no_randomize, nats_srv_resolve_f resolve, void *res_ctx,
		nats_srv_rand_f rnd, void *rnd_ctx, int *n_capped, int *n_failed);

void nats_srv_free_list(char **list, int n);

#endif /* NATS_SRV_H */
