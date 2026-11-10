/*
 * Copyright (C) 2025 OpenSIPS Solutions
 * Copyright (C) 2025 Norm Brandinger <n.brandinger@gmail.com>
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

#include <string.h>

#include "cachedb_nats_url.h"

/* append [s, s+n) to out at *pos; -1 if it does not fit (NUL included) */
static int url_put(char *out, int out_size, int *pos, const char *s, int n)
{
	if (n < 0 || *pos + n >= out_size)
		return -1;
	memcpy(out + *pos, s, n);
	*pos += n;
	return 0;
}

/* a host entry: non-empty, "[v6]" or name/IPv4, optional ":digits" */
static int url_host_ok(const char *h, int n)
{
	int i = 0, port;

	if (n <= 0)
		return 0;
	if (h[0] == '[') {
		while (i < n && h[i] != ']')
			i++;
		if (i == n || i == 1)
			return 0;
		i++;
	} else {
		while (i < n && h[i] != ':')
			i++;
		if (i == 0)
			return 0;
	}
	if (i == n)
		return 1;
	if (h[i] != ':' || i + 1 == n)
		return 0;
	for (port = i + 1; port < n; port++)
		if (h[port] < '0' || h[port] > '9')
			return 0;
	return 1;
}

int cdbn_url_to_servers(const char *url, int url_len, char *out, int out_size)
{
	const char *end, *auth = NULL, *limit, *at = NULL, *hosts, *hosts_end;
	const char *opt, *c;
	int tls = 0, pos = 0, cred_len = 0;

	if (!url || url_len <= 0 || !out || out_size <= 0)
		return CDBN_URL_BAD;
	if (memchr(url, '\0', url_len))
		return CDBN_URL_BAD;
	end = url + url_len;

	/* "scheme[:group]://" */
	for (c = url; c + 3 <= end; c++)
		if (c[0] == ':' && c[1] == '/' && c[2] == '/') {
			auth = c + 3;
			break;
		}
	if (!auth)
		return CDBN_URL_BAD;

	/* "?opts" after the authority; options are '&'-separated */
	limit = memchr(auth, '?', end - auth);
	if (limit) {
		for (opt = limit + 1; opt < end; ) {
			const char *oe = memchr(opt, '&', end - opt);
			int ol = (oe ? oe : end) - opt;
			static const char key[] = "tls_domain=";
			int kl = sizeof(key) - 1;

			if (ol >= kl && !memcmp(opt, key, kl)) {
				if (ol - kl != (int)strlen(CDBN_TLS_DOMAIN) ||
						memcmp(opt + kl, CDBN_TLS_DOMAIN, ol - kl))
					return CDBN_URL_TLS_DOMAIN;
				tls = 1;
			}
			opt += ol + 1;
		}
	} else
		limit = end;

	/* "[user[:pass]@]" -- the last '@' (a password may hold '@' or ',') */
	for (c = auth; c < limit; c++)
		if (*c == '@')
			at = c;
	if (at) {
		if (at == auth)
			return CDBN_URL_BAD;
		cred_len = at - auth + 1;
	}
	hosts = at ? at + 1 : auth;
	hosts_end = memchr(hosts, '/', limit - hosts);
	if (!hosts_end)
		hosts_end = limit;
	if (hosts == hosts_end)
		return CDBN_URL_BAD;

	/* one scheme://[cred@]host per comma-separated host */
	for (c = hosts; c <= hosts_end; ) {
		const char *he = memchr(c, ',', hosts_end - c);
		int hl = (he ? he : hosts_end) - c;

		if (!url_host_ok(c, hl))
			return CDBN_URL_BAD;
		if ((pos && url_put(out, out_size, &pos, ",", 1) < 0) ||
		    url_put(out, out_size, &pos, tls ? "tls://" : "nats://",
				tls ? 6 : 7) < 0 ||
		    url_put(out, out_size, &pos, auth, cred_len) < 0 ||
		    url_put(out, out_size, &pos, c, hl) < 0)
			return CDBN_URL_BAD;
		if (!he)
			break;
		c = he + 1;
	}
	out[pos] = '\0';
	return pos;
}
