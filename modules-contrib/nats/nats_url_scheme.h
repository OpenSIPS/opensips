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
 * nats_url_scheme.h -- classify the NATS server URLs the modules are
 * configured with.  Pure and header-inline (test/test_url_scheme.c).
 *
 *   tls://host[:port]          TLS
 *   nats+srv://domain          DNS SRV discovery (_nats._tcp.<domain>),
 *   tls+srv://domain           done by libnats; the second one with TLS
 *
 * Schemes are case-insensitive, as libnats treats them.
 */

#ifndef NATS_URL_SCHEME_H
#define NATS_URL_SCHEME_H

#include <stdio.h>
#include <string.h>
#include <strings.h>

static inline int nats_url_has_scheme(const char *url, const char *scheme)
{
	return url && strncasecmp(url, scheme, strlen(scheme)) == 0;
}

static inline int nats_url_is_tls(const char *url)
{
	return nats_url_has_scheme(url, "tls://")
		|| nats_url_has_scheme(url, "tls+srv://");
}

static inline int nats_url_is_srv(const char *url)
{
	return nats_url_has_scheme(url, "nats+srv://")
		|| nats_url_has_scheme(url, "tls+srv://");
}

/* Does any URL of a comma-separated list (tokenized as the pool does:
 * commas, spaces and tabs separate URLs) ask for SRV discovery? */
static inline int nats_url_list_has_srv(const char *list)
{
	const char *p = list;

	if (!p)
		return 0;
	while (*p) {
		while (*p == ',' || *p == ' ' || *p == '\t')
			p++;
		if (!*p)
			break;
		if (nats_url_is_srv(p))
			return 1;
		while (*p && *p != ',')
			p++;
	}
	return 0;
}

/* Is [d, d+n) a usable SRV domain: host name characters [A-Za-z0-9-_],
 * dot-separated labels of 1 to 63, 253 at most (plus a trailing dot)? */
static inline int nats_url_srv_domain_ok(const char *d, int n)
{
	int i, label = 0;

	if (n > 0 && d[n - 1] == '.')
		n--;
	if (n <= 0 || n > 253)
		return 0;
	for (i = 0; i < n; i++) {
		char c = d[i];
		if (c == '.') {
			if (label == 0)
				return 0;
			label = 0;
			continue;
		}
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '-' || c == '_'))
			return 0;
		if (++label > 63)
			return 0;
	}
	return label > 0;
}

/* Correct the SRV URL token [tok, tok+len) (nats_url_is_srv() true) into
 * @out, which has room for len + 1 bytes.  libnats takes the domain after
 * the last '@' and accepts no port and no path, so:
 *   1: the URL is fine;
 *   2: a port, path, query or fragment was dropped;
 *   0: there is no usable domain name (@out undefined).
 * For 1 and 2, @out is scheme://[credentials@]domain in its normal form:
 * the scheme in lower case, no trailing '/' or '.', as libnats reads it --
 * so the pool sees that two spellings are the same server. */
static inline int nats_url_srv_correct(const char *tok, int len, char *out)
{
	const char *end = tok + len, *auth, *d, *dend, *p;
	char *o = out;
	int n;

	auth = tok;
	while (auth + 3 <= end && memcmp(auth, "://", 3) != 0)
		auth++;
	if (auth + 3 > end)
		return 0;
	auth += 3;

	d = auth;
	for (p = auth; p < end; p++)
		if (*p == '@')
			d = p + 1;
	for (dend = d; dend < end && *dend != ':' && *dend != '/' &&
	     *dend != '?' && *dend != '#'; dend++)
		;
	if (!nats_url_srv_domain_ok(d, (int)(dend - d)))
		return 0;

	for (p = tok; p < auth; p++)
		*o++ = (*p >= 'A' && *p <= 'Z') ? (char)(*p - 'A' + 'a') : *p;
	n = (int)(dend - auth);
	if (dend[-1] == '.')
		n--;
	memcpy(o, auth, n);
	o[n] = '\0';

	return (dend == end || (dend + 1 == end && *dend == '/')) ? 1 : 2;
}

/* Write the SRV URL @url to @out (@size bytes, always NUL-terminated if
 * @size > 0) with its credentials masked, for logging.  libnats takes all
 * that comes before the LAST '@' of an SRV URL as credentials (it has no
 * path), so all of it is masked -- nats_redact_url() stops at a '/', which
 * a password may contain. */
static inline void nats_url_srv_redact(const char *url, char *out, size_t size)
{
	const char *auth, *at;

	if (size == 0)
		return;
	out[0] = '\0';
	if (!url)
		return;

	auth = strstr(url, "://");
	auth = auth ? auth + 3 : url;
	at = strrchr(auth, '@');
	if (!at)
		snprintf(out, size, "%s", url);
	else
		snprintf(out, size, "%.*s[redacted]%s", (int)(auth - url), url, at);
}

#endif /* NATS_URL_SCHEME_H */
