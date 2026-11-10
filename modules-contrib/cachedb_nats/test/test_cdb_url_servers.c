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
 * the NATS server list cachedb_nats derives from
 * cachedb_url when no nats_url is set.
 *
 * Every host needs its own scheme ("nats://h1,nats://h2", not
 * "nats://h1,h2"), credentials apply to every host, and TLS is asked for
 * the way cachedb_redis does it: "?tls_domain=<dom>" (the NATS pool's TLS
 * comes from the tls_mgm "nats" client domain, so that is the only name
 * accepted).  The URL is not NUL-terminated (core cachedb_store_url()), so
 * nothing past url_len may be read: every URL below is followed in its
 * buffer by another host and a TLS option, which an overread would pick up.
 */

#include <tap.h>
#include <string.h>

#include "../cachedb_nats_url.h"

#include "cn_ut.h"

/* What follows the URL in its buffer: another host and a TLS option, so a
 * parser reading past url_len returns something else (no ASan here). */
#define TAIL ",evil:1/?tls_domain=nats"

static void expect(const char *url, const char *want, int want_rc)
{
	int n = (int)strlen(url), rc;
	char u[512];
	char out[512];

	memcpy(u, url, n);
	memcpy(u + n, TAIL, sizeof TAIL);   /* not part of the URL */
	out[0] = '\0';
	rc = cdbn_url_to_servers(u, n, out, sizeof out);
	if (want)
		ok(rc == (int)strlen(want) && !strcmp(out, want),
			"cdb_url_servers: %s -> %s (got rc=%d '%s')",
			url, want, rc, rc >= 0 ? out : "");
	else
		ok(rc == want_rc, "cdb_url_servers: %s -> rc %d (got %d)",
			url, want_rc, rc);
}

void cn_ut_cdb_url_servers(void)
{
	char small[16];

	diag("hosts:");
	expect("nats:loc://127.0.0.1:4222/", "nats://127.0.0.1:4222", 0);
	expect("nats:loc://127.0.0.1:4222", "nats://127.0.0.1:4222", 0);
	expect("nats:loc://h1:4222,h2:4223/", "nats://h1:4222,nats://h2:4223", 0);
	expect("nats:loc://h1:4222,h2:4223,h3:4224/kvdb",
		"nats://h1:4222,nats://h2:4223,nats://h3:4224", 0);
	expect("nats:loc://[::1]:4222,[fe80::1]:4223/",
		"nats://[::1]:4222,nats://[fe80::1]:4223", 0);
	expect("nats://h:4222/", "nats://h:4222", 0);   /* no group */

	diag("credentials go on every host:");
	expect("nats:loc://user:pw@h1:4222,h2:4222/",
		"nats://user:pw@h1:4222,nats://user:pw@h2:4222", 0);
	expect("nats:loc://u:p@ss,w0rd@h1:4222/",
		"nats://u:p@ss,w0rd@h1:4222", 0);   /* '@' and ',' in the password */
	expect("nats:loc://tok@h1:4222/", "nats://tok@h1:4222", 0);

	diag("TLS the cachedb_redis way:");
	expect("nats:loc://h1:4222,h2:4223/?tls_domain=nats",
		"tls://h1:4222,tls://h2:4223", 0);
	expect("nats:loc://user:pw@h1:4222/kv?tls_domain=nats",
		"tls://user:pw@h1:4222", 0);
	expect("nats:loc://h1:4222/?foo=bar&tls_domain=nats", "tls://h1:4222", 0);
	expect("nats:loc://h1:4222/?tls_domain=nats&foo=bar", "tls://h1:4222", 0);
	expect("nats:loc://h1:4222/?tls_domain=redis", NULL, CDBN_URL_TLS_DOMAIN);
	expect("nats:loc://h1:4222/?tls_domain=", NULL, CDBN_URL_TLS_DOMAIN);
	expect("nats:loc://h1:4222/?tls_domain=natsx", NULL, CDBN_URL_TLS_DOMAIN);
	expect("nats:loc://h1:4222/?foo=bar", "nats://h1:4222", 0);

	diag("unusable URLs:");
	expect("", NULL, CDBN_URL_BAD);
	expect("nats:loc:/h:4222/", NULL, CDBN_URL_BAD);
	expect("nats:loc://", NULL, CDBN_URL_BAD);
	expect("nats:loc:///", NULL, CDBN_URL_BAD);
	expect("nats:loc://h1:4222,,h2:4223/", NULL, CDBN_URL_BAD);
	expect("nats:loc://h1:4222,/", NULL, CDBN_URL_BAD);
	expect("nats:loc://user:pw@/", NULL, CDBN_URL_BAD);
	expect("nats:loc://tls://h:4222/", NULL, CDBN_URL_BAD);  /* not a host */

	diag("bounds:");
	{
		/* the URL ends at url_len even if the buffer goes on */
		const char *buf = "nats:loc://h1:4222/?tls_domain=nats";
		char out[64];
		int rc = cdbn_url_to_servers(buf, 18, out, sizeof out);
		ok(rc >= 0 && !strcmp(out, "nats://h1:4222"),
			"cdb_url_servers: url_len honoured: options past it ignored (rc=%d)", rc);
	}
	ok(cdbn_url_to_servers("nats:loc://hostname:4222/", 25, small,
			sizeof small) == CDBN_URL_BAD,
		"cdb_url_servers: an output that does not fit is refused");
	{
		char out[64];
		int rc = cdbn_url_to_servers("nats:loc://h\0x:4222/", 20, out, sizeof out);
		ok(rc == CDBN_URL_BAD, "cdb_url_servers: embedded NUL refused (rc=%d)", rc);
	}
}
