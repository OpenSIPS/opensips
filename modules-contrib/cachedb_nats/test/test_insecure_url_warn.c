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
 * The registration bucket is a PII / LI-relevant
 * store (subscriber IP, UA, call-id, path).  Transport + auth are MANDATORY:
 * cachedb_nats MUST emit a startup LM_WARN when cachedb_url is plaintext
 * nats:// and/or carries no credentials, naming the data classification.
 *
 * nats_url_insecure_for(url, auth) drives the WARN: 1 if the URL must be
 * warned about (not tls://, OR no credentials: neither "user[:pass]@" in the
 * authority nor credential modparams), else 0.  URL credentials are only
 * recognized in the AUTHORITY (between "://" and the first "/"), so an "@"
 * in a path/query is not mistaken for credentials.
 *
 * Rule 6: the AUTHORITATIVE proof is the Tier-2 e2e against a TLS+accounts broker
 * fixture (insecure URL => WARN fires; tenant A cred cannot read tenant B).
 */
#include <tap.h>
#include <string.h>

#include "../../nats/nats_auth.h"

#include "cn_ut.h"

/* The production rule (cachedb_nats.c calls nats_url_insecure_for() with
 * nats_pool_auth_configured()); no carried copy, so the test cannot
 * drift from the code.  Here: no credential modparams. */
static int nats_url_insecure(const char *url)
{
	return nats_url_insecure_for(url, 0);
}

#define CHECK(cond, msg) do { if (!(cond)) { fail("insecure_url_warn: %s", msg); } \
	else pass("insecure_url_warn: %s", msg); } while (0)

void cn_ut_insecure_url_warn(void)
{
	diag("== nats_url_insecure_for (modules-contrib/nats/nats_auth.h) ==");

	diag("insecure URLs MUST warn:");
	CHECK(nats_url_insecure("nats://host:4222") == 1, "plaintext + no creds => WARN");
	CHECK(nats_url_insecure("nats://user:pass@host:4222") == 1, "plaintext WITH creds => still WARN (no TLS)");
	CHECK(nats_url_insecure("tls://host:4222") == 1, "TLS but NO creds => WARN");
	CHECK(nats_url_insecure("192.0.2.31:4222") == 1, "no scheme => WARN (malformed)");
	CHECK(nats_url_insecure(NULL) == 1, "NULL url => WARN");

	diag("only TLS + credentials is clean (no warn):");
	CHECK(nats_url_insecure("tls://user:pass@host:4222") == 0, "tls + user:pass => no WARN");
	CHECK(nats_url_insecure("tls://user@host:4222") == 0, "tls + user@ (creds present) => no WARN");
	CHECK(nats_url_insecure("tls://u:p@host:4222/path") == 0, "tls + creds + path => no WARN");

	diag("DNS SRV URLs are classified by their transport:");
	CHECK(nats_url_insecure("tls+srv://user:pass@example.com") == 0, "tls+srv + creds => no WARN");
	CHECK(nats_url_insecure("TLS+SRV://user@example.com") == 0, "TLS+SRV (any case) + creds => no WARN");
	CHECK(nats_url_insecure("tls+srv://example.com") == 1, "tls+srv but NO creds => WARN");
	CHECK(nats_url_insecure("nats+srv://user:pass@example.com") == 1, "nats+srv WITH creds => WARN (no TLS)");
	CHECK(nats_url_insecure("TLS://user:pass@host:4222") == 0, "TLS:// (any case) + creds => no WARN");
	CHECK(nats_url_insecure("tlsx://user:pass@host:4222") == 1, "tlsx:// is not TLS => WARN");

	diag("adversarial: '@' in the path is NOT a credential:");
	CHECK(nats_url_insecure("tls://host:4222/a@b") == 1, "'@' only in path => no creds => WARN");
	CHECK(nats_url_insecure("nats://host/u:p@x") == 1, "plaintext, '@' in path => WARN");

	diag("credentials as modparams (user, token, creds_file, nkey):");
	CHECK(nats_url_insecure_for("tls://host:4222", 1) == 0, "tls + modparam creds => no WARN");
	CHECK(nats_url_insecure_for("tls+srv://example.com", 1) == 0, "tls+srv + modparam creds => no WARN");
	CHECK(nats_url_insecure_for("nats://host:4222", 1) == 1, "plaintext + modparam creds => WARN (no TLS)");
	CHECK(nats_url_insecure_for("tls://host:4222", 0) == 1, "tls, no creds anywhere => WARN");

}
