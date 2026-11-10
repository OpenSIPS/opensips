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
 * Regression test: modules-contrib/nats/nats_redact_url() must scrub
 * userinfo (user:pass) from NATS URL strings before they are written
 * to logs.  The current code at modules-contrib/event_nats/event_nats.c:289
 * logs nats_url verbatim, leaking credentials when an operator embeds
 * them via nats://user:pass@host:port.
 *
 * The helper is declared in modules-contrib/nats/nats_pool.h:
 *
 *   #include "../nats_redact.h"
 *
 * Contract:
 *   - Replaces every "user[:pass]@" segment after a "scheme://" prefix
 *     with "[redacted]@".
 *   - Handles comma-separated lists of URLs.
 *   - Leaves URLs without userinfo unchanged.
 *   - Always NUL-terminates @out unless out_sz == 0.
 *   - NULL @url writes empty string into out (if out_sz > 0).
 *
 * Build:
 *   gcc -g -O0 -fsanitize=address -Wall -o test_redact_url \
 *       test_redact_url.c ../nats_pool_redact.o
 *
 * (the helper is extracted to a small object file so we can link
 *  against it without pulling in the whole nats_pool.c)
 */

#include <tap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nats_ut.h"

void nats_redact_url(const char *url, char *out, size_t out_sz);

#define ASSERT_EQ(actual, expected, label) is((actual), (expected), "%s", (label))

void nats_ut_redact_url(void)
{
	char buf[256];

	/* CASE 1: plain URL — unchanged */
	nats_redact_url("nats://host:4222", buf, sizeof(buf));
	ASSERT_EQ(buf, "nats://host:4222", "plain nats://host:port");

	/* CASE 2: user:pass — both components scrubbed */
	nats_redact_url("nats://alice:secret@host:4222", buf, sizeof(buf));
	ASSERT_EQ(buf, "nats://[redacted]@host:4222", "user:pass redacted");

	/* CASE 3: token-only (no colon) — still scrubbed */
	nats_redact_url("nats://my-token@host:4222", buf, sizeof(buf));
	ASSERT_EQ(buf, "nats://[redacted]@host:4222", "single-token userinfo redacted");

	/* CASE 4: tls:// scheme */
	nats_redact_url("tls://u:p@h:4222", buf, sizeof(buf));
	ASSERT_EQ(buf, "tls://[redacted]@h:4222", "tls:// scheme");

	/* CASE 5: comma-separated list — only the one with creds is redacted */
	nats_redact_url("nats://h1:4222,nats://u:p@h2:4222",
		buf, sizeof(buf));
	ASSERT_EQ(buf, "nats://h1:4222,nats://[redacted]@h2:4222",
		"comma-separated list");

	/* CASE 6: list where both have creds */
	nats_redact_url("nats://a:b@h1:4222,tls://c:d@h2:4222",
		buf, sizeof(buf));
	ASSERT_EQ(buf, "nats://[redacted]@h1:4222,tls://[redacted]@h2:4222",
		"both have creds");

	/* CASE 7: NULL input */
	nats_redact_url(NULL, buf, sizeof(buf));
	ASSERT_EQ(buf, "", "NULL url produces empty string");

	/* CASE 8: empty string */
	nats_redact_url("", buf, sizeof(buf));
	ASSERT_EQ(buf, "", "empty url produces empty string");

	/* CASE 9: missing scheme — no scheme to anchor on, leave alone */
	nats_redact_url("host:4222", buf, sizeof(buf));
	ASSERT_EQ(buf, "host:4222", "no scheme — left alone");

	/* CASE 10: scheme but @ before :// — pathological, leave alone */
	nats_redact_url("not-a-url", buf, sizeof(buf));
	ASSERT_EQ(buf, "not-a-url", "garbage left alone");

	/* CASE 11: URL with path-like segment — '@' must be in authority,
	 *           NOT in path/query.  We anchor on scheme://, so @ in
	 *           the authority (before next '/') is what we redact. */
	nats_redact_url("nats://u:p@h:4222/topic@home",
		buf, sizeof(buf));
	ASSERT_EQ(buf, "nats://[redacted]@h:4222/topic@home",
		"only authority @ is redacted");

	/* CASE 11b: base64 NATS token containing '/' and '=' — the in-token
	 *            '/' must NOT be mistaken for the path separator, which
	 *            would end the '@' search early and leak the token. */
	nats_redact_url("nats://AbC/dEf=@host:4222", buf, sizeof(buf));
	ASSERT_EQ(buf, "nats://[redacted]@host:4222",
		"slash-bearing base64 token redacted");

	/* CASE 12: out_sz == 0 — must not crash, no write */
	{
		char tiny[1] = {'X'};
		nats_redact_url("nats://u:p@h:4222", tiny, 0);
		ok(tiny[0] == 'X', "out_sz=0: nothing written");
	}

	/* CASE 14: password contains '@' — the userinfo/host boundary is the
	 *           LAST '@', so everything up to it must be masked (#45). */
	nats_redact_url("nats://user:p@ss@host:4222", buf, sizeof(buf));
	ASSERT_EQ(buf, "nats://[redacted]@host:4222", "last '@' is the boundary");

	/* CASE 15: scheme-less URL WITH credentials — still redact (#45).
	 *           A NATS URL string is always a URL, so user:pass@host
	 *           without a scheme is credentials, not data. */
	nats_redact_url("user:pass@host:4222", buf, sizeof(buf));
	ASSERT_EQ(buf, "[redacted]@host:4222", "scheme-less creds redacted");

	/* CASE 16: scheme-less, password with '@' */
	nats_redact_url("u:p@w@host:4222", buf, sizeof(buf));
	ASSERT_EQ(buf, "[redacted]@host:4222", "scheme-less last '@' boundary");

	/* CASE 13: small buffer — must NUL-terminate even on truncation */
	{
		char small[10];
		nats_redact_url("nats://abc:def@host:4222", small, sizeof(small));
		ok(small[sizeof(small) - 1] == '\0',
			"small buffer NUL-terminated");
	}

}
