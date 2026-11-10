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
 * URL scheme classification shared by the pool (nats_url_scheme.h):
 * which configured URLs mean TLS (tls://, tls+srv://) and which ask
 * libnats for DNS SRV discovery (nats+srv://, tls+srv://).  Schemes are
 * case-insensitive, as libnats treats them.
 */

#include <tap.h>
#include <stdio.h>
#include <string.h>

#include "../nats_url_scheme.h"

#include "nats_ut.h"

#define CHECK(cond, label) ok((cond), "%s", (label))

/* nats_url_srv_correct() on a whole string: expected result and output */
static int srv(const char *url, int want, const char *want_out)
{
	char out[512];
	int r;

	memset(out, 'X', sizeof out);
	r = nats_url_srv_correct(url, (int)strlen(url), out);
	if (r != want)
		return 0;
	return want == 0 || strcmp(out, want_out) == 0;
}

/* nats_url_srv_redact() into a buffer of @size bytes.  @size goes through
 * a volatile: the small sizes truncate on purpose, and gcc's
 * -Wformat-truncation (under -D_FORTIFY_SOURCE) would flag them once it
 * propagates the constant into the inlined snprintf(). */
static int red(const char *url, size_t size, const char *want)
{
	char out[512];
	volatile size_t vsize = size;

	memset(out, 'X', sizeof out);
	nats_url_srv_redact(url, out, vsize);
	return strcmp(out, want) == 0;
}

/* the credential must not appear in any truncation of the redacted form */
static int red_no_leak(const char *url, const char *secret)
{
	char out[512];
	size_t size;

	for (size = 1; size < 64; size++) {
		memset(out, 'X', sizeof out);
		nats_url_srv_redact(url, out, size);
		if (strlen(out) >= size || strstr(out, secret))
			return 0;
	}
	return 1;
}

void nats_ut_url_scheme(void)
{
	/* TLS */
	CHECK(nats_url_is_tls("tls://h:4222"), "tls:// is TLS");
	CHECK(nats_url_is_tls("TLS://h:4222"), "TLS:// is TLS");
	CHECK(nats_url_is_tls("tls+srv://example.com"), "tls+srv:// is TLS");
	CHECK(nats_url_is_tls("Tls+Srv://example.com"), "Tls+Srv:// is TLS");
	CHECK(!nats_url_is_tls("nats://h:4222"), "nats:// is not TLS");
	CHECK(!nats_url_is_tls("nats+srv://example.com"), "nats+srv:// is not TLS");
	CHECK(!nats_url_is_tls("tls+srvx://example.com"), "tls+srvx:// is not TLS");
	CHECK(!nats_url_is_tls("tls:/h"), "tls:/ is not TLS");
	CHECK(!nats_url_is_tls("tls"), "bare 'tls' is not TLS");
	CHECK(!nats_url_is_tls("h:4222/tls://"), "tls:// later in the string is not TLS");
	CHECK(!nats_url_is_tls(""), "empty is not TLS");
	CHECK(!nats_url_is_tls(NULL), "NULL is not TLS");

	/* SRV */
	CHECK(nats_url_is_srv("nats+srv://example.com"), "nats+srv:// is SRV");
	CHECK(nats_url_is_srv("NATS+SRV://example.com"), "NATS+SRV:// is SRV");
	CHECK(nats_url_is_srv("tls+srv://example.com"), "tls+srv:// is SRV");
	CHECK(!nats_url_is_srv("nats://example.com"), "nats:// is not SRV");
	CHECK(!nats_url_is_srv("tls://example.com"), "tls:// is not SRV");
	CHECK(!nats_url_is_srv("nats+srvx://example.com"), "nats+srvx:// is not SRV");
	CHECK(!nats_url_is_srv("nats+srv:/example.com"), "nats+srv:/ is not SRV");
	CHECK(!nats_url_is_srv("srv://example.com"), "srv:// is not SRV");
	CHECK(!nats_url_is_srv("\\nats+srv://example.com"), "backslash prefix is not SRV");
	CHECK(!nats_url_is_srv(""), "empty is not SRV");
	CHECK(!nats_url_is_srv(NULL), "NULL is not SRV");

	/* comma-separated lists, tokenized like the pool does */
	CHECK(nats_url_list_has_srv("nats+srv://example.com"), "single SRV URL");
	CHECK(nats_url_list_has_srv("nats://a:4222,nats+srv://example.com"),
		"SRV URL second in the list");
	CHECK(nats_url_list_has_srv("nats://a:4222, \ttls+srv://example.com"),
		"SRV URL after whitespace");
	CHECK(nats_url_list_has_srv(",,TLS+SRV://example.com,"), "SRV URL between commas");
	CHECK(!nats_url_list_has_srv("nats://a:4222,tls://b:4222"), "no SRV URL");
	CHECK(!nats_url_list_has_srv("nats://user:nats+srv://@a:4222"),
		"nats+srv:// inside a token is not SRV");
	CHECK(!nats_url_list_has_srv(""), "empty list");
	CHECK(!nats_url_list_has_srv(",, ,"), "only separators");
	CHECK(!nats_url_list_has_srv(NULL), "NULL list");

	/* SRV URL correction at startup: libnats takes the domain after the
	 * last '@' and wants no port and no path.  1 = fine (in its normal
	 * form), 2 = port / path / query dropped (warned), 0 = no usable
	 * domain (skipped).  The normal form -- scheme in lower case, no
	 * trailing '/' or '.' -- is what libnats makes of the URL anyway, and
	 * lets the pool see that two spellings are the same server. */
	CHECK(srv("nats+srv://example.com", 1, "nats+srv://example.com"), "plain SRV URL is fine");
	CHECK(srv("tls+srv://u:p@example.com/", 1, "tls+srv://u:p@example.com"),
		"credentials + trailing slash fine, slash dropped");
	CHECK(srv("nats+srv://example.com.", 1, "nats+srv://example.com"), "trailing dot fine, dropped");
	CHECK(srv("nats+srv://example.com./", 1, "nats+srv://example.com"), "trailing dot and slash dropped");
	CHECK(srv("NATS+SRV://example.com", 1, "nats+srv://example.com"), "scheme in lower case");
	CHECK(srv("Nats+Srv://BoB:PaSs@Example.com", 1, "nats+srv://BoB:PaSs@Example.com"),
		"credentials and domain case kept");
	CHECK(srv("NATS+SRV://example.com.:4222", 2, "nats+srv://example.com"),
		"port dropped, normal form");
	CHECK(srv("nats+srv://example.com..", 0, NULL), "empty last label: unusable");
	CHECK(srv("nats+srv://_srv.ex-ample1.com", 1, "nats+srv://_srv.ex-ample1.com"), "'_' and '-' fine");
	CHECK(srv("nats+srv://dom/@example.com", 1, "nats+srv://dom/@example.com"),
		"the domain is after the LAST '@', as libnats parses it");
	CHECK(srv("nats+srv://example.com:4222", 2, "nats+srv://example.com"), "port dropped");
	CHECK(srv("nats+srv://example.com:", 2, "nats+srv://example.com"), "empty port dropped");
	CHECK(srv("nats+srv://example.com/path", 2, "nats+srv://example.com"), "path dropped");
	CHECK(srv("nats+srv://example.com//", 2, "nats+srv://example.com"), "double slash dropped");
	CHECK(srv("nats+srv://example.com?x=1", 2, "nats+srv://example.com"), "query dropped");
	CHECK(srv("nats+srv://example.com#frag", 2, "nats+srv://example.com"), "fragment dropped");
	CHECK(srv("TLS+SRV://u:p%40w@example.com:4443/x", 2, "tls+srv://u:p%40w@example.com"),
		"credentials kept as written");
	CHECK(srv("nats+srv://", 0, NULL), "no domain: unusable");
	CHECK(srv("nats+srv://user:pw@", 0, NULL), "credentials only: unusable");
	CHECK(srv("nats+srv://:4222", 0, NULL), "port only: unusable");
	CHECK(srv("nats+srv://[::1]", 0, NULL), "IPv6 literal: unusable");
	CHECK(srv("nats+srv://exa\\mple.com", 0, NULL), "backslash: unusable");
	CHECK(srv("nats+srv://exa%41mple.com", 0, NULL), "percent: unusable");
	CHECK(srv("nats+srv://exa\tmple.com", 0, NULL), "tab: unusable");
	CHECK(srv("nats+srv://exa mple.com", 0, NULL), "space: unusable");
	CHECK(srv("nats+srv://example..com", 0, NULL), "empty label: unusable");
	CHECK(srv("nats+srv://.example.com", 0, NULL), "leading dot: unusable");
	CHECK(srv("nats+srv://ex\xc3\xa9mple.com", 0, NULL), "non-ASCII: unusable");
	CHECK(srv("nats+srv://exa\"mple.com", 0, NULL), "quote: unusable");
	{
		char long_label[128], url[300];
		memset(long_label, 'a', 64);
		strcpy(long_label + 64, ".com");
		snprintf(url, sizeof url, "nats+srv://%s", long_label);
		CHECK(srv(url, 0, NULL), "64-char label: unusable");
		snprintf(url, sizeof url, "nats+srv://%.63s.com", long_label);
		CHECK(srv(url, 1, url), "63-char label fine");
		memset(url, 'a', sizeof url);
		memcpy(url, "nats+srv://", 11);
		url[11 + 63] = '.'; url[11 + 127] = '.'; url[11 + 191] = '.';
		url[11 + 254] = '\0';
		CHECK(srv(url, 0, NULL), "254-char domain: unusable");
		url[11 + 253] = '\0';
		CHECK(srv(url, 1, url), "253-char domain fine");
	}
	{
		/* a token inside a list: only [tok, tok+len) counts */
		const char *list = "nats+srv://example.com:4222,nats://other:1";
		char out[64];
		CHECK(nats_url_srv_correct(list, 26, out) == 2 &&
			strcmp(out, "nats+srv://example.com") == 0,
			"token bounded by its length, not by the list");
	}

	/* Redaction of SRV URLs: libnats takes everything up to the LAST '@'
	 * as credentials (an SRV URL has no path), so the redaction does too
	 * -- the generic URL redaction ends them at a '/'. */
	CHECK(red("nats+srv://u:a@b/c@example.com", 64,
		"nats+srv://[redacted]@example.com"),
		"redact: '/' and '@' in the password: all of it masked");
	CHECK(red("tls+srv://user:p@ss@example.com", 64,
		"tls+srv://[redacted]@example.com"),
		"redact: '@' in the password");
	CHECK(red("nats+srv://u:a\\b%40\"q@example.com", 64,
		"nats+srv://[redacted]@example.com"),
		"redact: backslash, %-escape and quote in the password");
	CHECK(red("NATS+SRV://bob@example.com", 64,
		"NATS+SRV://[redacted]@example.com"),
		"redact: user only, scheme kept as written");
	CHECK(red("nats+srv://u:p/w@bad dom", 64,
		"nats+srv://[redacted]@bad dom"),
		"redact: an unusable URL is redacted too");
	CHECK(red("nats+srv://example.com", 64, "nats+srv://example.com"),
		"redact: no credentials, unchanged");
	CHECK(red("nats+srv://", 64, "nats+srv://"),
		"redact: empty authority, unchanged");
	CHECK(red("", 64, ""), "redact: empty string");
	CHECK(red(NULL, 64, ""), "redact: NULL gives an empty string");
	CHECK(red("example.com@x", 64, "[redacted]@x"),
		"redact: no scheme, credentials still masked");
	CHECK(red("nats+srv://u:p@example.com", 12, "nats+srv://"),
		"redact: truncated, NUL-terminated");
	CHECK(red_no_leak("nats+srv://u:s3cr3t@b/c@example.com", "s3cr3t") &&
		red_no_leak("nats+srv://u:s3cr3t@b/c@example.com", "b/c"),
		"redact: no buffer size leaks the credentials");
	{
		char out[4] = "abc";
		nats_url_srv_redact("nats+srv://u:p@h", out, 0);
		CHECK(strcmp(out, "abc") == 0, "redact: size 0 writes nothing");
	}

}
