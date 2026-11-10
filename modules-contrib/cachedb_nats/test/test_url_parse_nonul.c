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
 * The cachedb_url -> NATS server-list rewrite must not scan past the URL's
 * length: core cachedb_store_url() never NUL-terminates url.s, and a URL
 * without "://" once sent libc strstr() into the next allocation.  The
 * rewrite is cdbn_url_to_servers() (counted scan, more shapes in
 * test_cdb_url_servers.c).  Every URL here is followed in its buffer by
 * "://evil:1/", so a scan that ignores url_len finds a separator and a
 * host that are not in the URL.
 * Replaces tests/test_url_parse_nonul.c: its carried parse (pre-per-host
 * scheme) is gone, and its source-pattern half (the URL is handed over
 * with its length; no strstr in the URL code) is LOST.
 */

#include <tap.h>
#include <string.h>

#include "../cachedb_nats_url.h"

#include "cn_ut.h"

#define TAIL "://evil:1/"

static int rewrite(const char *url, int url_len, char *out, int out_sz)
{
	char buf[256];

	memcpy(buf, url, url_len);
	memcpy(buf + url_len, TAIL, sizeof TAIL);
	out[0] = '\0';
	return cdbn_url_to_servers(buf, url_len, out, out_sz);
}

void cn_ut_url_parse_nonul(void)
{
	char out[512];
	int rc;

	rc = rewrite("nats:no-separator-here", 22, out, sizeof out);
	ok(rc < 0, "url_parse_nonul: URL without :// rejected, no overread (rc=%d '%s')",
		rc, out);
	rc = rewrite("nats:group:/", 12, out, sizeof out);
	ok(rc < 0, "url_parse_nonul: separator cut short by the length not matched (rc=%d)", rc);
	rc = rewrite("nats://", 7, out, sizeof out);
	ok(rc < 0, "url_parse_nonul: empty host part after :// rejected (rc=%d)", rc);
	rc = rewrite("n", 1, out, sizeof out);
	ok(rc < 0, "url_parse_nonul: 1-byte URL rejected (rc=%d)", rc);
	rc = rewrite("n", 0, out, sizeof out);
	ok(rc < 0, "url_parse_nonul: 0-length URL rejected (rc=%d)", rc);

	rc = rewrite("nats:group1://host1:4222,host2:4223/", 36, out, sizeof out);
	ok(rc > 0 && !strcmp(out, "nats://host1:4222,nats://host2:4223"),
		"url_parse_nonul: group URL rewritten per host, trailing slash dropped ('%s')", out);
	rc = rewrite("nats://192.0.2.31:4222", 22, out, sizeof out);
	ok(rc > 0 && !strcmp(out, "nats://192.0.2.31:4222"),
		"url_parse_nonul: plain URL passes through ('%s')", out);
}
