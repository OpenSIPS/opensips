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
 * Behavioural (ASan): the MI server-info string policy
 * (nats_server_info.h, used by nats_pool_get_server_info()) against the
 * REAL nats_redact_url() — the string is surfaced to MI clients
 * (mi_nats_status) and must never leak "user:pass@" credentials, and a
 * failed/absent connection must read "not connected" rather than
 * whatever is in the buffer.  Replaces the source-pattern test that
 * grepped nats_pool.c for a nats_redact_url call.
 *
 * Build (see Makefile): links ../nats_redact.o, includes <nats/nats.h>
 * for the natsConnection/natsStatus types only — no broker, no cnats
 * calls; the URL getter is injected.
 */

#include <tap.h>
#include <stdio.h>
#include <string.h>

#include "../nats_server_info.h"

#include "nats_ut.h"

#define ASSERT(cond, label) ok((cond), "%s", (label))

/* A non-NULL "connection": the build helper only passes it through to
 * the injected getter, so any distinct pointer works. */
static natsConnection *fake_nc = (natsConnection *)0x1;

/* --- injectable getters ------------------------------------------- */

static const char *g_url;   /* what url_ok() serves */

static natsStatus url_ok(natsConnection *nc, char *buf, size_t sz)
{
	(void)nc;
	snprintf(buf, sz, "%s", g_url);
	return NATS_OK;
}

/* Failure path: scribble a full, UNTERMINATED buffer and return non-OK
 * — models GetConnectedUrl leaving the stack buffer dirty on error.
 * The policy must not let one byte of it reach the caller. */
static natsStatus url_fail_dirty(natsConnection *nc, char *buf, size_t sz)
{
	(void)nc;
	memset(buf, 'X', sz);
	return NATS_ERR;
}

static const char *build(const char *url, char *out, size_t out_sz)
{
	g_url = url;
	return nats_pool_server_info_build(fake_nc, url_ok, out, out_sz);
}

void nats_ut_server_info_redact(void)
{
	char out[512];
	const char *r;

	/* --- disconnected / failure paths ------------------------------ */

	r = nats_pool_server_info_build(NULL, url_ok, out, sizeof(out));
	ASSERT(strcmp(r, "not connected") == 0,
		"NULL connection reads \"not connected\"");

	r = nats_pool_server_info_build(fake_nc, url_fail_dirty,
		out, sizeof(out));
	ASSERT(strcmp(r, "not connected") == 0,
		"non-OK getter reads \"not connected\" even with a dirty, "
		"unterminated buffer");

	/* --- credential redaction (the MI-leak regression) ------------- */

	r = build("nats://user:secret@h1:4222", out, sizeof(out));
	ASSERT(r == out, "success returns the caller's buffer");
	ASSERT(strstr(r, "secret") == NULL && strstr(r, "user:") == NULL,
		"password and userinfo never reach the MI string");
	ASSERT(strcmp(r, "nats://[redacted]@h1:4222") == 0,
		"credentialed URL becomes nats://[redacted]@host");

	r = build("nats://u1:p1@h1:4222,nats://h2:4222,nats://u2:p2@h3",
		out, sizeof(out));
	ASSERT(strstr(r, "p1") == NULL && strstr(r, "p2") == NULL &&
		strstr(r, "u1") == NULL && strstr(r, "u2") == NULL,
		"every URL in a comma-separated list is scrubbed");
	ASSERT(strstr(r, "nats://h2:4222") != NULL,
		"credential-less list member is copied unchanged");

	r = build("user:pass@host:4222", out, sizeof(out));
	ASSERT(strstr(r, "pass") == NULL,
		"scheme-less user:pass@host still redacts");

	/* --- adversarial inputs ---------------------------------------- */

	r = build("nats://u:p\\a%s\"'@h:4222", out, sizeof(out));
	ASSERT(strstr(r, "p\\a%s") == NULL && strstr(r, "%s") == NULL,
		"backslash/format/quote bytes in the password never leak");

	r = build("nats://h1:4222", out, sizeof(out));
	ASSERT(strcmp(r, "nats://h1:4222") == 0,
		"URL without userinfo is returned verbatim");

	r = build("", out, sizeof(out));
	ASSERT(strcmp(r, "") == 0, "empty URL yields an empty string");

	/* Truncating output buffer: NUL-terminated, in-bounds (ASan), and
	 * still no credential bytes survive the cut. */
	{
		char tiny[8];
		r = build("nats://user:secret@h1:4222", tiny, sizeof(tiny));
		ASSERT(strlen(tiny) < sizeof(tiny),
			"truncated output stays NUL-terminated in-bounds");
		ASSERT(strstr(tiny, "secret") == NULL,
			"truncation cannot resurrect the password");
	}

	/* --- guard rails ------------------------------------------------ */

	r = nats_pool_server_info_build(fake_nc, NULL, out, sizeof(out));
	ASSERT(strcmp(r, "not connected") == 0,
		"NULL getter degrades to \"not connected\"");

	r = nats_pool_server_info_build(fake_nc, url_ok, NULL, 0);
	ASSERT(strcmp(r, "not connected") == 0,
		"zero-capacity output degrades to \"not connected\"");

}
