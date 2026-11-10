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
 * test_nats_auth.c -- the credential rules of the shared connection
 * (nats_auth.h):
 *   - a credential modparam set by several modules must have one value;
 *   - exactly one way to authenticate: user + password, token, a .creds
 *     file, or an NKey (public key + seed file); halves of a pair alone
 *     are refused;
 *   - credentials in a server URL and in modparams at once are refused;
 *     libnats takes everything before the LAST '@' after "://" as user
 *     information, so any '@' there counts;
 *   - the insecure-URL rule of cachedb_nats: plain text, or no
 *     credentials in the URL nor in modparams.
 */

#include <tap.h>
#include <stdio.h>
#include <string.h>

#include "../nats_auth.h"

#include "nats_ut.h"

#define ASSERT(cond, label) ok((cond), "%s", (label))

static int valid(const char *user, const char *pw, const char *token,
	const char *creds, const char *nkey, const char *seed)
{
	nats_auth_cfg a;
	const char *err = NULL;
	int rc;

	a.user = user; a.password = pw; a.token = token;
	a.creds_file = creds; a.nkey = nkey; a.nkey_seed_file = seed;
	rc = nats_auth_validate(&a, &err);
	if (rc < 0 && (!err || !*err))
		return -99;   /* a refusal must say why */
	return rc;
}

void nats_ut_nats_auth(void)
{
	ASSERT(nats_auth_str_decide(NULL, "a") == NATS_AUTH_SET, "first value: set");
	ASSERT(nats_auth_str_decide("a", "a") == NATS_AUTH_SAME,
		"the same value from another module: kept");
	ASSERT(nats_auth_str_decide("a", "b") == NATS_AUTH_CONFLICT,
		"a different value from another module: conflict");
	ASSERT(nats_auth_str_decide(NULL, "") == NATS_AUTH_CONFLICT,
		"an empty value: refused");
	ASSERT(nats_auth_str_decide(NULL, NULL) == NATS_AUTH_CONFLICT,
		"no value: refused");

	ASSERT(valid(0, 0, 0, 0, 0, 0) == 0, "no credentials: valid");
	ASSERT(nats_auth_method(&(nats_auth_cfg){0}) == NATS_AUTH_NONE,
		"...method none");
	ASSERT(valid("u", "p", 0, 0, 0, 0) == 0, "user + password: valid");
	ASSERT(valid(0, 0, "t", 0, 0, 0) == 0, "token: valid");
	ASSERT(valid(0, 0, 0, "/c.creds", 0, 0) == 0, "creds file: valid");
	ASSERT(valid(0, 0, 0, 0, "UABC", "/s.nk") == 0, "nkey + seed file: valid");
	ASSERT(valid("u", 0, 0, 0, 0, 0) == -1, "user without password: refused");
	ASSERT(valid(0, "p", 0, 0, 0, 0) == -1, "password without user: refused");
	ASSERT(valid(0, 0, 0, 0, "UABC", 0) == -1, "nkey without seed file: refused");
	ASSERT(valid(0, 0, 0, 0, 0, "/s.nk") == -1, "seed file without nkey: refused");
	ASSERT(valid("u", "p", "t", 0, 0, 0) == -1, "user/password and token: refused");
	ASSERT(valid(0, 0, "t", "/c.creds", 0, 0) == -1, "token and creds file: refused");
	ASSERT(valid(0, 0, 0, "/c.creds", "UABC", "/s.nk") == -1,
		"creds file and nkey: refused");
	ASSERT(valid("u", "p", 0, 0, "UABC", "/s.nk") == -1,
		"user/password and nkey: refused");

	{
		nats_auth_cfg a = {0};
		a.user = "u"; a.password = "p";
		ASSERT(nats_auth_method(&a) == NATS_AUTH_USERPASS, "method user/password");
		ASSERT(nats_auth_sends_secret(&a), "...sends a secret in CONNECT");
		memset(&a, 0, sizeof a); a.token = "t";
		ASSERT(nats_auth_method(&a) == NATS_AUTH_TOKEN, "method token");
		ASSERT(nats_auth_sends_secret(&a), "...sends a secret in CONNECT");
		memset(&a, 0, sizeof a); a.creds_file = "/c";
		ASSERT(nats_auth_method(&a) == NATS_AUTH_CREDS, "method creds file");
		ASSERT(!nats_auth_sends_secret(&a), "...signs a nonce, sends no secret");
		memset(&a, 0, sizeof a); a.nkey = "U"; a.nkey_seed_file = "/s";
		ASSERT(nats_auth_method(&a) == NATS_AUTH_NKEY, "method nkey");
		ASSERT(!nats_auth_sends_secret(&a), "...signs a nonce, sends no secret");
	}

	ASSERT(!nats_url_list_has_userinfo("nats://h:4222"), "no '@': no user info");
	ASSERT(nats_url_list_has_userinfo("nats://u:p@h:4222"), "u:p@: user info");
	ASSERT(nats_url_list_has_userinfo("nats://tok@h"), "token@: user info");
	ASSERT(nats_url_list_has_userinfo("nats://a:4222, tls://u:p@b:4222"),
		"user info in the second URL of a list");
	ASSERT(nats_url_list_has_userinfo("nats://u:p/x@h"),
		"a '/' before the '@' does not hide it (libnats splits at the last '@')");
	ASSERT(nats_url_list_has_userinfo("u:p@h:4222"),
		"no scheme: libnats still parses the user info");
	ASSERT(!nats_url_list_has_userinfo(""), "empty list");
	ASSERT(!nats_url_list_has_userinfo(NULL), "NULL list");

	ASSERT(nats_url_insecure_for("nats://u:p@h", 0) == 1, "plain text: insecure");
	ASSERT(nats_url_insecure_for("nats://h", 1) == 1,
		"plain text with modparam credentials: insecure");
	ASSERT(nats_url_insecure_for("tls://h", 0) == 1, "TLS without credentials: insecure");
	ASSERT(nats_url_insecure_for("tls://u:p@h", 0) == 0, "TLS + URL credentials: secure");
	ASSERT(nats_url_insecure_for("tls://h", 1) == 0,
		"TLS + modparam credentials: secure");
	ASSERT(nats_url_insecure_for("tls+srv://h", 1) == 0, "tls+srv:// counts as TLS");
	ASSERT(nats_url_insecure_for("h:4222", 1) == 1, "no scheme: insecure");
	ASSERT(nats_url_insecure_for(NULL, 1) == 1, "NULL: insecure");
	ASSERT(nats_url_insecure_for("tls://h/x@y", 0) == 1,
		"an '@' in a path is not credentials for this check");

}
