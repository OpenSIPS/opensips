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
 * nats_auth.h -- credentials of the shared NATS connection, given as
 * modparams instead of inside a server URL.
 *
 * The NATS modules (event_nats, cachedb_nats, nats_consumer) export
 * user, password, token, creds_file, nkey and nkey_seed_file through one
 * setter each (nats_pool.c); the connection uses exactly one of:
 *   user + password      natsOptions_SetUserInfo()
 *   token                natsOptions_SetToken()
 *   creds_file           natsOptions_SetUserCredentialsFromFiles()
 *                        (a .creds file holding the user JWT and seed)
 *   nkey + nkey_seed_file natsOptions_SetNKeyFromSeed()
 * TLS client certificates come from the tls_mgm "nats" domain and can
 * be combined with any of them.
 *
 * Pure, header-inline rules, unit-tested by test/test_nats_auth.c.
 */

#ifndef NATS_AUTH_H
#define NATS_AUTH_H

#include <string.h>

#include "nats_url_scheme.h"

typedef struct nats_auth_cfg {
	const char *user;
	const char *password;
	const char *token;
	const char *creds_file;
	const char *nkey;
	const char *nkey_seed_file;
} nats_auth_cfg;

typedef enum {
	NATS_AUTH_NONE = 0,
	NATS_AUTH_USERPASS,
	NATS_AUTH_TOKEN,
	NATS_AUTH_CREDS,
	NATS_AUTH_NKEY,
} nats_auth_method_t;

#define NATS_AUTH_SET       0   /* first value: take it */
#define NATS_AUTH_SAME      1   /* another module set the same value */
#define NATS_AUTH_CONFLICT (-1) /* empty, or another value already set */

/* Merge rule of a credential modparam that several modules may set: the
 * modules share one connection, so the value must be the same. */
static inline int nats_auth_str_decide(const char *current, const char *proposed)
{
	if (!proposed || !*proposed)
		return NATS_AUTH_CONFLICT;
	if (!current)
		return NATS_AUTH_SET;
	return strcmp(current, proposed) == 0 ? NATS_AUTH_SAME : NATS_AUTH_CONFLICT;
}

static inline nats_auth_method_t nats_auth_method(const nats_auth_cfg *a)
{
	if (a->user || a->password)
		return NATS_AUTH_USERPASS;
	if (a->token)
		return NATS_AUTH_TOKEN;
	if (a->creds_file)
		return NATS_AUTH_CREDS;
	if (a->nkey || a->nkey_seed_file)
		return NATS_AUTH_NKEY;
	return NATS_AUTH_NONE;
}

/* user/password and token travel in the CONNECT message; a .creds file
 * or an NKey only sign the server's nonce. */
static inline int nats_auth_sends_secret(const nats_auth_cfg *a)
{
	nats_auth_method_t m = nats_auth_method(a);
	return m == NATS_AUTH_USERPASS || m == NATS_AUTH_TOKEN;
}

/* 0 when the credentials are usable, -1 with *err set otherwise. */
static inline int nats_auth_validate(const nats_auth_cfg *a, const char **err)
{
	int n = 0;

	if (!!a->user != !!a->password) {
		*err = "user and password must be set together";
		return -1;
	}
	if (!!a->nkey != !!a->nkey_seed_file) {
		*err = "nkey and nkey_seed_file must be set together";
		return -1;
	}
	n += a->user ? 1 : 0;
	n += a->token ? 1 : 0;
	n += a->creds_file ? 1 : 0;
	n += a->nkey ? 1 : 0;
	if (n > 1) {
		*err = "set only one of user/password, token, creds_file and "
			"nkey/nkey_seed_file";
		return -1;
	}
	return 0;
}

/* Does any URL of the comma-separated @list carry user information?
 * libnats (url.c) takes everything before the last '@' after "://" (or
 * from the start, without a scheme) as user[:password] or a token, so
 * any '@' there counts. */
static inline int nats_url_list_has_userinfo(const char *list)
{
	const char *p = list, *end, *sep;
	size_t len;

	if (!p)
		return 0;
	while (*p) {
		end = strchr(p, ',');
		len = end ? (size_t)(end - p) : strlen(p);
		sep = NULL;
		{
			const char *q;
			for (q = p; q + 2 < p + len; q++)
				if (q[0] == ':' && q[1] == '/' && q[2] == '/') {
					sep = q + 3;
					break;
				}
		}
		if (!sep)
			sep = p;
		if (memchr(sep, '@', len - (size_t)(sep - p)))
			return 1;
		if (!end)
			break;
		p = end + 1;
	}
	return 0;
}

/* The insecure-connection rule of cachedb_nats (a PII store): insecure
 * unless the URL is TLS (tls://, tls+srv://) and credentials are given,
 * either in the URL's authority (between "://" and the first '/') or as
 * modparams (@auth_configured). */
static inline int nats_url_insecure_for(const char *url, int auth_configured)
{
	const char *sep, *authority, *slash, *at;
	int has_creds;

	if (!url)
		return 1;
	sep = strstr(url, "://");
	if (!sep)
		return 1;
	authority = sep + 3;
	slash = strchr(authority, '/');
	at = strchr(authority, '@');
	has_creds = auth_configured || ((at != NULL) && (slash == NULL || at < slash));
	return (!nats_url_is_tls(url) || !has_creds) ? 1 : 0;
}

#endif /* NATS_AUTH_H */
