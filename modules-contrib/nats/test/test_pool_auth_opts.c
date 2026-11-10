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
 * The credentials of the shared connection (modparams user / password,
 * token, creds_file, nkey / nkey_seed_file): which libnats call each
 * method makes, what is refused at startup, and that no secret reaches
 * the log.
 *
 * The real pool (nats_pool.c) against the fake libnats of nats_ut_fake.c.
 * Each scenario starts from a pristine pool.
 */

#include <tap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../../sr_module.h"
#include "../nats_pool.h"

#include "nats_ut.h"
#include "nats_ut_fake.h"

/* ── helpers ────────────────────────────────────────────────────── */

static char creds_path[64] = "/tmp/natsauthXXXXXX";
static char seed_path[64] = "/tmp/natsseedXXXXXX";

static int set(int (*setter)(unsigned int, void *), const char *v)
{
	return setter(STR_PARAM, (void *)v);
}

static int reg(const char *url)
{
	return nats_pool_register(url, "test", 2000, 3);
}

/* ── scenarios ──────────────────────────────────────────────────── */

static int s_none(void)
{
	return reg("nats://127.0.0.1:4222") == 0 && nats_pool_get() != NULL &&
		nf.n_auth_calls == 0 && !nats_pool_auth_configured();
}

static int s_userpass(void)
{
	return set(nats_pool_auth_user_setter, "alice") == 0 &&
		set(nats_pool_auth_password_setter, "pa55word") == 0 &&
		reg("nats://127.0.0.1:4222") == 0 && nats_pool_get() != NULL &&
		nf.n_auth_calls == 1 && !strcmp(nf.a_user, "alice") &&
		!strcmp(nf.a_pw, "pa55word") && nats_pool_auth_configured();
}

static int s_token(void)
{
	return set(nats_pool_auth_token_setter, "t0ken") == 0 &&
		reg("nats://127.0.0.1:4222") == 0 && nats_pool_get() != NULL &&
		nf.n_auth_calls == 1 && !strcmp(nf.a_token, "t0ken");
}

static int s_creds(void)
{
	return set(nats_pool_auth_creds_file_setter, creds_path) == 0 &&
		reg("nats://127.0.0.1:4222") == 0 && nats_pool_get() != NULL &&
		nf.n_auth_calls == 1 && !strcmp(nf.a_creds, creds_path) &&
		!strcmp(nf.a_creds_seed, "(null)");
}

static int s_nkey(void)
{
	return set(nats_pool_auth_nkey_setter, "UDXU4RCSJNZOIQHZNWXHXORDPRTGNJAHAHFRGZNEEJCPQTT2M7NLCNF4") == 0 &&
		set(nats_pool_auth_nkey_seed_file_setter, seed_path) == 0 &&
		reg("nats://127.0.0.1:4222") == 0 && nats_pool_get() != NULL &&
		nf.n_auth_calls == 1 && !strncmp(nf.a_nkey, "UDXU4RCS", 8) &&
		!strcmp(nf.a_seed, seed_path);
}

static int s_user_alone(void)
{
	return set(nats_pool_auth_user_setter, "alice") == 0 &&
		reg("nats://127.0.0.1:4222") == -1 &&
		strstr(nats_ut_log(), "user and password must be set together") != NULL;
}

static int s_seed_alone(void)
{
	return set(nats_pool_auth_nkey_seed_file_setter, seed_path) == 0 &&
		reg("nats://127.0.0.1:4222") == -1;
}

static int s_two_methods(void)
{
	return set(nats_pool_auth_token_setter, "t0ken") == 0 &&
		set(nats_pool_auth_creds_file_setter, creds_path) == 0 &&
		reg("nats://127.0.0.1:4222") == -1 && strstr(nats_ut_log(), "set only one");
}

static int s_url_and_modparam(void)
{
	return set(nats_pool_auth_token_setter, "t0ken") == 0 &&
		reg("nats://u:s3cr3t@127.0.0.1:4222") == -1 &&
		strstr(nats_ut_log(), "both in a server URL and") && !strstr(nats_ut_log(), "s3cr3t");
}

static int s_url_and_modparam_merge(void)
{
	/* a later module's URL with user info is refused too */
	return set(nats_pool_auth_token_setter, "t0ken") == 0 &&
		reg("nats://127.0.0.1:4222") == 0 &&
		nats_pool_register("nats://u:p@127.0.0.1:4223", "second", 2000, 3) == -1;
}

static int s_url_only(void)
{
	/* credentials only in the URL: as before, no libnats auth call */
	return reg("nats://u:p@127.0.0.1:4222") == 0 && nats_pool_get() != NULL &&
		nf.n_auth_calls == 0;
}

static int s_creds_missing(void)
{
	return set(nats_pool_auth_creds_file_setter, "/nonexistent/x.creds") == 0 &&
		reg("nats://127.0.0.1:4222") == -1 &&
		strstr(nats_ut_log(), "/nonexistent/x.creds");
}

static int s_seed_unreadable(void)
{
	return set(nats_pool_auth_nkey_setter, "UABC") == 0 &&
		set(nats_pool_auth_nkey_seed_file_setter, "/nonexistent/s.nk") == 0 &&
		reg("nats://127.0.0.1:4222") == -1;
}

static int s_setter_merge(void)
{
	return set(nats_pool_auth_user_setter, "alice") == 0 &&
		set(nats_pool_auth_user_setter, "alice") == 0 &&
		set(nats_pool_auth_user_setter, "bob") == -1 &&
		set(nats_pool_auth_token_setter, "") == -1 &&
		nats_pool_auth_token_setter(INT_PARAM, (void *)(long)5) == -1;
}

static int s_libnats_refuses(void)
{
	/* fail closed: no connection without the credentials */
	nf.auth_status = NATS_INVALID_ARG;
	return set(nats_pool_auth_token_setter, "t0ken") == 0 &&
		reg("nats://127.0.0.1:4222") == 0 && nats_pool_get() == NULL &&
		nf.n_connect == 0;
}

static int s_no_secret_logged(void)
{
	int ok = set(nats_pool_auth_user_setter, "alice") == 0 &&
		set(nats_pool_auth_password_setter, "pa55word") == 0 &&
		reg("nats://127.0.0.1:4222") == 0 && nats_pool_get() != NULL;
	return ok && !strstr(nats_ut_log(), "pa55word");
}

static int s_plaintext_warn(void)
{
	int ok = set(nats_pool_auth_token_setter, "t0ken") == 0 &&
		reg("nats://127.0.0.1:4222") == 0 && nats_pool_get() != NULL;
	return ok && strstr(nats_ut_log(), "in plain text") && !strstr(nats_ut_log(), "t0ken");
}

static int s_tls_no_plaintext_warn(void)
{
	/* no tls_mgm in this harness: the connect fails at the TLS setup,
	 * after the check */
	(void)(set(nats_pool_auth_token_setter, "t0ken") == 0 &&
		reg("tls://127.0.0.1:4222") == 0);
	(void)nats_pool_get();
	return !strstr(nats_ut_log(), "in plain text");
}

static int s_nkey_no_plaintext_warn(void)
{
	int ok = set(nats_pool_auth_creds_file_setter, creds_path) == 0 &&
		reg("nats://127.0.0.1:4222") == 0 && nats_pool_get() != NULL;
	return ok && !strstr(nats_ut_log(), "in plain text");
}

void nats_ut_pool_auth_opts(void)
{
	int fd;

	fd = mkstemp(creds_path);
	if (fd < 0)
		BAIL_OUT("mkstemp failed");
	close(fd);
	fd = mkstemp(seed_path);
	if (fd < 0)
		BAIL_OUT("mkstemp failed");
	close(fd);

	/* methods */
	nats_ut_run("no credentials: no libnats auth call", s_none);
	nats_ut_run("user + password: natsOptions_SetUserInfo", s_userpass);
	nats_ut_run("token: natsOptions_SetToken", s_token);
	nats_ut_run("creds_file: natsOptions_SetUserCredentialsFromFiles (chained file)", s_creds);
	nats_ut_run("nkey + nkey_seed_file: natsOptions_SetNKeyFromSeed", s_nkey);
	nats_ut_run("credentials only in the URL: unchanged, no auth call", s_url_only);

	/* refused at startup */
	nats_ut_run("user without password", s_user_alone);
	nats_ut_run("nkey_seed_file without nkey", s_seed_alone);
	nats_ut_run("two methods at once", s_two_methods);
	nats_ut_run("credentials in the URL and as modparams (URL not logged)", s_url_and_modparam);
	nats_ut_run("...also when the URL comes from a later module", s_url_and_modparam_merge);
	nats_ut_run("creds_file that cannot be read (path named)", s_creds_missing);
	nats_ut_run("nkey_seed_file that cannot be read", s_seed_unreadable);
	nats_ut_run("setter: same value kept, other value, empty and non-string refused", s_setter_merge);

	/* connect */
	nats_ut_run("libnats refuses the credentials: no connection", s_libnats_refuses);
	nats_ut_run("the password is never logged", s_no_secret_logged);
	nats_ut_run("token over plain text: warning, token not logged", s_plaintext_warn);
	nats_ut_run("token over TLS: no plain-text warning", s_tls_no_plaintext_warn);
	nats_ut_run("creds file over plain text: no warning (nothing secret sent)", s_nkey_no_plaintext_warn);


	unlink(creds_path);
	unlink(seed_path);
}
