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
 * Strict security for usrloc deployments: the default stays warn-only,
 * but require_secure_url=1 refuses to start on an insecure connection URL
 * (plaintext nats:// and/or no credentials) and
 * require_usrloc_safe_bucket=1 refuses a bound bucket with a non-zero
 * backing-stream MaxAge (it silently expires permanent contacts).  On
 * mod_init's real steps through UNIT_TESTS wrappers (cn_ut_init_pool,
 * cn_ut_bucket_checks in cachedb_nats.c) with fake pool registration and
 * bucket info; the URL is set through the module's own nats_url modparam
 * entry (the cachedb_url list is freed by child_init before the tests run,
 * see the observation in DISPOSITION.md).
 * Replaces tests/test_strict_security.c (its verdict model and greps).
 */

#include <tap.h>
#include <string.h>
#include <stdint.h>

#include "../../nats/nats_bind.h"
#include "../../../sr_module.h"

#include "cn_ut.h"
#include "cn_ut_fake.h"

int cn_ut_init_pool(void);
int cn_ut_bucket_checks(void);
extern int require_secure_url, require_usrloc_safe_bucket;

static int n_reg;
static int64_t maxage;

static int f_register(const char *url, const char *mod, int rw, int mr)
{ (void)url; (void)mod; (void)rw; (void)mr; n_reg++; return 0; }
static void f_bind_tls(const char *m) { (void)m; }
static int f_auth(void) { return 0; }
static int f_maxage(const char *bucket, int64_t *ns) { (void)bucket; *ns = maxage; return 0; }

static char **nats_url_param(void)
{
	struct sr_module *m;
	const param_export_t *p;

	for (m = modules; m; m = m->next)
		if (m->exports && !strcmp(m->exports->name, "cachedb_nats"))
			for (p = m->exports->params; p && p->name; p++)
				if (!strcmp(p->name, "nats_url"))
					return (char **)p->param_pointer;
	return NULL;
}

static int pool(int strict, const char *url)
{
	char **nu = nats_url_param(), *saved = nu ? *nu : NULL;
	int saved_strict = require_secure_url, rc;

	if (nu)
		*nu = (char *)url;
	require_secure_url = strict;
	n_reg = 0;
	cn_ut_fake_log_clear();
	rc = cn_ut_init_pool();
	require_secure_url = saved_strict;
	if (nu)
		*nu = saved;
	return rc;
}

static int bucket(int strict, int64_t ns)
{
	int saved = require_usrloc_safe_bucket, rc;

	require_usrloc_safe_bucket = strict;
	maxage = ns;
	cn_ut_fake_log_clear();
	rc = cn_ut_bucket_checks();
	require_usrloc_safe_bucket = saved;
	return rc;
}

void cn_ut_strict_security(void)
{
	cn_ut_fake_begin();
	nats_api.pool_register = f_register;
	nats_api.pool_register_default = f_register;
	nats_api.pool_bind_tls = f_bind_tls;
	nats_api.pool_auth_configured = f_auth;
	nats_api.pool_bucket_maxage_ns = f_maxage;

	ok(nats_url_param() != NULL, "strict_security: nats_url modparam found");
	ok(pool(0, "nats://127.0.0.1:14222") == 0 && n_reg == 1 && strstr(cn_ut_fake_log(), "INSECURE"),
		"strict_security: insecure URL warns and starts by default");
	ok(pool(1, "nats://127.0.0.1:14222") == -1 && n_reg == 0 && strstr(cn_ut_fake_log(), "refusing to start"),
		"strict_security: insecure URL refused under require_secure_url=1");
	ok(pool(1, "tls://user:pass@nats.example.com:4222") == 0 && n_reg == 1 &&
		!strstr(cn_ut_fake_log(), "INSECURE"),
		"strict_security: tls:// with credentials starts under strict");
	ok(pool(1, "tls://nats.example.com:4222") == -1 && n_reg == 0,
		"strict_security: tls:// without credentials refused under strict");
	ok(pool(1, "nats://user:pass@nats.example.com:4222") == -1,
		"strict_security: plaintext with credentials refused under strict");

	/* after child_init freed the cachedb_url list, init_pool must not
	 * read it again: it falls back to the default URL */
	ok(pool(0, NULL) == 0 && n_reg == 1 && strstr(cn_ut_fake_log(), "no nats_url or cachedb_url"),
		"strict_security: no nats_url after child_init: the freed cachedb_url list is not read");

	ok(bucket(1, 0) == 0, "strict_security: MaxAge=0 bucket proceeds (strict)");
	ok(bucket(0, 3600000000000LL) == 0 && strstr(cn_ut_fake_log(), "SILENTLY EXPIRE"),
		"strict_security: MaxAge!=0 warns by default");
	ok(bucket(1, 3600000000000LL) == -1 && strstr(cn_ut_fake_log(), "refusing to start"),
		"strict_security: MaxAge!=0 refused under require_usrloc_safe_bucket=1");
	ok(bucket(1, 1) == -1, "strict_security: even 1 ns MaxAge refused under strict");
	cn_ut_fake_end();
}
