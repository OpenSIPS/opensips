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
 * Binding the nats module's API, as a module that uses it does
 * (nats_bind_mod.h): load_nats fills every member of struct nats_binds,
 * and the module's settings of the shared connection (its
 * nats_alias_<name> parameter setters) reach the connection only through
 * nats_bind_api(), once, with the nats module's own checks -- a value of
 * the wrong type fails the bind.
 *
 * This file is the "other module": it has its own API table and alias
 * setters, and binds the real nats module it is linked into.
 */

#include <tap.h>
#include <string.h>

#include "../../../sr_module.h"
#include "../nats_dl.h"

/* the nats module's own table and setting, before nats_bind.h renames them */
static nats_dl_funcs_t *const real_dl = &nats_dl;
extern int nats_pool_no_randomize;
static int *const real_no_randomize = &nats_pool_no_randomize;

#include "nats_ut.h"
#include "nats_ut_fake.h"

/* ── the module side: as event_nats.c etc. ────────────────────────── */

/* this module's API table: its own name, nats.so has no nats_api */
#define nats_api nats_ut_bind_api
#include "../nats_bind_mod.h"

struct nats_binds nats_api;

NATS_ALIAS_SETTER(no_randomize)
NATS_ALIAS_SETTER(user)
NATS_ALIAS_SETTER(password)

/* each scenario starts as a module that has set nothing and bound nothing */
static void fresh_module(void)
{
	memset(&nats_api, 0, sizeof nats_api);
	nats_alias_cnt = 0;
}

static int s_every_member(void)
{
	struct nats_binds b;
	void *slot[sizeof(struct nats_binds) / sizeof(void *)];
	unsigned i;

	/* every member is a pointer: one added to struct nats_binds and not
	 * filled by load_nats stays NULL here */
	_Static_assert(sizeof(struct nats_binds) % sizeof(void *) == 0,
		"struct nats_binds holds pointers only");
	memset(&b, 0, sizeof b);
	if (load_nats_api(&b) != 0)
		return 0;
	memcpy(slot, &b, sizeof b);
	for (i = 0; i < sizeof slot / sizeof slot[0]; i++)
		if (!slot[i]) {
			diag("member %u of struct nats_binds is NULL", i);
			return 0;
		}
	return b.dl == real_dl && b.no_randomize == real_no_randomize;
}

static int s_null_table(void)
{
	load_nats_f load = (load_nats_f)find_export("load_nats", 0);

	return load != NULL && load(NULL) == -1;
}

static int s_aliases_forwarded(void)
{
	fresh_module();
	if (nats_alias_no_randomize(INT_PARAM, (void *)1L) != 0
	    || nats_alias_user(STR_PARAM, "alice") != 0
	    || nats_alias_password(STR_PARAM, "se\\cret") != 0)
		return 0;
	/* kept by the module: nothing has reached the nats module yet */
	if (nats_api.no_randomize != NULL || *real_no_randomize != 0)
		return 0;

	if (nats_bind_api("tmod") != 0)
		return 0;
	if (*real_no_randomize != 1 || !nats_api.pool_auth_configured())
		return 0;

	/* forwarded once: a second bind applies nothing again */
	return nats_alias_cnt == 0 && nats_bind_api("tmod") == 0
		&& strstr(nats_ut_log(), "se\\cret") == NULL;
}

static int s_forwarded_in_order(void)
{
	/* the first value of a credential stands: a different second one
	 * is refused by the pool, and the bind fails */
	fresh_module();
	return nats_alias_user(STR_PARAM, "alice") == 0
		&& nats_alias_user(STR_PARAM, "bob") == 0
		&& nats_bind_api("tmod") == -1
		&& strstr(nats_ut_log(), "user: NATS modules set different values")
			!= NULL;
}

static int s_wrong_type(void)
{
	fresh_module();
	/* the module keeps the value as given; the nats module checks it */
	return nats_alias_no_randomize(STR_PARAM, "yes") == 0
		&& nats_bind_api("tmod") == -1
		&& strstr(nats_ut_log(), "no_randomize") != NULL
		&& *real_no_randomize == 0;
}

static int s_refused_value(void)
{
	fresh_module();
	return nats_alias_no_randomize(INT_PARAM, (void *)7L) == 0
		&& nats_bind_api("tmod") == -1
		&& *real_no_randomize == 0;
}

static int s_nothing_set(void)
{
	fresh_module();
	return nats_bind_api("tmod") == 0 && nats_api.dl == real_dl
		&& *real_no_randomize == 0 && !nats_api.pool_auth_configured();
}

static int s_keep_limit(void)
{
	int i, rc = 0;

	fresh_module();
	for (i = 0; i < NATS_ALIAS_MAX && rc == 0; i++)
		rc = nats_alias_user(STR_PARAM, "alice");
	if (rc != 0 || nats_alias_cnt != NATS_ALIAS_MAX)
		return 0;
	nats_ut_log_clear();
	return nats_alias_user(STR_PARAM, "alice") == -1
		&& nats_alias_cnt == NATS_ALIAS_MAX
		&& strstr(nats_ut_log(), "too many NATS connection settings") != NULL
		/* the same value 32 times: all forwarded, all accepted */
		&& nats_bind_api("tmod") == 0 && nats_alias_cnt == 0;
}

void nats_ut_nats_bind(void)
{
	nats_ut_run("load_nats sets every member of struct nats_binds",
		s_every_member);
	nats_ut_run("load_nats refuses a NULL table", s_null_table);
	nats_ut_run("settings kept by the module reach the connection at the bind",
		s_aliases_forwarded);
	nats_ut_run("a setting given twice with different values fails the bind",
		s_forwarded_in_order);
	nats_ut_run("a value of the wrong type fails the bind", s_wrong_type);
	nats_ut_run("a value the nats module refuses fails the bind",
		s_refused_value);
	nats_ut_run("a module that sets nothing binds and changes nothing",
		s_nothing_set);
	nats_ut_run("the kept-settings table is bounded", s_keep_limit);
}
