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
 * The settings of the shared connection (no_randomize, reconnect_buf_size,
 * drain_timeout_ms and the credentials user, password, token, creds_file,
 * nkey, nkey_seed_file) reach the pool from two sides: as parameters of
 * the nats module, and through set_param() of the module API, which the
 * other NATS modules forward their own parameters of the same name to.
 * Either way the value must arrive at the one connection: a value kept
 * in a module would never be used.
 *
 * The nats module's own export table and its API as another module binds
 * it (load_nats_api()); the effect is read from the pool and from what the
 * fake libnats of nats_ut_fake.c receives at connect time.
 */

#include <tap.h>
#include <string.h>

#include "../../../sr_module.h"
#include "../nats_api.h"
#include "../nats_pool.h"

#include "nats_ut.h"
#include "nats_ut_fake.h"

/* the module's export table (nats.c) */
extern struct module_exports exports;

static const param_export_t *find_param(const char *name)
{
	const param_export_t *p;

	for (p = exports.params; p && p->name; p++)
		if (strcmp(p->name, name) == 0)
			return p;
	return NULL;
}

/* set @name the way the script's modparam() does */
static int modparam(const char *name, modparam_t type, void *val)
{
	const param_export_t *p = find_param(name);

	if (!p || !(p->type & USE_FUNC_PARAM) || !(p->type & type))
		return -99;
	return ((param_func_t)p->param_pointer)(type, val);
}

static int connect_pool(void)
{
	return nats_pool_register("nats://127.0.0.1:4222", "test", 2000, 3) == 0
		&& nats_pool_get() != NULL;
}

static struct nats_binds api;

static int bind_api(void)
{
	return load_nats_api(&api) == 0 && api.set_param != NULL;
}

/* ── as parameters of the nats module ───────────────────────────── */

static int s_mod_no_randomize(void)
{
	return modparam("no_randomize", INT_PARAM, (void *)(long)1) == 0
		&& connect_pool() && nf.last_no_randomize == 1;
}

static int s_mod_reconnect_buf_size(void)
{
	return modparam("reconnect_buf_size", INT_PARAM, (void *)(long)65536) == 0
		&& connect_pool() && nf.last_reconnect_buf == 65536;
}

static int s_mod_drain_timeout(void)
{
	return modparam("drain_timeout_ms", INT_PARAM, (void *)(long)750) == 0
		&& connect_pool() && (nats_pool_destroy(), nf.drain_wait == 750);
}

static int s_mod_user_password(void)
{
	return modparam("user", STR_PARAM, "alice") == 0
		&& modparam("password", STR_PARAM, "pa\\ss \"w\"") == 0
		&& connect_pool() && nf.n_auth_calls == 1
		&& !strcmp(nf.a_user, "alice") && !strcmp(nf.a_pw, "pa\\ss \"w\"");
}

static int s_mod_token(void)
{
	return modparam("token", STR_PARAM, "t0ken") == 0
		&& connect_pool() && !strcmp(nf.a_token, "t0ken");
}

static int s_mod_creds_file(void)
{
	/* the nats binary of the test host: any readable file will do */
	return modparam("creds_file", STR_PARAM, "/proc/self/exe") == 0
		&& connect_pool() && !strcmp(nf.a_creds, "/proc/self/exe");
}

static int s_mod_nkey(void)
{
	return modparam("nkey", STR_PARAM, "UABC") == 0
		&& modparam("nkey_seed_file", STR_PARAM, "/proc/self/exe") == 0
		&& connect_pool() && !strcmp(nf.a_nkey, "UABC")
		&& !strcmp(nf.a_seed, "/proc/self/exe");
}

static int s_mod_types(void)
{
	/* an integer parameter takes no string and the other way round */
	return modparam("no_randomize", STR_PARAM, "1") == -99
		&& modparam("reconnect_buf_size", STR_PARAM, "1") == -99
		&& modparam("drain_timeout_ms", STR_PARAM, "1") == -99
		&& modparam("user", INT_PARAM, (void *)(long)1) == -99
		&& modparam("token", INT_PARAM, (void *)(long)1) == -99
		&& modparam("nkey_seed_file", INT_PARAM, (void *)(long)1) == -99
		&& find_param("no_such_param") == NULL;
}

/* ── through the module API ─────────────────────────────────────── */

static int s_api_no_randomize(void)
{
	return bind_api()
		&& api.set_param("no_randomize", INT_PARAM, (void *)(long)1) == 0
		&& *api.no_randomize == 1
		&& connect_pool() && nf.last_no_randomize == 1;
}

static int s_api_reconnect_buf_size(void)
{
	return bind_api()
		&& api.set_param("reconnect_buf_size", INT_PARAM, (void *)(long)4096) == 0
		&& connect_pool() && nf.last_reconnect_buf == 4096;
}

static int s_api_credentials(void)
{
	return bind_api()
		&& api.set_param("user", STR_PARAM, "bob") == 0
		&& api.set_param("password", STR_PARAM, "pw") == 0
		&& api.pool_auth_configured()
		&& connect_pool() && !strcmp(nf.a_user, "bob") && !strcmp(nf.a_pw, "pw");
}

static int s_api_token_creds_nkey(void)
{
	/* each reaches its slot: a second method is refused at registration */
	return bind_api()
		&& api.set_param("token", STR_PARAM, "t0ken") == 0
		&& api.set_param("creds_file", STR_PARAM, "/proc/self/exe") == 0
		&& api.set_param("nkey", STR_PARAM, "UABC") == 0
		&& api.set_param("nkey_seed_file", STR_PARAM, "/proc/self/exe") == 0
		&& nats_pool_register("nats://127.0.0.1:4222", "test", 2000, 3) == -1
		&& strstr(nats_ut_log(), "set only one") != NULL;
}

static int s_api_timeouts(void)
{
	return bind_api()
		&& api.set_param("kv_op_timeout_ms", INT_PARAM, (void *)(long)300) == 0
		&& api.set_param("js_ack_timeout_ms", INT_PARAM, (void *)(long)700) == 0
		&& api.set_param("js_publish_retries", INT_PARAM, (void *)(long)5) == 0
		&& api.set_param("drain_timeout_ms", INT_PARAM, (void *)(long)900) == 0
		&& *api.kv_op_timeout_ms == 300 && nats_pool_kv_op_timeout_ms == 300
		&& *api.js_ack_timeout_ms == 700 && nats_pool_js_ack_timeout_ms == 700
		&& *api.js_publish_retries == 5 && nats_pool_js_publish_retries == 5
		&& *api.drain_timeout_ms == 900;
}

static int s_api_wrong_type(void)
{
	return bind_api()
		&& api.set_param("no_randomize", STR_PARAM, "1") == -1
		&& api.set_param("user", INT_PARAM, (void *)(long)1) == -1
		&& *api.no_randomize == 0 && !api.pool_auth_configured()
		/* refused by set_param() itself, by name */
		&& strstr(nats_ut_log(), "no_randomize: wrong value type") != NULL
		&& strstr(nats_ut_log(), "user: wrong value type") != NULL;
}

static int s_api_unknown_name(void)
{
	return bind_api()
		&& api.set_param("no_such_setting", INT_PARAM, (void *)(long)1) == -1
		&& api.set_param("", INT_PARAM, (void *)(long)1) == -1;
}

static int s_two_modules_one_connection(void)
{
	/* the nats module and another one set the same things: one merged
	 * value, not one per module */
	return bind_api()
		&& modparam("reconnect_buf_size", INT_PARAM, (void *)(long)1000) == 0
		&& api.set_param("reconnect_buf_size", INT_PARAM, (void *)(long)5000) == 0
		&& modparam("user", STR_PARAM, "alice") == 0
		&& api.set_param("user", STR_PARAM, "alice") == 0
		&& api.set_param("user", STR_PARAM, "bob") == -1
		&& nats_pool_reconnect_buf_size == 5000;
}

/* ── drain_timeout_ms merge ─────────────────────────────────────── */

static int drain(long v)
{ return nats_pool_drain_timeout_setter(INT_PARAM, (void *)v); }

static int s_drain_first_value_replaces_default(void)
{
	/* also below the 5000 ms default */
	return nats_pool_drain_timeout_ms == 5000
		&& drain(2000) == 0 && nats_pool_drain_timeout_ms == 2000;
}

static int s_drain_largest_wins_with_warning(void)
{
	if (drain(8000) != 0 || strstr(nats_ut_log(), "drain_timeout_ms") != NULL)
		return 0;
	/* a lower value from another module loses, and says so */
	return drain(3000) == 0 && nats_pool_drain_timeout_ms == 8000
		&& strstr(nats_ut_log(), "drain_timeout_ms=3000 is below") != NULL;
}

static int s_drain_raise_and_equal_quiet(void)
{
	return drain(2000) == 0 && drain(2000) == 0 && drain(9000) == 0
		&& nats_pool_drain_timeout_ms == 9000
		&& nats_ut_log()[0] == '\0';
}

static int s_drain_rejects(void)
{
	return drain(-1) == -1
		&& nats_pool_drain_timeout_setter(STR_PARAM, "100") == -1
		&& nats_pool_drain_timeout_ms == 5000
		&& drain(0) == 0 && nats_pool_drain_timeout_ms == 0;
}

void nats_ut_shared_params(void)
{
	/* as parameters of the nats module */
	nats_ut_run("modparam no_randomize reaches the connection",
		s_mod_no_randomize);
	nats_ut_run("modparam reconnect_buf_size reaches the connection",
		s_mod_reconnect_buf_size);
	nats_ut_run("modparam drain_timeout_ms bounds the shutdown drain",
		s_mod_drain_timeout);
	nats_ut_run("modparams user + password reach the connection",
		s_mod_user_password);
	nats_ut_run("modparam token reaches the connection", s_mod_token);
	nats_ut_run("modparam creds_file reaches the connection", s_mod_creds_file);
	nats_ut_run("modparams nkey + nkey_seed_file reach the connection",
		s_mod_nkey);
	nats_ut_run("each parameter is exported with its own value type",
		s_mod_types);

	/* through the module API */
	nats_ut_run("set_param(no_randomize) reaches the connection",
		s_api_no_randomize);
	nats_ut_run("set_param(reconnect_buf_size) reaches the connection",
		s_api_reconnect_buf_size);
	nats_ut_run("set_param(user, password) reaches the connection",
		s_api_credentials);
	nats_ut_run("set_param(token, creds_file, nkey, nkey_seed_file) reach "
		"the pool", s_api_token_creds_nkey);
	nats_ut_run("set_param() of the timeouts and retries", s_api_timeouts);
	nats_ut_run("set_param() refuses a value of the wrong type",
		s_api_wrong_type);
	nats_ut_run("set_param() refuses a name it does not know",
		s_api_unknown_name);
	nats_ut_run("a setting given to two modules is merged into one",
		s_two_modules_one_connection);

	/* drain_timeout_ms merge */
	nats_ut_run("drain_timeout_ms: the first value replaces the default",
		s_drain_first_value_replaces_default);
	nats_ut_run("drain_timeout_ms: a lower value loses, with a warning",
		s_drain_largest_wins_with_warning);
	nats_ut_run("drain_timeout_ms: raising or repeating a value is silent",
		s_drain_raise_and_equal_quiet);
	nats_ut_run("drain_timeout_ms: negative and non-integer refused, 0 kept",
		s_drain_rejects);
}
