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
 * nats.c -- the nats module: the NATS connection pool (nats_pool.c) and
 * the libnats loader (nats_dl.c) shared by event_nats, cachedb_nats,
 * cachedb_nats_fts and nats_consumer through load_nats_api()
 * (nats_api.h).  One nats.so per OpenSIPS process holds the connection
 * state of all of them.
 *
 * Its parameters are the settings of the shared connection; the other
 * NATS modules accept the same names and forward them here
 * (nats_binds.set_param), with the same merge rules.
 */

#include <string.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "nats_api.h"
#include "nats_pool.h"
#include "nats_redact.h"
#include "nats_validate.h"

static int load_nats(struct nats_binds *binds);
static int nats_set_param(const char *name, modparam_t type, void *val);

static int set_int(int *dst, const char *name, modparam_t type, void *val)
{
	if ((type & PARAM_TYPE_MASK(INT_PARAM)) == 0) {
		LM_ERR("%s: must be an integer\n", name);
		return -1;
	}
	*dst = (int)(long)val;
	return 0;
}

static int kv_op_timeout_setter(modparam_t type, void *val)
{ return set_int(&nats_pool_kv_op_timeout_ms, "kv_op_timeout_ms", type, val); }
static int js_ack_timeout_setter(modparam_t type, void *val)
{ return set_int(&nats_pool_js_ack_timeout_ms, "js_ack_timeout_ms", type, val); }
static int js_publish_retries_setter(modparam_t type, void *val)
{ return set_int(&nats_pool_js_publish_retries, "js_publish_retries", type, val); }

/* name -> setter: the module parameters, and what set_param() applies */
static const struct {
	const char *name;
	int (*setter)(modparam_t type, void *val);
	modparam_t type;
} shared_params[] = {
	{"no_randomize",       nats_pool_no_randomize_setter,         INT_PARAM},
	{"reconnect_buf_size", nats_pool_reconnect_buf_size_setter,   INT_PARAM},
	{"drain_timeout_ms",   nats_pool_drain_timeout_setter,        INT_PARAM},
	{"user",               nats_pool_auth_user_setter,            STR_PARAM},
	{"password",           nats_pool_auth_password_setter,        STR_PARAM},
	{"token",              nats_pool_auth_token_setter,           STR_PARAM},
	{"creds_file",         nats_pool_auth_creds_file_setter,      STR_PARAM},
	{"nkey",               nats_pool_auth_nkey_setter,            STR_PARAM},
	{"nkey_seed_file",     nats_pool_auth_nkey_seed_file_setter,  STR_PARAM},
	{"kv_op_timeout_ms",   kv_op_timeout_setter,                  INT_PARAM},
	{"js_ack_timeout_ms",  js_ack_timeout_setter,                 INT_PARAM},
	{"js_publish_retries", js_publish_retries_setter,             INT_PARAM},
};
#define SHARED_PARAMS_N (sizeof(shared_params) / sizeof(shared_params[0]))

static const param_export_t params[] = {
	{"no_randomize",       INT_PARAM|USE_FUNC_PARAM, (void *)nats_pool_no_randomize_setter},
	{"reconnect_buf_size", INT_PARAM|USE_FUNC_PARAM, (void *)nats_pool_reconnect_buf_size_setter},
	{"drain_timeout_ms",   INT_PARAM|USE_FUNC_PARAM, (void *)nats_pool_drain_timeout_setter},
	{"user",               STR_PARAM|USE_FUNC_PARAM, (void *)nats_pool_auth_user_setter},
	{"password",           STR_PARAM|USE_FUNC_PARAM, (void *)nats_pool_auth_password_setter},
	{"token",              STR_PARAM|USE_FUNC_PARAM, (void *)nats_pool_auth_token_setter},
	{"creds_file",         STR_PARAM|USE_FUNC_PARAM, (void *)nats_pool_auth_creds_file_setter},
	{"nkey",               STR_PARAM|USE_FUNC_PARAM, (void *)nats_pool_auth_nkey_setter},
	{"nkey_seed_file",     STR_PARAM|USE_FUNC_PARAM, (void *)nats_pool_auth_nkey_seed_file_setter},
	{0, 0, 0}
};

static const cmd_export_t cmds[] = {
	{"load_nats", (cmd_function)load_nats, {{0, 0, 0}}, 0},
	{0, 0, {{0, 0, 0}}, 0}
};

struct module_exports exports = {
	"nats",                     /* module name */
	MOD_TYPE_DEFAULT,           /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,            /* dlopen flags */
	0,                          /* load function */
	0,                          /* OpenSIPS module dependencies */
	cmds,                       /* exported functions */
	0,                          /* exported async functions */
	params,                     /* exported parameters */
	0,                          /* exported statistics */
	0,                          /* exported MI functions */
	0,                          /* exported pseudo-variables */
	0,                          /* exported transformations */
	0,                          /* extra processes */
	0,                          /* module pre-initialization function */
	0,                          /* module initialization function */
	0,                          /* response handling function */
	0,                          /* destroy function */
	0,                          /* per-child init function */
	0                           /* reload confirm function */
};

static int nats_set_param(const char *name, modparam_t type, void *val)
{
	unsigned i;

	for (i = 0; i < SHARED_PARAMS_N; i++) {
		if (strcmp(shared_params[i].name, name) != 0)
			continue;
		if ((type & PARAM_TYPE_MASK(shared_params[i].type)) == 0) {
			LM_ERR("%s: wrong value type\n", name);
			return -1;
		}
		return shared_params[i].setter(type, val);
	}
	LM_BUG("unknown shared NATS setting '%s'\n", name);
	return -1;
}

static int load_nats(struct nats_binds *b)
{
	if (!b)
		return -1;
	memset(b, 0, sizeof *b);
	b->dl = &nats_dl;

	b->pool_register = nats_pool_register;
	b->pool_register_default = nats_pool_register_default;
	b->pool_unregister = nats_pool_unregister;
	b->pool_bind_tls = nats_pool_bind_tls;
	b->pool_get = nats_pool_get;
	b->pool_get_js = nats_pool_get_js;
	b->pool_get_kv = nats_pool_get_kv;
	b->pool_is_connected = nats_pool_is_connected;
	b->pool_get_reconnect_epoch = nats_pool_get_reconnect_epoch;
	b->pool_has_servers = nats_pool_has_servers;
	b->pool_is_registered = nats_pool_is_registered;
	b->pool_should_init = nats_pool_should_init;
	b->pool_get_server_info = nats_pool_get_server_info;
	b->pool_set_pub_ack_cb = nats_pool_set_pub_ack_cb;
	b->pool_bucket_maxage_ns = nats_pool_bucket_maxage_ns;
	b->pool_bucket_mmps = nats_pool_bucket_mmps;
	b->pool_auth_configured = nats_pool_auth_configured;

	b->js_ack_timeout_ms = &nats_pool_js_ack_timeout_ms;
	b->js_publish_retries = &nats_pool_js_publish_retries;
	b->kv_op_timeout_ms = &nats_pool_kv_op_timeout_ms;
	b->drain_timeout_ms = &nats_pool_drain_timeout_ms;
	b->no_randomize = &nats_pool_no_randomize;
	b->set_param = nats_set_param;

	b->redact_url = nats_redact_url;
	b->redact_key = nats_redact_key;
	b->validate_publish_subject = nats_validate_publish_subject;
	b->validate = nats_validate;
	return 0;
}
