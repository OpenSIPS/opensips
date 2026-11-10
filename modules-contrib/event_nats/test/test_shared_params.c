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
 * The settings of the shared connection given to this module
 * (no_randomize, reconnect_buf_size, drain_timeout_ms, the JetStream ack
 * wait and retries, the credentials) are not this module's: there is one
 * connection, in the nats module.  Each is exported through a forwarding
 * setter and handed to the nats module when its API is bound; a value
 * kept here would never reach the connection.
 *
 * The suite's opensips.cfg sets them on event_nats; the test reads them
 * back from the nats module, through the API and from its own variables.
 */

#include <tap.h>
#include <string.h>
#include <dlfcn.h>

#include "../../../sr_module.h"
#include "../../nats/nats_bind.h"

#include "en_ut.h"

extern struct module_exports exports;

static const param_export_t *find_param(const char *name)
{
	const param_export_t *p;

	for (p = exports.params; p && p->name; p++)
		if (strcmp(p->name, name) == 0)
			return p;
	return NULL;
}

/* an int of the nats module, by its symbol */
static int nats_module_int(const char *symbol, int *out)
{
	void *h = get_mod_handle("nats");
	int *p = h ? (int *)dlsym(h, symbol) : NULL;

	if (!p)
		return -1;
	*out = *p;
	return 0;
}

void en_ut_shared_params(void)
{
	static const struct {
		const char *name;
		modparam_t type;
	} forwarded[] = {
		{"no_randomize",       INT_PARAM},
		{"reconnect_buf_size", INT_PARAM},
		{"drain_timeout_ms",   INT_PARAM},
		{"js_ack_timeout_ms",  INT_PARAM},
		{"js_publish_retries", INT_PARAM},
		{"user",               STR_PARAM},
		{"password",           STR_PARAM},
		{"token",              STR_PARAM},
		{"creds_file",         STR_PARAM},
		{"nkey",               STR_PARAM},
		{"nkey_seed_file",     STR_PARAM},
	};
	const param_export_t *p;
	unsigned i;
	int v;

	/* exported through a setter, not as a variable of this module */
	for (i = 0; i < sizeof forwarded / sizeof forwarded[0]; i++) {
		p = find_param(forwarded[i].name);
		ok(p && (p->type & USE_FUNC_PARAM) && (p->type & forwarded[i].type)
			&& p->param_pointer != NULL,
			"%s is exported through a forwarding setter", forwarded[i].name);
	}

	/* the values of the suite's opensips.cfg, in the nats module */
	cmp_ok(*nats_api.no_randomize, "==", 1,
		"no_randomize reached the nats module");
	cmp_ok(*nats_api.drain_timeout_ms, "==", 1500,
		"drain_timeout_ms reached the nats module");
	cmp_ok(*nats_api.js_ack_timeout_ms, "==", 900,
		"js_ack_timeout_ms reached the nats module");
	cmp_ok(*nats_api.js_publish_retries, "==", 2,
		"js_publish_retries reached the nats module");
	ok(nats_api.pool_auth_configured(),
		"user and password reached the nats module");
	if (nats_module_int("nats_pool_reconnect_buf_size", &v) == 0)
		cmp_ok(v, "==", 123456, "reconnect_buf_size reached the nats module");
	else
		fail("reconnect_buf_size reached the nats module (symbol not found)");
	ok(nats_api.pool_is_registered() && nats_api.pool_has_servers(),
		"the module registered its server with the pool");
}
