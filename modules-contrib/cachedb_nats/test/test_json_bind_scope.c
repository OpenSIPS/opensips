/*
 * Copyright (C) 2026 OpenSIPS Solutions
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
 * No symbol of cachedb_nats reaches the global scope (GitHub #4501): with
 * RTLD_GLOBAL, its "exports" took the place of the "exports" of every
 * module loaded after it (rtpengine's notification_sock setter wrote
 * cachedb_nats's exports.procs, so its process was never forked).  The
 * JSON walkers cachedb_nats_fts needs come through "cdbn_json_bind".
 */

#include <tap.h>
#include <dlfcn.h>
#include <string.h>

#include "../../../sr_module.h"
#include "../cachedb_nats_json_api.h"

#include "cn_ut.h"

static struct sr_module *own_module(void)
{
	struct sr_module *m;

	for (m = modules; m; m = m->next)
		if (m->exports && m->exports->name
				&& !strcmp(m->exports->name, "cachedb_nats"))
			return m;
	return NULL;
}

/* The symbols of cachedb_nats.so that a global scope would hand out. */
static const char *const own_symbols[] = {
	"exports",
	"cdbn_skip_ws",
	"cdbn_parse_json_string",
	"cdbn_skip_json_value",
	"cdbn_safe_json_to_dict",
	"cdbn_fts",
	"cdbn_fts_on",
	"kv_bucket",
	"nats_api",
	NULL
};

static void global_scope(const struct sr_module *m)
{
	const char *const *n;
	void *own, *glob, *main_h;

	ok(!(m->exports->dlflags & RTLD_GLOBAL),
		"json_bind_scope: dlopen flags carry no RTLD_GLOBAL (0x%x)",
		m->exports->dlflags);

	/* The main program's handle searches the global scope only: the
	 * program, its startup libraries and RTLD_GLOBAL objects.
	 * RTLD_DEFAULT cannot be used here, as glibc searches it from the
	 * scope of the caller, which always holds cachedb_nats.so itself. */
	main_h = dlopen(NULL, RTLD_NOW);
	ok(main_h != NULL, "json_bind_scope: dlopen(NULL) gives the global scope");
	if (!main_h)
		return;

	for (n = own_symbols; *n; n++) {
		own = dlsym(m->handle, *n);
		glob = dlsym(main_h, *n);
		ok(own != NULL && glob != own,
			"json_bind_scope: %s of cachedb_nats.so (%p) is not the "
			"global-scope %s (%p)", *n, own, *n, glob);
	}
	dlclose(main_h);
}

static void walkers(const cdbn_json_api_t *api)
{
	static const char ws[] = " \t\r\nx";
	static const char str[] = "\"a\\\"b\" tail";
	static const char unterminated[] = "\"abc";
	static const char obj[] = "{\"a\":[1,{\"b\":\"}]\"}]} ,";
	static const char truncated[] = "{\"a\":[1";
	static const char num[] = "-12.5e3,";
	const char *out = NULL, *r;
	int out_len = -1;

	ok(api->skip_ws(ws, ws + sizeof ws - 1) == ws + 4,
		"json_bind_scope: skip_ws stops at the first non-space byte");
	ok(api->skip_ws(ws, ws + 4) == ws + 4,
		"json_bind_scope: skip_ws on only whitespace returns end");

	r = api->parse_json_string(str, str + sizeof str - 1, &out, &out_len);
	ok(r == str + 6 && out == str + 1 && out_len == 4,
		"json_bind_scope: parse_json_string keeps the escaped quote "
		"(len %d)", out_len);
	out = NULL; out_len = -1;
	r = api->parse_json_string(unterminated,
		unterminated + sizeof unterminated - 1, &out, &out_len);
	ok(r == NULL && out == NULL && out_len == -1,
		"json_bind_scope: parse_json_string refuses an unterminated "
		"string and leaves the outputs alone");
	ok(api->parse_json_string(num, num + sizeof num - 1, &out, &out_len)
			== NULL,
		"json_bind_scope: parse_json_string refuses a non-string");

	ok(api->skip_json_value(obj, obj + sizeof obj - 1) == obj + 20,
		"json_bind_scope: skip_json_value skips a nested object with "
		"brackets inside a string");
	ok(api->skip_json_value(truncated, truncated + sizeof truncated - 1)
			== NULL,
		"json_bind_scope: skip_json_value refuses a truncated object");
	ok(api->skip_json_value(num, num + sizeof num - 1) == num + 7,
		"json_bind_scope: skip_json_value stops a number at the comma");
}

static void bind_api(const struct sr_module *m)
{
	cdbn_json_bind_f bind;
	cdbn_json_api_t api;

	bind = (cdbn_json_bind_f)find_export("cdbn_json_bind", 0);
	ok(bind != NULL, "json_bind_scope: cdbn_json_bind is exported");
	if (!bind)
		return;

	ok(bind(NULL) == -1, "json_bind_scope: cdbn_json_bind(NULL) fails");

	memset(&api, 0, sizeof api);
	ok(bind(&api) == 0, "json_bind_scope: cdbn_json_bind fills the API");
	ok(api.skip_ws == dlsym(m->handle, "cdbn_skip_ws"),
		"json_bind_scope: skip_ws is cachedb_nats's cdbn_skip_ws");
	ok(api.parse_json_string == dlsym(m->handle, "cdbn_parse_json_string"),
		"json_bind_scope: parse_json_string is cachedb_nats's "
		"cdbn_parse_json_string");
	ok(api.skip_json_value == dlsym(m->handle, "cdbn_skip_json_value"),
		"json_bind_scope: skip_json_value is cachedb_nats's "
		"cdbn_skip_json_value");

	if (api.skip_ws && api.parse_json_string && api.skip_json_value)
		walkers(&api);
}

void cn_ut_json_bind_scope(void)
{
	struct sr_module *m = own_module();

	ok(m != NULL && m->handle != NULL,
		"json_bind_scope: cachedb_nats is in the core's module list");
	if (!m || !m->handle)
		return;

	global_scope(m);
	bind_api(m);
}
