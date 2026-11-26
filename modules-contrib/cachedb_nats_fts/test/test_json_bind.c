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
 * The JSON walkers come from cachedb_nats through its "cdbn_json_bind"
 * command (GitHub #4501), not through the global scope: cachedb_nats is
 * opened without RTLD_GLOBAL, so none of its symbols resolve there, and
 * its "exports" cannot stand in for another module's.
 */

#include <tap.h>
#include <dlfcn.h>
#include <string.h>

#include "../../../sr_module.h"
#include "../fts_index.h"

#include "fts_ut.h"

static int bind_fails(cdbn_json_api_t *api)
{
	(void)api;
	return -1;
}

/* reports success but leaves parse_json_string unset */
static int bind_partial(cdbn_json_api_t *api)
{
	cdbn_json_bind_f real =
		(cdbn_json_bind_f)find_export("cdbn_json_bind", 0);

	if (!real || real(api) < 0)
		return -1;
	api->parse_json_string = NULL;
	return 0;
}

static const struct sr_module *module(const char *name)
{
	const struct sr_module *m;

	for (m = modules; m; m = m->next)
		if (m->exports && m->exports->name
				&& !strcmp(m->exports->name, name))
			return m;
	return NULL;
}

static void bound_at_init(void)
{
	cdbn_json_bind_f real =
		(cdbn_json_bind_f)find_export("cdbn_json_bind", 0);
	cdbn_json_api_t want;

	ok(real != NULL, "json_bind: cachedb_nats exports cdbn_json_bind");
	memset(&want, 0, sizeof want);
	ok(real && real(&want) == 0, "json_bind: cdbn_json_bind succeeds");
	ok(fts_json.skip_ws && fts_json.skip_ws == want.skip_ws,
		"json_bind: mod_init bound skip_ws from cachedb_nats");
	ok(fts_json.parse_json_string
			&& fts_json.parse_json_string == want.parse_json_string,
		"json_bind: mod_init bound parse_json_string from cachedb_nats");
	ok(fts_json.skip_json_value
			&& fts_json.skip_json_value == want.skip_json_value,
		"json_bind: mod_init bound skip_json_value from cachedb_nats");
}

static void refused_binds(void)
{
	cdbn_json_api_t saved = fts_json;

	ok(fts_json_bind(NULL) == -1,
		"json_bind: no cdbn_json_bind (cachedb_nats not loaded) fails");
	ok(!memcmp(&saved, &fts_json, sizeof saved),
		"json_bind: ... and keeps the bound walkers");
	ok(fts_json_bind(bind_fails) == -1,
		"json_bind: a failing cdbn_json_bind fails");
	ok(!memcmp(&saved, &fts_json, sizeof saved),
		"json_bind: ... and keeps the bound walkers");
	ok(fts_json_bind(bind_partial) == -1,
		"json_bind: an API with a NULL walker is refused");
	ok(!memcmp(&saved, &fts_json, sizeof saved),
		"json_bind: ... and keeps the bound walkers");

	memset(&fts_json, 0, sizeof fts_json);
	ok(fts_json_bind((cdbn_json_bind_f)find_export("cdbn_json_bind", 0))
			== 0 && !memcmp(&saved, &fts_json, sizeof saved),
		"json_bind: binding again restores the same walkers");
	fts_json = saved;
}

static void global_scope(void)
{
	const struct sr_module *cdb = module("cachedb_nats");
	const struct sr_module *fts = module("cachedb_nats_fts");
	/* the main program's handle searches the global scope only */
	void *main_h = dlopen(NULL, RTLD_NOW), *glob;

	ok(cdb && fts && main_h,
		"json_bind: cachedb_nats and cachedb_nats_fts loaded");
	if (!cdb || !fts || !main_h)
		return;
	glob = dlsym(main_h, "exports");
	ok(glob != (void *)cdb->exports,
		"json_bind: the global-scope exports (%p) is not cachedb_nats's "
		"(%p)", glob, (void *)cdb->exports);
	ok(dlsym(main_h, "cdbn_skip_ws") == NULL,
		"json_bind: cdbn_skip_ws does not resolve in the global scope");
	ok(dlsym(main_h, "cdbn_parse_json_string") == NULL,
		"json_bind: cdbn_parse_json_string does not resolve in the "
		"global scope");
	ok(dlsym(main_h, "cdbn_skip_json_value") == NULL,
		"json_bind: cdbn_skip_json_value does not resolve in the "
		"global scope");
	/* the rest of this module's lookup scope: itself and its
	 * dependencies (the handle form is POSIX; RTLD_DEFAULT is a GNU
	 * extension, declared only under _GNU_SOURCE) */
	ok(dlsym(fts->handle, "cdbn_skip_ws") == NULL,
		"json_bind: nor in cachedb_nats_fts.so and its dependencies");
	dlclose(main_h);
}

void fts_ut_json_bind(void)
{
	bound_at_init();
	refused_binds();
	global_scope();
}
