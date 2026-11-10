/*
 * Copyright (C) 2026 OpenSIPS Solutions
 * Copyright (C) 2026 Norm Brandinger <n.brandinger@gmail.com>
 *
 * This file is part of opensips, a free SIP server.
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
 * Implementation of the SHM string intern table -- see header
 * for the rationale.  ~half of all opensips CPU at 100k AoRs
 * was sem_wait -> hp_shm_malloc on the watcher's entry_add_key
 * path; this module collapses those allocations into a single
 * intern-or-acquire per unique doc key, with refcounted release.
 */

/*
 * cachedb_nats_fts.c — optional full-text-search / secondary-index module
 * for cachedb_nats.
 *
 * Loading this module IS the enable switch (it replaces the former
 * enable_search_index modparam): cachedb_nats binds to it at startup via
 * cdbn_fts_bind() and, when bound, feeds the SHM index from its writer
 * and watcher paths and routes non-PK string-equality query() filters
 * through query_match_keys().  Without this module cachedb_nats answers
 * primary-key queries directly and scans the bucket for any other
 * filter -- the flagship usrloc path never touches any of this.
 *
 * The module owns: the SHM hash index (fts_index.c), the doc-key intern
 * table (fts_intern.c) and the non-PK filter walk (fts_query.c).  The
 * KV watcher process, the resync timer and the kv_watch patterns stay
 * with cachedb_nats, which drives this module through the binds API.
 */

#include "../../sr_module.h"
#include "../nats/nats_bind_mod.h"
#include "../../dprint.h"

#include "cachedb_nats_fts_api.h"
#include "fts_index.h"
#include "fts_intern.h"

static int mod_init(void);
static void mod_destroy(void);

/* modparams (moved from cachedb_nats with the index) */
int fts_max_results = 100;
/* nats_idx_buckets / nats_idx_bucket_mask are defined in fts_index.c */

int fts_query_match_keys(const cdb_filter_t *filter,
		char ***out_keys, int *out_count);
void fts_release_keyset(char **keys, int count);
int fts_resolve_key(const str *field, const str *val,
		char *out, int out_len);

static int cdbn_fts_bind(cdbn_fts_api_t *api)
{
	if (!api)
		return -1;
	api->build             = nats_json_index_build;
	api->rebuild           = nats_json_index_rebuild;
	api->add               = nats_json_index_add;
	api->remove            = nats_json_index_remove;
	api->remove_by_revmap  = nats_json_index_remove_by_revmap;
	api->remove_fields     = nats_json_index_remove_fields;
	api->count             = nats_json_index_count;
	api->query_match_keys  = fts_query_match_keys;
	api->release_keyset    = fts_release_keyset;
	api->resolve_key       = fts_resolve_key;
	return 0;
}

static const cmd_export_t cmds[] = {
	{"cdbn_fts_bind", (cmd_function)cdbn_fts_bind, {{0, 0, 0}}, 0},
	{0, 0, {{0, 0, 0}}, 0}
};

/* the nats module API (nats_bind_mod.h), bound in mod_init */
struct nats_binds nats_api;

static const param_export_t params[] = {
	{"index_buckets",   INT_PARAM, &nats_idx_buckets},
	{"fts_max_results", INT_PARAM, &fts_max_results},
	{0, 0, 0}
};

/* nats.so holds the libnats function table (nats_dl) */
static const dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "nats", DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

struct module_exports exports = {
	"cachedb_nats_fts",
	MOD_TYPE_DEFAULT,
	MODULE_VERSION,
	DEFAULT_DLFLAGS,
	0,                 /* load function */
	&deps,             /* OpenSIPS module dependencies */
	cmds,
	NULL,              /* acmds */
	params,
	NULL,              /* stats */
	NULL,              /* MI */
	NULL,              /* pvars */
	NULL,              /* transformations */
	NULL,              /* procs */
	NULL,              /* preinit */
	mod_init,
	NULL,              /* response handler */
	mod_destroy,
	NULL,              /* child_init */
	NULL               /* reload confirm */
};

static int mod_init(void)
{
	LM_INFO("initializing cachedb_nats_fts (SHM search index)\n");

	if (nats_bind_api("cachedb_nats_fts") < 0)
		return -1;
	if (nats_intern_init(nats_idx_buckets) < 0) {
		LM_ERR("doc-key intern table init failed\n");
		return -1;
	}
	if (nats_json_index_init() < 0) {
		LM_ERR("search index init failed\n");
		return -1;
	}
	return 0;
}

static void mod_destroy(void)
{
	nats_json_index_destroy();
	/* after the index: free_entry releases interned keys */
	nats_intern_destroy();
}
