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
 * What cachedb_nats registers with the core, read back from its live
 * module exports (the core's module list): modparam names (canonical
 * only, no aliases), the script functions (no nats_cdb_request: the
 * nats_request owner is nats_consumer), the dedicated "NATS Reaper"
 * process (the reaper and the periodic resync run there, never in the
 * shared core timer process), and the index_resync_on_reconnect default.
 * Replaces the source-pattern tests test_param_aliases.c (cachedb_nats
 * half; the event_nats / nats_consumer halves belong to those suites),
 * test_nats_request_rename.c, test_resync_modparams.c, the export half of
 * test_reaper_dedicated_proc.c (its scheduler half: test_reaper_sched.c)
 * the default half of test_index_converge.c (its convergence model is
 * RETIRED) and test_dedicated_watcher_proc.c (the watcher is always a
 * dedicated process now; LOST: the watcher table's contents, not
 * selected in this cfg).  LOST: which file a function lives in, the doc-comment
 * greps, the watcher's use of the flag, "no register_timer in mod_init",
 * nats_consumer's export of nats_request (not loaded here).
 */

#include <tap.h>
#include <string.h>

#include "../../../sr_module.h"
#include "../cachedb_nats_expiry.h"

#include "cn_ut.h"

extern int index_resync_on_reconnect;

static const struct module_exports *mod(const char *name)
{
	struct sr_module *m;

	for (m = modules; m; m = m->next)
		if (m->exports && m->exports->name && !strcmp(m->exports->name, name))
			return m->exports;
	return NULL;
}

static const param_export_t *param(const struct module_exports *e, const char *name)
{
	const param_export_t *p;

	for (p = e ? e->params : NULL; p && p->name; p++)
		if (!strcmp(p->name, name))
			return p;
	return NULL;
}

static int has_cmd(const struct module_exports *e, const char *name)
{
	const cmd_export_t *c;

	for (c = e ? e->cmds : NULL; c && c->name; c++)
		if (!strcmp(c->name, name))
			return 1;
	return 0;
}

static void only_canonical(const struct module_exports *e, const char *canon,
	const char *alias)
{
	ok(param(e, canon) != NULL, "mod_exports: canonical %s registered", canon);
	ok(param(e, alias) == NULL, "mod_exports: %s not registered", alias);
}

void cn_ut_mod_exports(void)
{
	const struct module_exports *e = mod("cachedb_nats");
	const param_export_t *p;
	const proc_export_t *pr;
	int reapers = 0, reaper_fn = 0;

	ok(e != NULL, "mod_exports: cachedb_nats is in the core's module list");

	diag("canonical modparam names only (test_param_aliases):");
	only_canonical(e, "reconnect_wait_ms", "reconnect_wait");
	only_canonical(e, "drain_timeout_ms", "cdb_drain_timeout_ms");
	only_canonical(e, "cas_retries", "nats_cas_retries");
	only_canonical(e, "reap_grace", "nats_reap_grace");
	only_canonical(e, "reap_interval", "nats_reap_interval");
	only_canonical(e, "expired_linger", "nats_expired_linger");
	only_canonical(e, "max_value_size", "nats_max_value_size");

	diag("no request/reply in cachedb_nats (test_nats_request_rename):");
	ok(!has_cmd(e, "nats_cdb_request"), "mod_exports: no nats_cdb_request function");
	ok(!has_cmd(e, "nats_request"), "mod_exports: no nats_request function (nats_consumer owns it)");
	ok(param(e, "nats_request_max_reply") == NULL,
		"mod_exports: nats_request_max_reply modparam removed");
	ok(param(e, "nats_request_default_timeout_ms") == NULL,
		"mod_exports: nats_request_default_timeout_ms modparam removed");

	diag("index resync knobs (test_resync_modparams, test_index_converge):");
	p = param(e, "index_resync_on_reconnect");
	ok(p && p->param_pointer == (void *)&index_resync_on_reconnect,
		"mod_exports: index_resync_on_reconnect declared, bound to the flag");
	ok(index_resync_on_reconnect == 1,
		"mod_exports: index_resync_on_reconnect defaults to 1 (unset in the cfg)");
	ok(param(e, "index_resync_interval_secs") != NULL,
		"mod_exports: index_resync_interval_secs declared");

	diag("the dedicated reaper process (test_reaper_dedicated_proc):");
	for (pr = e ? e->procs : NULL; pr && pr->name; pr++)
		if (!strcmp(pr->name, "NATS Reaper")) {
			reapers++;
			if (pr->function == nats_cdb_reaper_proc_main && pr->no == 1)
				reaper_fn = 1;
		}
	ok(reapers == 1 && reaper_fn,
		"mod_exports: one \"NATS Reaper\" process running nats_cdb_reaper_proc_main");

	diag("the watcher is always a dedicated process (test_dedicated_watcher_proc):");
	ok(param(e, "dedicated_watcher_proc") == NULL,
		"mod_exports: no dedicated_watcher_proc modparam (no in-worker mode left)");
	{
		int watchers = 0;
		for (pr = e ? e->procs : NULL; pr && pr->name; pr++)
			if (!strcmp(pr->name, "NATS Watcher"))
				watchers++;
		ok(watchers == 0, "mod_exports: no kv_watch in this cfg -> no \"NATS Watcher\" process forked");
	}
}
