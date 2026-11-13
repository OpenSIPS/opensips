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
 * nats_bind_mod.h -- for the main file of a module that uses the nats
 * module: binds the nats module's API into `nats_api` (nats_bind.h).
 *
 * The main file defines `struct nats_binds nats_api;`, lists the "nats"
 * module as a dependency, and calls nats_bind_api() first in mod_init.
 * Settings of the shared connection given to the module are kept by a
 * nats_alias_<name> setter (NATS_ALIAS_SETTER, a USE_FUNC_PARAM) and
 * forwarded to the nats module by nats_bind_api().
 */

#ifndef NATS_BIND_MOD_H
#define NATS_BIND_MOD_H

#include "../../dprint.h"
#include "nats_api.h"
#include "nats_bind.h"

/* ---- settings of the shared connection given to this module ---- */

#define NATS_ALIAS_MAX 32

static struct {
	const char *name;
	modparam_t type;
	void *val;
} nats_alias_kept[NATS_ALIAS_MAX];
static int nats_alias_cnt;

/* USE_FUNC_PARAM setter body: keep the value until nats_bind_api() */
static inline int nats_alias_keep(const char *name, modparam_t type, void *val)
{
	if (nats_alias_cnt >= NATS_ALIAS_MAX) {
		LM_ERR("%s: too many NATS connection settings\n", name);
		return -1;
	}
	nats_alias_kept[nats_alias_cnt].name = name;
	nats_alias_kept[nats_alias_cnt].type = type;
	nats_alias_kept[nats_alias_cnt].val = val;
	nats_alias_cnt++;
	return 0;
}

/* A setter named nats_alias_<name> for the param_export_t table. */
#define NATS_ALIAS_SETTER(_name) \
	static int nats_alias_##_name(modparam_t type, void *val) \
	{ return nats_alias_keep(#_name, type, val); }

/* Bind the nats module's API into nats_api and forward the kept
 * settings.  From mod_init.  Returns 0, or -1 (logged). */
static inline int nats_bind_api(const char *modname)
{
	int i;

	if (load_nats_api(&nats_api) < 0) {
		LM_ERR("%s: cannot bind the nats module API "
			"(loadmodule \"nats.so\")\n", modname);
		return -1;
	}
	for (i = 0; i < nats_alias_cnt; i++)
		if (nats_api.set_param(nats_alias_kept[i].name,
		    nats_alias_kept[i].type, nats_alias_kept[i].val) < 0)
			return -1;
	nats_alias_cnt = 0;
	return 0;
}

#endif /* NATS_BIND_MOD_H */
