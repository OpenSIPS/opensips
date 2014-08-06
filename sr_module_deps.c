/*
 * $Id$
 *
 * Copyright (C) 2014 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * -------
 * 2014-05-12  removed all module ordering requirements at script level (liviu)
 */

#include <stdlib.h>
#include <stdarg.h>

#include "dprint.h"
#include "error.h"
#include "mem/mem.h"
#include "pt.h"

#include "sr_module_deps.h"

/* list of unsolved module dependencies: struct sr_module ----> "module_name" */
static struct sr_module_dep *unsolved_deps;

#define mod_type_to_string(type) \
	(type == MOD_TYPE_NULL ? NULL : \
	 type == MOD_TYPE_SQLDB ? "sqldb module" : \
	 type == MOD_TYPE_CACHEDB ? "cachedb module" : \
	 "module")

module_dependency_t *alloc_module_dep(enum module_type dep_type, char *mod_name)
{
	module_dependency_t *md;

	/* also allocate a zeroed entry in the end */
	md = pkg_malloc(2 * sizeof *md);
	if (!md) {
		LM_ERR("out of pkg\n");
		return NULL;
	}

	memset(md, 0, 2 * sizeof *md);
	md->mod_type = dep_type;
	md->mod_name = mod_name;

	return md;
}

module_dependency_t *get_deps_sqldb_url(param_export_t *param)
{
	char *db_url = *(char **)param->param_pointer;

	if (param->type & USE_FUNC_PARAM)
		return alloc_module_dep(MOD_TYPE_SQLDB, NULL);

	if (!db_url || strlen(db_url) == 0)
		return NULL;

	return alloc_module_dep(MOD_TYPE_SQLDB, NULL);
}

static int add_module_dependency(struct sr_module *mod, module_dependency_t *dep,
								 char *script_param)
{
	struct sr_module_dep *md;
	int len;

	LM_DBG("adding dependency %s - (%s %s)\n", mod->exports->name,
			mod_type_to_string(dep->mod_type), dep->mod_name);

	len = dep->mod_name ? strlen(dep->mod_name) : 0;

	md = pkg_malloc(sizeof *md + len + 1);
	if (!md) {
		LM_CRIT("out of pkg mem\n");
		return -1;
	}
	memset(md, 0, sizeof *md + len + 1);

	md->mod = mod;
	md->dep_type = dep->mod_type;
	if (dep->mod_name) {
		md->dep.s = (char *)(md + 1);
		md->dep.len = len;
		memcpy(md->dep.s, dep->mod_name, len);
	}

	if (script_param)
		md->script_param = script_param;

	md->next = unsolved_deps;
	unsolved_deps = md;

	return 0;
}

/*
 * register all OpenSIPS module dependencies of a single module parameter
 */
int add_modparam_dependencies(struct sr_module *mod, param_export_t *param)
{
	struct sr_module_dep *it, *tmp;
	module_dependency_t *md;
	modparam_dependency_t *mpd;
	struct module_dependency *(*get_deps_f)(param_export_t *param) = NULL;

	if (!mod->exports->deps)
		return 0;

	/* lookup this parameter's dependency fetching function */
	for (mpd = mod->exports->deps->mpd; mpd->script_param; mpd++) {
		if (strcmp(mpd->script_param, param->name) == 0)
			get_deps_f = mpd->get_deps_f;
	}

	/* 98% of OpenSIPS's modparams will stop here */
	if (!get_deps_f)
		return 0;

	/* clear previous entries in case this parameter is set multiple times */
	for (it = unsolved_deps; it && it->next; it = it->next) {
		if (strcmp(it->mod->exports->name, mod->exports->name) == 0 &&
			(it->next->script_param &&
			 strcmp(it->next->script_param, param->name) == 0)) {

			tmp = it->next;
			it->next = it->next->next;
			pkg_free(tmp);
		}
	}

	if (unsolved_deps &&
		strcmp(unsolved_deps->mod->exports->name, mod->exports->name) == 0 &&
		(unsolved_deps->script_param &&
		 strcmp(unsolved_deps->script_param, param->name) == 0)) {

		tmp = unsolved_deps;
		unsolved_deps = unsolved_deps->next;
		pkg_free(tmp);
	}

	md = get_deps_f(param);
	if (!md)
		return 0;

	LM_DBG("adding modparam dependencies:\n");
	for (; md->mod_type != MOD_TYPE_NULL; md++) {
		LM_DBG("dependency found: %s ---> ( %s %s )\n", mod->exports->name,
				mod_type_to_string(md->mod_type), md->mod_name);

		if (add_module_dependency(mod, md, param->name) != 0) {
			LM_ERR("failed to add dep!\n");
			return E_BUG;
		}
	}

	return 0;
}

/*
 * register all OpenSIPS module dependencies of a single module
 */
int add_module_dependencies(struct sr_module *mod)
{
	module_dependency_t *md;

	for (md = mod->exports->deps->md; md->mod_type != MOD_TYPE_NULL; md++) {
		if (add_module_dependency(mod, md, NULL) != 0) {
			LM_ERR("failed to add mod dep\n");
			return -1;
		}
	}

	return 0;
}

int solve_module_dependencies(void)
{
	struct sr_module_dep *md, *it;
	struct sr_module *this, *mod;
	enum module_type dep_type;
	int dep_solved;

	/*
	 * now that we've loaded all shared libraries,
	 * we can solve each dependency
	 */
	for (it = unsolved_deps; it; ) {
		md = it;
		it = it->next;

		LM_DBG("solving dependency %s -> %s %.*s\n", md->mod->exports->name,
				 mod_type_to_string(md->dep_type), md->dep.len, md->dep.s);

		/*
		 * for generic dependencies (e.g. dialog depends on MOD_TYPE_SQLDB),
		 * first load all modules of given type
		 */
		if (!md->dep.s) {
			this = md->mod;
			dep_type = md->dep_type;

			for (dep_solved = 0, mod = modules; mod; mod = mod->next) {
				if (mod != this && mod->exports->type == dep_type) {
					if (!md) {
						md = pkg_malloc(sizeof *md);
						if (!md) {
							LM_ERR("no more pkg\n");
							return -1;
						}
						memset(md, 0, sizeof *md);
					}

					/*
					 * re-purpose this structure by linking it into a module's
					 * list of dependencies (will be used at init time)
					 *
					 * md->mod used to point to (highlighted with []):
					 *		[sr_module A] ---> "mod_name"
					 *
					 * now, the dependency is solved. md->mod will point to:
					 *		sr_module A  ---> [sr_module B]
					 */
					md->mod = mod;
					md->next = this->sr_deps;
					this->sr_deps = md;

					md = NULL;
					dep_solved++;
				}
			}
		} else {
			for (dep_solved = 0, mod = modules; mod; mod = mod->next) {
				if (strcmp(mod->exports->name, md->dep.s) == 0) {

					/* quick sanity check */
					if (mod->exports->type != md->dep_type)
						LM_BUG("[%.*s %d] -> [%s %d]\n", md->dep.len, md->dep.s,
								md->dep_type, mod->exports->name,
								mod->exports->type);

					/* same re-purposing technique as above */
					md->next = md->mod->sr_deps;
					md->mod->sr_deps = md;
					md->mod = mod;

					dep_solved++;
					break;
				}
			}
		}

		/*
		 * since dependencies are meant to solve load ordering issues,
		 * we should not throw an error in this case
		 */
		if (!dep_solved)
			LM_WARN("module %s depends on %s %.*s, but it was not loaded!\n",
					md->mod->exports->name, mod_type_to_string(md->dep_type),
					md->dep.len, md->dep.s);
	}

	return 0;
}
