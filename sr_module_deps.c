/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * -------
 * 2014-05-12  removed all module ordering requirements at script level (liviu)
 */

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include "sr_module_deps.h"

#include "dprint.h"
#include "error.h"
#include "mem/mem.h"

#include "sr_module.h"
#include "pt.h"

/* the list head of unsolved module dependencies: struct sr_module ----> "module_name" */
static struct sr_module_dep unsolved_deps;

#define mod_type_to_string(type) \
	(type == MOD_TYPE_NULL ? NULL : \
	 type == MOD_TYPE_SQLDB ? "sqldb module" : \
	 type == MOD_TYPE_CACHEDB ? "cachedb module" : \
	 type == MOD_TYPE_AAA ? "aaa module" : \
	 "module")


module_dependency_t *alloc_module_dep(enum module_type mod_type, char *mod_name,
									  enum dep_type dep_type)
{
	return _alloc_module_dep(mod_type, mod_name, dep_type, MOD_TYPE_NULL);
}


module_dependency_t *_alloc_module_dep(enum module_type mod_type, char *mod_name,
                             enum dep_type dep_type, ... /* , MOD_TYPE_NULL */)
{
	va_list ap;
	module_dependency_t *md;
	int ndeps = 1;

	/* always keep a zeroed entry at the end */
	md = pkg_malloc(2 * sizeof *md);
	if (!md) {
		LM_ERR("oom\n");
		return NULL;
	}

	memset(md, 0, 2 * sizeof *md);
	md->mod_type = mod_type;
	md->mod_name = mod_name;
	md->type = dep_type;

	va_start(ap, dep_type);

	for (;;) {
		mod_type = va_arg(ap, enum module_type);
		if (mod_type == MOD_TYPE_NULL)
			break;

		ndeps++;

		md = pkg_realloc(md, (ndeps + 1) * sizeof *md);
		if (!md) {
			LM_ERR("oom\n");
			va_end(ap);
			return NULL;
		}
		memset(&md[ndeps], 0, sizeof *md);

		md[ndeps - 1].mod_type = mod_type;
		md[ndeps - 1].mod_name = va_arg(ap, char *);
		md[ndeps - 1].type = va_arg(ap, enum dep_type);
	}

	va_end(ap);
	return md;
}


module_dependency_t *get_deps_sqldb_url(param_export_t *param)
{
	char *db_url = *(char **)param->param_pointer;

	if (param->type & USE_FUNC_PARAM)
		return alloc_module_dep(MOD_TYPE_SQLDB, NULL, DEP_WARN);

	if (!db_url || strlen(db_url) == 0)
		return NULL;

	return alloc_module_dep(MOD_TYPE_SQLDB, NULL, DEP_WARN);
}


module_dependency_t *get_deps_cachedb_url(param_export_t *param)
{
	char *cdb_url = *(char **)param->param_pointer;

	if (!cdb_url || strlen(cdb_url) == 0)
		return NULL;

	return alloc_module_dep(MOD_TYPE_CACHEDB, NULL, DEP_ABORT);
}


static int add_module_dependency(struct sr_module *mod, module_dependency_t *dep,
								 char *script_param)
{
	struct sr_module_dep *md;
	int len;

	LM_DBG("adding type %d dependency %s - (%s %s)\n", dep->type,
			mod->exports->name, mod_type_to_string(dep->mod_type),
			dep->mod_name);

	len = dep->mod_name ? strlen(dep->mod_name) : 0;

	md = pkg_malloc(sizeof *md + len + 1);
	if (!md) {
		LM_CRIT("out of pkg mem\n");
		return -1;
	}
	memset(md, 0, sizeof *md + len + 1);

	md->mod = mod;
	md->mod_type = dep->mod_type;
	md->type = dep->type;
	if (dep->mod_name) {
		md->dep.s = (char *)(md + 1);
		md->dep.len = len;
		memcpy(md->dep.s, dep->mod_name, len);
	}

	if (script_param)
		md->script_param = script_param;

	md->next = unsolved_deps.next;
	unsolved_deps.next = md;

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
	for (it = &unsolved_deps; it && it->next; it = it->next) {
		if (strcmp(it->next->mod->exports->name, mod->exports->name) == 0 &&
			(it->next->script_param &&
			 strcmp(it->next->script_param, param->name) == 0)) {

			tmp = it->next;
			it->next = it->next->next;
			pkg_free(tmp);
		}
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


int solve_module_dependencies(struct sr_module *modules)
{
	struct sr_module_dep *md, *it;
	struct sr_module *this, *mod;
	enum module_type mod_type;
	enum dep_type dep_type;
	int dep_solved;

	/*
	 * now that we've loaded all shared libraries,
	 * we can attempt to solve each dependency
	 */
	for (it = unsolved_deps.next; it; ) {
		md = it;
		it = it->next;

		LM_DBG("solving dependency %s -> %s %.*s\n", md->mod->exports->name,
				 mod_type_to_string(md->mod_type), md->dep.len, md->dep.s);

		dep_type = md->type;

		/*
		 * for generic dependencies (e.g. dialog depends on MOD_TYPE_SQLDB),
		 * first load all modules of given type
		 */
		if (!md->dep.s) {
			this = md->mod;
			mod_type = md->mod_type;

			for (dep_solved = 0, mod = modules; mod; mod = mod->next) {
				if (mod != this && mod->exports->type == mod_type) {
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
					if (mod->exports->type != md->mod_type)
						LM_BUG("[%.*s %d] -> [%s %d]\n", md->dep.len, md->dep.s,
								md->mod_type, mod->exports->name,
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

		/* treat unmet dependencies using the intended behaviour */
		if (!dep_solved) {
			switch (dep_type) {
			case DEP_SILENT:
				LM_DBG("module %s soft-depends on "
				           "%s%s%s%.*s%s%s, and %s loaded -- proceeding\n",
						md->mod->exports->name,
						md->dep.len == 0 ?
							((md->mod_type == MOD_TYPE_SQLDB ||
							  md->mod_type == MOD_TYPE_AAA) ? "an " :
							md->mod_type == MOD_TYPE_CACHEDB ? "a " : "") : "",
						mod_type_to_string(md->mod_type),
						md->dep.len == 0 ? "" : " ",
						md->dep.len, md->dep.s,
						md->script_param ? " due to modparam " : "",
						md->script_param ? md->script_param : "",
						md->dep.len == 0 ? "none was" : "it was not");
				break;
			case DEP_WARN:
			case DEP_ABORT:
				LM_WARN("module %s depends on %s%s%s%.*s%s%s, but %s loaded!\n",
						md->mod->exports->name,
						md->dep.len == 0 ?
							((md->mod_type == MOD_TYPE_SQLDB ||
							  md->mod_type == MOD_TYPE_AAA) ? "an " :
							md->mod_type == MOD_TYPE_CACHEDB ? "a " : "") : "",
						mod_type_to_string(md->mod_type),
						md->dep.len == 0 ? "" : " ",
						md->dep.len, md->dep.s,
						md->script_param ? " due to modparam " : "",
						md->script_param ? md->script_param : "",
						md->dep.len == 0 ? "none was" : "it was not");
				break;
			}

			pkg_free(md);
			if (dep_type == DEP_ABORT)
				return -1;
		}
	}

	return 0;
}


/* after all modules are properly loaded, free all sr_module_dep structures */
void free_module_dependencies(struct sr_module *modules)
{
	struct sr_module_dep *aux;
	struct sr_module *mod;

	for (mod = modules; mod; mod = mod->next) {
		while (mod->sr_deps) {
			aux = mod->sr_deps;
			mod->sr_deps = aux->next;
			pkg_free(aux);
		}
	}
}
