/*
 * Copyright (C) 2014-2021 OpenSIPS Solutions
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
									  unsigned int dep_type)
{
	return _alloc_module_dep(mod_type, mod_name, dep_type, MOD_TYPE_NULL);
}


module_dependency_t *_alloc_module_dep(enum module_type mod_type, char *mod_name,
                             unsigned int dep_type, ... /* , MOD_TYPE_NULL */)
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
		md[ndeps - 1].type = va_arg(ap, unsigned int);
	}

	va_end(ap);
	return md;
}


module_dependency_t *get_deps_sqldb_url(const param_export_t *param)
{
	char *db_url = *(char **)param->param_pointer;

	if (param->type & USE_FUNC_PARAM)
		return alloc_module_dep(MOD_TYPE_SQLDB, NULL, DEP_WARN);

	if (!db_url || strlen(db_url) == 0)
		return NULL;

	return alloc_module_dep(MOD_TYPE_SQLDB, NULL, DEP_WARN);
}


module_dependency_t *get_deps_cachedb_url(const param_export_t *param)
{
	char *cdb_url = *(char **)param->param_pointer;

	if (!cdb_url || strlen(cdb_url) == 0)
		return NULL;

	return alloc_module_dep(MOD_TYPE_CACHEDB, NULL, DEP_ABORT);
}


static int add_module_dependency(struct sr_module *mod, const module_dependency_t *dep,
								 const char *script_param)
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
int add_modparam_dependencies(struct sr_module *mod, const param_export_t *param)
{
	struct sr_module_dep *it, *tmp;
	module_dependency_t *md;
	const modparam_dependency_t *mpd;
	struct module_dependency *(*get_deps_f)(const param_export_t *param) = NULL;

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
	const module_dependency_t *md;

	for (md = mod->exports->deps->md; md->mod_type != MOD_TYPE_NULL; md++) {
		if (add_module_dependency(mod, md, NULL) != 0) {
			LM_ERR("failed to add mod dep\n");
			return -1;
		}
	}

	return 0;
}

static struct sr_module_dep *make_dep(struct sr_module_dep *md,
    unsigned int dep_type, unsigned int df, struct sr_module *mod_a,
    struct sr_module *mod_b)
{
	struct sr_module_dep **dip_a, **dip_b;

	switch (df) {
	case DEP_REVERSE_MINIT:
		dip_a = &mod_a->sr_deps_init;
		dip_b = &mod_b->sr_deps_init;
		break;
	case DEP_REVERSE_CINIT:
		dip_a = &mod_a->sr_deps_cinit;
		dip_b = &mod_b->sr_deps_cinit;
		break;
	case DEP_REVERSE_DESTROY:
		dip_a = &mod_a->sr_deps_destroy;
		dip_b = &mod_b->sr_deps_destroy;
		break;
	default:
		LM_ERR("BUG, unhandled dep_type: %d\n", df);
		abort();
	}

	if (md == NULL) {
		md = pkg_malloc(sizeof *md);
		if (!md) {
			LM_ERR("no more pkg\n");
			return NULL;
		}
		memset(md, 0, sizeof *md);
	}

	if (dep_type & df) {
		md->mod = mod_a;
		md->next = *dip_b;
		*dip_b = md;
	} else {
		md->mod = mod_b;
		md->next = *dip_a;
		*dip_a = md;
	}
	return md;
}

int solve_module_dependencies(struct sr_module *modules)
{
	struct sr_module_dep *md, *it;
	struct sr_module *this, *mod;
	enum module_type mod_type;
	unsigned int dep_type;
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

		this = md->mod;
		dep_type = md->type;
		int byname = !!md->dep.s;
		mod_type = md->mod_type;

		/*
		 * for generic dependencies (e.g. dialog depends on MOD_TYPE_SQLDB),
		 * first load all modules of given type
		 *
		 * re-purpose this @md structure by linking it into a module's
		 * list of dependencies (will be used at init time)
		 *
		 * md->mod used to point to (highlighted with []):
		 *		[sr_module A] ---> "mod_name"
		 *
		 * now, the dependency is solved. md->mod will point to:
		 *		sr_module A  ---> [sr_module B]
		 */

		for (dep_solved = 0, mod = modules; mod; mod = mod->next) {
			if (!byname) {
				if (mod == this || mod->exports->type != mod_type)
					continue;
			} else {
				if (strcmp(mod->exports->name, md->dep.s) != 0)
					continue;
				if (mod->exports->type != mod_type)
					LM_BUG("[%.*s %d] -> [%s %d]\n", md->dep.len, md->dep.s,
						mod_type, mod->exports->name,
						mod->exports->type);
			}

			if (!make_dep(md, dep_type, DEP_REVERSE_MINIT, this, mod))
				return -1;
			md = NULL;

			if (!make_dep(NULL, dep_type, DEP_REVERSE_DESTROY, mod, this))
				return -1;

			if (!make_dep(NULL, dep_type, DEP_REVERSE_CINIT, this, mod))
				return -1;

			dep_solved++;
			if (byname)
				break;
		}

		/* reverse-init dependencies are always solved! */
		if (dep_solved || dep_type & DEP_REVERSE_MINIT)
			continue;

		/* treat unmet dependencies using the intended behaviour */
		if (dep_type & DEP_SILENT) {
			LM_DBG("module %s soft-depends on "
			           "%s%s%s%.*s%s%s, and %s loaded -- continuing\n",
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
		} else if (dep_type & (DEP_WARN|DEP_ABORT)) {
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
		}

		pkg_free(md);
		if (dep_type & DEP_ABORT)
			return -1;
	}

	return 0;
}


/* After all modules are loaded & destroyed, free the dep structures */
void free_module_dependencies(struct sr_module *modules)
{
	struct sr_module_dep *aux;
	struct sr_module *mod;

	for (mod = modules; mod; mod = mod->next) {
		while (mod->sr_deps_init) {
			aux = mod->sr_deps_init;
			mod->sr_deps_init = aux->next;
			pkg_free(aux);
		}

		while (mod->sr_deps_destroy) {
			aux = mod->sr_deps_destroy;
			mod->sr_deps_destroy = aux->next;
			pkg_free(aux);
		}
	}
}
