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

#ifndef SR_MODULE_DEPS_H
#define SR_MODULE_DEPS_H

/*
 * Description:
 *
 * - the core module dependencies code simply helps rearrange the module loading
 *   order so that the dependencies of each OpenSIPS module are satisfied
 *
 * - a module may specify dependencies in two ways:
 *   * module -> module (if X -> Y, load Y before X) - most common
 *   * modparam -> module (if a parameter of module X has a certain value,
 *                         ensure module Y loads first)
 *
 * - a dependency can be of two types:
 *   * straightforward dependency ("acc" depends on "tm")
 *   * generic dependency ("acc" depends on any MOD_TYPE_SQLDB module)
 *
 * - both module and modparam dependencies are populated within exports->deps
 *
 * - for the latter, a function must be provided for each modparam:
 *   * input: the parameter's populated param_export_t struct
 *   * output: NULL / module dependency resulted from the value of the modparam
 *
 * when dependencies are not satisfied (e.g. depending module not present),
 * OpenSIPS may throw a warning, abort or not do anything at all
 *
 * For a complete usage example, please refer to the "acc" module
 *
 * Developer Notes:
 *		- circular module dependencies are possible and not detected!
 *		- it is up to the module writers to prevent such side effects
 */

#include <stdarg.h>

#include "str.h"

#define MAX_MOD_DEPS 10
typedef struct param_export_ param_export_t;

/* core + module level structures */
enum module_type {
	MOD_TYPE_NULL, /* for iteration purposes */
	MOD_TYPE_DEFAULT,
	MOD_TYPE_SQLDB,
	MOD_TYPE_CACHEDB,
	MOD_TYPE_AAA,
};

/* behaviour at startup if the dependency is not met */
enum dep_type {
	DEP_SILENT, /* load re-ordering only if possible */
	DEP_WARN,   /* load re-ordering, and a warning if module not found */
	DEP_ABORT,  /* load re-ordering, and shut down if module not found */
};

typedef struct module_dependency {
	enum module_type mod_type;
	char *mod_name; /* as found in "module_exports" */
	enum dep_type type;
} module_dependency_t;

typedef struct modparam_dependency {
	char *script_param; /* module parameter at script level */

	/* return value must be allocated in pkg memory! */
	struct module_dependency *(*get_deps_f)(param_export_t *param);
} modparam_dependency_t;


/* helps to avoid duplicate code when writing "get_deps_f" functions */
module_dependency_t *alloc_module_dep(enum module_type mod_type, char *mod_name,
									  enum dep_type dep_type);


/* same as above, but with VLA, (3 * N + 1) arguments
 * and _must_ end with the special MOD_TYPE_NULL value */
module_dependency_t *_alloc_module_dep(enum module_type mod_type, char *mod_name,
                             enum dep_type dep_type, ... /* , MOD_TYPE_NULL */);


/* commonly used modparam dependency functions */

/**
 * get_deps_sqldb_url - commonly used by modules which use SQL DB URLs
 *
 * Behaviour:
 *	- imposes a generic MOD_TYPE_SQLDB dependency only when the URL is set
 *	  (strlen(url) > 0)
 */
module_dependency_t *get_deps_sqldb_url(param_export_t *param);
module_dependency_t *get_deps_cachedb_url(param_export_t *param);

/* core level structures and functions */
struct sr_module_dep {
	struct sr_module *mod;
	char *script_param;
	enum module_type mod_type;
	enum dep_type type;
	str dep;

	struct sr_module_dep *next;
};

int add_modparam_dependencies(struct sr_module *mod, param_export_t *param);
int add_module_dependencies(struct sr_module *mod);

int solve_module_dependencies(struct sr_module *modules);
void free_module_dependencies(struct sr_module *modules);

#endif
