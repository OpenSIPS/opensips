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

#ifndef SR_MODULE_DEPS_H
#define SR_MODULE_DEPS_H

/*
 * Description:
 *
 * - the core module dependencies code aids in arranging the OpenSIPS module
 *   initialization and destruction order, so the dependencies of each
 *   module are satisfied
 *
 * - a module may specify dependencies in two ways:
 *   * module -> module (if X -> Y, initialize Y before X, destroy X before Y)
 *   * modparam -> module (if a parameter of module X has a certain value,
 *                  ensure module Y initializes first and destroys last)
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
 * when an init dependency is not satisfied (e.g. depending module not loaded),
 * OpenSIPS may throw a warning, abort or not do anything at all
 *
 * For a complete usage example, refer to the "acc" and "dialog" modules
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
#define DEP_SILENT	(1 << 0) /* re-order init & destroy if possible */
#define DEP_WARN	(1 << 1) /* re-order init & destroy; warn if dep n/f */
#define DEP_ABORT	(1 << 2) /* re-order init & destroy; exit if dep n/f */
/* in some cases, the dependency direction will be reversed */
#define DEP_REVERSE_MINIT   (1 << 3) /* if A->B, A.mod_init() before B.mod_init() */
#define DEP_REVERSE_DESTROY (1 << 4) /* if A->B, B destroys before A */
#define DEP_REVERSE_CINIT   (1 << 5) /* if A->B, A.child_init() before B.child_init() */

#define DEP_REVERSE_INIT (DEP_REVERSE_MINIT|DEP_REVERSE_CINIT)
#define DEP_REVERSE      (DEP_REVERSE_INIT|DEP_REVERSE_DESTROY)

typedef struct module_dependency {
	enum module_type mod_type;
	char *mod_name;    /* as found in "module_exports" */
	unsigned int type; /* per the DEP_* flags */
} module_dependency_t;

typedef struct modparam_dependency {
	char *script_param; /* module parameter at script level */

	/* return value must be allocated in pkg memory! */
	struct module_dependency *(*get_deps_f)(const param_export_t *param);
} modparam_dependency_t;


/* helps to avoid duplicate code when writing "get_deps_f" functions */
module_dependency_t *alloc_module_dep(enum module_type mod_type, char *mod_name,
									  unsigned int dep_type);


/* same as above, but with VLA, (3 * N + 1) arguments
 * and _must_ end with the special MOD_TYPE_NULL value */
module_dependency_t *_alloc_module_dep(enum module_type mod_type, char *mod_name,
                             unsigned int dep_type, ... /* , MOD_TYPE_NULL */);


/* commonly used modparam dependency functions */

/**
 * get_deps_sqldb_url - commonly used by modules which use SQL DB URLs
 *
 * Behaviour:
 *	- imposes a generic MOD_TYPE_SQLDB dependency only when the URL is set
 *	  (strlen(url) > 0)
 */
module_dependency_t *get_deps_sqldb_url(const param_export_t *param);
module_dependency_t *get_deps_cachedb_url(const param_export_t *param);

/* core level structures and functions */
struct sr_module_dep {
	struct sr_module *mod;
	const char *script_param;
	enum module_type mod_type;
	unsigned int type;
	str dep;

	struct sr_module_dep *next;
};

int add_modparam_dependencies(struct sr_module *mod, const param_export_t *param);
int add_module_dependencies(struct sr_module *mod);

int solve_module_dependencies(struct sr_module *modules);
void free_module_dependencies(struct sr_module *modules);

#endif
