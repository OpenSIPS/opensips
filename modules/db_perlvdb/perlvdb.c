/*
 * Perl virtual database module
 *
 * Copyright (C) 2007 Collax GmbH
 *                    (Bastian Friedrich <bastian.friedrich@collax.com>)
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
 */

#include "../../sr_module.h"
#include "perlvdb.h"



static int child_init(int rank);

static int mod_init(void);

static void mod_destroy(void);

SV* vdbmod;

/*
 * Perl virtual database module interface
 */
static cmd_export_t cmds[] = {
	{"db_use_table",	(cmd_function)perlvdb_use_table, {{0,0,0}},0},
	{"db_init",			(cmd_function)perlvdb_db_init, {{0,0,0}},0},
	{"db_close",		(cmd_function)perlvdb_db_close, {{0,0,0}},0},
	{"db_insert",		(cmd_function)perlvdb_db_insert, {{0,0,0}},0},
	{"db_update",		(cmd_function)perlvdb_db_update, {{0,0,0}},0},
	{"db_delete",		(cmd_function)perlvdb_db_delete, {{0,0,0}},0},
	{"db_query",		(cmd_function)perlvdb_db_query, {{0,0,0}},0},
	{"db_free_result",	(cmd_function)perlvdb_db_free_result, {{0,0,0}},0},
	{0,0,{{0,0,0}},0}
};

/*
 * Exported parameters
 */
static param_export_t params[] = {
	{0, 0, 0}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "perl", DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

struct module_exports exports = {
	"db_perlvdb",
	MOD_TYPE_SQLDB,/* class of this module */
	MODULE_VERSION,
	RTLD_NOW | RTLD_GLOBAL, /* dlopen flags */
	0,           /* load function */
	&deps,       /* OpenSIPS module dependencies */
	cmds,
	0,
	params,      /*  module parameters */
	0,           /* exported statistics */
	0,           /* exported MI functions */
	0,           /* exported pseudo-variables */
	0,			 /* exported transformations */
	0,           /* extra processes */
	0,           /* module pre-initialization function */
	mod_init,    /* module initialization function */
	0,           /* response function*/
	mod_destroy, /* destroy function */
	child_init,  /* per-child init function */
	0            /* reload confirm function */
};


static int mod_init(void)
{
	if (!module_loaded("perl")) {
		LM_CRIT("perl module not loaded. Exiting.\n");
		return -1;
	}

	return 0;
}


static void mod_destroy(void)
{
}


static int child_init(int rank)
{
	return 0;
}
