/*
 * Copyright (C) 2004-2006 Voice Sistem SRL
 *
 * This file is part of Open SIP Server (opensips).
 *
 * opensips is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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
 * History:
 * ---------
 *
 */


#include <stdio.h>
#include <string.h>
#include "../../sr_module.h"
#include "../../db/db.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../mem/mem.h"
#include "../../mod_fix.h"

#include "sdlookup.h"




/* Module destroy function prototype */
static void destroy(void);


/* Module child-init function prototype */
static int child_init(int rank);


/* Module initialization function prototype */
static int mod_init(void);

/* Module parameter variables */
static str db_url    = {NULL,0};
str user_column      = str_init("username");
str domain_column    = str_init("domain");
str sd_user_column   = str_init("sd_username");
str sd_domain_column = str_init("sd_domain");
str new_uri_column   = str_init("new_uri");
int use_domain       = 0;
static str domain_prefix    = {NULL, 0};

str dstrip_s = {NULL, 0};


db_func_t db_funcs;      /* Database functions */
db_con_t* db_handle=0;   /* Database connection handle */


/* Exported functions */
// static cmd_export_t cmds[] = {
// 	{"sd_lookup", (cmd_function)sd_lookup, 1, fixup_spve_null, 0,
// 		REQUEST_ROUTE},
// 	{"sd_lookup", (cmd_function)sd_lookup, 2, fixup_spve_spve, 0,
// 		REQUEST_ROUTE},
// 	{0, 0, 0, 0, 0, 0}
// };

static cmd_export_t cmds[] = {
	{"sd_lookup", (cmd_function)sd_lookup, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, {0,0,0}},
		REQUEST_ROUTE},
};

/* Exported parameters */
static param_export_t params[] = {
	{"db_url",           STR_PARAM, &db_url.s             },
	{"user_column",      STR_PARAM, &user_column.s        },
	{"domain_column",    STR_PARAM, &domain_column.s      },
	{"sd_user_column",   STR_PARAM, &sd_user_column.s     },
	{"sd_domain_column", STR_PARAM, &sd_domain_column.s   },
	{"new_uri_column",   STR_PARAM, &new_uri_column.s     },
	{"use_domain",       INT_PARAM, &use_domain           },
	{"domain_prefix",    STR_PARAM, &domain_prefix.s      },
	{0, 0, 0}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_SQLDB, NULL, DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

/* Module interface */
struct module_exports exports = {
	"speeddial",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	&deps,           /* OpenSIPS module dependencies */
	cmds,       /* Exported functions */
	NULL,       /* Exported async functions */
	params,     /* Exported parameters */
	0,          /* exported statistics */
	0,          /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,			/* exported transformations */
	0,          /* extra processes */
	0,          /* module pre-initialization function */
	mod_init,   /* module initialization function */
	0,          /* response function */
	destroy,    /* destroy function */
	child_init, /* child initialization function */
	0           /* reload confirm function */
};


/**
 *
 */
static int child_init(int rank)
{
	db_handle = db_funcs.init(&db_url);
	if (!db_handle)
	{
		LM_ERR("failed to connect database\n");
		return -1;
	}
	return 0;

}


/**
 *
 */
static int mod_init(void)
{
	LM_DBG("initializing\n");

	init_db_url( db_url , 0 /*cannot be null*/);
	user_column.len = strlen(user_column.s);
	domain_column.len = strlen(domain_column.s);
	sd_user_column.len = strlen(sd_user_column.s);
	sd_domain_column.len  = strlen(sd_domain_column.s);
	new_uri_column.len = strlen(new_uri_column.s);
	if (domain_prefix.s)
		domain_prefix.len = strlen(domain_prefix.s);

    /* Find a database module */
	if (db_bind_mod(&db_url, &db_funcs))
	{
		LM_ERR("failed to bind database module\n");
		return -1;
	}
	if (!DB_CAPABILITY(db_funcs, DB_CAP_QUERY))
	{
		LM_ERR("Database modules does not "
			"provide all functions needed by SPEEDDIAL module\n");
		return -1;
	}
	if (domain_prefix.s && domain_prefix.len > 0) {
		dstrip_s.s = domain_prefix.s;
		dstrip_s.len = domain_prefix.len;
	}

	return 0;
}


/**
 *
 */
static void destroy(void)
{
}

