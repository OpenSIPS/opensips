/*
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
 * 2009-02-07 Initial version of closeddial module (saguti)
 */


#include <stdio.h>
#include <string.h>
#include "../../sr_module.h"
#include "../../db/db.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../mem/mem.h"
#include "../../mod_fix.h"

#include "cdlookup.h"



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
str group_id_column  = str_init("group_id");
str cd_user_column   = str_init("cd_username");
str cd_domain_column = str_init("cd_domain");
str new_uri_column   = str_init("new_uri");
int use_domain       = 0;

db_func_t db_functions;      /* Database functions */
db_con_t* db_connection=NULL;   /* Database connection handle */

/* Exported functions */
static cmd_export_t cmds[] = {
	{"cd_lookup", (cmd_function)cd_lookup, 1, fixup_spve_null, 0,
		REQUEST_ROUTE},
	{"cd_lookup", (cmd_function)cd_lookup, 2, fixup_spve_spve, 0,
		REQUEST_ROUTE},
	{0, 0, 0, 0, 0, 0}

};


/* Exported parameters */
static param_export_t params[] = {
	{"db_url",           STR_PARAM, &db_url.s             },
	{"user_column",      STR_PARAM, &user_column.s        },
	{"domain_column",    STR_PARAM, &domain_column.s      },
	{"cd_user_column",   STR_PARAM, &cd_user_column.s     },
	{"cd_domain_column", STR_PARAM, &cd_domain_column.s   },
	{"group_id_column",  STR_PARAM, &group_id_column.s   },
	{"new_uri_column",   STR_PARAM, &new_uri_column.s     },
	{"use_domain",       INT_PARAM, &use_domain           },
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
	"closeddial",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,  /* module version */
	DEFAULT_DLFLAGS, /* dlopen flags */
	&deps,           /* OpenSIPS module dependencies */
	cmds,       /* Exported functions */
	0,          /* Exported async functions */
	params,     /* Exported parameters */
	0,          /* exported statistics */
	0,          /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,          /* extra processes */
	mod_init,   /* module initialization function */
	0,          /* response function */
	destroy,    /* destroy function */
	child_init  /* child initialization function */
};


/**
 *
 */
static int child_init(int rank)
{
	db_connection = db_functions.init(&db_url);
	if (db_connection == NULL) {
		LM_ERR("Failed to connect database\n");
		return -1;
	}
	return 0;
}


/**
 *
 */
static int mod_init(void)
{
	LM_DBG("Initializing\n");

	init_db_url( db_url , 0 /*cannot be null*/);
	user_column.len = strlen(user_column.s);
	domain_column.len = strlen(domain_column.s);
	cd_user_column.len = strlen(cd_user_column.s);
	cd_domain_column.len  = strlen(cd_domain_column.s);
	group_id_column.len = strlen(group_id_column.s);
	new_uri_column.len = strlen(new_uri_column.s);

	/* Find a database module */
	if (db_bind_mod(&db_url, &db_functions) == -1) {
		LM_ERR("Failed to bind database module\n");
		return -1;
	}

	if (!DB_CAPABILITY(db_functions, DB_CAP_QUERY)) {
		LM_ERR("Database modules does not "
			"provide all functions needed by closeddial module.\n");
		return -1;
	}

	return 0;
}


/**
 *
 */
static void destroy(void)
{
	if (db_connection != NULL) {
		db_functions.close(db_connection);
	}
}
