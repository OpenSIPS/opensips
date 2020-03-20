/*
 * Domain Policy related functions
 *
 * Copyright (C) 2006 Otmar Lendl & Klaus Darilion
 *
 * Based on the ENUM and domain module.
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
 *  2006-04-20  Initial Version
 *  2006-09-08  Updated to -02 version, added support for D2P+SIP:std
 */


#include <stdio.h>
#include "../../sr_module.h"
#include "domainpolicy_mod.h"
#include "../../mem/shm_mem.h"
#include "../../ut.h"
#include "domainpolicy.h"

/*
 * Module management function prototypes
 */
static int mod_init(void);
static void destroy(void);
static int child_init(int rank);



/*
 * Version of gw and lcr tables required by the module,
 * increment this value if you change the table in
 * an backwards incompatible way
 */
#define DOMAINPOLICY_TABLE_VERSION 3


#define DOMAINPOLICY_TABLE "domainpolicy"
#define DOMAINPOLICY_COL_RULE "rule"
#define DOMAINPOLICY_COL_TYPE "type"
#define DOMAINPOLICY_COL_ATT "att"
#define DOMAINPOLICY_COL_VAL "val"

/* Default avp names */
#define DEF_PORT_OVERRIDE_AVP         "portoverride"
#define DEF_TRANSPORT_OVERRIDE_AVP    "transportoverride"
#define DEF_DOMAIN_PREFIX_AVP         "domainprefix"
#define DEF_DOMAIN_SUFFIX_AVP         "domainsuffix"
#define DEF_DOMAIN_REPLACEMENT_AVP    "domainreplacement"
#define DEF_SEND_SOCKET_AVP           "sendsocket"

/*
 * Module parameter variables
 */
static str db_url         = {NULL, 0};
/* Name of domainpolicy table */
str domainpolicy_table    = str_init(DOMAINPOLICY_TABLE);

str domainpolicy_col_rule = str_init(DOMAINPOLICY_COL_RULE);
str domainpolicy_col_type = str_init(DOMAINPOLICY_COL_TYPE);
str domainpolicy_col_att  = str_init(DOMAINPOLICY_COL_ATT);
str domainpolicy_col_val  = str_init(DOMAINPOLICY_COL_VAL);

str port_override_avp         = str_init(DEF_PORT_OVERRIDE_AVP);
str transport_override_avp    = str_init(DEF_TRANSPORT_OVERRIDE_AVP);
str domain_prefix_avp         = str_init(DEF_DOMAIN_PREFIX_AVP);
str domain_suffix_avp         = str_init(DEF_DOMAIN_SUFFIX_AVP);
str domain_replacement_avp    = str_init(DEF_DOMAIN_REPLACEMENT_AVP);
str send_socket_avp           = str_init(DEF_SEND_SOCKET_AVP);

/*
 * Other module variables
 */

int port_override_name, transport_override_name, domain_prefix_name,
	domain_suffix_name, domain_replacement_name, send_socket_name;

/*
 * Exported functions
 */
static cmd_export_t cmds[] = {
	{"dp_can_connect",  (cmd_function)dp_can_connect, {{0,0,0}},
		REQUEST_ROUTE},
	{"dp_apply_policy", (cmd_function)dp_apply_policy, {{0,0,0}},
		REQUEST_ROUTE},
	{0,0,{{0,0,0}},0}
};

/*
 * Exported parameters
 */
static param_export_t params[] = {
	{"db_url",                    STR_PARAM, &db_url.s                   },
	{"dp_table",                  STR_PARAM, &domainpolicy_table.s       },
	{"dp_col_rule",               STR_PARAM, &domainpolicy_col_rule.s    },
	{"dp_col_type",               STR_PARAM, &domainpolicy_col_type.s    },
	{"dp_col_att",                STR_PARAM, &domainpolicy_col_att.s     },
	{"dp_col_val",                STR_PARAM, &domainpolicy_col_val.s     },
	{"port_override_avp",         STR_PARAM, &port_override_avp.s        },
	{"transport_override_avp",    STR_PARAM, &transport_override_avp.s   },
	{"domain_prefix_avp",         STR_PARAM, &domain_prefix_avp.s        },
	{"domain_suffix_avp",         STR_PARAM, &domain_suffix_avp.s        },
	{"domain_replacement_avp",    STR_PARAM, &domain_replacement_avp.s   },
	{"send_socket_avp",           STR_PARAM, &send_socket_avp.s          },
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

/*
 * Module interface
 */
struct module_exports exports = {
	"domainpolicy",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	&deps,           /* OpenSIPS module dependencies */
	cmds,      /* exported functions */
	0,         /* exported async functions */
	params,    /* exported parameters */
	0,         /* exported statistics */
	0,         /* exported MI functions */
	0,         /* exported pseudo-variables */
	0,		   /* exported transformations */
	0,         /* extra processes */
	0,         /* module pre-initialization function */
	mod_init,  /* module initialization function */
	0,         /* response function*/
	destroy,   /* destroy function */
	child_init,/* per-child init function */
	0          /* reload confirm function */
};


static int mod_init(void)
{
	int ver;

	LM_INFO("initializing...\n");

	init_db_url( db_url , 0 /*cannot be null*/);
	domainpolicy_table.len = strlen(domainpolicy_table.s);
	domainpolicy_col_rule.len = strlen(domainpolicy_col_rule.s);
	domainpolicy_col_type.len = strlen(domainpolicy_col_type.s);
	domainpolicy_col_att.len = strlen(domainpolicy_col_att.s);
	domainpolicy_col_val.len = strlen(domainpolicy_col_val.s);

	LM_INFO("check for DB module\n");

	/* Check if database module has been loaded */
	if (domainpolicy_db_bind(&db_url)<0)  {
		LM_ERR("no database module loaded!"
			" Please make sure that a DB module is loaded first\n");
		return -1;
	}

	LM_INFO("update length of module variables\n");
	/* Update length of module variables */
	port_override_avp.len         = strlen(port_override_avp.s);
	transport_override_avp.len    = strlen(transport_override_avp.s);
	domain_prefix_avp.len         = strlen(domain_prefix_avp.s);
	domain_suffix_avp.len         = strlen(domain_suffix_avp.s);
	domain_replacement_avp.len    = strlen(domain_replacement_avp.s);
	send_socket_avp.len           = strlen(send_socket_avp.s);

	/* Check table version */
	ver = domainpolicy_db_ver(&db_url, &domainpolicy_table);
	if (ver < 0) {
		LM_ERR("failed to query table version\n");
		return -1;
	} else if (ver < DOMAINPOLICY_TABLE_VERSION) {
		LM_ERR("invalid table version of domainpolicy table\n");
		return -1;
	}

	/* Assign AVP parameter names */
	LM_INFO("AVP\n");
	if (parse_avp_spec(&port_override_avp, &port_override_name) < 0) {
		LM_ERR("invalid port_override_avp!\n");
		return -1;
	}
	if (parse_avp_spec(&transport_override_avp, &transport_override_name) < 0) {
		LM_ERR("invalid transport_override_avp!\n");
		return -1;
	}
	if (parse_avp_spec(&domain_prefix_avp, &domain_prefix_name) < 0) {
		LM_ERR("invalid domain_prefix_avp!\n");
		return -1;
	}
	if (parse_avp_spec(&domain_suffix_avp, &domain_suffix_name) < 0) {
		LM_ERR("invalid domain_suffix_avp!\n");
		return -1;
	}
	if (parse_avp_spec(&domain_replacement_avp, &domain_replacement_name) < 0) {
		LM_ERR("invalid domain_replacement_avp!\n");
		return -1;
	}
	if (parse_avp_spec(&send_socket_avp, &send_socket_name) < 0) {
		LM_ERR("invalid send_socket_avp!\n");
		return -1;
	}

	return 0;
}


static int child_init(int rank)
{
	LM_DBG("initializing\n");

	if (domainpolicy_db_init(&db_url)<0) {
		LM_ERR("unable to connect to the database\n");
		return -1;
	}
	return 0;
}


static void destroy(void)
{
	/* Destroy is called from the main process only,
	 * there is no need to close database here because
	 * it is closed in mod_init already
	 */
}
