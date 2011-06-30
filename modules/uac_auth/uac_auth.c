/*
 * $Id$
 *
 * uac_auth module
 *
 * Copyright (C) 2011 VoIP Embedded Inc.
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
 * --------
 *  2011-05-13  initial version (Ovidiu Sas)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../../sr_module.h"
#include "uac_auth.h"


/** Functions declarations */
static int mod_init(void);
static void mod_destroy(void);
static int child_init(int rank);
int uac_auth_bind(uac_auth_api_t* api);
int add_credential( unsigned int type, void *val);
void destroy_credentials(void);

/** Exported functions */
static cmd_export_t cmds[]=
{
	{"load_uac_auth", (cmd_function)uac_auth_bind, 1,  0,  0,  0},
	{0,0,0,0,0,0}
};

/** Exported parameters */
static param_export_t params[]= {
	{"credential",	STR_PARAM|USE_FUNC_PARAM,	(void*)&add_credential	},
	{0,0,0}
};

/** MI commands */
static mi_export_t mi_cmds[] = {
	{0,0,0,0,0}
};

/** Module interface */
struct module_exports exports= {
        "uac_auth",			/* module name */
        MODULE_VERSION,			/* module version */
        DEFAULT_DLFLAGS,		/* dlopen flags */
        cmds,				/* exported functions */
        params,				/* exported parameters */
        NULL,				/* exported statistics */
        mi_cmds,			/* exported MI functions */
        NULL,				/* exported pseudo-variables */
        0,				/* extra processes */
        mod_init,			/* module initialization function */
        (response_function) NULL,	/* response handling function */
        (destroy_function) mod_destroy,	/* destroy function */
        child_init			/* per-child init function */
};

/** Module init function */
static int mod_init(void)
{
	LM_DBG("start\n");

	return 0;
}

static void mod_destroy(void)
{
	destroy_credentials();
	LM_DBG("done\n");
	return;
}

static int child_init(int rank){return 0;}

int uac_auth_bind(uac_auth_api_t *api)
{
	if (!api){
		LM_ERR("Invalid parameter value\n");
		return -1;
	}

	api->_do_uac_auth = do_uac_auth;
	api->_build_authorization_hdr = build_authorization_hdr;
	api->_lookup_realm = lookup_realm;

	return 0;
}

