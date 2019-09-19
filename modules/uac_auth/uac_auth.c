/*
 * uac_auth module
 *
 * Copyright (C) 2011 VoIP Embedded Inc.
 * Copyright (C) 2013 OpenSIPS Solutions.
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
int uac_auth_bind(uac_auth_api_t* api);
int add_credential( unsigned int type, void *val);
void destroy_credentials(void);

/* local variable used for init */
static char* auth_username_avp = NULL;
static char* auth_realm_avp = NULL;
static char* auth_password_avp = NULL;

int            realm_avp_name = 0;
unsigned short realm_avp_type=0;
int            user_avp_name = 0;
unsigned short user_avp_type=0;
int            pwd_avp_name = 0;
unsigned short pwd_avp_type=0;


/** Exported functions */
static cmd_export_t cmds[] = {
	{"load_uac_auth", (cmd_function)uac_auth_bind, {{0,0,0}},0},
	{0,0,{{0,0,0}},0}
};

/** Exported parameters */
static param_export_t params[]= {
	{"credential",          STR_PARAM|USE_FUNC_PARAM, (void*)&add_credential },
	{"auth_username_avp",   STR_PARAM,                &auth_username_avp     },
	{"auth_realm_avp",      STR_PARAM,                &auth_realm_avp        },
	{"auth_password_avp",   STR_PARAM,                &auth_password_avp     },

	{0,0,0}
};

/** Module interface */
struct module_exports exports= {
	"uac_auth",			/* module name */
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,		/* module version */
	DEFAULT_DLFLAGS,	/* dlopen flags */
	0,					/* load function */
	NULL,				/* OpenSIPS module dependencies */
	cmds,				/* exported functions */
	0,					/* exported async functions */
	params,				/* exported parameters */
	NULL,				/* exported statistics */
	0,					/* exported MI functions */
	NULL,				/* exported pseudo-variables */
	0,					/* exported transformations */
	0,					/* extra processes */
	0,					/* module pre-initialization function */
	mod_init,			/* module initialization function */
	(response_function) NULL,	/* response handling function */
	(destroy_function) mod_destroy,	/* destroy function */
	NULL,				/* per-child init function */
	NULL				/* reload confirm function */
};



inline static int parse_auth_avp( char *avp_spec, pv_spec_t *avp, char *txt)
{
	str s;
	s.s = avp_spec; s.len = strlen(s.s);
	if (pv_parse_spec(&s, avp)==NULL) {
		LM_ERR("malformed or non AVP %s AVP definition\n",txt);
		return -1;
	}
	return 0;
}



/** Module init function */
static int mod_init(void)
{
	pv_spec_t user_spec;
	pv_spec_t realm_spec;
	pv_spec_t pwd_spec;

	LM_DBG("start\n");

	/* parse the auth AVP spesc, if any */
	if ( auth_username_avp || auth_password_avp || auth_realm_avp) {
		if (!auth_username_avp || !auth_password_avp || !auth_realm_avp) {
			LM_ERR("partial definition of auth AVP!\n");
			return -1;
		}
		if ( parse_auth_avp(auth_realm_avp, &realm_spec, "realm")<0
		|| parse_auth_avp(auth_username_avp, &user_spec, "username")<0
		|| parse_auth_avp(auth_password_avp, &pwd_spec, "password")<0
		|| pv_get_avp_name(0, &(realm_spec.pvp), &(realm_avp_name), &(realm_avp_type) )!=0
		|| pv_get_avp_name(0, &(user_spec.pvp), &(user_avp_name), &(user_avp_type) )!=0
		|| pv_get_avp_name(0, &(pwd_spec.pvp), &(pwd_avp_name), &(pwd_avp_type) )!=0
		) {
			LM_ERR("invalid AVP definition for AUTH avps\n");
			return -1;
		}
	}

	return 0;
}



static void mod_destroy(void)
{
	destroy_credentials();
	LM_DBG("done\n");
	return;
}



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

