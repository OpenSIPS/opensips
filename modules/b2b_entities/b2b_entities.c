/*
 * $Id: b2b_entities.c $
 *
 * back-to-back entities module
 *
 * Copyright (C) 2009 Free Software Fundation
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
 *  2009-08-03  initial version (Anca Vamanu)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../ut.h"
#include "../../script_cb.h"
#include "../../parser/parse_from.h"
#include "../presence/hash.h"
#include "../dialog/dlg_load.h"

#include "b2b_entities.h"
#include "server.h"
#include "dlg.h"


/** Functions declarations */
static int mod_init(void);
static void mod_destroy(void);
static int child_init(int rank);
int b2b_bind(b2b_api_t* api);

/** Global variables */
unsigned int server_hsize = 9;
unsigned int client_hsize = 9;
str server_address = {0, 0};
struct sip_uri srv_addr_uri;
static char* script_req_route = NULL;
static char* script_reply_route = NULL;
int req_routeid  = -1;
int reply_routeid = -1;


/* TM bind */
struct tm_binds tmb;

/** Exported functions */
static cmd_export_t cmds[]=
{
	{"load_b2b",  (cmd_function)b2b_load_api,    1,  0,  0,  0},
	{ 0,               0,                        0,  0,  0,  0}
};

/** Exported parameters */
static param_export_t params[]={
	{ "server_address",        STR_PARAM,    &server_address.s   },
	{ "server_hsize",          INT_PARAM,    &server_hsize       },
	{ "client_hsize",          INT_PARAM,    &client_hsize       },
	{ "script_req_route",      STR_PARAM,    &script_req_route   },
	{ "script_reply_route",    STR_PARAM,    &script_reply_route  },
	{ 0,                       0,            0                   }
};

/** Module interface */
struct module_exports exports= {
	"b2b_entities",                 /* module name */
	MODULE_VERSION,					/* module version */
	DEFAULT_DLFLAGS,                /* dlopen flags */
	cmds,                           /* exported functions */
	params,                         /* exported parameters */
	0,                              /* exported statistics */
	0,                              /* exported MI functions */
	0,                              /* exported pseudo-variables */
	0,                              /* extra processes */
	mod_init,                       /* module initialization function */
	(response_function) 0,          /* response handling function */
	(destroy_function) mod_destroy, /* destroy function */
	child_init                      /* per-child init function */
};

/** Module initialize function */
static int mod_init(void)
{
	/* inspect the parameters */
	if(server_hsize< 1 || server_hsize> 20 ||
			client_hsize< 1 || client_hsize> 20)
	{
		LM_ERR("Wrong hash size. Needs to be greater than 1"
				" and smaller than 20. Be aware that you should set the log 2"
				" value of the real size\n");
		return -1;
	}
	server_hsize = 1<<server_hsize;
	client_hsize = 1<<client_hsize;

	if(server_address.s == NULL)
	{
		LM_ERR("'server_address parameter not set. This parameter is compulsory"
				" and must be set to the IP address of the server running b2b\n");
		return -1;
	}
	server_address.len = strlen(server_address.s);
	if(parse_uri(server_address.s, server_address.len, &srv_addr_uri) < 0)
	{
		LM_ERR("Bad format for server address - not a SIP URI\n");
		return -1;
	}
	/* load all TM stuff */
	if(load_tm_api(&tmb)==-1)
	{
		LM_ERR("can't load tm functions\n");
		return -1;
	}

	/* initialize the hash tables; they will be allocated in shared memory 
	 * to be accesible by all processes */
	if(init_b2b_htables()< 0)
	{
		LM_ERR("Failed to initialize b2b table\n");
		return -1;
	}

	if(register_script_cb( b2b_prescript_f, PRE_SCRIPT_CB|REQ_TYPE_CB, 0 ) < 0)
	{
		LM_ERR("Failed to register prescript function\n");
		return -1;
	}

	if (script_req_route)
	{
		req_routeid = get_script_route_ID_by_name( script_req_route, rlist, RT_NO);
		if (req_routeid < 1)
		{
			LM_ERR("route <%s> does not exist\n",script_req_route);
			return -1;
		}
	}

	if (script_reply_route)
	{
		reply_routeid = get_script_route_ID_by_name( script_reply_route, rlist, RT_NO);
		if (reply_routeid < 1)
		{
			LM_ERR("route <%s> does not exist\n",script_reply_route);
			return -1;
		}
	}

	return 0;
}


/** Module child initialize function */
static int child_init(int rank)
{
	return 0;
}
/** Module destroy function */
static void mod_destroy(void)
{
//	destroy_b2b_htables();
}

int b2b_load_api(b2b_api_t* api)
{
	if (!api)
	{
		LM_ERR("Invalid parameter value\n");
		return -1;
	}

	api->server_new = server_new;
	api->client_new = client_new;

	api->send_request = b2b_send_request;
	api->send_reply = b2b_send_reply;

	api->entity_delete =  b2b_entity_delete;

	return 0;
}


