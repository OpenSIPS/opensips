/*
 * pua_mi module - MI pua module
 *
 * Copyright (C) 2006 Voice Sistem S.R.L.
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
 *  2006-11-29  initial version (Anca Vamanu)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libxml/parser.h>
#include <time.h>

#include "../../sr_module.h"
#include "../../parser/parse_expires.h"
#include "../../dprint.h"
#include "../../mem/shm_mem.h"
#include "../../parser/msg_parser.h"
#include "../../str.h"
#include "../../mem/mem.h"
#include "../../pt.h"
#include "../tm/tm_load.h"
#include "../pua/pua_bind.h"
#include "mi_func.h"



pua_api_t pua;

/** module functions */

static int mod_init(void);
static int child_init(int);
static void destroy(void);

send_publish_t pua_send_publish;
send_subscribe_t pua_send_subscribe;
str presence_server= {0, 0};

/*
 * Exported MI functions
 */
static mi_export_t mi_cmds[] = {
	{ "pua_publish",	0, mi_pua_publish,     MI_ASYNC_RPL_FLAG,  0,  0},
	{ "pua_subscribe",	0, mi_pua_subscribe,   0,				     0,  0},
	{ 0,				0, 0,					 0,					 0,  0}
};

/*
 * Exported parameters
 */
static param_export_t params[]={
	{"presence_server",	 STR_PARAM, &presence_server.s	},
	{0,							 0,			0			}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "pua", DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

/** module exports */
struct module_exports exports= {
	"pua_mi",					/* module name */
	MOD_TYPE_DEFAULT,           /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,            /* dlopen flags */
	&deps,                      /* OpenSIPS module dependencies */
	 0,							/* exported functions */
	 0,							/* exported async functions */
	 params,					/* exported parameters */
	 0,							/* exported statistics */
	 mi_cmds,					/* exported MI functions */
	 0,							/* exported pseudo-variables */
	 0,							/* exported transformations */
	 0,							/* extra processes */
	 mod_init,					/* module initialization function */
	 (response_function) 0,		/* response handling function */
 	 destroy,					/* destroy function */
	 child_init                 /* per-child init function */
};

/**
 * init module function
 */
static int mod_init(void)
{
	bind_pua_t bind_pua;

	if(presence_server.s)
		presence_server.len = strlen(presence_server.s);

	bind_pua= (bind_pua_t)find_export("bind_pua", 1,0);
	if (!bind_pua)
	{
		LM_ERR("Can't bind pua (check if pua module is loaded)\n");
		return -1;
	}

	if (bind_pua(&pua) < 0)
	{
		LM_ERR("Can't bind pua\n");
		return -1;
	}
	if(pua.send_publish == NULL)
	{
		LM_ERR("Could not import send_publish\n");
		return -1;
	}
	pua_send_publish= pua.send_publish;

	if(pua.send_subscribe == NULL)
	{
		LM_ERR("Could not import send_subscribe\n");
		return -1;
	}
	pua_send_subscribe= pua.send_subscribe;

	if(pua.register_puacb(MI_ASYN_PUBLISH, mi_publ_rpl_cback, NULL)< 0)
	{
		LM_ERR("Could not register callback\n");
		return -1;
	}

	return 0;
}

static int child_init(int rank)
{
	LM_DBG("child [%d]  pid [%d]\n", rank, getpid());
	return 0;
}

static void destroy(void)
{
	LM_DBG("destroying module ...\n");

	return ;
}



