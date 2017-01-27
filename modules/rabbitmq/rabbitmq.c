/*
 * Copyright (C) 2017 OpenSIPS Project
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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
 *
 * History:
 * ---------
 *  2017-01-24  created (razvanc)
 */

#include "../../mem/shm_mem.h"
#include "../../sr_module.h"
#include "../../db/db_id.h"
#include "../../lib/list.h"
#include "../../mod_fix.h"
#include "../../dprint.h"
#include "../../ut.h"

#include "rmq_servers.h"

static int mod_init(void);
static int child_init(int);
static void mod_destroy(void);

static int rmq_publish(struct sip_msg *msg, char *cid);
static int fixup_rmq(void **param, int param_no);

static param_export_t params[]={
	{ "server_id",			STR_PARAM|USE_FUNC_PARAM,
		(void *)rmq_server_add},
	{0,0,0}
};

/* modules dependencies */
static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

/* exported commands */
static cmd_export_t cmds[] = {
	{"rabbitmq_publish",(cmd_function)rmq_publish, 1,
		fixup_rmq, 0, ALL_ROUTES },
	{0, 0, 0, 0, 0, 0}
};

/* module exports */
struct module_exports exports= {
	"rabbitmq",						/* module name */
	MOD_TYPE_DEFAULT,				/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,				/* dlopen flags */
	&deps,						    /* OpenSIPS module dependencies */
	cmds,							/* exported functions */
	0,								/* exported async functions */
	params,							/* exported parameters */
	0,								/* exported statistics */
	0,								/* exported MI functions */
	0,								/* exported pseudo-variables */
	0,								/* extra processes */
	mod_init,						/* module initialization function */
	(response_function) 0,			/* response handling function */
	(destroy_function)mod_destroy,	/* destroy function */
	child_init						/* per-child init function */
};

/**
 * init module function
 */
static int mod_init(void)
{
	LM_NOTICE("initializing RabbitMQ module ...\n");
	return 0;
}

/*
 * function called when a child process starts
 */
static int child_init(int rank)
{
	rmq_connect_servers();
	return 0;
}

/*
 * function called after OpenSIPS has been stopped to cleanup resources
 */
static void mod_destroy(void)
{
	LM_NOTICE("destroying RabbitMQ module ...\n");
}

/*
 * fixup function
 */
static int fixup_rmq(void **param, int param_no)
{
	if (param_no == 1)
		return fixup_rmq_server(param);
	/* TODO: check if this is needed */
	if (param_no < 2)
		return fixup_sgp(param);
	LM_ERR("Unsupported parameter %d\n", param_no);
	return E_CFG;
}

/*
 * function that simply prints the parameters passed
 */
static int rmq_publish(struct sip_msg *msg, char *cid)
{
	struct rmq_server *srv;
	
	srv = rmq_resolve_server(msg, cid);
	if (!srv) {
		LM_ERR("cannot find a RabbitMQ server connection\n");
		return -1;
	}
	return -1;
}

