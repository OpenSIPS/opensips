/*
 * Copyright (C) 2019 OpenSIPS Project
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
 */

#include "../../sr_module.h"
#include "../../dprint.h"

#include "rmq_connection.h"


static int mod_init(void);
static int child_init(int);
static void mod_destroy(void);

static param_export_t params[] = {
	{"connection_id", STR_PARAM|USE_FUNC_PARAM, (void *)rmq_conn_add},
	{"connect_timeout", INT_PARAM, &rmq_connect_timeout},
	{"retry_timeout", INT_PARAM, &rmq_retry_timeout},
	{0,0,0}
};

static proc_export_t procs[] = {
	{ "RabbitMQ Consumer", 0, 0, rmq_cons_process, 1,
		PROC_FLAG_HAS_IPC },
	{ 0, 0, 0, 0, 0, 0 },
};

/* module exports */
struct module_exports exports = {
	"rabbitmq_consumer",			/* module name */
	MOD_TYPE_DEFAULT,				/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,				/* dlopen flags */
	0,								/* load functionn */
	0,						        /* OpenSIPS module dependencies */
	0,							    /* exported functions */
	0,								/* exported async functions */
	params,							/* exported parameters */
	0,								/* exported statistics */
	0,								/* exported MI functions */
	0,								/* exported pseudo-variables */
	0,								/* exported transformations */
	procs,							/* extra processes */
	0,								/* module pre-initialization function */
	mod_init,						/* module initialization function */
	(response_function) 0,			/* response handling function */
	(destroy_function)mod_destroy,	/* destroy function */
	child_init,						/* per-child init function */
	0
};

static int mod_init(void)
{
	return 0;
}

static int child_init(int rank)
{
	return 0;
}

static void mod_destroy(void)
{
	return;
}
