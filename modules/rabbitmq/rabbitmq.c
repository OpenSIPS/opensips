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

static int fixup_check_avp(void** param);
static int rmq_publish(struct sip_msg *msg, struct rmq_server *srv, str *srkey,
			str *sbody, str *sctype, pv_spec_t *hnames, pv_spec_t *hvals);

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
	{"rabbitmq_publish",(cmd_function)rmq_publish, {
		{CMD_PARAM_STR, fixup_rmq_server, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, fixup_check_avp, 0},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, fixup_check_avp, 0}, {0,0,0}},
		ALL_ROUTES},
	{0,0,{{0,0,0}},0}
};

/* module exports */
struct module_exports exports= {
	"rabbitmq",						/* module name */
	MOD_TYPE_DEFAULT,				/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,				/* dlopen flags */
	0,								/* load function */
	&deps,						    /* OpenSIPS module dependencies */
	cmds,							/* exported functions */
	0,								/* exported async functions */
	params,							/* exported parameters */
	0,								/* exported statistics */
	0,								/* exported MI functions */
	0,								/* exported pseudo-variables */
	0,								/* exported transformations */
	0,								/* extra processes */
	0,								/* module pre-initialization function */
	mod_init,						/* module initialization function */
	(response_function) 0,			/* response handling function */
	(destroy_function)mod_destroy,	/* destroy function */
	child_init,						/* per-child init function */
	0								/* reload confirm function */
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

static int fixup_check_avp(void** param)
{
	if (((pv_spec_t *)*param)->type!=PVT_AVP) {
		LM_ERR("return parameter must be an AVP\n");
		return E_SCRIPT;
	}

	return 0;
}

/*
 * function that simply prints the parameters passed
 */
static int rmq_publish(struct sip_msg *msg, struct rmq_server *srv, str *srkey,
			str *sbody, str *sctype, pv_spec_t *hnames, pv_spec_t *hvals)
{
	int aname, avals;
	unsigned short type;

	if (hnames && !hvals) {
		LM_ERR("header names without values!\n");
		return -1;
	}
	if (!hnames && hvals) {
		LM_ERR("header values without names!\n");
		return -1;
	}

	if (hnames &&
			pv_get_avp_name(msg, &hnames->pvp, &aname, &type) < 0) {
		LM_ERR("cannot resolve names AVP\n");
		return -1;
	}

	if (hvals &&
			pv_get_avp_name(msg, &hvals->pvp, &avals, &type) < 0) {
		LM_ERR("cannot resolve values AVP\n");
		return -1;
	}

	/* resolve the AVP */
	return rmq_send(srv, srkey, sbody, sctype,
			(hnames ? &aname : NULL),
			(hvals ? &avals : NULL)) == 0 ? 1: -1;
}
