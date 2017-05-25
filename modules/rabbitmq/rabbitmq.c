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

static int fixup_rmq(void **param, int param_no);
static int rmq_publish(struct sip_msg *msg, char *siv, char *rkey, char *body,
		char *ctype, char *hnames, char *hvals);

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
	{"rabbitmq_publish",(cmd_function)rmq_publish, 3,
		fixup_rmq, 0, ALL_ROUTES },
	{"rabbitmq_publish",(cmd_function)rmq_publish, 4,
		fixup_rmq, 0, ALL_ROUTES },
	{"rabbitmq_publish",(cmd_function)rmq_publish, 6,
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
	0,								/* exported transformations */
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
	str name;
	pv_spec_t *e;

	if (param_no == 1)
		return fixup_rmq_server(param);
	/* TODO: check if this is needed */
	if (param_no < 5)
		return fixup_spve(param);
	if (param_no < 7) {
		name.s = (char *)*param;
		name.len = strlen(name.s);
		e = pkg_malloc(sizeof *e);
		if (!e) {
			LM_ERR("out of mem!\n");
			return E_OUT_OF_MEM;
		}
		if (pv_parse_spec(&name, e) == 0) {
			LM_ERR("invalid spec %s\n", name.s);
			return E_SCRIPT;
		}
		if (e->type != PVT_AVP) {
			LM_ERR("invalid pvar type %s - only AVPs are allowed!\n", name.s);
			return E_SCRIPT;
		}
		*param = (void *)e;
		return 0;
	}
	LM_ERR("Unsupported parameter %d\n", param_no);
	return E_CFG;
}

/*
 * function that simply prints the parameters passed
 */
static int rmq_publish(struct sip_msg *msg, char *sid, char *rkey, char *body,
		char *ctype, char *hnames, char *hvals)
{
	struct rmq_server *srv;
	str srkey, sbody, sctype;
	int aname, avals;
	unsigned short type;
	
	srv = rmq_resolve_server(msg, sid);
	if (!srv) {
		LM_ERR("cannot find a RabbitMQ server connection\n");
		return -1;
	}

	if (fixup_get_svalue(msg, (gparam_p)rkey, &srkey) < 0) {
		LM_ERR("cannot get routing key!\n");
		return -1;
	}

	if (fixup_get_svalue(msg, (gparam_p)body, &sbody) < 0) {
		LM_ERR("cannot get body value!\n");
		return -1;
	}

	if (ctype && fixup_get_svalue(msg, (gparam_p)ctype, &sctype) < 0) {
		LM_ERR("cannot get content-type value\n");
		return -1;
	}

	if (hnames && !hvals) {
		LM_ERR("header names without values!\n");
		return -1;
	}
	if (!hnames && hvals) {
		LM_ERR("header values without names!\n");
		return -1;
	}

	if (hnames &&
			pv_get_avp_name(msg, &((pv_spec_p)hnames)->pvp, &aname, &type) < 0) {
		LM_ERR("cannot resolve names AVP\n");
		return -1;
	}

	if (hvals &&
			pv_get_avp_name(msg, &((pv_spec_p)hvals)->pvp, &avals, &type) < 0) {
		LM_ERR("cannot resolve values AVP\n");
		return -1;
	}

	/* resolve the AVP */
	return rmq_send(srv, &srkey, &sbody,
			(ctype ? &sctype : NULL),
			(hnames ? &aname : NULL),
			(hvals ? &avals : NULL)) == 0 ? 1: -1;
}
