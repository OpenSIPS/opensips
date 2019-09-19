/*
 * presence_callinfo module - Presence Handling of call-info events
 *
 * Copyright (C) 2010 Ovidiu Sas
 * Copyright (C) 2013 OpenSIPS Solutions
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
 *  2010-03-11  initial version (osas)
 *  2010-07-13  added support for SCA Broadsoft with dialog module (bogdan)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../str.h"
#include "../../mod_fix.h"
#include "../../parser/msg_parser.h"
#include "../../parser/parse_from.h"
#include "../../mem/mem.h"
#include "../presence/bind_presence.h"
#include "add_events.h"
#include "sca_hash.h"
#include "sca_dialog.h"


int call_info_timeout_notification = 1;
int line_seize_timeout_notification = 0;
int no_dialog_support = 0;
static int hash_size = 64;

/* external API's */
presence_api_t pres;

/* module functions */
static int mod_init(void);
static int child_init(int);
static void destroy(void);


int sca_set_calling_line(struct sip_msg *msg, str *line);
int sca_set_called_line(struct sip_msg *msg, str *line);


/* module exported commands */
static cmd_export_t cmds[] ={
	{"sca_set_calling_line", (cmd_function)sca_set_calling_line, {
		{CMD_PARAM_STR,0,0}, {0,0,0}},
		REQUEST_ROUTE},
	{"sca_set_called_line",  (cmd_function)sca_set_called_line, {
		{CMD_PARAM_STR,0,0}, {0,0,0}},
		REQUEST_ROUTE},
	{0,0,{{0,0,0}},0}
};

/* module exported parameters */
static param_export_t params[] = {
	{"line_hash_size",                  INT_PARAM, &hash_size},
	{"disable_dialog_support_for_sca",  INT_PARAM, &no_dialog_support},
	{"call_info_timeout_notification",  INT_PARAM, &call_info_timeout_notification},
	{"line_seize_timeout_notification", INT_PARAM, &line_seize_timeout_notification},
	{0, 0, 0}
};

static module_dependency_t *get_deps_dialog_support(param_export_t *param)
{
	int no_dialog_support = *(int *)param->param_pointer;

	if (no_dialog_support)
		return NULL;

	return alloc_module_dep(MOD_TYPE_DEFAULT, "dialog", DEP_ABORT);
}

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "presence", DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ "disable_dialog_support_for_sca", get_deps_dialog_support },
		{ NULL, NULL },
	},
};

/* module exports */
struct module_exports exports= {
	"presence_callinfo",	/* module name */
	MOD_TYPE_DEFAULT,       /* class of this module */
	MODULE_VERSION,			/* module version */
	DEFAULT_DLFLAGS,		/* dlopen flags */
	0,						/* load function */
	&deps,                  /* OpenSIPS module dependencies */
	cmds,					/* exported functions */
	0,						/* exported async functions */
	params,					/* exported parameters */
	0,						/* exported statistics */
	0,						/* exported MI functions */
	0,						/* exported pseudo-variables */
	0,			 			/* exported transformations */
	0,						/* extra processes */
	0,						/* module pre-initialization function */
	mod_init,				/* module initialization function */
	(response_function) 0,	/* response handling function */
	destroy,				/* destroy function */
	child_init,				/* per-child init function */
	0						/* reload confirm function */
};


/*
 * init module function
 */
static int mod_init(void)
{
	bind_presence_t bind_presence;

	LM_INFO("initializing...\n");

	/* bind to presence module */
	bind_presence= (bind_presence_t)find_export("bind_presence",0);
	if (!bind_presence) {
		LM_ERR("can't bind presence\n");
		return -1;
	}
	if (bind_presence(&pres) < 0) {
		LM_ERR("can't bind pua\n");
		return -1;
	}

	if (pres.add_event == NULL) {
		LM_ERR("could not import add_event\n");
		return -1;
	}
	if(callinfo_add_events() < 0) {
		LM_ERR("failed to add call-info events\n");
		return -1;
	}

	if (no_dialog_support==0) {
		/* bind to the dialog API */
		if (init_dialog_support()<0 ) {
			LM_ERR("failed to enable the dialog support\n");
			return -1;
		}

		/* init internal hash table to keep the SCA/lines status */
		if ( init_sca_hash(hash_size) < 0 ) {
			LM_ERR("failed to init hash table for SCA lines\n");
			return -1;
		}
	}

	return 0;
}


static int child_init(int rank)
{
	return 0;
}


static void destroy(void)
{
	LM_DBG("destroying module ...\n");
	if (no_dialog_support==0)
		destroy_sca_hash();
	return;
}


int sca_set_calling_line(struct sip_msg *msg, str *line)
{
	if (no_dialog_support) {
		LM_ERR("dialog support is disabled, cannot use this function\n");
		return -1;
	}

	if (msg->REQ_METHOD != METHOD_INVITE)
		return 1;

	/* get the name of line first */
	if (!line) {
		/* take it from FROM msg */
		if (parse_from_header(msg) < 0 ) {
			LM_ERR("failed to extract FROM URI\n");
			return -1;
		}
		line = &(get_from(msg)->uri);
	}

	return sca_set_line(msg, line, 1/*calling*/);
}


int sca_set_called_line(struct sip_msg *msg, str *line)
{
	if (no_dialog_support) {
		LM_ERR("dialog support is disabled, cannot use this function\n");
		return -1;
	}

	if (msg->REQ_METHOD != METHOD_INVITE)
		return 1;

	if (!line) {
		/* take it from RURI msg */
		line = GET_RURI(msg);
	}

	return sca_set_line(msg, line, 0/*called*/);
}

