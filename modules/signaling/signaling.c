/*
 * signaling module - interface for sending sip messages
 *
 * Copyright (C) 2008 Voice Sistem S.R.L.
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
 *  2008-11-5  initial version (Anca Vamanu)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../../sr_module.h"
#include "../tm/tm_load.h"
#include "../sl/sl_api.h"
#include "signaling.h"



/** global variables*/

/* TM bind */
struct tm_binds tmb;
/* SL bind */
struct sl_binds slb;

int sl_loaded = 0;
int tm_loaded = 0;

int sig_send_reply(struct sip_msg* msg, int* code_i, str* code_s);
int sig_send_reply_mod(struct sip_msg* msg, int code, str* reason, str* to_tag);
static int fixup_sig_send_reply(void** param);
static int mod_init(void);

/** exported commands */
static cmd_export_t cmds[]={
	{"send_reply",(cmd_function)sig_send_reply, {	
		{CMD_PARAM_INT,fixup_sig_send_reply,0},
		{CMD_PARAM_STR,0,0}, {0,0,0}},
		REQUEST_ROUTE | ERROR_ROUTE | FAILURE_ROUTE},
	{"load_sig", (cmd_function)load_sig, {{0,0,0}},0},
	{0,0,{{0,0,0}},0}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "tm", DEP_SILENT },
		{ MOD_TYPE_DEFAULT, "sl", DEP_SILENT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

/** module exports */
struct module_exports exports= {
	"signaling",				/* module name */
	MOD_TYPE_DEFAULT,           /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,			/* dlopen flags */
	&deps,                      /* OpenSIPS module dependencies */
	cmds,						/* exported functions */
	0,							/* exported async functions */
	0,							/* exported parameters */
	0,							/* exported statistics */
	0,							/* exported MI functions */
	0,							/* exported pseudo-variables */
	0,							/* exported transformations */
	0,							/* extra processes */
	mod_init,					/* module initialization function */
	(response_function) 0,      /* response handling function */
	(destroy_function)  0,      /* destroy function */
	0,                          /* per-child init function */
	0                           /* reload confirm function */
};

/**
 * init module function
 */
static int mod_init(void)
{
	load_tm_f load_tm;
	load_sl_f load_sl;
	LM_NOTICE("initializing module ...\n");

	/* load TM API*/
	if ( (load_tm=(load_tm_f)find_export("load_tm", 0)))
	{
		if (load_tm( &tmb )==-1)
		{
			LM_ERR("failed to load tm api\n");
			return -1;
		}
		tm_loaded = 1;
	}

	/* load SL API */
	if ((load_sl=(load_sl_f)find_export("load_sl", 0)))
	{
		if (load_sl( &slb )==-1)
		{
			LM_ERR("failed to load sl api although sl module is loaded\n");
			return -1;
		}
		sl_loaded = 1;
	}

	if(!tm_loaded && !sl_loaded)
	{
		LM_ERR("neither 'tm' nor 'sl' module loaded! Sipreply module requires"
				" loading at least one of these two\n");
		return -1;
	}

	return 0;
}

/*
 * sig_send_reply - function to be called from script to send appropiate
 * replies (statefull or stateless)
 * */
int sig_send_reply(struct sip_msg* msg, int* code_i, str* code_s)
{
	return sig_send_reply_mod(msg, *code_i, code_s, 0);
}

/*
 * sig_send_reply_mod function - sends stateless or staefull reply depending on
 * whether a transaction was created and on which modules are loaded( tm, sl).
 * */
int sig_send_reply_mod(struct sip_msg* msg, int code, str* reason, str* to_tag)
{
	struct cell * t;

	if(reason== NULL || reason->s== NULL)
	{
		LM_ERR("empty reason parameter\n");
		return -1;
	}

	/* search transaction */
	if(tm_loaded)
	{
		t = tmb.t_gett();
		if(t== NULL || t==T_UNDEFINED)
		{
			if(!sl_loaded)
			{
				LM_ERR("sl module not loaded and no transaction found for the"
						" message. Can not send reply!\n");
				return -1;
			}
			goto sl_reply;
		}
		if( tmb.t_reply(msg, code, reason)< 0)
		{
			LM_ERR("failed to send reply with tm module\n");
			return -1;
		}
		if(to_tag)
			*to_tag = t->uas.local_totag;
		return 1;
	}

sl_reply:

	if(slb.reply(msg, code, reason)< 0)
	{
		LM_ERR("failed to send reply with sl module\n");
		return -1;
	}
	if(to_tag)
	{
		if(slb.get_totag(msg, to_tag)< 0)
		{
			LM_ERR("failed to get to_tag from sl\n");
			return -1;
		}
	}

	return 1;
}

/* *
 * fixup_sig_send_reply
 */
static int fixup_sig_send_reply(void** param)
{
	if (*(int*)*param < 100 || *(int*)*param > 699) {
		LM_ERR("wrong code: %d, allowed values: 1xx - 6xx only!\n",
			*(int*)*param);
		return E_UNSPEC;
	}

	return 0;
}

int load_sig( struct sig_binds *sigb)
{
	if(sigb==NULL)
		return -1;

	sigb->reply = sig_send_reply_mod;

	return 1;
}

