/*
 * pua_xmpp module - presence SIP - XMPP Gateway
 *
 * Copyright (C) 2007 Voice Sistem S.R.L.
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
 *  2007-03-29  initial version (Anca Vamanu)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libxml/parser.h>
#include <time.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../str.h"
#include "../../pt.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../parser/parse_expires.h"
#include "../../parser/msg_parser.h"
#include "../tm/tm_load.h"
#include "../xmpp/xmpp_api.h"
#include "../pua/pua_bind.h"

#include "pua_xmpp.h"
#include "xmpp2simple.h"
#include "simple2xmpp.h"
#include "request_winfo.h"



struct tm_binds tmb;

/* functions imported from pua module*/
pua_api_t pua;
send_publish_t pua_send_publish;
send_subscribe_t pua_send_subscribe;
query_dialog_t pua_is_dialog;

/* functions imported from xmpp module*/
xmpp_api_t xmpp_api;
xmpp_send_xsubscribe_f xmpp_subscribe;
xmpp_send_xnotify_f xmpp_notify;
xmpp_send_xpacket_f xmpp_packet;
uri_xmpp2sip_f xmpp_uri_xmpp2sip;
uri_sip2xmpp_f xmpp_uri_sip2xmpp;

/* libxml wrapper functions */
xmlNodeGetAttrContentByName_t XMLNodeGetAttrContentByName;
xmlDocGetNodeByName_t XMLDocGetNodeByName;
xmlNodeGetNodeByName_t XMLNodeGetNodeByName;
xmlNodeGetNodeContentByName_t XMLNodeGetNodeContentByName;

str server_address= {0, 0};
str presence_server= {0, 0};

/** module functions */

static int mod_init(void);
static int child_init(int);

static cmd_export_t cmds[]={
	{"pua_xmpp_notify", (cmd_function)Notify2Xmpp, {{0,0,0}},
		REQUEST_ROUTE},
	{"pua_xmpp_req_winfo", (cmd_function)request_winfo, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_INT,0,0}, {0,0,0}},
		REQUEST_ROUTE},
	{0,0,{{0,0,0}},0}
};

static param_export_t params[]={
	{"server_address",		STR_PARAM,	&server_address.s},
	{"presence_server",		STR_PARAM,	&presence_server},
	{0,						0,			0				}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "tm",   DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "xmpp", DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "pua",  DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

/** module exports */
struct module_exports exports= {
	"pua_xmpp",					/* module name */
	MOD_TYPE_DEFAULT,           /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,			/* dlopen flags */
	0,							/* load function */
	&deps,						/* OpenSIPS module dependencies */
	cmds,						/* exported functions */
	0,							/* exported async functions */
	params,						/* exported  parameters */
	0,							/* exported statistics */
	0,							/* exported MI functions*/
	0,							/* exported pseudo-variables */
	0,							/* exported transformations */
	0,							/* extra processes */
	0,							/* module pre-initialization function */
	mod_init,					/* module initialization function */
	(response_function) 0,		/* response handling function */
	(destroy_function) 0,		/* destroy function */
	child_init,					/* per-child init function */
	0							/* reload confirm function */
};

/**
 * init module function
 */
static int mod_init(void)
{
	load_tm_f  load_tm;
	bind_pua_t bind_pua;
	bind_xmpp_t bind_xmpp;
	bind_libxml_t bind_libxml;
	libxml_api_t libxml_api;

	/* check if compulsory parameter server_address is set */
	if(server_address.s== NULL)
	{
		LM_ERR("compulsory 'server_address' parameter not set!\n");
		return -1;
	}
	server_address.len= strlen(server_address.s);

	if(presence_server.s)
		presence_server.len = strlen(presence_server.s);

	/* import the TM auto-loading function */
	if((load_tm=(load_tm_f)find_export("load_tm", 0))==NULL)
	{
		LM_ERR("can't import load_tm\n");
		return -1;
	}
	/* let the auto-loading function load all TM stuff */

	if(load_tm(&tmb)==-1)
	{
		LM_ERR("can't load tm functions\n");
		return -1;
	}

	/* bind libxml wrapper functions */
	if((bind_libxml= (bind_libxml_t)find_export("bind_libxml_api", 0))== NULL)
	{
		LM_ERR("can't import bind_libxml_api\n");
		return -1;
	}
	if(bind_libxml(&libxml_api)< 0)
	{
		LM_ERR("can not bind libxml api\n");
		return -1;
	}
	XMLNodeGetAttrContentByName= libxml_api.xmlNodeGetAttrContentByName;
	XMLDocGetNodeByName= libxml_api.xmlDocGetNodeByName;
	XMLNodeGetNodeByName= libxml_api.xmlNodeGetNodeByName;
    XMLNodeGetNodeContentByName= libxml_api.xmlNodeGetNodeContentByName;

	if(XMLNodeGetAttrContentByName== NULL || XMLDocGetNodeByName== NULL ||
		XMLNodeGetNodeByName== NULL || XMLNodeGetNodeContentByName== NULL)
	{
		LM_ERR("libxml wrapper functions could not be bound\n");
		return -1;
	}


	/* bind xmpp */
	bind_xmpp= (bind_xmpp_t)find_export("bind_xmpp",0);
	if (!bind_xmpp)
	{
		LM_ERR("Can't bind xmpp\n");
		return -1;
	}
	if(bind_xmpp(&xmpp_api)< 0)
	{
		LM_ERR("Can't bind xmpp\n");
		return -1;
	}
	if(xmpp_api.xsubscribe== NULL)
	{
		LM_ERR("Could not import xsubscribe from xmpp\n");
		return -1;
	}
	xmpp_subscribe= xmpp_api.xsubscribe;

	if(xmpp_api.xnotify== NULL)
	{
		LM_ERR("Could not import xnotify from xmpp\n");
		return -1;
	}
	xmpp_notify= xmpp_api.xnotify;

	if(xmpp_api.xpacket== NULL)
	{
		LM_ERR("Could not import xnotify from xmpp\n");
		return -1;
	}
	xmpp_packet= xmpp_api.xpacket;

	xmpp_uri_xmpp2sip = xmpp_api.uri_xmpp2sip;
	xmpp_uri_sip2xmpp = xmpp_api.uri_sip2xmpp;

	if(xmpp_api.register_callback== NULL)
	{
		LM_ERR("Could not import register_callback"
				" to xmpp\n");
		return -1;
	}
	if(xmpp_api.register_callback(XMPP_RCV_PRESENCE, pres_Xmpp2Sip, NULL)< 0)
	{
		LM_ERR("ERROR while registering callback"
				" to xmpp\n");
		return -1;
	}

	/* bind pua */
	bind_pua= (bind_pua_t)find_export("bind_pua",0);
	if (!bind_pua)
	{
		LM_ERR("Can't bind pua\n");
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

	if(pua.is_dialog == NULL)
	{
		LM_ERR("Could not import send_subscribe\n");
		return -1;
	}
	pua_is_dialog= pua.is_dialog;

	if(pua.register_puacb(XMPP_INITIAL_SUBS, Sipreply2Xmpp, NULL)< 0)
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
