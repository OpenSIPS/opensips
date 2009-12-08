/*
 * $Id$
 *
 * pua_dialoginfo module - publish dialog-info from dialog module
 *
 * Copyright (C) 2006 Voice Sistem S.R.L.
 * Copyright (C) 2007-2008 Dan Pascu
 * Copyright (C) 2008 Klaus Darilion IPCom
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
 *  2008-08-25  initial version (kd)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libxml/parser.h>
#include <time.h>

#include "../../script_cb.h"
#include "../../sr_module.h"
#include "../../parser/parse_expires.h"
#include "../../dprint.h"
#include "../../mem/shm_mem.h"
#include "../../parser/msg_parser.h"
#include "../../str.h"
#include "../../mem/mem.h"
#include "../../pt.h"
#include "../../parser/parse_from.h"
#include "../dialog/dlg_load.h"
#include "../dialog/dlg_hash.h"
#include "../pua/pua_bind.h"
#include "pua_dialoginfo.h"



/* Default module parameter values */
#define DEF_INCLUDE_CALLID 1
#define DEF_INCLUDE_LOCALREMOTE 1
#define DEF_INCLUDE_TAGS 1
#define DEF_CALLER_ALWAYS_CONFIRMED 0

#define DEFAULT_CREATED_LIFETIME 3600

/* define PUA_DIALOGINFO_DEBUG to activate more verbose 
 * logging and dialog info callback debugging
 */
/* #define PUA_DIALOGINFO_DEBUG 1 */

pua_api_t pua;

struct dlg_binds dlg_api;

/* Module parameter variables */
int include_callid      = DEF_INCLUDE_CALLID;
int include_localremote = DEF_INCLUDE_LOCALREMOTE;
int include_tags        = DEF_INCLUDE_TAGS;
int caller_confirmed    = DEF_CALLER_ALWAYS_CONFIRMED;
str presence_server = {0, 0};

/** module functions */

static int mod_init(void);
int dialoginfo_set(struct sip_msg* msg, char* str1, char* str2);


static cmd_export_t cmds[]=
{
	{"dialoginfo_set", (cmd_function)dialoginfo_set, 0,0,0, REQUEST_ROUTE},
	{0,                   0,                         0,0,0, 0}
};

static param_export_t params[]={
	{"include_callid",      INT_PARAM, &include_callid },
	{"include_localremote", INT_PARAM, &include_localremote },
	{"include_tags",        INT_PARAM, &include_tags },
	{"caller_confirmed",    INT_PARAM, &caller_confirmed },
	{"presence_server",     STR_PARAM, &presence_server.s },
	{0, 0, 0 }
};

struct module_exports exports= {
	"pua_dialoginfo",		/* module name */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,		/* dlopen flags */
	cmds,					/* exported functions */
	params,					/* exported parameters */
	0,						/* exported statistics */
	0,						/* exported MI functions */
	0,						/* exported pseudo-variables */
	0,						/* extra processes */
	mod_init,				/* module initialization function */
	0,						/* response handling function */
	0,						/* destroy function */
	NULL					/* per-child init function */
};


#ifdef PUA_DIALOGINFO_DEBUG
static void
__dialog_cbtest(struct dlg_cell *dlg, int type, struct dlg_cb_params *_params)
{
	str tag;

	LM_DBG("dialog callback received, from=%.*s, to=%.*s\n",
		dlg->from_uri.len, dlg->from_uri.s, dlg->to_uri.len, dlg->to_uri.s);

	if (dlg->tag[0].len && dlg->tag[0].s ) {
		LM_DBG("dialog callback: tag[0] = %.*s\n",
			dlg->tag[0].len, dlg->tag[0].s);
	}
	if (dlg->tag[0].len && dlg->tag[1].s ) {
		LM_DBG("dialog callback: tag[1] = %.*s\n",
			dlg->tag[1].len, dlg->tag[1].s);
	}

	if (_params->msg && _params->msg!=FAKED_REPLY && type != DLGCB_DESTROY) {
		/* get to tag*/
		if ( !_params->msg->to) {
			/* to header not defined, parse to header */
			LM_DBG("to header not defined, parse to header\n");
			if (parse_headers(_params->msg, HDR_TO_F,0)<0) {
				/* parser error */
				LM_ERR("parsing of to-header failed\n");
				tag.s = 0;
				tag.len = 0;
			} else if (!_params->msg->to) {
				/* to header still not defined */
				LM_ERR("no to although to-header is parsed: bad reply "
					"or missing TO hdr :-/\n");
				tag.s = 0;
				tag.len = 0;
			} else 
				tag = get_to(_params->msg)->tag_value;
		} else {
			tag = get_to(_params->msg)->tag_value;
			if (tag.s==0 || tag.len==0) {
				LM_DBG("missing TAG param in TO hdr :-/\n");
				tag.s = 0;
				tag.len = 0;
			}
		}
		if (tag.s) {
			LM_DBG("dialog callback: _params->msg->to->parsed->tag_value "
				"= %.*s\n", tag.len, tag.s);
		}
	}

	switch (type) {
	case DLGCB_FAILED:
		LM_DBG("dialog callback type 'DLGCB_FAILED' received, from=%.*s\n",
			dlg->from_uri.len, dlg->from_uri.s);
		break;
	case DLGCB_CONFIRMED:
		LM_DBG("dialog callback type 'DLGCB_CONFIRMED' received, from=%.*s\n",
			dlg->from_uri.len, dlg->from_uri.s);
		break;
	case DLGCB_REQ_WITHIN:
		LM_DBG("dialog callback type 'DLGCB_REQ_WITHIN' received, from=%.*s\n",
			dlg->from_uri.len, dlg->from_uri.s);
		break;
	case DLGCB_TERMINATED:
		LM_DBG("dialog callback type 'DLGCB_TERMINATED' received, from=%.*s\n",
			dlg->from_uri.len, dlg->from_uri.s);
		break;
	case DLGCB_EXPIRED:
		LM_DBG("dialog callback type 'DLGCB_EXPIRED' received, from=%.*s\n",
			dlg->from_uri.len, dlg->from_uri.s);
		break;
	case DLGCB_EARLY:
		LM_DBG("dialog callback type 'DLGCB_EARLY' received, from=%.*s\n",
			dlg->from_uri.len, dlg->from_uri.s);
		break;
	case DLGCB_RESPONSE_FWDED:
		LM_DBG("dialog callback type 'DLGCB_RESPONSE_FWDED' received, "
			"from=%.*s\n", dlg->from_uri.len, dlg->from_uri.s);
		break;
	case DLGCB_RESPONSE_WITHIN:
		LM_DBG("dialog callback type 'DLGCB_RESPONSE_WITHIN' received, "
			"from=%.*s\n", dlg->from_uri.len, dlg->from_uri.s);
		break;
	case DLGCB_MI_CONTEXT:
		LM_DBG("dialog callback type 'DLGCB_MI_CONTEXT' received, from=%.*s\n",
			dlg->from_uri.len, dlg->from_uri.s);
		break;
	case DLGCB_DESTROY:
		LM_DBG("dialog callback type 'DLGCB_DESTROY' received, from=%.*s\n",
			dlg->from_uri.len, dlg->from_uri.s);
		break;
	default:
		LM_DBG("dialog callback type 'unknown' received, from=%.*s\n",
			dlg->from_uri.len, dlg->from_uri.s);
	}
}
#endif

static void
__dialog_sendpublish(struct dlg_cell *dlg, int type, struct dlg_cb_params *_params)
{
	str tag = {0,0};
	struct to_body to, from;

	if(_params->msg && _params->msg != FAKED_REPLY)
	{
		struct sip_msg* msg = _params->msg;

		if(msg->to->parsed != NULL)
		{
			to = *((struct to_body*)msg->to->parsed);
			LM_DBG("'To' header ALREADY PARSED: <%.*s>\n",to.uri.len,to.uri.s);
		}
		else
		{
			if(!parse_to(msg->to->body.s,msg->to->body.s + msg->to->body.len + 1, &to))
			{
				LM_DBG("'To' header NOT parsed\n");
				return;
			}
		}
		if (msg->from->parsed == NULL)
		{
			LM_DBG("'From' header not parsed\n");
			/* parsing from header */
			if ( parse_from_header( msg )<0 ) 
			{
				LM_ERR("cannot parse From header\n");
				return;
			}
		}
		from = *((struct to_body*)msg->from->parsed);
	}
	else
	{
		memset(&to, 0, sizeof(struct to_body));
		memset(&from, 0, sizeof(struct to_body));
		to.uri = dlg->to_uri;
		from.uri = dlg->from_uri;
	}

	switch (type) {
	case DLGCB_FAILED:
	case DLGCB_TERMINATED:
	case DLGCB_EXPIRED:
		LM_DBG("dialog over, from=%.*s\n", dlg->from_uri.len, dlg->from_uri.s);
		dialog_publish("terminated", &from, &to, &(dlg->callid), 1, dlg->lifetime, 0, 0);
		dialog_publish("terminated", &to, &from, &(dlg->callid), 0, dlg->lifetime, 0, 0);
		break;
	case DLGCB_CONFIRMED:
	case DLGCB_REQ_WITHIN:
		LM_DBG("dialog confirmed, from=%.*s\n", dlg->from_uri.len, dlg->from_uri.s);
		dialog_publish("confirmed", &from, &to, &(dlg->callid), 1, dlg->lifetime, 0, 0);
		dialog_publish("confirmed", &to, &from, &(dlg->callid), 0, dlg->lifetime, 0, 0);
		break;
	case DLGCB_EARLY:
		LM_DBG("dialog is early, from=%.*s\n", dlg->from_uri.len, dlg->from_uri.s);
		if (include_tags) {
			/* get to tag*/
			if ( !_params->msg->to && ((parse_headers(_params->msg, HDR_TO_F,0)<0) || !_params->msg->to) ) {
				LM_ERR("bad reply or missing TO hdr :-/\n");
				tag.s = 0;
				tag.len = 0;
			} else {
				tag = get_to(_params->msg)->tag_value;
				if (tag.s==0 || tag.len==0) {
					LM_ERR("missing TAG param in TO hdr :-/\n");
					tag.s = 0;
					tag.len = 0;
				}
			}
			if (caller_confirmed) {
				dialog_publish("confirmed", &from, &to, &(dlg->callid), 1,
					dlg->lifetime, &(dlg->legs[DLG_CALLER_LEG].tag), &tag);
			} else {
				dialog_publish("early", &from, &to, &(dlg->callid), 1,
					dlg->lifetime, &(dlg->legs[DLG_CALLER_LEG].tag), &tag);
			}
			dialog_publish("early", &to, &from, &(dlg->callid), 0,
				dlg->lifetime, &tag, &(dlg->legs[DLG_CALLER_LEG].tag));
		} else {
			if (caller_confirmed) {
				dialog_publish("confirmed", &from, &to, &(dlg->callid), 1,
					dlg->lifetime, 0, 0);
			} else {
				dialog_publish("early", &from, &to, &(dlg->callid), 1,
					dlg->lifetime, 0, 0);
			}
			dialog_publish("early", &to, &from, &(dlg->callid), 0,
				dlg->lifetime, 0, 0);
		}
		break;
	default:
		LM_ERR("unhandled dialog callback type %d received, from=%.*s\n", type, dlg->from_uri.len, dlg->from_uri.s);
		dialog_publish("terminated", &from, &to, &(dlg->callid), 1, dlg->lifetime, 0, 0);
		dialog_publish("terminated", &to, &from, &(dlg->callid), 0, dlg->lifetime, 0, 0);
	}
}


/**
 * init module function
 */
static int mod_init(void)
{
	bind_pua_t bind_pua;
	
	bind_pua= (bind_pua_t)find_export("bind_pua", 1,0);
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

	/* add event in pua module */
	if(pua.add_event(DIALOG_EVENT, "dialog", "application/dialog-info+xml", NULL) < 0) {
		LM_ERR("failed to add 'dialog' event to pua module\n");
		return -1;
	}

	/* bind to the dialog API */
	if (load_dlg_api(&dlg_api)!=0) {
		LM_ERR("failed to find dialog API - is dialog module loaded?\n");
		return -1;
	}

	if(presence_server.s)
		presence_server.len = strlen(presence_server.s);

	return 0;
}


int dialoginfo_set(struct sip_msg* msg, char* str1, char* str2)
{
	struct dlg_cell * dlg;
	dlg_api.create_dlg(msg);

	dlg = dlg_api.get_dlg();

	if (msg->REQ_METHOD != METHOD_INVITE)
		return 1;

	LM_DBG("new INVITE dialog created: from=%.*s\n",
		dlg->from_uri.len, dlg->from_uri.s);

	/* register dialog callbacks which triggers sending PUBLISH */
	if (dlg_api.register_dlgcb(dlg,
		DLGCB_FAILED| DLGCB_CONFIRMED | DLGCB_TERMINATED | DLGCB_EXPIRED |
		DLGCB_REQ_WITHIN | DLGCB_EARLY,
		__dialog_sendpublish, 0, 0) != 0) {
		LM_ERR("cannot register callback for interesting dialog types\n");
		return -1;
	}

#ifdef PUA_DIALOGINFO_DEBUG
	/* dialog callback testing (registered last to be executed frist) */
	if (dlg_api.register_dlgcb(dlg,
		DLGCB_FAILED| DLGCB_CONFIRMED | DLGCB_REQ_WITHIN | DLGCB_TERMINATED |
		DLGCB_EXPIRED | DLGCB_EARLY | DLGCB_RESPONSE_FWDED |
		DLGCB_RESPONSE_WITHIN  | DLGCB_MI_CONTEXT | DLGCB_DESTROY,
		__dialog_cbtest, NULL, NULL) != 0) {
		LM_ERR("cannot register callback for all dialog types\n");
		return -1;
	}
#endif

	dialog_publish("Trying", get_from(msg), get_to(msg), &(dlg->callid), 1, DEFAULT_CREATED_LIFETIME, 0, 0);

	return 1;
}
