/*
 * Copyright (C) 2017 OpenSIPS Solutions
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
 * Foundation Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include "../../sr_module.h"
#include "../../ut.h"
#include "../../ipc.h"
#include "../../mod_fix.h"
#include "../../evi/evi_transport.h"
#include "../../evi/evi_modules.h"
#include "../tm/tm_load.h"
#include "ebr_data.h"



/* module API */
static int fix_event_name(void** param);
static int fix_notification_route(void** param);
static int fixup_notify(void** param, int param_no);
static int fixup_wait(void** param, int param_no);

static int mod_init(void);
static int notify_on_event(struct sip_msg *msg, void *ev, void *avp_filter,
	void *route, void *timeout);
static int wait_for_event(struct sip_msg* msg, async_ctx *ctx,
		char *ev, char* avp_filter, char* timeout);


/* EVI transport API */
static int ebr_raise(struct sip_msg *msg, str* ev_name,
		evi_reply_sock *sock, evi_params_t *params);
static evi_reply_sock* ebr_parse(str socket);
static int ebr_match(evi_reply_sock *sock1, evi_reply_sock *sock2);
static str ebr_print(evi_reply_sock *sock);


/* IPC type registered with the IPC layer */
int ebr_ipc_type;

/* the TM API */
struct tm_binds ebr_tmb;




/* exported module parameters */
static param_export_t params[] = {
	{0, 0, 0}
};

/* exported module functions (to script) */
static cmd_export_t cmds[]={
	{"notify_on_event", (cmd_function)notify_on_event, 3,
		fixup_notify, 0,
		EVENT_ROUTE|REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE },
	{"notify_on_event", (cmd_function)notify_on_event, 4,
		fixup_notify, 0,
		EVENT_ROUTE|REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE },
	{0,0,0,0,0,0}
};

/* exported module async functions (to script) */
static acmd_export_t acmds[] = {
	{"wait_for_event",  (acmd_function)wait_for_event,  3, fixup_wait },
	{0, 0, 0, 0}
};



/**
 * module exports
 */
struct module_exports exports= {
	/* module name */
	"event_routing",
	/* class of this module */
	MOD_TYPE_DEFAULT,
	MODULE_VERSION,
	/* dlopen flags */
	DEFAULT_DLFLAGS,
	/* OpenSIPS module dependencies */
	NULL,
	/* exported functions */
	cmds,
	/* exported async functions */
	acmds,
	/* exported parameters */
	params,
	/* exported statistics */
	NULL,
	/* exported MI functions */
	NULL,
	/* exported pseudo-variables */
	NULL,
	/* exported transformations */
	NULL,
	/* extra processes */
	NULL,
	/* module initialization function */
	mod_init,
	/* response handling function */
	NULL,
	/* destroy function */
	NULL,
	/* per-child init function */
	NULL
};


/**
 * exported functions for core event interface
 */
static evi_export_t evi_backend_ebr = {
	/* the name of the exported EVI backend*/
	str_init(EVI_ROUTING_NAME),
	/* function called for dispatching an event via backend */
	ebr_raise,
	/* function to parse an EBR specific socket */
	ebr_parse,
	/* function for EBR specific socket matching */
	ebr_match,
	/* no free function */
	0,
	/* function for printing an EBR socket */
	ebr_print,
	/* super flags for unknown purposes :D */
	(1<<25)
};



/*********************  module interface functions  ************************/

static int mod_init(void)
{
	/* register function for EVI transport API */
	if (register_event_mod(&evi_backend_ebr)) {
		LM_ERR("cannot register EVI backend for event-based-routing\n");
		return -1;
	}

	/* register with the IPC layer */
	ebr_ipc_type = ipc_register_handler( handle_ebr_ipc, "EBR");
	if (ebr_ipc_type<0) {
		LM_ERR("cannot register IPC handler for 'EBR'\n");
		return -1;
	}

	/* try binding to TM if needed and if available */
	memset( &ebr_tmb, 0, sizeof(ebr_tmb) );
	if ( is_script_func_used("notify_on_event",-1) ) {
		/* TM may be used passing the transaction context to the 
		 * notification routes */
		LM_DBG("trying to load TM API, if available\n");
		if (load_tm_api(&ebr_tmb)<0) {
			LM_NOTICE("unable to load TM API, so TM context will not be "
				"available in notification routes\n");
		}
	}

	return 0;
}


/* Fixes an EBR event (given by name) by coverting to an internal
 * structure (if not already found)
 */
int fix_event_name(void** param)
{
	str event;
	ebr_event *ev;

	/* convert the event to numerical ID */
	event.s = (char*)*param;
	event.len = strlen(event.s);

	/* check if we have the ID in our list */
	ev = search_ebr_event( &event );

	if (ev==NULL) {
		/* add the new event into the list */
		if ( (ev=add_ebr_event( &event )) == NULL ) {
			LM_ERR("failed to add event <%s>\n",event.s);
			return -1;
		}
	}

	pkg_free(*param);
	*param = (void*)ev;
	return 0;
}


static int fix_notification_route(void** param)
{
	int route_idx;

	route_idx = get_script_route_ID_by_name( (char*)*param, rlist, RT_NO);
	if (route_idx==-1) {
		LM_ERR("notification route <%s> not defined in script\n",
			(char*)*param);
		return -1;
	}
	pkg_free((char*)*param);
	*param = (void*)(long)route_idx;
	return 0;
}


int fixup_notify(void** param, int param_no)
{
	if (param_no==1) {
		/* name of the event */
		return fix_event_name(param);
	} else
	if (param_no==2) {
		/* AVP for key-val event filter */
		if (fixup_pvar(param)<0)
			return -1;
		/* must be an AVP */
		if (((pv_spec_t*)(*param))->type!= PVT_AVP) {
			LM_ERR("KEY and VAL filter variables must be AVPs\n");
			return -1;
		}
		pkg_free(*param);
		/* ugly, but directly grab the ID of the AVP from the spec */
		*param = (void*)(long)((pv_spec_t*)(*param))->pvp.pvn.u.isname.name.n;
		return 0;
	} else
	if (param_no==3) {
		/* notification route */
		return fix_notification_route(param);
	} else
	if (param_no==4) {
		/* timeout */
		return fixup_uint(param);
	}

	return -1;
}


int fixup_wait(void** param, int param_no)
{
	if (param_no==1) {
		/* name of the event */
		return fix_event_name(param);
	} else
	if (param_no==2) {
		/* AVPs for key-val event filter */
		if (fixup_pvar(param)<0)
			return -1;
		/* must be an AVP */
		if (((pv_spec_t*)(*param))->type!= PVT_AVP) {
			LM_ERR("KEY and VAL filter variables must be AVPs\n");
			return -1;
		}
		pkg_free(*param);
		/* ugly, but directly grab the ID of the AVP from the spec */
		*param = (void*)(long)((pv_spec_t*)(*param))->pvp.pvn.u.isname.name.n;
		return 0;
	} else
	if (param_no==3) {
		/* timeout */
		return fixup_uint(param);
	}

	return -1;
}


static int notify_on_event(struct sip_msg *msg, void *ev, void *avp_filter,
									void *route, void *timeout)
{
	ebr_event* event=(ebr_event*)ev;

	if (event->event_id==-1) {
		/* do the init of the event*/
		if (init_ebr_event(event)<0) {
			LM_ERR("failed to init event\n");
			return -1;
		}
	}

	/* we have a valid EBR event here, let's subscribe on it */
	if (add_ebr_subscription( msg, event, (int)(long)avp_filter,
	    timeout ? (int)*(unsigned int *)timeout : 0, route,
	    EBR_SUBS_TYPE_NOTY ) <0 ) {
		LM_ERR("failed to add ebr subscription for event %d\n",
			event->event_id);
		return -1;
	}

	return 1;
}


static int wait_for_event(struct sip_msg* msg, async_ctx *ctx,
								char *ev, char* avp_filter, char* timeout)
{
	ebr_event* event=(ebr_event*)ev;

	if (event->event_id==-1) {
		/* do the init of the event*/
		if (init_ebr_event(event)<0) {
			LM_ERR("failed to init event\n");
			return -1;
		}
	}

	/* we have a valid EBR event here, let's subscribe on it */
	if (add_ebr_subscription( msg, event, (int)(long)avp_filter,
	    (int)*(unsigned int *)timeout, (void*)ctx,
	    EBR_SUBS_TYPE_WAIT ) <0 ) {
		LM_ERR("failed to add ebr subscription for event %d\n",
			event->event_id);
		return -1;
	}

	ctx->resume_param = NULL; /* this will be auto generated by EBR
	                           * notification dispatcher */
	ctx->resume_f = ebr_resume_from_wait;
	async_status = ASYNC_NO_FD;

	return 1;
}

/************ implementation of the EVI transport API *******************/

static int ebr_match(evi_reply_sock *sock1, evi_reply_sock *sock2)
{
	if (!sock1 || !sock2)
		return 0;
	if (!(sock1->flags & EVI_PARAMS) || !(sock2->flags & EVI_PARAMS) ||
	sock1->params != sock2->params )
		return 0;
	return 1;
}


static evi_reply_sock* ebr_parse(str socket)
{
	evi_reply_sock *sock = NULL;
	ebr_event *ev;

	if (!socket.len || !socket.s) {
		LM_ERR("no socket specified\n");
		return NULL;
	}

	LM_DBG("parsing socket <%.*s>\n",socket.len,socket.s);

	/* search the EBR event based on name */
	ev = search_ebr_event( &socket );
	if (ev==NULL) {
		LM_BUG("event <%.*s> not found in EBR socket :P\n",
			socket.len, socket.s);
		return NULL;
	}

	/* build the EVI socket */
	sock = shm_malloc(sizeof(evi_reply_sock));
	if (!sock) {
		LM_ERR("no more memory for socket\n");
		return NULL;
	}
	memset(sock, 0, sizeof(evi_reply_sock));

	/* ev is static structure (never changes, not freeable),
	 * so it is safe to refer it*/
	sock->address = ev->event_name;
	sock->params = (void*)ev;;
	sock->flags = EVI_ADDRESS|EVI_PARAMS;

	return sock;
}


static str ebr_print(evi_reply_sock *sock)
{
	/* return only the event name */
	return sock->address;
}


static int ebr_raise(struct sip_msg *msg, str* ev_name,
							 evi_reply_sock *sock, evi_params_t *params)
{
	if (!sock || !(sock->flags & EVI_PARAMS)) {
		LM_ERR("no socket found\n");
		return -1;
	}

	notify_ebr_subscriptions( (ebr_event*)sock->params, params);

	return 0;
}

