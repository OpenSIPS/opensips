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
#include "api.h"


/* module API */
static int fix_event_name(void** param);
static int fix_notification_route(void** param);
static int fixup_check_avp(void** param);

static int mod_init(void);
static int cfg_validate(void);
static int notify_on_event(struct sip_msg *msg, ebr_event* event, pv_spec_t *avp_filter,
					void *route, int *timeout);
static int wait_for_event(struct sip_msg* msg, async_ctx *ctx,
					ebr_event* event, pv_spec_t* avp_filter, int* timeout);


/* EVI transport API */
static int ebr_raise(struct sip_msg *msg, str* ev_name,
		evi_reply_sock *sock, evi_params_t *params);
static evi_reply_sock* ebr_parse(str socket);
static int ebr_match(evi_reply_sock *sock1, evi_reply_sock *sock2);
static str ebr_print(evi_reply_sock *sock);

void ebr_bind(ebr_api_t *api);
ebr_event *get_ebr_event(const str *name);
int api_notify_on_event(struct sip_msg *msg, ebr_event *event,
                        const ebr_filter *filters,
                        ebr_pack_params_cb pack_params,
                        ebr_notify_cb notify, int timeout);
int api_wait_for_event(struct sip_msg *msg, async_ctx *ctx,
                        ebr_event *event, const ebr_filter *filters,
                        ebr_pack_params_cb pack_params, int timeout);

/* IPC type registered with the IPC layer */
ipc_handler_type ebr_ipc_type;

/* the TM API */
struct tm_binds ebr_tmb;




/* exported module parameters */
static param_export_t params[] = {
	{0, 0, 0}
};

/* exported module functions (to script) */
static cmd_export_t cmds[]={
	{"notify_on_event", (cmd_function)notify_on_event, {
		{CMD_PARAM_STR, fix_event_name, 0},
		{CMD_PARAM_VAR, fixup_check_avp, 0},
		{CMD_PARAM_STR, fix_notification_route, 0},
		{CMD_PARAM_INT, 0 ,0}, {0,0,0}},
		EVENT_ROUTE|REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE},
	{"ebr_bind", (cmd_function)ebr_bind, {{0,0,0}}, 0},
	{0,0,{{0,0,0}},0}
};

/* exported module async functions (to script) */
static acmd_export_t acmds[] = {
	{"wait_for_event",  (acmd_function)wait_for_event, {
		{CMD_PARAM_STR, fix_event_name, 0},
		{CMD_PARAM_VAR, fixup_check_avp, 0},
		{CMD_PARAM_INT, 0 ,0}, {0,0,0}}},
	{0,0,{{0,0,0}}}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "tm",        DEP_SILENT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
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
	/* load function */
	0,
	/* OpenSIPS module dependencies */
	&deps,
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
	/* module pre-initialization function */
	NULL,
	/* module initialization function */
	mod_init,
	/* response handling function */
	NULL,
	/* destroy function */
	NULL,
	/* per-child init function */
	NULL,
	/* reload confirm function */
	cfg_validate
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
	(1<<22)
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
	if (ipc_bad_handler_type(ebr_ipc_type)) {
		LM_ERR("cannot register IPC handler for 'EBR'\n");
		return -1;
	}

	/* try binding to TM if available */
	memset( &ebr_tmb, 0, sizeof(ebr_tmb) );

	/* TM may be used passing the transaction context to the
	 * notification routes */
	LM_DBG("trying to load TM API, if available\n");
	if (load_tm_api(&ebr_tmb) < 0)
		LM_NOTICE("unable to load TM API, so TM context will not be "
		          "available in notification routes\n");

	return 0;
}


void ebr_bind(ebr_api_t *api)
{
	api->get_ebr_event = get_ebr_event;
	api->notify_on_event = api_notify_on_event;
	api->async_wait_for_event = api_wait_for_event;
}


static int cfg_validate(void)
{
	if ( ebr_tmb.t_gett==NULL && is_script_func_used("notify_on_event",-1)) {
		LM_ERR("notify_on_event() was found, but module started without TM "
			"support/biding, better restart\n");
		return 0;
	}

	return 1;
}


ebr_event *get_ebr_event(const str *name)
{
	ebr_event *ev;

	/* check if we have the ID in our list */
	if (!(ev = search_ebr_event(name))) {
		/* add the new event into the list */
		if (!(ev = add_ebr_event(name))) {
			LM_ERR("failed to add event <%.*s>\n", name->len, name->s);
			return NULL;
		}
	}

	return ev;
}


/* Fix an EBR event (given by name) by converting to an internal structure */
int fix_event_name(void** param)
{
	ebr_event *ev;

	if (!(ev = get_ebr_event((str *)*param))) {
		LM_ERR("failed to fix event name\n");
		return -1;
	}

	*param = ev;
	return 0;
}


static int fix_notification_route(void** param)
{
	int route_idx;
	str name_s;

	if (pkg_nt_str_dup(&name_s, (str*)*param) < 0)
		return -1;

	route_idx = get_script_route_ID_by_name(name_s.s,
		sroutes->request, RT_NO);
	if (route_idx==-1) {
		LM_ERR("notification route <%s> not defined in script\n",
			name_s.s);
		return -1;
	}

	*param = (void*)(long)route_idx;
	pkg_free(name_s.s);
	return 0;
}

static int fixup_check_avp(void** param)
{
	if (((pv_spec_t *)*param)->type!=PVT_AVP) {
		LM_ERR("filter parameter must be an AVP\n");
		return E_SCRIPT;
	}

	return 0;
}


static int notify_on_event(struct sip_msg *msg, ebr_event* event, pv_spec_t *avp_filter,
									void *route, int *timeout)
{
	ebr_filter *filters;

	if (event->event_id==-1) {
		/* do the init of the event*/
		if (init_ebr_event(event)<0) {
			LM_ERR("failed to init event\n");
			return -1;
		}
	}

	if (pack_ebr_filters(msg, avp_filter->pvp.pvn.u.isname.name.n,
	                     &filters) < 0) {
		LM_ERR("failed to build list of EBR filters\n");
		return -1;
	}

	/* we have a valid EBR event here, let's subscribe on it */
	if (add_ebr_subscription( msg, event, filters,
	    timeout ? *timeout : 0, NULL, route,
	    EBR_SUBS_TYPE_NOTY|EBR_DATA_TYPE_ROUT ) <0 ) {
		LM_ERR("failed to add ebr subscription for event %d\n",
			event->event_id);
		return -1;
	}

	return 1;
}


int api_notify_on_event(struct sip_msg *msg, ebr_event *event,
                        const ebr_filter *filters,
                        ebr_pack_params_cb pack_params,
                        ebr_notify_cb notify, int timeout)
{
	ebr_filter *filters_cpy;

	if (event->event_id == -1) {
		/* do the init of the event*/
		if (init_ebr_event(event)<0) {
			LM_ERR("failed to init event\n");
			return -1;
		}
	}

	if (dup_ebr_filters(filters, &filters_cpy) != 0) {
		LM_ERR("oom\n");
		return -1;
	}

	/* we have a valid EBR event here, let's subscribe on it */
	if (add_ebr_subscription( msg, event, filters_cpy,
	    timeout, pack_params, notify,
	    EBR_SUBS_TYPE_NOTY|EBR_DATA_TYPE_FUNC ) <0 ) {
		LM_ERR("failed to add ebr subscription for event %d\n",
			event->event_id);
		return -1;
	}

	return 0;
}


static int _wait_for_event(struct sip_msg *msg, async_ctx *ctx,
                    ebr_event *event, ebr_filter *filters, int timeout,
                    ebr_pack_params_cb pack_params)
{
	if (event->event_id == -1) {
		/* do the init of the event*/
		if (init_ebr_event(event) < 0) {
			LM_ERR("failed to init event\n");
			return -1;
		}
	}

	/* we have a valid EBR event here, let's subscribe on it */
	if (add_ebr_subscription(msg, event, filters,
	    timeout, pack_params, (void *)ctx, EBR_SUBS_TYPE_WAIT) < 0) {
		LM_ERR("failed to add ebr subscription for event %d\n",
		       event->event_id);
		return -1;
	}

	ctx->resume_param = NULL; /* this will be auto generated by EBR
	                           * notification dispatcher */
	ctx->resume_f = ebr_resume_from_wait;
	async_status = ASYNC_NO_FD;

	return 0;
}


static int wait_for_event(struct sip_msg* msg, async_ctx *ctx,
					ebr_event* event, pv_spec_t* avp_filter, int* timeout)
{
	ebr_filter *filters;
	int rc;

	if (pack_ebr_filters(msg, avp_filter->pvp.pvn.u.isname.name.n,
	                     &filters) < 0) {
		LM_ERR("failed to build list of EBR filters\n");
		return -1;
	}

	rc = _wait_for_event(msg, ctx, event, filters, *timeout, NULL);
	return rc == 0 ? 1 : rc;
}


int api_wait_for_event(struct sip_msg *msg, async_ctx *ctx,
                        ebr_event *event, const ebr_filter *filters,
                        ebr_pack_params_cb pack_params, int timeout)
{
	ebr_filter *filters_cpy;

	if (dup_ebr_filters(filters, &filters_cpy) != 0) {
		LM_ERR("oom\n");
		return -1;
	}

	return _wait_for_event(msg, ctx, event, filters_cpy, timeout, pack_params);
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
