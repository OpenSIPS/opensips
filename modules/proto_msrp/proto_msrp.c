/*
 * Copyright (C) 2022 - OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

#include <errno.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <poll.h>

#include "../../timer.h"
#include "../../sr_module.h"
#include "../../socket_info.h"
#include "../../tsend.h"
#include "../../trace_api.h"  // ??
#include "../../net/api_proto.h"
#include "../../net/api_proto_net.h"
#include "../../net/net_tcp.h"
#include "../../net/net_tcp_report.h"
#include "../../net/tcp_common.h"
#include "../../net/trans_trace.h"  // ??
#include "../../mi/mi.h"
#include "msrp_plain.h"
#include "msrp_signaling.h"
#include "msrp_api.h"

static int  mod_init(void);
static void mod_destroy(void);
static int  proto_msrp_init(struct proto_info *pi);

static mi_response_t *w_msrp_trace_mi(const mi_params_t *params,
		struct mi_handler *async_hdl);
static mi_response_t *w_msrp_trace_mi_1(const mi_params_t *params,
		struct mi_handler *async_hdl);


#define MSRP_TRACE_PROTO "proto_hep"
#define MSRP_TRANS_TRACE_PROTO_ID "net"
static str trace_destination_name = {NULL, 0};
static trace_proto_t tprot;
trace_dest msrp_t_dst;

/* module  tracing parameters */
static int msrp_trace_is_on_tmp=0;
static char* trace_filter_route;


static cmd_export_t cmds[] = {
	{"proto_init", (cmd_function)proto_msrp_init, {{0, 0, 0}}, 0},
	{"load_msrp", (cmd_function)load_msrp, {{0,0,0}}, 0},
	{0,0,{{0,0,0}},0}
};


static param_export_t params[] = {
	{ "msrp_send_timeout",		INT_PARAM, &msrp_send_timeout       },
	{ "msrp_max_msg_chunks",	INT_PARAM, &msrp_max_msg_chunks },
	{ "trace_destination",		STR_PARAM, &trace_destination_name.s},
	{ "trace_on",				INT_PARAM, &msrp_trace_is_on_tmp        },
	{ "trace_filter_route",		STR_PARAM, &trace_filter_route     },
	{0, 0, 0}
};

static mi_export_t mi_cmds[] = {
	{ "msrp_trace", 0, 0, 0, {
		{w_msrp_trace_mi, {0}},
		{w_msrp_trace_mi_1, {"trace_mode", 0}},
		{EMPTY_MI_RECIPE}
		}
	},
	{EMPTY_MI_EXPORT}
};

/* module dependencies */
static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "proto_hep", DEP_SILENT },
		{ MOD_TYPE_NULL, NULL, 0 }
	},
	{ /* modparam dependencies */
		{ NULL, NULL}
	}
};

struct module_exports exports = {
	PROTO_PREFIX "msrp",  /* module name*/
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,               /* load function */
	&deps,           /* OpenSIPS module dependencies */
	cmds,       /* exported functions */
	0,          /* exported async functions */
	params,     /* module parameters */
	0,          /* exported statistics */
	mi_cmds,          /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,          /* exported transformations */
	0,          /* extra processes */
	0,          /* module pre-initialization function */
	mod_init,   /* module initialization function */
	0,          /* response function */
	mod_destroy,/* destroy function */
	0,          /* per-child init function */
	0           /* reload confirm function */
};

static int proto_msrp_init(struct proto_info *pi)
{
	pi->id					= PROTO_MSRP;
	pi->name				= "msrp";

	pi->tran.init_listener	= proto_msrp_init_listener;
	pi->tran.send			= proto_msrp_send;
	pi->tran.dst_attr		= tcp_conn_fcntl;

	pi->net.flags			= PROTO_NET_USE_TCP;
	pi->net.read			= (proto_net_read_f)msrp_read_req;
	pi->net.report			= msrp_report;

	return 0;
}

#ifdef MSRP_SELF_TESTING
#include "msrp_api.h"
void *self_hdl = NULL;

int self_req_hdl(struct msrp_msg *req, void *param)
{
	msrp_fwd_request( self_hdl, req, NULL, 0);
	return 0;
}

int self_rpl_hdl(struct msrp_msg *rpl, struct msrp_cell *tran, void *param)
{
	msrp_fwd_reply( self_hdl, rpl);
	return 0;
}
#endif


static int mod_init(void)
{
	LM_INFO("initializing MSRP-plain protocol\n");

	if (msrp_init_trans_layer( handle_msrp_timeout )<0) {
		LM_ERR("failed to init transactional layer\n");
		return -1;
	}

	if (trace_destination_name.s) {
		if ( !net_trace_api ) {
			if ( trace_prot_bind( MSRP_TRACE_PROTO, &tprot) < 0 ) {
				LM_ERR( "can't bind trace protocol <%s>\n", MSRP_TRACE_PROTO );
				return -1;
			}

			net_trace_api = &tprot;
		} else {
			tprot = *net_trace_api;
		}

		trace_destination_name.len = strlen( trace_destination_name.s );

		if ( net_trace_proto_id == -1 )
			net_trace_proto_id =
				tprot.get_message_id( MSRP_TRANS_TRACE_PROTO_ID );

		msrp_t_dst = tprot.get_trace_dest_by_name( &trace_destination_name );
	}

	/* fix route name */
	if ( !(msrp_trace_is_on = shm_malloc(sizeof(int))) ) {
		LM_ERR("no more shared memory!\n");
		return -1;
	}

	*msrp_trace_is_on = msrp_trace_is_on_tmp;
	if ( trace_filter_route ) {
		msrp_trace_filter_route_id =
			get_script_route_ID_by_name( trace_filter_route, sroutes->request,
				RT_NO);
	}

#ifdef MSRP_SELF_TESTING
	str host_all = str_init("*");
	self_hdl = register_msrp_handler( &host_all, 0, 0,
			self_req_hdl, self_rpl_hdl, NULL);
#endif

	return 0;
}


static void mod_destroy(void)
{
	msrp_destroy_trans_layer();
}


/**************  MI related functions ***************/

static mi_response_t *w_msrp_trace_mi(const mi_params_t *mi_params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if (add_mi_string_fmt(resp_obj, MI_SSTR("MSRP tracing"), "%s",
		*msrp_trace_is_on ? "on" : "off") < 0) {
		free_mi_response(resp);
		return 0;
	}

	return resp;
}


static mi_response_t *w_msrp_trace_mi_1(const mi_params_t *mi_params,
		struct mi_handler *async_hdl)
{
	str new_mode;

	if (get_mi_string_param(mi_params, "trace_mode",
	&new_mode.s, &new_mode.len) < 0)
		return init_mi_param_error();

	if ( new_mode.len==2 && strncasecmp( new_mode.s, "on", 2)==0) {
		*msrp_trace_is_on = 1;
		return init_mi_result_ok();
	} else
	if ( new_mode.len==3 && strncasecmp( new_mode.s, "off", 2)==0) {
		*msrp_trace_is_on = 0;
		return init_mi_result_ok();
	} else {
		return init_mi_error_extra(JSONRPC_INVAL_PARAMS_CODE,
			MI_SSTR(JSONRPC_INVAL_PARAMS_MSG),
			MI_SSTR("trace_mode should be 'on' or 'off'"));
	}
}
