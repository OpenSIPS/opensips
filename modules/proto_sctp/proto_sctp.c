/*
 * Copyright (C) 2015 OpenSIPS Foundation
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
 *
 * History:
 * -------
 *  2015-02-12  first version (bogdan)
 */


#include "../../dprint.h"
#include "../../net/trans.h"
#include "../../sr_module.h"


#include "sctp_server.h"

static int sctp_port = SIP_PORT;

static int proto_sctp_init(struct proto_info *pi);

static cmd_export_t cmds[] = {
	{"proto_init", (cmd_function)proto_sctp_init, {{0, 0, 0}}, 0},
	{0,0,{{0,0,0}},0}
};


static param_export_t params[] = {
	{ "sctp_port",    INT_PARAM,    &sctp_port },
	{0, 0, 0}
};


struct module_exports exports = {
	PROTO_PREFIX "sctp",  /* module name*/
	MOD_TYPE_DEFAULT,    /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	NULL,            /* OpenSIPS module dependencies */
	cmds,       /* exported functions */
	0,          /* exported async functions */
	params,     /* module parameters */
	0,          /* exported statistics */
	0,          /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,			/* exported transformations */
	0,          /* extra processes */
	0,          /* module pre-initialization function */
	0,          /* module initialization function */
	0,          /* response function */
	0,          /* destroy function */
	0,          /* per-child init function */
	0           /* reload confirm function */
};


static int proto_sctp_init(struct proto_info *pi)
{
	pi->id					= PROTO_SCTP;
	pi->name				= "sctp";
	pi->default_port		= sctp_port;

	pi->tran.init_listener	= proto_sctp_init_listener;
	pi->tran.send			= proto_sctp_send;

	pi->net.flags			= PROTO_NET_USE_UDP;
	pi->net.read			= (proto_net_read_f)proto_sctp_read;

	return 0;
}



