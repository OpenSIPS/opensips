/*
 * Copyright (C) 2012 OpenSIPS Solutions
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
 * history:
 * ---------
 *  2012-12-xx  created (razvancrainea)
 */

#ifndef _EV_ROUTE_H_
#define _EV_ROUTE_H_

#define ROUTE_SEND_RETRY 3

/* transport protocol name */
#define SCRIPTROUTE_NAME		"route"
#define SCRIPTROUTE_NAME_STR	{ SCRIPTROUTE_NAME, sizeof(SCRIPTROUTE_NAME)-1}

/* module flag */
#define SCRIPTROUTE_FLAG		(1 << 26)

/* separation char */
#define COLON_C				':'

/* maximum length of the socket */
#define EV_SCRIPTROUTE_MAX_SOCK	256


#include "../sr_module.h"
#include "evi_transport.h"

evi_reply_sock* scriptroute_parse(str socket);
void scriptroute_free(evi_reply_sock *sock);
int scriptroute_raise(struct sip_msg *msg, str* ev_name,
	evi_reply_sock *sock, evi_params_t *params, evi_async_ctx_t *async_ctx);
int scriptroute_match(evi_reply_sock *sock1, evi_reply_sock *sock2);
str scriptroute_print(evi_reply_sock *sock);

/**
 * exported functions for core event interface
 */
static const evi_export_t trans_export_scriptroute = {
	SCRIPTROUTE_NAME_STR,	/* transport module name */
	scriptroute_raise,		/* raise function */
	scriptroute_parse,		/* parse function */
	scriptroute_match,		/* sockets match function */
	scriptroute_free,		/* no free function */
	scriptroute_print,		/* socket print function */
	SCRIPTROUTE_FLAG		/* flags */
};

typedef struct _route_send {
	struct script_route_ref *ev_route;
	str event;
	evi_params_t params;
} route_send_t;

int route_build_buffer(str *event_name, evi_reply_sock *sock,
		evi_params_t *params, route_send_t **msg);

int route_send(route_send_t *route_s);
void route_run(struct script_route route, struct sip_msg* msg,
		evi_params_t *params, str *event);

#endif