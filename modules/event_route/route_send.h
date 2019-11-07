/*
 * Copyright (C) 2014 VoIP Embedded, Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 *
 */


#ifndef _ROUTE_SEND_H_
#define _ROUTE_SEND_H_


#define ROUTE_SEND_RETRY 3

typedef struct _route_send {
	int ev_route_id;
	str event;
	evi_params_t params;
} route_send_t;

int route_build_buffer(str *event_name, evi_reply_sock *sock,
		evi_params_t *params, route_send_t **msg);

int route_send(route_send_t *route_s);
void route_run(struct action* a, struct sip_msg* msg,
		evi_params_t *params, str *event);

#endif
