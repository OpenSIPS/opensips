/*
 * Copyright (C) 2015-2021 - OpenSIPS Foundation
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
 */

#include "../../trace_api.h"

#define TLS_TRACE_IS_ON( CONN ) (CONN->proto_data && \
		((struct tls_data*)CONN->proto_data)->tprot && \
			((struct tls_data*)CONN->proto_data)->dest && \
			*((struct tls_data*)CONN->proto_data)->trace_is_on)

struct tls_data {
	TRACE_PROTO_COMMON;
};

void tls_send_trace_data(struct tcp_connection *c, trace_dest t_dst) {
	struct tls_data* data;

	if ( (c->flags&F_CONN_ACCEPTED)==0 && c->proto_flags & F_TLS_TRACE_READY ) {
		data = c->proto_data;

		/* send the message if set from tls_mgm */
		if ( data->message ) {
			send_trace_message( data->message, t_dst);
			data->message = NULL;
		}

		/* don't allow future traces for this connection */
		data->tprot = 0;
		data->dest  = 0;

		c->proto_flags &= ~( F_TLS_TRACE_READY );
	}
}
