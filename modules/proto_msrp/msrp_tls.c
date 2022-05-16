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

#include "../../trace_api.h"
#include "../../net/net_tcp.h"
#include "../../net/net_tcp_report.h"
#include "../../net/trans_trace.h"
#include "msrp_common.h"


int msrps_conn_extra_match(struct tcp_connection *c, void *id)
{
	return tls_mgm_api.tls_conn_extra_match(c, id);
}


int proto_msrps_conn_init(struct tcp_connection* c)
{
	struct tls_domain *dom;

	if ( c->flags&F_CONN_ACCEPTED ) {
		LM_DBG("looking up TLS server "
			"domain [%s:%d]\n", ip_addr2a(&c->rcv.dst_ip), c->rcv.dst_port);
		dom = tls_mgm_api.find_server_domain(&c->rcv.dst_ip, c->rcv.dst_port);
	} else {
		dom = tls_mgm_api.find_client_domain(&c->rcv.src_ip, c->rcv.src_port);
	}
	if (!dom) {
		LM_ERR("no TLS %s domain found\n",
				(c->flags&F_CONN_ACCEPTED?"server":"client"));
		return -1;
	}

	return tls_mgm_api.tls_conn_init(c, dom);
}


void proto_msrps_conn_clean(struct tcp_connection* c)
{
	struct tls_domain *dom;

	tls_mgm_api.tls_conn_clean(c, &dom);

	if (!dom)
		LM_ERR("Failed to retrieve the TLS domain from the SSL struct\n");
	else
		tls_mgm_api.release_domain(dom);
}


void msrps_report(int type, unsigned long long conn_id, int conn_flags,
		void *extra)
{
	str s;

	if (type==TCP_REPORT_CLOSE) {

		if ( !TRACE_ON( conn_flags ) )
			return;

		/* grab reason text */
		if (extra) {
			s.s = (char*)extra;
			s.len = strlen (s.s);
		}

		trace_message_atonce( PROTO_MSRPS, conn_id, NULL/*src*/, NULL/*dst*/,
			TRANS_TRACE_CLOSED, TRANS_TRACE_SUCCESS, extra?&s:NULL,
			msrp_t_dst );
	}
}


int msrps_write_on_socket(struct tcp_connection *c, int fd,
		char *buf, int len, int handshake_timeout, int send_timeout)
{
	int n;

	lock_get(&c->write_lock);
	n = tls_mgm_api.tls_blocking_write(c, fd, buf, len,
			handshake_timeout, send_timeout, msrp_t_dst);
	lock_release(&c->write_lock);

	return n;
}


