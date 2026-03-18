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
#include "../../net/tcp_common.h"
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
	if (fd < 0) {
		n = tcp_async_add_chunk(c, buf, len, 0);
		if (n == 0)
			n = len;
	} else {
		n = tls_mgm_api.tls_blocking_write(c, fd, buf, len,
				handshake_timeout, send_timeout, msrp_t_dst);
	}
	lock_release(&c->write_lock);
	if (fd >= 0 && n > 0)
		tcp_conn_reset_lifetime(c);

	return n;
}

int msrps_async_write(struct tcp_connection *c, int fd)
{
	int n;
	struct tcp_async_chunk *chunk;

	n = tls_mgm_api.tls_fix_read_conn(c, fd, msrp_tls_handshake_timeout,
			msrp_t_dst, 0);
	if (n < 0) {
		LM_ERR("failed to do pre-tls handshake!\n");
		return -1;
	} else if (n == 0) {
		LM_DBG("SSL accept/connect still pending!\n");
		return 1;
	}

	tls_mgm_api.tls_update_fd(c, fd);

	while ((chunk = tcp_async_get_chunk(c)) != NULL) {
		LM_DBG("Trying to send %d bytes from chunk %p in conn %p - %d %d \n",
				chunk->len, chunk, c, chunk->ticks, get_ticks());

		n = tls_mgm_api.tls_write(c, fd, chunk->buf, chunk->len, NULL);
		if (n == 0) {
			LM_DBG("Can't finish to write chunk %p on conn %p\n",
					chunk, c);
			return 1;
		} else if (n < 0) {
			return -1;
		}

		tcp_async_update_write(c, n);
		tcp_conn_reset_lifetime(c);
	}

	return 0;
}
