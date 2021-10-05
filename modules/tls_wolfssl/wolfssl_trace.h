/*
 * Copyright (C) 2015 - 2021 OpenSIPS Foundation
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

#ifndef WOLFSSL_TRACE_H
#define WOLFSSL_TRACE_H

#include "../../trace_api.h"
#include "../../net/trans_trace.h"
#include "../tls_mgm/tls_helper.h"
#include "../tls_mgm/tls_trace_common.h"

static inline void tls_append_cert_info(WOLFSSL_X509 *cert, char client,
	trace_message message, trace_proto_t* tprot)
{
	str subj, issuer;

	if (!cert || !message || !tprot)
		return;

	subj.s   = wolfSSL_X509_NAME_oneline(wolfSSL_X509_get_subject_name(cert), 0, 0);
	issuer.s = wolfSSL_X509_NAME_oneline(wolfSSL_X509_get_issuer_name(cert), 0, 0);

	subj.len = strlen(subj.s);
	issuer.len = strlen(issuer.s);

	if (client) {
		add_trace_data(message, "client-subject", &subj);
		add_trace_data(message, "client-issuer", &issuer);
	} else {
		add_trace_data(message, "server-subject", &subj);
		add_trace_data(message, "server-issuer", &issuer);
	}

	wolfSSL_Free(subj.s);
	wolfSSL_Free(issuer.s);
}

static inline void tls_append_master_secret(WOLFSSL *ssl, struct tls_data* data)
{
	static char ssl_print_master_buf[WOLFSSL_MAX_MASTER_KEY_LENGTH * 2];
	str master;
	SSL_SESSION* s;

	s = wolfSSL_get1_session(ssl);
	if ( !s ) {
		LM_DBG("no session to get master key from!\n");
		return;
	}

	master.s = ssl_print_master_buf;
	master.len = wolfSSL_SESSION_get_master_key(s, (unsigned char *)master.s,
		SSL_MAX_MASTER_KEY_LENGTH * 2);

	data->tprot->add_payload_part( data->message, "master-key", &master);

	wolfSSL_SESSION_free(s);
}

static void add_certificates(WOLFSSL *ssl, struct tls_data* data)
{
	WOLFSSL_X509* cert;

	cert = wolfSSL_get_peer_certificate(ssl);
	tls_append_cert_info(cert, 1/* client */, data->message, data->tprot);

	cert = wolfSSL_get_certificate(ssl);
	tls_append_cert_info(cert, 0/* server */, data->message, data->tprot);
}

static inline int _wolfssl_trace_tls(struct tcp_connection* conn, WOLFSSL *ssl,
	trans_trace_event event, trans_trace_status status, str* message)
{
	struct tls_data* data;
	union sockaddr_union src, dst;

	if ( !conn || !TLS_TRACE_IS_ON(conn) || !(data=conn->proto_data) )
		return 0;

	if ( data->trace_route_id != -1 ) {
		check_trace_route( data->trace_route_id, conn );
		/* avoid doing this multiple times */
		data->trace_route_id = -1;
	}

	/* check if tracing is deactivated from the route for this connection */
	if ( conn->flags & F_CONN_TRACE_DROPPED )
		return 0;

	if ( !data->message ) {
		if ( tcpconn2su( conn, &src, &dst ) < 0 ) {
			LM_ERR("can't get network info from connection!\n");
			return -1;
		}

		data->message = create_trace_message( conn->cid, &src, &dst,
				conn->type, data->dest );
		if ( !data->message ) {
			LM_ERR("failed to create trace message!\n");
			return -1;
		}
	}

	add_certificates(ssl, data);
	tls_append_master_secret(ssl, data);

	add_trace_data( data->message, "Event", &trans_trace_str_event[event]);
	add_trace_data( data->message, "Status", &trans_trace_str_status[status]);

	if ( message && message->s && message->len) {
		add_trace_data( data->message, "Message", message);
	}

	conn->proto_flags |= F_TLS_TRACE_READY;

	return 0;
}

#endif	/* WOLFSSL_TRACE_H */
