/*
 * utilities
 *
 * Copyright (C) 2001-2003 FhG Fokus
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
 * History:
 * -------
 *  2003-02-13  added proto to uri2proxy (andrei)
 *  2003-04-09  uri2sock moved from uac.c (janakj)
 *  2003-04-14  added get_proto to determine protocol from uri unless
 *              specified explicitly (jiri)
 *  2003-07-07  get_proto takes now two protos as arguments (andrei)
 *              tls/sips support for get_proto & uri2proxy (andrei)
 */


#ifndef _TM_UT_H
#define _TM_UT_H


#include "../../proxy.h"
#include "../../str.h"
#include "../../parser/parse_uri.h"
#include "../../dprint.h"
#include "../../ut.h"
#include "../../ip_addr.h"
#include "../../error.h"
#include "../../forward.h"
#include "../../mem/mem.h"
#include "../../parser/msg_parser.h"

/* a forced_proto takes precedence if != PROTO_NONE */
inline static enum sip_protos get_proto(enum sip_protos force_proto,
										enum sip_protos proto)
{
	/* calculate transport protocol */
	if (force_proto == PROTO_NONE) {/* no protocol forced -- look at proto */
		if (proto >= PROTO_OTHER) {
			LM_ERR("unsupported transport: %d\n", proto );
			return PROTO_NONE;
		}
		/* lower values are valid protocols, including PROTO_NONE */
		return proto;
	}
	if (force_proto >= PROTO_OTHER) {
		LM_ERR("unsupported forced protocol: %d\n", force_proto);
		return PROTO_NONE;
	}
	return force_proto;
}



/*
 * Convert a URI into a proxy structure
 */
inline static struct proxy_l *uri2proxy( str *uri, int forced_proto )
{
	struct sip_uri parsed_uri;
	struct proxy_l *p;
	enum sip_protos proto;

	if (parse_uri(uri->s, uri->len, &parsed_uri) < 0) {
		LM_ERR("bad_uri: %.*s\n", uri->len, uri->s );
		return 0;
	}

	if (parsed_uri.type==SIPS_URI_T && ((parsed_uri.proto!=PROTO_WSS) &&
	(parsed_uri.proto!=PROTO_TLS) && (parsed_uri.proto!=PROTO_NONE)) ) {
		LM_ERR("bad transport for sips uri: %d\n", parsed_uri.proto);
		return 0;
	}
	proto=parsed_uri.proto;

	proto = get_proto(forced_proto, proto);

	p = mk_proxy(
		parsed_uri.maddr_val.len?&parsed_uri.maddr_val:&parsed_uri.host,
		parsed_uri.port_no, proto, (parsed_uri.type==SIPS_URI_T)?1:0 );
	if (p == 0) {
		LM_ERR("bad host name in URI <%.*s>\n", uri->len, ZSW(uri->s));
		return 0;
	}

	return p;
}


static inline int uri2su(str *uri, union sockaddr_union *to_su, int proto)
{
	struct proxy_l *proxy;

	proxy = uri2proxy(uri, proto);
	if (!proxy) {
		ser_error = E_BAD_ADDRESS;
		LM_ERR("failed create a dst proxy\n");
		return -1;
	}

	hostent2su(to_su, &proxy->host, proxy->addr_idx,
		(proxy->port) ? proxy->port : SIP_PORT);
	proto = proxy->proto;

	free_proxy(proxy);
	pkg_free(proxy);
	return proto;
}



/*
 * Convert a URI into socket_info
 */
static inline struct socket_info *uri2sock(struct sip_msg* msg, str *uri,
									union sockaddr_union *to_su, int proto)
{
	struct socket_info* send_sock;

	if ( (proto=uri2su(uri, to_su, proto))==-1 )
		return 0;

	send_sock = get_send_socket(msg, to_su, proto);
	if (!send_sock) {
		LM_ERR("no corresponding socket for af %d\n", to_su->s.sa_family);
		ser_error = E_NO_SOCKET;
	}

	return send_sock;
}


#endif /* _TM_UT_H */
