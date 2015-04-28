/*
 * Various URI checks and Request URI manipulation
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../error.h"
#include "../../pvar.h"
#include "../../resolve.h"
#include "../../socket_info.h"
#include "db_checks.h"
#include "methods.h"

#define PLIST_DELIM ";"
#define PHP_BUFFER_SIZE 4+2+INET6_ADDRSTRLEN+1+5+10+5

/* Resolves R-URI host based on sip_resolvehost logic */
int uri_resolve(struct sip_msg* msg, char* _php, char* _plist) {
        static char resolve_buf[INET6_ADDRSTRLEN];
        static char php_buf[PHP_BUFFER_SIZE];
	static char tmp[MAX_DNS_NAME];
	char pbuf[5];
	char* save = NULL;
	char* p;
	unsigned short port;
	int proto;
	pv_value_t pv_plist;
	str* name;
        struct hostent* he;
	int_str php;
	int_str plist;

	if (pv_get_spec_value(msg, (pv_spec_t *)_plist, &pv_plist) != 0) {
		LM_ERR("failed to get pseudo variable proto value\n");
		return -1;
 	}

	if (!(pv_plist.flags & PV_VAL_STR)) {
		LM_ERR("pseudo variable plist is not type string\n");
		return -1;
	}

	name = &(msg->parsed_uri.host);  /* R-URI   host */
	port = SIP_PORT;		 /* default port */
	proto = PROTO_UDP;		 /* default proto */

        if (str2ip(name) != 0 || str2ip6(name) != 0)
		/* If it's an IP, bypass the SRV checks */
		p = NULL;
	else
		/* get the first protocol in the list */
		p = strtok_r(pv_plist.rs.s, PLIST_DELIM, &save);

	for (; p != NULL; p = strtok_r(NULL, PLIST_DELIM, &save)) {
		if (parse_proto((unsigned char *)p, (long)strlen(p), &proto) != 0) {
			LM_ERR("invalid protocol defined\n");
			return -1;
		}

		/* pilfered the srv builder from sip_resolvehost */
		switch (proto) {
			case PROTO_UDP:
				memcpy(tmp, SRV_UDP_PREFIX, SRV_UDP_PREFIX_LEN);
				memcpy(tmp+SRV_UDP_PREFIX_LEN, name->s, name->len);
				tmp[SRV_UDP_PREFIX_LEN + name->len] = '\0';
				break;
			case PROTO_TCP:
				memcpy(tmp, SRV_TCP_PREFIX, SRV_TCP_PREFIX_LEN);
				memcpy(tmp+SRV_TCP_PREFIX_LEN, name->s, name->len);
				tmp[SRV_TCP_PREFIX_LEN + name->len] = '\0';
				break;
			case PROTO_TLS:
				memcpy(tmp, SRV_TLS_PREFIX, SRV_TLS_PREFIX_LEN);
				memcpy(tmp+SRV_TLS_PREFIX_LEN, name->s, name->len);
				tmp[SRV_TLS_PREFIX_LEN + name->len] = '\0';
				break;
			default:
				return -1;
		}

        	he = do_srv_lookup( tmp, &port, NULL );

		if (he != 0)
			/* Finalize the successful results */
			goto finalize;
        }

	if (he == 0) {
		/* No SRV records, simply resolve the host
		   or the IP to get the address family */
		memcpy(tmp, name->s, name->len);
		tmp[name->len] = '\0';
		he = resolvehost(tmp, 0);
	}

	if (he == 0) { /* no results */
		LM_ERR("no results, return error\n");
		return -1;
	}

finalize:
	/* dig into multiple return addresses? */
	inet_ntop(he->h_addrtype, he->h_addr_list[0], resolve_buf, INET6_ADDRSTRLEN);

	proto2str(proto, pbuf); /* convert the int protocol to string representation */
	
	/* write the phost:port;proto to the pv */
	char *str = (he->h_addrtype == AF_INET) ? "sip:%s:%d;protocol=%s" : "sip:[%s]:%d;protocol=%s";
	php.s.len = snprintf(php_buf, PHP_BUFFER_SIZE, str, resolve_buf, port, pbuf);

	php.s.s = php_buf;
	set_result_pv(msg, AVP_VAL_STR, php, _php);

	/* save the remaining protocols in the list for failover */
	plist.s.s = save;
	if (plist.s.s)
		plist.s.len = strlen(plist.s.s);
	else
		plist.s.len = 0;
	set_result_pv(msg, AVP_VAL_STR, plist, _plist);

	return 1;
}

