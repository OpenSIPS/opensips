/*
 * Copyright (C) 2015 OpenSIPS Project
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *
 * history:
 * ---------
 *  2015-01-xx  created (razvanc)
 */

#include <string.h>
#include "trans.h"
#include "proto.h"
#include "../mem/mem.h"
#include "../sr_module.h"


/* we alocate this dinamically because we don't know how when new protocols
 * are developed. Since this is done only once, it's not that bad */
struct proto_info *protos;
unsigned int proto_nr;


int init_trans_interface(void)
{
//	unsigned int i;

	proto_nr = PROTO_OTHER - PROTO_NONE - 1;
	protos = pkg_malloc(proto_nr * sizeof(struct proto_info));
	if (!protos) {
		LM_ERR("no more memory to allocate protocols\n");
		return -1;
	}

	memset(protos, 0, proto_nr * sizeof(struct proto_info));
//	for (i = 0; i < proto_nr; i++)
//		protos[i].id = i + 1;

	return 0;
}

enum sip_protos get_proto_id(char *s, int len)
{
#define PROTO2UINT(a, b, c) ((	(((unsigned int)(a))<<16)+ \
								(((unsigned int)(b))<<8)+  \
								((unsigned int)(c)) ) | 0x20202020)
	unsigned int i;

	/* must support 3-char arrays for udp, tcp, tls,
	 * must support 4-char arrays for sctp */
	if (len < 2 || len > 4)
		goto error;

	i=PROTO2UINT(s[0], s[1], s[2]);
	switch(i){
		case PROTO2UINT('u', 'd', 'p'):
			if(len == 3)
				return PROTO_UDP;
			break;
#ifdef USE_TCP
		case PROTO2UINT('t', 'c', 'p'):
			if(len == 3)
				return PROTO_TCP;
			break;
#ifdef USE_TLS
		case PROTO2UINT('t', 'l', 's'):
			if(len == 3)
				return PROTO_TLS;
			break;
#endif
#endif
#ifdef USE_SCTP
		case PROTO2UINT('s', 'c', 't'):
			if(len == 4 && (s[3]=='p' || s[3]=='P'))
				return PROTO_SCTP;
			break;
#endif
	}
error:
	return PROTO_NONE;
#undef PROTO2UINT
}

enum sip_protos get_trans_proto(char *name)
{
	int len = strlen(name);
	char name_buf[/* net_ */ 4 + len + /* .so */ 3 + /* '\0' */ + 1];
	enum sip_protos proto = get_proto_id(name, len);
	int i;
	proto_bind_api proto_api;

	if (proto == PROTO_NONE) {
		LM_ERR("unknown protocol %s\n", name);
		goto end;
	}
	if (protos[proto - 1].id == PROTO_NONE) {
		/* load the protocol */
		memcpy(name_buf, "net_", 4);
		memcpy(name_buf + 4, name, len);
		memcpy(name_buf + len + 4, ".so", 3);
		/* lowercase the protocol */
		for (i = 5; i < 5 + len; i++)
			name_buf[i] |= 0x20;
		name_buf[len + 7] = '\0';

		if (load_module(name_buf) < 0) {
			LM_ERR("cannot load module %s\n", name_buf);
			goto end;
		}
		proto_api = (proto_bind_api)find_export("proto_bind_api", 0, 0);
		if (!proto_api) {
			LM_ERR("cannot find transport API for protocol %s\n", name);
			goto end;
		}
		if (proto_api(&protos[proto - 1].funcs) < 0) {
			LM_ERR("cannot bind transport API for protocol %s\n", name);
			goto end;
		}

		/* initialize the module */
		if (protos[proto - 1].funcs.init && protos[proto - 1].funcs.init() < 0) {
			LM_ERR("cannot initialzie protocol %s\n", name);
			goto end;
		}
		protos[proto - 1].id = proto;

		LM_DBG("Loaded <%.*s> protocol handlers\n", len, name_buf + 4);
	}

	return proto;
end:
	return PROTO_NONE;
}
