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
#include "net.h"
#include "../mem/mem.h"
#include "../sr_module.h"
#include "../socket_info.h"
#include "proto_tcp/proto_tcp_handler.h"


/* we alocate this dinamically because we don't know how when new protocols
 * are developed. Since this is done only once, it's not that bad */
struct proto_info *protos;
unsigned int proto_nr;

static struct socket_id *tmp_listeners;


int init_trans_interface(void)
{

	proto_nr = PROTO_OTHER - PROTO_NONE - 1;
	protos = pkg_malloc(proto_nr * sizeof(struct proto_info));
	if (!protos) {
		LM_ERR("no more memory to allocate protocols\n");
		return -1;
	}

	memset(protos, 0, proto_nr * sizeof(struct proto_info));

	if (init_net_interface(proto_nr) < 0) {
		LM_ERR("cannot init network interface\n");
		pkg_free(protos);
		return -1;
	}

	return 0;
}

#define PROTO_PREFIX_LEN (sizeof(PROTO_PREFIX) - 1)

int load_trans_proto(char *name, enum sip_protos proto)
{
	int len = strlen(name);
	char name_buf[/* PROTO_PREFIX */ PROTO_PREFIX_LEN + len + /* '\0' */ 1];
	int i;
	proto_bind_api proto_api;

	if (proto == PROTO_NONE) {
		LM_ERR("unknown protocol %s\n", name);
		goto error;
	}
	if (protos[proto - 1].id != PROTO_NONE) {
		if (proto != protos[proto - 1].id) {
			LM_BUG("inconsistent protocol id\n");
			goto error;
		}
		return 0;
	}

	/* load the protocol */
	memcpy(name_buf, PROTO_PREFIX, PROTO_PREFIX_LEN);
	memcpy(name_buf + PROTO_PREFIX_LEN, name, len);
	name_buf[len + PROTO_PREFIX_LEN] = '\0';

	/* lowercase the protocol */
	for (i = PROTO_PREFIX_LEN; i < PROTO_PREFIX_LEN + len; i++)
		name_buf[i] |= 0x20;


	/* check built-in protocols */
	switch (proto) {
#ifndef DISABLE_AUTO_TCP
	case PROTO_TCP:
		if (register_module(&proto_tcp_exports, "net/proto", 0) < 0) {
			LM_ERR("cannot load static TCP protocol\n");
			return -1;
		}
		break;
#endif
	case PROTO_UDP:
		/* TODO: handle UDP protocol */
	default:

		/* load module if not already loaded from script */
		if (!module_loaded(name_buf)) {

			char module_buf[/* PROTO_PREFIX */ PROTO_PREFIX_LEN + len +
				/* .so */ 3 + /* '\0' */ 1];
			strcpy(module_buf, name_buf);
			strcat(module_buf, ".so");

			if (load_module(module_buf) < 0) {
				LM_ERR("cannot load module %s\n", name_buf);
				goto error;
			}
		}
		break;
	}

	proto_api = (proto_bind_api)find_mod_export(name_buf,
			"proto_bind_api", 0, 0);
	if (!proto_api) {
		LM_ERR("cannot find transport API for protocol %s\n", name);
		goto error;
	}
	if (proto_api(&protos[proto - 1].binds,
			&proto_net_binds[proto - 1]) < 0) {
		LM_ERR("cannot bind transport API for protocol %s\n", name);
		goto error;
	}

	/* initialize the module */
	if (protos[proto - 1].binds.init && protos[proto - 1].binds.init() < 0) {
		LM_ERR("cannot initialzie protocol %s\n", name);
		goto error;
	}
	protos[proto - 1].id = proto;

	LM_DBG("Loaded <%.*s> protocol handlers\n", len, name_buf + 4);

	return 0;
error:
	return -1;
}
#undef PROTO_PREFIX_LEN


int add_listener(struct socket_id *sock, enum si_flags flags)
{
	/*
	 * XXX: using the new version, the protocol _MUST_ be specified
	 * otherwise UDP will be assumed
	 */
	enum sip_protos proto = sock->proto;
	struct proto_info *pi;
	int port;

	/* validate the protocol */
	if (proto < 0 || proto >= proto_nr) {
		LM_BUG("invalid protocol number %d\n", proto);
		return -1;
	}
	pi = &protos[proto - 1];
	if (pi->id == PROTO_NONE) {
		LM_BUG("protocol %d not registered\n", proto);
		return -1;
	}
	/* fix the socket's protocol */
	port = sock->port ? sock->port : pi->binds.default_port;

	/* convert to socket_info */
	if (new_sock2list(sock->name, port, sock->proto, sock->adv_name, sock->adv_port,
			sock->children, flags, &pi->listeners) < 0) {
		LM_ERR("cannot add socket to the list\n");
		return -1;
	}

/*
 * TODO: can't add them right away because we first have to resolve the hosts
 * and the resolver is not yet initialized
 *
	if (protos[proto - 1].binds.add_listener &&
			protos[proto - 1].binds.add_listener(sock->name, port) < 0) {
		LM_ERR("cannot add socket");
		return -1;
	}
*/
	return 0;
}

int add_tmp_listener(char *name, int port, int proto)
{
	struct socket_id *tmp = pkg_malloc(sizeof(struct socket_id));
	if (!tmp) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}
	memset(tmp, 0, sizeof(struct socket_id));
	tmp->name = name;
	tmp->port = port;
	tmp->proto = proto;
	tmp->next = tmp_listeners;
	tmp_listeners = tmp;

	return 0;
}


int fix_tmp_listeners(void)
{
	struct socket_id *si, *prev;
	for (si = tmp_listeners; si;) {
		if (add_listener(si, 0) < 0)
			LM_ERR("cannot add socket <%s>, skipping...\n", si->name);
		prev = si;
		si = si->next;
		pkg_free(prev);
	}
	return 0;
}

int add_all_listeners(struct socket_info *si, proto_add_listener_f add_func)
{
	for (; si; si = si->next)
		if (add_func(si) < 0) {
			LM_ERR("cannot add listener %.*s\n", si->name.len, si->name.s);
			return -1;
		}
	return 0;
}

/*
 * return 0 on success, -1 on error */
int fix_all_socket_lists(void)
{
	int i;
	int found = 0;
#if 0
	/* TODO: decide what to do with this */
	struct utsname myname;

	if ((udp_listen==0)
#ifdef USE_TCP
			&& (tcp_listen==0)
#ifdef USE_TLS
			&& (tls_listen==0)
#endif
#endif
#ifdef USE_SCTP
			&& (sctp_listen==0)
#endif
		){
		/* get all listening ipv4 interfaces */
		if (add_interfaces(0, AF_INET, 0,  PROTO_UDP, &udp_listen)==0){
			/* if ok, try to add the others too */
#ifdef USE_TCP
			if (!tcp_disable){
				if (add_interfaces(0, AF_INET, 0,  PROTO_TCP, &tcp_listen)!=0)
					goto error;
#ifdef USE_TLS
				if (!tls_disable){
					if (add_interfaces(0, AF_INET, 0, PROTO_TLS,
								&tls_listen)!=0)
					goto error;
				}
#endif
			}
#endif
#ifdef USE_SCTP
			if (!sctp_disable){
				if (add_interfaces(0, AF_INET, 0, PROTO_SCTP, &sctp_listen)!=0)
					goto error;
			}
#endif
		}else{
			/* if error fall back to get hostname */
			/* get our address, only the first one */
			if (uname (&myname) <0){
				LM_ERR("cannot determine hostname, try -l address\n");
				goto error;
			}
			if (add_listen_iface(myname.nodename, 0, 0, 0, 0, 0, 0)!=0){
				LM_ERR("add_listen_iface failed \n");
				goto error;
			}
		}
	}
#endif

	for (i = 0; i < proto_nr; i++)
		if (protos[i].id != PROTO_NONE) {
			if (fix_socket_list(&protos[i].listeners)!=0) {
				LM_ERR("fix_socket_list for %d failed\n", protos[i].id);
				goto error;
			}

			/* add all sockets to the protocol list */
			if (add_all_listeners(protos[i].listeners, protos[i].binds.add_listener)!=0) {
				LM_ERR("cannot add listeners for proto %d\n", protos[i].id);
				goto error;
			}

			found++;
		}

	if (!found){
		LM_ERR("no listening sockets\n");
		goto error;
	}
	return 0;
error:
	return -1;
}

void print_all_socket_lists(void)
{
	struct socket_info *si;
	int i;


	for (i = 0; i < proto_nr; i++) {
		if (protos[i].id == PROTO_NONE)
			continue;

		for (si = protos[i].listeners; si; si = si->next)
			printf("             %s: %s [%s]:%s%s\n", protos[i].binds.name,
					si->name.s, si->address_str.s, si->port_no_str.s,
					si->flags & SI_IS_MCAST ? " mcast" : "");
	}
}
