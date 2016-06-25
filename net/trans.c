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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *
 * history:
 * ---------
 *  2015-01-xx  created (razvanc)
 */

#include <string.h>
#include "trans.h"
#include "api_proto.h"
#include "../mem/mem.h"
#include "../sr_module.h"
#include "../socket_info.h"
#include "proto_tcp/proto_tcp_handler.h"
#include "proto_udp/proto_udp_handler.h"


/*
 * we need to always populate this structure at startup, at least the SIP
 * protocols, because we never know what kind of traffic we receive and have
 * to print its name
 */
struct proto_info protos[PROTO_LAST - PROTO_NONE] = {
	{ .name = NULL,  .default_rfc_port = 0 }, /* PROTO_NONE */

	{ .name = "udp",  .default_rfc_port = 5060 }, /* PROTO_UDP */
	{ .name = "tcp",  .default_rfc_port = 5060 }, /* PROTO_TCP */
	{ .name = "tls",  .default_rfc_port = 5061 }, /* PROTO_TLS */
	{ .name = "sctp", .default_rfc_port = 5060 }, /* PROTO_SCTP */
	{ .name = "ws",   .default_rfc_port = 80 },   /* PROTO_WS */
	/* populate here for other protos - not necessary right now */
};

static struct socket_id *cmd_listeners;

#define PROTO_PREFIX_LEN (sizeof(PROTO_PREFIX) - 1)

int trans_load(void)
{
	struct sr_module *mod;
	struct sr_module *prev = NULL, *next;
	cmd_export_t *cmd;
	char * proto_name;
	int proto = PROTO_NONE;
	api_proto_init abind;

	/* go through all protocol modules loaded and load only the ones
	 * that are prefixed with the PROTO_PREFIX token */
	for (mod=modules; mod && (next = mod->next, 1); mod = next) {
		if (strncmp(PROTO_PREFIX, mod->exports->name, PROTO_PREFIX_LEN) == 0) {
			proto_name = mod->exports->name + PROTO_PREFIX_LEN;
			if (parse_proto((unsigned char *)proto_name,
					strlen(proto_name), &proto) < 0) {
				LM_ERR("don't know any protocol <%s>\n", proto_name);
				return -1;
			}

			/* check if we have any listeners for that protocol */
			if (!protos[proto].listeners) {
				LM_WARN("protocol %s loaded, but no listeners defined! "
						"Skipping ...\n", proto_name);
				if (!prev)
					modules = mod->next;
				else
					prev->next = mod->next;

				/* we do not call the destroy_f because the module was not
				 * initialized yet here */
				pkg_free(mod);
				continue;
			}

			for (cmd = mod->exports->cmds; cmd && cmd->name; cmd++) {
				if (strcmp("proto_init", cmd->name)==0) {
					abind = (api_proto_init)cmd->function;
					if (abind(&protos[proto]) < 0) {
						LM_ERR("cannot load protocol's functions for %s\n",
								proto_name);
						return -1;
					}
					/* everything was fine, return */
					protos[proto].id = proto;
					protos[proto].name = proto_name;
					goto next;
				}
			}
			LM_ERR("No binding found for protocol %s\n", proto_name);
			return -1;
		}
next:
		prev = mod;
	}
	return 0;
}
#undef PROTO_PREFIX_LEN


int add_listener(struct socket_id *sock, enum si_flags flags)
{
	/*
	 * XXX: using the new version, the protocol _MUST_ be specified
	 * otherwise UDP will be assumed
	 */
	enum sip_protos proto = sock->proto;

	/* validate the protocol */
	if (proto < PROTO_FIRST || proto >= PROTO_LAST) {
		LM_BUG("invalid protocol number %d\n", proto);
		return -1;
	}

	/* convert to socket_info */
	if (new_sock2list(sock->name, sock->port, sock->proto, sock->adv_name, sock->adv_port,
			sock->children, flags, &protos[proto].listeners) < 0) {
		LM_ERR("cannot add socket to the list\n");
		return -1;
	}

	return 0;
}

int add_cmd_listener(char *name, int port, int proto)
{
	struct socket_id *tmp = pkg_malloc(sizeof(struct socket_id));
	if (!tmp) {
		fprintf(stderr, "no more pkg memory\n");
		return -1;
	}
	memset(tmp, 0, sizeof(struct socket_id));
	tmp->name = name;
	tmp->port = port;
	tmp->proto = proto;
	tmp->next = cmd_listeners;
	cmd_listeners = tmp;

	return 0;
}


int fix_cmd_listeners(void)
{
	struct socket_id *si, *prev;
	for (si = cmd_listeners; si;) {
		if (si->proto == PROTO_NONE)
			si->proto = PROTO_UDP;
		if (add_listener(si, 0) < 0)
			LM_ERR("Cannot add socket <%s>, skipping...\n", si->name);
		prev = si;
		si = si->next;
		pkg_free(prev);
	}
	return 0;
}


/*
 * return 0 on success, -1 on error */
int fix_all_socket_lists(void)
{
	int i;
	int found = 0;
	static char buf[5 /* currently sctp\0 is the largest protocol */];
	char *p;
#if 0
	/* TODO: decide what to do with this */
	struct utsname myname;

	if ((udp_listen==0)
			&& (tcp_listen==0)
			&& (tls_listen==0)
			&& (sctp_listen==0)
		){
		/* get all listening ipv4 interfaces */
		if (add_interfaces(0, AF_INET, 0,  PROTO_UDP, &udp_listen)==0){
			/* if ok, try to add the others too */
			if (!tcp_disable){
				if (add_interfaces(0, AF_INET, 0,  PROTO_TCP, &tcp_listen)!=0)
					goto error;
				if (!tls_disable){
					if (add_interfaces(0, AF_INET, 0, PROTO_TLS,
								&tls_listen)!=0)
					goto error;
				}
			}
			if (!sctp_disable){
				if (add_interfaces(0, AF_INET, 0, PROTO_SCTP, &sctp_listen)!=0)
					goto error;
			}
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

	for (i = PROTO_FIRST; i < PROTO_LAST; i++) {
		if (protos[i].id != PROTO_NONE) {
			if (fix_socket_list(&protos[i].listeners)!=0) {
				LM_ERR("fix_socket_list for %d failed\n", protos[i].id);
				goto error;
			}

			found++;
		} else if (protos[i].listeners) {
			p = proto2str(i, buf);
			if (p == NULL)
				goto error;
			*p = '\0';

			LM_ERR("listeners found for protocol %s, but no module "
					"can handle it\n", buf);
			goto error;
		}
	}

	if (!found){
		LM_ERR("no listening sockets\n");
		goto error;
	}
	return 0;
error:
	return -1;
}


int trans_init_all_listeners(void)
{
	struct socket_info *si;
	int i;

	for (i = PROTO_FIRST; i < PROTO_LAST; i++)
		if (protos[i].id != PROTO_NONE)
			for( si=protos[i].listeners ; si ; si=si->next ) {
				if (protos[i].tran.init_listener(si)<0) {
					LM_ERR("failed to init listener [%.*s], proto %s\n",
						si->name.len, si->name.s,
						protos[i].name );
					return -1;
				}
				/* set first IPv4 and IPv6 listeners for this proto */
				if ((si->address.af==AF_INET) &&
				(!protos[i].sendipv4 || (protos[i].sendipv4->flags&SI_IS_LO)))
					protos[i].sendipv4=si;
				if (!protos[i].sendipv6 && (si->address.af==AF_INET6))
					protos[i].sendipv6=si;
			}

	return 0;
}

void print_all_socket_lists(void)
{
	struct socket_info *si;
	int i;


	for (i = PROTO_FIRST; i < PROTO_LAST; i++) {
		if (protos[i].id == PROTO_NONE)
			continue;

		for (si = protos[i].listeners; si; si = si->next)
			printf("             %s: %s [%s]:%s%s\n", protos[i].name,
					si->name.s, si->address_str.s, si->port_no_str.s,
					si->flags & SI_IS_MCAST ? " mcast" : "");
	}
}
