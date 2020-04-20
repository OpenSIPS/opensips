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
	{ .name = "wss",  .default_rfc_port = 443 },  /* PROTO_WSS */
	/* populate here for other protos - not necessary right now */
};

static struct socket_id *cmd_listeners;

#define PROTO_PREFIX_LEN (sizeof(PROTO_PREFIX) - 1)

int trans_load(void)
{
	int id;
	struct sr_module *mod;
	cmd_export_t *cmd;
	int found_all = 0;
	int found_proto;
	api_proto_init abind;
	struct proto_info pi;

	/* go through all protocol modules loaded and load only the ones
	 * that are prefixed with the PROTO_PREFIX token */
	for (mod = modules; mod; mod = mod->next) {
		if (strncmp(PROTO_PREFIX, mod->exports->name, PROTO_PREFIX_LEN) != 0)
			continue;
		found_proto = 0;
		/* we have a transport module here - check for protocols */
		for (cmd = mod->exports->cmds; cmd && cmd->name; cmd++) {
			if (strcmp("proto_init", cmd->name)!=0)
				continue;
			abind = (api_proto_init)cmd->function;
			memset(&pi, 0, sizeof(pi));
			if (abind(&pi) < 0) {
				LM_ERR("cannot load protocol's functions for %s\n",
						cmd->name);
				return -1;
			}
			/* double check if it is a known/valid proto */
			if (pi.id < PROTO_FIRST || pi.id >= PROTO_OTHER) {
				LM_ERR("Unknown protocol id %d; check sip_protos structure!\n", pi.id);
				return -1;
			}
			/* double check the name of the proto */
			if (parse_proto((unsigned char *)pi.name, strlen(pi.name), &id) < 0) {
				LM_ERR("Cannot parse protocol %s\n", pi.name);
				return -1;
			}
			if (id != pi.id) {
				LM_ERR("Protocol ID mismatch %d != %d\n", id, pi.id);
				return -1;
			}
			found_proto = 1;
			/* check if there is any listener for this protocol */
			if (!proto_has_listeners(pi.id)) {
				LM_DBG("No listener defined for proto %s\n", pi.name);
				continue;
			}

			/* check if already added */
			if (protos[id].id != PROTO_NONE) {
				LM_ERR("Protocol already loaded %s\n", pi.name);
				return -1;
			}
			/* all good now */
			found_all++;
			/* copy necessary info */
			protos[pi.id].id = pi.id;
			protos[pi.id].name = pi.name;
			protos[pi.id].default_port = pi.default_port;
			protos[pi.id].tran = pi.tran;
			protos[pi.id].net = pi.net;
		}
		if (found_proto)
			continue;
		LM_ERR("No binding found for protocol %s\n", mod->exports->name);
		return -1;
	}
	/* return whether we found any protocol or not */
	return found_all;
}
#undef PROTO_PREFIX_LEN


int add_listening_socket(struct socket_id *sock)
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
	if (new_sock2list(sock, &protos[proto].listeners) < 0) {
		LM_ERR("cannot add socket to the list\n");
		return -1;
	}

	return 0;
}

int add_cmd_listening_socket(char *name, int port, int proto)
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


int fix_cmd_listening_sockets(void)
{
	struct socket_id *si, *prev;
	for (si = cmd_listeners; si;) {
		if (si->proto == PROTO_NONE)
			si->proto = PROTO_UDP;
		if (add_listening_socket(si) < 0)
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
	static char buf[PROTO_NAME_MAX_SIZE /* currently we shouldn't hardcode that much */];
	char *p;

	for (i = PROTO_FIRST; i < PROTO_LAST; i++) {
		if (protos[i].id != PROTO_NONE) {
			if (fix_socket_list(&protos[i].listeners)!=0) {
				LM_ERR("fix_socket_list for %d failed\n", protos[i].id);
				goto error;
			}

			found++;
		} else if (proto_has_listeners(i)) {
			p = proto2str(i, buf);
			if (p == NULL)
				goto error;
			*p = '\0';

			LM_ERR("listeners found for protocol %s, but no module "
					"can handle it, %d, %d \n", buf,i,protos[i].id);
			goto error;
		}
	}

	if (!found && !testing_framework) {
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
				if ((si->address.af==AF_INET6) &&
				(!protos[i].sendipv6 || (protos[i].sendipv6->flags&SI_IS_LO)))
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
			printf("             %s: %s [%s]:%s%s%s\n", protos[i].name,
					si->name.s, si->address_str.s, si->port_no_str.s,
					si->flags & SI_IS_MCAST ? " mcast" : "",
					is_anycast(si)? " anycast" : "");
	}
}
