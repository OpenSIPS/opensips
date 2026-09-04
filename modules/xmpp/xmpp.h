/*
 * XMPP Module
 * This file is part of opensips, a free SIP server.
 *
 * Copyright (C) 2006 Voice Sistem S.R.L.
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
 * Author: Andreea Spirea
 *
 */

#ifndef _MOD_XMPP_H
#define _MOD_XMPP_H

#include <stdio.h>
#include <string.h>

#include "../../config.h"
#include "../../str.h"

enum xmpp_pipe_cmd_type {
	XMPP_PIPE_SEND_PACKET     = 1,
	XMPP_PIPE_SEND_MESSAGE    = 2,
	XMPP_PIPE_SEND_PSUBSCRIBE = 4,
	XMPP_PIPE_SEND_PNOTIFY    = 8
};

struct xmpp_pipe_cmd {
	enum xmpp_pipe_cmd_type type;
	char *from, *to, *body, *id;
};

static inline int xmpp_encode_sip_uri(str *dst, char *buf, size_t buf_size,
		const char *src)
{
	const char *slash;
	size_t full_len, uri_len;
	int len;

	if (!dst || !buf || !src)
		return -1;

	full_len = strlen(src);
	slash = strchr(src, '/');
	uri_len = slash ? (size_t)(slash - src) : full_len;

	if (full_len > MAX_URI_SIZE - 4 ||
			full_len + sizeof("sip:") > buf_size)
		return -1;

	len = snprintf(buf, buf_size, "sip:%s", src);
	if (len < 0 || (size_t)len != full_len + 4 || len > MAX_URI_SIZE)
		return -1;

	dst->s = buf;
	dst->len = uri_len + 4;
	return 0;
}


/* configuration parameters */
extern char *xmpp_domain;
extern char *xmpp_host;
extern int xmpp_port;
extern char *xmpp_password;
extern str sip_domain;

extern int curr_fd;

/* mod_xmpp.c */
extern int xmpp_send_sip_msg(char *from, char *to, char *msg);
extern void xmpp_free_pipe_cmd(struct xmpp_pipe_cmd *cmd);

/* util.c */
char *extract_domain(char *jid);
char *random_secret(void);
char *db_key(char *secret, char *domain, char *id);
char* uri_sip2xmpp(str* uri);
char* uri_xmpp2sip(char* uri, int* len);


/* xmpp_server.c */
int xmpp_server_child_process(int data_pipe);

/* xmpp_component.c */
int xmpp_component_child_process(int data_pipe);

/* sha.c */
char *shahash(const char *str);

struct xmpp_private_data {
	int fd;		/* outgoing stream socket */
	int listen_fd;	/* listening socket */
	int in_fd;	/* incoming stream socket */
	int running;
	int authenticated;
};

void xmpp_server_net_send(struct xmpp_pipe_cmd *cmd);
void xmpp_component_net_send(struct xmpp_pipe_cmd *cmd,
		struct xmpp_private_data* priv);

#endif
