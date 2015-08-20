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

#define ENC_SIP_URI(dst, buf, src) \
	do{\
		char* slash = strchr(src, '/'); \
		if(slash)\
			dst.len = slash - src + 4;\
		else\
			dst.len = strlen(src) + 4; \
		dst.s = buf;\
		sprintf(buf, "sip:%s", src);\
	}while(0)

struct xmpp_private_data {
	int fd;		/* outgoing stream socket */
	int listen_fd;	/* listening socket */
	int in_fd;	/* incoming stream socket */
	int running;
};

void xmpp_server_net_send(struct xmpp_pipe_cmd *cmd);
void xmpp_component_net_send(struct xmpp_pipe_cmd *cmd,
		struct xmpp_private_data* priv);

#endif
