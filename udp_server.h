/*
 * $Id$
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
 */


#ifndef udp_server_h
#define udp_server_h

#include <sys/types.h>
#include <sys/socket.h>
#include "ip_addr.h"

typedef int (callback_f)(int sockfd, struct sockaddr_in* from,
                            char* buffer, int size, void* param);

typedef struct cb_list{
    callback_f* func;       /* function to be called */
    void* param;            /* extra parameter */
    char a;                 /* first byte of message */
    char b;                 /* second byte of message */
    struct cb_list* next;   /* linked list */
}callback_list;

int udp_init(struct socket_info* si);
int udp_send(struct socket_info* source,char *buf, unsigned len,
				union sockaddr_union*  to);
int udp_rcv_loop();

int register_udprecv_cb(callback_f func, void* param, char a, char b);

#endif
