/*
 * Copyright (C) 2014-2015 OpenSIPS Solutions
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
 */



#ifndef _NET_proto_udp_h
#define _NET_proto_udp_h

typedef int (udp_rcv_cb_f)(int sockfd, struct receive_info *ri,
													str* msg, void* param);

typedef struct cb_list{
	udp_rcv_cb_f* func;     /* function to be called */
	void* param;            /* extra parameter */
	char a;                 /* first byte of message */
	char b;                 /* second byte of message */
	struct cb_list* next;   /* linked list */
}callback_list;


int register_udprecv_cb(udp_rcv_cb_f* func, void* param, char a, char b);


#endif
