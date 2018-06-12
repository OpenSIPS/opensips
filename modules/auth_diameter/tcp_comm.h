/*
 * $Id$
 *
 * Digest Authentication - Diameter support
 *
 * Copyright (C) 2001-2003 Fhg Fokus
 *
 * This file is part of ser, a free SIP server.
 *
 * ser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 * 
 * For a license to use the ser software under conditions
 * other than those described here, or to purchase support for this
 * software, please contact iptel.org by e-mail at the following addresses:
 *    info@iptel.org
 *
 * ser is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * -------
 *  
 *  
 */

#ifndef TCP_COMM_H
#define TCP_COMM_H

#include "defs.h"

#define MAX_WAIT_SEC	2
#define MAX_WAIT_USEC	0

#define MAX_AAA_MSG_SIZE  65536

#define CONN_SUCCESS	 1 
#define CONN_ERROR		-1
#define CONN_CLOSED		-2


void reset_read_buffer(rd_buf_t *rb);
int do_read( int socket, rd_buf_t *p);

/* it initializes the TCP connection */ 
int init_mytcp(char* host, char* port);

/* send a message over an already opened TCP connection */
int tcp_send_recv(int sockfd, char* buf, int len, rd_buf_t* resp,
					 unsigned int id);

void close_tcp_connection(int sfd);

#endif
