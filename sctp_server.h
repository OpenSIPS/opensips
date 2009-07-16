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
 *
 * History
 * --------
 *  2007-06-22	sctp_server.h created, using udp_server.h as template -gmarmon
 */

/*!
 * \file
 * \brief SCTP protocol support
 */

#ifdef USE_SCTP

#ifndef sctp_server_h
#define sctp_server_h

#include <netinet/sctp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "ip_addr.h"

int sctp_server_init(struct socket_info* si);
int sctp_server_send(struct socket_info* source,char *buf, unsigned len,
				union sockaddr_union*  to);
int sctp_server_rcv_loop();


#endif
#endif
