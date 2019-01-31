/*
 * Copyright (C) 2007 Voice Sistem SRL
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
 * History:
 * ---------
 *  2007-06-25  first version (ancuta)
 */

#ifndef _DATAGRAM_FNC_H
#define _DATAGRAM_FNC_H

#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include "../../ip_addr.h"
#include "../../str.h"
#include "../../dprint.h"
#include "../../ut.h"
#include "../../mi/mi.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"

#include "mi_datagram.h"

#define DATAGRAM_SOCK_BUF_SIZE 65457

#define MI_PARSE_ERROR					 "400 Parse_error"
#define MI_PARSE_ERROR_LEN               (sizeof(MI_PARSE_ERROR)-1)

#define MI_INTERNAL_ERROR                "500 Internal error"
#define MI_INTERNAL_ERROR_LEN            (sizeof(MI_INTERNAL_ERROR)-1)

typedef struct rx_tx{
	int rx_sock, tx_sock;
}rx_tx_sockets;

int  mi_init_datagram_server(sockaddr_dtgram * address, unsigned int domain,
								rx_tx_sockets * socks,int mode,
								int uid, int gid );
int mi_init_datagram_buffer();
void mi_datagram_server(int rx_sock, int tx_sock);
#endif /*_DATAGRAM_FNC_H*/
