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

#ifndef _MI_DATAGRAM_H_
#define _MI_DATAGRAM_H_

#include <sys/socket.h>

/* maximum size for the socket reply name */
#define MAX_MI_FILENAME 128

/* size of buffer used by parser to read and build the MI tree */
#define MI_CHILD_NO	    1

#include <sys/un.h>
#include "../../ip_addr.h"

typedef union{
	union sockaddr_union udp_addr;
	struct sockaddr_un   unix_addr;
}sockaddr_dtgram;


#endif /* _MI_DATAGRAM */


