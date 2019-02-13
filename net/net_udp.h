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

#ifndef _NET_UDP_H_
#define _NET_UDP_H_

#include "../socket_info.h"


/**************************** Control functions ******************************/

/* initializes the UDP network layer */
int udp_init(void);

/* destroys the UDP network layer */
void udp_destroy(void);

/* tells how mnay processes the UDP layer will create */
int udp_count_processes(unsigned int *extra);

/* starts all UDP related processes */
int udp_start_processes(int *chd_rank, int *startup_done);

/**************************** Listener functions *****************************/

struct socket_info* udp_find_listener(union sockaddr_union* to, int proto);

/* initializes an already defined TCP listener */
int udp_init_listener(struct socket_info *si, int status_flags);

#endif /* _NET_UDP_H_ */
