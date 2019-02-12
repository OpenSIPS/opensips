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
 *  2015-02-05  created (bogdan)
 */

#ifndef _NET_net_tcp_proc_h
#define _NET_net_tcp_proc_h

/* Loop implementing a TCP worker */
void tcp_worker_proc_loop(void);
int tcp_worker_proc_reactor_init( int fd);

/* function to terminate TCP workers at runtime; it must be call within
 * the context of the process to be terminated */
void tcp_terminate_worker(void);

/*! \brief  releases expired connections and cleans up bad ones (state<0) */
void tcp_receive_timeout(void);

#endif
