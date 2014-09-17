/*
 * Copyright (C) 2014 OpenSIPS Solutions
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *
 * history:
 * ---------
 *  2014-08-25  created (bogdan)
 */


#ifndef _REACTOR_DEFS_H_
#define _REACTOR_DEFS_H_

/*  This should be included by files where the reactor is used (in terms of 
 *  submitting fd's to it).
 *  The header file provides both the reactor definitions, the fd manipulation
 *  functions, but NO looping and triggering functions.
 *  IF you need to implement a reactor core (looping, triggering), use
 *  the reactor.h file directly !!!
 */


#include "io_wait.h"

struct worker_io_data {
	/* source info buffer */
	union sockaddr_union* from_sa;
	/* received info */
	struct receive_info ri;
	/* SIP interface */
	struct socket_info *si;
};

enum fd_types { F_NONE=0, F_TIMER_JOB=1, F_UDP_READ=2, F_TCPMAIN=4, F_TCPCONN=8 };

extern io_wait_h _worker_io;

#define init_worker_reactor( _max_fd, _async) \
	init_io_wait(&_worker_io, _max_fd, io_poll_method, _async)

#define reactor_add_reader( _fd, _type, _data) \
	io_watch_add(&_worker_io, _fd, _type, _data, IO_WATCH_READ)

#define reactor_del_reader( _fd, _idx, _io_flags) \
	io_watch_del(&_worker_io, _fd, _idx, _io_flags, IO_WATCH_READ)

#define reactor_del_all( _fd, _idx, _io_flags) \
	io_watch_del(&_worker_io, _fd, _idx, _io_flags, IO_WATCH_READ|IO_WATCH_WRITE)


#define destroy_worker_reactor() \
	destroy_io_wait(&_worker_io)

#endif

