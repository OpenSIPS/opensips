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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
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


#include "ip_addr.h"
#include "io_wait.h"
#include "globals.h"

struct worker_io_data {
	/* source info buffer */
	union sockaddr_union* from_sa;
	/* received info */
	struct receive_info ri;
	/* SIP interface */
	struct socket_info *si;
};

enum reactor_prios {
	RCT_PRIO_NET=0,
	RCT_PRIO_ASYNC,
	RCT_PRIO_PROC,
	RCT_PRIO_TIMER,
	RCT_PRIO_MAX };

enum fd_types { F_NONE=0,
		/* generic fd types, to be handled by all SIP worker processes */
		F_TIMER_JOB,  F_FD_ASYNC, F_LAUNCH_ASYNC, F_IPC, F_SCRIPT_ASYNC=16,
		/* fd type specifc to UDP oriented processes (SIP workers) */
		F_UDP_READ,
		/* fd types specific to TCP oriented processes (SIP workers) */
		F_TCPMAIN, F_TCPCONN,
		/* fd types for TCP management process (TCP main process) */
		F_TCP_LISTENER, F_TCP_TCPWORKER, F_TCP_WORKER,
		/* fd type specific to FreeSWITCH ESL traffic (FS worker process) */
		F_FS_CONN,
		};

extern io_wait_h _worker_io;
extern unsigned int reactor_size;

int init_reactor_size(void);

#define init_worker_reactor( _name, _prio_max) \
	init_io_wait(&_worker_io, _name, reactor_size, io_poll_method, _prio_max)

#define reactor_add_reader( _fd, _type, _prio, _data) \
	io_watch_add(&_worker_io, _fd, _type, _data, _prio, 0, IO_WATCH_READ)

#define reactor_add_reader_with_timeout( _fd, _type, _prio, _t, _data) \
	io_watch_add(&_worker_io, _fd, _type, _data, _prio, _t, IO_WATCH_READ)

#define reactor_add_writer( _fd, _type, _prio, _data) \
	io_watch_add(&_worker_io, _fd, _type, _data, _prio, 0, IO_WATCH_WRITE)

#define reactor_del_reader( _fd, _idx, _io_flags) \
	io_watch_del(&_worker_io, _fd, _idx, _io_flags, IO_WATCH_READ)

#define reactor_del_writer( _fd, _idx, _io_flags) \
	io_watch_del(&_worker_io, _fd, _idx, _io_flags, IO_WATCH_WRITE)

#define reactor_del_all( _fd, _idx, _io_flags) \
	io_watch_del(&_worker_io, _fd, _idx, _io_flags, IO_WATCH_READ|IO_WATCH_WRITE)

#define destroy_worker_reactor() \
	destroy_io_wait(&_worker_io)

#define reactor_has_async() \
	(io_poll_method==POLL_POLL || io_poll_method==POLL_EPOLL)

#define reactor_is_empty() \
	(_worker_io.fd_no==0)

#define reactor_set_app_flag( _type, _app_flag) \
	io_set_app_flag( &_worker_io , _type, _app_flag)

#define reactor_check_app_flag(_app_flag) \
	io_check_app_flag( &_worker_io , _app_flag)

#endif

