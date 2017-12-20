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
 *  2014-08-23  created (bogdan)
 */


#ifndef _REACTOR_H_
#define _REACTOR_H_

/*  This should be included by files where the reactor core (looping,
 *  triggering) is implemented.
 *  The header file provides both the reactor definitions, the fd manipulation
 *  functions, but looping and triggering too.
 *  IF you need just to use the reactor (in terms of submitting fd's to it), use
 *  only the reactor_defs.h file !!!
 */

#include "reactor_defs.h"

#define HANDLE_IO_INLINE
#include "io_wait_loop.h"
//#include <fcntl.h> /* must be included after io_wait.h if SIGIO_RT is used */

#ifdef HAVE_SELECT
#define reactor_SELECT_CASE(_timeout_sec, _loop_extra) \
		case POLL_SELECT: \
			while(1){ \
				io_wait_loop_select(&_worker_io, _timeout_sec, 0); \
				_loop_extra;\
			} \
			break;
#else
#define reactor_SELECT_CASE(_timeout_sec, _loop_extra)
#endif


#ifdef HAVE_SIGIO_RT
#define reactor_SIGIORT_CASE(_timeout_sec, _loop_extra) \
		case POLL_SIGIO_RT: \
			while(1){ \
				io_wait_loop_sigio_rt(&_worker_io, _timeout_sec); \
				_loop_extra;\
			} \
			break;
#else
#define reactor_SIGIORT_CASE(_timeout_sec, _loop_extra)
#endif


#ifdef HAVE_EPOLL
#define reactor_EPOLL_CASE(_timeout_sec,_loop_extra) \
		case POLL_EPOLL: \
			while(1){ \
				io_wait_loop_epoll(&_worker_io, _timeout_sec, 0); \
				_loop_extra;\
			} \
			break;
#else
#define reactor_EPOLL_CASE(_timeout_sec, _loop_extra)
#endif


#ifdef HAVE_KQUEUE
#define reactor_KQUEUE_CASE(_timeout_sec, _loop_extra) \
		case POLL_KQUEUE: \
			while(1){ \
				io_wait_loop_kqueue(&_worker_io, _timeout_sec, 0); \
				_loop_extra;\
			} \
			break;
#else
#define reactor_KQUEUE_CASE(_timeout_sec, _loop_extra)
#endif


#ifdef HAVE_DEVPOLL
#define reactor_DEVPOLL_CASE(_timeout_sec, _loop_extra) \
		case POLL_DEVPOLL: \
			while(1){ \
				io_wait_loop_devpoll(&_worker_io, _timeout_sec, 0); \
				_loop_extra;\
			} \
			break;
#else
#define reactor_DEVPOLL_CASE(_timeout_sec, _loop_extra)
#endif


#define reactor_main_loop( _timeout_sec, _err, _loop_extra) \
	switch(_worker_io.poll_method) { \
		case POLL_POLL: \
			while(1){ \
				io_wait_loop_poll(&_worker_io, _timeout_sec, 0); \
				_loop_extra;\
			} \
			break; \
		reactor_SELECT_CASE(_timeout_sec, _loop_extra) \
		reactor_SIGIORT_CASE(_timeout_sec, _loop_extra) \
		reactor_EPOLL_CASE(_timeout_sec, _loop_extra) \
		reactor_KQUEUE_CASE(_timeout_sec, _loop_extra) \
		reactor_DEVPOLL_CASE(_timeout_sec, _loop_extra) \
		default:\
			LM_CRIT("no support for poll method %s (%d)\n", \
				poll_method_name(_worker_io.poll_method), \
				_worker_io.poll_method);\
			goto _err; \
	}


#endif

