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
 *  2014-10-15  created (bogdan)
 */


#ifndef _ASYNC_H_
#define _ASYNC_H_

#include "route_struct.h"
#include "parser/msg_parser.h"


/* The possible values of the status of async operations (as reported by
 * module functions, at start and resume)
 * NOTE: all values in this enum must be negative
 */
enum async_ret_code {
	ASYNC_NO_IO = -6,
	ASYNC_SYNC,
	ASYNC_CONTINUE,
	ASYNC_CHANGE_FD,
	ASYNC_DONE_CLOSE_FD,
	ASYNC_DONE,
};

extern int async_status;


/* function to handle script function in async mode.
   Input: the sip message, the function/action (MODULE_T) and the ID of
          the resume route (where to continue after the I/O is done).
   Output: 0 if the async call was successfully done and script execution
          must be terminated.
          -1 some error happened and the async call did not happened.
 */


/* internal used functions to start (from script) and
 * to continue (from reactor) async I/O ops */
typedef int (async_start_function)
	(struct sip_msg *msg, struct action* a , int resume_route);

typedef int (async_resume_function)
	(int fd, void *param);

extern async_start_function  *async_start_f;
extern async_resume_function *async_resume_f;

int register_async_handlers(async_start_function *f1, async_resume_function *f2);


/* async related functions to be used by the
 * functions exported by modules */
typedef int (async_resume_module)
	(int fd, struct sip_msg *msg, void *param);

#endif

