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


/* The possible values of the status of async operatations (as reported by
 * module functions, at start and resume)
 * NOTE: all values in this enum must be negative
 */
enum async_ret_code {
	ASYNC_NO_IO = -8 ,
	ASYNC_SYNC,
	ASYNC_NO_FD,
	ASYNC_CONTINUE,
	ASYNC_CHANGE_FD,
	ASYNC_DONE_CLOSE_FD,
	ASYNC_DONE_NO_IO,		/* don't do any I/O related changes */
	ASYNC_DONE,
};



/* async context, basic structure to be reused by the more complex
 * async implementations */
typedef struct _async_ctx {
	/* the resume function to be called when data to read is available */
	void *resume_f;
	/* parameter registered to the resume function */
	void *resume_param;
} async_ctx;


extern int async_status;


/******** functions related to script async ops *******/

/* function to handle script function in async mode.
   Input: the sip message, the function/action (MODULE_T) and the ID of
          the resume route (where to continue after the I/O is done).
   Output: 0 if the async call was successfully done and script execution
          must be terminated.
          -1 some error happened and the async call did not happened.
 */
typedef int (async_script_start_function)
	(struct sip_msg *msg, struct action* a , int resume_route);

typedef int (async_script_resume_function)
	(int *fd, void *param);

/* internal used functions to start (from script) and
 * to continue (from reactor) async I/O ops */
extern async_script_start_function  *async_script_start_f;
extern async_script_resume_function *async_script_resume_f;

/* Registers the start and resume functions for the script async ops */
int register_async_script_handlers(async_script_start_function *f1,
											async_script_resume_function *f2);

/* async related functions to be used by the
 * functions exported by modules */
typedef int (async_resume_module)
	(int fd, struct sip_msg *msg, void *param);



/******** functions related to generic fd async ops *******/

/* async resume function triggered by
 * an IO event on a a registered FD */
typedef int (async_resume_fd)
	(int fd, void *param);


/* Registers the fd into the reactor for READ monitoring; The f function
 * (together with the param parameter) will be triggered for each READ event
 * on the fd.
 * The return code of the f resume function dictates when the fd will be
 * removed from the reactor (see async_ret_code).
 * Returns : 0 - on successful FD registration
 *          -1 - failure to register the FD
 * Function to be used by modules seeking to launch async I/O ops
 */
int register_async_fd(int fd, async_resume_fd *f, void *param);

/* Reseum function for the registered async fd. This is internally called
 * by the reactor via the handle_io() routine
   Function only for internal usage.
 */
int async_fd_resume(int *fd, void *param);



/******** functions related to async launch *******/

int async_script_launch(struct sip_msg *msg, struct action* a,
		int report_route);

int async_launch_resume(int *fd, void *param);


#endif

