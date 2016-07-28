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

#include "mem/shm_mem.h"
#include "dprint.h"
#include "reactor_defs.h"
#include "async.h"

int async_status = ASYNC_NO_IO;

/* start/resume functions used for script async ops */
async_start_function  *async_start_f  = NULL;
async_resume_function *async_resume_f = NULL;

/* async context used for fd async operations */
typedef struct _async_fd_ctx {
	/* the resume function to be called when data to read is available */
	async_resume_fd *resume_f;
	/* parameter registered to the resume function */
	void *resume_param;
} async_fd_ctx;



int register_async_handlers(async_start_function *f1, async_resume_function *f2)
{
	if (async_start_f) {
		LM_ERR("aync handler already registered, it cannot be override\n");
		return -1;
	}

	async_start_f = f1;
	async_resume_f = f2;

	return 0;
}


int register_async_fd(int fd, async_resume_fd *f, void *param)
{
	async_fd_ctx *ctx = NULL;

	if ( (ctx=shm_malloc(sizeof(async_fd_ctx)))==NULL) {
		LM_ERR("failed to allocate new async_fd_ctx\n");
		return -1;
	}

	ctx->resume_f = f;
	ctx->resume_param = param;

	/* place the FD + resume function (as param) into reactor */
	if (reactor_add_reader( fd, F_FD_ASYNC, RCT_PRIO_ASYNC, (void*)ctx)<0 ) {
		LM_ERR("failed to add async FD to reactor\n");
		shm_free(ctx);
		return -1;
	}

	return 0;
}


int async_fd_resume(int *fd, void *param)
{
	async_fd_ctx *ctx = (async_fd_ctx *)param;
	int ret;

	async_status = ASYNC_DONE; /* assume default status as done */

	/* call the resume function in order to read and handle data */
	ret = ctx->resume_f( *fd, ctx->resume_param );
	if (async_status==ASYNC_CONTINUE) {
		/* leave the fd into the reactor*/
		return 0;
	} else if (async_status==ASYNC_CHANGE_FD) {
		if (ret<0) {
			LM_ERR("ASYNC_CHANGE_FD: given file descriptor shall be positive!\n");
			return 0;
		} else if (ret>0 && ret==*fd) {
			/*trying to add the same fd; shall continue*/
			LM_CRIT("You are trying to replace the old fd with the same fd!"
					"Will act as in ASYNC_CONTINUE!\n");
			return 0;
		}

		/* remove the old fd from the reactor */
		reactor_del_reader( *fd, -1, IO_FD_CLOSING);
		*fd=ret;

		/* insert the new fd inside the reactor */
		if (reactor_add_reader(*fd,F_FD_ASYNC,RCT_PRIO_ASYNC,(void*)ctx)<0 ) {
			LM_ERR("failed to add async FD to reactor -> act in sync mode\n");
			do {
				ret = ctx->resume_f( *fd, ctx->resume_param );
				if (async_status == ASYNC_CHANGE_FD)
					*fd=ret;
			} while(async_status==ASYNC_CONTINUE||async_status==ASYNC_CHANGE_FD);
		} else {

			/* succesfully changed fd */
			return 0;
		}
	}

	/* remove from reactor, we are done */
	reactor_del_reader( *fd, -1, IO_FD_CLOSING);

	if (async_status == ASYNC_DONE_CLOSE_FD)
		close(*fd);

	return 0;
}


