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
#include "route.h"
#include "action.h"
#include "sr_module.h"

int async_status = ASYNC_NO_IO;

extern int return_code; /* from action.c, return code */


/* start/resume functions used for script async ops */
async_script_start_function  *async_script_start_f  = NULL;
async_script_resume_function *async_script_resume_f = NULL;


/* async context used by Launch Async operation */
typedef struct _async_launch_ctx {
	/* generic async context - MUST BE FIRST */
	async_ctx  async;
	/* the ID of the report script route (-1 if none) */
	int report_route;
} async_launch_ctx;



/************* Functions related to ASYNC via script functions ***************/

int register_async_script_handlers(async_script_start_function *f1,
											async_script_resume_function *f2)
{
	if (async_script_start_f) {
		LM_ERR("aync script handlers already registered\n");
		return -1;
	}

	async_script_start_f = f1;
	async_script_resume_f = f2;

	return 0;
}


/************* Functions related to internal ASYNC support ***************/

int register_async_fd(int fd, async_resume_fd *f, void *resume_param)
{
	async_ctx *ctx = NULL;

	if ( (ctx=shm_malloc(sizeof(async_ctx)))==NULL) {
		LM_ERR("failed to allocate new async_ctx\n");
		return -1;
	}

	ctx->resume_f = f;
	ctx->resume_param = resume_param;

	/* place the FD + resume function (as param) into reactor */
	if (reactor_add_reader( fd, F_FD_ASYNC, RCT_PRIO_ASYNC, (void*)ctx)<0 ) {
		LM_ERR("failed to add async FD to reactor\n");
		shm_free(ctx);
		return -1;
	}

	return 0;
}


int async_fd_resume(int fd, void *param)
{
	async_ctx *ctx = (async_ctx *)param;
	int ret;

	async_status = ASYNC_DONE; /* assume default status as done */

	/* call the resume function in order to read and handle data */
	ret = ((async_resume_fd*)ctx->resume_f)( fd, ctx->resume_param );
	if (async_status==ASYNC_CONTINUE) {
		/* leave the fd into the reactor*/
		return 0;
	} else if (async_status==ASYNC_CHANGE_FD) {
		if (ret<0) {
			LM_ERR("ASYNC_CHANGE_FD: given file descriptor shall be "
				"positive!\n");
			return 0;
		} else if (ret>0 && ret==fd) {
			/*trying to add the same fd; shall continue*/
			LM_CRIT("You are trying to replace the old fd with the same fd!"
					"Will act as in ASYNC_CONTINUE!\n");
			return 0;
		}

		/* remove the old fd from the reactor */
		reactor_del_reader(fd, -1, IO_FD_CLOSING);
		fd=ret;

		/* insert the new fd inside the reactor */
		if (reactor_add_reader(fd,F_FD_ASYNC,RCT_PRIO_ASYNC,(void*)ctx)<0 ) {
			LM_ERR("failed to add async FD to reactor -> act in sync mode\n");
			do {
				async_status = ASYNC_DONE;
				ret = ((async_resume_fd*)ctx->resume_f)(fd,ctx->resume_param);
				if (async_status == ASYNC_CHANGE_FD)
					fd=ret;
			} while(async_status==ASYNC_CONTINUE||async_status==ASYNC_CHANGE_FD);
			goto done;
		} else {

			/* successfully changed fd */
			return 0;
		}
	}

	/* remove from reactor, we are done */
	reactor_del_reader(fd, -1, IO_FD_CLOSING);

done:
	if (async_status == ASYNC_DONE_CLOSE_FD)
		close(fd);

	return 0;
}


/************* Functions related to ASYNC Launch support ***************/

int async_launch_resume(int fd, void *param)
{
	struct sip_msg *req;
	async_launch_ctx *ctx = (async_launch_ctx *)param;

	LM_DBG("resume for a launch job\n");

	req = get_dummy_sip_msg();
	if(req == NULL) {
		LM_ERR("No more memory\n");
		return -1;
	}

	async_status = ASYNC_DONE; /* assume default status as done */

	/* call the resume function in order to read and handle data */
	return_code = ((async_resume_module*)(ctx->async.resume_f))
		( fd, req, ctx->async.resume_param );

	if (async_status==ASYNC_CONTINUE) {
		/* do not run the report route, leave the fd into the reactor*/
		goto restore;

	} else if (async_status==ASYNC_DONE_NO_IO) {
		/* don't do any change on the fd, since the module handled everything*/
		goto run_route;

	} else if (async_status==ASYNC_CHANGE_FD) {
		if (return_code<0) {
			LM_ERR("ASYNC_CHANGE_FD: given file descriptor must be "
				"positive!\n");
			goto restore;
		} else if (return_code>0 && return_code==fd) {
			/*trying to add the same fd; shall continue*/
			LM_CRIT("You are trying to replace the old fd with the same fd!"
					"Will act as in ASYNC_CONTINUE!\n");
			goto restore;
		}

		/* remove the old fd from the reactor */
		reactor_del_reader(fd, -1, IO_FD_CLOSING);
		fd=return_code;

		/* insert the new fd inside the reactor */
		if (reactor_add_reader(fd, F_LAUNCH_ASYNC, RCT_PRIO_ASYNC,
		(void*)ctx)<0 ) {
			LM_ERR("failed to add async FD to reactor -> act in sync mode\n");
			do {
				async_status = ASYNC_DONE;
				return_code = ((async_resume_module*)(ctx->async.resume_f))
					(fd, req, ctx->async.resume_param );
				if (async_status == ASYNC_CHANGE_FD)
					fd=return_code;
			} while(async_status==ASYNC_CONTINUE||async_status==ASYNC_CHANGE_FD);
			goto run_route;
		} else {

			/* successfully changed fd */
			goto restore;
		}
	}

	/* remove from reactor, we are done */
	reactor_del_reader(fd, -1, IO_FD_CLOSING);

run_route:
	if (async_status == ASYNC_DONE_CLOSE_FD)
		close(fd);

	if (ctx->report_route!=-1) {
		LM_DBG("runinng report route for a launch job\n");
		set_route_type( REQUEST_ROUTE );
		run_top_route( sroutes->request[ctx->report_route].a, req);

		/* remove all added AVP */
		reset_avps( );
	}

	/* no need for the context anymore */
	shm_free(ctx);
	LM_DBG("done with a launch job\n");

restore:
	/* clean whatever extra structures were added by script functions */
	release_dummy_sip_msg(req);

	return 0;
}


int async_script_launch(struct sip_msg *msg, struct action* a,
					int report_route, void **params)
{
	struct sip_msg *req;
	struct usr_avp *report_avps = NULL, **bak_avps = NULL;
	async_launch_ctx *ctx;
	int fd;

	/* run the function (the action) and get back from it the FD,
	 * resume function and param */
	if ( a->type!=AMODULE_T || a->elem[0].type!=ACMD_ST ||
	a->elem[0].u.data==NULL ) {
		LM_CRIT("BUG - invalid action for async I/O - it must be"
			" a MODULE_T ACMD_ST \n");
		return -1;
	}

	if ( (ctx=shm_malloc(sizeof(async_launch_ctx)))==NULL) {
		LM_ERR("failed to allocate new ctx, forcing sync mode\n");
		return -1;
	}

	async_status = ASYNC_NO_IO; /*assume defauly status "no IO done" */

	return_code = ((acmd_export_t*)(a->elem[0].u.data))->function(msg,
			(async_ctx*)ctx,
			params[0], params[1], params[2],
			params[3], params[4], params[5],
			params[6], params[7]);
	/* what to do now ? */
	if (async_status>=0) {
		/* async I/O was successfully launched */
		fd = async_status;
	} else if (async_status==ASYNC_NO_FD) {
		/* async was successfully launched but without a FD resume
		 * in this case, we need to push the async ctx back to the
		 * function, so it can trigger the resume later, by itself */
	} else if (async_status==ASYNC_NO_IO) {
		/* no IO, so simply continue with the script */
		shm_free(ctx);
		return 1;
	} else if (async_status==ASYNC_SYNC) {
		/* IO already done in SYNC'ed way */
		goto report;
	} else if (async_status==ASYNC_CHANGE_FD) {
		LM_ERR("Incorrect ASYNC_CHANGE_FD status usage!"
				"You should use this status only from the"
				"resume function in case something went wrong"
				"and you have other alternatives!\n");
		shm_free(ctx);
		return -1;
	} else {
		/* generic error, go for resume route, report it to script */
		shm_free(ctx);
		return -1;
	}

	/* ctx is to be used from this point further */
	ctx->report_route = report_route;

	if (async_status!=ASYNC_NO_FD) {
		LM_DBG("placing launch job into reactor\n");
		/* place the FD + resume function (as param) into reactor */
		if (reactor_add_reader(fd,F_LAUNCH_ASYNC,RCT_PRIO_ASYNC,(void*)ctx)<0){
			LM_ERR("failed to add async FD to reactor -> act in sync mode\n");
			goto sync;
		}
	}

	/* done, return to the script */
	return 1;
sync:
	/* run the resume function */
	LM_DBG("running launch job in sync mode\n");
	do {
		async_status = ASYNC_DONE;
		return_code = ((async_resume_module*)(ctx->async.resume_f))
			( fd, msg, ctx->async.resume_param );
		if (async_status == ASYNC_CHANGE_FD)
			fd = return_code;
	} while(async_status==ASYNC_CONTINUE||async_status==ASYNC_CHANGE_FD);
	/* the IO completed, so report now */
report:
	shm_free(ctx);
	if (report_route==-1)
		return 1;

	/* run the report route inline */
	req = get_dummy_sip_msg();
	if(req == NULL) {
		LM_ERR("No more memory\n");
		return -1;
	}

	set_route_type( REQUEST_ROUTE );
	bak_avps = set_avp_list(&report_avps);

	run_top_route( sroutes->request[report_route].a, req);

	destroy_avp_list(&report_avps);
	set_avp_list(bak_avps);

	release_dummy_sip_msg(req);

	return 1;
}



