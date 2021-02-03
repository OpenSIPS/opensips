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
 *  2014-10-16  created (bogdan)
 */

#include "../../dprint.h"
#include "../../async.h"
#include "../../context.h"
#include "../../reactor_defs.h"
#include "h_table.h"
#include "t_lookup.h"
#include "t_msgbuilder.h"


typedef struct _async_tm_ctx {
	/* generic async context - MUST BE FIRST */
	async_ctx  async;
	/* the script route to be used to continue after the resume function */
	int resume_route;
	/* the type of the route where the suspend was done */
	int route_type;
	/* the processing context for the handled message */
	context_p msg_ctx;
	/* the transaction for the handled message */
	struct cell *t;

	enum kill_reason kr;

	/* the transaction that was cancelled by this message */
	struct cell *cancelled_t;
	/* e2e ACK */
	struct cell *e2eack_t;

} async_tm_ctx;

extern int return_code; /* from action.c, return code */



static inline void run_resume_route( int resume_route, struct sip_msg *msg,
															int run_post_cb)
{
	/* run the resume route and if it ends the msg handling (no other aysnc
	 * started), run the post script callbacks. */
	if ( (run_top_route(sroutes->request[resume_route].a, msg) & ACT_FL_TBCONT) == 0 )
		if (run_post_cb)
			exec_post_req_cb(msg);
}


/* function triggered from reactor in order to continue the processing
 */
int t_resume_async(int fd, void *param, int was_timeout)
{
	static struct sip_msg faked_req;
	static struct ua_client uac;
	async_tm_ctx *ctx = (async_tm_ctx *)param;
	struct cell *backup_t;
	struct cell *backup_cancelled_t;
	struct cell *backup_e2eack_t;
	struct usr_avp **backup_list;
	struct socket_info* backup_si;
	struct cell *t= ctx->t;
	int route;

	if (valid_async_fd(fd))
		LM_DBG("resuming on fd %d, transaction %p \n", fd, t);
	else
		LM_DBG("resuming without a fd, transaction %p \n", t);

	if (current_processing_ctx) {
		LM_CRIT("BUG - a context already set!\n");
		abort();
	}

	/* prepare for resume route, by filling in a phony UAC structure to
	 * trigger the inheritance of the branch specific values */
	uac.br_flags = getb0flags( t->uas.request ) ;
	uac.uri = *GET_RURI( t->uas.request );
	uac.duri = t->uas.request->dst_uri;
	uac.path_vec = t->uas.request->path_vec;
	uac.adv_address = t->uas.request->set_global_address;
	uac.adv_port = t->uas.request->set_global_port;
	if (!fake_req( &faked_req /* the fake msg to be built*/,
		t->uas.request, /* the template msg saved in transaction */
		&t->uas, /*the UAS side of the transaction*/
		&uac /* the fake UAC */)
	) {
		LM_ERR("fake_req failed\n");
		return 0;
	}

	/* enviroment setting */
	current_processing_ctx = ctx->msg_ctx;
	backup_t = get_t();
	backup_e2eack_t = get_e2eack_t();
	backup_cancelled_t = get_cancelled_t();
	/* fake transaction */
	set_t( t );
	set_cancelled_t(ctx->cancelled_t);
	set_e2eack_t(ctx->e2eack_t);
	reset_kr();
	set_kr(ctx->kr);
	/* make available the avp list from transaction */
	backup_list = set_avp_list( &t->user_avps );
	/* set default send address to the saved value */
	backup_si = bind_address;
	bind_address = t->uac[0].request.dst.send_sock;

	async_status = ASYNC_DONE; /* assume default status as done */
	/* call the resume function in order to read and handle data */
	return_code = ((async_resume_module*)
		(was_timeout ? ctx->async.timeout_f : ctx->async.resume_f))
		( (valid_async_fd(fd) ? fd: ASYNC_FD_NONE), &faked_req,
		ctx->async.resume_param );
	if (async_status==ASYNC_CONTINUE) {
		/* do not run the resume route */
		goto restore;
	} else if (async_status==ASYNC_DONE_NO_IO) {
		/* don't do any change on the fd, since the module handled everything */
		goto route;
	} else if (async_status==ASYNC_CHANGE_FD) {
		if (return_code<0) {
			LM_ERR("ASYNC_CHANGE_FD: given file descriptor shall be positive!\n");
			goto restore;
		} else if (return_code > 0 && valid_async_fd(fd) && return_code == fd) {
			/*trying to add the same fd; shall continue*/
			LM_CRIT("You are trying to replace the old fd with the same fd!"
					"Will act as in ASYNC_CONTINUE!\n");
			goto restore;
		}

		/* if there was a file descriptor, remove it from the reactor */
		reactor_del_reader(fd, -1, IO_FD_CLOSING);
		fd=return_code;

		/* insert the new fd inside the reactor */
		if(reactor_add_reader(fd,F_SCRIPT_ASYNC,RCT_PRIO_ASYNC,(void*)ctx)<0){
			LM_ERR("failed to add async FD to reactor -> act in sync mode\n");
			do {
				async_status = ASYNC_DONE;
				return_code = ((async_resume_module*)(ctx->async.resume_f))
					(fd, &faked_req, ctx->async.resume_param );
				if (async_status == ASYNC_CHANGE_FD)
					fd=return_code;
			} while(async_status==ASYNC_CONTINUE||async_status==ASYNC_CHANGE_FD);
			goto route;
		}

		/* changed fd; now restore old state */
		goto restore;
	}

	if (valid_async_fd(fd)) {
		/* remove from reactor, we are done */
		reactor_del_reader(fd, -1, IO_FD_CLOSING);
	}

route:
	if (async_status == ASYNC_DONE_CLOSE_FD && valid_async_fd(fd))
		close(fd);

	/* run the resume_route (some type as the original one) */
	swap_route_type(route, ctx->route_type);
	run_resume_route( ctx->resume_route, &faked_req, 1);
	set_route_type(route);

	/* no need for the context anymore */
	shm_free(ctx);

	/* free also the processing ctx if still set
	 * NOTE: it may become null if inside the run_resume_route
	 * another async jump was made (and context attached again
	 * to transaction) */
	if (current_processing_ctx) {
		context_destroy(CONTEXT_GLOBAL, current_processing_ctx);
		pkg_free(current_processing_ctx);
	}

restore:
	/* restore original environment */
	set_t(backup_t);
	set_cancelled_t(backup_cancelled_t);
	set_e2eack_t(backup_e2eack_t);
	/* restore original avp list */
	set_avp_list( backup_list );
	bind_address = backup_si;

	free_faked_req( &faked_req, t);
	current_processing_ctx = NULL;

	return 0;
}


int t_handle_async(struct sip_msg *msg, struct action* a , int resume_route,
										unsigned int timeout, void **params)
{
	async_tm_ctx *ctx = NULL;
	struct cell *t;
	int r;
	int fd = 0;

	/* create transaction and save everything into transaction */
	t=get_t();
	if ( t==0 || t==T_UNDEFINED ) {
		/* create transaction */
		r = t_newtran( msg , 1 /*full uas clone*/ );
		if (r==0) {
			/* retransmission -> no follow up; we return a negative
			 * code to indicate do_action that the top route is
			 * is completed (there no resume route to follow) */
			return -1;
		} else if (r<0) {
			LM_ERR("could not create a new transaction\n");
			goto failure;
		}
		t=get_t();
	} else {
		/* update the cloned UAS (from transaction)
		 * with data from current msg */
		if (t->uas.request)
			update_cloned_msg_from_msg( t->uas.request, msg);
	}

	/* run the function (the action) and get back from it the FD,
	 * resume function and param */
	if ( a->type!=AMODULE_T || a->elem[0].type!=ACMD_ST ||
	a->elem[0].u.data==NULL ) {
		LM_CRIT("BUG - invalid action for async I/O - it must be"
			" a MODULE_T ACMD_ST \n");
		goto failure;
	}

	if ( (ctx=shm_malloc(sizeof(async_tm_ctx)))==NULL) {
		LM_ERR("failed to allocate new ctx\n");
		goto failure;
	}

	async_status = ASYNC_NO_IO; /*assume default status "no IO done" */
	return_code = ((acmd_export_t*)(a->elem[0].u.data))->function(msg,
			(async_ctx*)ctx,
			params[0], params[1], params[2],
			params[3], params[4], params[5],
			params[6], params[7]);
	/* what to do now ? */
	if (async_status>=0) {
		/* async I/O was successfully launched */
		fd = async_status;
		if (msg->REQ_METHOD==METHOD_ACK ||
		/* ^^^ end2end ACK, there is no actual transaction here */
		t->uas.request==NULL
		/* ^^^ local requests do not support async in local route */
		) {
			goto sync;
		}
	} else if (async_status==ASYNC_NO_FD) {
		/* async was successfully launched but without a FD resume
		 * in this case, we need to push the async ctx back to the
		 * function, so it can trigger the resume later, by itself */
	} else if (async_status==ASYNC_NO_IO) {
		/* no IO, so simply go for resume route */
		goto resume;
	} else if (async_status==ASYNC_SYNC) {
		/* IO already done in SYNC'ed way */
		goto resume;
	} else if (async_status==ASYNC_CHANGE_FD) {
		LM_ERR("Incorrect ASYNC_CHANGE_FD status usage!"
				"You should use this status only from the"
				"resume function in case something went wrong"
				"and you have other alternatives!\n");
		/* FIXME should we go to resume or exit? as it's quite 
		   an invalid scenario */
		goto resume;
	} else {
		/* generic error, go for resume route */
		goto resume;
	}

	/* do we have a reactor in this process, to handle this
	   asyn I/O ? */
	if ( 0/*reactor_exists()*/ ) {
		/* no reactor, so we directly call the resume function
		   which will block waiting for data */
		goto sync;
	}

	if (route_type!=REQUEST_ROUTE) {
		LM_WARN("async detected in non-request route, switching to sync\n");
		goto sync;
	}

	ctx->resume_route = resume_route;
	ctx->route_type = route_type;
	ctx->msg_ctx = current_processing_ctx;
	ctx->t = t;
	ctx->kr = get_kr();

	ctx->cancelled_t = get_cancelled_t();
	ctx->e2eack_t = get_e2eack_t();

	current_processing_ctx = NULL;
	set_t(T_UNDEFINED);
	reset_cancelled_t();
	reset_e2eack_t();

	if (async_status!=ASYNC_NO_FD) {
		/* check if timeout should be used */
		if (timeout && ctx->async.timeout_f==NULL) {
			timeout = 0;
			LM_ERR("this async function has no support for timeouts -- "
			       "still using an infinite timeout!\n");
		}

		LM_DBG("placing async job into reactor with timeout %d\n", timeout);
		/* place the FD + resume function (as param) into reactor */
		if (reactor_add_reader_with_timeout( fd, F_SCRIPT_ASYNC,
		RCT_PRIO_ASYNC, timeout, (void*)ctx)<0) {
			LM_ERR("failed to add async FD to reactor -> act in sync mode\n");
		 	/* as attaching to reactor failed, we have to run in sync mode,
			 * so we have to restore the environment -- razvanc */
			current_processing_ctx = ctx->msg_ctx;
			set_t(t);
			set_cancelled_t(ctx->cancelled_t);
			set_e2eack_t(ctx->e2eack_t);
			goto sync;
		}
	}

	/* done, break the script */
	return 0;

sync:
	/* run the resume function */
	do {
		async_status = ASYNC_DONE;
		return_code = ((async_resume_module*)(ctx->async.resume_f))
			( fd, msg, ctx->async.resume_param );
		if (async_status == ASYNC_CHANGE_FD)
			fd = return_code;
		if (async_status == ASYNC_DONE_CLOSE_FD)
			close(fd);
	} while(async_status==ASYNC_CONTINUE||async_status==ASYNC_CHANGE_FD);
	/* get rid of the context, useless at this point further */
	shm_free(ctx);
	/* run the resume route in sync mode */
	run_resume_route( resume_route, msg, (route_type!=REQUEST_ROUTE)?0:1);

	/* break original script */
	return 0;

failure:
	/* execute here the resume route with failure indication */
	return_code = -1;
resume:
	/* get rid of the context, useless at this point further */
	if (ctx) shm_free(ctx);
	/* run the resume route */
	run_resume_route( resume_route, msg, (route_type!=REQUEST_ROUTE)?0:1);
	/* the triggering route is terminated and whole script ended */
	return 0;
}

