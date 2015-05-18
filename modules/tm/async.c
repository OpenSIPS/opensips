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
 *  2014-10-16  created (bogdan)
 */

#include "../../dprint.h"
#include "../../async.h"
#include "../../context.h"
#include "../../reactor_defs.h"
#include "h_table.h"
#include "t_lookup.h"
#include "t_msgbuilder.h"


typedef struct _async_ctx {
	/* the resume function to be called when data to read is available */
	async_resume_module *resume_f;
	/* parameter registered to the resume function */
	void *resume_param;
	/* the script route to be used to continue after the resume function */
	int resume_route;
	/* the type of the route where the suspend was done */
	int route_type;
	/* the processing context for the handled message */
	context_p msg_ctx;
	/* the transaction for the handled message */
	struct cell *t;

	enum kill_reason kr;
} async_ctx;

extern int return_code; /* from action.c, return code */



static inline void run_resume_route( int resume_route, struct sip_msg *msg)
{
	/* run the resume route and if it ends the msg handling (no other aysnc
	 * started), run the post script callbacks. */
	if ( (run_top_route(rlist[resume_route].a, msg) & ACT_FL_TBCONT) == 0 )
		exec_post_req_cb(msg);
}


/* function triggered from reactor in order to continue the processing
 */
int t_resume_async(int fd, void *param)
{
	static struct sip_msg faked_req;
	static struct ua_client uac;
	async_ctx *ctx = (async_ctx *)param;
	struct cell *backup_t;
	struct usr_avp **backup_list;
	struct socket_info* backup_si;
	struct cell *t= ctx->t;
	int route;

	LM_DBG("resuming on fd %d, transaction %p \n",fd, t);

	if (current_processing_ctx) {
		LM_CRIT("BUG - a context already set!\n");
		abort();
	}

	/* prepare for resume route */
	uac.br_flags = getb0flags( t->uas.request ) ;
	uac.uri = *GET_RURI( t->uas.request );
	if (!fake_req( &faked_req /* the fake msg to be built*/,
		t->uas.request, /* the template msg saved in transaction */
		&t->uas, /*the UAS side of the transaction*/
		&uac, /* the fake UAC */
		1 /* copy dst_uri too */)
	) {
		LM_ERR("fake_req failed\n");
		return 0;
	}

	/* enviroment setting */
	current_processing_ctx = ctx->msg_ctx;
	backup_t = get_t();
	/* fake transaction */
	set_t( t );
	reset_kr();
	set_kr(ctx->kr);
	/* make available the avp list from transaction */
	backup_list = set_avp_list( &t->user_avps );
	/* set default send address to the saved value */
	backup_si = bind_address;
	bind_address = t->uac[0].request.dst.send_sock;

	async_status = ASYNC_DONE; /* assume default status as done */
	/* call the resume function in order to read and handle data */
	return_code = ctx->resume_f( fd, &faked_req, ctx->resume_param );
	if (async_status==ASYNC_CONTINUE) {
		/* do not run the resume route */
		goto restore;
	}

	/* remove from reactor, we are done */
	reactor_del_reader( fd, -1, IO_FD_CLOSING);

	if (async_status == ASYNC_DONE_CLOSE_FD)
		close(fd);

	/* run the resume_route (some type as the original one) */
	swap_route_type(route, ctx->route_type);
	run_resume_route( ctx->resume_route, &faked_req);
	set_route_type(route);

	/* no need for the context anymore */
	shm_free(ctx);

restore:
	/* restore original environment */
	set_t(backup_t);
	/* restore original avp list */
	set_avp_list( backup_list );
	bind_address = backup_si;

	free_faked_req( &faked_req, t);
	current_processing_ctx = NULL;

	return 0;
}


int t_handle_async(struct sip_msg *msg, struct action* a , int resume_route)
{
	async_ctx *ctx;
	async_resume_module *ctx_f;
	void *ctx_p;
	struct cell *t;
	int r;
	int fd;

	/* create transaction and save everything into transaction */
	t=get_t();
	if ( t==0 || t==T_UNDEFINED ) {
		/* create transaction */
		r = t_newtran( msg , 1 /*full uas clone*/ );
		if (r==0) {
			/* retransmission -> break the script, no follow up */
			return 0;
		} else if (r<0) {
			LM_ERR("could not create a new transaction\n");
			goto failure;
		}
		t=get_t();
	} else {
		/* update the cloned UAS (from transaction)
		 * with data from current msg */
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

	async_status = ASYNC_NO_IO; /*assume defauly status "no IO done" */
	return_code = ((acmd_export_t*)(a->elem[0].u.data))->function(msg,
			&ctx_f, &ctx_p,
			(char*)a->elem[1].u.data, (char*)a->elem[2].u.data,
			(char*)a->elem[3].u.data, (char*)a->elem[4].u.data,
			(char*)a->elem[5].u.data, (char*)a->elem[6].u.data );
	/* what to do now ? */
	if (async_status>=0) {
		/* async I/O was succesfully launched */
		fd = async_status;
	} else if (async_status==ASYNC_NO_IO) {
		/* no IO, so simply go for resume route */
		goto resume;
	} else if (async_status==ASYNC_SYNC) {
		/* IO already done in SYNC'ed way */
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

	if ( (ctx=shm_malloc(sizeof(async_ctx)))==NULL) {
		LM_ERR("failed to allocate new ctx\n");
		goto sync;
	}

	ctx->resume_f = ctx_f;
	ctx->resume_param = ctx_p;
	ctx->resume_route = resume_route;
	ctx->route_type = route_type;
	ctx->msg_ctx = current_processing_ctx;
	ctx->t = t;
	ctx->kr = get_kr();

	current_processing_ctx = NULL;
	set_t(T_UNDEFINED);

	/* place the FD + resume function (as param) into reactor */
	if (reactor_add_reader( fd, F_SCRIPT_ASYNC, RCT_PRIO_ASYNC, (void*)ctx)<0 ) {
		LM_ERR("failed to add async FD to reactor -> act in sync mode\n");
		shm_free(ctx);
		goto sync;
	}

	/* done, break the script */
	return 0;

sync:
	/* run the resume function */
	do {
		return_code = ctx_f( fd, msg, ctx_p );
	} while(async_status!=ASYNC_CONTINUE);
	/* run the resume route in sync mode */
	run_resume_route( resume_route, msg);
	/* break original script */
	return 0;

failure:
	/* execute here the resume route with failure indication */
	return_code = -1;
resume:
	/* run the resume route */
	run_resume_route( resume_route, msg);
	/* the triggering route is terminated and whole script ended */
	return 0;
}

