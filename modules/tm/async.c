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
#include "../../reactor_defs.h"
#include "h_table.h"
#include "t_lookup.h"
#include "t_msgbuilder.h"


typedef struct _async_ctx {
	async_resume_module *resume_f;
	void *resume_param;
	int resume_route;
	struct cell *t;
} async_ctx;

extern int return_code; /* from action.c, return code */


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
	enum async_ret_code ret;

	LM_DBG("resuming on fd %d, transaction %p \n",fd,ctx->t);

	/* prepare for resume route */
	uac.br_flags = 0 ; /* FIXME - we do not have them stored !! */
	uac.uri = *GET_RURI( ctx->t->uas.request );
	if (!fake_req( &faked_req /* the fake msg to be built*/,
		ctx->t->uas.request, /* the template msg saved in transaction */
		&ctx->t->uas, /*the UAS side of the transaction*/
		&uac /* the fake UAC */)
	) {
		LM_ERR("fake_req failed\n");
		return 0;
	}

	/* enviroment setting */
	backup_t = get_t();
	/* fake transaction */
	set_t(ctx->t);
	/* make available the avp list from transaction */
	backup_list = set_avp_list( &ctx->t->user_avps );
	/* set default send address to the saved value */
	backup_si = bind_address;
	bind_address = ctx->t->uac[0].request.dst.send_sock;

	/* call the resume function in order to read and handle data */
	ret = ctx->resume_f( fd, &faked_req, ctx->resume_param );
	if (ret==ASYNC_CONTINUE) {
		/* do not run the resume route */
		goto restore;
	} else if (ret==ASYNC_ERROR) {
		shm_free(ctx);
		/* FIXME set some error indication for the route */
	}

	/* remove from reactor, we are done */
	reactor_del_reader( fd, -1, IO_FD_CLOSING);
	close(fd);

	/* run the resume_route[] */
	run_top_route( rlist[ctx->resume_route].a, &faked_req);

restore:
	/* restore original environment */
	set_t(backup_t);
	/* restore original avp list */
	set_avp_list( backup_list );
	bind_address = backup_si;

	free_faked_req( &faked_req, ctx->t);

	/* FIXME - we need to do complete update on the transaction,
	  likr RURI, DURI, flags, path, etc */
	ctx->t->uas.request->flags = faked_req.flags;

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
		r = t_newtran( msg );
		if (r==0) {
			/* retransmission -> break the script, no follow up */
			return 0;
		} else if (r<0) {
			LM_ERR("could not create a new transaction\n");
			goto failure; /* FIXME - should we try to go sync here ?? */
		}
		t=get_t();
	} else {
		/* update transaction */
		t->uas.request->flags = msg->flags;
		// FIXME what about RURI, DSTURI, callbacks, path, global_address/port, lumps ???
	}

	/* run the function (the action) and get back from it the FD, resume function and param */
	if ( a->type!=AMODULE_T || a->elem[0].type!=ACMD_ST || a->elem[0].u.data==NULL ) {
		LM_CRIT("BUG - invalid action for async I/O - it must a MODULE_T ACMD_ST \n");
		goto failure;
	}
	fd = ((acmd_export_t*)(a->elem[0].u.data))->function(msg, &ctx_f, &ctx_p,
			 (char*)a->elem[1].u.data, (char*)a->elem[2].u.data,
			 (char*)a->elem[3].u.data, (char*)a->elem[4].u.data,
			 (char*)a->elem[5].u.data, (char*)a->elem[6].u.data );
	/* what to do now ? */
	if (fd==0) {
		/* function wants to break script, no follow up */
		return 0;
	} else if (fd < 0) {
		/* async I/O was not launched, go for resume route */
		goto failure;
	}
	/* async I/O was succesfully launched */

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
	ctx->t = t;

	set_kr(REQ_FWDED);

	/* place the FD + resume function (as param) into reactor */
	if (reactor_add_reader( fd, F_SCRIPT_ASYNC, (void*)ctx)<0 ) {
		LM_ERR("failed to add async FD to reactor -> act in sync mode\n");
		shm_free(ctx);
		goto sync;
	}

	/* done, break the script */
	return 0;


sync:
	/* run the resume function */
	ctx_f( fd, msg, ctx_p );
	/* run the resume route in sync mode */
	run_top_route(rlist[resume_route].a, msg);
	/* break original script */
	return 0;


failure:
	/* execute here the resume route with failure indication */
	return_code = -1; /* FIXME */
	/* run the resume route */
	run_top_route(rlist[resume_route].a, msg);
	/* the triggering route is terminated and whole script ended */
	return 0;
}

