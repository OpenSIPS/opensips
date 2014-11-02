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


typedef struct _async_ctx {
	async_resume_function *resume_f;
	void *resume_param;
	int resume_route;
	struct cell *t;
} async_ctx;

extern int return_code; /* from action.c, return code */


/* function triggered from reactor in order to continue the processing
 */
int t_resume_async(int fd, void *param)
{
	async_ctx *ctx = (async_ctx *)param;
	int ret;

	/* call the resume function in order to read and handle data */
	ret = ctx->resume_f( fd, ctx->resume_param );

	/* start the resume_route[] */

	return 0;
}


int t_handle_async(struct sip_msg *msg, struct action* a , int resume_route)
{
	async_ctx *ctx;
	async_resume_function *ctx_f;
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
	fd = ((acmd_export_t*)(a->elem[0].u.data))->function(msg,
			 (char*)a->elem[1].u.data, (char*)a->elem[2].u.data,
			 (char*)a->elem[3].u.data, (char*)a->elem[4].u.data,
			 (char*)a->elem[5].u.data, (char*)a->elem[6].u.data,
			 &ctx_f, &ctx_p);
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
	ctx_f( fd, ctx_p );
	/* break original script */
	return 0;
	// FIXME start the resume route


failure:
	/* execute here the resume route with failure indication */
	return_code = -1;

	//run_top_route(struct action* a, struct sip_msg* msg)

	return 0;
}

