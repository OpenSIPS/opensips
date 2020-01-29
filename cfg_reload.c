/*
 * Copyright (C) 2019 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */


#include <unistd.h>
#include <errno.h>

#include "mem/mem.h"
#include "globals.h"
#include "locking.h"
#include "rw_locking.h"
#include "daemonize.h"
#include "pt.h"
#include "route.h"
#include "reactor_defs.h"
#include "cfg_pp.h"
#include "cfg_reload.h"

extern FILE *yyin;
extern int yyparse();
#ifdef DEBUG_PARSER
extern int yydebug;
#endif

/* maximum number of milliseconds to wait for processes to get to final
 * conclusion over validating a script reloading */
#define MAX_PROC_RELOAD_WAIT 20000

enum proc_reload_status {
	RELOAD_NONE=0,        /* no reload going on */
	RELOAD_SENT,          /* reload cmd sent */
	RELOAD_RECEIVED,      /* reload cmd received by proc (load in progress)*/
	RELOAD_SUCCESS,       /* cfg reload succeded */
	RELOAD_FAILED         /* cfg reload failed */
	};

struct script_reload_ctx {
	gen_lock_t lock;
	rw_lock_t *rw_lock;
	unsigned int seq_no;
	unsigned int next_seq_no;
	str cfg_buf;
	enum proc_reload_status *proc_status;
};


int cfg_parse_only_routes = 0;

/* scripting routes reload context */
struct script_reload_ctx *srr_ctx = NULL;

/* if currently we run an older version of the cfg, resulting form a recent
 * reload - this just a santinel variable when (due async resume) we have to
 * go back and use the old script (which was used for triggering the async)
 * Of course, this is per process */
int _running_old_script = 0;

/* if we still keep the old/previous cfg (as a result of a recent reload)
 * this will stay on as time as we have in memory the old script. When the
 * old script is free, this will also be reset (also see the above comment) */
int _have_old_script = 0;

/* old/prev cfg - we may need to keep it in paralle with the new one in 
 * order to properly complete the ongoing async operatation */
static struct os_script_routes *prev_sr=NULL;

static struct os_script_routes *swap_bk = NULL;



void reload_swap_old_script(void)
{
	swap_bk = sroutes;
	sroutes = prev_sr;
}


void reload_swap_current_script(void)
{
	sroutes = swap_bk;
}


void reload_free_old_cfg(void)
{
	LM_ERR("finally removing the old/prev cfg\n");
	free_route_lists(prev_sr);
	prev_sr = NULL;
	_have_old_script = 0;
}


int init_script_reload(void)
{
	srr_ctx = (struct script_reload_ctx *)shm_malloc( sizeof(*srr_ctx) +
		counted_max_processes*sizeof(enum proc_reload_status) );
	if (srr_ctx==NULL) {
		LM_ERR("failed to shm allocate the script reload context\n");
		return -1;
	}

	memset( srr_ctx, 0, sizeof(*srr_ctx) +
		counted_max_processes*sizeof(enum proc_reload_status));

	srr_ctx->next_seq_no = 1;

	lock_init( &srr_ctx->lock );

	srr_ctx->rw_lock = lock_init_rw();
	if (srr_ctx->rw_lock==NULL) {
		LM_ERR("failed to create rw lock for script reload context\n");
		shm_free(srr_ctx);
		srr_ctx = NULL;
		return -1;
	}

	srr_ctx->proc_status = (enum proc_reload_status*)(srr_ctx + 1);

	return 0;
}


static inline void reset_script_reload_ctx(void)
{
	if (srr_ctx->cfg_buf.s)
		shm_free(srr_ctx->cfg_buf.s);
	srr_ctx->cfg_buf.s = NULL;
	srr_ctx->cfg_buf.len = 0;

	memset( srr_ctx->proc_status, 0,
		counted_max_processes*sizeof(enum proc_reload_status));


	/* this must be the last as it will allow the ctx reusage
	 * for another reload */
	srr_ctx->seq_no = 0;
}


static int reindex_new_sroutes(struct script_route *new_sr,
						struct script_route *old_sr, int size, int has_zero)
{
	static char *deleted_route_name = "_X_deleted_Y_";
	struct script_route *my_sr;
	int i, n, adding_idx;

	/* devel only
	for(i=0+(has_zero?0:1) ; i<size && old_sr[i].name ; i++)
		LM_DBG("OLD [%d] is [%s]\n",i,old_sr[i].name);
	for(i=0+(has_zero?0:1) ; i<size && new_sr[i].name ; i++)
		LM_DBG("NEW [%d] is [%s]\n",i,new_sr[i].name);*/

	my_sr = (struct script_route*)pkg_malloc(size*sizeof(struct script_route));
	if (my_sr==NULL) {
		LM_ERR("failed to allocate pkg mem (needing %zu)\n",
			size*sizeof(struct script_route));
		return -1;
	}
	memset( my_sr, 0, size*sizeof(struct script_route));
	/* iterate the old set of route and try to correlate the entries with the
	 * new set of routes - the idea is to try to preserv the indexes */
	if (has_zero) {
		my_sr[0] = new_sr[0];
		new_sr[0].name = NULL;
		new_sr[0].a = NULL;
	}
	for ( i=1 ; i<size && old_sr[i].name ; i++) {
		if (old_sr[i].name == deleted_route_name) {
			/* simply preserve the index of old deleted routes */
			my_sr[i] = old_sr[i];
		} else {
			n = get_script_route_ID_by_name( old_sr[i].name, new_sr, size);
			if (n==-1) {
				/* route was removed in the new set , set the dummy one here */
				my_sr[i].name = deleted_route_name;
				my_sr[i].a = pkg_malloc( sizeof(struct action) );
				if (my_sr[i].a==NULL) {
					LM_ERR("failed to allocate dummy EXIT action\n");
					pkg_free(my_sr);
					return -1;
				}
				my_sr[i].a->type = EXIT_T;
			} else {
				/* copy new route definition over the original index*/
				my_sr[i] = new_sr[n];
				new_sr[n].name = deleted_route_name;
				new_sr[n].a = NULL;
			}
		}
	}
	adding_idx = i;

	/* now see what is left in new set and not re-mapped to the old set 
	 * (basically the newly defined routes */
	for ( i=1 ; i<size ; i++) {
		if (new_sr[i].name==deleted_route_name || new_sr[i].name==NULL)
			continue;
		if (adding_idx==size) {
			LM_ERR("too many routes, cannot re-index newly defined routes "
				"after reload\n");
			pkg_free(my_sr);
			return -1;
		}
		my_sr[adding_idx++] = new_sr[i];
	}

	/* copy the re-indexed set of routes as the new set of routes */
	memcpy( new_sr, my_sr, size*sizeof(struct script_route));
	pkg_free(my_sr);
	/* devel only
	for(i=0+(has_zero?0:1) ; i<size && new_sr[i].name ; i++)
		LM_DBG("END NEW [%d] is [%s]\n",i,new_sr[i].name);
	*/
	return 0;
}


static int reindex_all_new_sroutes(struct os_script_routes *new_srs,
											struct os_script_routes *old_srs)
{
	if (reindex_new_sroutes( new_srs->request, old_srs->request,
	RT_NO, 1)<0) {
		LM_ERR("failed to re-index the request routes\n");
		return -1;
	}
	if (reindex_new_sroutes( new_srs->onreply, old_srs->onreply,
	ONREPLY_RT_NO, 1)<0) {
		LM_ERR("failed to re-index the on_reply routes\n");
		return -1;
	}
	if (reindex_new_sroutes( new_srs->failure, old_srs->failure,
	FAILURE_RT_NO, 0)<0) {
		LM_ERR("failed to re-index the on_failure routes\n");
		return -1;
	}
	if (reindex_new_sroutes( new_srs->branch, old_srs->branch,
	BRANCH_RT_NO, 0)<0) {
		LM_ERR("failed to re-index the branch routes\n");
		return -1;
	}
	if (reindex_new_sroutes( new_srs->event, old_srs->event,
	EVENT_RT_NO, 0)<0) {
		LM_ERR("failed to re-index the branch routes\n");
		return -1;
	}

	return 0;
}


static inline void send_cmd_to_all_procs(ipc_rpc_f *rpc)
{
	int i;

	/* send it to all process with IPC and needing SCRIPT */

	for( i=1 ; i<counted_max_processes ; i++) {
		if ( (pt[i].flags&(OSS_PROC_NO_IPC|OSS_PROC_NEEDS_SCRIPT))==
		OSS_PROC_NEEDS_SCRIPT ) {
			if (ipc_send_rpc( i, rpc, (void*)(long)srr_ctx->seq_no)<0)
				srr_ctx->proc_status[i] = RELOAD_FAILED;
			else
				srr_ctx->proc_status[i] = RELOAD_SENT;
		}
	}
}


static inline int check_status_of_all_procs(enum proc_reload_status min_status,
											enum proc_reload_status max_status)
{
	int i;

	for( i=1 ; i<counted_max_processes ; i++) {
		if ( (pt[i].flags&(OSS_PROC_NO_IPC|OSS_PROC_NEEDS_SCRIPT))==
		OSS_PROC_NEEDS_SCRIPT ) {
				if (srr_ctx->proc_status[i]<min_status ||
				srr_ctx->proc_status[i]>max_status)
					return -1;
		}
	}

	return 1;
}


/* global, per process holder for a new script to be used (during reload).
   This is used to store the pending-to-use script during the validation
   step and the actual switching (to new script) step */
static struct os_script_routes *parsed_sr=NULL;


static void routes_reload_per_proc(int sender, void *param)
{
	struct os_script_routes *sr_bk;
	int seq_no = (int)(long)param;
	FILE *cfg;

	LM_DBG("reload cmd received in process %d, with seq no %d\n",
		process_no, seq_no);

	if (_have_old_script) {
		LM_ERR("cannot reload again as still having the previous cfg,"
			" retry later\n");
		srr_ctx->proc_status[process_no] = RELOAD_FAILED;
		return;
	}

	lock_start_read(srr_ctx->rw_lock);

	if (srr_ctx->seq_no==0 || srr_ctx->seq_no!=seq_no) {
		LM_INFO("dropping reload cmd due out of sequence reason\n");
		lock_stop_read(srr_ctx->rw_lock);
		return;
	}

	srr_ctx->proc_status[process_no] = RELOAD_RECEIVED;

	/* get a file stream from the buffer */
	cfg = fmemopen( srr_ctx->cfg_buf.s, srr_ctx->cfg_buf.len, "r");
	if (!cfg) {
		LM_ERR("failed to obtain file from cfg buffer\n");
		goto error;
	}

	/* get and set a new script routes holder (for new cfg) */
	if (parsed_sr) {
		/* probabaly left by mistake from a prev attempt ?? */
		free_route_lists(parsed_sr);
		pkg_free(parsed_sr);
	}
	parsed_sr = new_sroutes_holder();
	if (parsed_sr==NULL) {
		LM_ERR("failed to allocate a new script routes holder\n");
		fclose(cfg);
		goto error;
	}
	sr_bk = sroutes;
	sroutes = parsed_sr;

	/* parse, but only the routes */
	cfg_parse_only_routes = 1;
	yyin = cfg;
	if (yyparse() != 0 || cfg_errors) {
		LM_ERR("bad config file (%d errors)\n", cfg_errors);
		fclose(cfg);
		goto error;
	}
	fclose(cfg);
	cfg_parse_only_routes = 0;

	if (reindex_all_new_sroutes( sroutes, sr_bk)<0) {
		LM_ERR("re-indexing routes failed, abording\n");
		goto error;
	}

	if (fix_rls()<0) {
		LM_ERR("fixing routes failed, abording\n");
		goto error;
	}

	sroutes = sr_bk;

	/* keep the parsed routes, waiting for the confirmation to switch */

	srr_ctx->proc_status[process_no] = RELOAD_SUCCESS;

	lock_stop_read(srr_ctx->rw_lock);
	LM_INFO("process successfully parsed new cfg (seq %d)\n",seq_no);

	return;

error:
	srr_ctx->proc_status[process_no] = RELOAD_FAILED;
	lock_stop_read(srr_ctx->rw_lock);
	if (parsed_sr) {
		free_route_lists(parsed_sr);
		pkg_free(parsed_sr);
		parsed_sr = NULL;
	}

	return;
}


static void routes_switch_per_proc(int sender, void *param)
{
	int seq_no = (int)(long)param;

	LM_DBG("swich cmd received in process %d, with seq no %d\n",
		process_no, seq_no);

	if (srr_ctx->seq_no!=0 && srr_ctx->seq_no!=seq_no) {
		LM_INFO("dropping switch cmd due out of sequence reason\n");
		if (parsed_sr) free_route_lists(parsed_sr);
		parsed_sr = NULL;
		return;
	}

	/* handle the async fd - mark them and see if we have any; if yes, 
	 * then we need to keep the previous cfg until all the async are done */
	reactor_set_app_flag( F_SCRIPT_ASYNC, REACTOR_RELOAD_TAINTED_FLAG);
	reactor_set_app_flag(     F_FD_ASYNC, REACTOR_RELOAD_TAINTED_FLAG);
	reactor_set_app_flag( F_LAUNCH_ASYNC, REACTOR_RELOAD_TAINTED_FLAG);

	if (reactor_check_app_flag(REACTOR_RELOAD_TAINTED_FLAG)) {
		/* we do have onlgoing aync fds */
		LM_DBG("keeping previous cfg until all ongoing async complete\n");
		prev_sr = sroutes;
		_have_old_script = 1;
	} else {
		/* we can get rid of the script right away*/
		LM_DBG("no ongoing async, freeing the previous cfg\n");
		free_route_lists(sroutes);
		prev_sr = NULL;
		_have_old_script = 0;
	}

	/* swap the old route set with the new parsed set */
	sroutes = parsed_sr;
	parsed_sr = NULL;
}


/* This is the trigger point for script reloading
 */
int reload_routing_script(void)
{
	struct os_script_routes *sr, *sr_bk;
	char * curr_wdir=NULL;
	str cfg_buf={NULL,0};
	int cnt_sleep, ret;

	/* one reload at a time */
	lock_get( &srr_ctx->lock );
	if (srr_ctx->seq_no!=0) {
		LM_INFO("Reload already in progress, cannot start a new one\n");
		lock_release( &srr_ctx->lock );
		return -1;
	}
	srr_ctx->seq_no = srr_ctx->next_seq_no++;
	lock_release( &srr_ctx->lock );

	sr = new_sroutes_holder();
	if (sr==NULL) {
		LM_ERR("failed to allocate a new script routes holder\n");
		goto error;
	}

	LM_INFO("reparsing routes from <%s> file\n",cfg_file);

	sr_bk = sroutes;
	sroutes = sr;

	/* parse, but only the routes */
	cfg_parse_only_routes = 1;

	/* switch to the startup working dir, to be sure the file pathname 
	 * (as given at startup via cli) still match */
	if (startup_wdir) {
		if ( (curr_wdir=getcwd(NULL,0))==NULL) {
			LM_ERR("failed to determin the working dir %d/%s\n", errno,
				strerror(errno));
			goto error;
		}
		if (chdir(startup_wdir)<0){
			LM_CRIT("Cannot chdir to %s: %s\n", startup_wdir, strerror(errno));
			goto error;
		}
	}

	ret = parse_opensips_cfg( cfg_file, preproc, &cfg_buf);

	cfg_parse_only_routes = 0;

	/* revert to the original working dir */
	if (curr_wdir) {
		if (chdir(curr_wdir)<0){
			LM_CRIT("Cannot chdir to %s: %s\n", curr_wdir, strerror(errno));
		}
		free(curr_wdir);
		curr_wdir=NULL;
	}

	if (ret<0) {
		LM_ERR("parsing failed, abording\n");
		goto error;
	}

	LM_INFO("fixing the loaded routes\n");

	if (fix_rls()<0) {
		LM_ERR("fixing routes failed, abording\n");
		goto error;
	}

	/* trigger module's validation functions to check if the reload of this 
	 * new route set is "approved" */
	if (!modules_validate_reload()) {
		LM_ERR("routes validation by modules failed, abording reload. "
			"OpenSIPS restart is recomended to deploy the new script\n");
		goto error;
	}

	/* we do not need the cfg, so free it and restore previous set of routes */
	sroutes = sr_bk;
	free_route_lists(sr);
	pkg_free(sr);
	sr = NULL;

	LM_DBG("new routes are valid and approved, push it to all procs\n");


	if (shm_nt_str_dup( &srr_ctx->cfg_buf, &cfg_buf)<0) {
		LM_ERR("failed to shmem'ize the cfg buffer, abording\n");
		goto error;
	}

	/* we do not need the local cfg buffer anymore */
	free( cfg_buf.s );
	cfg_buf.s = NULL;
	cfg_buf.len = 0;

	/* send the script for parse and validation to all procs */
	send_cmd_to_all_procs( routes_reload_per_proc );

	LM_DBG("reload triggered into all processes, waiting...\n");

	/* wait until all the processes validate (or not) the new cfg */
	cnt_sleep = 0;
	while ( (cnt_sleep++)<MAX_PROC_RELOAD_WAIT &&
	check_status_of_all_procs( RELOAD_SUCCESS, RELOAD_FAILED)==-1)
		usleep(1000);

	LM_DBG("done with waiting after %d miliseconds\n",cnt_sleep);

	/* done with waiting -> check what happened so far, but be sure all
	 * procs are not during a reload validation (in progress) */
	lock_start_write(srr_ctx->rw_lock);

	/* no other proc is doing script validation anymore,
	 * so recheck the status */
	if (check_status_of_all_procs( RELOAD_SUCCESS, RELOAD_SUCCESS)!=1) {
		LM_INFO("not all processes managed to load the new script, "
			"aborting the reload\n");
		/* some processes failed with the reload - setting an out-of-order
		 * sequence number will prevent any potential process waiting to 
		 * start the reload to actually do it */
		srr_ctx->seq_no = INT_MAX;
		/* if the script was succesfully loaded by some procs, it will
		 * be freed upon next reload attempt due sequence number */
		lock_stop_write(srr_ctx->rw_lock);
		goto error;
	}

	LM_DBG("all procs successfully reloaded, send the switch cmd\n");

	send_cmd_to_all_procs( routes_switch_per_proc );

	/* ready for a new reload :) */
	reset_script_reload_ctx();

	lock_stop_write(srr_ctx->rw_lock);

	return 0;
error:
	/* allow other reloads to be triggered */
	reset_script_reload_ctx();
	/* do cleanup */
	if (curr_wdir) free(curr_wdir);
	if (sr) {
		free_route_lists(sr);
		pkg_free(sr);
		sroutes = sr_bk;
	}
	if (cfg_buf.s)
		free(cfg_buf.s);
	return -1;
}

