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
#include "cfg_pp.h"

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


static inline int stream_2_sh_buffer(FILE *cfg_stream, str *buf)
{
	/* this shouldn't be needed as the parser should have read the full 
	 * file, but let's do it to be 100% sure */
	fseek( cfg_stream, 0L, SEEK_END);
	buf->len = ftell(cfg_stream);

	buf->s = (char*)shm_malloc( buf->len+1 );
	if (buf->s==NULL) {
		LM_ERR("failed to sh allocate cfg buffer (size %d)\n",buf->len);
		return -1;
	}

	rewind( cfg_stream );

	fread( buf->s, sizeof(char), buf->len, cfg_stream);
	if ( ferror(cfg_stream)!=0 ) {
		LM_ERR("failed copying the cfg stream to buffer");
		shm_free( buf->s );
		buf->s = NULL;
		buf->len = 0;
		return -1;
	}

	buf->s[buf->len] = 0; /* just in case */

	return 0;
}


static inline void send_cmd_to_all_procs(ipc_rpc_f *rpc)
{
	int i;

	/* FIXME - some issues here :
	 *   1) we cannot reach the non-IPC procs, like module or att procs 
	 *   2) be sure we do not IPC ourselves, but as reload is MI trigger, 
	 *      this is ok, until MI procs will get IPC */

	for( i=1 ; i<counted_max_processes ; i++) {
		if ( (pt[i].flags&OSS_PROC_NO_IPC)==0 ) {
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
		if ( (pt[i].flags&OSS_PROC_NO_IPC)==0 ) {
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

	/* TODO - start the draining of the ongoign script related ops */

	/* swap the old route set with the new parsed set */
	free_route_lists(sroutes);
	sroutes = parsed_sr;
	parsed_sr = NULL;
}


/* This is the trigger point for script reloading
 */
int reload_routing_script(void)
{
	struct os_script_routes *sr, *sr_bk;
	char * curr_wdir=NULL;
	FILE *cfg_stream;
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

	ret = parse_opensips_cfg( cfg_file, preproc, &cfg_stream);

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

	/* TODO - trigger module's callbacks to check if the reload of this 
	 * new route set is "approved" */

	/* we do not need the cfg, so free it and restore previous set of routes */
	sroutes = sr_bk;
	free_route_lists(sr);
	pkg_free(sr);
	sr = NULL;

	LM_DBG("new routes are valid and approved, push it to all procs\n");

	if (stream_2_sh_buffer( cfg_stream, &srr_ctx->cfg_buf)<0) {
		LM_ERR("failed to buffer'ize the cfg stream, abording\n");
		goto error;
	}

	/* we do not need the stream anymore */
	fclose( cfg_stream );
	cfg_stream = NULL;

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
	if (cfg_stream)
		fclose(cfg_stream);
	return -1;
}
