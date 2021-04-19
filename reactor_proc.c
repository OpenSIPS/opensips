/*
 * Copyright (C) 2021 OpenSIPS Solutions
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
 */

#include "cfg_reload.h"
#include "reactor.h"
#include "reactor_proc.h"


int reactor_proc_init(char *name)
{
	if ( init_worker_reactor( name, RCT_PRIO_MAX)<0 ) {
		LM_ERR("failed to init reactor <%s>\n",name);
		goto error;
	}

	/* start watching for the dedicated IPC jobs */
	if (reactor_add_reader(IPC_FD_READ_SELF, F_IPC, RCT_PRIO_ASYNC, NULL)<0){
		LM_CRIT("failed to add IPC pipe to reactor <%s>\n",name);
		goto error;
	}

	return 0;
error:
	destroy_worker_reactor();
	return -1;
}


int reactor_proc_add_fd(int fd, reactor_proc_cb_f func, void *param)
{
	struct reactor_proc_cb *cb;

	cb = (struct reactor_proc_cb *)pkg_malloc(sizeof(struct reactor_proc_cb));
	if (cb==NULL) {
		LM_ERR("failed to allocate a reactor_proc <%s> callback\n",
			reactor_name());
		return -1;
	}

	cb->func = func;
	cb->param = param;

	if (reactor_add_reader( fd, F_GEN_PROC, RCT_PRIO_PROC, cb)<0){
		LM_CRIT("failed to add fd to reactor <%s>\n", reactor_name());
		return -1;
	}

	return 0;
}


inline static int handle_io(struct fd_map* fm, int idx,int event_type)
{
	int n = 0;

	pt_become_active();

	pre_run_handle_script_reload(fm->app_flags);

	switch(fm->type){
		case F_GEN_PROC:
			n = ((struct reactor_proc_cb*)fm->data)->func(
					fm->fd,
					((struct reactor_proc_cb*)fm->data)->param,
					(event_type==IO_WATCH_TIMEOUT)?1:0
				);
			break;
		case F_SCRIPT_ASYNC:
			async_script_resume_f( fm->fd, fm->data,
				(event_type==IO_WATCH_TIMEOUT)?1:0 );
			break;
		case F_FD_ASYNC:
			async_fd_resume( fm->fd, fm->data);
			break;
		case F_LAUNCH_ASYNC:
			async_launch_resume( fm->fd, fm->data);
			break;
		case F_IPC:
			ipc_handle_job(fm->fd);
			break;
		default:
			LM_CRIT("unknown fd type %d in reactor proc\n", fm->type);
			n = -1;
			break;
	}

	post_run_handle_script_reload();

	pt_become_idle();
	return n;
}


int reactor_proc_loop( void )
{
	reactor_main_loop( REACTOR_PROC_TIMEOUT, error,);
	destroy_worker_reactor();

error:
	LM_ERR("failed to fire up reactor <%s>\n",reactor_name());
	return -1;
}
