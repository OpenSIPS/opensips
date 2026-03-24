/*
 * Copyright (C) 2013-2014 OpenSIPS Solutions
 * Copyright (C) 2001-2003 FhG Fokus
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * --------
 * 2015-02-05 imported from former tpc_read.c (bogdan)
 */


#include <stdint.h>

#include "../pt_load.h"
#include "../ipc.h"
#include "../timer.h"
#include "../reactor.h"
#include "../async.h"
#include "../cfg_reload.h"
#include "../mem/shm_mem.h"
#include "../receive.h"

#include "tcp_conn.h"
#include "net_tcp.h"
#include "tcp_passfd.h"
#include "trans.h"
#include "net_tcp_dbg.h"

/*!< the FD currently used by the process to communicate with TCP MAIN*/
static int _my_fd_to_tcp_main = -1;

static int tcpmain_sock=-1;
extern int unix_tcp_sock;

static void tcpconn_release(struct tcp_connection* c, long state, int writer,
															int as_tcp_worker)
{
	long response[2];

	LM_DBG(" releasing con %p, state %ld, fd=%d, id=%d\n",
			c, state, c->fd, c->id);
	LM_DBG(" extra_data %p\n", c->extra_data);

	/* errno==EINTR, EWOULDBLOCK a.s.o todo */
	response[0]=(long)c;
	response[1]=state;

	if (send_all( as_tcp_worker?tcpmain_sock:unix_tcp_sock, response,
	sizeof(response))<=0)
		LM_ERR("send_all failed state=%ld con=%p\n", state, c);
}


/* wrapper around internal tcpconn_release() - to be called by functions which
 * used tcp_conn_get(), in order to release the connection;
 * It does the unref and pushes back (if needed) some update to TCP main;
 * right now, it used only from the xxx_send() functions
 */
void tcp_conn_release(struct tcp_connection* c, int pending_data)
{
	if (c->state==S_CONN_BAD) {
		/* do more or less nothing, let the TCP READER owning the conn
		 * to trash it based on the S_CONN_BAD marker */
		c->lifetime=0;
		c->timeout=0;
		/* but be sure we unref the conn */
		tcpconn_put(c);
		return;
	}
	if (!pending_data && c->async && c->async->pending &&
			((c->state == S_CONN_OK && (c->flags & F_CONN_REMOVED_WRITE)) ||
			 c->fd == -1))
		pending_data = 1;
	if (pending_data) {
		tcpconn_release(c, ASYNC_WRITE_GENW, 1, 0 /*not TCP, but GEN worker*/);
		return;
	}
	tcpconn_put(c);
}


int tcp_done_reading(struct tcp_connection* con)
{
	/* Single-process TCP IO is now always enabled. */
	(void)con;
	return 0;
}

struct tcp_ipc_payload {
	struct receive_info rcv;
	int msg_len;
	char msg_buf[0];
};


/*! \brief no-op: TCP workers no longer own connection fds */
static void tcp_receive_timeout(void)
{
	/* TCP worker reads are dispatched by TCP main via shared payloads only. */
}


/*! \brief
 *  handle io routine, based on the fd_map type
 * (it will be called from reactor_main_loop )
 * params:  fm  - pointer to a fd hash entry
 *          idx - index in the fd_array (or -1 if not known)
 * return: -1 on error, or when we are not interested any more on reads
 *            from this fd (e.g.: we are closing it )
 *          0 on EAGAIN or when by some other way it is known that no more
 *            io events are queued on the fd (the receive buffer is empty).
 *            Usefull to detect when there are no more io events queued for
 *            sigio_rt, epoll_et, kqueue.
 *         >0 on successful read from the fd (when there might be more io
 *            queued -- the receive buffer might still be non-empty)
 */
inline static int handle_io(struct fd_map* fm, int idx,int event_type)
{
	int ret=0;
	int n;

	(void)idx;
	pt_become_active();

	pre_run_handle_script_reload(fm->app_flags);

	switch(fm->type){
		case F_TIMER_JOB:
			handle_timer_job();
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
		case F_TCPMAIN:
		{
			struct tcp_ipc_payload *payload;
			uintptr_t payload_ptr;
again_payload:
			ret = n = recv_all(fm->fd, &payload_ptr, sizeof(payload_ptr),
				MSG_DONTWAIT);
			if (n < 0) {
				if (errno == EWOULDBLOCK || errno == EAGAIN) {
					ret = 0;
					break;
				} else if (errno == EINTR) {
					goto again_payload;
				}
				LM_CRIT("read from tcp main dispatch socket failed: %s\n",
					strerror(errno));
				goto error;
			}
			if (n == 0) {
				LM_WARN("EOF received from tcp main dispatch socket\n");
				goto error;
			}
			if (n < (int)sizeof(payload_ptr)) {
				LM_CRIT("short read on tcp main dispatch socket: %d bytes\n", n);
				goto error;
			}

			payload = (struct tcp_ipc_payload *)(uintptr_t)payload_ptr;
			if (!payload) {
				LM_BUG("null payload pointer from tcp main\n");
				break;
			}

			bind_address = payload->rcv.bind_address;
			if (receive_msg(payload->msg_buf, payload->msg_len, &payload->rcv,
					NULL, 0) < 0)
				LM_ERR("receive_msg() failed for dispatched TCP message\n");
			shm_free(payload);
			break;
		}
		case F_NONE:
			LM_CRIT("empty fd map %p: "
						"{%d, %d, %p}\n", fm,
						fm->fd, fm->type, fm->data);
			goto error;
		default:
			LM_CRIT("unknown fd type %d\n", fm->type);
			goto error;
	}

	if (_termination_in_progress==1) {
		/* legacy timeout hook, now a no-op for TCP workers */
		tcp_receive_timeout();
		/* check if anything is still left */
		if (reactor_is_empty()) {
			LM_WARN("reactor got empty while termination in progress\n");
			ipc_handle_all_pending_jobs(IPC_FD_READ_SELF);
			if (reactor_is_empty())
				dynamic_process_final_exit();
		}
	}

	post_run_handle_script_reload();

	pt_become_idle();
	return ret;
error:
	pt_become_idle();
	return -1;
}


int tcp_worker_proc_reactor_init( int unix_sock)
{
	/* init reactor for TCP worker */
	tcpmain_sock=unix_sock; /* init com. socket */
	if ( init_worker_reactor( "TCP_worker", RCT_PRIO_MAX)<0 ) {
		goto error;
	}

	/* start watching for the timer jobs */
	if (reactor_add_reader( timer_fd_out, F_TIMER_JOB, RCT_PRIO_TIMER,NULL)<0){
		LM_CRIT("failed to add timer pipe_out to reactor\n");
		goto error;
	}

	/* init: start watching for the IPC jobs */
	if (reactor_add_reader(IPC_FD_READ_SELF, F_IPC, RCT_PRIO_ASYNC, NULL)<0){
		LM_CRIT("failed to add IPC pipe to reactor\n");
		goto error;
	}

	/* init: start watching for IPC "dispatched" jobs */
	if (reactor_add_reader(IPC_FD_READ_SHARED, F_IPC, RCT_PRIO_ASYNC, NULL)<0){
		LM_CRIT("failed to add IPC shared pipe to reactor\n");
		return -1;
	}

	/* add the unix socket */
	if (reactor_add_reader( tcpmain_sock, F_TCPMAIN, RCT_PRIO_PROC, NULL)<0) {
		LM_CRIT("failed to add socket to the fd list\n");
		goto error;
	}
	_my_fd_to_tcp_main = tcpmain_sock;

	return 0;
error:
	destroy_worker_reactor();
	return -1;
}

void tcp_worker_proc_loop(void)
{
	/* main loop */
	reactor_main_loop( TCP_CHILD_SELECT_TIMEOUT, error,
			tcp_receive_timeout());
	LM_CRIT("exiting...");
	exit(-1);
error:
	destroy_worker_reactor();
}


void tcp_terminate_worker(void)
{
	/*remove from reactor all the shared fds, so we stop reading from them */

	/*remove timer jobs pipe */
	reactor_del_reader( timer_fd_out, -1, 0);

	/*remove IPC dispatcher pipe */
	reactor_del_reader( IPC_FD_READ_SHARED, -1, 0);

	/*remove private IPC pipe */
	reactor_del_reader( IPC_FD_READ_SELF, -1, 0);

	/*remove unix sock to TCP main */
	reactor_del_reader( _my_fd_to_tcp_main, -1, 0);

	_termination_in_progress = 1;

	/* let's drain the private IPC */
	ipc_handle_all_pending_jobs(IPC_FD_READ_SELF);

	/* legacy timeout hook, now a no-op for TCP workers */
	tcp_receive_timeout();

	/* what is left now is the reactor are async fd's, so we need to 
	 * wait to complete all of them */
	if (reactor_is_empty())
		dynamic_process_final_exit();

	/* the exit will be triggered by the reactor, when empty */
	LM_INFO("reactor not empty, waiting for pending async/conns\n");
}
