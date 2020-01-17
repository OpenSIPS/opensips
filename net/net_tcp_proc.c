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


#include "../pt_load.h"
#include "../ipc.h"
#include "../timer.h"
#include "../reactor.h"
#include "../async.h"
#include "../cfg_reload.h"

#include "tcp_conn.h"
#include "tcp_passfd.h"
#include "net_tcp_report.h"
#include "net_tcp_dbg.h"
#include "trans.h"


/*!< the FD currently used by the process to communicate with TCP MAIN*/
static int _my_fd_to_tcp_main = -1;

/*!< list of tcp connections handled by this process */
static struct tcp_connection* tcp_conn_lst=0;

static int tcpmain_sock=-1;
extern int unix_tcp_sock;

extern struct struct_hist_list *con_hist;

#define tcpconn_release_error(_conn, _writer, _reason) \
	do { \
		tcp_trigger_report( _conn, TCP_REPORT_CLOSE, _reason);\
		tcpconn_release( _conn, CONN_ERROR, _writer);\
	}while(0)




static void tcpconn_release(struct tcp_connection* c, long state,int writer)
{
	long response[2];

	LM_DBG(" releasing con %p, state %ld, fd=%d, id=%d\n",
			c, state, c->fd, c->id);
	LM_DBG(" extra_data %p\n", c->extra_data);

	/* if we are in a writer context, do not touch the buffer contain read packets per connection
	might be in a completely different process
	even if in our process we shouldn't touch it, since it might currently be in use, when we've read multiple SIP messages in one try*/
	if (!writer && c->con_req) {
		pkg_free(c->con_req);
		c->con_req = NULL;
	}

	/* release req & signal the parent */
	if (!writer)
		c->proc_id = -1;

	/* errno==EINTR, EWOULDBLOCK a.s.o todo */
	response[0]=(long)c;
	response[1]=state;

	if (send_all((tcpmain_sock==-1)?unix_tcp_sock:tcpmain_sock, response,
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
		c->lifetime=0;
		/* CONN_ERROR will auto-dec refcnt => we must not call tcpconn_put !!*/
		tcpconn_release(c, CONN_ERROR2,1);
		return;
	}
	if (pending_data) {
		tcpconn_release(c, ASYNC_WRITE2,1);
		return;
	}
	tcpconn_put(c);
}


/*! \brief  releases expired connections and cleans up bad ones (state<0) */
static void tcp_receive_timeout(void)
{
	struct tcp_connection* con;
	struct tcp_connection* next;
	unsigned int ticks;

	ticks=get_ticks();
	for (con=tcp_conn_lst; con; con=next) {
		next=con->c_next; /* safe for removing */
		if (con->state<0){   /* kill bad connections */
			/* S_CONN_BAD or S_CONN_ERROR, remove it */
			/* fd will be closed in tcpconn_release */

			reactor_del_reader(con->fd, -1/*idx*/, IO_FD_CLOSING/*io_flags*/ );
			tcpconn_check_del(con);
			tcpconn_listrm(tcp_conn_lst, con, c_next, c_prev);
			con->proc_id = -1;
			con->state=S_CONN_BAD;
			if (con->fd!=-1) { close(con->fd); con->fd = -1; }
			sh_log(con->hist, TCP_SEND2MAIN, "state: %d, att: %d",
			       con->state, con->msg_attempts);
			tcpconn_release_error(con, 0, "Unknown reason");
			continue;
		}
		/* pass back to Main connections that are inactive (expired) or
		 * if we are in termination mode (this worker is doing graceful 
		 * shutdown) and there is no pending data on the conn. */
		if (con->timeout<=ticks ||
		(_termination_in_progress && !con->msg_attempts) ){
			LM_DBG("%p expired - (%d, %d) lt=%d\n",
					con, con->timeout, ticks,con->lifetime);
			/* fd will be closed in tcpconn_release */
			reactor_del_reader(con->fd, -1/*idx*/, IO_FD_CLOSING/*io_flags*/ );
			tcpconn_check_del(con);
			tcpconn_listrm(tcp_conn_lst, con, c_next, c_prev);

			/* connection is going to main */
			con->proc_id = -1;
			if (con->fd!=-1) { close(con->fd); con->fd = -1; }

			sh_log(con->hist, TCP_SEND2MAIN, "timeout: %d, att: %d",
			       con->timeout, con->msg_attempts);
			if (con->msg_attempts)
				tcpconn_release_error(con, 0, "Read timeout with"
					"incomplete SIP message");
			else
				tcpconn_release(con, CONN_RELEASE,0);
		}
	}
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
	struct tcp_connection* con;
	int s,rw;
	long resp;
	long response[2];

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
again:
			ret=n=receive_fd(fm->fd, response, sizeof(response), &s, 0);
			if (n<0){
				if (errno == EWOULDBLOCK || errno == EAGAIN){
					ret=0;
					break;
				}else if (errno == EINTR) goto again;
				else{
					LM_CRIT("read_fd: %s \n", strerror(errno));
						abort(); /* big error*/
				}
			}
			if (n==0){
				LM_WARN("0 bytes read\n");
				break;
			}
			con = (struct tcp_connection *)response[0];
			rw = (int)response[1];

			if (con==0){
					LM_CRIT("null pointer\n");
					break;
			}
			if (s==-1) {
				LM_BUG("read_fd:no fd read\n");
				/* FIXME? */
				goto error;
			}

			if (!(con->flags & F_CONN_INIT)) {
				if (protos[con->type].net.conn_init &&
						protos[con->type].net.conn_init(con) < 0) {
					LM_ERR("failed to do proto %d specific init for conn %p\n",
							con->type, con);
					goto con_error;
				}
				con->flags |= F_CONN_INIT;
			}

			LM_DBG("We have received conn %p with rw %d on fd %d\n",con,rw,s);
			if (rw & IO_WATCH_READ) {
				if (tcpconn_list_find(con, tcp_conn_lst)) {
					LM_CRIT("duplicate connection received: %p, id %d, fd %d, "
					        "refcnt %d state %d (n=%d)\n", con, con->id,
					        con->fd, con->refcnt, con->state, n);
					tcpconn_release_error(con, 0, "Internal duplicate");
					break; /* try to recover */
				}

				/* 0 attempts so far for this SIP MSG */
				con->msg_attempts = 0;

				/* must be before reactor_add, as the add might catch some
				 * already existing events => might call handle_io and
				 * handle_io might decide to del. the new connection =>
				 * must be in the list */
				tcpconn_check_add(con);
				tcpconn_listadd(tcp_conn_lst, con, c_next, c_prev);
				/* pending event on a connection -> prevent premature expiry */
				tcp_conn_set_lifetime(con, tcp_con_lifetime);
				con->timeout = con->lifetime;
				if (reactor_add_reader( s, F_TCPCONN, RCT_PRIO_NET, con )<0) {
					LM_CRIT("failed to add new socket to the fd list\n");
					tcpconn_check_del(con);
					tcpconn_listrm(tcp_conn_lst, con, c_next, c_prev);
					goto con_error;
				}

				/* mark that the connection is currently in our process
				future writes to this con won't have to acquire FD */
				con->proc_id = process_no;
				/* save FD which is valid in context of this TCP worker */
				con->fd=s;
			} else if (rw & IO_WATCH_WRITE) {
				LM_DBG("Received con for async write %p ref = %d\n",con,con->refcnt);
				lock_get(&con->write_lock);
				resp = protos[con->type].net.write( (void*)con, s );
				lock_release(&con->write_lock);
				if (resp<0) {
					ret=-1; /* some error occurred */
					con->state=S_CONN_BAD;
					sh_log(con->hist, TCP_SEND2MAIN, "handle write, err, state: %d, att: %d",
					       con->state, con->msg_attempts);
					tcpconn_release_error(con, 1,"Write error");
					break;
				} else if (resp==1) {
					sh_log(con->hist, TCP_SEND2MAIN, "handle write, async, state: %d, att: %d",
					       con->state, con->msg_attempts);
					tcpconn_release(con, ASYNC_WRITE,1);
				} else {
					sh_log(con->hist, TCP_SEND2MAIN, "handle write, ok, state: %d, att: %d",
					       con->state, con->msg_attempts);
					tcpconn_release(con, CONN_RELEASE_WRITE,1);
				}
				ret = 0;
				/* we always close the socket received for writing */
				close(s);
			}
			break;
		case F_TCPCONN:
			if (event_type & IO_WATCH_READ) {
				con=(struct tcp_connection*)fm->data;
				resp = protos[con->type].net.read( (void*)con, &ret );
				if (resp<0) {
					ret=-1; /* some error occurred */
					con->state=S_CONN_BAD;
					reactor_del_all( con->fd, idx, IO_FD_CLOSING );
					tcpconn_check_del(con);
					tcpconn_listrm(tcp_conn_lst, con, c_next, c_prev);
					con->proc_id = -1;
					if (con->fd!=-1) { close(con->fd); con->fd = -1; }
					sh_log(con->hist, TCP_SEND2MAIN, "handle read, err, resp: %d, att: %d",
					       resp, con->msg_attempts);
					tcpconn_release_error(con, 0, "Read error");
				} else if (con->state==S_CONN_EOF) {
					reactor_del_all( con->fd, idx, IO_FD_CLOSING );
					tcpconn_check_del(con);
					tcpconn_listrm(tcp_conn_lst, con, c_next, c_prev);
					con->proc_id = -1;
					if (con->fd!=-1) { close(con->fd); con->fd = -1; }
					tcp_trigger_report( con, TCP_REPORT_CLOSE,
						"EOF received");
					sh_log(con->hist, TCP_SEND2MAIN, "handle read, EOF, resp: %d, att: %d",
					       resp, con->msg_attempts);
					tcpconn_release(con, CONN_EOF,0);
				} else {
					//tcpconn_release(con, CONN_RELEASE);
					/* keep the connection for now */
					break;
				}
			}
			break;
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
		/* force (again) passing back all the active conns */
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
con_error:
	con->state=S_CONN_BAD;
	tcpconn_release_error(con, 0, "Internal error");
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
	reactor_main_loop( TCP_CHILD_SELECT_TIMEOUT, error, tcp_receive_timeout());
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

	/* force passing back all the active conns */
	tcp_receive_timeout();

	/* what is left now is the reactor are async fd's, so we need to 
	 * wait to complete all of them */
	if (reactor_is_empty())
		dynamic_process_final_exit();

	/* the exit will be triggered by the reactor, when empty */
	LM_INFO("reactor not empty, waiting for pending async/conns\n");
}

