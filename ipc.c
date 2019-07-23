/*
 * Copyright (C) 2017 OpenSIPS Project
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */


#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "ipc.h"
#include "dprint.h"
#include "mem/mem.h"

#include <fcntl.h>

#define IPC_HANDLER_NAME_MAX  32
typedef struct _ipc_handler {
	/* handler function */
	ipc_handler_f *func;
	/* same name/description, null terminated */
	char name[IPC_HANDLER_NAME_MAX+1];
} ipc_handler;

typedef struct _ipc_job {
	/* the ID (internal) of the process sending the job */
	unsigned short snd_proc;
	/* the job's handler type */
	ipc_handler_type handler_type;
	/* the payload of the job, just pointers */
	void *payload1;
	void *payload2;
} ipc_job;

static ipc_handler *ipc_handlers = NULL;
static unsigned int ipc_handlers_no = 0;

/* shared IPC support: dispatching a job to a random OpenSIPS worker */
static int ipc_shared_pipe[2];

/* IPC type used for RPC - a self registered type */
static ipc_handler_type ipc_rpc_type = 0;

/* FD (pipe) used for dispatching IPC jobs between all processes (1 to any) */
int ipc_shared_fd_read;

int init_ipc(void)
{
	int optval;

	/* create the pipe for dispatching the timer jobs */
	if (pipe(ipc_shared_pipe) != 0) {
		LM_ERR("failed to create ipc pipe (%s)!\n", strerror(errno));
		return -1;
	}

	/* make reading fd non-blocking */
	optval = fcntl(ipc_shared_pipe[0], F_GETFL);
	if (optval == -1) {
		LM_ERR("fcntl failed: (%d) %s\n", errno, strerror(errno));
		return -1;
	}

	if (fcntl(ipc_shared_pipe[0], F_SETFL, optval|O_NONBLOCK) == -1) {
		LM_ERR("set non-blocking failed: (%d) %s\n", errno, strerror(errno));
		return -1;
	}

	ipc_shared_fd_read = ipc_shared_pipe[0];

	/* self-register the IPC type for RPC */
	ipc_rpc_type = ipc_register_handler( NULL, "RPC");
	if (ipc_bad_handler_type(ipc_rpc_type)) {
		LM_ERR("failed to self register RPC type\n");
		return -1;
	}

	/* we are all set */
	return 0;
}


int create_ipc_pipes( int proc_no )
{
	int i;

	for( i=0 ; i<proc_no ; i++ ) {
		if (pipe(pt[i].ipc_pipe_holder)<0) {
			LM_ERR("failed to create IPC pipe for process %d, err %d/%s\n",
				i, errno, strerror(errno));
			return -1;
		}

		if (pipe(pt[i].ipc_sync_pipe_holder)<0) {
			LM_ERR("failed to create IPC sync pipe for process %d, err %d/%s\n",
				i, errno, strerror(errno));
			return -1;
		}
	}
	return 0;
}


ipc_handler_type ipc_register_handler( ipc_handler_f *hdl, char *name)
{
	ipc_handler *new;

	/* allocate an n+1 new buffer to accomodate the new handler */
	new = (ipc_handler*)
		pkg_malloc( (ipc_handlers_no+1)*sizeof(ipc_handler) );
	if (new==NULL) {
		LM_ERR("failed to alloctes IPC handler array for size %d\n",
			ipc_handlers_no+1);
		return -1;
	}

	/* copy previous records, if any */
	if (ipc_handlers) {
		memcpy( new, ipc_handlers, ipc_handlers_no*sizeof(ipc_handler) );
		pkg_free( ipc_handlers );
	}

	/* copy handler function */
	new[ipc_handlers_no].func = hdl;

	/* copy the name, trunkate it needed, but keep it null terminated */
	strncpy( new[ipc_handlers_no].name , name, IPC_HANDLER_NAME_MAX);
	new[ipc_handlers_no].name[IPC_HANDLER_NAME_MAX] = 0;

	ipc_handlers = new;

	LM_DBG("IPC type %d [%s] registered with handler %p\n",
		ipc_handlers_no, ipc_handlers[ipc_handlers_no].name, hdl );

	return ipc_handlers_no++;
}


static inline int __ipc_send_job(int fd, ipc_handler_type type,
												void *payload1, void *payload2)
{
	ipc_job job;
	int n;

	// FIXME - we should check if the destination process really listens
	// for read, otherwise we may end up filling in the pipe and block

	job.snd_proc = (short)process_no;
	job.handler_type = type;
	job.payload1 = payload1;
	job.payload2 = payload2;

again:
	// TODO - should we do this non blocking and discard if we block ??
	n = write(fd, &job, sizeof(job) );
	if (n<0) {
		if (errno==EINTR)
			goto again;
		LM_ERR("sending job type %d[%s] on %d failed: %s\n",
			type, ipc_handlers[type].name, fd, strerror(errno));
		return -1;
	}
	return 0;
}

int ipc_send_job(int dst_proc, ipc_handler_type type, void *payload)
{
	return __ipc_send_job(IPC_FD_WRITE(dst_proc), type, payload, NULL);
}

int ipc_dispatch_job(ipc_handler_type type, void *payload)
{
	return __ipc_send_job(ipc_shared_pipe[1], type, payload, NULL);
}

int ipc_send_rpc(int dst_proc, ipc_rpc_f *rpc, void *param)
{
	return __ipc_send_job(IPC_FD_WRITE(dst_proc), ipc_rpc_type, rpc, param);
}

int ipc_dispatch_rpc( ipc_rpc_f *rpc, void *param)
{
	return __ipc_send_job(ipc_shared_pipe[1], ipc_rpc_type, rpc, param);
}

int ipc_send_sync_reply(int dst_proc, void *param)
{
	int n;

again:
	n = write(IPC_FD_SYNC_WRITE(dst_proc), &param, sizeof(param));
	if (n<0) {
		if (errno==EINTR)
			goto again;
		LM_ERR("sending sync rpc %d[%s]\n", errno, strerror(errno));
		return -1;
	}
	return 0;
}

int ipc_recv_sync_reply(void **param)
{
	void *ret;
	int n;

again:
	n = read(IPC_FD_SYNC_READ_SELF, &ret, sizeof(ret));
	if (n < sizeof(*ret)) {
		if (errno == EINTR)
			goto again;
		/* if we got here, it's definitely an error, because the socket is
		 * blocking, so we can't read partial messages */
		LM_ERR("read failed:[%d] %s\n", errno, strerror(errno));
		return -1;
	}
	*param = ret;
	return 0;
}

void ipc_handle_job(int fd)
{
	ipc_job job;
	int n;

	/* read one IPC job from the pipe; even if the read is blocking,
	 * we are here triggered from the reactor, on a READ event, so 
	 * we shouldn;t ever block */
	n = read(fd, &job, sizeof(job) );
	if (n==-1) {
		if (errno==EAGAIN || errno==EINTR || errno==EWOULDBLOCK )
			return;
		LM_ERR("read failed:[%d] %s\n", errno, strerror(errno));
		return;
	}

	LM_DBG("received job type %d[%s] from process %d\n",
		job.handler_type, ipc_handlers[job.handler_type].name, job.snd_proc);

	/* custom handling for RPC type */
	if (job.handler_type==ipc_rpc_type) {
		((ipc_rpc_f*)job.payload1)( job.snd_proc, job.payload2);
	} else {
		/* generic registered type */
		ipc_handlers[job.handler_type].func( job.snd_proc, job.payload1);
	}

	return;
}


void ipc_handle_all_pending_jobs(int fd)
{
	char buf;

	while ( recv(fd, &buf, 1, MSG_DONTWAIT|MSG_PEEK)==1 )
		ipc_handle_job(fd);
}

