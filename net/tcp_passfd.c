/*
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
 *  2002-11-29  created by andrei
 *  2003-02-20  added solaris support (! HAVE_MSGHDR_MSG_CONTROL) (andrei)
 *  2003-11-03  added send_all, recv_all  and updated send/get_fd
 *               to handle signals  (andrei)
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <stdlib.h> /* for NULL definition on openbsd */
#include <errno.h>
#include <string.h>

#include "../dprint.h"



/* receive all the data or returns error (handles EINTR etc.)
 * params: socket
 *         data     - buffer for the results
 *         data_len -
 *         flags    - recv flags for the first recv (see recv(2)), only
 *                    0, MSG_WAITALL and MSG_DONTWAIT make sense
 * if flags is set to MSG_DONWAIT (or to 0 and the socket fd is non-blocking),
 * and if no data is queued on the fd, recv_all will not wait (it will
 * return error and set errno to EAGAIN/EWOULDBLOCK). However if even 1 byte
 *  is queued, the call will block until the whole data_len was read or an
 *  error or eof occurred ("semi-nonblocking" behaviour,  some tcp code
 *   counts on it).
 * if flags is set to MSG_WAITALL it will block even if no byte is available.
 *
 * returns: bytes read or error (<0)
 * can return < data_len if EOF */
int recv_all(int socket, void* data, int data_len, int flags)
{
	int b_read;
	int n;

	b_read=0;
again:
	n=recv(socket, (char*)data, data_len, flags);
	if (n<0){
		/* error */
		if (errno==EINTR) goto again; /* signal, try again */
		/* on EAGAIN just return (let the caller know) */
		if ((errno==EAGAIN)||(errno==EWOULDBLOCK)) return n;
			LM_CRIT("1st recv on %d failed: %s\n", socket, strerror(errno));
			return n;
	}
	b_read+=n;
	while( (b_read!=data_len) && (n)){
		n=recv(socket, (char*)data+b_read, data_len-b_read, MSG_WAITALL);
		if (n<0){
			/* error */
			if (errno==EINTR) continue; /* signal, try again */
			LM_CRIT("2nd recv on %d failed: %s\n",
					socket, strerror(errno));
			return n;
		}
		b_read+=n;
	}
	return b_read;
}



/* sends all data (takes care of signals) (assumes blocking fd)
 * returns number of bytes sent or < 0 for an error */
int send_all(int socket, void* data, int data_len)
{
	int n;

again:
	n=send(socket, data, data_len, 0);
	if (n<0){
			/* error */
		if (errno==EINTR) goto again; /* signal, try again */
		LM_CRIT("send on %d failed: %s\n", socket, strerror(errno));
	}
	return n;
}

/* gcc does the right thing */
static inline int get_unaligned_int(const void *p)
{
	const struct { int d; } __attribute__((packed)) *pp = p;
	return pp->d;
}

/* gcc does the right thing */
static inline void put_unaligned_int(void *p, int value)
{
	struct { int d; } __attribute__((packed, may_alias)) *pp = p;
	pp->d = value;
}

/* at least 1 byte must be sent! */
int send_fd(int unix_socket, void* data, int data_len, int fd)
{
	struct msghdr msg;
	struct iovec iov[1];
	int ret;
#ifdef HAVE_MSGHDR_MSG_CONTROL
	struct cmsghdr* cmsg;
	/* make sure msg_control will point to properly aligned data */
	union {
		struct cmsghdr cm;
		char control[CMSG_SPACE(sizeof(fd))];
	}control_un;

	msg.msg_control=control_un.control;
	/* openbsd doesn't like "more space", msg_controllen must not
	 * include the end padding */
	msg.msg_controllen=CMSG_LEN(sizeof(fd));

	cmsg=CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
	put_unaligned_int(CMSG_DATA(cmsg), fd);
	msg.msg_flags=0;
#else
	msg.msg_accrights=(caddr_t) &fd;
	msg.msg_accrightslen=sizeof(fd);
#endif

	msg.msg_name=0;
	msg.msg_namelen=0;

	iov[0].iov_base=data;
	iov[0].iov_len=data_len;
	msg.msg_iov=iov;
	msg.msg_iovlen=1;

again:
	ret=sendmsg(unix_socket, &msg, 0);
	if (ret<0){
		if (errno==EINTR) goto again;
		if (errno==EAGAIN || errno==EWOULDBLOCK) {
			LM_ERR("sendmsg would block on %d: %s\n",
				unix_socket, strerror(errno));
		} else {
			LM_CRIT("sendmsg failed on %d: %s\n",
				unix_socket, strerror(errno));
		}
	}

	return ret;
}



/* receives a fd and data_len data
 * params: unix_socket
 *         data
 *         data_len
 *         fd         - will be set to the passed fd value or -1 if no fd
 *                      was passed
 *         flags      - 0, MSG_DONTWAIT, MSG_WAITALL; same as recv_all flags
 * returns: bytes read on success, -1 on error (and sets errno) */
int receive_fd(int unix_socket, void* data, int data_len, int* fd, int flags)
{
	struct msghdr msg;
	struct iovec iov[1];
	int new_fd;
	int ret;
	int n;
#ifdef HAVE_MSGHDR_MSG_CONTROL
	struct cmsghdr* cmsg;
	union{
		struct cmsghdr cm;
		char control[CMSG_SPACE(sizeof(new_fd))];
	}control_un;

	msg.msg_control=control_un.control;
	msg.msg_controllen=sizeof(control_un.control);
#else
	msg.msg_accrights=(caddr_t) &new_fd;
	msg.msg_accrightslen=sizeof(int);
#endif

	msg.msg_name=0;
	msg.msg_namelen=0;

	iov[0].iov_base=data;
	iov[0].iov_len=data_len;
	msg.msg_iov=iov;
	msg.msg_iovlen=1;
	msg.msg_flags = 0;

again:
	ret=recvmsg(unix_socket, &msg, flags);
	if (ret<0){
		if (errno==EINTR) goto again;
		if ((errno==EAGAIN)||(errno==EWOULDBLOCK)) goto error;
		LM_CRIT("recvmsg on %d failed: %s\n", unix_socket, strerror(errno));
		goto error;
	}
	if (ret==0){
		/* EOF */
		LM_CRIT("EOF on %d\n", unix_socket);
		goto error;
	}
	if (ret<data_len){
		LM_WARN("too few bytes read (%d from %d) trying to fix...\n",
				ret, data_len);
		/* blocking recv_all */
		n=recv_all(unix_socket, (char*)data+ret, data_len-ret, MSG_WAITALL);
		if (n>=0) ret+=n;
		else{
			ret=n;
			goto error;
		}
	}

#ifdef HAVE_MSGHDR_MSG_CONTROL
	cmsg=CMSG_FIRSTHDR(&msg);
	if ((cmsg!=0) && (cmsg->cmsg_len==CMSG_LEN(sizeof(new_fd)))){
		if (cmsg->cmsg_type!= SCM_RIGHTS){
			LM_ERR("msg control type != SCM_RIGHTS\n");
			ret=-1;
			goto error;
		}
		if (cmsg->cmsg_level!= SOL_SOCKET){
			LM_ERR("msg level != SOL_SOCKET\n");
			ret=-1;
			goto error;
		}
		*fd = get_unaligned_int(CMSG_DATA(cmsg));
	}else{
		/*
		LM_ERR("no descriptor passed, cmsg=%p,len=%d\n",
			cmsg, (unsigned)cmsg->cmsg_len); */
		*fd=-1;
		/* it's not really an error */
	}
#else
	if (msg.msg_accrightslen==sizeof(int)){
		*fd=new_fd;
	}else{
		/*LM_ERR("no descriptor passed, accrightslen=%d\n",
			msg.msg_accrightslen); */
		*fd=-1;
	}
#endif

error:
	return ret;
}
