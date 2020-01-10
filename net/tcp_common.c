/*
 * Copyright (C) 2019 - OpenSIPS Solutions
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
 */

#include "../reactor_defs.h"
#include "net_tcp.h"
#include "tcp_common.h"
#include "../tsend.h"

/*! \brief blocking connect on a non-blocking fd; it will timeout after
 * tcp_connect_timeout
 * if BLOCKING_USE_SELECT and HAVE_SELECT are defined it will internally
 * use select() instead of poll (bad if fd > FD_SET_SIZE, poll is preferred)
 */
int tcp_connect_blocking_timeout(int fd, const struct sockaddr *servaddr,
											socklen_t addrlen, int timeout)
{
	int n;
#if defined(HAVE_SELECT) && defined(BLOCKING_USE_SELECT)
	fd_set sel_set;
	fd_set orig_set;
	struct timeval timeout;
#else
	struct pollfd pf;
#endif
	int elapsed;
	int to;
	int err;
	struct timeval begin;
	unsigned int err_len;
	int poll_err;
	char *ip;
	unsigned short port;

	poll_err=0;
	to = timeout*1000;

	if (gettimeofday(&(begin), NULL)) {
		LM_ERR("Failed to get TCP connect start time\n");
		goto error;
	}

again:
	n=connect(fd, servaddr, addrlen);
	if (n==-1){
		if (errno==EINTR){
			elapsed=get_time_diff(&begin);
			if (elapsed<to) goto again;
			else goto error_timeout;
		}
		if (errno!=EINPROGRESS && errno!=EALREADY){
			get_su_info( servaddr, ip, port);
			LM_ERR("[server=%s:%d] (%d) %s\n",ip, port, errno, strerror(errno));
			goto error;
		}
	}else goto end;

	/* poll/select loop */
#if defined(HAVE_SELECT) && defined(BLOCKING_USE_SELECT)
		FD_ZERO(&orig_set);
		FD_SET(fd, &orig_set);
#else
		pf.fd=fd;
		pf.events=POLLOUT;
#endif
	while(1){
		elapsed = get_time_diff(&begin);
		if (elapsed<to)
			to-=elapsed;
		else
			goto error_timeout;
#if defined(HAVE_SELECT) && defined(BLOCKING_USE_SELECT)
		sel_set=orig_set;
		timeout.tv_sec = to/1000000;
		timeout.tv_usec = to%1000000;
		n=select(fd+1, 0, &sel_set, 0, &timeout);
#else
		n=poll(&pf, 1, to/1000);
#endif
		if (n<0){
			if (errno==EINTR) continue;
			get_su_info( servaddr, ip, port);
			LM_ERR("poll/select failed:[server=%s:%d] (%d) %s\n",
				ip, port, errno, strerror(errno));
			goto error;
		}else if (n==0) /* timeout */ continue;
#if defined(HAVE_SELECT) && defined(BLOCKING_USE_SELECT)
		if (FD_ISSET(fd, &sel_set))
#else
		if (pf.revents&(POLLERR|POLLHUP|POLLNVAL)){
			LM_ERR("poll error: flags %d - %d %d %d %d \n", pf.revents,
				   POLLOUT,POLLERR,POLLHUP,POLLNVAL);
			poll_err=1;
		}
#endif
		{
			err_len=sizeof(err);
			getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
			if ((err==0) && (poll_err==0)) goto end;
			if (err!=EINPROGRESS && err!=EALREADY){
				get_su_info( servaddr, ip, port);
				LM_ERR("failed to retrieve SO_ERROR [server=%s:%d] (%d) %s\n",
					ip, port, err, strerror(err));
				goto error;
			}
		}
	}
error_timeout:
	/* timeout */
	LM_ERR("connect timed out, %d us elapsed out of %d us\n", elapsed,
		timeout*1000);
error:
	return -1;
end:
	return 0;
}

int tcp_connect_blocking(int fd, const struct sockaddr *servaddr,
															socklen_t addrlen)
{
	return tcp_connect_blocking_timeout(fd, servaddr, addrlen,
			tcp_connect_timeout);
}

int tcp_sync_connect_fd(union sockaddr_union* src, union sockaddr_union* dst)
{
	int s;
	union sockaddr_union my_name;
	socklen_t my_name_len;

	s=socket(AF2PF(dst->s.sa_family), SOCK_STREAM, 0);
	if (s==-1){
		LM_ERR("socket: (%d) %s\n", errno, strerror(errno));
		goto error;
	}
	if (tcp_init_sock_opt(s)<0){
		LM_ERR("tcp_init_sock_opt failed\n");
		goto error;
	}
	if (src) {
		my_name_len = sockaddru_len(*src);
		memcpy( &my_name, src, my_name_len);
		su_setport( &my_name, 0);
		if (bind(s, &my_name.s, my_name_len )!=0) {
			LM_ERR("bind failed (%d) %s\n", errno,strerror(errno));
			goto error;
		}
	}

	if (tcp_connect_blocking(s, &dst->s, sockaddru_len(*dst))<0){
		LM_ERR("tcp_blocking_connect failed\n");
		goto error;
	}
	return s;
error:
	/* close the opened socket */
	if (s!=-1) close(s);
	return -1;
}

struct tcp_connection* tcp_sync_connect(struct socket_info* send_sock,
		union sockaddr_union* server, int *fd, int send2main)
{
	struct tcp_connection* con;
	int s;

	s = tcp_sync_connect_fd(&send_sock->su, server);
	if (s < 0)
		return NULL;

	con=tcp_conn_create(s, server, send_sock, S_CONN_OK, send2main);
	if (con==NULL){
		LM_ERR("tcp_conn_create failed, closing the socket\n");
		close(s);
		return 0;
	}
	*fd = s;
	return con;
}

int tcp_async_connect(struct socket_info* send_sock,
					union sockaddr_union* server, int timeout,
					struct tcp_connection** c, int *ret_fd, int send2main)
{
	int fd, n;
	union sockaddr_union my_name;
	socklen_t my_name_len;
	struct tcp_connection* con;
#if defined(HAVE_SELECT) && defined(BLOCKING_USE_SELECT)
	fd_set sel_set;
	fd_set orig_set;
	struct timeval timeout_val;
#else
	struct pollfd pf;
#endif
	unsigned int elapsed,to;
	int err;
	unsigned int err_len;
	int poll_err;
	char *ip;
	unsigned short port;
	struct timeval begin;

	/* create the socket */
	fd=socket(AF2PF(server->s.sa_family), SOCK_STREAM, 0);
	if (fd==-1){
		LM_ERR("socket: (%d) %s\n", errno, strerror(errno));
		return -1;
	}
	if (tcp_init_sock_opt(fd)<0){
		LM_ERR("tcp_init_sock_opt failed\n");
		goto error;
	}
	my_name_len = sockaddru_len(send_sock->su);
	memcpy( &my_name, &send_sock->su, my_name_len);
	su_setport( &my_name, 0);
	if (bind(fd, &my_name.s, my_name_len )!=0) {
		LM_ERR("bind failed (%d) %s\n", errno,strerror(errno));
		goto error;
	}

	/* attempt to do connect and see if we do block or not */
	poll_err=0;
	elapsed = 0;
	to = timeout*1000;

	if (gettimeofday(&(begin), NULL)) {
		LM_ERR("Failed to get TCP connect start time\n");
		goto error;
	}

again:
	n=connect(fd, &server->s, sockaddru_len(*server));
	if (n==-1) {
		if (errno==EINTR){
			elapsed=get_time_diff(&begin);
			if (elapsed<to) goto again;
			else {
				LM_DBG("Local connect attempt failed \n");
				goto async_connect;
			}
		}
		if (errno!=EINPROGRESS && errno!=EALREADY){
			get_su_info(&server->s, ip, port);
			LM_ERR("[server=%s:%d] (%d) %s\n",ip, port, errno,strerror(errno));
			goto error;
		}
	} else goto local_connect;

	/* let's poll for a little */
#if defined(HAVE_SELECT) && defined(BLOCKING_USE_SELECT)
	FD_ZERO(&orig_set);
	FD_SET(fd, &orig_set);
#else
	pf.fd=fd;
	pf.events=POLLOUT;
#endif

	while(1){
		elapsed=get_time_diff(&begin);
		if (elapsed<to)
			to-=elapsed;
		else {
			LM_DBG("Polling is overdue \n");
			goto async_connect;
		}
#if defined(HAVE_SELECT) && defined(BLOCKING_USE_SELECT)
		sel_set=orig_set;
		timeout_val.tv_sec=to/1000000;
		timeout_val.tv_usec=to%1000000;
		n=select(fd+1, 0, &sel_set, 0, &timeout_val);
#else
		n=poll(&pf, 1, to/1000);
#endif
		if (n<0){
			if (errno==EINTR) continue;
			get_su_info(&server->s, ip, port);
			LM_ERR("poll/select failed:[server=%s:%d] (%d) %s\n",
				ip, port, errno, strerror(errno));
			goto error;
		}else if (n==0) /* timeout */ continue;
#if defined(HAVE_SELECT) && defined(BLOCKING_USE_SELECT)
		if (FD_ISSET(fd, &sel_set))
#else
		if (pf.revents&(POLLERR|POLLHUP|POLLNVAL)){
			LM_ERR("poll error: flags %x\n", pf.revents);
			poll_err=1;
		}
#endif
		{
			err_len=sizeof(err);
			getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
			if ((err==0) && (poll_err==0)) goto local_connect;
			if (err!=EINPROGRESS && err!=EALREADY){
				get_su_info(&server->s, ip, port);
				LM_ERR("failed to retrieve SO_ERROR [server=%s:%d] (%d) %s\n",
					ip, port, err, strerror(err));
				goto error;
			}
		}
	}

async_connect:
	LM_DBG("Create connection for async connect\n");
	/* create a new dummy connection */
	con=tcp_conn_create(fd, server, send_sock, S_CONN_CONNECTING, send2main);
	if (con==NULL) {
		LM_ERR("tcp_conn_create failed\n");
		goto error;
	}
	/* report an async, in progress connect */
	*c = con;
	return 0;

local_connect:
	con=tcp_conn_create(fd, server, send_sock, S_CONN_OK, send2main);
	if (con==NULL) {
		LM_ERR("tcp_conn_create failed, closing the socket\n");
		goto error;
	}
	*c = con;
	*ret_fd = fd;
	/* report a local connect */
	return 1;

error:
	close(fd);
	*c = NULL;
	return -1;
}

int tcp_async_write(struct tcp_connection* con,int fd)
{
	int n;
	struct tcp_async_chunk *chunk;

	while ((chunk = tcp_async_get_chunk(con)) != NULL) {
		LM_DBG("Trying to send %d bytes from chunk %p in conn %p - %d %d \n",
				chunk->len, chunk, con, chunk->ticks, get_ticks());
		n=send(fd, chunk->buf, chunk->len,
#ifdef HAVE_MSG_NOSIGNAL
				MSG_NOSIGNAL
#else
				0
#endif
			  );

		if (n<0) {
			if (errno==EINTR)
				continue;
			else if (errno==EAGAIN || errno==EWOULDBLOCK) {
				LM_DBG("Can't finish to write chunk %p on conn %p\n",
						chunk,con);
				/* report back we have more writting to be done */
				return 1;
			} else {
				LM_ERR("Error occurred while sending async chunk %d (%s)\n",
						errno,strerror(errno));
				/* report the conn as broken */
				return -1;
			}
		}
		tcp_async_update_write(con, n);
	}
	return 0;
}

/**
 * called under the TCP connection write lock, timeout is in milliseconds
 *
 * @return: -1 or bytes written (if 0 < ret < len: the last bytes are chunked)
 */
static int tsend_stream_async(struct tcp_connection *c,
		int fd, char* buf, unsigned int len, int timeout)
{
	int written;
	int n;
	struct pollfd pf;

	pf.fd=fd;
	pf.events=POLLOUT;
	written=0;

again:
	n=send(fd, buf, len,0);
	if (n<0){
		if (errno==EINTR) goto again;
		else if (errno!=EAGAIN && errno!=EWOULDBLOCK) {
			LM_ERR("Failed first TCP async send : (%d) %s\n",
					errno, strerror(errno));
			return -1;
		} else
			goto poll_loop;
	}

	written+=n;
	if (n < len) {
		/* partial write */
		buf += n;
		len -= n;
	} else {
		/* successful write from the first try */
		LM_DBG("Async successful write from first try on %p\n",c);
		return len;
	}

poll_loop:
	n = poll(&pf,1,timeout);
	if (n<0) {
		if (errno==EINTR)
			goto poll_loop;
		LM_ERR("Polling while trying to async send failed %s [%d]\n",
				strerror(errno), errno);
		return -1;
	} else if (n == 0) {
		LM_DBG("timeout -> do an async write (add it to conn)\n");
		/* timeout - let's just pass to main */
		if (tcp_async_add_chunk(c,buf,len,0) < 0) {
			LM_ERR("Failed to add write chunk to connection \n");
			return -1;
		} else {
			/* we have successfully added async write chunk
			 * tell MAIN to poll out for us */
			LM_DBG("Data still pending for write on conn %p\n",c);
			return 0;
		}
	}

	if (pf.revents&POLLOUT)
		goto again;

	/* some other events triggered by poll - treat as errors */
	return -1;
}

int tcp_write_on_socket(struct tcp_connection* c, int fd,
		char *buf, int len, int write_timeout, int async_write_timeout)
{
	int n;

	lock_get(&c->write_lock);
	if (c->async) {
		/*
		 * if there is any data pending to write, we have to wait for those chunks
		 * to be sent, otherwise we will completely break the messages' order
		 */
		if (c->async->pending)
			n = tcp_async_add_chunk(c, buf, len, 0);
		else
			n = tsend_stream_async(c,fd,buf,len, async_write_timeout);
	} else {
		n = tsend_stream(fd, buf, len, write_timeout);
	}
	lock_release(&c->write_lock);

	return n;
}

/* returns :
 * 0  - in case of success
 * -1 - in case there was an internal error
 * -2 - in case our chunks buffer is full
 *		and we need to let the connection go
 */
int tcp_async_add_chunk(struct tcp_connection *con, char *buf,
		int len, int lock)
{
	struct tcp_async_chunk *c;

	c = shm_malloc(sizeof(struct tcp_async_chunk) + len);
	if (!c) {
		LM_ERR("No more SHM\n");
		return -1;
	}

	c->len = len;
	c->ticks = get_ticks();
	c->buf = (char *)(c+1);
	memcpy(c->buf,buf,len);

	if (lock)
		lock_get(&con->write_lock);

	if (con->async->allocated == con->async->pending) {
		LM_ERR("We have reached the limit of max async postponed chunks %d\n",
				con->async->pending);
		if (lock)
			lock_release(&con->write_lock);
		shm_free(c);
		return -2;
	}

	con->async->chunks[con->async->pending++] = c;
	if (con->async->pending == 1)
		con->async->oldest = c->ticks;

	if (lock)
		lock_release(&con->write_lock);

	return 0;
}


struct tcp_async_chunk *tcp_async_get_chunk(struct tcp_connection *con)
{
	if (con->async->pending == 0)
		return NULL;
	return con->async->chunks[0];
}

void tcp_async_update_write(struct tcp_connection *con, int len)
{
	int i = 0, c;
	struct tcp_async_chunk *chunk;

	while (len > 0) {
		chunk = con->async->chunks[i];
		if (len < chunk->len) {
			/* partial write */
			chunk->len -= len;
			memmove(chunk->buf, chunk->buf + len, chunk->len);
			return;
		} else {
			/* written the entire chunk */
			i++;
			len -= chunk->len;
		}
	}
	con->async->pending -= i;
	for (c = 0; c < i; c++)
		shm_free(con->async->chunks[c]);
	if (con->async->pending) {
		LM_DBG("We still have %d chunks pending on %p\n",
				con->async->pending, con);
		memmove(con->async->chunks, con->async->chunks + i,
				con->async->pending * sizeof(struct tcp_async_chunk *));
		con->async->oldest = con->async->chunks[0]->ticks;
	} else {
		LM_DBG("We have finished writing all our async chunks in %p\n", con);
		con->async->oldest = 0;
	}
}
