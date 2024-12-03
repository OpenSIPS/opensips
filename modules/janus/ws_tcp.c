/*
 * Janus Module
 *
 * Copyright (C) 2024 OpenSIPS Project
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
 *
 * History:
 * --------
 * 2024-12-03 initial release (vlad)
 */

#include "../../mem/shm_mem.h"
#include "../../ut.h"
#include "../../globals.h"
#include "../../tsend.h"
#include "ws_tcp.h"
#include <sys/uio.h>
#include <unistd.h>

#include "janus_common.h"

/**************  READ related functions ***************/

/*! \brief reads next available bytes
 * \return number of bytes read, 0 on EOF or -1 on error,
 * on EOF it also sets c->state to S_CONN_EOF
 * (to distinguish from reads that would block which could return 0)
 * sets also wb->error
 */
int janus_ws_raw_read(janus_connection *c,struct tcp_req *r)
{
	int bytes_free, bytes_read;
	int fd;

	fd=c->fd;
	bytes_free=TCP_BUF_SIZE- (int)(r->pos - r->buf);

	if (bytes_free==0){
		LM_ERR("buffer overrun, dropping\n");
		r->error=TCP_REQ_OVERRUN;
		return -1;
	}
again:
	bytes_read=read(fd, r->pos, bytes_free);

	if(bytes_read==-1){
		if (errno == EWOULDBLOCK || errno == EAGAIN){
			return 0; /* nothing has been read */
		} else if (errno == EINTR) {
			goto again;
		} else if (errno == ECONNRESET) {
			c->state=S_CONN_EOF;
			LM_DBG("EOF on %p, FD %d\n", c, fd);
			bytes_read = 0;
		} else {
			LM_ERR("error reading: %s\n",strerror(errno));
			r->error=TCP_READ_ERROR;
			return -1;
		}
	}else if (bytes_read==0){
		c->state=S_CONN_EOF;
		LM_DBG("EOF on %p, FD %d\n", c, fd);
	}

	LM_DBG("read %d bytes:\n%.*s\n", bytes_read, bytes_read, r->pos);
	r->pos+=bytes_read;
	return bytes_read;
}

int janus_ws_raw_writev(int fd,	const struct iovec *iov, int iovcnt, int tout)
{
	int n;

	/* optimize write for a single chunk */
	if (iovcnt == 1)
		n=tsend_stream(fd, iov[0].iov_base, iov[0].iov_len, tout);
	else
		n=tsend_stream_ev(fd, iov, iovcnt, tout);

	return n;
}
