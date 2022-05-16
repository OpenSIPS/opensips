/*
 * Copyright (C) 2022 - OpenSIPS Solutions
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
 *
 */

#include "../../socket_info.h"
#include "../../trace_api.h"
#include "../../net/api_proto.h"
#include "../../net/api_proto_net.h"
#include "../../net/net_tcp.h"
#include "../../net/net_tcp_report.h"
#include "../../net/trans_trace.h"
#include "../../net/tcp_common.h"
#include "msrp_tls.h"
#include "msrp_common.h"


int proto_msrp_init_listener(struct socket_info *si)
{
	/* we do not do anything particular to TCP plain here, so
	 * transparently use the generic listener init from net TCP layer */
	return tcp_init_listener(si);
}


void msrp_report(int type, unsigned long long conn_id, int conn_flags,
		void *extra)
{
	str s;

	if (type==TCP_REPORT_CLOSE) {

		if ( !TRACE_ON( conn_flags ) )
			return;

		/* grab reason text */
		if (extra) {
			s.s = (char*)extra;
			s.len = strlen (s.s);
		}

		trace_message_atonce( PROTO_MSRP, conn_id, NULL/*src*/, NULL/*dst*/,
			TRANS_TRACE_CLOSED, TRANS_TRACE_SUCCESS, extra?&s:NULL,
			msrp_t_dst );
	}

	return;
}


/**************  READ related functions ***************/

/*! \brief reads next available bytes
 * \return number of bytes read, 0 on EOF or -1 on error,
 * on EOF it also sets c->state to S_CONN_EOF
 * (to distinguish from reads that would block which could return 0)
 * sets also r->error
 */
int msrp_read_plain(struct tcp_connection *c, struct msrp_req *r)
{
	int bytes_free, bytes_read;
	int fd;

	fd=c->fd;
	bytes_free=TCP_BUF_SIZE- (int)(r->tcp.pos - r->tcp.buf);

	if (bytes_free==0){
		LM_ERR("buffer overrun, dropping\n");
		r->tcp.error=TCP_REQ_OVERRUN;
		return -1;
	}
again:
	bytes_read=read(fd, r->tcp.pos, bytes_free);

	if(bytes_read==-1){
		if (errno == EWOULDBLOCK || errno == EAGAIN){
			return 0; /* nothing has been read */
		} else if (errno == EINTR) {
			goto again;
		} else if (errno == ECONNRESET) {
			c->state=S_CONN_EOF;
			LM_DBG("CONN RESET on %p, FD %d\n", c, fd);
			bytes_read = 0;
		} else {
			LM_ERR("error reading: %s\n",strerror(errno));
			r->tcp.error=TCP_READ_ERROR;
			return -1;
		}
	}else if (bytes_read==0){
		c->state=S_CONN_EOF;
		LM_DBG("EOF on %p, FD %d\n", c, fd);
	}
#ifdef EXTRA_DEBUG
	LM_DBG("read %d bytes:\n%.*s\n", bytes_read, bytes_read, r->tcp.pos);
#endif
	r->tcp.pos+=bytes_read;
	return bytes_read;
}


