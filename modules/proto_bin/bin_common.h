/*
 * Copyright (C) 2021 - OpenSIPS Foundation
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
 *
 */

static inline void bin_parse_headers(struct tcp_req *req){
	unsigned int  *px;
	if(req->content_len == 0 && req->pos - req->buf < HEADER_SIZE){
		req->parsed = req->pos;
		return;
	}

	if (!is_valid_bin_packet(req->buf)) {
		LM_ERR("Invalid packet marker, got %.4s\n", req->buf);
		req->error = TCP_REQ_BAD_LEN;
		return;
	}

	px = (unsigned int*)(req->buf + MARKER_SIZE);
	req->content_len = (*px);
	if(req->pos - req->buf == req->content_len){
		LM_DBG("received a COMPLETE message\n");
		req->complete = 1;
		req->parsed = req->buf + req->content_len;
	} else if(req->pos - req->buf > req->content_len){
		LM_DBG("received MORE then a message\n");
		req->complete = 1;
		req->parsed = req->buf + req->content_len;
	} else {
		LM_DBG("received only PART of a message\n");
		req->parsed = req->pos;
	}
}

static inline int bin_receive_msg(char *buf, int len, struct receive_info *rcv,
		void *data, int data_len)
{
	(void)len;
	(void)data;
	(void)data_len;

	call_callbacks(buf, rcv);
	return 0;
}

static inline int bin_handle_req(struct tcp_req *req,
								struct tcp_connection *con, int _max_msg_chunks)
{
	long size;
	struct receive_info local_rcv;

	if (req->complete){
		/* refresh connection lifetime after successful read progress */
		tcp_conn_reset_lifetime(con);
		con->timeout = con->lifetime;

		LM_DBG("completely received a message\n");
		/* rcv.bind_address should always be !=0 */
		/* just for debugging use sendipv4 as receiving socket  FIXME*/
		con->rcv.proto_reserved1=con->id; /* copy the id */

		/* prepare for next request */
		size=req->pos - req->parsed;

		if (!size) {
			/* did not read any more things -  we can release
			 * the connection */
			LM_DBG("Nothing more to read on TCP conn %p, currently in state %d \n",
				con,con->state);
		} else {
			LM_DBG("We still have things on the pipe - "
				"keeping connection \n");
		}

		local_rcv = con->rcv;
		if (tcp_dispatch_msg(req->buf,
				req->parsed - req->buf, &local_rcv,
				NULL, 0) < 0) {
			LM_ERR("failed to deliver BIN message\n");
			goto error;
		}


			con->msg_attempts = 0;

		if (size) {
			memmove(req->buf, req->parsed, size);

			init_tcp_req(req, size);

			/* if we still have some unparsed bytes, try to  parse them too*/
			return 1;
		}

	} else {
		/* request not complete - check the if the thresholds are exceeded */
		if (con->msg_attempts == 0)
			tcp_conn_set_msg_read_timeout(con);

		con->msg_attempts ++;
		if (con->msg_attempts == _max_msg_chunks) {
			LM_ERR("Made %u read attempts but message is not complete yet - "
				   "closing connection \n",con->msg_attempts);
			goto error;
		}
	}

	/* everything ok */
	return 0;
error:
	/* report error */
	return -1;
}

#define TRANS_TRACE_PROTO_ID "net"
