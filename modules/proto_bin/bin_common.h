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

static inline int bin_handle_req(struct tcp_req *req,
							struct tcp_connection *con, int _max_msg_chunks)
{
	long size;

	if (req->complete){
		/* update the timeout - we successfully read the request */
		tcp_conn_set_lifetime( con, tcp_con_lifetime);
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
			if (req != &_bin_common_current_req) {
				/* we have the buffer in the connection tied buff -
				 *	detach it , release the conn and free it afterwards */
				con->con_req = NULL;
			}
		} else {
			LM_DBG("We still have things on the pipe - "
				"keeping connection \n");
		}

		/* give the message to the registered functions */
		call_callbacks(req->buf, &con->rcv);


		if (!size && req != &_bin_common_current_req) {
			/* if we no longer need this tcp_req
			 * we can free it now */
			pkg_free(req);
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
		if (con->msg_attempts==0)
			/* if first iteration, set a short timeout for reading
			 * a whole SIP message */
			con->timeout = get_ticks() + tcp_max_msg_time;

		con->msg_attempts ++;
		if (con->msg_attempts == _max_msg_chunks) {
			LM_ERR("Made %u read attempts but message is not complete yet - "
				   "closing connection \n",con->msg_attempts);
			goto error;
		}

		if (req == &_bin_common_current_req) {
			/* let's duplicate this - most likely another conn will come in */

			LM_DBG("We didn't manage to read a full request\n");
			con->con_req = pkg_malloc(sizeof(struct tcp_req));
			if (con->con_req == NULL) {
				LM_ERR("No more mem for dynamic con request buffer\n");
				goto error;
			}

			if (req->pos != req->buf) {
				/* we have read some bytes */
				memcpy(con->con_req->buf,req->buf,req->pos-req->buf);
				con->con_req->pos = con->con_req->buf + (req->pos-req->buf);
			} else {
				con->con_req->pos = con->con_req->buf;
			}

			if (req->parsed != req->buf)
				con->con_req->parsed =con->con_req->buf+(req->parsed-req->buf);
			else
				con->con_req->parsed = con->con_req->buf;

			con->con_req->complete=req->complete;
			con->con_req->content_len=req->content_len;
			con->con_req->error = req->error;
		}
	}

	/* everything ok */
	return 0;
error:
	/* report error */
	return -1;
}
