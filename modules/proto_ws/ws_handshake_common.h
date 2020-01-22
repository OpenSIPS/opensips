/*
 * Copyright (C) 2015 - OpenSIPS Foundation
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
 * History:
 * -------
 *  2015-02-xx  first version (razvanc)
 */

#ifndef _WS_HANDSHAKE_H_
#define _WS_HANDSHAKE_H_

#include "../../ip_addr.h"

#define HTTP_SEP			"\r\n"
#define HTTP_SEP_LEN		(sizeof(HTTP_SEP) - 1)
#define HTTP_END HTTP_SEP HTTP_SEP
#define HTTP_END_LEN		(sizeof(HTTP_END) - 1)
#define HTTP_GET_METHOD		"GET"
#define HTTP_GET_METHOD_LEN	(sizeof(HTTP_GET_METHOD) - 1)
#define HTTP_VER_TOKEN		"HTTP/"
#define HTTP_VER_TOKEN_LEN	(sizeof(HTTP_VER_TOKEN) - 1)
#define HTTP_VER_MAJ		1
#define HTTP_VER_MIN		1
#define HTTP_VERSION		HTTP_VER_TOKEN "1.1"
#define HTTP_VERSION_LEN	(sizeof(HTTP_VERSION) - 1)
#define HTTP_REPLY_CODE		"101"
#define HTTP_REPLY_CODE_LEN	(sizeof(HTTP_REPLY_CODE) - 1)
#define HTTP_REPLY_REASON1	"Switching"
#define HTTP_REPLY_REASON1_LEN	(sizeof(HTTP_REPLY_REASON1) - 1)
#define HTTP_REPLY_REASON2	"Protocols"
#define HTTP_REPLY_REASON2_LEN	(sizeof(HTTP_REPLY_REASON2) - 1)

#define WS_HOST_F		(1 << 0)
#define WS_UPGRADE_F	(1 << 1)
#define WS_CONN_F		(1 << 2)
#define WS_KEY_F		(1 << 3)
#define WS_ORIGIN_F		(1 << 4)
#define WS_VER_F		(1 << 5)
/* for SIP connections, RFC7118 requires sip protocol */
#define WS_PROTO_F		(1 << 6)
#define WS_ACCEPT_F		(1 << 7)

#define HDR_LEN(_s) (sizeof(_s) - 1)

#define WS_HDR "websocket"
#define WS_HDR_LEN (sizeof(WS_HDR) - 1)
#define WS_PROTO_SIP "sip"
#define WS_PROTO_SIP_LEN (sizeof(WS_PROTO_SIP) - 1)
#define WS_UPGRADE_HDR "Upgrade"
#define WS_UPGRADE_HDR_LEN (sizeof(WS_UPGRADE_HDR) - 1)

/* all flags for req */
#define WS_ALL_REQ_F (WS_HOST_F | \
					WS_UPGRADE_F | \
					WS_CONN_F | \
					WS_ORIGIN_F | \
					WS_KEY_F | \
					WS_VER_F | \
					WS_PROTO_F)

/* all flags for reply */
#define WS_ALL_RPL_F (WS_UPGRADE_F | \
					WS_CONN_F | \
					WS_ACCEPT_F | \
					WS_PROTO_F)

#define GET_LOWER(_p) \
	((*(_p)) | 0x20)
#define GET_LOWER_DWORD(_p) \
	((*(_p) + (*((_p)+1)<<8) + (*((_p)+2)<<16) + (*((_p)+3)<<24)) | 0x20202020)
#define GET_DWORD(_c0, _c1, _c2, _c3) \
	((_c0) + ((_c1)<<8) + ((_c2)<<16) + ((_c3)<<24))

#define WS_SHA1_KEY_LEN		20
#define WS_ACCEPT_KEY_LEN	28 /* 20-bytes string BASE64 encoded */

#define WS_GUID_KEY "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WS_GUID_KEY_LEN (sizeof(WS_GUID_KEY) - 1)

#define WS_HTTP_ACCEPT							\
	HTTP_VERSION " " HTTP_REPLY_CODE " Switching Protocols" HTTP_SEP	\
	"Upgrade: websocket" HTTP_SEP				\
	"Connection: Upgrade" HTTP_SEP				\
	"Sec-WebSocket-Protocol: sip" HTTP_SEP		\
	"Sec-WebSocket-Accept: "
#define WS_HTTP_ACCEPT_LEN (sizeof(WS_HTTP_ACCEPT) - 1)


#define WS_HTTP_BAD_REQ						\
	"HTTP/1.1 400 Bad Request" HTTP_SEP		\
	"Sec-WebSocket-Version: 13" HTTP_END

#define WS_HTTP_BAD_REQ_LEN (sizeof(WS_HTTP_BAD_REQ) - 1)


/* TODO: protocol should be dynamic */
#define HTTP_HANDSHAKE_END							\
	"Upgrade: websocket" HTTP_SEP					\
	"Connection: upgrade" HTTP_SEP					\
	"Sec-WebSocket-Version: 13" HTTP_SEP			\
	"Sec-WebSocket-Protocol: " WS_PROTO_SIP HTTP_END
#define HTTP_HANDSHAKE_END_LEN (sizeof(HTTP_HANDSHAKE_END) - 1)

#define MAX_HOST_LEN IP_ADDR_MAX_STR_SIZE /*IP*/ + 1 /*':'*/ + 5 /*65535*/

#include "../../sha1.h"

static int ws_read_http(struct tcp_connection *c, struct tcp_req *r);
static int ws_parse_req_handshake(struct tcp_connection *c, char *msg, int len);
static int ws_parse_rpl_handshake(struct tcp_connection *c, char *msg, int len);
static int ws_complete_handshake(struct tcp_connection *c);
static int ws_start_handshake(struct tcp_connection *c);
static int ws_bad_handshake(struct tcp_connection *c);
static int trace_ws( struct tcp_connection* conn, trans_trace_event event, str* req);
static int complete_ws_trace( struct tcp_connection* conn, trans_trace_status status, str* rpl, str* message);

#define WS_TRACE_MAX 1024
static char ws_trace_buf[WS_TRACE_MAX];

/* safety checks */
#ifndef _ws_common_module
#error "_ws_common_module not defined!"
#endif
#ifndef _ws_common_tcp_current_req
#error "_ws_common_tcp_current_req not defined!"
#endif
#ifndef _ws_common_max_msg_chunks
#error "_ws_common_max_msg_chunks not defined!"
#endif
#ifndef _ws_common_read
#error "_ws_common_read not defined!"
#endif
#ifndef _ws_common_writev
#error "_ws_common_writev not defined!"
#endif
#ifndef _ws_common_read_tout
#error "_ws_common_read_tout not defined!"
#endif
#ifndef _ws_common_write_tout
#error "_ws_common_write_tout not defined!"
#endif


#define WS_KEY_LEN 24
static char ws_key[WS_KEY_LEN];
static const char base64alphabet[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
#define BASE64ALPHABET_LEN (sizeof(base64alphabet)-1)


/* we're using a completely random key - no reason yet for something else */
static str ws_rand_key(void)
{
	static str key = { ws_key, WS_KEY_LEN };
	int i;

	/* randomly selected 16-byte base64 encoded value requires
	 * 22 characters and 2 paddings at the end */
	for (i = 0; i < WS_KEY_LEN - 2; i++)
		ws_key[i] = base64alphabet[rand() % BASE64ALPHABET_LEN];
	ws_key[i++] = '=';
	ws_key[i++] = '=';

	return key;
}

static inline int ws_client_handshake(struct tcp_connection *con)
{

	int bytes;
	long size = 0;
	int msg_len;
	char *msg_buf;
	struct tcp_req *req;
	int to;
	int elapsed;
	struct timeval begin;
	unsigned int err_len, poll_err = 0, err;
	int n;
	str trace_str;
#if defined(HAVE_SELECT) && defined(BLOCKING_USE_SELECT)
	fd_set sel_set;
	fd_set orig_set;
	struct timeval timeout;
#else
	struct pollfd pf;
#endif

	WS_STATE(con) = WS_CON_HANDSHAKE;
	WS_KEY(con) = ws_rand_key();
	if (ws_start_handshake(con) < 0) {
		LM_ERR("cannot start handshake\n");
		return -1;
	}

	/* there should be no req in the con */
	if (con->con_req) {
		LM_BUG("there should not be any con req!\n");
		goto error;
	}
	init_tcp_req(&_ws_common_tcp_current_req, 0);
	req=&_ws_common_tcp_current_req;

	to = _ws_common_read_tout*1000;
	if (gettimeofday(&(begin), NULL)) {
		LM_ERR("Failed to get TCP connect start time\n");
		goto error;
	}
#if defined(HAVE_SELECT) && defined(BLOCKING_USE_SELECT)
		FD_ZERO(&orig_set);
		FD_SET(con->fd, &orig_set);
#else
		pf.fd=con->fd;
		pf.events=POLLIN;
#endif

	do {
		elapsed = get_time_diff(&begin);
		if (elapsed<to) {
			to-=elapsed;
		} else {
			LM_ERR("Timeout waiting for handshake read\n");
			goto error;
		}
#if defined(HAVE_SELECT) && defined(BLOCKING_USE_SELECT)
		sel_set=orig_set;
		timeout.tv_sec = to/1000000;
		timeout.tv_usec = to%1000000;
		n=select(con->fd+1, 0, &sel_set, 0, &timeout);
#else
		n=poll(&pf, 1, to/1000);
#endif
		if (n<0){
			if (errno==EINTR) continue;
			goto error;
		}else if (n==0) /* timeout */ continue;
#if defined(HAVE_SELECT) && defined(BLOCKING_USE_SELECT)
		if (FD_ISSET(con->fd, &sel_set))
#else
		if (pf.revents&(POLLERR|POLLHUP|POLLNVAL)) {
			LM_ERR("poll error: flags %d - %d %d %d %d \n", pf.revents,
				   POLLOUT,POLLERR,POLLHUP,POLLNVAL);
			poll_err=1;
		}
#endif
		{
			err_len=sizeof(err);
			if (getsockopt(con->fd, SOL_SOCKET, SO_ERROR, &err, &err_len) < 0 ||
					err != 0 || poll_err != 0) {
				if (err != EINPROGRESS && err != EALREADY)
					goto error;
				continue;
			}
		}

		if (req->error == TCP_REQ_OK) {
			bytes = ws_read_http(con, req);
			if (bytes == -1) {
				LM_ERR("failed to read %d:%s\n", errno, strerror(errno));
				goto error;
			}

			if ((con->state==S_CONN_EOF) && (req->complete==0)) {
				LM_DBG("EOF received\n");
				goto done;
			}

		}
		if (req->error!=TCP_REQ_OK){
			LM_ERR("bad request, state=%d, error=%d "
					  "buf:\n%.*s\nparsed:\n%.*s\n", req->state, req->error,
					  (int)(req->pos-req->buf), req->buf,
					  (int)(req->parsed-req->start), req->start);
			LM_DBG("- received from: port %d\n", con->rcv.src_port);
			print_ip("- received from: ip ",&con->rcv.src_ip, "\n");
			goto error;
		}

		con->msg_attempts++;
		if (con->msg_attempts == _ws_common_max_msg_chunks) {
			LM_ERR("Made %u read attempts but message is not complete yet - "
				   "closing connection \n",con->msg_attempts);
			goto error;
		}

		elapsed = get_time_diff(&begin);
		if (elapsed >= to) {
			LM_ERR("Timeout waiting for handshare response\n");
			goto error;
		} else {
			to -= elapsed;
		}
	} while(!req->complete);

#ifdef EXTRA_DEBUG
	LM_DBG("end of header part\n");
	LM_DBG("- received from: port %d\n", con->rcv.src_port);
	print_ip("- received from: ip ", &con->rcv.src_ip, "\n");
	LM_DBG("headers:\n%.*s.\n",(int)(req->body-req->start), req->start);
#endif
	if (req->has_content_len) {
		LM_DBG("content-length= %d\n", req->content_len);
#ifdef EXTRA_DEBUG
		LM_DBG("body:\n%.*s\n", req->content_len,req->body);
#endif
	}

	/* update the timeout - we successfully read the request */
	tcp_conn_set_lifetime(con, tcp_con_lifetime);
	con->timeout=con->lifetime;

	con->rcv.proto_reserved1=con->id; /* copy the id */
	/* we overwrite whatever is there, since we are not interested
	 * in any other data after the handshake */
	*req->parsed=0;

	/* prepare for next request */
	size=req->pos-req->parsed;

	msg_buf = req->start;
	msg_len = req->parsed-req->start;

	if (!size) {
		/* did not read any more things -  we can release
		 * the connection */
		LM_DBG("We're releasing the connection in state %d \n",
				con->state);
	} else {
		/* TODO - should we handle whatever data is sent by the client
		 * even though the handshake is not completed */
		/* TODO - we need to find a way to move data from tcp_req to ws_req */
		LM_WARN("extra data on socket before handshake is completed!\n");
		WS_STATE(con) = WS_CON_BAD_REQ;
		goto error;
	}

	/* TODO: parse and verify response */
	if (ws_parse_rpl_handshake(con, msg_buf, msg_len) < 0) {
		LM_ERR("invalid WebSocket reply <%.*s>\n", msg_len, msg_buf);
		goto error;
	}

	if ( ((struct ws_data *) con->proto_data)->dest ) {
		trace_str.len = msg_len;
		trace_str.s = msg_buf;

		if ( complete_ws_trace( con, TRANS_TRACE_SUCCESS,
							&trace_str, &CONNECT_OK) < 0 ) {
			LM_ERR("failed to complete web socket trace!\n");
		}
	}

	init_tcp_req(req, 0);
	con->msg_attempts = 0;

	/* handshake now completed, destroy the handshake data */
	WS_STATE(con) = WS_CON_HANDSHAKE_DONE;

	LM_DBG("ws_read end\n");
done:
	/* connection will be released */
	return size;
error:
	/* ws_start_handshake must be completed so trace_ws was called
	 * in order to get here so we're safe */
	if ( ((struct ws_data *) con->proto_data)->dest ) {
		if ( complete_ws_trace( con, TRANS_TRACE_FAILURE,
							0, &CONNECT_FAIL) < 0 ) {
			LM_ERR("failed to trace ws connect failure!\n");
		}
	}

	return -1;
}

static int ws_server_handshake(struct tcp_connection *con)
{
	int bytes, total_bytes = 0;
	long size = 0;
	int msg_len;
	char *msg_buf;
	struct tcp_req *req;
	str trace_str;

	if (con->con_req) {
		if (WS_TYPE(con) != WS_SERVER) {
			LM_BUG("cannot create handshake as %d\n", WS_TYPE(con));
			return -1;
		}
		req=con->con_req;
		LM_DBG("Using the per connection buff \n");
	} else {
		if (WS_TYPE(con) != WS_NONE) {
			LM_BUG("not a new connection here %d", WS_TYPE(con));
			return -1;
		}
		WS_TYPE(con) = WS_SERVER;
		WS_STATE(con) = WS_CON_HANDSHAKE;
		LM_DBG("Using the global ( per process ) buff \n");
		init_tcp_req(&_ws_common_tcp_current_req, 0);
		req=&_ws_common_tcp_current_req;
		/* first time here, mark the state as being SERVER */
	}

	if (req->error == TCP_REQ_OK) {
		bytes = ws_read_http(con, req);
		if (bytes == -1) {
			LM_ERR("failed to read %d:%s\n", errno, strerror(errno));
			goto error;
		}

		total_bytes+=bytes;
		/* eof check:
		 * is EOF if eof on fd and r.  not complete yet,
		 * if r. is complete we might have a second unparsed
		 * request after it, so postpone release_with_eof
		 */
		if ((con->state==S_CONN_EOF) && (req->complete==0)) {
			LM_DBG("EOF received\n");
			goto done;
		}

	}
	if (req->error!=TCP_REQ_OK){
		LM_ERR("bad request, state=%d, error=%d "
				  "buf:\n%.*s\nparsed:\n%.*s\n", req->state, req->error,
				  (int)(req->pos-req->buf), req->buf,
				  (int)(req->parsed-req->start), req->start);
		LM_DBG("- received from: port %d\n", con->rcv.src_port);
		print_ip("- received from: ip ",&con->rcv.src_ip, "\n");
		goto error;
	}
	if (req->complete){
#ifdef EXTRA_DEBUG
		LM_DBG("end of header part\n");
		LM_DBG("- received from: port %d\n", con->rcv.src_port);
		print_ip("- received from: ip ", &con->rcv.src_ip, "\n");
		LM_DBG("headers:\n%.*s.\n",(int)(req->body-req->start), req->start);
#endif
		if (req->has_content_len) {
			LM_DBG("content-length= %d\n", req->content_len);
#ifdef EXTRA_DEBUG
			LM_DBG("body:\n%.*s\n", req->content_len,req->body);
#endif
		}

		/* update the timeout - we successfully read the request */
		tcp_conn_set_lifetime( con, tcp_con_lifetime);
		con->timeout=con->lifetime;

		con->rcv.proto_reserved1=con->id; /* copy the id */
		/* we overwrite whatever is there, since we are not interested
		 * in any other data after the handshake */
		*req->parsed=0;

		/* prepare for next request */
		size=req->pos-req->parsed;

		msg_buf = req->start;
		msg_len = req->parsed-req->start;

		if (!size) {
			/* did not read any more things -  we can release
			 * the connection */
			LM_DBG("We're releasing the connection in state %d \n",
					con->state);
			if (req != &_ws_common_tcp_current_req) {
				/* we have the buffer in the connection tied buff -
				 *	detach it , release the conn and free it afterwards */
				con->con_req = NULL;
			}
			/* TODO - we could indicate to the TCP net layer to release
			 * the connection -> other worker may read the next available
			 * message on the pipe */
		} else {
			/* TODO - should we handle whatever data is sent by the client
			 * even though the handshake is not completed */
			LM_WARN("extra data on socket before handshake is completed!\n");
			WS_STATE(con) = WS_CON_BAD_REQ;
			goto error;
		}

		if (ws_parse_req_handshake(con, msg_buf, msg_len) < 0) {
			LM_DBG("cannot parse handshake\n");
			goto error;
		}

		if ( ((struct ws_data *) con->proto_data)->dest ) {
			trace_str.len = msg_len;
			trace_str.s = msg_buf;

			if ( trace_ws( con, TRANS_TRACE_ACCEPTED, &trace_str) < 0 ) {
				LM_ERR("failed to trace WS request!\n");
			}
		}


		if (ws_complete_handshake(con) < 0) {
			LM_DBG("cannot complete handshake\n");
			goto error;
		}

		con->msg_attempts = 0;
		if (req != &_ws_common_tcp_current_req)
			pkg_free(req);

		/* handshake now completed, destroy the handshake data */
		WS_STATE(con) = WS_CON_HANDSHAKE_DONE;

		/* finished handshake */
		goto done;

	} else {
		/* request not complete - check the if the thresholds are exceeded */

		con->msg_attempts++;
		if (con->msg_attempts == _ws_common_max_msg_chunks) {
			LM_ERR("Made %u read attempts but message is not complete yet - "
				   "closing connection \n",con->msg_attempts);
			goto error;
		}
	}

	if (!req->complete && (req == &_ws_common_tcp_current_req)) {
		/* let's duplicate this - most likely another conn will come in */

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

		if (req->start != req->buf)
			con->con_req->start = con->con_req->buf +(req->start-req->buf);
		else
			con->con_req->start = con->con_req->buf;

		if (req->parsed != req->buf)
			con->con_req->parsed =con->con_req->buf+(req->parsed-req->buf);
		else
			con->con_req->parsed = con->con_req->buf;

		if (req->body != 0) {
			con->con_req->body = con->con_req->buf + (req->body-req->buf);
		} else
			con->con_req->body = 0;

		con->con_req->complete=req->complete;
		con->con_req->has_content_len=req->has_content_len;
		con->con_req->content_len=req->content_len;
		con->con_req->bytes_to_go=req->bytes_to_go;
		con->con_req->error = req->error;
		con->con_req->state = req->state;
		/* req will be reset on the next usage */
	}

	LM_DBG("ws_read end\n");
done:
	/* connection will be released */
	return size;
error:
	/* connection will be released as ERROR */
	if (WS_STATE(con) == WS_CON_BAD_REQ)
		ws_bad_handshake(con);
	if (req != &_ws_common_tcp_current_req) {
		pkg_free(req);
		con->con_req = NULL;
	}
	return -1;
}

static inline int ws_parse_req_http_fl(struct tcp_connection *c,
		char **msg_buf, int *msg_len, unsigned *ver_maj, unsigned *ver_min)
{
	char *p, *sp, *spe, *end, *cr;
	int len;
	str tmp;

	/* go to the first CRLF. According to RFC 2616:
	 * No CR or LF is allowed except in the final CRLF sequence.*/
	cr = q_memchr(*msg_buf, '\r', *msg_len);
	if (!cr) {
		LM_ERR("invalid first line: cannot find CR\n");
		goto error;
	}
	if (cr == *msg_buf + *msg_len || *(cr + 1) != '\n') {
		LM_ERR("invalid first line: CR is not followed by LF\n");
		goto error;
	}
	/* update the message and len */
	p = *msg_buf;
	end = cr;
	len = end - p;

	if (len < HTTP_GET_METHOD_LEN) {
		LM_ERR("invalid first line: method too small <%.*s>\n", len, p);
		goto error;
	}

	/* get the first space */
	sp = q_memchr(p, ' ', len);
	if (!sp) {
		LM_ERR("invalid first line: cannot find method end\n");
		goto error;
	}
	if (sp - p != HTTP_GET_METHOD_LEN ||
			memcmp(p, HTTP_GET_METHOD, HTTP_GET_METHOD_LEN) != 0) {
		LM_ERR("invalid first line: method <%.*s>\n", len, p);
		goto error;
	}
	*msg_buf = cr + 2;
	*msg_len -= len + 2;
	/* XXX: skip spaces - the RFC says only spaces are allowed, but should we
	 * also allow tabs?*/
	for (; sp < end && *sp == ' '; sp++);
	if (sp == end) {
		LM_ERR("invalid first line: cannot find Request-URI\n");
		goto error;
	}
	/* request URI */
	for (spe = end - 1; spe > sp && *spe != ' '; spe--);
	if (spe == sp) {
		LM_ERR("invalid request URI: <%.*s>\n", (int)(end - sp), sp);
		goto error;
	}
	spe++;

	/* reverse search for the version */
	if (end - spe < (5/* HTTP/ */ + 1/* DIGIT */ + 1/* . */ + 1 /* DIGIT */))
		goto version_error;

	if (memcmp(spe, "HTTP/", 5) != 0)
		goto version_error;

	tmp.s = spe + 5; /* start of the major */
	sp = q_memchr(tmp.s, '.', end - tmp.s);
	if (!sp || sp == tmp.s) {
		LM_ERR("cannot find DOT\n");
		goto version_error;
	}
	tmp.len = sp - tmp.s;
	if (str2int(&tmp, ver_maj) < 0) {
		LM_ERR("invalid major\n");
		goto version_error;
	}
	tmp.s = sp + 1;
	tmp.len = end - tmp.s;
	if (tmp.s >= end || str2int(&tmp, ver_min) < 0) {
		LM_ERR("invlid minor\n");
		goto version_error;
	}

	return 0;
version_error:
	LM_ERR("invalid version: <%.*s>\n", (int)(end - spe), spe);
error:
	return -1;
}


static inline int ws_parse_rpl_http_fl(struct tcp_connection *c,
		char **msg_buf, int *msg_len, unsigned *ver_maj, unsigned *ver_min)
{
	char *p, *sp, *end, *cr;
	int len;
	str tmp;

	/* go to the first CRLF. According to RFC 2616:
	 * No CR or LF is allowed except in the final CRLF sequence.*/
	cr = q_memchr(*msg_buf, '\r', *msg_len);
	if (!cr) {
		LM_ERR("invalid first line: cannot find CR\n");
		goto error;
	}
	if (cr == *msg_buf + *msg_len || *(cr + 1) != '\n') {
		LM_ERR("invalid first line: CR is not followed by LF\n");
		goto error;
	}
	/* update the message and len */
	p = *msg_buf;
	end = cr;
	len = end - p;

	*msg_buf = cr + 2;
	*msg_len -= len + 2;

	if (len < HTTP_VERSION_LEN) {
		LM_ERR("invalid first line: version too small <%.*s>\n", len, p);
		goto error;
	}
	if (memcmp(p, HTTP_VER_TOKEN, HTTP_VER_TOKEN_LEN) != 0) {
		LM_ERR("invalid first line: invalid protocol <%.*s>\n", len, p);
		goto error;
	}
	p += HTTP_VER_TOKEN_LEN;
	tmp.s = p;
	sp = q_memchr(tmp.s, '.', end - tmp.s);
	if (!sp || sp == tmp.s) {
		LM_ERR("cannot find version DOT\n");
		goto error;
	}
	tmp.len = sp - tmp.s;
	if (str2int(&tmp, ver_maj) < 0) {
		LM_ERR("invalid major <%.*s>\n", tmp.len, tmp.s);
		goto error;
	}
	p = sp + 1;
	tmp.s = p;
	sp = q_memchr(tmp.s, ' ', end - tmp.s);
	if (!sp || sp == tmp.s) {
		LM_ERR("cannot find version separator\n");
		goto error;
	}
	tmp.len = sp - tmp.s;
	if (str2int(&tmp, ver_min) < 0) {
		LM_ERR("invalid minor <%.*s>\n", tmp.len, tmp.s);
		goto error;
	}

	for (; sp < end && *sp == ' '; sp++);
	if (sp == end || (end - sp) < HTTP_REPLY_CODE_LEN) {
		LM_ERR("invalid first line: cannot find reply code\n");
		goto error;
	}
	if (memcmp(sp, HTTP_REPLY_CODE, HTTP_REPLY_CODE_LEN) != 0) {
		LM_ERR("invalid first line: reply code <%.*s>\n", (int)(end - sp), sp);
		goto error;
	}
	sp += HTTP_REPLY_CODE_LEN;
	for (; sp < end && *sp == ' '; sp++);
	if (sp == end || (end - sp) < HTTP_REPLY_REASON1_LEN) {
		LM_ERR("invalid first line: cannot find reason1\n");
		goto error;
	}
	if (strncasecmp(sp, HTTP_REPLY_REASON1, HTTP_REPLY_REASON1_LEN) != 0) {
		LM_ERR("invalid first line: reason <%.*s>\n", (int)(end - sp), sp);
		goto error;
	}
	p = sp + HTTP_REPLY_REASON1_LEN;
	for (; p < end && *p == ' '; p++);
	if (p == end || (end - p) < HTTP_REPLY_REASON2_LEN) {
		LM_ERR("invalid first line: cannot find reason2\n");
		goto error;
	}
	if (strncasecmp(p, HTTP_REPLY_REASON2, HTTP_REPLY_REASON2_LEN) != 0) {
		LM_ERR("invalid first line: reason <%.*s>\n", (int)(end - sp), sp);
		goto error;
	}
	p += HTTP_REPLY_REASON2_LEN;
	for (; p < end; p++)
		if (*p != ' ') {
			LM_ERR("trailing characters: <%.*s>\n", (int)(end - p), p);
			goto error;
		}

	return 0;
error:
	return -1;
}


static inline int ws_has_param(const char *p, int l, str ps)
{
	char *pe;
	str tmp;

	do {
		/* search next comma */
		pe = q_memchr(ps.s, ',', ps.len);
		if (!pe) {
			/* last parameter */
			str_trim_spaces_lr(ps);
			return (ps.len == l && !strncasecmp(p, ps.s, ps.len));
		}
		tmp.s = ps.s;
		tmp.len = pe - ps.s;
		str_trim_spaces_lr(tmp);
		if (tmp.len == l && !strncasecmp(p, tmp.s, tmp.len))
			return 1;
		ps.len -= pe - ps.s + 1;
		ps.s = pe + 1;
	} while (ps.len > 0);

	return 0;
}


static int ws_parse_req_handshake(struct tcp_connection *c, char *msg, int len)
{
	struct sip_msg tmp_msg;
	struct hdr_field *hf;
	unsigned version;
	unsigned char flags = 0;
	unsigned ver_min, ver_maj;

	if (ws_parse_req_http_fl(c, &msg, &len, &ver_maj, &ver_min) != 0) {
		LM_ERR("cannot parse the first line of the message\n%.*s\n", len, msg);
		goto error;
	}

	/* check the HTTP version */
	if (ver_maj < HTTP_VER_MAJ ||
			(ver_maj == HTTP_VER_MAJ && ver_min < HTTP_VER_MIN)) {
		LM_ERR("Invalid HTTP version: %u.%u\n", ver_maj, ver_min);
		goto error;
	}

	/* Parse the Headers */
	memset(&tmp_msg, 0, sizeof(struct sip_msg));
	tmp_msg.len = len;
	tmp_msg.buf = tmp_msg.unparsed = msg;
	if (parse_headers(&tmp_msg, HDR_EOH_F, 0) < 0) {
		LM_ERR("cannot parse headers\n%.*s\n", len, msg);
		goto error;
	}
	/* verify headers according to RFC6455 */
	for (hf = tmp_msg.headers; hf; hf = hf->next) {
		if (hf->type != HDR_OTHER_T)
			continue;
		/*
		 * since all mandatory headers have name length larger
		 * than 4, we can use integer comparison from start
		 */
		if (hf->name.len < 4)
			continue;

		switch (GET_LOWER_DWORD(hf->name.s)) {
		case GET_DWORD('h', 'o', 's', 't'): /* Host */
			if (hf->name.len == HDR_LEN("Host"))
				flags |= WS_HOST_F;
			break;
		case GET_DWORD('u', 'p', 'g', 'r'): /* Upgrade */
			if (hf->name.len != HDR_LEN("Upgrade") ||
					GET_LOWER(hf->name.s + 4) != 'a' ||
					GET_LOWER(hf->name.s + 5) != 'd' ||
					GET_LOWER(hf->name.s + 6) != 'e')
				break;

			if (!ws_has_param(WS_HDR, WS_HDR_LEN, hf->body)) {
				LM_ERR("Invalid Upgrade header <%.*s>\n",
						hf->body.len, hf->body.s);
				goto ws_error;
			}
			flags |= WS_UPGRADE_F;
			break;
		case GET_DWORD('c', 'o', 'n', 'n'): /* Connection */
			if (hf->name.len != HDR_LEN("Connection") ||
					GET_LOWER(hf->name.s + 4) != 'e' ||
					GET_LOWER(hf->name.s + 5) != 'c' ||
					GET_LOWER(hf->name.s + 6) != 't' ||
					GET_LOWER(hf->name.s + 7) != 'i' ||
					GET_LOWER(hf->name.s + 8) != 'o' ||
					GET_LOWER(hf->name.s + 9) != 'n')
				break;

			if (!ws_has_param(WS_UPGRADE_HDR, WS_UPGRADE_HDR_LEN, hf->body)) {
				LM_ERR("Invalid Connection header <%.*s>\n",
						hf->body.len, hf->body.s);
				goto ws_error;
			}

			flags |= WS_CONN_F;
			break;
		case GET_DWORD('o', 'r', 'i', 'g'): /* Origin */
			/* TODO: always check for origin? */
			if (hf->name.len !=  HDR_LEN("Origin") ||
					GET_LOWER(hf->name.s + 4) != 'i' ||
					GET_LOWER(hf->name.s + 5) != 'n')
				break;

			flags |= WS_ORIGIN_F;
			break;
		case GET_DWORD('s', 'e', 'c', '-'): /* Sec-* */
			if (hf->name.len < HDR_LEN("Sec-Websocket-*") ||
					GET_LOWER(hf->name.s + 4) != 'w' ||
					GET_LOWER(hf->name.s + 5) != 'e' ||
					GET_LOWER(hf->name.s + 6) != 'b' ||
					GET_LOWER(hf->name.s + 7) != 's' ||
					GET_LOWER(hf->name.s + 8) != 'o' ||
					GET_LOWER(hf->name.s + 9) != 'c' ||
					GET_LOWER(hf->name.s + 10) != 'k' ||
					GET_LOWER(hf->name.s + 11) != 'e' ||
					GET_LOWER(hf->name.s + 12) != 't' ||
					GET_LOWER(hf->name.s + 13) != '-')
				break;

			if (hf->name.len == HDR_LEN("Sec-WebSocket-Key") &&
					GET_LOWER(hf->name.s + 14) == 'k' &&
					GET_LOWER(hf->name.s + 15) == 'e' &&
					GET_LOWER(hf->name.s + 16) == 'y') {

				str_trim_spaces_lr(hf->body);

				/* RFC-6455 4.1: Opening Handshake: Client Requirements
				 * 7.  The request MUST include a header field with the name
				 *     |Sec-WebSocket-Key|.  The value of this header field MUST be a
				 *     nonce consisting of a randomly selected 16-byte value that has
				 *     been base64-encoded (see Section 4 of [RFC4648]).  The nonce
				 *     MUST be selected randomly for each connection. */
				if (hf->body.len == WS_KEY_LEN) {
					/* the key is already in the buffer, so we can just copy it */
					WS_KEY(c) = hf->body;
					flags |= WS_KEY_F;
				}
			} else if (hf->name.len == HDR_LEN("Sec-WebSocket-Version") &&
					GET_LOWER(hf->name.s + 14) == 'v' &&
					GET_LOWER(hf->name.s + 15) == 'e' &&
					GET_LOWER(hf->name.s + 16) == 'r' &&
					GET_LOWER(hf->name.s + 17) == 's' &&
					GET_LOWER(hf->name.s + 18) == 'i' &&
					GET_LOWER(hf->name.s + 19) == 'o' &&
					GET_LOWER(hf->name.s + 20) == 'n') {

				str_trim_spaces_lr(hf->body);
				if (str2int(&hf->body, &version) < 0 || \
						version != WS_SUPPORTED_VERSION) {
					LM_ERR("Invalid or unsported version <%.*s>\n", \
							hf->body.len, hf->body.s);
					goto ws_error;
				}
				flags |= WS_VER_F;
			} else if (hf->name.len == HDR_LEN("Sec-WebSocket-Protocol") &&
					GET_LOWER(hf->name.s + 14) == 'p' &&
					GET_LOWER(hf->name.s + 15) == 'r' &&
					GET_LOWER(hf->name.s + 16) == 'o' &&
					GET_LOWER(hf->name.s + 17) == 't' &&
					GET_LOWER(hf->name.s + 18) == 'o' &&
					GET_LOWER(hf->name.s + 19) == 'c' &&
					GET_LOWER(hf->name.s + 20) == 'o' &&
					GET_LOWER(hf->name.s + 21) == 'l') {

				if (!ws_has_param(WS_PROTO_SIP, WS_PROTO_SIP_LEN, hf->body)) {
					LM_ERR("Invalid Protocol <%.*s>\n",
							hf->body.len, hf->body.s);
					goto ws_error;
				}
				flags |= WS_PROTO_F;
			}
			break;
		}

	}

	if (flags != (unsigned char)WS_ALL_REQ_F) {
		/* negate so we can easily compare them */
		flags = ~flags;
		if (flags & WS_HOST_F)
			LM_ERR("Host header not present!\n");
		if (flags & WS_UPGRADE_F)
			LM_ERR("Upgrade header not present!\n");
		if (flags & WS_CONN_F)
			LM_ERR("Connection header not present!\n");
		if (flags & WS_ORIGIN_F)
			LM_ERR("Origin header not present!\n");
		if (flags & WS_KEY_F)
			LM_ERR("Sec-WebSocket-Key header not present or does not "
					"have the desired length (%d)!\n", WS_KEY_LEN);
		if (flags & WS_VER_F)
			LM_ERR("Sec-WebSocket-Version header not present!\n");
		if (flags & WS_PROTO_F)
			LM_ERR("Sec-WebSocket-Protocol header not present!\n");
		goto ws_error;
	}

	/* parsing done, free headers */
	free_hdr_field_lst(tmp_msg.headers);

	return 0;
ws_error:
	free_hdr_field_lst(tmp_msg.headers);
error:
	WS_STATE(c) = WS_CON_BAD_REQ;
	return -1;
}

/*
 * The Polar library needs this to be 64 bytes, to avoid overflow
 * when computing the SHA1 hash
 */
unsigned char ws_key_buf[64] = "xxxxxxxxxxxxxxxxxxxxxxxx" /* the key len: 24 */
		WS_GUID_KEY /* the GUID */;
unsigned char ws_sha1_buf[WS_SHA1_KEY_LEN];
unsigned char ws_accept_buf[WS_ACCEPT_KEY_LEN];

static void ws_compute_key(str *key)
{
	memcpy(ws_key_buf, key->s, key->len);
	sha1(ws_key_buf, key->len + WS_GUID_KEY_LEN, ws_sha1_buf);
	base64encode(ws_accept_buf, ws_sha1_buf, WS_SHA1_KEY_LEN);
}

static int ws_is_valid_key(str *key, str *accept)
{
	ws_compute_key(key);
	return strncasecmp((char *)ws_accept_buf, accept->s, accept->len) == 0;
}

static int ws_complete_handshake(struct tcp_connection *c)
{
	int n;
	struct timeval get;
	static struct iovec iov[] = {
		{ (void*)WS_HTTP_ACCEPT, WS_HTTP_ACCEPT_LEN }, /* all mandatory headers */
		{ (void *)ws_accept_buf, WS_ACCEPT_KEY_LEN }, /* the cookie */
		{ (void *)HTTP_END, HTTP_END_LEN }/* message end */
	};

	str trace_str = { ws_trace_buf, 0 };
	int iov_len = sizeof(iov) / sizeof(struct iovec), i;

	reset_tcp_vars(tcpthreshold);
	start_expire_timer(get, tcpthreshold);

	/* compute the ws_key in ws_accept_buf */
	ws_compute_key(&WS_KEY(c));

	n = _ws_common_writev(c, c->fd, iov, 3, _ws_common_write_tout);
	stop_expire_timer(get, tcpthreshold,
			_ws_common_module " handshake", "", 0, 1);

	if ( ((struct ws_data *) c->proto_data)->dest ) {
		for ( i=0; i < iov_len; i++ ) {
			/* avoid overflow */
			if ( trace_str.len + iov[i].iov_len > WS_TRACE_MAX )
				break;

			memcpy( trace_str.s + trace_str.len,
					iov[i].iov_base, iov[i].iov_len );
			trace_str.len += iov[i].iov_len;
		}

		if ( complete_ws_trace( c, TRANS_TRACE_SUCCESS,
									&trace_str, &ACCEPT_OK ) < 0 ) {
			LM_ERR("failed to complete webSocket handshake!\n");
		}
	}

	return n;
}

static int ws_bad_handshake(struct tcp_connection *c)
{
	int n;
	struct timeval get;
	static struct iovec iov[] = {
		{ (void*)WS_HTTP_BAD_REQ, WS_HTTP_BAD_REQ_LEN },
	};

	str trace_str = { WS_HTTP_BAD_REQ, WS_HTTP_BAD_REQ_LEN };

	reset_tcp_vars(tcpthreshold);
	start_expire_timer(get, tcpthreshold);
	n = _ws_common_writev(c, c->fd, iov, 1, _ws_common_write_tout);
	stop_expire_timer(get, tcpthreshold,
			_ws_common_module " handshake", "", 0, 1);

	if ( ((struct ws_data *) c->proto_data)->dest ) {
		if ( complete_ws_trace( c, TRANS_TRACE_FAILURE,
							&trace_str, &ACCEPT_FAIL) < 0 ) {
			LM_ERR("failed to complete web socket trace!\n");
		}
	}

	return n;
}

static int ws_parse_rpl_handshake(struct tcp_connection *c, char *msg, int len)
{
	struct sip_msg tmp_msg;
	struct hdr_field *hf;
	unsigned char flags = 0;
	unsigned ver_min, ver_maj;

	if (ws_parse_rpl_http_fl(c, &msg, &len, &ver_maj, &ver_min) != 0) {
		LM_ERR("cannot parse the first line of the message\n%.*s\n", len, msg);
		goto error;
	}

	/* check the HTTP version */
	if (ver_maj < HTTP_VER_MAJ ||
			(ver_maj == HTTP_VER_MAJ && ver_min < HTTP_VER_MIN)) {
		LM_ERR("Invalid HTTP version: %u.%u\n", ver_maj, ver_min);
		goto error;
	}

	/* Parse the Headers */
	memset(&tmp_msg, 0, sizeof(struct sip_msg));
	tmp_msg.len = len;
	tmp_msg.buf = tmp_msg.unparsed = msg;
	if (parse_headers(&tmp_msg, HDR_EOH_F, 0) < 0) {
		LM_ERR("cannot parse headers\n%.*s\n", len, msg);
		goto error;
	}
	/* verify headers according to RFC6455 */
	for (hf = tmp_msg.headers; hf; hf = hf->next) {
		if (hf->type != HDR_OTHER_T)
			continue;
		/*
		 * since all mandatory headers have name length larger
		 * than 4, we can use integer comparison from start
		 */
		if (hf->name.len < 7)
			continue;

		switch (GET_LOWER_DWORD(hf->name.s)) {
		case GET_DWORD('u', 'p', 'g', 'r'): /* Upgrade */
			if (hf->name.len != HDR_LEN("Upgrade") ||
					GET_LOWER(hf->name.s + 4) != 'a' ||
					GET_LOWER(hf->name.s + 5) != 'd' ||
					GET_LOWER(hf->name.s + 6) != 'e')
				break;

			if (!ws_has_param(WS_HDR, WS_HDR_LEN, hf->body)) {
				LM_ERR("Invalid Upgrade header <%.*s>\n",
						hf->body.len, hf->body.s);
				goto ws_error;
			}
			flags |= WS_UPGRADE_F;
			break;
		case GET_DWORD('c', 'o', 'n', 'n'): /* Connection */
			if (hf->name.len != HDR_LEN("Connection") ||
					GET_LOWER(hf->name.s + 4) != 'e' ||
					GET_LOWER(hf->name.s + 5) != 'c' ||
					GET_LOWER(hf->name.s + 6) != 't' ||
					GET_LOWER(hf->name.s + 7) != 'i' ||
					GET_LOWER(hf->name.s + 8) != 'o' ||
					GET_LOWER(hf->name.s + 9) != 'n')
				break;

			if (!ws_has_param(WS_UPGRADE_HDR, WS_UPGRADE_HDR_LEN, hf->body)) {
				LM_ERR("Invalid Connection header <%.*s>\n",
						hf->body.len, hf->body.s);
				goto ws_error;
			}

			flags |= WS_CONN_F;
			break;
		case GET_DWORD('s', 'e', 'c', '-'): /* Sec-* */
			if (hf->name.len < HDR_LEN("Sec-Websocket-*") ||
					GET_LOWER(hf->name.s + 4) != 'w' ||
					GET_LOWER(hf->name.s + 5) != 'e' ||
					GET_LOWER(hf->name.s + 6) != 'b' ||
					GET_LOWER(hf->name.s + 7) != 's' ||
					GET_LOWER(hf->name.s + 8) != 'o' ||
					GET_LOWER(hf->name.s + 9) != 'c' ||
					GET_LOWER(hf->name.s + 10) != 'k' ||
					GET_LOWER(hf->name.s + 11) != 'e' ||
					GET_LOWER(hf->name.s + 12) != 't' ||
					GET_LOWER(hf->name.s + 13) != '-')
				break;

			if (hf->name.len == HDR_LEN("Sec-WebSocket-Accept") &&
					GET_LOWER(hf->name.s + 14) == 'a' &&
					GET_LOWER(hf->name.s + 15) == 'c' &&
					GET_LOWER(hf->name.s + 16) == 'c' &&
					GET_LOWER(hf->name.s + 17) == 'e' &&
					GET_LOWER(hf->name.s + 18) == 'p' &&
					GET_LOWER(hf->name.s + 19) == 't') {

				str_trim_spaces_lr(hf->body);
				if (!ws_is_valid_key(&WS_KEY(c), &hf->body)) {
					LM_ERR("invalid answer key <%.*s> for <%.*s>\n",
							hf->body.len, hf->body.s,
							WS_KEY(c).len, WS_KEY(c).s);
					goto error;
				}

				flags |= WS_ACCEPT_F;
			} else if (hf->name.len == HDR_LEN("Sec-WebSocket-Protocol") &&
					GET_LOWER(hf->name.s + 14) == 'p' &&
					GET_LOWER(hf->name.s + 15) == 'r' &&
					GET_LOWER(hf->name.s + 16) == 'o' &&
					GET_LOWER(hf->name.s + 17) == 't' &&
					GET_LOWER(hf->name.s + 18) == 'o' &&
					GET_LOWER(hf->name.s + 19) == 'c' &&
					GET_LOWER(hf->name.s + 20) == 'o' &&
					GET_LOWER(hf->name.s + 21) == 'l') {

				if (!ws_has_param(WS_PROTO_SIP, WS_PROTO_SIP_LEN, hf->body)) {
					LM_ERR("Invalid Protocol <%.*s>\n",
							hf->body.len, hf->body.s);
					goto ws_error;
				}
				/* TODO: verify accepted protocols */
				flags |= WS_PROTO_F;
			} else if (hf->name.len == HDR_LEN("Sec-WebSocket-Extensions") &&
					GET_LOWER(hf->name.s + 14) == 'e' &&
					GET_LOWER(hf->name.s + 15) == 'x' &&
					GET_LOWER(hf->name.s + 16) == 't' &&
					GET_LOWER(hf->name.s + 17) == 'e' &&
					GET_LOWER(hf->name.s + 18) == 'n' &&
					GET_LOWER(hf->name.s + 19) == 's' &&
					GET_LOWER(hf->name.s + 20) == 'i' &&
					GET_LOWER(hf->name.s + 21) == 'o' &&
					GET_LOWER(hf->name.s + 22) == 'n' &&
					GET_LOWER(hf->name.s + 23) == 's') {

				LM_ERR("Extensions are not yet supported\n");
				goto ws_error;
			}
			break;
		}

	}

	if (flags != (unsigned char)WS_ALL_RPL_F) {
		/* negate so we can easily compare them */
		flags = ~flags;
		if (flags & WS_UPGRADE_F)
			LM_ERR("Upgrade header not present!\n");
		if (flags & WS_CONN_F)
			LM_ERR("Connection header not present!\n");
		if (flags & WS_ACCEPT_F)
			LM_ERR("Sec-WebSocket-Protocol header not present!\n");
		if (flags & WS_PROTO_F)
			LM_ERR("Sec-WebSocket-Protocol header not present!\n");
		goto ws_error;
	}

	/* parsing done, free headers */
	free_hdr_field_lst(tmp_msg.headers);

	return 0;
ws_error:
	free_hdr_field_lst(tmp_msg.headers);
error:
	WS_STATE(c) = WS_CON_BAD_REQ;
	return -1;
}


static int ws_start_handshake(struct tcp_connection *c)
{
	int n;
	int i;
	struct timeval get;
	char *ip;
	char *port;
	int port_len;
	static char host_orig_buf[MAX_HOST_LEN];

	str trace_str = { ws_trace_buf, 0 };

	static struct iovec iov[] = {
		{ (void*)HTTP_GET_METHOD, HTTP_GET_METHOD_LEN },	/* GET method */
		{ (void*)" ", 1 },
		{ (void*)NULL, 0 },									/* the resource */
		{ (void*)" ", 1 },
		{ (void*)HTTP_VERSION, HTTP_VERSION_LEN },			/* the version */
		{ (void*)HTTP_SEP, HTTP_SEP_LEN },
		{ (void*)"Host: ", 6 },
		{ (void*)host_orig_buf, 0 },						/* the host */
		{ (void*)HTTP_SEP, HTTP_SEP_LEN },
		{ (void*)"Origin: ", 8 },
		{ (void*)host_orig_buf, 0 },						/* the origin */
		{ (void*)HTTP_SEP, HTTP_SEP_LEN },
		{ (void*)"Sec-WebSocket-Key: ", 19 },
		{ (void*)NULL, 0 },									/* the origin */
		{ (void*)HTTP_SEP, HTTP_SEP_LEN },
		{ (void*)HTTP_HANDSHAKE_END, HTTP_HANDSHAKE_END_LEN }, /* constant part */
	};

	int iov_len = sizeof(iov) / sizeof(struct iovec);

	reset_tcp_vars(tcpthreshold);
	start_expire_timer(get, tcpthreshold);

	ip = ip_addr2a(&c->rcv.src_ip);
	port = int2str(c->rcv.src_port, &port_len);
	n = strlen(ip);
	memcpy(host_orig_buf, ip, n);
	host_orig_buf[n] = ':';
	memcpy(host_orig_buf + n + 1, port, port_len);

	iov[2].iov_base = _ws_common_resource.s;
	iov[2].iov_len = _ws_common_resource.len;

	iov[7].iov_len = n + port_len + 1;
	iov[10].iov_len = iov[7].iov_len;

	iov[13].iov_base = WS_KEY(c).s;
	iov[13].iov_len = WS_KEY(c).len;

	n = _ws_common_writev(c, c->fd, iov, 16, _ws_common_write_tout);
	stop_expire_timer(get, tcpthreshold,
			_ws_common_module " start handshake", "", 0, 1);

	if ( ((struct ws_data *) c->proto_data)->dest ) {
		for ( i=0; i < iov_len; i++ ) {
			/* avoid overflow */
			if ( trace_str.len + iov[i].iov_len > WS_TRACE_MAX )
				break;

			memcpy( trace_str.s + trace_str.len,
					iov[i].iov_base, iov[i].iov_len );
			trace_str.len += iov[i].iov_len;
		}
		if ( trace_ws( c, TRANS_TRACE_CONNECTED, &trace_str ) < 0 ) {
			LM_ERR("WS trace failed!\n");
		}
	}

	return n;
}

/*! \brief
 * reads all headers (until double crlf), & parses the content-length header
 *
 * \note (WARNING: inefficient, tries to reuse receive_msg but will go through
 * the headers twice [once here looking for Content-Length and for the end
 * of the headers and once in receive_msg]; a more speed efficient version will
 * result in either major code duplication or major changes to the receive code)
 *
 * \return number of bytes read & sets r->state & r->body
 * when either r->body!=0 or r->state==H_BODY =>
 * all headers have been read. It should be called in a while loop.
 * returns < 0 if error or 0 if EOF */
static int ws_read_http(struct tcp_connection *c, struct tcp_req *r)
{
	unsigned int remaining;
	int bytes;
	char *p;

	#define crlf_default_skip_case \
					case '\n': \
						r->state=H_LF; \
						break; \
					default: \
						r->state=H_SKIP

	#define content_len_beg_case \
					case ' ': \
					case '\t': \
						if (!r->has_content_len) r->state=H_STARTWS; \
						else r->state=H_SKIP; \
							/* not interested if we already found one */ \
						break; \
					case 'C': \
					case 'c': \
						if(!r->has_content_len) r->state=H_CONT_LEN1; \
						else r->state=H_SKIP; \
						break; \
					case 'l': \
					case 'L': \
						/* short form for Content-Length */ \
						if (!r->has_content_len) r->state=H_L_COLON; \
						else r->state=H_SKIP; \
						break

	#define change_state(upper, lower, newstate)\
					switch(*p){ \
						case upper: \
						case lower: \
							r->state=(newstate); break; \
						crlf_default_skip_case; \
					}

	#define change_state_case(state0, upper, lower, newstate)\
					case state0: \
							  change_state(upper, lower, newstate); \
							  p++; \
							  break


	/* if we still have some unparsed part, parse it first, don't do the read*/
	if (r->parsed<r->pos){
		bytes=0;
	}else{
		bytes=_ws_common_read(c, r);
		if (bytes<=0) return bytes;
	}
	p=r->parsed;

	while(p<r->pos && r->error==TCP_REQ_OK){
		switch((unsigned char)r->state){
			case H_BODY: /* read the body*/
				LM_INFO("Reading the body\n");
				remaining=r->pos-p;
				if (remaining>r->bytes_to_go) remaining=r->bytes_to_go;
				r->bytes_to_go-=remaining;
				p+=remaining;
				if (r->bytes_to_go==0){
					r->complete=1;
					goto skip;
				}
				break;

			case H_SKIP:
				/* find lf, we are in this state if we are not interested
				 * in anything till end of line*/
				p=q_memchr(p, '\n', r->pos-p);
				if (p){
					p++;
					r->state=H_LF;
				}else{
					p=r->pos;
				}
				break;

			case H_LF:
				/* terminate on LF CR LF or LF LF */
				switch (*p){
					case '\r':
						r->state=H_LFCR;
						break;
					case '\n':
						/* found LF LF */
						r->state=H_BODY;
						if (r->has_content_len){
							r->body=p+1;
							r->bytes_to_go=r->content_len;
							if (r->bytes_to_go==0){
								r->complete=1;
								p++;
								goto skip;
							}
						}else{
							LM_DBG("no clen, p=%X\n", *p);
							r->complete=1;
							p++;
							goto skip;
						}
						break;
					content_len_beg_case;
					default:
						r->state=H_SKIP;
				}
				p++;
				break;
			case H_LFCR:
				if (*p=='\n'){
					/* found LF CR LF */
					r->state=H_BODY;
					if (r->has_content_len){
						r->body=p+1;
						r->bytes_to_go=r->content_len;
						if (r->bytes_to_go==0){
							r->complete=1;
							p++;
							goto skip;
						}
					}else{
						LM_DBG("no clen, p=%X\n", *p);
						r->complete=1;
						p++;
						goto skip;
					}
				}else r->state=H_SKIP;
				p++;
				break;

			case H_STARTWS:
				switch (*p){
					content_len_beg_case;
					crlf_default_skip_case;
				}
				p++;
				break;
			case H_SKIP_EMPTY:
				switch (*p){
					case '\n':
					case '\r':
					case ' ':
					case '\t':
						/* skip empty lines */
						break;
					case 'C':
					case 'c':
						r->state=H_CONT_LEN1;
						r->start=p;
						break;
					case 'l':
					case 'L':
						/* short form for Content-Length */
						r->state=H_L_COLON;
						r->start=p;
						break;
					default:
						r->state=H_SKIP;
						r->start=p;
				};
				p++;
				break;
			case H_SKIP_EMPTY_CR_FOUND:
				if (*p=='\n'){
					r->state=H_SKIP_EMPTY_CRLF_FOUND;
					p++;
				}else{
					r->state=H_SKIP_EMPTY;
				}
				break;

			case H_SKIP_EMPTY_CRLF_FOUND:
				if (*p=='\r'){
					r->state = H_SKIP_EMPTY_CRLFCR_FOUND;
					p++;
				}else{
					r->state = H_SKIP_EMPTY;
				}
				break;

			case H_SKIP_EMPTY_CRLFCR_FOUND:
				if (*p=='\n'){
					r->state = H_PING_CRLFCRLF;
					r->complete = 1;
					r->has_content_len = 0; /* hack to avoid error check */
					p++;
					goto skip;
				}else{
					r->state = H_SKIP_EMPTY;
				}
				break;
			change_state_case(H_CONT_LEN1,  'O', 'o', H_CONT_LEN2);
			change_state_case(H_CONT_LEN2,  'N', 'n', H_CONT_LEN3);
			change_state_case(H_CONT_LEN3,  'T', 't', H_CONT_LEN4);
			change_state_case(H_CONT_LEN4,  'E', 'e', H_CONT_LEN5);
			change_state_case(H_CONT_LEN5,  'N', 'n', H_CONT_LEN6);
			change_state_case(H_CONT_LEN6,  'T', 't', H_CONT_LEN7);
			change_state_case(H_CONT_LEN7,  '-', '_', H_CONT_LEN8);
			change_state_case(H_CONT_LEN8,  'L', 'l', H_CONT_LEN9);
			change_state_case(H_CONT_LEN9,  'E', 'e', H_CONT_LEN10);
			change_state_case(H_CONT_LEN10, 'N', 'n', H_CONT_LEN11);
			change_state_case(H_CONT_LEN11, 'G', 'g', H_CONT_LEN12);
			change_state_case(H_CONT_LEN12, 'T', 't', H_CONT_LEN13);
			change_state_case(H_CONT_LEN13, 'H', 'h', H_L_COLON);

			case H_L_COLON:
				switch(*p){
					case ' ':
					case '\t':
						break; /* skip space */
					case ':':
						r->state=H_CONT_LEN_BODY;
						break;
					crlf_default_skip_case;
				};
				p++;
				break;

			case  H_CONT_LEN_BODY:
				switch(*p){
					case ' ':
					case '\t':
						break; /* eat space */
					case '0':
					case '1':
					case '2':
					case '3':
					case '4':
					case '5':
					case '6':
					case '7':
					case '8':
					case '9':
						r->state=H_CONT_LEN_BODY_PARSE;
						r->content_len=(*p-'0');
						break;
					/*FIXME: content length on different lines ! */
					crlf_default_skip_case;
				}
				p++;
				break;

			case H_CONT_LEN_BODY_PARSE:
				switch(*p){
					case '0':
					case '1':
					case '2':
					case '3':
					case '4':
					case '5':
					case '6':
					case '7':
					case '8':
					case '9':
						r->content_len=r->content_len*10+(*p-'0');
						break;
					case '\r':
					case ' ':
					case '\t': /* FIXME: check if line contains only WS */
						r->state=H_SKIP;
						r->has_content_len=1;
						break;
					case '\n':
						/* end of line, parse successful */
						r->state=H_LF;
						r->has_content_len=1;
						break;
					default:
						LM_ERR("bad Content-Length header value, unexpected "
								"char %c in state %d\n", *p, r->state);
						r->state=H_SKIP; /* try to find another?*/
				}
				p++;
				break;

			default:
				LM_CRIT("unexpected state %d\n", r->state);
				abort();
		}
	}
skip:
	r->parsed=p;
	return bytes;
}

static int trace_ws( struct tcp_connection* conn, trans_trace_event event, str* req)
{
#define WS_TRACE_IS_ON( CONN ) (CONN->proto_data && \
		((struct ws_data*)CONN->proto_data)->tprot && \
			((struct ws_data*)CONN->proto_data)->dest && \
			*((struct ws_data*)CONN->proto_data)->trace_is_on)


	struct ws_data* d;
	union sockaddr_union src, dst;

	if ( !conn || !req || !req->s || !req->len ||
			!WS_TRACE_IS_ON(conn) || ! (d = conn->proto_data) )
		return 0;

	if ( d->trace_route_id != -1 ) {
		check_trace_route( d->trace_route_id, conn );
		/* avoid doing this multiple times */
		d->trace_route_id = -1;
	}

	/* check if tracing is deactivated from the route for this connection */
	if ( conn->flags & F_CONN_TRACE_DROPPED )
		return 0;

	if ( !d->message  ) {
		if ( tcpconn2su( conn, &src, &dst ) < 0 ) {
			LM_ERR("can't fetch network info!\n");
			return -1;
		}

		if ( (d->message = create_trace_message( conn->cid, &src, &dst,
						conn->type, d->dest )) == 0 )  {
			LM_ERR(" can't init trace_message!\n");
			return -1;
		}
	}

	add_trace_data( d->message, "Event", &trans_trace_str_event[event]);
	add_trace_data( d->message, "Ws-Request", req);

	return 0;
#undef WS_TRACE_IS_ON
}

static int complete_ws_trace( struct tcp_connection* conn, trans_trace_status status, str* rpl, str* message)
{
	struct ws_data* d;

	if ( !conn || !rpl || !rpl->s || !rpl->len || !(d = conn->proto_data) || !d->message )
		return 0;

	if ( !(*d->trace_is_on) || conn->flags & F_CONN_TRACE_DROPPED )
		return 0;

	/* most probably tracing was activated after the request was processed */
	if ( !d->message )
		return 0;

	add_trace_data( d->message, "Status", &trans_trace_str_status[status]);
	add_trace_data( d->message, "Ws-Reply", rpl);
	if ( message && message->s && message->len )
		add_trace_data( d->message, "Message", message);

	return 0;
}

#undef WS_TRACE_MAX
#endif /* _WS_HANDSHAKE_COMMON_H_ */
