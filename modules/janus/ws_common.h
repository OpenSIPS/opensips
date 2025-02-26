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

#ifndef _JANUSWS_COMMON_H_
#define _JANUSWS_COMMON_H_

#include "../../mem/shm_mem.h"
#include "../../globals.h"
#include "../../receive.h"
#include "../../dprint.h"
#include "../../tsend.h"
#include "../../timer.h"
#include "../../ut.h"
#include "../../pt.h"
#include "../../resolve.h"
#include "janus_ws.h"
#include "ws_tcp.h"
#include "ws_common_defs.h"


/*
 * WebSocket frame
 *
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-------+-+-------------+-------------------------------+
     |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
     |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
     |N|V|V|V|       |S|             |   (if payload len==126/127)   |
     | |1|2|3|       |K|             |                               |
     +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
     |     Extended payload length continued, if payload len == 127  |
     + - - - - - - - - - - - - - - - +-------------------------------+
     |                               |Masking-key, if MASK set to 1  |
     +-------------------------------+-------------------------------+
     | Masking-key (continued)       |          Payload Data         |
     +-------------------------------- - - - - - - - - - - - - - - - +
     :                     Payload Data continued ...                :
     + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
     |                     Payload Data continued ...                |
     +---------------------------------------------------------------+
*/


#define WS_EXT_LEN			126
#define WS_EXTC_LEN			127

#define WS_OP_CONT			0x0
#define WS_OP_TEXT			0x1
#define WS_OP_BIN			0x2
#define WS_OP_CLOSE			0x8
#define WS_OP_PING			0x9
#define WS_OP_PONG			0xA

#define WS_BIT_FIN			0x80
#define WS_BIT_MASK			0x80
#define WS_MASK_SLEN		0x7F
#define WS_MASK_OPCODE		0x0F



/* Minimum size of a header - not masked, nor extended len */
#define WS_MIN_HDR_LEN		(sizeof(uint16_t))

/* Size of extended len */
#define WS_ELEN_SIZE		(sizeof(uint16_t))

/* Size of extended complex len */
#define WS_ELENC_SIZE		(sizeof(uint64_t))

/* Size of mask */
#define WS_MASK_SIZE		(sizeof(uint32_t))

/* Size of an extened header - both mask and extended len */
#define WS_MAX_HDR_LEN		(WS_MIN_HDR_LEN + WS_ELENC_SIZE + WS_MASK_SIZE)

/* Maximum size of an extended header */
#define WS_MAX_ELEN			((uint16_t)(-1))

/* Returns the TCP buffer */
#define WS_BUF(_r) ((uint8_t *)(_r)->tcp.buf)
#define WS_BODY(_r) ((uint8_t *)(_r)->tcp.body)

/* Size of a simple, not exteneded message */
#define WS_SLEN(_r)			(WS_BUF(_r)[1] & WS_MASK_SLEN)

/* Size of an extended message */
#define WS_ELEN(_r)			\
	(((uint16_t)(WS_BUF(_r)[2])) << 8 |\
	 ((uint16_t)(WS_BUF(_r)[3])) << 0)

/* Size of an 64 extended message */
#define WS_ELENC(_r)	\
	(((uint64_t)(WS_BUF(_r)[2])) << 56 |\
	 ((uint64_t)(WS_BUF(_r)[3])) << 48 |\
	 ((uint64_t)(WS_BUF(_r)[4])) << 40 |\
	 ((uint64_t)(WS_BUF(_r)[5])) << 32 |\
	 ((uint64_t)(WS_BUF(_r)[6])) << 24 |\
	 ((uint64_t)(WS_BUF(_r)[7])) << 16 |\
	 ((uint64_t)(WS_BUF(_r)[8])) << 8  |\
	 ((uint64_t)(WS_BUF(_r)[9])) << 0)

/* returns the close code */
#define WS_CLOSE_CODE(_r)\
	(((uint16_t)(WS_BODY(_r)[0])) << 8 |\
	 ((uint16_t)(WS_BODY(_r)[1])) << 0)

#define WS_USE_ELEN(_r)		(WS_SLEN(_r) == WS_EXT_LEN)
#define WS_USE_ELENC(_r)	(WS_SLEN(_r) == WS_EXTC_LEN)
#define WS_IS_MASKED(_r)	(WS_BUF(_r)[1] & WS_BIT_MASK)
#define WS_IS_FIN(_r)		(WS_BUF(_r)[0] & WS_BIT_FIN)
#define WS_OPCODE(_r)		(WS_BUF(_r)[0] & WS_MASK_OPCODE)
#define WS_MASK(_r)			(*((unsigned int *)(WS_BODY(_r)) - 1))

/* Returns the size of the mask, if needed */
#define WS_IF_MASK_SIZE(_r)	(WS_IS_MASKED(_r) ? WS_MASK_SIZE : 0)

#define ROTATE32(_k) ((((_k) & 0xFF) << 24) | ((_k) >> 8))
#define MASK8(_k) ((unsigned char)((_k) & 0xFF))

#ifndef _ws_common_writev
#error "_ws_common_writev not defined!"
#endif
#ifndef _ws_common_write_tout
#error "_ws_common_write_tout not defined!"
#endif

static inline void ws_print_masked(char *buf, int len)
{
	static char *print_buf;
	static long print_buf_len = 0;
	int current_len;

	char *p = print_buf;
	int i, j;
	for (i = j = 0; i < len; i++) {
		if (p - print_buf + print_buf_len < 1024) {
			print_buf_len += 1024;
			current_len = p - print_buf;
			print_buf = pkg_realloc(print_buf, print_buf_len);
			if (!print_buf)
				return;
			p = print_buf + current_len;
		}
		if (buf[i] < 32)
			p += sprintf(p, ".");
		else
			p += sprintf(p, "%c", buf[i]);
		if ((i + 1) % 32 == 0) {
			p += sprintf(p, "   |    ");
			for (; j <= i; j++)
				p += sprintf(p, "%02X%s", buf[j], j % 2 == 0 ? "" : "  ");
			j = i + 1;
			p += sprintf(p, "\n");
		}
	}
}

static inline void ws_mask(char *buf, int len, unsigned int mask)
{
	char *p = buf;
	char *end = buf + len;

	/* xor first bits, until aligned */
	for (; p < end && (((unsigned long)p) % sizeof(unsigned long *)); p++,
			mask = ROTATE32(mask))
		*p ^= MASK8(mask);

	/* xor the big chunk, which is aligned */
	for (; p < end - (sizeof(int) - 1); p += sizeof(int))
		*((int *)p) ^= mask;

	/* the last chunk may not be processed */
	for (; p < end; p++, mask >>= 8)
		*p ^= MASK8(mask);
	//ws_print_masked(buf, len);
}


static inline int janus_ws_send(janus_connection *con, int op,
		char *body, unsigned int len)
{
	/*
	 * we need this buffer to mask the message sent to the client
	 * since we cannot modify the buffer - it might be readonly
	 */
	static char *body_buf = 0;
	static unsigned char hdr_buf[WS_MAX_HDR_LEN];
	static struct iovec v[2] = { {hdr_buf, 0}, {0, 0}};
	unsigned int mask = rand();

	LM_DBG("Sending out %.*s over Janus WS\n",len,body);

	/* FIN + OPCODE */
	hdr_buf[0] = WS_BIT_FIN | (op & WS_MASK_OPCODE);

	if (len == 0) {
		hdr_buf[1] = 0;
		/* don't have any data, send only the heeader  */
		v[0].iov_len = WS_MIN_HDR_LEN;
		return janus_ws_raw_writev(con->fd, v, 1, _ws_common_write_tout);
	} else if (len < WS_EXT_LEN) {
		hdr_buf[1] = len;
		v[0].iov_len = WS_MIN_HDR_LEN;
	} else if (len < WS_MAX_ELEN) {
		v[0].iov_len = WS_MIN_HDR_LEN + WS_ELEN_SIZE;
		hdr_buf[1] = WS_EXT_LEN;
		*(uint16_t *)(hdr_buf + WS_MIN_HDR_LEN) = htons(len);
	} else {
		v[0].iov_len = WS_MIN_HDR_LEN + WS_ELENC_SIZE;
		hdr_buf[1] = WS_EXTC_LEN;
		/* len can't be larger than 32 bits long */
		*(uint64_t *)(hdr_buf + WS_MIN_HDR_LEN) = htonl(len);
	}

	if (WS_TYPE(con) == WS_CLIENT) {
		/* set the mask in the message */
		*(uint32_t *)(v[0].iov_base + v[0].iov_len) = mask;
		v[0].iov_len += WS_MASK_SIZE;
		/* also indicate that the message is masked */
		hdr_buf[1] |= WS_BIT_MASK;

		body_buf = body_buf ? pkg_realloc(body_buf, len) : pkg_malloc(len);
		if (!body_buf) {
			LM_ERR("oom for body buffer\n");
			return -1;
		}
		memcpy(body_buf, body, len);

		ws_mask(body_buf, len, mask);
		v[1].iov_base = body_buf;
	} else {
		v[1].iov_base = body;
	}

	v[1].iov_len = len;

	return janus_ws_raw_writev(con->fd, v, 2, _ws_common_write_tout);
}

static inline int janus_ws_send_pong(janus_connection *con, struct janus_ws_req *req)
{
	return janus_ws_send(con, WS_OP_PONG,
			req->tcp.body, req->tcp.content_len);
}

static inline int janus_ws_send_close(janus_connection *con)
{
	uint16_t code;
	int len;
	char *buf;

	if (WS_CODE(con)) {
		code = htons(WS_CODE(con));
		len = sizeof(uint16_t);
	} else {
		len = 0;
	}

	buf = (char *)&code;
	return janus_ws_send(con, WS_OP_CLOSE, buf, len);
}

/* Public functions down here */

static int janus_ws_req_write(janus_connection *con, char *buf, int len)
{
	return janus_ws_send(con, WS_OP_TEXT, buf, len);
}

static enum ws_close_code inline janus_ws_parse(struct janus_ws_req *req)
{

	uint64_t clen;

	/* when the header is parsed, parse is moved at the end of the header */
	if (!req->tcp.body) {

		/* check if we have the minimal header */
		if (req->tcp.pos - req->tcp.buf < WS_MIN_HDR_LEN) {
			/* wait for more data to come */
			LM_DBG("Wait for more \n");
			goto update_parsed;
		}

		if (!WS_IS_FIN(req)) {
			LM_ERR("We do not support fragmemntation yet. Dropping...\n");
			req->tcp.error = TCP_READ_ERROR;
			return WS_ERR_POLICY;
		}

		/* check if it is an operation that we support */
		req->op = WS_OPCODE(req);
		switch (req->op) {
		case WS_OP_TEXT:
		case WS_OP_BIN:
		case WS_OP_CLOSE:
		case WS_OP_PING:
		case WS_OP_PONG:
			/* continue to read whole packet */
			break;
		default:
			LM_ERR("Unsupported WebSocket opcode: %d\n", req->op);
			return WS_ERR_INVALID;
		}

		/* if it has extended lenght, drop it because we can't read it all */
		if (WS_USE_ELENC(req)) {
			/* extended case */
			if (req->tcp.pos - req->tcp.buf < WS_MIN_HDR_LEN + WS_ELENC_SIZE +
					WS_IF_MASK_SIZE(req))
				/* wait for more data to come */
				goto update_parsed;

			clen = WS_ELENC(req);
			if ((clen+WS_MIN_HDR_LEN+WS_ELENC_SIZE+WS_IF_MASK_SIZE(req))>
					TCP_BUF_SIZE) {
				LM_ERR("packet too large, can't fit: %" PRIu64 "\n", clen);
				req->tcp.error = TCP_REQ_OVERRUN;
				return WS_ERR_TOO_BIG;
			}
			req->tcp.content_len = clen;
			/* body of the packet */
			req->tcp.body = (char *)req->tcp.buf + WS_MIN_HDR_LEN + WS_ELENC_SIZE;
		} else if (WS_USE_ELEN(req)) {
			/* extended case */
			if (req->tcp.pos - req->tcp.buf < WS_MIN_HDR_LEN + WS_ELEN_SIZE +
					WS_IF_MASK_SIZE(req))
				/* wait for more data to come */
				goto update_parsed;

			req->tcp.content_len = WS_ELEN(req);
			if ((req->tcp.content_len+WS_MIN_HDR_LEN+WS_ELEN_SIZE+WS_IF_MASK_SIZE(req))>
					TCP_BUF_SIZE) {
				LM_ERR("packet too large, can't fit: %u\n", req->tcp.content_len);
				req->tcp.error = TCP_REQ_OVERRUN;
				return WS_ERR_TOO_BIG;
			}
			/* body of the packet */
			req->tcp.body = (char *)req->tcp.buf + WS_MIN_HDR_LEN + WS_ELEN_SIZE;
		} else {
			/* we should have no problems here, the buffer should be large enough */
			req->tcp.content_len = WS_SLEN(req);
			req->tcp.body = (char *)req->tcp.buf + WS_MIN_HDR_LEN;
		}

		if (WS_IS_MASKED(req)) {
			req->tcp.body += WS_MASK_SIZE;
			req->mask = WS_MASK(req);
			req->is_masked = 1;
		} else {
			req->is_masked = 0;
		}
	}

	/* do we have the entire packet? */
	if (req->tcp.pos - req->tcp.body >= req->tcp.content_len) {
		/*
		 * decode only if we have something interesting out there
		 * even if we have a mask but it is 0, XOR doesn't do anything
		 */
		if (req->mask && req->tcp.content_len)
			ws_mask(req->tcp.body, req->tcp.content_len, req->mask);

		req->tcp.complete = 1;
		req->tcp.parsed = req->tcp.body + req->tcp.content_len;
		//LM_DBG("read full, parsed = %p , %d\n",req->tcp.parsed,*(req->tcp.parsed));
	} else {
update_parsed:
		req->tcp.parsed = req->tcp.pos;
	}

	return 0;
}

#define init_janus_ws_req(_req, _size) \
	do { \
		init_tcp_req(&(_req)->tcp, _size); \
		(_req)->op = WS_OP_CONT; \
		(_req)->mask = 0; \
		(_req)->is_masked = 0; \
		(_req)->complete=0; \
		(_req)->body=NULL; \
	} while(0)

static int janus_connection_read_data(janus_connection *sock, struct janus_ws_req *req, int _max_msg_chunks)
{
	int ret=-1;
	long size=0;
	enum ws_close_code ret_code = WS_ERR_NONE;
	unsigned char bk;

	if (req->tcp.complete) {
		/* sanity mask checks */
		if ((WS_TYPE(sock) == WS_CLIENT && req->is_masked) ||
			(WS_TYPE(sock) == WS_SERVER && !req->is_masked)) {
			LM_DBG("malformed WS msg - %s %s\n",
					req->is_masked ? "masked" : "not masked",
					WS_TYPE(sock) == WS_CLIENT ? "client" : "server");
			ret_code = WS_ERR_BADDATA;
			goto error;
		}

		switch (req->op) {
		case WS_OP_CLOSE:
			if (req->tcp.content_len) {
				/* for now we are only interested in the code, not the reason */
				ret_code = WS_CLOSE_CODE(req);
				switch(ret_code) {
				case WS_ERR_NORMAL: LM_DBG("Normal WebSocket close\n"); break;
				case WS_ERR_CLIENT: LM_DBG("Client error close\n"); break;
				case WS_ERR_PROTO:  LM_DBG("WebSocket protocol error\n"); break;
				case WS_ERR_BADDATA: LM_DBG("Data type not consistent\n"); break;
				case WS_ERR_POLICY: LM_DBG("Bad policy close\n"); break;
				case WS_ERR_TOO_BIG: LM_DBG("Packet too big close\n"); break;
				case WS_ERR_BADEXT: LM_DBG("Bad extension close\n"); break;
				case WS_ERR_UNEXPECT: LM_DBG("Unexpected condition close\n"); break;
				default:
					LM_DBG("Unknown WebSocket close: %d\n", ret_code);
				}
			} else {
				ret_code = WS_ERR_NORMAL;
			}

			LM_DBG("Responding to close with %d\n",ret_code);
			/* respond to close */
			WS_CODE(sock) = ret_code;
			janus_ws_send_close(sock);
			WS_CODE(sock) = WS_ERR_NOSEND;

			/* release the connextion */
			sock->state = S_CONN_EOF;

			/* we are trying to populate the handler ID, close if not expected */
			return -1;

		case WS_OP_PING:
			if (janus_ws_send_pong(sock, req) < 0)
					LM_ERR("cannot send PONG msg\n");
			break;

		case WS_OP_PONG:
			LM_DBG("Received WebSocket PONG\n");
			break;

		case WS_OP_TEXT:
		case WS_OP_BIN:
			LM_DBG("read complete [%.*s] \n",(int)(req->tcp.parsed-req->tcp.body),req->tcp.body); 

			bk = *req->tcp.parsed;
			*req->tcp.parsed = 0;

			req->buf = req->tcp.body;
			req->buf_len = req->tcp.parsed-req->tcp.body;
			
			janus_brief_parse_msg((struct janus_req *)req);

			if (req->complete) {
				*req->tcp.parsed=0;

				/* prepare for next request */
				size=req->tcp.pos-req->tcp.parsed;

				if (size) {
					LM_DBG("We still have %lu bytes, keeping connection \n", size);
				}

				if (handle_janus_json_request(sock, req->body) <0) {
					LM_ERR("Failed to process janus request \n");
					cJSON_Delete(req->body);
					return -1;
				}

				cJSON_Delete(req->body);

				*req->tcp.parsed = bk;

				/* we have received our data */
				ret = 0;
			} else {
				/* we need to read some more */
				ret = 1;
			}

			break;

			default:
				LM_BUG("Can't handle %d\n", req->op);
				goto error;
		}

		if (size) memmove(req->tcp.buf, req->tcp.parsed, size);

		LM_DBG("preparing for new request, kept %ld bytes\n", size);

		init_janus_ws_req(req, size);
		sock->msg_attempts = 0;

		if (size)
			return 1;

		return ret;
	} else {
		/* we need to read some more */
		return 1;
	}

	/* connection will be released */
	return size;
error:
	WS_CODE(sock) = ret_code;
	if (WS_CODE(sock) != WS_ERR_NONE) {
		janus_ws_send_close(sock);
		WS_CODE(sock) = WS_ERR_NOSEND;
	}
	return -1;
}

static int janus_connection_handler_id(janus_connection *sock, struct janus_ws_req *req, int _max_msg_chunks)
{
	int ret=-1;
	long size=0;
	enum ws_close_code ret_code = WS_ERR_NONE;

	if (req->tcp.complete) {
		/* sanity mask checks */
		if ((WS_TYPE(sock) == WS_CLIENT && req->is_masked) ||
			(WS_TYPE(sock) == WS_SERVER && !req->is_masked)) {
			LM_DBG("malformed WS msg - %s %s\n",
					req->is_masked ? "masked" : "not masked",
					WS_TYPE(sock) == WS_CLIENT ? "client" : "server");
			ret_code = WS_ERR_BADDATA;
			goto error;
		}

		size=req->tcp.pos-req->tcp.parsed;

		switch (req->op) {
		case WS_OP_CLOSE:
			if (req->tcp.content_len) {
				/* for now we are only interested in the code, not the reason */
				ret_code = WS_CLOSE_CODE(req);
				switch(ret_code) {
				case WS_ERR_NORMAL: LM_DBG("Normal WebSocket close\n"); break;
				case WS_ERR_CLIENT: LM_DBG("Client error close\n"); break;
				case WS_ERR_PROTO:  LM_DBG("WebSocket protocol error\n"); break;
				case WS_ERR_BADDATA: LM_DBG("Data type not consistent\n"); break;
				case WS_ERR_POLICY: LM_DBG("Bad policy close\n"); break;
				case WS_ERR_TOO_BIG: LM_DBG("Packet too big close\n"); break;
				case WS_ERR_BADEXT: LM_DBG("Bad extension close\n"); break;
				case WS_ERR_UNEXPECT: LM_DBG("Unexpected condition close\n"); break;
				default:
					LM_DBG("Unknown WebSocket close: %d\n", ret_code);
				}
			} else {
				ret_code = WS_ERR_NORMAL;
			}

			/* respond to close */
			WS_CODE(sock) = ret_code;
			janus_ws_send_close(sock);
			WS_CODE(sock) = WS_ERR_NOSEND;

			/* release the connextion */
			sock->state = S_CONN_EOF;

			/* we are trying to populate the handler ID, close if not expected */
			return -1;

		case WS_OP_PING:
			if (janus_ws_send_pong(sock, req) < 0)
					LM_ERR("cannot send PONG msg\n");
			break;

		case WS_OP_PONG:
			LM_DBG("Received WebSocket PONG\n");
			break;

		case WS_OP_TEXT:
		case WS_OP_BIN:
			LM_DBG("read complete [%.*s] \n",(int)(req->tcp.parsed-req->tcp.body),req->tcp.body); 

			req->buf = req->tcp.body;
			req->buf_len = req->tcp.parsed-req->tcp.body;

			janus_brief_parse_msg((struct janus_req *)req);

			if (req->complete) {
				*req->tcp.parsed=0;

				/* prepare for next request */
				size=req->tcp.pos-req->tcp.parsed;

				if (size) {
					LM_DBG("We still have %lu bytes, keeping connection \n", size);
				}

				if (populate_janus_handler_id(sock, req->body) <0) {
					LM_ERR("Failed to populate handler id \n");
					cJSON_Delete(req->body);
					return -1;
				}

				cJSON_Delete(req->body);
				/* we have populated the janus handler id */
				ret = 0;
			} else {
				ret = 1;
			}

			break;

			default:
				LM_BUG("Can't handle %d\n", req->op);
				goto error;
			}

		if (size) memmove(req->tcp.buf, req->tcp.parsed, size);

		LM_DBG("preparing for new request, kept %ld bytes\n", size);

		init_janus_ws_req(req, size);
		sock->msg_attempts = 0;

		if (size)
			return 1;

		return ret;
	} else {
		/* we need to read some more */
		return 1;
	}

	/* connection will be released */
	return size;
error:
	WS_CODE(sock) = ret_code;
	if (WS_CODE(sock) != WS_ERR_NONE) {
		janus_ws_send_close(sock);
		WS_CODE(sock) = WS_ERR_NOSEND;
	}
	return -1;
}

void print_sockaddr_union3(union sockaddr_union *addr) {
    char buffer[INET6_ADDRSTRLEN];

    if (addr->s.sa_family == AF_INET) {
        inet_ntop(AF_INET, &(addr->sin.sin_addr), buffer, INET_ADDRSTRLEN);
        LM_DBG("IPv4: %s, Port: %d\n", buffer, ntohs(addr->sin.sin_port));
    } else if (addr->s.sa_family == AF_INET6) {
        inet_ntop(AF_INET6, &(addr->sin6.sin6_addr), buffer, INET6_ADDRSTRLEN);
        LM_DBG("IPv6: %s, Port: %d\n", buffer, ntohs(addr->sin6.sin6_port));
    } else {
        LM_ERR("Unknown address family: %d\n", addr->s.sa_family);
    }
}

static int janus_ws_sync_connect(janus_connection *sock)
{
	int s;
	struct hostent *he;
	char c;
	union sockaddr_union su;
	union sockaddr_union *to_su;
	union sockaddr_union *src_su=NULL;
	struct ws_data *d;

	if (!sock) {
		LM_ERR("NULL JANUS socket provided \n");
		return -1;
	}

	if (sock->fd >= 0) {
		LM_ERR("Internal BUG - JANUS FD found when trying to connect \n");
		return -1;
	}

	/* NULL terminate */
	c = sock->parsed_url.host.s[sock->parsed_url.host.len];
	sock->parsed_url.host.s[sock->parsed_url.host.len]= 0;

	to_su = &su;

	he = resolvehost(sock->parsed_url.host.s,0);
	if (!he || hostent2su(to_su, he, 0, sock->parsed_url.port_no) < 0) {
		LM_ERR("Could not resolve the destination <%s>\n",
			sock->parsed_url.host.s);
		sock->parsed_url.host.s[sock->parsed_url.host.len] = c;
		return -2;
	}

	sock->parsed_url.host.s[sock->parsed_url.host.len] = c;

	LM_DBG("Connecting to JANUS at : \n");
	print_sockaddr_union3(to_su);

	tcp_con_get_profile(to_su, src_su, PROTO_TCP, &sock->profile);

	s = tcp_sync_connect_fd(src_su, to_su, PROTO_TCP, &sock->profile,0);
	if (s < 0) {
		LM_ERR("cannot TCP connect to %.*s:%d\n",
		sock->parsed_url.host.len,sock->parsed_url.host.s,
		sock->parsed_url.port_no);
		return -3;
	}

	/* allocate the tcp_data and the array of chunks as a single mem chunk */
	d = (struct ws_data *)shm_malloc(sizeof(*d));
	if (d==NULL) {
		LM_ERR("failed to create ws states in shm mem\n");
		return -1;
	}
	memset( d, 0, sizeof( struct ws_data ) );

	d->state = WS_CON_INIT;
	d->type = WS_NONE;
	d->code = WS_ERR_NONE;

	sock->proto_data = (void*)d;

	return s;
}

int janus_handle_data(janus_connection *sock)
{
	struct janus_ws_req *req;
	enum ws_close_code ret_code = WS_ERR_NONE;
	int total_bytes=0,bytes=0;

	LM_DBG("We have data incoming on %.*s\n",sock->janus_id.len,sock->janus_id.s);

	req = &sock->con_req;

read_again:
	if(sock->state!=S_CONN_OK)
		goto done; /* not enough data */
	if (req->tcp.error == TCP_REQ_OK) {
		if (req->tcp.parsed >= req->tcp.pos) {
			if ((bytes = janus_ws_raw_read(sock, &sock->con_req.tcp)) < 0) {
				LM_ERR("failed to read %d:%s\n", errno, strerror(errno));
				goto error;
			}

			total_bytes+=bytes;
		}

		ret_code = janus_ws_parse(req);
		LM_DBG("Read %d bytes ; total = %d, %.*s\n",bytes,total_bytes,bytes,req->tcp.body);
		if (ret_code)
			goto error;

		/* eof check:
		 * is EOF if eof on fd and r.  not complete yet,
		 * if r. is complete we might have a second unparsed
		 * request after it, so postpone release_with_eof
		 */
		if ((sock->state==S_CONN_EOF) && (req->complete==0)) {
			LM_DBG("EOF received\n");
			goto done;
		}
	}

	if (req->tcp.error!=TCP_REQ_OK){
		LM_ERR("bad request, error=%d "
				  "buf:\n%.*s\nparsed:\n%.*s\n", req->tcp.error,
				  (int)(req->tcp.pos-req->tcp.buf), req->tcp.buf,
				  (int)(req->tcp.parsed-req->tcp.start), req->tcp.start);
		goto error;
	}

	int max_chunks = tcp_attr_isset(sock, TCP_ATTR_MAX_MSG_CHUNKS) ?
			sock->profile.attrs[TCP_ATTR_MAX_MSG_CHUNKS] : janusws_max_msg_chunks;

	switch (janus_connection_read_data(sock, req, max_chunks) ) {
		case 1:
			LM_DBG("We have more to read on janus ws conn, going again \n");
			goto read_again;
		case -1:
			goto error;

		case 0:
			goto done;
		default:
			LM_ERR("Unexpected return code from handler id population \n");
			goto error;
	}

done:
	/* connection will be released */
	return 0;
error:
	/* connection will be released as ERROR */
	LM_ERR("Failed JANUS process - releasing conn \n");
	return -1;
}

int janus_populate_handler_id(janus_connection *sock)
{
	struct janus_ws_req *req;
	enum ws_close_code ret_code = WS_ERR_NONE;
	int total_bytes=0,bytes=0;

	req = &sock->con_req;

	if(sock->state!=S_CONN_OK)
		goto done; /* not enough data */
read_again:
	if (req->tcp.error == TCP_REQ_OK) {
		if (req->tcp.parsed >= req->tcp.pos) {
			if ((bytes = janus_ws_raw_read(sock, &sock->con_req.tcp)) < 0) {
				LM_ERR("failed to read %d:%s\n", errno, strerror(errno));
				goto error;
			}

			if (bytes == 0) {
				LM_DBG("Read 0 bytes, blocking here to go again \n");
				usleep(10000);
				goto read_again;
			}
			total_bytes+=bytes;
		}
		ret_code = janus_ws_parse(req);
		if (ret_code)
			goto error;

		/* eof check:
		 * is EOF if eof on fd and r.  not complete yet,
		 * if r. is complete we might have a second unparsed
		 * request after it, so postpone release_with_eof
		 */
		if ((sock->state==S_CONN_EOF) && (req->complete==0)) {
			LM_DBG("EOF received\n");
			goto done;
		}
	}

	if (req->tcp.error!=TCP_REQ_OK){
		LM_ERR("bad request, error=%d "
				  "buf:\n%.*s\nparsed:\n%.*s\n", req->tcp.error,
				  (int)(req->tcp.pos-req->tcp.buf), req->tcp.buf,
				  (int)(req->tcp.parsed-req->tcp.start), req->tcp.start);
		goto error;
	}

	int max_chunks = tcp_attr_isset(sock, TCP_ATTR_MAX_MSG_CHUNKS) ?
			sock->profile.attrs[TCP_ATTR_MAX_MSG_CHUNKS] : janusws_max_msg_chunks;

	/* FIXME - remove duplicate code here vs regular reading, and pass function as param */
	switch (janus_connection_handler_id(sock, req, max_chunks) ) {
		case 1:
			LM_DBG("We have more to read on janus ws conn, going again \n");
			goto read_again;
		case -1:
			goto error;

		case 0:
			goto done;
		default:
			LM_ERR("Unexpected return code from handler id population \n");
			goto error;
	}

done:
	/* connection will be released */
	return 0;
error:
	/* connection will be released as ERROR */
	LM_ERR("Failed JANUS process - releasing conn \n");
	return -1;
}


/* does initial transaction creation & gets handler id
 * it does this sinchronously, connection is not in the reactor yet */
int janus_init_connection(janus_connection *sock)
{
	str connect_cmd = str_init("{\"janus\":\"create\",\"transaction\":\"1\"}");

	LM_DBG("About to send %.*s on %.*s\n",connect_cmd.len,connect_cmd.s,
			sock->full_url.len,sock->full_url.s);

	if (janusws_write_req(sock,connect_cmd.s,connect_cmd.len) < 0) {
		LM_ERR("Failed to send initial transaction create \n"); 
		return -1;
	}

	if (janus_populate_handler_id(sock) < 0 ) {
		LM_ERR("Failed to populate transaction id \n"); 
		return -1;
	}

	return 1;
}

int janus_ws_connect(janus_connection *sock) 
{
	int fd=-1;

	fd = janus_ws_sync_connect(sock);
	if (fd < 0) {
		LM_ERR("Failed to connect to JANUS at TCP level \n");
		return -1;
	}

	sock->fd = fd;

	if (WS_TYPE(sock) != WS_NONE) {
		LM_BUG("invalid type for connection %d\n", WS_TYPE(sock));
		goto error;
	}
	WS_TYPE(sock) = WS_CLIENT;

	if (janus_ws_client_handshake(sock)) {
		LM_ERR("cannot complete WebSocket handshake\n");
		goto error;
	}

	return 1;
error:
	if (fd != -1)
		close(fd);

	return -1;
}

#endif /* _WS_COMMON_H_ */
