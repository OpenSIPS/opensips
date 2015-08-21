/*
 * Copyright (C) 2015 - OpenSIPS Foundation
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
 *
 * History:
 * -------
 *  2015-02-xx  first version (razvanc)
 */

#include "../../mem/shm_mem.h"
#include "../../net/net_tcp.h"
#include "../../globals.h"
#include "../../receive.h"
#include "../../dprint.h"
#include "../../tsend.h"
#include "../../timer.h"
#include "../../ut.h"
#include "../../pt.h"
#include "ws_tcp.h"
#include "ws.h"


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


#define WS_ERR_NORMAL		1000
#define WS_ERR_CLIENT		1001
#define WS_ERR_PROTO		1002
#define WS_ERR_INVALID		1003
#define WS_ERR_BADDATA		1007
#define WS_ERR_POLICY		1008
#define WS_ERR_TOO_BIG		1009
#define WS_ERR_BADEXT		1010
#define WS_ERR_UNEXPECT		1011


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



/* wrapper around tcp request to add ws info */
struct ws_req {
	struct tcp_req tcp;
	unsigned int op;
	unsigned int mask;
};

#define ROTATE32(_k) ((((_k) & 0xFF) << 24) | ((_k) >> 8))
#define MASK8(_k) ((unsigned char)((_k) & 0xFF))

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
	LM_INFO("Print buffer\n%s", print_buf);
}

void inline ws_mask(char *buf, int len, unsigned int mask)
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


static inline int ws_send(struct tcp_connection *con, int fd, int op,
		int should_mask, unsigned int mask, char *body, unsigned int len)
{
	static unsigned char hdr_buf[WS_MAX_HDR_LEN];
	static struct iovec v[2] = { {hdr_buf, 0}, {0, 0}};

	/* FIN + OPCODE */
	hdr_buf[0] = WS_BIT_FIN | (op & WS_MASK_OPCODE);

	if (len == 0) {
		hdr_buf[1] = 0;
		/* don't have any data, send only the heeader  */
		return ws_raw_write(con, fd, (char *)hdr_buf, WS_MIN_HDR_LEN);
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

	if (should_mask) {
		/* set the mask in the message */
		*(uint32_t *)(v[0].iov_base + v[0].iov_len) = mask;
		v[0].iov_len += WS_MASK_SIZE;
		/* also indicate that the message is masked */
		hdr_buf[1] |= WS_BIT_MASK;

		ws_mask(body, len, mask);
	}

	v[1].iov_base = body;
	v[1].iov_len = len;

	return ws_raw_writev(con, fd, v, 2);
}

static inline int ws_send_pong(struct tcp_connection *con, struct ws_req *req)
{
	return ws_send(con, con->fd, WS_OP_PONG, !WS_IS_MASKED(req),
			0/* XXX: no need to mask for now, only when act as client */,
			req->tcp.body, req->tcp.content_len);
}

static inline int ws_send_close(struct tcp_connection *con, int ret)
{
	uint16_t code;
	int len;
	char *buf;

	if (ret) {
		code = htons(ret);
		len = sizeof(uint16_t);
	} else {
		len = 0;
	}

	buf = (char *)&code;
	return ws_send(con, con->fd, WS_OP_CLOSE, 0, 0, buf, len);
}

/* Public functions down here */

int ws_req_write(struct tcp_connection *con, int fd, char *buf, int len)
{
	return ws_send(con, fd, WS_OP_TEXT, 0/* XXX: should be taken from con */,
			0/* XXX: taken from con */,
			buf, len);
}

static struct ws_req ws_current_req;

static inline int ws_parse(struct ws_req *req)
{

	uint64_t clen;

	/* when the header is parsed, parse is moved at the end of the header */
	if (!req->tcp.body) {

		/* check if we have the minimal header */
		if (req->tcp.pos - req->tcp.buf < WS_MIN_HDR_LEN)
			/* wait for more data to come */
			return 0;

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
				return 0;

			clen = WS_ELENC(req);
			if ((clen+WS_MIN_HDR_LEN+WS_ELENC_SIZE+WS_IF_MASK_SIZE(req))>
					TCP_BUF_SIZE) {
				LM_ERR("packet too large, can't fit: %lu\n", clen);
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
				return 0;

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
	} else
		req->tcp.parsed = req->tcp.pos;

	return 0;
}

#define init_ws_req(_req, _size) \
	do { \
		init_tcp_req(&(_req)->tcp, _size); \
		(_req)->op = WS_OP_CONT; \
		(_req)->mask = 0; \
	} while(0)

int ws_process(struct tcp_connection *con)
{
	struct ws_req *req;
	struct ws_req *newreq;
	long size = 0;
	int ret_code = 0;
	unsigned char bk;
	char *msg_buf;
	int msg_len;
	struct receive_info local_rcv;

	if (con->con_req) {
		req=(struct ws_req *)con->con_req;
		LM_DBG("Using the per connection buff \n");
	} else {
		LM_DBG("Using the global ( per process ) buff \n");
		init_ws_req(&ws_current_req, 0);
		req=&ws_current_req;
	}

again:
	if (req->tcp.error == TCP_REQ_OK) {
		if (req->tcp.parsed >= req->tcp.pos) {
			if (ws_raw_read(con, &req->tcp) < 0) {
				LM_ERR("failed to read %d:%s\n", errno, strerror(errno));
				goto error;
			}
		}
		ret_code = ws_parse(req);
		if (ret_code)
			goto error;

		/* eof check:
		 * is EOF if eof on fd and r.  not complete yet,
		 * if r. is complete we might have a second unparsed
		 * request after it, so postpone release_with_eof
		 */
		if ((con->state==S_CONN_EOF) && (req->tcp.complete==0)) {
			LM_DBG("EOF received\n");
			goto done;
		}
	}

	if (req->tcp.complete) {

		/* update the timeout - we successfully read the request */
		tcp_conn_set_lifetime(con, ws_send_timeout);
		con->timeout=con->lifetime;

		/* if we are here everything is nice and ok*/
		update_stat( pt[process_no].load, +1 );
		/* rcv.bind_address should always be !=0 */
		bind_address=con->rcv.bind_address;

		con->rcv.proto_reserved1=con->id; /* copy the id */
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
			ws_send_close(con, ret_code);

			/* release the connextion */
			con->state = S_CONN_EOF;
			goto done;

		case WS_OP_PING:
			if (ws_send_pong(con, req) < 0)
					LM_ERR("cannot send PONG msg\n");
			break;

		case WS_OP_PONG:
			LM_DBG("Received WebSocket PONG\n");
			break;

		case WS_OP_TEXT:
		case WS_OP_BIN:

			bk = *req->tcp.parsed;
			*req->tcp.parsed = 0;
			msg_buf = req->tcp.body;
			msg_len = req->tcp.parsed-req->tcp.body;
			local_rcv = con->rcv;

			if (!size) {
				/* did not read any more things -  we can release
				 * the connection */
				LM_DBG("We're releasing the connection in state %d \n",
					con->state);
				if (req != &ws_current_req) {
					/* we have the buffer in the connection tied buff -
					 *	detach it , release the conn and free it afterwards */
					con->con_req = NULL;
				}
				/* TODO - we could indicate to the TCP net layer to release
				 * the connection -> other worker may read the next available
				 * message on the pipe */
			} else {
				LM_DBG("We still have things on the pipe - "
					"keeping connection \n");
			}

			if (receive_msg(msg_buf, msg_len, &local_rcv) <0)
					LM_ERR("receive_msg failed \n");

			*req->tcp.parsed = bk;

			break;

			default:
				LM_BUG("Can't handle %d\n", req->op);
				goto error;
			}

		update_stat( pt[process_no].load, -1 );

		if (size) memmove(req->tcp.buf, req->tcp.parsed, size);
#ifdef EXTRA_DEBUG
		LM_DBG("preparing for new request, kept %ld bytes\n", size);
#endif
		init_ws_req(req, size);
		con->msg_attempts = 0;

		/* if we still have some unparsed bytes, try to  parse them too*/
		if (size)
			goto again;
		/* cleanup the existing request */
		if (req != &ws_current_req)
			pkg_free(req);

	} else {
		/* request not complete - check the if the thresholds are exceeded */

		con->msg_attempts++;
		if (con->msg_attempts == ws_max_msg_chunks) {
			LM_ERR("Made %u read attempts but message is not complete yet - "
				   "closing connection \n",con->msg_attempts);
			goto error;
		}

		if (req == &ws_current_req) {
			/* let's duplicate this - most likely another conn will come in */

			LM_DBG("We didn't manage to read a full request\n");
			newreq = pkg_malloc(sizeof(struct ws_req));
			if (newreq == NULL) {
				LM_ERR("No more mem for dynamic con request buffer\n");
				goto error;
			}

			if (req->tcp.pos != req->tcp.buf) {
				/* we have read some bytes */
				memcpy(newreq->tcp.buf,req->tcp.buf,req->tcp.pos-req->tcp.buf);
				newreq->tcp.pos = newreq->tcp.buf + (req->tcp.pos-req->tcp.buf);
			} else {
				newreq->tcp.pos = newreq->tcp.buf;
			}

			if (req->tcp.start != req->tcp.buf)
				newreq->tcp.start = newreq->tcp.buf +(req->tcp.start-req->tcp.buf);
			else
				newreq->tcp.start = newreq->tcp.buf;

			if (req->tcp.parsed != req->tcp.buf)
				newreq->tcp.parsed =newreq->tcp.buf+(req->tcp.parsed-req->tcp.buf);
			else
				newreq->tcp.parsed = newreq->tcp.buf;

			if (req->tcp.body != 0) {
				newreq->tcp.body = newreq->tcp.buf + (req->tcp.body-req->tcp.buf);
			} else
				newreq->tcp.body = 0;

			newreq->tcp.complete=req->tcp.complete;
			newreq->tcp.has_content_len=req->tcp.has_content_len;
			newreq->tcp.content_len=req->tcp.content_len;
			newreq->tcp.bytes_to_go=req->tcp.bytes_to_go;
			newreq->tcp.error = req->tcp.error;
			newreq->tcp.state = req->tcp.state;

			newreq->op = req->op;
			newreq->mask = req->mask;

			con->con_req = (struct tcp_req *)newreq;
		}
	}

	LM_DBG("ws_read end\n");
done:
	/* connection will be released */
	return size;
error:
	if (ret_code)
		ws_send_close(con, ret_code);
	return -1;
}
