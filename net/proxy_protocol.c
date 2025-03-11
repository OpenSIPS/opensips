/*
 * Copyright (C) 2025 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
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
 */

#include <stdlib.h>
#include <string.h>
#include "proxy_protocol.h"
#include "../socket_info.h"
#include "tcp_conn_defs.h"
#include "../ut.h"

#define PROXY_PROTOCOL_V1_HDR "PROXY "
#define PROXY_PROTOCOL_V1_HDR_LEN (sizeof(PROXY_PROTOCOL_V1_HDR) - 1)
#define PROXY_PROTOCOL_TCP4 "TCP4 "
#define PROXY_PROTOCOL_TCP4_LEN (sizeof(PROXY_PROTOCOL_TCP4) - 1)
#define PROXY_PROTOCOL_TCP6 "TCP6 "
#define PROXY_PROTOCOL_TCP6_LEN (sizeof(PROXY_PROTOCOL_TCP6) - 1)
#define PROXY_PROTOCOL_UNKN "UNKNOWN"
#define PROXY_PROTOCOL_UNKN_LEN (sizeof(PROXY_PROTOCOL_UNKN) - 1)
#define PROXY_PROTOCOL_END "\r\n"
#define PROXY_PROTOCOL_END_LEN (sizeof(PROXY_PROTOCOL_END) - 1)
#define PROXY_PROTOCOL_SEP ' '
/*
 * these are defined in the specs:
 * https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
 */
#define PROXY_PROTOCOL_TCP4_MAX 56
#define PROXY_PROTOCOL_TCP4_PAYLOAD_MAX \
	(PROXY_PROTOCOL_TCP4_MAX - PROXY_PROTOCOL_V1_HDR_LEN - PROXY_PROTOCOL_TCP4_LEN)
#define PROXY_PROTOCOL_TCP6_MAX 104
#define PROXY_PROTOCOL_TCP6_PAYLOAD_MAX \
	(PROXY_PROTOCOL_TCP6_MAX - PROXY_PROTOCOL_V1_HDR_LEN - PROXY_PROTOCOL_TCP6_LEN)
#define PROXY_PROTOCOL_UNKN_MAX 107
#define PROXY_PROTOCOL_BUF_MAX PROXY_PROTOCOL_UNKN_MAX
#define PROXY_PROTOCOL_UNKN_PAYLOAD_MAX \
	(PROXY_PROTOCOL_UNKN_MAX - PROXY_PROTOCOL_V1_HDR_LEN - PROXY_PROTOCOL_UNKN_LEN)

enum proxy_tok_match {
	PP_TOK_MISMATCH = -1,
	PP_TOK_PARTIAL = 0,
	PP_TOK_MATCH = 1,
};

static inline enum proxy_tok_match match_proxy_token(const str *buf,
		const char *tok, int tok_len)
{
	int cmp_len;

	cmp_len = (buf->len < tok_len) ? buf->len : tok_len;
	if (strncasecmp(buf->s, tok, cmp_len) != 0)
		return PP_TOK_MISMATCH;
	if (buf->len < tok_len)
		return PP_TOK_PARTIAL;
	return PP_TOK_MATCH;
}

int is_net_proxy_protocol(char *buf, int size)
{
	if (size < PROXY_PROTOCOL_V1_HDR_LEN)
		return -1; /* don't know yet */
	if (memcmp(buf, PROXY_PROTOCOL_V1_HDR, PROXY_PROTOCOL_V1_HDR_LEN))
		return 0;
	/* TODO: support v2 as well? */
	return 1;
}

char *parse_net_proxy_protocol(char *buf, int size, struct proxy_protocol *proxy)
{
	int af, max;
	char *p, *end;
	str _buf, tmp;
	struct ip_addr *ip;
	unsigned int port;
	enum proxy_tok_match m;

	if (size < PROXY_PROTOCOL_V1_HDR_LEN ||
			memcmp(buf, PROXY_PROTOCOL_V1_HDR, PROXY_PROTOCOL_V1_HDR_LEN) != 0)
		goto error;

	_buf.s = buf + PROXY_PROTOCOL_V1_HDR_LEN;
	_buf.len = size - PROXY_PROTOCOL_V1_HDR_LEN;

	m = match_proxy_token(&_buf, PROXY_PROTOCOL_TCP4, PROXY_PROTOCOL_TCP4_LEN);
	if (m == PP_TOK_MATCH) {
		af = AF_INET;
		_buf.s += PROXY_PROTOCOL_TCP4_LEN;
		_buf.len -= PROXY_PROTOCOL_TCP4_LEN;
		if (_buf.len > PROXY_PROTOCOL_TCP4_PAYLOAD_MAX)
			_buf.len = PROXY_PROTOCOL_TCP4_PAYLOAD_MAX;
		max = PROXY_PROTOCOL_TCP4_MAX;
	} else if (m == PP_TOK_PARTIAL) {
		return NULL;
	} else {
		m = match_proxy_token(&_buf, PROXY_PROTOCOL_TCP6, PROXY_PROTOCOL_TCP6_LEN);
		if (m == PP_TOK_MATCH) {
			af = AF_INET6;
			_buf.s += PROXY_PROTOCOL_TCP6_LEN;
			_buf.len -= PROXY_PROTOCOL_TCP6_LEN;
			if (_buf.len > PROXY_PROTOCOL_TCP6_PAYLOAD_MAX)
				_buf.len = PROXY_PROTOCOL_TCP6_PAYLOAD_MAX;
			max = PROXY_PROTOCOL_TCP6_MAX;
		} else if (m == PP_TOK_PARTIAL) {
			return NULL;
		} else {
			m = match_proxy_token(&_buf, PROXY_PROTOCOL_UNKN, PROXY_PROTOCOL_UNKN_LEN);
			if (m == PP_TOK_MATCH) {
				_buf.s += PROXY_PROTOCOL_UNKN_LEN;
				_buf.len -= PROXY_PROTOCOL_UNKN_LEN;
				if (_buf.len == 0)
					return NULL;
				if (_buf.s[0] != PROXY_PROTOCOL_SEP &&
						_buf.s[0] != PROXY_PROTOCOL_END[0]) {
					LM_DBG("bad separator after proxy_protocol UNKNOWN: 0x%x\n",
							(unsigned char)_buf.s[0]);
					goto error;
				}
				if (_buf.len > PROXY_PROTOCOL_UNKN_PAYLOAD_MAX)
					_buf.len = PROXY_PROTOCOL_UNKN_PAYLOAD_MAX;
				af = AF_UNSPEC;
				max = PROXY_PROTOCOL_UNKN_MAX;
			} else if (m == PP_TOK_PARTIAL) {
				return NULL;
			} else {
				LM_DBG("unknown proxy_protocol proto [%.*s]\n", _buf.len, _buf.s);
				goto error;
			}
		}
	}

	/* search for the end within the maximum payload */
	end = str_strstr(&_buf, _str(PROXY_PROTOCOL_END));
	if (!end) {
		if (size < max) /* we still don't have enough data to find the end */
			return NULL;
		LM_DBG("could not find proxy_protocol end in [%.*s]\n",
				_buf.len, _buf.s);
		goto error;
	}
	if (af == AF_UNSPEC) {
		/* we have an unknown protocol - stop it here */
		proxy->flags = PP_UNKNOWN;
		return end + PROXY_PROTOCOL_END_LEN;
	}
	_buf.len = end - _buf.s;
	/* src ip */
	p = q_memchr(_buf.s, PROXY_PROTOCOL_SEP, _buf.len);
	if (!p)
		goto error;
	tmp.s = _buf.s;
	tmp.len = p - _buf.s;
	ip = (af == AF_INET?str2ip(&tmp):str2ip6(&tmp));
	if (!ip) {
		LM_DBG("could not parse proxy_protocol src ip %.*s for af %d\n",
				tmp.len, tmp.s, af);
		goto error;
	}
	memcpy(&proxy->src_ip, ip, sizeof *ip);
	_buf.len -= tmp.len + 1;
	_buf.s = p + 1;

	/* dst ip */
	p = q_memchr(_buf.s, PROXY_PROTOCOL_SEP, _buf.len);
	if (!p)
		goto error;
	tmp.s = _buf.s;
	tmp.len = p - _buf.s;
	ip = (af == AF_INET?str2ip(&tmp):str2ip6(&tmp));
	if (!ip) {
		LM_DBG("could not parse proxy_protocol dst ip %.*s for af %d\n",
				tmp.len, tmp.s, af);
		goto error;
	}
	memcpy(&proxy->dst_ip, ip, sizeof *ip);
	_buf.len -= tmp.len + 1;
	_buf.s = p + 1;

	/* src port */
	p = q_memchr(_buf.s, PROXY_PROTOCOL_SEP, _buf.len);
	if (!p)
		goto error;
	tmp.s = _buf.s;
	tmp.len = p - _buf.s;
	if (str2int(&tmp, &port) < 0) {
		LM_DBG("could not parse proxy_protocol src port %.*s\n", tmp.len, tmp.s);
		goto error;
	}
	if (port > 65535) {
		LM_DBG("bad proxy_protocol src port %d\n", port);
		goto error;
	}
	proxy->src_port = port;
	_buf.len -= tmp.len + 1;
	_buf.s = p + 1;

	/* dst port */
	/* remaining should be just the dst port */
	if (str2int(&_buf, &port) < 0) {
		LM_DBG("could not parse proxy_protocol dst port %.*s\n", _buf.len, _buf.s);
		goto error;
	}
	if (port > 65535) {
		LM_DBG("bad proxy_protocol dst port %d\n", port);
		goto error;
	}
	proxy->dst_port = port;
	proxy->flags = PP_OK;
	return end + PROXY_PROTOCOL_END_LEN;
error:
	proxy->flags = PP_ERROR;
	return NULL;
}

static int tcp_peek(struct tcp_connection *c, char *buf, int len)
{
	int bytes_read;
	int fd;

	fd=c->fd;
again:
	bytes_read=recv(fd, buf, len, MSG_PEEK);

	if(bytes_read==-1){
		if (errno == EWOULDBLOCK || errno == EAGAIN){
			return 0; /* nothing has been read */
		} else if (errno == EINTR) {
			goto again;
		} else if (errno == ECONNRESET) {
			c->state=S_CONN_EOF;
			LM_DBG("CONN RESET on %p, FD %d\n", c, fd);
			return -1;
		} else {
			LM_ERR("error reading: %s\n",strerror(errno));
			return -1;
		}
	}else if (bytes_read==0){
		c->state=S_CONN_EOF;
		LM_DBG("EOF on %p, FD %d\n", c, fd);
		return -1;
	}
#ifdef EXTRA_DEBUG
	LM_DBG("peek %d bytes:\n%.*s\n", bytes_read, bytes_read, buf);
#endif
	return bytes_read;
}

static int tcp_drain(struct tcp_connection *c, char *buf, int len)
{
	int bytes_read, total = 0;
	int retries = 0;
	int fd = c->fd;
again:
	bytes_read = read(fd, buf + total, len - total);
	if (bytes_read < 0) {
		if (errno == EINTR) {
			goto again;
		} else if (errno == EAGAIN || errno == EWOULDBLOCK) {
			if (++retries > 100) {
				LM_ERR("failed consuming proxy_protocol header due to repeated EAGAIN\n");
				return -1;
			}
			goto again;
		} else {
			LM_ERR("error consuming proxy_protocol header: %s\n", strerror(errno));
			return -1;
		}
	} else if (bytes_read == 0) {
		c->state = S_CONN_EOF;
		LM_DBG("EOF on %p, FD %d while consuming proxy_protocol header\n", c, fd);
		return -1;
	}
	total += bytes_read;
	retries = 0;
	if (total < len)
		goto again;

	return total;
}

int check_tcp_proxy_protocol(struct tcp_connection *c)
{
	static char pp_buf[PROXY_PROTOCOL_BUF_MAX];
	char *p;
	int len;

	if (c->flags & F_CONN_DATA_READY)
		return 1;

	len = tcp_peek(c, pp_buf, PROXY_PROTOCOL_BUF_MAX);
	if (len < 0)
		return len;

	switch (is_net_proxy_protocol(pp_buf, len)) {
		case -1:
			return 0;
		case 0:
			c->flags |= F_CONN_DATA_READY;
			return 1;
		default:
			/* parse proxy_protocol fields */
			break;
	}

	p = parse_net_proxy_protocol(pp_buf, len, &c->rcv.real_ep);
	if (!p) {
		if (c->rcv.real_ep.flags == PP_ERROR) {
			LM_ERR("could not parse proxy_protocol header\n");
			return -1;
		}
		return 0;
	}
	if (c->rcv.real_ep.flags == PP_OK) {
		LM_DBG("message proxy_protocol %s:%hu -> %s:%hu\n",
				ip_addr2a(&c->rcv.real_ep.src_ip), c->rcv.real_ep.src_port,
				ip_addr2a(&c->rcv.real_ep.dst_ip), c->rcv.real_ep.dst_port);
	} else {
		LM_DBG("message proxy_protocol UNKNOWN\n");
	}

	if (tcp_drain(c, pp_buf, p - pp_buf) < 0) {
		LM_ERR("could not consume PROXY header\n");
		return -1;
	}

	c->flags |= F_CONN_DATA_READY;
	return 1;
}

int check_udp_proxy_protocol(char **buf, int *size, struct receive_info *ri)
{
	char *p, *msg;
	int len;

	if (!buf || !*buf || !size || !ri)
		return -1;

	ri->real_ep.flags = PP_INIT;
	msg = *buf;
	len = *size;

	switch (is_net_proxy_protocol(msg, len)) {
	case -1:
	case 0:
		return 1;
	default:
		break;
	}

	p = parse_net_proxy_protocol(msg, len, &ri->real_ep);
	if (!p) {
		if (ri->real_ep.flags == PP_ERROR) {
			LM_ERR("could not parse proxy_protocol header\n");
		} else {
			LM_ERR("incomplete proxy_protocol header in UDP packet\n");
		}
		return -1;
	}

	if (ri->real_ep.flags == PP_OK) {
		LM_DBG("message proxy_protocol %s:%hu -> %s:%hu\n",
				ip_addr2a(&ri->real_ep.src_ip), ri->real_ep.src_port,
				ip_addr2a(&ri->real_ep.dst_ip), ri->real_ep.dst_port);
	} else {
		LM_DBG("message proxy_protocol UNKNOWN\n");
	}

	*size -= p - msg;
	*buf = p;
	return 1;
}
