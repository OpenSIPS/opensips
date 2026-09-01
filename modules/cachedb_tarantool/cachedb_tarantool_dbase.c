/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * Module: cachedb_tarantool - High-performance Tarantool 3.x CacheDB driver and IProto client
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "cachedb_tarantool_dbase.h"
#include "msgpuck.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <sys/uio.h>

int tarantool_connect_tout = DEFAULT_CONNECT_TIMEOUT_MS;
int tarantool_query_tout = DEFAULT_QUERY_TIMEOUT_MS;
int tarantool_lazy_connect = 0;
int tarantool_disable_time = DEFAULT_DISABLE_TIME_SEC;
int tarantool_allowed_errors = DEFAULT_ALLOWED_ERRORS;
int tarantool_init_without_tnt = 1;
int tarantool_pool_size = DEFAULT_POOL_SIZE;
int tarantool_tcp_keepalive = 1;

static void finalize_packet(char *buf, size_t total_len);
static int resolve_space_id(tnt_cluster_con_t *tcon, tnt_single_conn_t *conn);
static int tnt_connect_single(tnt_cluster_con_t *tcon, tnt_single_conn_t *conn);

/* --- CERT C MSC06-C Secure Memory Zeroing --- */

static void tnt_memzero_explicit(void *ptr, size_t len)
{
	if (!ptr || len == 0)
		return;
	memset(ptr, 0, len);
#if defined(__GNUC__) || defined(__clang__)
	__asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
}

/* --- Embedded RFC 3174 SHA-1 Implementation --- */

typedef struct {
	uint32_t state[5];
	uint32_t count[2];
	unsigned char buffer[64];
} tnt_sha1_ctx_t;

#define TNT_SHA1_ROL(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

static void tnt_sha1_transform(uint32_t state[5], const unsigned char buffer[64])
{
	uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];
	uint32_t block[80];
	int i;

	for (i = 0; i < 16; i++) {
		block[i] = ((uint32_t)buffer[i * 4] << 24) |
			   ((uint32_t)buffer[i * 4 + 1] << 16) |
			   ((uint32_t)buffer[i * 4 + 2] << 8) |
			   ((uint32_t)buffer[i * 4 + 3]);
	}
	for (i = 16; i < 80; i++) {
		block[i] = TNT_SHA1_ROL(block[i - 3] ^ block[i - 8] ^ block[i - 14] ^ block[i - 16], 1);
	}

	for (i = 0; i < 20; i++) {
		uint32_t temp = TNT_SHA1_ROL(a, 5) + ((b & c) | ((~b) & d)) + e + block[i] + 0x5a827999;
		e = d; d = c; c = TNT_SHA1_ROL(b, 30); b = a; a = temp;
	}
	for (i = 20; i < 40; i++) {
		uint32_t temp = TNT_SHA1_ROL(a, 5) + (b ^ c ^ d) + e + block[i] + 0x6ed9eba1;
		e = d; d = c; c = TNT_SHA1_ROL(b, 30); b = a; a = temp;
	}
	for (i = 40; i < 60; i++) {
		uint32_t temp = TNT_SHA1_ROL(a, 5) + ((b & c) | (b & d) | (c & d)) + e + block[i] + 0x8f1bbcdc;
		e = d; d = c; c = TNT_SHA1_ROL(b, 30); b = a; a = temp;
	}
	for (i = 60; i < 80; i++) {
		uint32_t temp = TNT_SHA1_ROL(a, 5) + (b ^ c ^ d) + e + block[i] + 0xca62c1d6;
		e = d; d = c; c = TNT_SHA1_ROL(b, 30); b = a; a = temp;
	}

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
}

static void tnt_sha1_init(tnt_sha1_ctx_t *context)
{
	context->state[0] = 0x67452301;
	context->state[1] = 0xefcdab89;
	context->state[2] = 0x98badcfe;
	context->state[3] = 0x10325476;
	context->state[4] = 0xc3d2e1f0;
	context->count[0] = 0;
	context->count[1] = 0;
}

static void tnt_sha1_update(tnt_sha1_ctx_t *context, const unsigned char *data, uint32_t len)
{
	uint32_t i, j;

	j = (context->count[0] >> 3) & 63;
	if ((context->count[0] += len << 3) < (len << 3))
		context->count[1]++;
	context->count[1] += (len >> 29);

	if ((j + len) > 63) {
		memcpy(&context->buffer[j], data, (size_t)(i = 64 - j));
		tnt_sha1_transform(context->state, context->buffer);
		for (; i + 63 < len; i += 64) {
			tnt_sha1_transform(context->state, &data[i]);
		}
		j = 0;
	} else {
		i = 0;
	}
	memcpy(&context->buffer[j], &data[i], (size_t)(len - i));
}

static void tnt_sha1_final(unsigned char digest[20], tnt_sha1_ctx_t *context)
{
	uint32_t i;
	unsigned char finalcount[8];

	for (i = 0; i < 8; i++) {
		finalcount[i] = (unsigned char)((context->count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255);
	}
	tnt_sha1_update(context, (const unsigned char *)"\200", 1);
	while ((context->count[0] & 504) != 448) {
		tnt_sha1_update(context, (const unsigned char *)"\0", 1);
	}
	tnt_sha1_update(context, finalcount, 8);
	for (i = 0; i < 20; i++) {
		digest[i] = (unsigned char)((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
	}
	tnt_memzero_explicit(context, sizeof(*context));
}

static void tnt_sha1(const unsigned char *data, uint32_t len, unsigned char digest[20])
{
	tnt_sha1_ctx_t ctx;
	tnt_sha1_init(&ctx);
	tnt_sha1_update(&ctx, data, len);
	tnt_sha1_final(digest, &ctx);
}

/* --- Embedded RFC 4648 Base64 Decoder --- */

static const int8_t tnt_b64_table[256] = {
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
	52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
	-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
	15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
	-1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
	41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
};

static int tnt_base64_decode(const char *src, size_t slen, unsigned char *dst, size_t dlen)
{
	size_t i = 0, j = 0;
	uint32_t buf = 0;
	int bits = 0;

	for (i = 0; i < slen && src[i] && src[i] != '='; i++) {
		int val = tnt_b64_table[(unsigned char)src[i]];
		if (val < 0)
			continue;
		buf = (buf << 6) | (uint32_t)val;
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			if (j < dlen)
				dst[j++] = (unsigned char)((buf >> bits) & 0xff);
		}
	}
	return (int)j;
}

/* --- Socket Helpers --- */

static int tnt_send_all(int fd, const char *buf, size_t len)
{
	size_t off = 0;
	while (off < len) {
		ssize_t n = send(fd, buf + off, len - off, MSG_NOSIGNAL);
		if (n < 0) {
			if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
				continue;
			return -1;
		}
		off += (size_t)n;
	}
	return 0;
}

static int tnt_writev_all(int fd, struct iovec *iov, int iovcnt)
{
	while (iovcnt > 0) {
		ssize_t n = writev(fd, iov, iovcnt);
		if (n < 0) {
			if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		while (iovcnt > 0 && n >= (ssize_t)iov[0].iov_len) {
			n -= iov[0].iov_len;
			iov++;
			iovcnt--;
		}
		if (n > 0) {
			iov[0].iov_base = (char *)iov[0].iov_base + n;
			iov[0].iov_len -= (size_t)n;
		}
	}
	return 0;
}

static int tnt_recv_all(int fd, char *buf, size_t len)
{
	size_t off = 0;
	while (off < len) {
		ssize_t n = recv(fd, buf + off, len - off, 0);
		if (n < 0) {
			if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		off += (size_t)n;
	}
	return 0;
}

static void tnt_socket_drain(int fd)
{
	char drain_buf[1024];
	if (fd < 0)
		return;
	while (recv(fd, drain_buf, sizeof(drain_buf), MSG_DONTWAIT) > 0) {
		/* Discard pending ACKs */
	}
}

static ssize_t tnt_read_frame(const tnt_single_conn_t *conn, char *dst, size_t cap, char **dyn)
{
	unsigned char pfx[5];
	uint32_t blen;
	char *tgt;

	*dyn = NULL;
	if (tnt_recv_all(conn->sock_fd, (char *)pfx, 5) < 0)
		return -1;
	if (pfx[0] != (unsigned char)MP_UINT32) {
		LM_ERR("Unexpected IProto length tag 0x%02x\n", pfx[0]);
		return -1;
	}
	blen = ((uint32_t)pfx[1] << 24) | ((uint32_t)pfx[2] << 16) |
	       ((uint32_t)pfx[3] << 8) | (uint32_t)pfx[4];
	if (blen == 0 || blen > 16 * 1024 * 1024) {
		LM_ERR("IProto frame length %u out of range\n", blen);
		return -1;
	}
	tgt = dst;
	if ((size_t)blen > cap) {
		tgt = (char *)pkg_malloc(blen);
		if (!tgt)
			return -1;
		*dyn = tgt;
	}
	if (tnt_recv_all(conn->sock_fd, tgt, blen) < 0) {
		if (*dyn) {
			pkg_free(*dyn);
			*dyn = NULL;
		}
		return -1;
	}
	return (ssize_t)blen;
}

static void tnt_conn_error(const tnt_cluster_con_t *tcon, tnt_single_conn_t *conn)
{
	if (conn->sock_fd >= 0) {
		close(conn->sock_fd);
		conn->sock_fd = -1;
	}
	conn->state = TNT_STATE_ERROR;
	conn->consecutive_errors++;
	if (conn->consecutive_errors >= tcon->allowed_errors) {
		conn->state = TNT_STATE_DISABLED;
		conn->disabled_until = time(NULL) + tcon->disable_time_sec;
		LM_WARN("Tarantool connection marked DISABLED for %d seconds\n", tcon->disable_time_sec);
	}
}

static int check_iproto_status(const char *body, size_t len, uint64_t want_sync)
{
	const char *p;
	const char *end;
	uint32_t h_map;
	uint32_t i;

	if (!body || len == 0)
		return -1;

	p = body;
	end = body + len;
	h_map = mp_decode_map(&p);

	for (i = 0; i < h_map && p < end; i++) {
		uint64_t k = mp_decode_uint(&p);
		if (k == IPROTO_REQUEST_TYPE) {
			uint64_t code = mp_decode_uint(&p);
			if (code != IPROTO_OK) {
				LM_ERR("Tarantool IProto returned error code 0x%lx\n", (unsigned long)code);
				return -1;
			}
		} else if (k == IPROTO_SYNC) {
			uint64_t sync = mp_decode_uint(&p);
			if (sync != want_sync) {
				LM_ERR("IProto sync mismatch (got %lu, want %lu)\n",
				       (unsigned long)sync, (unsigned long)want_sync);
				return -2;
			}
		} else {
			mp_next(&p);
		}
	}
	return 0;
}

static int tnt_auth_scramble(const tnt_cluster_con_t *tcon, int sock_fd, const char *salt_b64, size_t salt_b64_len)
{
	unsigned char raw_salt[64];
	int raw_salt_len;
	unsigned char h1[TNT_SHA1_DIGEST_SIZE];
	unsigned char h2[TNT_SHA1_DIGEST_SIZE];
	unsigned char step3_in[TNT_SHA1_DIGEST_SIZE * 2];
	unsigned char h3[TNT_SHA1_DIGEST_SIZE];
	unsigned char scramble[TNT_SHA1_DIGEST_SIZE];
	int j;
	char packet_buf[512];
	char *p = packet_buf + 5;
	uint32_t payload_len;
	char resp_hdr[5] = {0};
	uint32_t resp_len;
	char *resp_body = NULL;
	int rc = -1;

	if (!tcon->user.s || tcon->user.len <= 0 || !tcon->pass.s || tcon->pass.len <= 0)
		return 0;

	raw_salt_len = tnt_base64_decode(salt_b64, salt_b64_len, raw_salt, sizeof(raw_salt));
	if (raw_salt_len < TNT_SHA1_DIGEST_SIZE)
		return -1;

	tnt_sha1((const unsigned char *)tcon->pass.s, (uint32_t)tcon->pass.len, h1);
	tnt_sha1(h1, TNT_SHA1_DIGEST_SIZE, h2);

	memcpy(step3_in, raw_salt, TNT_SHA1_DIGEST_SIZE);
	memcpy(step3_in + TNT_SHA1_DIGEST_SIZE, h2, TNT_SHA1_DIGEST_SIZE);
	tnt_sha1(step3_in, TNT_SHA1_DIGEST_SIZE * 2, h3);

	for (j = 0; j < TNT_SHA1_DIGEST_SIZE; j++)
		scramble[j] = h1[j] ^ h3[j];

	p = mp_encode_map(p, 2);
	p = mp_encode_uint(p, IPROTO_REQUEST_TYPE);
	p = mp_encode_uint(p, IPROTO_AUTH);
	p = mp_encode_uint(p, IPROTO_SYNC);
	p = mp_encode_uint(p, 1);

	p = mp_encode_map(p, 2);
	p = mp_encode_uint(p, IPROTO_USER_NAME);
	p = mp_encode_str(p, tcon->user.s, (uint32_t)tcon->user.len);
	p = mp_encode_uint(p, IPROTO_TUPLE);
	p = mp_encode_array(p, 2);
	p = mp_encode_str(p, "chap-sha1", 9);
	p = mp_encode_bin(p, (const char *)scramble, TNT_SHA1_DIGEST_SIZE);

	payload_len = (uint32_t)(p - (packet_buf + 5));
	packet_buf[0] = (char)MP_UINT32;
	packet_buf[1] = (char)(payload_len >> 24);
	packet_buf[2] = (char)(payload_len >> 16);
	packet_buf[3] = (char)(payload_len >> 8);
	packet_buf[4] = (char)(payload_len);

	if (tnt_send_all(sock_fd, packet_buf, 5 + payload_len) < 0)
		goto out_cleanup;

	if (tnt_recv_all(sock_fd, resp_hdr, 5) < 0 || (uint8_t)resp_hdr[0] != MP_UINT32)
		goto out_cleanup;

	resp_len = ((uint32_t)(uint8_t)resp_hdr[1] << 24) |
		   ((uint32_t)(uint8_t)resp_hdr[2] << 16) |
		   ((uint32_t)(uint8_t)resp_hdr[3] << 8) |
		   ((uint32_t)(uint8_t)resp_hdr[4]);

	if (resp_len == 0 || resp_len > 65536)
		goto out_cleanup;

	resp_body = (char *)calloc(1, resp_len);
	if (!resp_body)
		goto out_cleanup;

	if (tnt_recv_all(sock_fd, resp_body, resp_len) < 0)
		goto out_free;

	if ((uint8_t)resp_body[0] >= 0x80 && (uint8_t)resp_body[1] == 0x00)
		rc = 0;

out_free:
	free(resp_body);
out_cleanup:
	tnt_memzero_explicit(h1, sizeof(h1));
	tnt_memzero_explicit(h2, sizeof(h2));
	tnt_memzero_explicit(h3, sizeof(h3));
	tnt_memzero_explicit(step3_in, sizeof(step3_in));
	tnt_memzero_explicit(scramble, sizeof(scramble));
	tnt_memzero_explicit(raw_salt, sizeof(raw_salt));
	return rc;
}

static int tnt_connect_single(tnt_cluster_con_t *tcon, tnt_single_conn_t *conn)
{
	time_t now;
	int nodelay = 1;
	int buf_size = 1024 * 1024;
	struct timeval tv;
	struct sockaddr_in serv_addr;
	char host_buf[256];
	char port_str[16];
	int host_len;
	char greeting[TNT_GREETING_SIZE];

	if (!tcon || !conn)
		return -1;

	now = time(NULL);
	if (conn->state == TNT_STATE_DISABLED) {
		if (now < conn->disabled_until)
			return -1;
		conn->state = TNT_STATE_DISCONNECTED;
		conn->consecutive_errors = 0;
	}

	if (conn->sock_fd >= 0) {
		close(conn->sock_fd);
		conn->sock_fd = -1;
	}

	conn->sock_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (conn->sock_fd < 0) {
		LM_ERR("Failed to create TCP socket for Tarantool (errno: %d)\n", errno);
		conn->state = TNT_STATE_ERROR;
		return -1;
	}

	setsockopt(conn->sock_fd, IPPROTO_TCP, TCP_NODELAY, (char *)&nodelay, sizeof(nodelay));
#ifdef TCP_QUICKACK
	setsockopt(conn->sock_fd, IPPROTO_TCP, TCP_QUICKACK, (char *)&nodelay, sizeof(nodelay));
#endif
	if (tcon->tcp_keepalive) {
		int optval = 1;
		setsockopt(conn->sock_fd, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval));
	}

	tv.tv_sec = tcon->query_timeout_ms / 1000;
	tv.tv_usec = (suseconds_t)(tcon->query_timeout_ms % 1000) * 1000;
	setsockopt(conn->sock_fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
	setsockopt(conn->sock_fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
	setsockopt(conn->sock_fd, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));
	setsockopt(conn->sock_fd, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));

	host_len = tcon->host.len < (int)sizeof(host_buf) - 1 ? tcon->host.len : (int)sizeof(host_buf) - 1;
	memcpy(host_buf, tcon->host.s, (size_t)host_len);
	host_buf[host_len] = '\0';

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(tcon->port);

	if (inet_pton(AF_INET, host_buf, &serv_addr.sin_addr) <= 0) {
		struct addrinfo hints, *res = NULL;
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		snprintf(port_str, sizeof(port_str), "%d", tcon->port);

		if (getaddrinfo(host_buf, port_str, &hints, &res) != 0 || !res) {
			LM_ERR("Failed to resolve Tarantool host '%s'\n", host_buf);
			close(conn->sock_fd);
			conn->sock_fd = -1;
			conn->state = TNT_STATE_ERROR;
			return -1;
		}
		memcpy(&serv_addr, res->ai_addr, sizeof(serv_addr));
		freeaddrinfo(res);
	}

	if (connect(conn->sock_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		LM_WARN("Failed to connect to Tarantool server %s:%d (errno: %d)\n", host_buf, tcon->port, errno);
		close(conn->sock_fd);
		conn->sock_fd = -1;
		conn->state = TNT_STATE_ERROR;
		conn->consecutive_errors++;
		if (conn->consecutive_errors >= tcon->allowed_errors) {
			conn->state = TNT_STATE_DISABLED;
			conn->disabled_until = now + tcon->disable_time_sec;
			LM_WARN("Tarantool connection marked DISABLED for %d seconds\n", tcon->disable_time_sec);
		}
		return -1;
	}

	if (tnt_recv_all(conn->sock_fd, greeting, sizeof(greeting)) < 0) {
		LM_ERR("Failed to read Tarantool greeting handshake\n");
		close(conn->sock_fd);
		conn->sock_fd = -1;
		conn->state = TNT_STATE_ERROR;
		return -1;
	}

	if (tcon->user.s && tcon->user.len > 0 && tcon->pass.s && tcon->pass.len > 0) {
		if (tnt_auth_scramble(tcon, conn->sock_fd, greeting + 64, 44) < 0) {
			LM_ERR("Failed to authenticate with Tarantool as '%.*s'\n", tcon->user.len, tcon->user.s);
			close(conn->sock_fd);
			conn->sock_fd = -1;
			conn->state = TNT_STATE_ERROR;
			return -1;
		}
	}

	conn->state = TNT_STATE_AUTHENTICATED;
	conn->consecutive_errors = 0;
	conn->last_activity = time(NULL);

	if (tcon->space_id == 0)
		resolve_space_id(tcon, conn);

	return 0;
}

static tnt_single_conn_t *tnt_get_conn(tnt_cluster_con_t *tcon)
{
	int idx;
	tnt_single_conn_t *conn;

	if (!tcon || tcon->pool_size <= 0)
		return NULL;

	pthread_mutex_lock(&tcon->lock);
	idx = tcon->current_idx++;
	if (tcon->current_idx >= tcon->pool_size)
		tcon->current_idx = 0;
	conn = &tcon->conns[idx];
	pthread_mutex_unlock(&tcon->lock);

	if (conn->sock_fd < 0 || conn->state != TNT_STATE_AUTHENTICATED) {
		if (tnt_connect_single(tcon, conn) < 0)
			return NULL;
	}

	tnt_socket_drain(conn->sock_fd);
	return conn;
}

static void finalize_packet(char *buf, size_t total_len)
{
	uint32_t payload_len = (uint32_t)(total_len - 5);
	buf[0] = (char)MP_UINT32;
	buf[1] = (char)(payload_len >> 24);
	buf[2] = (char)(payload_len >> 16);
	buf[3] = (char)(payload_len >> 8);
	buf[4] = (char)(payload_len);
}

static size_t pack_select_header(char *buf, uint64_t sync_id, uint32_t space_id)
{
	char *p = buf + 5;

	p = mp_encode_map(p, 2);
	p = mp_encode_uint(p, IPROTO_REQUEST_TYPE);
	p = mp_encode_uint(p, IPROTO_SELECT);
	p = mp_encode_uint(p, IPROTO_SYNC);
	p = mp_encode_uint(p, sync_id);

	p = mp_encode_map(p, 6);
	p = mp_encode_uint(p, IPROTO_SPACE_ID);
	p = mp_encode_uint(p, space_id);
	p = mp_encode_uint(p, IPROTO_INDEX_ID);
	p = mp_encode_uint(p, 0);
	p = mp_encode_uint(p, IPROTO_LIMIT);
	p = mp_encode_uint(p, 1);
	p = mp_encode_uint(p, IPROTO_OFFSET);
	p = mp_encode_uint(p, 0);
	p = mp_encode_uint(p, IPROTO_ITERATOR);
	p = mp_encode_uint(p, 0);
	p = mp_encode_uint(p, IPROTO_KEY);
	p = mp_encode_array(p, 1);

	return (size_t)(p - buf);
}

static size_t pack_delete_header(char *buf, uint64_t sync_id, uint32_t space_id)
{
	char *p = buf + 5;

	p = mp_encode_map(p, 2);
	p = mp_encode_uint(p, IPROTO_REQUEST_TYPE);
	p = mp_encode_uint(p, IPROTO_DELETE);
	p = mp_encode_uint(p, IPROTO_SYNC);
	p = mp_encode_uint(p, sync_id);

	p = mp_encode_map(p, 3);
	p = mp_encode_uint(p, IPROTO_SPACE_ID);
	p = mp_encode_uint(p, space_id);
	p = mp_encode_uint(p, IPROTO_INDEX_ID);
	p = mp_encode_uint(p, 0);
	p = mp_encode_uint(p, IPROTO_KEY);
	p = mp_encode_array(p, 1);

	return (size_t)(p - buf);
}

static int resolve_space_id(tnt_cluster_con_t *tcon, tnt_single_conn_t *conn)
{
	char buf[512];
	uint64_t sync_id = ++conn->sync_counter;
	char *p = buf + 5;
	size_t len;
	char resp[1024], *dyn = NULL;
	ssize_t blen;
	const char *rptr;
	uint32_t map_size, i;

	p = mp_encode_map(p, 2);
	p = mp_encode_uint(p, IPROTO_REQUEST_TYPE);
	p = mp_encode_uint(p, IPROTO_EVAL);
	p = mp_encode_uint(p, IPROTO_SYNC);
	p = mp_encode_uint(p, sync_id);

	p = mp_encode_map(p, 2);
	p = mp_encode_uint(p, IPROTO_EXPR);
	p = mp_encode_str(p, "return box.space[...].id", 24);
	p = mp_encode_uint(p, IPROTO_TUPLE);
	p = mp_encode_array(p, 1);
	p = mp_encode_str(p, tcon->space.s, (uint32_t)tcon->space.len);

	len = (size_t)(p - buf);
	finalize_packet(buf, len);

	if (tnt_send_all(conn->sock_fd, buf, len) < 0)
		return -1;

	blen = tnt_read_frame(conn, resp, sizeof(resp), &dyn);
	if (blen <= 0)
		return -1;

	rptr = dyn ? dyn : resp;
	map_size = mp_decode_map(&rptr);

	for (i = 0; i < map_size; i++) {
		uint64_t k = mp_decode_uint(&rptr);
		if (k == IPROTO_DATA) {
			uint32_t arr_len = mp_decode_array(&rptr);
			if (arr_len > 0)
				tcon->space_id = (uint32_t)mp_decode_uint(&rptr);
		} else {
			mp_next(&rptr);
		}
	}

	if (dyn)
		pkg_free(dyn);

	if (tcon->space_id == 0)
		tcon->space_id = 512;

	return 0;
}

#ifndef TNT_REAL_OPENSIPS
static int parse_tnt_url(const str *url, tnt_cluster_con_t *tcon)
{
	char *buf;
	char *p;
	char *slash;
	char *at;
	char *colon;

	if (!url || !url->s || url->len <= 0 || !tcon)
		return -1;

	buf = (char *)pkg_malloc(url->len + 1);
	if (!buf)
		return -1;
	memcpy(buf, url->s, (size_t)url->len);
	buf[url->len] = '\0';

	p = buf;
	if (strncmp(p, "tarantool://", 12) == 0) {
		tcon->name.s = pkg_strdup("default");
		tcon->name.len = 7;
		p += 12;
	} else if (strncmp(p, "tarantool:", 10) == 0) {
		char *name_end;
		p += 10;
		name_end = strstr(p, "://");
		if (!name_end) {
			pkg_free(buf);
			return -1;
		}
		*name_end = '\0';
		tcon->name.s = pkg_strdup(p);
		tcon->name.len = (int)strlen(tcon->name.s);
		p = name_end + 3;
	} else {
		pkg_free(buf);
		return -1;
	}

	slash = strchr(p, '/');
	if (slash) {
		*slash = '\0';
		tcon->space.s = pkg_strdup(slash + 1);
		tcon->space.len = (int)strlen(tcon->space.s);
	} else {
		tcon->space.s = pkg_strdup("rtpe_calls");
		tcon->space.len = 10;
	}

	at = strchr(p, '@');
	if (at) {
		*at = '\0';
		colon = strchr(p, ':');
		if (colon) {
			*colon = '\0';
			tcon->user.s = pkg_strdup(p);
			tcon->pass.s = pkg_strdup(colon + 1);
		} else {
			tcon->user.s = pkg_strdup(p);
			tcon->pass.s = pkg_strdup("");
		}
		p = at + 1;
	} else {
		tcon->user.s = pkg_strdup("guest");
		tcon->pass.s = pkg_strdup("");
	}
	tcon->user.len = (int)strlen(tcon->user.s);
	tcon->pass.len = (int)strlen(tcon->pass.s);

	colon = strchr(p, ':');
	if (colon) {
		*colon = '\0';
		tcon->port = atoi(colon + 1);
	} else {
		tcon->port = 3301;
	}
	tcon->host.s = pkg_strdup(p);
	tcon->host.len = (int)strlen(tcon->host.s);

	tcon->space_id = 0;
	tcon->pool_size = tarantool_pool_size > 0 ? tarantool_pool_size : DEFAULT_POOL_SIZE;
	tcon->connect_timeout_ms = tarantool_connect_tout;
	tcon->query_timeout_ms = tarantool_query_tout;
	tcon->disable_time_sec = tarantool_disable_time;
	tcon->allowed_errors = tarantool_allowed_errors;
	tcon->lazy_connect = tarantool_lazy_connect;
	tcon->init_without_tarantool = tarantool_init_without_tnt;
	tcon->tcp_keepalive = tarantool_tcp_keepalive;

	pkg_free(buf);
	return 0;
}
#endif /* !TNT_REAL_OPENSIPS */

static int tnt_setup_pool(tnt_cluster_con_t *tcon)
{
	int i;

	tcon->conns = (tnt_single_conn_t *)pkg_malloc(sizeof(tnt_single_conn_t) * (size_t)tcon->pool_size);
	if (!tcon->conns)
		return -1;

	memset(tcon->conns, 0, sizeof(tnt_single_conn_t) * (size_t)tcon->pool_size);
	for (i = 0; i < tcon->pool_size; i++) {
		tcon->conns[i].sock_fd = -1;
		tcon->conns[i].state = TNT_STATE_DISCONNECTED;
	}

	pthread_mutex_init(&tcon->lock, NULL);
	tcon->owner_pid = getpid();

	if (!tcon->lazy_connect) {
		for (i = 0; i < tcon->pool_size; i++) {
			tnt_connect_single(tcon, &tcon->conns[i]);
		}
	}
	return 0;
}

static void tnt_teardown(tnt_cluster_con_t *tcon)
{
	if (!tcon)
		return;

	pthread_mutex_lock(&tcon->lock);
	if (tcon->conns) {
		int i;
		for (i = 0; i < tcon->pool_size; i++) {
			if (tcon->conns[i].sock_fd >= 0)
				close(tcon->conns[i].sock_fd);
		}
		pkg_free(tcon->conns);
	}
	pthread_mutex_unlock(&tcon->lock);
	pthread_mutex_destroy(&tcon->lock);

	if (tcon->name.s) pkg_free(tcon->name.s);
	if (tcon->host.s) pkg_free(tcon->host.s);
	if (tcon->user.s) {
		tnt_memzero_explicit(tcon->user.s, (size_t)tcon->user.len);
		pkg_free(tcon->user.s);
	}
	if (tcon->pass.s) {
		tnt_memzero_explicit(tcon->pass.s, (size_t)tcon->pass.len);
		pkg_free(tcon->pass.s);
	}
	if (tcon->space.s) pkg_free(tcon->space.s);
	pkg_free(tcon);
}

#ifdef TNT_REAL_OPENSIPS

static tnt_cluster_con_t *tnt_new_connection(struct cachedb_id *id)
{
	tnt_cluster_con_t *tcon;

	if (!id || !id->host) {
		LM_ERR("no host in Tarantool URL\n");
		return NULL;
	}

	tcon = (tnt_cluster_con_t *)pkg_malloc(sizeof(tnt_cluster_con_t));
	if (!tcon) {
		LM_ERR("Out of memory allocating Tarantool cluster connection\n");
		return NULL;
	}
	memset(tcon, 0, sizeof(tnt_cluster_con_t));
	tcon->cache_con.id = id;
	tcon->cache_con.ref = 1;

	tcon->name.s = pkg_strdup(id->group_name ? id->group_name : "default");
	tcon->host.s = pkg_strdup(id->host);
	tcon->user.s = pkg_strdup(id->username ? id->username : "guest");
	tcon->pass.s = pkg_strdup(id->password ? id->password : "");
	tcon->space.s = pkg_strdup(id->database ? id->database : "rtpe_calls");
	if (!tcon->name.s || !tcon->host.s || !tcon->user.s || !tcon->pass.s || !tcon->space.s) {
		LM_ERR("Out of memory duplicating Tarantool URL parts\n");
		goto error;
	}
	tcon->name.len = (int)strlen(tcon->name.s);
	tcon->host.len = (int)strlen(tcon->host.s);
	tcon->user.len = (int)strlen(tcon->user.s);
	tcon->pass.len = (int)strlen(tcon->pass.s);
	tcon->space.len = (int)strlen(tcon->space.s);

	tcon->port = id->port ? id->port : 3301;
	tcon->space_id = 0;

	tcon->pool_size = tarantool_pool_size > 0 ? tarantool_pool_size : DEFAULT_POOL_SIZE;
	tcon->connect_timeout_ms = tarantool_connect_tout;
	tcon->query_timeout_ms = tarantool_query_tout;
	tcon->disable_time_sec = tarantool_disable_time;
	tcon->allowed_errors = tarantool_allowed_errors;
	tcon->lazy_connect = tarantool_lazy_connect;
	tcon->init_without_tarantool = tarantool_init_without_tnt;
	tcon->tcp_keepalive = tarantool_tcp_keepalive;

	if (tnt_setup_pool(tcon) < 0)
		goto error;

	return tcon;

error:
	if (tcon->name.s) pkg_free(tcon->name.s);
	if (tcon->host.s) pkg_free(tcon->host.s);
	if (tcon->user.s) pkg_free(tcon->user.s);
	if (tcon->pass.s) pkg_free(tcon->pass.s);
	if (tcon->space.s) pkg_free(tcon->space.s);
	pkg_free(tcon);
	return NULL;
}

cachedb_con *tarantool_init(const str *url)
{
	return cachedb_do_init((str *)url, (void *)tnt_new_connection);
}

static void tnt_free_connection(cachedb_pool_con *cpc)
{
	if (!cpc)
		return;
	tnt_teardown((tnt_cluster_con_t *)cpc);
}

void tarantool_destroy(cachedb_con *con)
{
	cachedb_do_close(con, tnt_free_connection);
}

#else /* standalone / mock build */

cachedb_con *tarantool_init(const str *url)
{
	tnt_cluster_con_t *tcon;

	if (!url)
		return NULL;

	tcon = (tnt_cluster_con_t *)pkg_malloc(sizeof(tnt_cluster_con_t));
	if (!tcon) {
		LM_ERR("Out of memory allocating Tarantool cluster connection\n");
		return NULL;
	}
	memset(tcon, 0, sizeof(tnt_cluster_con_t));

	if (parse_tnt_url(url, tcon) != 0) {
		LM_ERR("Failed to parse Tarantool URL '%.*s'\n", url->len, url->s);
		pkg_free(tcon);
		return NULL;
	}

	if (tnt_setup_pool(tcon) < 0) {
		pkg_free(tcon);
		return NULL;
	}

	return (cachedb_con *)tcon;
}

void tarantool_destroy(cachedb_con *con)
{
	if (!con)
		return;
	tnt_teardown((tnt_cluster_con_t *)con);
}

#endif /* !TNT_REAL_OPENSIPS */

int tarantool_get(cachedb_con *con, const str *attr, str *val)
{
	tnt_cluster_con_t *tcon = (tnt_cluster_con_t *)con;
	tnt_single_conn_t *c;
	char buf[1024];
	uint64_t sync_id;
	size_t len;
	char *p;
	char resp[4096], *dyn = NULL;
	ssize_t blen;
	int rc;
	const char *rptr;
	uint32_t i;

	if (!tcon || !attr || !val)
		return -1;

	c = tnt_get_conn(tcon);
	if (!c)
		return -1;

	sync_id = ++c->sync_counter;
	len = pack_select_header(buf, sync_id, tcon->space_id);
	p = buf + len;
	p = mp_encode_str(p, attr->s, (uint32_t)attr->len);
	len = (size_t)(p - buf);
	finalize_packet(buf, len);

	if (tnt_send_all(c->sock_fd, buf, len) < 0) {
		tnt_conn_error(tcon, c);
		return -1;
	}

	blen = tnt_read_frame(c, resp, sizeof(resp), &dyn);
	if (blen <= 0) {
		tnt_conn_error(tcon, c);
		return -1;
	}

	rc = check_iproto_status(dyn ? dyn : resp, (size_t)blen, sync_id);
	if (rc < 0) {
		if (dyn) pkg_free(dyn);
		if (rc == -2) tnt_conn_error(tcon, c);
		return -1;
	}

	rptr = dyn ? dyn : resp;
	uint32_t header_map = mp_decode_map(&rptr);
	for (i = 0; i < header_map; i++) {
		mp_decode_uint(&rptr);
		mp_next(&rptr);
	}

	uint32_t body_map = mp_decode_map(&rptr);
	val->s = NULL;
	val->len = 0;

	for (i = 0; i < body_map; i++) {
		uint64_t k = mp_decode_uint(&rptr);
		if (k == IPROTO_DATA) {
			uint32_t arr_len = mp_decode_array(&rptr);
			if (arr_len > 0) {
				uint32_t tuple_len = mp_decode_array(&rptr);
				const char *vstr = NULL;
				uint32_t vlen = 0;
				uint32_t dummy_len = 0;

				if (tuple_len >= 7) {
					mp_decode_str(&rptr, &dummy_len); /* 1. call_id */
					mp_decode_str(&rptr, &dummy_len); /* 2. node_id */
					mp_decode_str(&rptr, &dummy_len); /* 3. state */
					mp_decode_uint(&rptr);            /* 4. created_at */
					mp_decode_uint(&rptr);            /* 5. updated_at */
					mp_decode_uint(&rptr);            /* 6. expires_at */
					vstr = mp_decode_str(&rptr, &vlen);/* 7. payload */
				} else if (tuple_len >= 2) {
					mp_decode_str(&rptr, &dummy_len);
					vstr = mp_decode_str(&rptr, &vlen);
				}

				if (vstr) {
					val->s = (char *)pkg_malloc(vlen + 1);
					if (val->s) {
						memcpy(val->s, vstr, vlen);
						val->s[vlen] = '\0';
						val->len = (int)vlen;
					}
				}
			}
		} else {
			mp_next(&rptr);
		}
	}

	if (dyn) pkg_free(dyn);
	return val->s ? 0 : -2;
}

int tarantool_get_buf(cachedb_con *con, const str *attr, char *buf, unsigned int buflen, unsigned int *vlen, unsigned int *needed)
{
	str val = {0, 0};
	int rc = tarantool_get(con, attr, &val);
	if (rc == 0 && val.s) {
		if ((unsigned int)val.len > buflen) {
			if (needed) *needed = (unsigned int)val.len;
			pkg_free(val.s);
			return -3;
		}
		memcpy(buf, val.s, (size_t)val.len);
		if (vlen) *vlen = (unsigned int)val.len;
		pkg_free(val.s);
		return 0;
	}
	return rc;
}

int tarantool_set(cachedb_con *con, const str *attr, const str *val, int expires)
{
	tnt_cluster_con_t *tcon = (tnt_cluster_con_t *)con;
	tnt_single_conn_t *c;
	char hdr_buf[256];
	char *p;
	uint64_t sync_id;
	size_t hdr_len;
	struct iovec iov[4];
	char resp[512], *dyn = NULL;
	ssize_t blen;
	int rc;
	time_t now;
	uint64_t exp;

	if (!tcon || !attr || !val)
		return -1;

	c = tnt_get_conn(tcon);
	if (!c)
		return -1;

	now = time(NULL);
	exp = (expires > 0) ? (uint64_t)(now + expires) : (uint64_t)(now + 3600);
	sync_id = ++c->sync_counter;
	p = hdr_buf + 5;

	p = mp_encode_map(p, 2);
	p = mp_encode_uint(p, IPROTO_REQUEST_TYPE);
	p = mp_encode_uint(p, IPROTO_REPLACE);
	p = mp_encode_uint(p, IPROTO_SYNC);
	p = mp_encode_uint(p, sync_id);

	p = mp_encode_map(p, 2);
	p = mp_encode_uint(p, IPROTO_SPACE_ID);
	p = mp_encode_uint(p, tcon->space_id);
	p = mp_encode_uint(p, IPROTO_TUPLE);
	p = mp_encode_array(p, 7);
	p = mp_encode_str(p, attr->s, (uint32_t)attr->len);
	p = mp_encode_str(p, "opensips", 8);
	p = mp_encode_str(p, "active", 6);
	p = mp_encode_uint(p, (uint64_t)now);
	p = mp_encode_uint(p, (uint64_t)now);
	p = mp_encode_uint(p, exp);
	p = mp_encode_str(p, val->s, (uint32_t)val->len);

	hdr_len = (size_t)(p - hdr_buf);
	finalize_packet(hdr_buf, hdr_len);

	iov[0].iov_base = hdr_buf;
	iov[0].iov_len  = hdr_len;

	if (tnt_writev_all(c->sock_fd, iov, 1) < 0) {
		tnt_conn_error(tcon, c);
		return -1;
	}

	blen = tnt_read_frame(c, resp, sizeof(resp), &dyn);
	if (blen <= 0) {
		tnt_conn_error(tcon, c);
		return -1;
	}

	rc = check_iproto_status(dyn ? dyn : resp, (size_t)blen, sync_id);
	if (dyn) pkg_free(dyn);
	if (rc < 0) {
		if (rc == -2) tnt_conn_error(tcon, c);
		return -1;
	}
	return 0;
}

int tarantool_remove(cachedb_con *con, const str *attr)
{
	tnt_cluster_con_t *tcon = (tnt_cluster_con_t *)con;
	tnt_single_conn_t *c;
	char buf[1024];
	uint64_t sync_id;
	size_t len;
	char *p;
	char resp[512], *dyn = NULL;
	ssize_t blen;
	int rc;

	if (!tcon || !attr)
		return -1;

	c = tnt_get_conn(tcon);
	if (!c)
		return -1;

	sync_id = ++c->sync_counter;
	len = pack_delete_header(buf, sync_id, tcon->space_id);
	p = buf + len;
	p = mp_encode_str(p, attr->s, (uint32_t)attr->len);
	len = (size_t)(p - buf);
	finalize_packet(buf, len);

	if (tnt_send_all(c->sock_fd, buf, len) < 0) {
		tnt_conn_error(tcon, c);
		return -1;
	}

	blen = tnt_read_frame(c, resp, sizeof(resp), &dyn);
	if (blen <= 0) {
		tnt_conn_error(tcon, c);
		return -1;
	}

	rc = check_iproto_status(dyn ? dyn : resp, (size_t)blen, sync_id);
	if (dyn) pkg_free(dyn);
	if (rc < 0) {
		if (rc == -2) tnt_conn_error(tcon, c);
		return -1;
	}
	return 0;
}

int tarantool_raw_query(cachedb_con *con, const str *query, cdb_raw_entry ***reply, int num_cols, int *num_rows)
{
	(void)num_cols;
	tnt_cluster_con_t *tcon = (tnt_cluster_con_t *)con;
	tnt_single_conn_t *c;
	char buf[4096];
	uint64_t sync_id;
	char *p;
	size_t len;
	char resp[4096], *dyn = NULL;
	ssize_t blen;
	int rc;

	if (!tcon || !query)
		return -1;

	c = tnt_get_conn(tcon);
	if (!c)
		return -1;

	sync_id = ++c->sync_counter;
	p = buf + 5;

	p = mp_encode_map(p, 2);
	p = mp_encode_uint(p, IPROTO_REQUEST_TYPE);
	p = mp_encode_uint(p, IPROTO_EVAL);
	p = mp_encode_uint(p, IPROTO_SYNC);
	p = mp_encode_uint(p, sync_id);

	p = mp_encode_map(p, 2);
	p = mp_encode_uint(p, IPROTO_EXPR);
	p = mp_encode_str(p, query->s, (uint32_t)query->len);
	p = mp_encode_uint(p, IPROTO_TUPLE);
	p = mp_encode_array(p, 0);

	len = (size_t)(p - buf);
	finalize_packet(buf, len);

	if (tnt_send_all(c->sock_fd, buf, len) < 0) {
		tnt_conn_error(tcon, c);
		return -1;
	}

	blen = tnt_read_frame(c, resp, sizeof(resp), &dyn);
	if (blen <= 0) {
		tnt_conn_error(tcon, c);
		return -1;
	}

	rc = check_iproto_status(dyn ? dyn : resp, (size_t)blen, sync_id);
	if (dyn) pkg_free(dyn);
	if (rc < 0) {
		if (rc == -2) tnt_conn_error(tcon, c);
		return -1;
	}

	if (reply && num_rows)
		*num_rows = 0;

	return 0;
}

int tarantool_call_proc(tnt_cluster_con_t *tcon, const str *proc, const str *args, str *res)
{
	tnt_single_conn_t *c;
	char buf[4096];
	uint64_t sync_id;
	char *p;
	size_t len;
	char resp[4096], *dyn = NULL;
	ssize_t blen;
	int rc;

	if (!tcon || !proc)
		return -1;

	c = tnt_get_conn(tcon);
	if (!c)
		return -1;

	sync_id = ++c->sync_counter;
	p = buf + 5;

	p = mp_encode_map(p, 2);
	p = mp_encode_uint(p, IPROTO_REQUEST_TYPE);
	p = mp_encode_uint(p, IPROTO_CALL);
	p = mp_encode_uint(p, IPROTO_SYNC);
	p = mp_encode_uint(p, sync_id);

	p = mp_encode_map(p, 2);
	p = mp_encode_uint(p, IPROTO_FUNCTION_NAME);
	p = mp_encode_str(p, proc->s, (uint32_t)proc->len);
	p = mp_encode_uint(p, IPROTO_TUPLE);
	if (args && args->len > 0) {
		p = mp_encode_array(p, 1);
		p = mp_encode_str(p, args->s, (uint32_t)args->len);
	} else {
		p = mp_encode_array(p, 0);
	}

	len = (size_t)(p - buf);
	finalize_packet(buf, len);

	if (tnt_send_all(c->sock_fd, buf, len) < 0) {
		tnt_conn_error(tcon, c);
		return -1;
	}

	blen = tnt_read_frame(c, resp, sizeof(resp), &dyn);
	if (blen <= 0) {
		tnt_conn_error(tcon, c);
		return -1;
	}

	rc = check_iproto_status(dyn ? dyn : resp, (size_t)blen, sync_id);
	if (dyn) pkg_free(dyn);
	if (rc < 0) {
		if (rc == -2) tnt_conn_error(tcon, c);
		return -1;
	}

	if (res) {
		res->s = NULL;
		res->len = 0;
	}
	return 0;
}

int tarantool_eval_expr(tnt_cluster_con_t *tcon, const str *expr, const str *args, str *res)
{
	(void)args;
	(void)res;
	return tarantool_raw_query((cachedb_con *)tcon, expr, NULL, 0, NULL);
}
