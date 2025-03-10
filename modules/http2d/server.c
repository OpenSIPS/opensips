/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2013 Tatsuhiro Tsujikawa
 * Copyright (c) 2024 OpenSIPS Solutions
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include "../../ut.h"
#include "../../lib/list.h"
#include "../../lib/cJSON.h"

#include "server.h"
#include "h2_evi.h"

extern unsigned int max_headers_size;

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <sys/types.h>
#ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif /* HAVE_SYS_SOCKET_H */
#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif /* HAVE_NETDB_H */
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif /* HAVE_NETINET_IN_H */
#include <netinet/tcp.h>
#include <string.h>
#include <errno.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>

#include <event.h>
#include <event2/event.h>
#include <event2/bufferevent_ssl.h>
#include <event2/listener.h>

#define NGHTTP2_NO_SSIZE_T

#define OUTPUT_WOULDBLOCK_THRESHOLD (1 << 16)

#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))

#define MAKE_NV(NAME, VALUE)                                                   \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1,    \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

struct app_context;
typedef struct app_context app_context;

typedef struct http2_stream_data {
	int32_t stream_id;

	char *method;
	char *path;
	cJSON *hdrs;
	unsigned hdrs_len;
	str data;
	int fd;

	struct list_head list;
} http2_stream_data;

typedef struct http2_session_data {
	struct list_head root;
	struct bufferevent *bev;
	app_context *app_ctx;
	nghttp2_session *session;
	char *client_addr;
} http2_session_data;

struct app_context {
	SSL_CTX *ssl_ctx;
	struct event_base *evbase;
};

static int alpn_select_proto_cb(SSL *ssl, const unsigned char **out,
                                unsigned char *outlen, const unsigned char *in,
                                unsigned int inlen, void *arg) {
	int rv;
	(void)ssl;
	(void)arg;

	rv = nghttp2_select_alpn(out, outlen, in, inlen);

	if (rv != 1)
		return SSL_TLSEXT_ERR_NOACK;

  return SSL_TLSEXT_ERR_OK;
}

/* Create SSL_CTX. */
static SSL_CTX *create_ssl_ctx(const char *key_file, const char *cert_file) {
	SSL_CTX *ssl_ctx;

	ssl_ctx = SSL_CTX_new(TLS_server_method());
	if (!ssl_ctx) {
		LM_ERR("Could not create SSL/TLS context: %s\n",
		     ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}
	SSL_CTX_set_options(ssl_ctx,
	                  SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
	                      SSL_OP_NO_COMPRESSION |
	                      SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	if (SSL_CTX_set1_curves_list(ssl_ctx, "P-256") != 1) {
		LM_ERR("SSL_CTX_set1_curves_list failed: %s\n",
		      ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}
#else  /* !(OPENSSL_VERSION_NUMBER >= 0x30000000L) */
	{
		EC_KEY *ecdh;
		ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
		if (!ecdh) {
			LM_ERR("EC_KEY_new_by_curv_name failed: %s\n",
			     ERR_error_string(ERR_get_error(), NULL));
			return NULL;
		}
		SSL_CTX_set_tmp_ecdh(ssl_ctx, ecdh);
		EC_KEY_free(ecdh);
	}
#endif /* !(OPENSSL_VERSION_NUMBER >= 0x30000000L) */

	if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key_file, SSL_FILETYPE_PEM) != 1) {
		LM_ERR("Could not read private key file %s\n", key_file);
		return NULL;
	}
	if (SSL_CTX_use_certificate_chain_file(ssl_ctx, cert_file) != 1) {
		LM_ERR("Could not read certificate file %s\n", cert_file);
		return NULL;
	}

	SSL_CTX_set_alpn_select_cb(ssl_ctx, alpn_select_proto_cb, NULL);

	return ssl_ctx;
}

/* Create SSL object */
static SSL *create_ssl(SSL_CTX *ssl_ctx) {
	SSL *ssl;
	ssl = SSL_new(ssl_ctx);
	if (!ssl) {
		LM_ERR("Could not create SSL/TLS session object: %s\n",
		     ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}
	return ssl;
}

static void add_stream(http2_session_data *session_data,
                       http2_stream_data *stream_data) {
	list_add(&stream_data->list, &session_data->root);
}

static void remove_stream(http2_session_data *session_data,
                          http2_stream_data *stream_data) {
	(void)session_data;
	list_del(&stream_data->list);
}

static http2_stream_data *
create_http2_stream_data(http2_session_data *session_data, int32_t stream_id) {
	http2_stream_data *stream_data;

	stream_data = pkg_malloc(sizeof *stream_data);
	if (!stream_data) {
		LM_ERR("oom\n");
		return NULL;
	}

	memset(stream_data, 0, sizeof *stream_data);
	stream_data->stream_id = stream_id;
	stream_data->hdrs = cJSON_CreateObject();
	if (!stream_data->hdrs) {
		pkg_free(stream_data);
		LM_ERR("oom\n");
		return NULL;
	}

	stream_data->fd = -1;

	add_stream(session_data, stream_data);
	return stream_data;
}

static void delete_http2_stream_data(http2_stream_data *stream_data) {
	if (stream_data->fd != -1)
		close(stream_data->fd);

	free(stream_data->path);
	cJSON_Delete(stream_data->hdrs);
	pkg_free(stream_data->data.s);
	pkg_free(stream_data);
}

static http2_session_data *create_http2_session_data(app_context *app_ctx,
                                                     int fd,
                                                     struct sockaddr *addr,
                                                     int addrlen) {
	int rv;
	http2_session_data *session_data;
	SSL *ssl;
	char host[NI_MAXHOST];
	int val = 1;

	ssl = create_ssl(app_ctx->ssl_ctx);
	session_data = malloc(sizeof *session_data);
	memset(session_data, 0, sizeof *session_data);
	INIT_LIST_HEAD(&session_data->root);

	session_data->app_ctx = app_ctx;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&val, sizeof(val));
	session_data->bev = bufferevent_openssl_socket_new(
	    app_ctx->evbase, fd, ssl, BUFFEREVENT_SSL_ACCEPTING,
	    BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	bufferevent_enable(session_data->bev, EV_READ | EV_WRITE);
	rv = getnameinfo(addr, (socklen_t)addrlen, host, sizeof(host), NULL, 0,
	                 NI_NUMERICHOST);
	if (rv != 0) {
		session_data->client_addr = strdup("(unknown)");
	} else {
		session_data->client_addr = strdup(host);
	}

	return session_data;
}

static void delete_http2_session_data(http2_session_data *session_data) {
	http2_stream_data *stream_data;
	SSL *ssl = bufferevent_openssl_get_ssl(session_data->bev);
	struct list_head *it, *aux;

	LM_INFO("%s disconnected\n", session_data->client_addr);
	if (ssl)
		SSL_shutdown(ssl);
	bufferevent_free(session_data->bev);
	nghttp2_session_del(session_data->session);

	list_for_each_safe (it, aux, &session_data->root) {
		stream_data = list_entry(it, http2_stream_data, list);

		list_del(&stream_data->list);
		delete_http2_stream_data(stream_data);
	}

	free(session_data->client_addr);
	free(session_data);
}

/* Serialize the frame and send (or buffer) the data to
   bufferevent. */
static int session_send(http2_session_data *session_data) {
	int rv;
	rv = nghttp2_session_send(session_data->session);
	if (rv != 0) {
		LM_WARN("Fatal error: %s", nghttp2_strerror(rv));
		return -1;
	}
	return 0;
}

/* Read the data in the bufferevent and feed them into nghttp2 library
   function. Invocation of nghttp2_session_mem_recv2() may make
   additional pending frames, so call session_send() at the end of the
   function. */
static int session_recv(http2_session_data *session_data) {
	nghttp2_ssize readlen;
	struct evbuffer *input = bufferevent_get_input(session_data->bev);
	size_t datalen = evbuffer_get_length(input);
	unsigned char *data = evbuffer_pullup(input, -1);

	readlen = nghttp2_session_mem_recv2(session_data->session, data, datalen);
	if (readlen < 0) {
		LM_WARN("Fatal error: %s", nghttp2_strerror((int)readlen));
		return -1;
	}
	if (evbuffer_drain(input, (size_t)readlen) != 0) {
		LM_WARN("Fatal error: evbuffer_drain failed");
		return -1;
	}
	if (session_send(session_data) != 0)
		return -1;
	return 0;
}

static nghttp2_ssize send_callback(nghttp2_session *session,
                                   const uint8_t *data, size_t length,
                                   int flags, void *user_data) {
	http2_session_data *session_data = (http2_session_data *)user_data;
	struct bufferevent *bev = session_data->bev;
	(void)session;
	(void)flags;

	/* Avoid excessive buffering in server side. */
	if (evbuffer_get_length(bufferevent_get_output(session_data->bev)) >=
		  OUTPUT_WOULDBLOCK_THRESHOLD) {
		return NGHTTP2_ERR_WOULDBLOCK;
	}

	bufferevent_write(bev, data, length);
	return (nghttp2_ssize)length;
}

/* Returns nonzero if the string |s| ends with the substring |sub| */
static int ends_with(const char *s, const char *sub) {
	size_t slen = strlen(s);
	size_t sublen = strlen(sub);
	if (slen < sublen)
		return 0;
	return memcmp(s + slen - sublen, sub, sublen) == 0;
}

/* Returns int value of hex string character |c| */
static uint8_t hex_to_uint(uint8_t c) {
	if ('0' <= c && c <= '9') {
		return (uint8_t)(c - '0');
	}
	if ('A' <= c && c <= 'F') {
		return (uint8_t)(c - 'A' + 10);
	}
	if ('a' <= c && c <= 'f') {
		return (uint8_t)(c - 'a' + 10);
	}
	return 0;
}

/* Decodes percent-encoded byte string |value| with length |valuelen|
   and returns the decoded byte string in allocated buffer. The return
   value is NULL terminated. The caller must free the returned
   string. */
static char *percent_decode(const uint8_t *value, size_t valuelen) {
	char *res;

	res = malloc(valuelen + 1);
	if (valuelen > 3) {
		size_t i, j;
		for (i = 0, j = 0; i < valuelen - 2;) {
			if (value[i] != '%' || !isxdigit(value[i + 1]) ||
				  !isxdigit(value[i + 2])) {
				res[j++] = (char)value[i++];
				continue;
			}
			res[j++] =
			    (char)((hex_to_uint(value[i + 1]) << 4) + hex_to_uint(value[i + 2]));
			i += 3;
		}
		memcpy(&res[j], &value[i], 2);
		res[j + 2] = '\0';
	} else {
		memcpy(res, value, valuelen);
		res[valuelen] = '\0';
	}
	return res;
}

/* a callback of type "nghttp2_data_source_read_callback2" */
static nghttp2_ssize file_read_callback(nghttp2_session *session,
                                        int32_t stream_id, uint8_t *buf,
                                        size_t length, uint32_t *data_flags,
                                        nghttp2_data_source *source,
                                        void *user_data) {
	int fd = source->fd;
	ssize_t r;
	(void)session;
	(void)stream_id;
	(void)user_data;

	while ((r = read(fd, buf, length)) == -1 && errno == EINTR)
	  ;
	if (r == -1)
		return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;

	if (r == 0)
		*data_flags |= NGHTTP2_DATA_FLAG_EOF;

	return (nghttp2_ssize)r;
}

static int send_response_fd(nghttp2_session *session, int32_t stream_id,
                         nghttp2_nv *nva, size_t nvlen, int fd) {
	int rv;
	nghttp2_data_provider2 data_prd;

	data_prd.source.fd = fd;
	data_prd.read_callback = file_read_callback;

	rv = nghttp2_submit_response2(session, stream_id, nva, nvlen,
			fd > 0 ? &data_prd : NULL);
	if (rv != 0) {
		LM_WARN("Fatal error: %s", nghttp2_strerror(rv));
		return -1;
	}

	return 0;
}

static int send_response_empty(nghttp2_session *session, int32_t stream_id,
                         nghttp2_nv *nva, size_t nvlen) {
	int rv;

	rv = nghttp2_submit_response2(session, stream_id, nva, nvlen, NULL);
	if (rv != 0) {
		LM_WARN("Fatal error: %s", nghttp2_strerror(rv));
		return -1;
	}
	return 0;
}

static const char ERROR_HTML[] = "<html><head><title>500</title></head>"
                                 "<body><h1>500 Internal Server Error</h1></body></html>";

static int error_reply(nghttp2_session *session,
                       http2_stream_data *stream_data) {
	int rv;
	ssize_t writelen;
	int pipefd[2];
	nghttp2_nv hdrs[] = {MAKE_NV(":status", "500")};

	rv = pipe(pipefd);
	if (rv != 0) {
		LM_WARN("Could not create pipe");
		rv = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
		                               stream_data->stream_id,
		                               NGHTTP2_INTERNAL_ERROR);
		if (rv != 0) {
			LM_WARN("Fatal error: %s", nghttp2_strerror(rv));
			return -1;
		}

		return 0;
	}

	writelen = write(pipefd[1], ERROR_HTML, sizeof(ERROR_HTML) - 1);
	close(pipefd[1]);

	if (writelen != sizeof(ERROR_HTML) - 1) {
		close(pipefd[0]);
		return -1;
	}

	stream_data->fd = pipefd[0];

	if (send_response_fd(session, stream_data->stream_id, hdrs, ARRLEN(hdrs),
		                pipefd[0]) != 0) {
		close(pipefd[0]);
		return -1;
	}

	return 0;
}


static int timeout_reply(nghttp2_session *session,
                       http2_stream_data *stream_data) {
	nghttp2_nv hdrs[] = {MAKE_NV(":status", "408")};

	if (send_response_empty(session, stream_data->stream_id, hdrs, ARRLEN(hdrs)) != 0)
		return -1;

	return 0;
}


/* Minimum check for directory traversal. Returns nonzero if it is
   safe. */
static int check_path(const char *path) {
	/* We don't like '\' in url. */
	return path[0] && path[0] == '/' && strchr(path, '\\') == NULL &&
	       strstr(path, "/../") == NULL && strstr(path, "/./") == NULL &&
	       !ends_with(path, "/..") && !ends_with(path, "/.");
}


static int h2_fdpack(str *data)
{
	int rv;
	ssize_t writelen;
	int pipefd[2];

	if (!data->s || data->len == 0)
		return 0;

	rv = pipe(pipefd);
	if (rv != 0) {
		LM_ERR("failed to create pipe %d (%s)\n", errno, strerror(errno));
		return -1;
	}

	writelen = write(pipefd[1], data->s, data->len);
	close(pipefd[1]);

	if (writelen != data->len) {
		close(pipefd[0]);
		return -1;
	}

	return pipefd[0];
}


static int on_request_recv(nghttp2_session *session,
                           http2_session_data *session_data,
                           http2_stream_data *stream_data) {
	int rc;
	struct timespec wait_until;
	struct timeval now, wait_time, res;
	struct timespec begin;
	unsigned long long diff_ns;
	char *H;

	if (!stream_data->path) {
		if (error_reply(session, stream_data) != 0) {
			return NGHTTP2_ERR_CALLBACK_FAILURE;
		}
		return 0;
	}

	LM_INFO("%s GET %s (stream_id: %d)\n", session_data->client_addr,
	        stream_data->path, stream_data->stream_id);
	if (stream_data->data.len)
		LM_INFO("body: (%d) %.*s\n", stream_data->data.len, stream_data->data.len, stream_data->data.s);
	else
		LM_INFO("body: (none)\n");

	if (!check_path(stream_data->path)) {
		if (error_reply(session, stream_data) != 0) {
			return NGHTTP2_ERR_CALLBACK_FAILURE;
		}
		return 0;
	}

	pthread_mutex_lock(&ng_h2_response->mutex);

	H = cJSON_PrintUnformatted(stream_data->hdrs);
	h2_raise_event_request(stream_data->method, stream_data->path,
	                         H, &stream_data->data);
	cJSON_PurgeString(H);

	gettimeofday(&now, NULL);
	wait_time.tv_sec = h2_response_timeout / 1000;
	wait_time.tv_usec = h2_response_timeout % 1000 * 1000UL;
	LM_DBG("awaiting HTTP2 reply (%ld s, %ld us)...\n", wait_time.tv_sec, wait_time.tv_usec);

	timeradd(&now, &wait_time, &res);

	wait_until.tv_sec = res.tv_sec;
	wait_until.tv_nsec = res.tv_usec * 1000UL;

	clock_gettime(CLOCK_REALTIME, &begin);
	rc = pthread_cond_timedwait(&ng_h2_response->cond,
			&ng_h2_response->mutex, &wait_until);
	diff_ns = get_clock_diff(&begin);
	LM_DBG("waited %lld ns in total\n", diff_ns);
	if (rc != 0) {
		pthread_mutex_unlock(&ng_h2_response->mutex);

		LM_ERR("timeout (errno: %d '%s') while awaiting "
				"HTTP2 reply from opensips.cfg\n", rc, strerror(rc));
		if (timeout_reply(session, stream_data) != 0)
			return NGHTTP2_ERR_CALLBACK_FAILURE;

		return 0;
	}

	pthread_mutex_unlock(&ng_h2_response->mutex);

	/* we failed to build a reply in the SIP worker, so reply with a 500 */
	if (ng_h2_response->code <= 0) {
		if (error_reply(session, stream_data) != 0)
			return NGHTTP2_ERR_CALLBACK_FAILURE;
		return 0;
	}

	LM_DBG("rpl code: %d\n", ng_h2_response->code);
	LM_DBG("rpl # headers: %d\n", ng_h2_response->hdrs_len);
	LM_DBG("rpl body: %.*s\n", ng_h2_response->body.len, ng_h2_response->body.s);

	int fd = h2_fdpack(&ng_h2_response->body);
	if (fd < 0) {
		LM_ERR("failed to pack data\n");
		if (error_reply(session, stream_data) != 0)
			return NGHTTP2_ERR_CALLBACK_FAILURE;
		return 0;
	}

	if (send_response_fd(session, stream_data->stream_id,
				ng_h2_response->hdrs, ng_h2_response->hdrs_len, fd) != 0) {
		close(fd);
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}


static int on_frame_recv_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame, void *user_data) {
	http2_session_data *session_data = (http2_session_data *)user_data;
	http2_stream_data *stream_data;

	switch (frame->hd.type) {
	case NGHTTP2_DATA:
	case NGHTTP2_HEADERS:
		LM_DBG("h2 header [%d], %p %ld\n", frame->hd.type, frame->headers.nva, frame->headers.nvlen);
		/* Check that the client request has finished */
		if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
			stream_data =
			    nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
			LM_DBG("END STREAM, data: %p\n", stream_data);
			  /* For DATA and HEADERS frame, this callback may be called after
			     on_stream_close_callback. Check that stream still alive. */
			  if (!stream_data) {
			    return 0;
			  }
			  return on_request_recv(session, session_data, stream_data);
			}
		break;

	default:
		break;
	}

	return 0;
}


int on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags,
        int32_t stream_id, const uint8_t *data, size_t len, void *user_data)
{
	http2_stream_data *stream_data;
	str *body;
	int prevsz;

	stream_data =
		nghttp2_session_get_stream_user_data(session, stream_id);

	body = &stream_data->data;
	prevsz = body->len;

	if (pkg_str_extend(body, body->len + len) != 0) {
		LM_ERR("out of PKG memory\n");
		return -1;
	}

	memcpy(body->s+prevsz, data, len);
	LM_DBG("stored %zu bytes\n", len);

	return 0;
}


/* nghttp2_on_header_callback: Called when nghttp2 library emits
   single header name/value pair. */
static int on_header_callback(nghttp2_session *session,
                              const nghttp2_frame *frame, const uint8_t *name,
                              size_t namelen, const uint8_t *_value,
                              size_t valuelen, uint8_t flags, void *user_data) {
	http2_stream_data *stream_data;
	const char PATH[] = ":path", METHOD[] = ":method";
	char *value = (char *)_value;
	(void)flags;
	(void)user_data;

	if (frame->hd.type != NGHTTP2_HEADERS
	      || frame->headers.cat != NGHTTP2_HCAT_REQUEST)
		return 0;

	stream_data =
	    nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
	if (!stream_data) {
		LM_ERR("failed to fetch data for stream %d\n", frame->hd.stream_id);
		return 0;
	}

	LM_DBG("received hdr(%d) on stream %d: '%.*s' = '%.*s' (%p)\n", frame->hd.type,
	    stream_data->stream_id, (int)namelen, name, (int)valuelen, value, stream_data);

	if (stream_data->path)
		goto store_hdr;

	if (namelen == sizeof(PATH) - 1 && memcmp(PATH, name, namelen) == 0) {
		size_t j;
		for (j = 0; j < valuelen && _value[j] != '?'; ++j)
		  ;
		stream_data->path = percent_decode(_value, j);

		LM_DBG("detected ':path' header, decoded value: '%s'\n", stream_data->path);

		value = stream_data->path;
		valuelen = strlen(value);
	}

store_hdr:
	if (stream_data->hdrs_len + namelen + valuelen > max_headers_size) {
		LM_ERR("max_headers_size exceeded (%d), skipping header: %s\n",
				max_headers_size, name);
		return 0;
	}

	{
		cJSON *val = cJSON_CreateStr(value, valuelen);
		str key = {(char *)name, namelen};

		if (!val) {
			LM_ERR("oom\n");
			return 0;
		}

		_cJSON_AddItemToObject(stream_data->hdrs, &key, val);
		if (!val->string) {
			LM_ERR("oom\n");
			cJSON_Delete(val);
			return 0;
		}

		stream_data->hdrs_len += namelen + valuelen;

		if (!stream_data->method && namelen == sizeof(METHOD) - 1
				&& memcmp(METHOD, name, namelen) == 0)
			stream_data->method = val->valuestring;
	}

	return 0;
}

static int on_begin_headers_callback(nghttp2_session *session,
                                     const nghttp2_frame *frame,
                                     void *user_data) {
	http2_session_data *session_data = (http2_session_data *)user_data;
	http2_stream_data *stream_data;

	if (frame->hd.type != NGHTTP2_HEADERS ||
		  frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
		return 0;
	}

	stream_data = create_http2_stream_data(session_data, frame->hd.stream_id);
	if (!stream_data) {
		LM_ERR("failed to allocate stream data\n");
		return -1;
	}

	LM_DBG("------------ BEGIN HEADERS (data: %p, stream_id: %d) ----------\n", stream_data, frame->hd.stream_id);
	if (nghttp2_session_set_stream_user_data(session, frame->hd.stream_id,
	                                     stream_data) < 0) {
		LM_ERR("failed to set user data\n");
		return -1;
	}

	return 0;
}

static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                                    uint32_t error_code, void *user_data) {
	http2_session_data *session_data = (http2_session_data *)user_data;
	http2_stream_data *stream_data;
	(void)error_code;

	stream_data = nghttp2_session_get_stream_user_data(session, stream_id);
	if (!stream_data)
		return 0;

	remove_stream(session_data, stream_data);
	delete_http2_stream_data(stream_data);
	h2_response_clean();
	return 0;
}

static void initialize_nghttp2_session(http2_session_data *session_data) {
	nghttp2_session_callbacks *callbacks;

	nghttp2_session_callbacks_new(&callbacks);

	nghttp2_session_callbacks_set_send_callback2(callbacks, send_callback);
	nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
	                                                     on_frame_recv_callback);
	nghttp2_session_callbacks_set_on_stream_close_callback(
	    callbacks, on_stream_close_callback);
	nghttp2_session_callbacks_set_on_header_callback(callbacks,
	                                                 on_header_callback);
	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks,
	                                                 on_data_chunk_recv_callback);
	nghttp2_session_callbacks_set_on_begin_headers_callback(
	    callbacks, on_begin_headers_callback);

	nghttp2_session_server_new(&session_data->session, callbacks, session_data);

	nghttp2_session_callbacks_del(callbacks);
}

/* Send HTTP/2 client connection header, which includes 24 bytes
   magic octets and SETTINGS frame */
static int send_server_connection_header(http2_session_data *session_data) {
	nghttp2_settings_entry iv[1] = {
		{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
	int rv;

	rv = nghttp2_submit_settings(session_data->session, NGHTTP2_FLAG_NONE, iv,
	                             ARRLEN(iv));
	if (rv != 0) {
		LM_WARN("Fatal error: %s", nghttp2_strerror(rv));
		return -1;
	}
	return 0;
}

/* readcb for bufferevent after client connection header was
   checked. */
static void readcb(struct bufferevent *bev, void *ptr) {
  http2_session_data *session_data = (http2_session_data *)ptr;
	(void)bev;

	if (session_recv(session_data) != 0) {
		delete_http2_session_data(session_data);
		return;
	}
}

/* writecb for bufferevent. To greaceful shutdown after sending or
   receiving GOAWAY, we check the some conditions on the nghttp2
   library and output buffer of bufferevent. If it indicates we have
   no business to this session, tear down the connection. If the
   connection is not going to shutdown, we call session_send() to
   process pending data in the output buffer. This is necessary
   because we have a threshold on the buffer size to avoid too much
   buffering. See send_callback(). */
static void writecb(struct bufferevent *bev, void *ptr) {
	http2_session_data *session_data = (http2_session_data *)ptr;
	if (evbuffer_get_length(bufferevent_get_output(bev)) > 0)
		return;

	if (nghttp2_session_want_read(session_data->session) == 0 &&
		  nghttp2_session_want_write(session_data->session) == 0) {
		delete_http2_session_data(session_data);
		return;
	}
	if (session_send(session_data) != 0) {
		delete_http2_session_data(session_data);
		return;
	}
}

/* eventcb for bufferevent */
static void eventcb(struct bufferevent *bev, short events, void *ptr) {
  http2_session_data *session_data = (http2_session_data *)ptr;
	if (events & BEV_EVENT_CONNECTED) {
		const unsigned char *alpn = NULL;
		unsigned int alpnlen = 0;
		SSL *ssl;
		(void)bev;

		LM_INFO("%s connected\n", session_data->client_addr);

		ssl = bufferevent_openssl_get_ssl(session_data->bev);

		SSL_get0_alpn_selected(ssl, &alpn, &alpnlen);

		if (alpn == NULL || alpnlen != 2 || memcmp("h2", alpn, 2) != 0) {
			LM_ERR("%s h2 is not negotiated\n", session_data->client_addr);
			delete_http2_session_data(session_data);
			return;
		}

		initialize_nghttp2_session(session_data);

		if (send_server_connection_header(session_data) != 0 ||
		    session_send(session_data) != 0) {
			delete_http2_session_data(session_data);
			return;
		}

		return;
	}

	if (events & BEV_EVENT_EOF)
		LM_INFO("%s EOF\n", session_data->client_addr);
	else if (events & BEV_EVENT_ERROR)
		LM_INFO("%s network error\n", session_data->client_addr);
	else if (events & BEV_EVENT_TIMEOUT)
		LM_INFO("%s timeout\n", session_data->client_addr);

	delete_http2_session_data(session_data);
}

/* callback for evconnlistener */
static void acceptcb(struct evconnlistener *listener, int fd,
                     struct sockaddr *addr, int addrlen, void *arg) {
	app_context *app_ctx = (app_context *)arg;
	http2_session_data *session_data;
	(void)listener;

	session_data = create_http2_session_data(app_ctx, fd, addr, addrlen);

	bufferevent_setcb(session_data->bev, readcb, writecb, eventcb, session_data);
}

static void start_listen(struct event_base *evbase, const char *service,
                         app_context *app_ctx) {
	int rv;
	struct addrinfo hints;
	struct addrinfo *res, *rp;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
#ifdef AI_ADDRCONFIG
	hints.ai_flags |= AI_ADDRCONFIG;
#endif /* AI_ADDRCONFIG */

	rv = getaddrinfo(h2_ip, service, &hints, &res);
	if (rv != 0) {
		LM_ERR("Could not resolve server address\n");
		return;
	}

	for (rp = res; rp; rp = rp->ai_next) {
		struct evconnlistener *listener;
		listener = evconnlistener_new_bind(
			evbase, acceptcb, app_ctx, LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
			16, rp->ai_addr, (int)rp->ai_addrlen);

		if (listener) {
			freeaddrinfo(res);
			return;
		}
	}

	LM_ERR("Could not start listener\n");
}

static void initialize_app_context(app_context *app_ctx, SSL_CTX *ssl_ctx,
                                   struct event_base *evbase) {
	memset(app_ctx, 0, sizeof(app_context));
	app_ctx->ssl_ctx = ssl_ctx;
	app_ctx->evbase = evbase;
}

static void run(const char *service, const char *key_file,
                const char *cert_file) {
	SSL_CTX *ssl_ctx;
	app_context app_ctx;
	struct event_base *evbase;

	ssl_ctx = create_ssl_ctx(key_file, cert_file);
	evbase = event_base_new();
	initialize_app_context(&app_ctx, ssl_ctx, evbase);
	start_listen(evbase, service, &app_ctx);

	LM_DBG("event loop start\n");
	event_base_loop(evbase, 0);
	LM_DBG("event loop end\n");

	event_base_free(evbase);
	SSL_CTX_free(ssl_ctx);
}

static void init_mutex_cond(pthread_mutex_t *mutex, pthread_cond_t *cond)
{
	pthread_mutexattr_t mattr;
	pthread_mutexattr_init(&mattr);
	pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED);
	pthread_mutexattr_setrobust(&mattr, PTHREAD_MUTEX_ROBUST);
	pthread_mutex_init(mutex, &mattr);
	pthread_mutexattr_destroy(&mattr);

	pthread_condattr_t cattr;
	pthread_condattr_init(&cattr);
	pthread_condattr_setpshared(&cattr, PTHREAD_PROCESS_SHARED);
	pthread_cond_init(cond, &cattr);
	pthread_condattr_destroy(&cattr);
}

void h2_response_clean(void)
{
	int i;

	if (ng_h2_response->hdrs) {
		for (i = 0; i < ng_h2_response->hdrs_len; i++) {
			shm_free(ng_h2_response->hdrs[i].name);
			shm_free(ng_h2_response->hdrs[i].value);
		}

		shm_free(ng_h2_response->hdrs);
		ng_h2_response->hdrs = NULL;
		ng_h2_response->hdrs_len = 0;
	}

	if (ng_h2_response->body.s) {
		shm_free(ng_h2_response->body.s);
		memset(&ng_h2_response->body, 0, sizeof ng_h2_response->body);
	}

	ng_h2_response->code = 0;
}

void http2_server(int rank)
{
	struct sigaction act;

	ng_h2_response = shm_malloc(sizeof *ng_h2_response);
	if (!ng_h2_response) {
		LM_ERR("oom SHM\n");
		return;
	}
	memset(ng_h2_response, 0, sizeof *ng_h2_response);
	init_mutex_cond(&ng_h2_response->mutex, &ng_h2_response->cond);
	*h2_response = ng_h2_response;

	memset(&act, 0, sizeof act);
	act.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &act, NULL);

	LM_INFO("HTTP2 server starting\n");
	run(int2str(h2_port, NULL), h2_tls_key.s, h2_tls_cert.s);
	LM_ERR("HTTP2 server exiting!\n");
}

