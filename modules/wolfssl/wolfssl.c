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

#include <poll.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/tcp.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>

#include "../../dprint.h"
#include "../../mem/shm_mem.h"
#include "../../sr_module.h"
#include "../../locking.h"
#include "../../pt.h"
#include "../../net/tcp_conn_defs.h"
#include "../../net/proto_tcp/tcp_common_defs.h"
#include "../tls_mgm/tls_helper.h"

#include "wolfssl_api.h"

static int load_wolfssl(struct wolfssl_binds *binds);

static int mod_init(void);
static void mod_destroy(void);

static int _wolfssl_init(void);
static void _wolfssl_destroy(void);

struct _WOLFSSL {
	WOLFSSL *read_ssl;
	WOLFSSL *write_ssl;
};

#define _WOLFSSL_READ_SSL(_ssl) \
	(((struct _WOLFSSL *)(_ssl))->read_ssl)
#define _WOLFSSL_WRITE_SSL(_ssl) \
	(((struct _WOLFSSL *)(_ssl))->write_ssl)

#define _WOLFSSL_ERR_BUFLEN 80

WOLFSSL_CTX *ssl_ctx_client;
WOLFSSL_CTX *ssl_ctx_server;

int *ssl_ctx_refcnt;
gen_lock_t *ssl_ctx_lock;

char *ca_list;
char *certificate;
char *private_key;

static param_export_t params[] = {
	{"ca_list", STR_PARAM, &ca_list},
	{"certificate", STR_PARAM, &certificate},
	{"private_key", STR_PARAM, &private_key},
	{0, 0, 0}
};

static cmd_export_t cmds[] = {
	{"load_wolfssl", (cmd_function)load_wolfssl,
		{{0,0,0}}, ALL_ROUTES},
	{0,0,{{0,0,0}},0}
};

struct module_exports exports = {
	"wolfssl",  /* module name*/
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	0,          /* OpenSIPS module dependencies */
	cmds,          /* exported functions */
	0,          /* exported async functions */
	params,     /* module parameters */
	0,          /* exported statistics */
	0,          /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,			/* exported transformations */
	0,          /* extra processes */
	0,          /* module pre-initialization function */
	mod_init,   /* module initialization function */
	0,          /* response function */
	mod_destroy,/* destroy function */
	0,          /* per-child init function */
	0           /* reload confirm function */
};

static int mod_init(void)
{
	LM_INFO("initializing wolfssl module\n");

	_wolfssl_init();

	return 0;
}

static void mod_destroy(void)
{
	LM_INFO("destroying wolfssl module\n");

	_wolfssl_destroy();
}

static void *oss_malloc(size_t size)
{
	return shm_malloc(size);
}

static void oss_free(void *ptr)
{
	return shm_free(ptr);
}

static void *oss_realloc(void *ptr, size_t size)
{
	return shm_realloc(ptr, size);
}

static int _wolfssl_init(void)
{
	int ret;

	LM_INFO("wolfSSL version: %s\n", wolfSSL_lib_version());

	wolfSSL_SetAllocators(oss_malloc, oss_free, oss_realloc);
	wolfSSL_Init();

	ssl_ctx_lock = lock_alloc();
	if (!ssl_ctx_lock || !lock_init(ssl_ctx_lock)) {
		LM_ERR("could not initialize ssl_ctx lock!\n");
		return -1;
	}

	ssl_ctx_refcnt = shm_malloc(sizeof(int));
	if (!ssl_ctx_refcnt) {
		LM_ERR("no more shm mem!\n");
		return -1;
	}
	*ssl_ctx_refcnt = 1;

	if (!(ssl_ctx_client = wolfSSL_CTX_new(wolfTLSv1_2_client_method()))) {
		LM_ERR("Failed to create WOLFSSL_CTX\n");
		return -1;
	}
	if (!(ssl_ctx_server = wolfSSL_CTX_new(wolfTLSv1_2_server_method()))) {
		LM_ERR("Failed to create WOLFSSL_CTX\n");
		return -1;
	}

	wolfSSL_CTX_set_session_cache_mode(ssl_ctx_client, WOLFSSL_SESS_CACHE_OFF);
	wolfSSL_CTX_set_session_cache_mode(ssl_ctx_server, WOLFSSL_SESS_CACHE_OFF);

	ret = wolfSSL_CTX_load_verify_locations(ssl_ctx_client, ca_list, NULL);
	if (ret != SSL_SUCCESS) {
		switch (ret) {
		case WOLFSSL_BAD_FILE:
			LM_ERR("Bad CA list file: %s, (ret=%d)\n", ca_list, ret);
			return -1;
		default:
			LM_ERR("Failed to load CA list from file: %s, (ret=%d)\n", ca_list, ret);
			return -1;
		}
	}
	ret = wolfSSL_CTX_load_verify_locations(ssl_ctx_server, ca_list, NULL);
	if (ret != SSL_SUCCESS) {
		switch (ret) {
		case WOLFSSL_BAD_FILE:
			LM_ERR("Bad CA list file: %s, (ret=%d)\n", ca_list, ret);
			return -1;
		default:
			LM_ERR("Failed to load CA list from file: %s, (ret=%d)\n", ca_list, ret);
			return -1;
		}
	}

	if (wolfSSL_CTX_use_certificate_file(ssl_ctx_client, certificate,
		SSL_FILETYPE_PEM)
		!= SSL_SUCCESS) {
		LM_ERR("Failed to load certificate from file: %s\n", certificate);
		return -1;
	}
	if (wolfSSL_CTX_use_certificate_file(ssl_ctx_server, certificate,
		SSL_FILETYPE_PEM)
		!= SSL_SUCCESS) {
		LM_ERR("Failed to load certificate from file: %s\n", certificate);
		return -1;
	}

	if (wolfSSL_CTX_use_PrivateKey_file(ssl_ctx_client, private_key,
		SSL_FILETYPE_PEM)
		!= SSL_SUCCESS) {
		LM_ERR("Failed to load private_key from file: %s\n", private_key);
		return -1;
	}
	if (wolfSSL_CTX_use_PrivateKey_file(ssl_ctx_server, private_key,
		SSL_FILETYPE_PEM)
		!= SSL_SUCCESS) {
		LM_ERR("Failed to load private_key from file: %s\n", private_key);
		return -1;
	}

	return 0;
}

static void get_wolfssl_ctx(void)
{
	lock_get(ssl_ctx_lock);
	(*ssl_ctx_refcnt)++;
	lock_release(ssl_ctx_lock);
}

static void release_wolfssl_ctx(void)
{
	lock_get(ssl_ctx_lock);

	if (--(*ssl_ctx_refcnt) == 0) {
		if (ssl_ctx_client) {
			wolfSSL_CTX_free(ssl_ctx_client);
			ssl_ctx_client = NULL;
		}
		if (ssl_ctx_server) {
			wolfSSL_CTX_free(ssl_ctx_server);
			ssl_ctx_server = NULL;
		}

		shm_free(ssl_ctx_client);
		shm_free(ssl_ctx_server);
	}

	lock_release(ssl_ctx_lock);
}

static void _wolfssl_destroy(void)
{
	release_wolfssl_ctx();

	wolfSSL_Cleanup();

	lock_destroy(ssl_ctx_lock);
	lock_dealloc(ssl_ctx_lock);
}

static int _wolfssl_tls_conn_init(struct tcp_connection* c)
{
	WOLFSSL_CTX *ssl_ctx;

	/*
	* new connection within a single process, no lock necessary
	*/
	LM_DBG("Creating a whole new ssl connection\n");

	c->extra_data = shm_malloc(sizeof(struct _WOLFSSL));
	if (!c->extra_data) {
		LM_ERR("no more shm memory\n");
		return -1;
	}
	memset(c->extra_data, 0, sizeof(struct _WOLFSSL));

	if ( c->flags&F_CONN_ACCEPTED ) {
		/* connection created as a result of an accept -> server */
		c->proto_flags = F_TLS_DO_ACCEPT;
		ssl_ctx = ssl_ctx_server;
	} else {
		/* connection created as a result of a connect -> client */
		c->proto_flags = F_TLS_DO_CONNECT;
		ssl_ctx = ssl_ctx_client;
	}

	_WOLFSSL_READ_SSL(c->extra_data) = wolfSSL_new(ssl_ctx);
	if (!_WOLFSSL_READ_SSL(c->extra_data)) {
		LM_ERR("failed to create SSL structure (%d:%s)\n",
			errno, strerror(errno));
		return -1;
	}

	get_wolfssl_ctx();

	return 0;
}

static int _wolfssl_tls_update_fd(struct tcp_connection *c, int fd)
{
	if (wolfSSL_set_fd(_WOLFSSL_READ_SSL(c->extra_data), fd) !=
		SSL_SUCCESS) {
		LM_ERR("failed to assign socket to ssl\n");
		return -1;
	}
	if (_WOLFSSL_WRITE_SSL(c->extra_data) &&
		wolfSSL_set_fd(_WOLFSSL_WRITE_SSL(c->extra_data), fd) != SSL_SUCCESS) {
		LM_ERR("failed to assign socket to ssl\n");
		return -1;
	}

	LM_DBG("New fd is %d\n", fd);
	return 0;
}

static int _wolfssl_tls_conn_shutdown(struct tcp_connection *c)
{
	int ret, err;
	WOLFSSL *ssl;
	char err_buf[_WOLFSSL_ERR_BUFLEN];

	/* If EOF or other error on connection, no point in attempting to
	 * do further writing & reading on the con */
	if (c->state == S_CONN_BAD ||
		c->state == S_CONN_ERROR ||
		c->state == S_CONN_EOF)
		return 0;
	/*
	* we do not implement full ssl shutdown
	*/
	ssl = _WOLFSSL_WRITE_SSL(c->extra_data);
	if (ssl == 0) {
		LM_ERR("no ssl data\n");
		return -1;
	}

	ret = wolfSSL_shutdown(ssl);
	if (ret == SSL_SUCCESS) {
		LM_DBG("shutdown successful\n");
		return 0;
	} else if (ret == SSL_SHUTDOWN_NOT_DONE) {
		LM_DBG("first phase of 2-way handshake completed succesfuly\n");
		return 0;
	} else {
		err = wolfSSL_get_error(ssl, ret);
		switch (err) {
		case SSL_ERROR_ZERO_RETURN:
			c->state = S_CONN_EOF;

			return 0;
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			c->state = S_CONN_EOF;
			return 0;
		case SSL_ERROR_SYSCALL:
			LM_ERR("SSL_ERROR_SYSCALL err=%s(%d)\n",
				strerror(errno), errno);
		default:
			LM_ERR("SYSCALL ERROR err=%s(%d)\n",
				strerror(errno), errno);
			LM_ERR("TLS shutdown error: %d, %s\n",err,
				wolfSSL_ERR_error_string(err, err_buf));
			c->state = S_CONN_BAD;

			return -1;
		}
	}

	LM_ERR("bug\n");
	return -1;
}

static void _wolfssl_tls_conn_clean(struct tcp_connection* c)
{
	if (c->extra_data) {
		if (c->s != -1 && process_no != 0) {
			_wolfssl_tls_update_fd(c,c->s);
			_wolfssl_tls_conn_shutdown(c);
		}

		wolfSSL_free(_WOLFSSL_READ_SSL(c->extra_data));
		if (_WOLFSSL_WRITE_SSL(c->extra_data))
			wolfSSL_free(_WOLFSSL_WRITE_SSL(c->extra_data));

		shm_free(c->extra_data);
		c->extra_data = 0;

		release_wolfssl_ctx();
	}
}

static int _wolfssl_tls_async_connect(struct tcp_connection *con, int fd,
	int timeout)
{
	unsigned int elapsed,to;
	unsigned int err_len;
	int poll_err, n, err;
	struct timeval begin;
	char err_buf[_WOLFSSL_ERR_BUFLEN];
#if defined(HAVE_SELECT) && defined(BLOCKING_USE_SELECT)
	fd_set sel_set;
	fd_set orig_set;
	struct timeval timeout_val;
#else
	struct pollfd pf;
#endif
	WOLFSSL *ssl = _WOLFSSL_READ_SSL(con->extra_data);

	/* attempt to do connect and see if we do block or not */
	poll_err=0;
	elapsed = 0;
	to = timeout*1000;

#if defined(HAVE_SELECT) && defined(BLOCKING_USE_SELECT)
	FD_ZERO(&orig_set);
	FD_SET(fd, &orig_set);
#else
	pf.fd=fd;
	pf.events=POLLOUT|POLLIN;
#endif

	if (gettimeofday(&(begin), NULL)) {
		LM_ERR("Failed to get TLS connect start time\n");
		goto failure;
	}

	while (1) {
		if ((n = wolfSSL_connect(ssl)) == SSL_SUCCESS) {
			LM_INFO("new TLS connection to %s:%d established\n",
					ip_addr2a(&con->rcv.src_ip), con->rcv.src_port);
			con->proto_flags &= ~F_TLS_DO_CONNECT;

			_WOLFSSL_WRITE_SSL(con->extra_data) = wolfSSL_write_dup(ssl);
			if (!_WOLFSSL_WRITE_SSL(con->extra_data)) {
				LM_ERR("failed to create duplicate write SSL structure (%d:%s)\n",
					errno, strerror(errno));
				return -1;
			}

			return 1;
		}

		err = wolfSSL_get_error(ssl, n);
		switch (err) {
			case SSL_ERROR_ZERO_RETURN:
				LM_INFO("New TLS connection to %s:%d failed cleanly\n",
					ip_addr2a(&con->rcv.src_ip), con->rcv.src_port);

				goto failure;
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				/* we need to retry, if time has not passed yet */
again:
				elapsed=get_time_diff(&begin);
				if (elapsed >= to) /* timed out */ {
					LM_DBG("handshake timeout for connection %p %dms elapsed\n",
							con, timeout);
					return 0;
				}
				to -= elapsed;
#if defined(HAVE_SELECT) && defined(BLOCKING_USE_SELECT)
				sel_set=orig_set;
				timeout_val.tv_sec=to/1000000;
				timeout_val.tv_usec=to%1000000;
				n=select(fd+1, 0, &sel_set, 0, &timeout_val);
#else
				n=poll(&pf, 1, to/1000);
#endif
				if (n<0){
					if (errno == EINTR)
						goto again;
					LM_ERR("poll/select failed:[server=%s:%d] (%d) %s\n",
							ip_addr2a(&con->rcv.src_ip), con->rcv.src_port,
							errno, strerror(errno));
					goto failure;
				}else if (n==0) /* timeout */
					goto again;
#if defined(HAVE_SELECT) && defined(BLOCKING_USE_SELECT)
				if (FD_ISSET(fd, &sel_set))
#else
				if (pf.revents&(POLLERR|POLLHUP|POLLNVAL)){
					LM_ERR("poll error: flags %x\n", pf.revents);
					poll_err=1;
				}
#endif
				{
					err_len=sizeof(err);
					getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
					if ((err==0) && (poll_err==0))
						continue; /* retry ssl connect */
					if (err!=EINPROGRESS && err!=EALREADY){
						LM_ERR("failed to retrieve SO_ERROR [server=%s:%d] (%d) %s\n",
								ip_addr2a(&con->rcv.src_ip), con->rcv.src_port,
								err, strerror(err));
						goto failure;
					}
					continue;
				}
			case SSL_ERROR_SYSCALL:
				LM_ERR("SSL_ERROR_SYSCALL err=%s(%d)\n",
					strerror(errno), errno);
			default:
				LM_ERR("New TLS connection to %s:%d failed\n",
					ip_addr2a(&con->rcv.src_ip), con->rcv.src_port);
				LM_ERR("TLS connect error: %d, %s\n", err,
					wolfSSL_ERR_error_string(err, err_buf));

				con->state = S_CONN_BAD;

				return -1;
		}
	}
failure:
	con->state = S_CONN_BAD;
	return -1;
}

static int _wolfssl_tls_write(struct tcp_connection *c, int fd, const void *buf,
	size_t len, short *poll_events)
{
	int ret;
	int err;
	char err_buf[_WOLFSSL_ERR_BUFLEN];
	WOLFSSL *ssl;

	ssl = _WOLFSSL_WRITE_SSL(c->extra_data);

	ret = wolfSSL_write(ssl, buf, len);
	if (ret > 0) {
		LM_DBG("write was successful (%d bytes)\n", ret);
		return ret;
	} else {
		err = wolfSSL_get_error(ssl, ret);
		switch (err) {
		case SSL_ERROR_ZERO_RETURN:
			LM_DBG("connection closed cleanly\n");
			c->state = S_CONN_EOF;

			return -1;
		case SSL_ERROR_WANT_READ:
			if (poll_events)
				*poll_events = POLLIN;

			return 0;
		case SSL_ERROR_WANT_WRITE:
			if (poll_events)
				*poll_events = POLLOUT;

			return 0;
		default:
			LM_ERR("TLS connection to %s:%d write failed (%d:%d:%d)\n",
				ip_addr2a(&c->rcv.src_ip), c->rcv.src_port, err, ret, errno);
			LM_ERR("TLS write error: %d, %s\n",err,
				wolfSSL_ERR_error_string(err, err_buf));
			c->state = S_CONN_BAD;

			return -1;
		}
	}

	LM_BUG("bug\n");
	return -1;
}

static int _wolfssl_tls_accept(struct tcp_connection *c, short *poll_events)
{
	int ret, err;
	WOLFSSL *ssl;
	char err_buf[_WOLFSSL_ERR_BUFLEN];

	if ( (c->proto_flags&F_TLS_DO_ACCEPT)==0 ) {
		LM_BUG("invalid connection state (bug in TLS code)\n");
		return -1;
	}

	ssl = _WOLFSSL_READ_SSL(c->extra_data);

	ret = wolfSSL_accept(ssl);
	if (ret == SSL_SUCCESS) {
		LM_INFO("New TLS connection from %s:%d accepted\n",
			ip_addr2a(&c->rcv.src_ip), c->rcv.src_port);

		/* TLS accept done, reset the flag */
		c->proto_flags &= ~F_TLS_DO_ACCEPT;

		_WOLFSSL_WRITE_SSL(c->extra_data) = wolfSSL_write_dup(ssl);
		if (!_WOLFSSL_WRITE_SSL(c->extra_data)) {
			LM_ERR("failed to create duplicate write SSL structure (%d:%s)\n",
				errno, strerror(errno));
			return -1;
		}

		LM_DBG("new TLS connection from %s:%d using %s\n",
			ip_addr2a(&c->rcv.src_ip), c->rcv.src_port,
			wolfSSL_get_cipher_name(ssl));

		LM_DBG("local socket: %s:%d\n",
			ip_addr2a(&c->rcv.dst_ip), c->rcv.dst_port );

		return 0;
	} else {
		err = wolfSSL_get_error(ssl, ret);
		switch (err) {
			case SSL_ERROR_ZERO_RETURN:
				LM_INFO("TLS connection from %s:%d accept failed cleanly\n",
					ip_addr2a(&c->rcv.src_ip), c->rcv.src_port);

				c->state = S_CONN_BAD;

				return -1;
			case SSL_ERROR_WANT_READ:
				if (poll_events)
					*poll_events = POLLIN;

				return 0;
			case SSL_ERROR_WANT_WRITE:
				if (poll_events)
					*poll_events = POLLOUT;

				return 0;
			case SSL_ERROR_SYSCALL:
				LM_ERR("SSL_ERROR_SYSCALL err=%s(%d)\n",
					strerror(errno), errno);
			default:
				c->state = S_CONN_BAD;
				LM_ERR("New TLS connection from %s:%d failed to accept\n",
					ip_addr2a(&c->rcv.src_ip), c->rcv.src_port);
				LM_ERR("TLS accept error: %d, %s\n", err,
					wolfSSL_ERR_error_string(err, err_buf));

				return -1;
		}
	}

	LM_BUG("bug\n");
	return -1;
}

static int _wolfssl_tls_connect(struct tcp_connection *c, short *poll_events)
{
	int ret, err;
	WOLFSSL *ssl;
	char err_buf[_WOLFSSL_ERR_BUFLEN];

	if ( (c->proto_flags&F_TLS_DO_CONNECT)==0 ) {
		LM_BUG("invalid connection state (bug in TLS code)\n");
		return -1;
	}

	ssl = _WOLFSSL_READ_SSL(c->extra_data);

	ret = wolfSSL_connect(ssl);
	if (ret == SSL_SUCCESS) {
		LM_INFO("New TLS connection to %s:%d established\n",
			ip_addr2a(&c->rcv.src_ip), c->rcv.src_port);
		c->proto_flags &= ~F_TLS_DO_CONNECT;

		_WOLFSSL_WRITE_SSL(c->extra_data) = wolfSSL_write_dup(ssl);
		if (!_WOLFSSL_WRITE_SSL(c->extra_data)) {
			LM_ERR("failed to create duplicate write SSL structure (%d:%s)\n",
				errno, strerror(errno));
			return -1;
		}

		LM_DBG("new TLS connection to %s:%d using %s\n",
			ip_addr2a(&c->rcv.src_ip), c->rcv.src_port,
			wolfSSL_get_cipher_name(ssl));
		LM_DBG("sending socket: %s:%d \n",
			ip_addr2a(&c->rcv.dst_ip), c->rcv.dst_port);

		return 0;
	} else {
		err = wolfSSL_get_error(ssl, ret);
		switch (err) {
			case SSL_ERROR_ZERO_RETURN:
				LM_INFO("New TLS connection to %s:%d failed cleanly\n",
					ip_addr2a(&c->rcv.src_ip), c->rcv.src_port);

				c->state = S_CONN_BAD;
				return -1;
			case SSL_ERROR_WANT_READ:
				if (poll_events)
					*poll_events = POLLIN;

				return 0;
			case SSL_ERROR_WANT_WRITE:
				if (poll_events)
					*poll_events = POLLOUT;

				return 0;
			case SSL_ERROR_SYSCALL:
				LM_ERR("SSL_ERROR_SYSCALL err=%s(%d)\n",
					strerror(errno), errno);
				/* fall through */
			default:
				LM_ERR("New TLS connection to %s:%d failed\n",
					ip_addr2a(&c->rcv.src_ip), c->rcv.src_port);
				LM_ERR("TLS connect error: %d, %s\n", err,
					wolfSSL_ERR_error_string(err, err_buf));
				c->state = S_CONN_BAD;

				return -1;
		}
	}

	LM_BUG("bug\n");
	return -1;
}

static int _wolfssl_tls_blocking_write(struct tcp_connection *c, int fd,
	const char *buf, size_t len, int handshake_timeout, int send_timeout)
{
	#define MAX_SSL_RETRIES 32
	int             written, n;
	int             timeout, retries;
	struct pollfd   pf;
	pf.fd = fd;

	written = 0;
	retries = 0;

	if (c->state!=S_CONN_OK) {
		LM_ERR("TLS broken connection\n");
		goto error;
	}

	if (_wolfssl_tls_update_fd(c, fd) < 0)
		goto error;

	timeout = send_timeout;
again:
	n = 0;
	pf.events = 0;

	if ( c->proto_flags & F_TLS_DO_ACCEPT ) {
		if (_wolfssl_tls_accept(c, &(pf.events)) < 0)
			goto error;
		timeout = handshake_timeout;
	} else if ( c->proto_flags & F_TLS_DO_CONNECT ) {
		if (_wolfssl_tls_connect(c, &(pf.events)) < 0)
			goto error;
		timeout = handshake_timeout;
	} else {
		n = _wolfssl_tls_write(c, fd, buf, len, &(pf.events));
		timeout = send_timeout;
	}

	if (n < 0) {
		LM_ERR("TLS failed to send data\n");
		goto error;
	}

	/* nothing happens */
	if (n==0) {
		retries++;
		/* avoid looping */
		if (retries==MAX_SSL_RETRIES) {
			LM_ERR("too many retries with no operation\n");
			goto error;
		}
	} else {
		/* reset the retries if we succeeded in doing something*/
		retries = 0;
	}

	written += n;
	if (n < len) {
		/*
		* partial write
		*/
		buf += n;
		len -= n;
	} else {
		/*
		* successful full write
		*/
		return written;
	}

	if (pf.events == 0)
		pf.events = POLLOUT;

poll_loop:
	while (1) {
		n = poll(&pf, 1, timeout);
		if (n < 0) {
			if (errno == EINTR)
				continue;	/* signal, ignore */
			else if (errno != EAGAIN && errno != EWOULDBLOCK) {
				LM_ERR("TLS poll failed: %s [%d]\n",strerror(errno), errno);
				goto error;
			} else
				goto poll_loop;
		} else if (n == 0) {
			/*
			* timeout
			*/
			LM_ERR("TLS send timeout (%d)\n", timeout);
			goto error;
		}
		if (pf.revents & POLLOUT || pf.revents & POLLIN) {
			/*
			* we can read or write again
			*/
			goto again;
		} else if (pf.revents & (POLLERR | POLLHUP | POLLNVAL)) {
			LM_ERR("TLS bad poll flags %x\n",pf.revents);
			goto error;
		}
		/*
		* if POLLPRI or other non-harmful events happened, continue (
		* although poll should never signal them since we're not
		* interested in them => we should never reach this point)
		*/
	}

error:
	return -1;
}

static int _wolfssl_tls_fix_read_conn(struct tcp_connection *c, int fd,
	int async_timeout, int lock)
{
	int ret = 0;

	if (lock)
		lock_get(&c->write_lock);

	if ( c->proto_flags & F_TLS_DO_ACCEPT ) {
		ret = _wolfssl_tls_update_fd(c, fd);
		if (!ret)
			ret = _wolfssl_tls_accept(c, NULL);
	} else if ( c->proto_flags & F_TLS_DO_CONNECT ) {
		ret = _wolfssl_tls_update_fd(c, fd);
		if (!ret) {
			if (c->async && async_timeout)
				ret = _wolfssl_tls_async_connect(c, fd, async_timeout);
			else
				ret = _wolfssl_tls_connect(c, NULL);
		}
	} else
		ret = 1;

	if (lock)
		lock_release(&c->write_lock);

	return ret;
}

static int _wolfssl_read(struct tcp_connection *c, void *buf, size_t len)
{
	int ret, err;
	WOLFSSL *ssl;
	char err_buf[_WOLFSSL_ERR_BUFLEN];

	ssl = _WOLFSSL_READ_SSL(c->extra_data);

	ret = wolfSSL_read(ssl, buf, len);
	if (ret > 0) {
		LM_DBG("%d bytes read\n", ret);
		return ret;
	} else if (ret == 0) {
		c->state = S_CONN_EOF;

		err = wolfSSL_get_error(ssl, ret);
		if (err == SSL_ERROR_ZERO_RETURN) {
			LM_DBG("TLS connection to %s:%d closed cleanly\n",
				ip_addr2a(&c->rcv.src_ip), c->rcv.src_port);
		} else if (err == SOCKET_PEER_CLOSED_E) {
			LM_DBG("TLS connection to %s:%d closed, unclean shutdown by peer\n",
				ip_addr2a(&c->rcv.src_ip), c->rcv.src_port);
		}

		return 0;
	} else {
		err = wolfSSL_get_error(ssl, ret);
		switch (err) {
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			return 0;
		case SSL_ERROR_SYSCALL:
			LM_ERR("SYSCALL error -> (%d) <%s>\n",errno,strerror(errno));
			/* fall through */
		default:
			LM_ERR("TLS connection to %s:%d read failed\n",
				ip_addr2a(&c->rcv.src_ip), c->rcv.src_port);
			LM_ERR("TLS read error: %d, %s\n",err,
				wolfSSL_ERR_error_string(err, err_buf));
			c->state = S_CONN_BAD;

			return -1;
		}
	}

	LM_BUG("bug\n");
	return -1;
}

static int _wolfssl_tls_read(struct tcp_connection * c,struct tcp_req *r)
{
	int bytes_free;
	int fd, read;

	fd = c->fd;
	bytes_free = TCP_BUF_SIZE - (int) (r->pos - r->buf);

	if (bytes_free == 0) {
		LM_ERR("TLS buffer overrun, dropping\n");
		r->error = TCP_REQ_OVERRUN;
		return -1;
	}

	/*
	* ssl structures may be accessed from several processes, we need to
	* protect each access and modification by a lock
	*/
	lock_get(&c->write_lock);
	_wolfssl_tls_update_fd(c, fd);
	read = _wolfssl_read(c, r->pos, bytes_free);
	lock_release(&c->write_lock);
	if (read > 0)
		r->pos += read;
	return read;
}

static int load_wolfssl(struct wolfssl_binds *binds)
{
	binds->tls_conn_init = _wolfssl_tls_conn_init;
	binds->tls_conn_clean = _wolfssl_tls_conn_clean;
	binds->tls_update_fd = _wolfssl_tls_update_fd;
	binds->tls_async_connect = _wolfssl_tls_async_connect;
	binds->tls_write = _wolfssl_tls_write;
	binds->tls_blocking_write = _wolfssl_tls_blocking_write;
	binds->tls_fix_read_conn = _wolfssl_tls_fix_read_conn;
	binds->tls_read = _wolfssl_tls_read;

	return 1;
}
