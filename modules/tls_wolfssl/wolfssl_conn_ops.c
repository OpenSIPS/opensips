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

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>

#include <poll.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/tcp.h>

#include "../../net/tcp_conn_defs.h"
#include "../../net/proto_tcp/tcp_common_defs.h"
#include "../../trace_api.h"
#include "../tls_mgm/tls_helper.h"

#include "wolfssl.h"

int _wolfssl_has_session_ticket(WOLFSSL *ssl);

void tls_dump_cert_info(char* s, WOLFSSL_X509* cert)
{
	char* subj;
	char* issuer;

	subj   = wolfSSL_X509_NAME_oneline(wolfSSL_X509_get_subject_name(cert), 0, 0);
	issuer = wolfSSL_X509_NAME_oneline(wolfSSL_X509_get_issuer_name(cert), 0, 0);

	LM_INFO("%s subject: %s, issuer: %s\n", s ? s : "", subj, issuer);
	wolfSSL_Free(subj);
	wolfSSL_Free(issuer);
}

static void tls_dump_verification_failure(long verification_result)
{
	switch(verification_result) {
	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
		LM_WARN("unable to get issuer certificate\n");
		break;
	case X509_V_ERR_UNABLE_TO_GET_CRL:
		LM_WARN("unable to get certificate CRL\n");
		break;
	case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
		LM_WARN("unable to decrypt certificate's signature\n");
		break;
	case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
		LM_WARN("unable to decrypt CRL's signature\n");
		break;
	case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
		LM_WARN("unable to decode issuer public key\n");
		break;
	case X509_V_ERR_CERT_SIGNATURE_FAILURE:
		LM_WARN("certificate signature failure\n");
		break;
	case X509_V_ERR_CRL_SIGNATURE_FAILURE:
		LM_WARN("CRL signature failure\n");
		break;
	case X509_V_ERR_CERT_NOT_YET_VALID:
		LM_WARN("certificate is not yet valid\n");
		break;
	case X509_V_ERR_CERT_HAS_EXPIRED:
		LM_WARN("certificate has expired\n");
		break;
	case X509_V_ERR_CRL_NOT_YET_VALID:
		LM_WARN("CRL is not yet valid\n");
		break;
	case X509_V_ERR_CRL_HAS_EXPIRED:
		LM_WARN("CRL has expired\n");
		break;
	case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
		LM_WARN("format error in certificate's notBefore field\n");
		break;
	case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
		LM_WARN("format error in certificate's notAfter field\n");
		break;
	case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
		LM_WARN("format error in CRL's lastUpdate field\n");
		break;
	case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
		LM_WARN("format error in CRL's nextUpdate field\n");
		break;
	case X509_V_ERR_OUT_OF_MEM:
		LM_WARN("out of memory\n");
		break;
	case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
		LM_WARN("self signed certificate\n");
		break;
	case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
		LM_WARN("self signed certificate in certificate chain\n");
		break;
	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
		LM_WARN("unable to get local issuer certificate\n");
		break;
	case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
		LM_WARN("unable to verify the first certificate\n");
		break;
	case X509_V_ERR_CERT_CHAIN_TOO_LONG:
		LM_WARN("certificate chain too long\n");
		break;
	case X509_V_ERR_CERT_REVOKED:
		LM_WARN("certificate revoked\n");
		break;
	case X509_V_ERR_INVALID_CA:
		LM_WARN("invalid CA certificate\n");
		break;
	case X509_V_ERR_PATH_LENGTH_EXCEEDED:
		LM_WARN("path length constraint exceeded\n");
		break;
	case X509_V_ERR_INVALID_PURPOSE:
		LM_WARN("unsupported certificate purpose\n");
		break;
	case X509_V_ERR_CERT_UNTRUSTED:
		LM_WARN("certificate not trusted\n");
		break;
	case X509_V_ERR_CERT_REJECTED:
		LM_WARN("certificate rejected\n");
		break;
	case X509_V_ERR_SUBJECT_ISSUER_MISMATCH:
		LM_WARN("subject issuer mismatch\n");
		break;
	case X509_V_ERR_AKID_SKID_MISMATCH:
		LM_WARN("authority and subject key identifier mismatch\n");
		break;
	case X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH:
		LM_WARN("authority and issuer serial number mismatch\n");
		break;
	case X509_V_ERR_KEYUSAGE_NO_CERTSIGN:
		LM_WARN("key usage does not include certificate signing\n");
		break;
	case X509_V_ERR_APPLICATION_VERIFICATION:
		LM_WARN("application verification failure\n");
		break;
	}
}

int _wolfssl_tls_update_fd(struct tcp_connection *c, int fd)
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

int _wolfssl_tls_conn_init(struct tcp_connection* c,
	struct tls_domain *tls_dom)
{
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

	if ( c->flags&F_CONN_ACCEPTED )
		/* connection created as a result of an accept -> server */
		c->proto_flags = F_TLS_DO_ACCEPT;
	else
		/* connection created as a result of a connect -> client */
		c->proto_flags = F_TLS_DO_CONNECT;

	_WOLFSSL_READ_SSL(c->extra_data) = wolfSSL_new(tls_dom->ctx);
	if (!_WOLFSSL_READ_SSL(c->extra_data)) {
		LM_ERR("failed to create SSL structure (%d:%s)\n",
			errno, strerror(errno));
		return -1;
	}

	/* put pointers to the tcp_connection and tls_domain structs
	 * in the WOLFSSL struct as extra data */
	if (!wolfSSL_set_ex_data(_WOLFSSL_READ_SSL(c->extra_data),
		SSL_EX_CONN_IDX, c)) {
		LM_ERR("Failed to store tcp_connection pointer in SSL struct\n");
		return -1;
	}
	if (!wolfSSL_set_ex_data(_WOLFSSL_READ_SSL(c->extra_data),
		SSL_EX_DOM_IDX, tls_dom)) {
		LM_ERR("Failed to store tls_domain pointer in SSL struct\n");
		return -1;
	}

	if ( c->proto_flags & F_TLS_DO_ACCEPT ) {
		LM_DBG("Setting in ACCEPT mode (server)\n");
		wolfSSL_set_accept_state(_WOLFSSL_READ_SSL(c->extra_data));
	} else {
		LM_DBG("Setting in CONNECT mode (client)\n");
		wolfSSL_set_connect_state(_WOLFSSL_READ_SSL(c->extra_data));
	}

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

void _wolfssl_tls_conn_clean(struct tcp_connection* c,
	struct tls_domain **tls_dom)
{
	void *d = NULL;

	if (c->extra_data) {
		d = wolfSSL_get_ex_data(_WOLFSSL_READ_SSL(c->extra_data), SSL_EX_DOM_IDX);

		if (c->s != -1 && process_no != 0) {
			_wolfssl_tls_update_fd(c,c->s);
			_wolfssl_tls_conn_shutdown(c);
		}

		wolfSSL_free(_WOLFSSL_READ_SSL(c->extra_data));
		if (_WOLFSSL_WRITE_SSL(c->extra_data))
			wolfSSL_free(_WOLFSSL_WRITE_SSL(c->extra_data));

		shm_free(c->extra_data);
		c->extra_data = 0;
	}

	*tls_dom = d;
}

int _wolfssl_tls_async_connect(struct tcp_connection *con, int fd,
	int timeout, trace_dest t_dst)
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

int _wolfssl_tls_write(struct tcp_connection *c, int fd, const void *buf,
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
	WOLFSSL_X509* cert;

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

		cert = wolfSSL_get_peer_certificate(ssl);
		if (cert != 0) {
			tls_dump_cert_info("tls_accept: client TLS certificate", cert);
			if (wolfSSL_get_verify_result(ssl) != X509_V_OK) {
				LM_WARN("TLS client certificate verification failed\n");
				tls_dump_verification_failure(wolfSSL_get_verify_result(ssl));
			}
			wolfSSL_X509_free(cert);
		} else {
			/* client certificate can only be retrieved when
			 * session tickets are not used */
			if (!_wolfssl_has_session_ticket(ssl))
				LM_INFO("client did not present a TLS certificate\n");
		}

		return 1;
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
	WOLFSSL_X509* cert;

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

		cert = wolfSSL_get_peer_certificate(ssl);
		if (cert != 0) {
			tls_dump_cert_info("tls_connect: server TLS certificate", cert);
			if (wolfSSL_get_verify_result(ssl) != X509_V_OK) {
				LM_WARN("TLS server certificate verification failed\n");
				tls_dump_verification_failure(wolfSSL_get_verify_result(ssl));
			}
			wolfSSL_X509_free(cert);
		} else {
			LM_ERR("server did not present a TLS certificate\n");
		}

		return 1;
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

int _wolfssl_tls_blocking_write(struct tcp_connection *c, int fd,
	const char *buf, size_t len, int handshake_timeout, int send_timeout,
	trace_dest t_dst)
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

int _wolfssl_tls_fix_read_conn(struct tcp_connection *c, int fd,
	int async_timeout, trace_dest t_dst, int lock)
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
				ret = _wolfssl_tls_async_connect(c, fd, async_timeout, t_dst);
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

int _wolfssl_tls_read(struct tcp_connection * c,struct tcp_req *r)
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

int _wolfssl_tls_conn_extra_match(struct tcp_connection *c, void *id)
{
	if ( (c->flags&F_CONN_ACCEPTED) ||
	(wolfSSL_get_ex_data(c->extra_data, SSL_EX_DOM_IDX) == id) )
		return 1; /*true*/

	return 0; /*false*/
}
