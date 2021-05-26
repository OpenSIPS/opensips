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
 */

#include <openssl/ui.h>
#include <openssl/ssl.h>
#include <openssl/opensslv.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <poll.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/tcp.h>

#include "../../net/tcp_conn_defs.h"
#include "../../net/proto_tcp/tcp_common_defs.h"
#include "../tls_mgm/tls_helper.h"

#include "openssl_trace.h"

void tls_print_errstack(void);
void tls_dump_cert_info(char* s, X509* cert);

extern gen_lock_t *tls_global_lock;

#define TLS_ERR_MAX 256
static char tls_err_buf[TLS_ERR_MAX];

static int tls_get_errstack( char* result, int size )
{
	int len = 0, new, code;

	if ( !result || !size )
		return 0;


	while ((code = ERR_get_error())) {
		/* in case we overflow the buffer we still need to report the error
		 * to syslog */
		if ( len < size ) {
			new = snprintf( result + len, size - len,
						"%s\n", ERR_error_string( code, 0) );
			LM_ERR("TLS errstack: %s\n", result + len);
		} else {
			/* even though there s no place in the buffer we still have
			 * to print the errors */
			LM_ERR("TLS errstack: %s\n", ERR_error_string(code, 0));
			continue;
		}

		if ( new < size ) {
			len += new;
		} else {
			len = size;
		}
	}

	return len;
}

static void tls_dump_verification_failure(long verification_result)
{
	switch(verification_result) {
	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
		LM_ERR("unable to get issuer certificate\n");
		break;
	case X509_V_ERR_UNABLE_TO_GET_CRL:
		LM_ERR("unable to get certificate CRL\n");
		break;
	case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
		LM_ERR("unable to decrypt certificate's signature\n");
		break;
	case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
		LM_ERR("unable to decrypt CRL's signature\n");
		break;
	case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
		LM_ERR("unable to decode issuer public key\n");
		break;
	case X509_V_ERR_CERT_SIGNATURE_FAILURE:
		LM_ERR("certificate signature failure\n");
		break;
	case X509_V_ERR_CRL_SIGNATURE_FAILURE:
		LM_ERR("CRL signature failure\n");
		break;
	case X509_V_ERR_CERT_NOT_YET_VALID:
		LM_ERR("certificate is not yet valid\n");
		break;
	case X509_V_ERR_CERT_HAS_EXPIRED:
		LM_ERR("certificate has expired\n");
		break;
	case X509_V_ERR_CRL_NOT_YET_VALID:
		LM_ERR("CRL is not yet valid\n");
		break;
	case X509_V_ERR_CRL_HAS_EXPIRED:
		LM_ERR("CRL has expired\n");
		break;
	case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
		LM_ERR("format error in certificate's notBefore field\n");
		break;
	case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
		LM_ERR("format error in certificate's notAfter field\n");
		break;
	case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
		LM_ERR("format error in CRL's lastUpdate field\n");
		break;
	case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
		LM_ERR("format error in CRL's nextUpdate field\n");
		break;
	case X509_V_ERR_OUT_OF_MEM:
		LM_ERR("out of memory\n");
		break;
	case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
		LM_ERR("self signed certificate\n");
		break;
	case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
		LM_ERR("self signed certificate in certificate chain\n");
		break;
	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
		LM_ERR("unable to get local issuer certificate\n");
		break;
	case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
		LM_ERR("unable to verify the first certificate\n");
		break;
	case X509_V_ERR_CERT_CHAIN_TOO_LONG:
		LM_ERR("certificate chain too long\n");
		break;
	case X509_V_ERR_CERT_REVOKED:
		LM_ERR("certificate revoked\n");
		break;
	case X509_V_ERR_INVALID_CA:
		LM_ERR("invalid CA certificate\n");
		break;
	case X509_V_ERR_PATH_LENGTH_EXCEEDED:
		LM_ERR("path length constraint exceeded\n");
		break;
	case X509_V_ERR_INVALID_PURPOSE:
		LM_ERR("unsupported certificate purpose\n");
		break;
	case X509_V_ERR_CERT_UNTRUSTED:
		LM_ERR("certificate not trusted\n");
		break;
	case X509_V_ERR_CERT_REJECTED:
		LM_ERR("certificate rejected\n");
		break;
	case X509_V_ERR_SUBJECT_ISSUER_MISMATCH:
		LM_ERR("subject issuer mismatch\n");
		break;
	case X509_V_ERR_AKID_SKID_MISMATCH:
		LM_ERR("authority and subject key identifier mismatch\n");
		break;
	case X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH:
		LM_ERR("authority and issuer serial number mismatch\n");
		break;
	case X509_V_ERR_KEYUSAGE_NO_CERTSIGN:
		LM_ERR("key usage does not include certificate signing\n");
		break;
	case X509_V_ERR_APPLICATION_VERIFICATION:
		LM_ERR("application verification failure\n");
		break;
	}
}

int openssl_tls_update_fd(struct tcp_connection *c, int fd)
{
	/*
	* must be run from within a lock
	*/
	SSL            *ssl;

	ssl = (SSL *) c->extra_data;

	if (!SSL_set_fd(ssl, fd)) {
		LM_ERR("failed to assign socket to ssl\n");
		return -1;
	}

	LM_DBG("New fd is %d\n", fd);
	return 0;
}

int openssl_tls_conn_init(struct tcp_connection* c, struct tls_domain *tls_dom)
{
	/*
	* new connection within a single process, no lock necessary
	*/
	LM_DBG("Creating a whole new ssl connection\n");

	if ( c->flags&F_CONN_ACCEPTED ) {
		/* connection created as a result of an accept -> server */
		c->proto_flags = F_TLS_DO_ACCEPT;
	} else
		/* connection created as a result of a connect -> client */
		c->proto_flags = F_TLS_DO_CONNECT;

	c->extra_data = SSL_new(((void**)tls_dom->ctx)[process_no]);
	if (!c->extra_data) {
		LM_ERR("failed to create SSL structure (%d:%s)\n", errno, strerror(errno));
		tls_print_errstack();
		return -1;
	}

	/* put pointers to the tcp_connection and tls_domain structs
	 * in the SSL struct as extra data */
	if (!SSL_set_ex_data(c->extra_data, SSL_EX_CONN_IDX, c)) {
		LM_ERR("Failed to store tcp_connection pointer in SSL struct\n");
		return -1;
	}
	if (!SSL_set_ex_data(c->extra_data, SSL_EX_DOM_IDX, tls_dom)) {
		LM_ERR("Failed to store tls_domain pointer in SSL struct\n");
		return -1;
	}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#ifndef OPENSSL_NO_KRB5
	if ( ((SSL *)c->extra_data)->kssl_ctx ) {
		kssl_ctx_free( ((SSL *)c->extra_data)->kssl_ctx );
		((SSL *)c->extra_data)->kssl_ctx = 0;
	}
#endif
#endif

	if ( c->proto_flags & F_TLS_DO_ACCEPT ) {
		LM_DBG("Setting in ACCEPT mode (server)\n");
		SSL_set_accept_state((SSL *) c->extra_data);
	} else {
		LM_DBG("Setting in CONNECT mode (client)\n");
		SSL_set_connect_state((SSL *) c->extra_data);
	}

	/* if the connection is asynchronous, allow partial writes */
	if (c->async && !SSL_set_mode((SSL *)c->extra_data,
			SSL_MODE_ENABLE_PARTIAL_WRITE|SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER))
		LM_ERR("Failed to enable non-blocking write! Running in blocking mode!\n");
	return 0;
}

static int openssl_tls_conn_shutdown(struct tcp_connection *c)
{
	int             ret,
					err;
	SSL            *ssl;

	/* If EOF or other error on connection, no point in attempting to
	 * do further writing & reading on the con */
	if (c->state == S_CONN_BAD ||
		c->state == S_CONN_ERROR ||
		c->state == S_CONN_EOF)
		return 0;
	/*
	* we do not implement full ssl shutdown
	*/
	ssl = (SSL *) c->extra_data;
	if (ssl == 0) {
		LM_ERR("no ssl data\n");
		return -1;
	}

	#ifndef NO_SSL_GLOBAL_LOCK
	lock_get(tls_global_lock);
	#endif

	ERR_clear_error();

	ret = SSL_shutdown(ssl);
	if (ret == 1) {
		#ifndef NO_SSL_GLOBAL_LOCK
		lock_release(tls_global_lock);
		#endif
		LM_DBG("shutdown successful\n");
		return 0;
	} else if (ret == 0) {
		#ifndef NO_SSL_GLOBAL_LO
		lock_release(tls_global_lock);
		#endif
		LM_DBG("first phase of 2-way handshake completed succesfuly\n");
		return 0;
	} else {
		err = SSL_get_error(ssl, ret);
		switch (err) {
			case SSL_ERROR_ZERO_RETURN:
				#ifndef NO_SSL_GLOBAL_LOCK
				lock_release(tls_global_lock);
				#endif

				c->state = S_CONN_EOF;

				return 0;

			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				#ifndef NO_SSL_GLOBAL_LOCK
				lock_release(tls_global_lock);
				#endif

				c->state = S_CONN_EOF;
				return 0;

			default:
				LM_ERR("something wrong in SSL: %d, %d, %s\n",err,errno,strerror(errno));
				/* fall through */

			case SSL_ERROR_SYSCALL:
				c->state = S_CONN_BAD;
				tls_print_errstack();

				#ifndef NO_SSL_GLOBAL_LOCK
				lock_release(tls_global_lock);
				#endif

				return -1;
		}
	}

	LM_ERR("bug\n");
	return -1;
}

void openssl_tls_conn_clean(struct tcp_connection *c, struct tls_domain **tls_dom)
{
	void *d = NULL;

	if (c->extra_data) {
		d = SSL_get_ex_data(c->extra_data, SSL_EX_DOM_IDX);

		openssl_tls_update_fd(c,c->s);
		openssl_tls_conn_shutdown(c);
		SSL_free((SSL *) c->extra_data);
		c->extra_data = 0;
	}

	*tls_dom = d;
}

static int openssl_tls_connect(struct tcp_connection *c, short *poll_events,
	trace_dest t_dst)
{
	int ret, err;
	SSL *ssl;
	X509* cert;

	str tls_err_s;

	if ( (c->proto_flags&F_TLS_DO_CONNECT)==0 ) {
		LM_BUG("invalid connection state (bug in TLS code)\n");
		return -1;
	}

	ssl = (SSL *) c->extra_data;

	#ifndef NO_SSL_GLOBAL_LOCK
	lock_get(tls_global_lock);
	#endif

	ERR_clear_error();

	ret = SSL_connect(ssl);
	if (ret > 0) {
		#ifndef NO_SSL_GLOBAL_LOCK
		lock_release(tls_global_lock);
		#endif

		LM_INFO("New TLS connection to %s:%d established\n",
			ip_addr2a(&c->rcv.src_ip), c->rcv.src_port);
		trace_tls( c, ssl, TRANS_TRACE_CONNECTED,
				TRANS_TRACE_SUCCESS, &CONNECT_FAIL);

		tls_send_trace_data(c, t_dst);

		c->proto_flags &= ~F_TLS_DO_CONNECT;
		LM_DBG("new TLS connection to %s:%d using %s %s %d\n",
			ip_addr2a(&c->rcv.src_ip), c->rcv.src_port,
			SSL_get_cipher_version(ssl), SSL_get_cipher_name(ssl),
			SSL_get_cipher_bits(ssl, 0)
			);
		LM_DBG("sending socket: %s:%d \n",
			ip_addr2a(&c->rcv.dst_ip), c->rcv.dst_port
			);
		cert = SSL_get_peer_certificate(ssl);
		if (cert != 0) {
			tls_dump_cert_info("tls_connect: server TLS certificate", cert);
			if (SSL_get_verify_result(ssl) != X509_V_OK) {
				LM_WARN("TLS server certificate verification failed\n");
				tls_dump_verification_failure(SSL_get_verify_result(ssl));
			}
			X509_free(cert);
		} else {
			/* this should not happen, servers always present a cert */
			LM_ERR("server did not present a TLS certificate\n");
		}
		cert = SSL_get_certificate(ssl);
		if (cert != 0) {
			tls_dump_cert_info("tls_connect: local TLS client certificate",
				cert);
		} else {
			LM_INFO("local TLS client domain does not have a certificate\n");
		}
		return 1;
	} else {
		err = SSL_get_error(ssl, ret);
		switch (err) {
			case SSL_ERROR_ZERO_RETURN:
			#ifndef NO_SSL_GLOBAL_LOCK
			lock_release(tls_global_lock);
			#endif

				LM_INFO("New TLS connection to %s:%d failed cleanly\n",
					ip_addr2a(&c->rcv.src_ip), c->rcv.src_port);

				trace_tls( c, ssl, TRANS_TRACE_CONNECTED,
						TRANS_TRACE_FAILURE, &CONNECT_FAIL);

				tls_send_trace_data(c, t_dst);

				c->state = S_CONN_BAD;
				return -1;
			case SSL_ERROR_WANT_READ:
				#ifndef NO_SSL_GLOBAL_LOCK
				lock_release(tls_global_lock);
				#endif

				if (poll_events)
					*poll_events = POLLIN;
				return 0;
			case SSL_ERROR_WANT_WRITE:
				#ifndef NO_SSL_GLOBAL_LOCK
				lock_release(tls_global_lock);
				#endif

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

				LM_ERR("TLS error: %d (ret=%d) err=%s(%d)\n",
					err,ret,strerror(errno), errno);
				c->state = S_CONN_BAD;

				if ( TRACE_IS_ON( c ) ) {
					if ( ( tls_err_s.len =
							tls_get_errstack( tls_err_buf, TLS_ERR_MAX ) ) == 0 ) {
						tls_err_s.len = snprintf( tls_err_buf, TLS_ERR_MAX,
								"New TLS connection failed to connect" );
					}
					tls_err_s.s = tls_err_buf;
					trace_tls( c, ssl, TRANS_TRACE_CONNECTED,
							TRANS_TRACE_FAILURE, &tls_err_s);

					tls_send_trace_data(c, t_dst);
				} else {
					tls_print_errstack();
				}

				#ifndef NO_SSL_GLOBAL_LOCK
				lock_release(tls_global_lock);
				#endif

				return -1;
		}
	}

	LM_BUG("bug\n");
	return -1;
}

static int openssl_tls_accept(struct tcp_connection *c, short *poll_events)
{
	int ret, err;
	SSL *ssl;
	X509* cert;

	str tls_err_s;

	if ( (c->proto_flags&F_TLS_DO_ACCEPT)==0 ) {
		LM_BUG("invalid connection state (bug in TLS code)\n");
		return -1;
	}

	ssl = (SSL *) c->extra_data;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#ifndef OPENSSL_NO_KRB5
	if ( ssl->kssl_ctx==NULL )
		ssl->kssl_ctx = kssl_ctx_new( );
#endif
#endif
	#ifndef NO_SSL_GLOBAL_LOCK
	lock_get(tls_global_lock);
	#endif
	ERR_clear_error();
	ret = SSL_accept(ssl);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#ifndef OPENSSL_NO_KRB5
	if ( ssl->kssl_ctx ) {
		kssl_ctx_free( ssl->kssl_ctx );
		ssl->kssl_ctx = 0;
	}
#endif
#endif

	if (ret > 0) {
		#ifndef NO_SSL_GLOBAL_LOCK
		lock_release(tls_global_lock);
		#endif

		LM_INFO("New TLS connection from %s:%d accepted\n",
			ip_addr2a(&c->rcv.src_ip), c->rcv.src_port);
		trace_tls( c, ssl, TRANS_TRACE_ACCEPTED, TRANS_TRACE_SUCCESS, &ACCEPT_OK);

		/* TLS accept done, reset the flag */
		c->proto_flags &= ~F_TLS_DO_ACCEPT;

		LM_DBG("new TLS connection from %s:%d using %s %s %d\n",
			ip_addr2a(&c->rcv.src_ip), c->rcv.src_port,
			SSL_get_cipher_version(ssl), SSL_get_cipher_name(ssl),
			SSL_get_cipher_bits(ssl, 0) );
		LM_DBG("local socket: %s:%d\n",
			ip_addr2a(&c->rcv.dst_ip), c->rcv.dst_port );
		cert = SSL_get_peer_certificate(ssl);
		if (cert != 0) {
			tls_dump_cert_info("tls_accept: client TLS certificate", cert);
			if (SSL_get_verify_result(ssl) != X509_V_OK) {
				LM_WARN("TLS client certificate verification failed\n");
				tls_dump_verification_failure(SSL_get_verify_result(ssl));
			}
			X509_free(cert);
		} else {
			LM_INFO("Client did not present a TLS certificate\n");
		}
		cert = SSL_get_certificate(ssl);
		if (cert != 0) {
			tls_dump_cert_info("tls_accept: local TLS server certificate",
				cert);
		} else {
			/* this should not happen, servers always present a cert */
			LM_ERR("local TLS server domain has no certificate\n");
		}
		return 1;
	} else {
		err = SSL_get_error(ssl, ret);
		switch (err) {
			case SSL_ERROR_ZERO_RETURN:
				#ifndef NO_SSL_GLOBAL_LOCK
				lock_release(tls_global_lock);
				#endif

				LM_INFO("TLS connection from %s:%d accept failed cleanly\n",
					ip_addr2a(&c->rcv.src_ip), c->rcv.src_port);

				trace_tls( c, ssl, TRANS_TRACE_ACCEPTED,
						TRANS_TRACE_FAILURE, &ACCEPT_FAIL);

				c->state = S_CONN_BAD;

				return -1;
			case SSL_ERROR_WANT_READ:
				#ifndef NO_SSL_GLOBAL_LOCK
				lock_release(tls_global_lock);
				#endif

				if (poll_events)
					*poll_events = POLLIN;
				return 0;
			case SSL_ERROR_WANT_WRITE:
				#ifndef NO_SSL_GLOBAL_LOCK
				lock_release(tls_global_lock);
				#endif

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

				if (errno != 0) {
					LM_ERR("TLS error: (ret=%d, err=%d, errno=%d/%s):\n",
					       ret, err, errno, strerror(errno));
				}

				if ( TRACE_IS_ON( c ) ) {
					if ( ( tls_err_s.len =
							tls_get_errstack( tls_err_buf, TLS_ERR_MAX ) ) == 0 ) {
						if ( errno ) {
							tls_err_s.len = snprintf( tls_err_buf, TLS_ERR_MAX,
									"TLS error: (ret=%d, err=%d, errno=%d/%s)",
										ret, err, errno, strerror(errno));
						} else {
							tls_err_s.len = snprintf( tls_err_buf, TLS_ERR_MAX,
									"New TLS connection failed to accept" );
						}
					}
					tls_err_s.s = tls_err_buf;
					trace_tls( c, ssl, TRANS_TRACE_ACCEPTED,
							TRANS_TRACE_FAILURE, &tls_err_s);
				} else {
					tls_print_errstack();
				}

				#ifndef NO_SSL_GLOBAL_LOCK
				lock_release(tls_global_lock);
				#endif

				return -1;
		}
	}

	LM_BUG("bug\n");
	return -1;
}

int openssl_tls_async_connect(struct tcp_connection *con, int fd,
	int timeout, trace_dest t_dst)
{
	unsigned int elapsed,to;
	unsigned int err_len;
	int poll_err, n, err;
	struct timeval begin;
	str tls_err_s;
#if defined(HAVE_SELECT) && defined(BLOCKING_USE_SELECT)
	fd_set sel_set;
	fd_set orig_set;
	struct timeval timeout_val;
#else
	struct pollfd pf;
#endif
	SSL *ssl = (SSL *)con->extra_data;

	/* attempt to do connect and see if we do block or not */
	poll_err=0;
	elapsed = 0;
	to = timeout*1000;
	fd = con->fd;

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
		#ifndef NO_SSL_GLOBAL_LOCK
		lock_get(tls_global_lock);
		#endif

		n = SSL_connect(ssl);
		if (n > 0) {
			#ifndef NO_SSL_GLOBAL_LOC
			lock_release(tls_global_lock);
			#endif

			LM_INFO("new TLS connection to %s:%d established\n",
					ip_addr2a(&con->rcv.src_ip), con->rcv.src_port);
			trace_tls(con, ssl, TRANS_TRACE_CONNECTED,
					TRANS_TRACE_SUCCESS, &CONNECT_FAIL);

			tls_send_trace_data(con, t_dst);
			con->proto_flags &= ~F_TLS_DO_CONNECT;
			return 1;
		} else if (n == 0) {
			err = SSL_get_error(ssl, n);
			#ifndef NO_SSL_GLOBAL_LOC
			lock_release(tls_global_lock);
			#endif

			LM_ERR("Failed to connect to %s:%d %d:%d (%s)\n",
					ip_addr2a(&con->rcv.src_ip), con->rcv.src_port,
					err, errno, strerror(errno));

			goto failure;
		}
		err = SSL_get_error(ssl, n);
		switch (err) {
			case SSL_ERROR_ZERO_RETURN:
				#ifndef NO_SSL_GLOBAL_LOCK
				lock_release(tls_global_lock);
				#endif

				LM_INFO("New TLS connection to %s:%d failed cleanly\n",
					ip_addr2a(&con->rcv.src_ip), con->rcv.src_port);

				goto failure;
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				#ifndef NO_SSL_GLOBAL_LOCK
				lock_release(tls_global_lock);
				#endif

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
				#ifndef NO_SSL_GLOBAL_LOCK
				lock_release(tls_global_lock);
				#endif

				LM_ERR("SSL_ERROR_SYSCALL err=%s(%d)\n",
					strerror(errno), errno);
			default:
				LM_ERR("New TLS connection to %s:%d failed\n",
					ip_addr2a(&con->rcv.src_ip), con->rcv.src_port);

				LM_ERR("TLS error: %d (ret=%d) err=%s(%d)\n",
					err, n, strerror(errno), errno);
				con->state = S_CONN_BAD;

				if ( TRACE_IS_ON( con ) ) {
					if ( ( tls_err_s.len =
							tls_get_errstack( tls_err_buf, TLS_ERR_MAX ) ) == 0 ) {
						tls_err_s.len = snprintf( tls_err_buf, TLS_ERR_MAX,
								"New TLS connection failed to connect" );
					}
					tls_err_s.s = tls_err_buf;
					trace_tls( con, ssl, TRANS_TRACE_CONNECTED,
							TRANS_TRACE_FAILURE, &tls_err_s);

					tls_send_trace_data(con, t_dst);
				}
				tls_print_errstack();

				#ifndef NO_SSL_GLOBAL_LOCK
				lock_release(tls_global_lock);
				#endif

				return -1;
		}
	}
failure:
	trace_tls(con, ssl, TRANS_TRACE_CONNECTED,
			TRANS_TRACE_FAILURE, &CONNECT_FAIL);

	tls_send_trace_data(con, t_dst);

	con->state = S_CONN_BAD;
	return -1;
}

int openssl_tls_write(struct tcp_connection *c, int fd, const void *buf,
	size_t len, short *poll_events)
{
	int             ret,
					err;
	/*
	* runs within write lock, no need to lock here
	*/
	SSL            *ssl;

	ssl = (SSL *) c->extra_data;

	#ifndef NO_SSL_GLOBAL_LOCK
	lock_get(tls_global_lock);
	#endif

	ERR_clear_error();

	ret = SSL_write(ssl, buf, len);
	if (ret > 0) {
		#ifndef NO_SSL_GLOBAL_LOC
		lock_release(tls_global_lock);
		#endif

		LM_DBG("write was successful (%d bytes)\n", ret);
		return ret;
	} else {
		err = SSL_get_error(ssl, ret);
		switch (err) {
		case SSL_ERROR_ZERO_RETURN:
			#ifndef NO_SSL_GLOBAL_LOCK
			lock_release(tls_global_lock);
			#endif

			LM_DBG("connection closed cleanly\n");
			c->state = S_CONN_EOF;
			return -1;
		case SSL_ERROR_WANT_READ:
			#ifndef NO_SSL_GLOBAL_LOCK
			lock_release(tls_global_lock);
			#endif

			if (poll_events)
				*poll_events = POLLIN;
			return 0;
		case SSL_ERROR_WANT_WRITE:
			#ifndef NO_SSL_GLOBAL_LOCK
			lock_release(tls_global_lock);
			#endif

			if (poll_events)
				*poll_events = POLLOUT;
			return 0;
		default:
			LM_ERR("TLS connection to %s:%d write failed (%d:%d:%d)\n",
				ip_addr2a(&c->rcv.src_ip), c->rcv.src_port, err, ret, errno);
			LM_ERR("TLS write error:\n");
			c->state = S_CONN_BAD;
			tls_print_errstack();

			#ifndef NO_SSL_GLOBAL_LOCK
			lock_release(tls_global_lock);
			#endif

			return -1;
		}
	}

	LM_BUG("bug\n");
	return -1;
}

int openssl_tls_blocking_write(struct tcp_connection *c, int fd,
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

	if (openssl_tls_update_fd(c, fd) < 0)
		goto error;

	timeout = send_timeout;
again:
	n = 0;
	pf.events = 0;

	if ( c->proto_flags & F_TLS_DO_ACCEPT ) {
		if (openssl_tls_accept(c, &(pf.events)) < 0)
			goto error;
		timeout = handshake_timeout;
	} else if ( c->proto_flags & F_TLS_DO_CONNECT ) {
		if (openssl_tls_connect(c, &(pf.events), t_dst) < 0)
			goto error;
		timeout = handshake_timeout;
	} else {
		n = openssl_tls_write(c, fd, buf, len, &(pf.events));
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

int openssl_tls_fix_read_conn(struct tcp_connection *c, int fd,
	int async_timeout, trace_dest t_dst, int lock)
{
	int ret = 0;

	if (lock)
		lock_get(&c->write_lock);

	if ( c->proto_flags & F_TLS_DO_ACCEPT ) {
		ret = openssl_tls_update_fd(c, fd);
		if (!ret)
			ret = openssl_tls_accept(c, NULL);
	} else if ( c->proto_flags & F_TLS_DO_CONNECT ) {
		ret = openssl_tls_update_fd(c, fd);
		if (!ret) {
			if (c->async && async_timeout)
				ret = openssl_tls_async_connect(c, fd, async_timeout, t_dst);
			else
				ret = openssl_tls_connect(c, NULL, t_dst);
		}
	} else
		ret = 1;

	if (lock)
		lock_release(&c->write_lock);

	return ret;
}

static int openssl_read(struct tcp_connection *c, void *buf, size_t len)
{
	int ret, err;
	SSL *ssl;

	ssl = c->extra_data;

	#ifndef NO_SSL_GLOBAL_LO
	lock_get(tls_global_lock);
	#endif

	ERR_clear_error();

	ret = SSL_read(ssl, buf, len);
	if (ret > 0) {
		#ifndef NO_SSL_GLOBAL_LOC
		lock_release(tls_global_lock);
		#endif

		LM_DBG("%d bytes read\n", ret);
		return ret;
	} else if (ret == 0) {
		#ifndef NO_SSL_GLOBAL_LOC
		lock_release(tls_global_lock);
		#endif

		/* unclean shutdown of the other peer */
		c->state = S_CONN_EOF;
		return 0;
	} else {
		err = SSL_get_error(ssl, ret);
		switch (err) {
		case SSL_ERROR_ZERO_RETURN:
			#ifndef NO_SSL_GLOBAL_LOCK
			lock_release(tls_global_lock);
			#endif

			LM_DBG("TLS connection to %s:%d closed cleanly\n",
				ip_addr2a(&c->rcv.src_ip), c->rcv.src_port);
			/*
			* mark end of file
			*/
			c->state = S_CONN_EOF;
			return 0;

		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			#ifndef NO_SSL_GLOBAL_LOCK
			lock_release(tls_global_lock);
			#endif

			return 0;

		case SSL_ERROR_SYSCALL:
			LM_ERR("SYSCALL error -> (%d) <%s>\n",errno,strerror(errno));
			/* fall through */
		default:
			LM_ERR("TLS connection to %s:%d read failed\n",
				ip_addr2a(&c->rcv.src_ip), c->rcv.src_port);
			LM_ERR("TLS read error: %d\n",err);
			c->state = S_CONN_BAD;
			tls_print_errstack();

			#ifndef NO_SSL_GLOBAL_LOCK
			lock_release(tls_global_lock);
			#endif

			return -1;
		}
	}

	LM_BUG("bug\n");
	return -1;
}

int openssl_tls_read(struct tcp_connection * c,struct tcp_req *r)
{
	int             bytes_free;
	int             fd, read;

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
	openssl_tls_update_fd(c, fd);
	read = openssl_read(c, r->pos, bytes_free);
	lock_release(&c->write_lock);
	if (read > 0)
		r->pos += read;
	return read;
}

int openssl_tls_conn_extra_match(struct tcp_connection *c, void *id)
{
	if ( (c->flags&F_CONN_ACCEPTED) ||
	(SSL_get_ex_data(c->extra_data, SSL_EX_DOM_IDX) == id) )
		return 1; /*true*/

	return 0; /*false*/
}
