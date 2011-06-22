/*
 * $Id$
 *
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2004,2005 Free Software Foundation, Inc.
 * Copyright (C) 2006 enum.at
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include <sys/poll.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <string.h>
#include <errno.h>

#include "../dprint.h"
#include "tls_server.h"
#include "tls_config.h"
#include "tls_init.h"
#include "tls_domain.h"
#include "../ip_addr.h"
#include "../mem/shm_mem.h"
#include "../timer.h"
#include "../usr_avp.h"
#include "../ut.h"

/*
 * Open questions:
 *
 * - what would happen when select exits, connection is passed
 *   to reader to perform read, but another process would acquire
 *   the same connection meanwhile, performs a write and finishes
 *   accept/connect on behalf of the reader process, thus the
 *   reader process would have nothing to read ? (resolved)
 *
 * - What happens if SSL_accept or SSL_connect gets called on
 *   already established connection (c->S_CONN_OK) ? We could
 *   save some locking provided that the functions do not screw
 *   up the connection (in tcp_fix_read_conn we would not have
 *   to lock before the switch).
 *
 * - tls_blocking_write needs fixing..
 *
 * - we need to protect ctx by a lock -- it is in shared memory
 *   and may be accessed simultaneously
 */


/*
 * Update ssl structure with new fd 
 */
static int
tls_update_fd(struct tcp_connection *c, int fd)
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


/*
 * dump ssl error stack 
 */
void
tls_print_errstack(void)
{
	int             code;

	while ((code = ERR_get_error())) {
		LM_ERR("%s\n", ERR_error_string(code, 0));
	}
}

static void tls_dump_cert_info(char* s,	X509* cert)
{
	char* subj;
	char* issuer;

	subj   = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
	issuer = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);

	LM_DBG("%s subject:%s\n", s ? s : "", subj);
	LM_DBG("%s issuer: %s\n", s ? s : "", issuer);
	OPENSSL_free(subj);
	OPENSSL_free(issuer);
}


static void tls_dump_verification_failure(long verification_result)
{
	switch(verification_result) {
	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
		LM_DBG("unable to get issuer certificate\n");
		break;
	case X509_V_ERR_UNABLE_TO_GET_CRL:
		LM_DBG("unable to get certificate CRL\n");
		break;
	case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
		LM_DBG("unable to decrypt certificate's signature\n");
		break;
	case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
		LM_DBG("unable to decrypt CRL's signature\n");
		break;
	case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
		LM_DBG("unable to decode issuer public key\n");
		break;
	case X509_V_ERR_CERT_SIGNATURE_FAILURE:
		LM_DBG("certificate signature failure\n");
		break;
	case X509_V_ERR_CRL_SIGNATURE_FAILURE:
		LM_DBG("CRL signature failure\n");
		break;
	case X509_V_ERR_CERT_NOT_YET_VALID:
		LM_DBG("certificate is not yet valid\n");
		break;
	case X509_V_ERR_CERT_HAS_EXPIRED:
		LM_DBG("certificate has expired\n");
		break;
	case X509_V_ERR_CRL_NOT_YET_VALID:
		LM_DBG("CRL is not yet valid\n");
		break;
	case X509_V_ERR_CRL_HAS_EXPIRED:
		LM_DBG("CRL has expired\n");
		break;
	case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
		LM_DBG("format error in certificate's notBefore field\n");
		break;
	case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
		LM_DBG("format error in certificate's notAfter field\n");
		break;
	case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
		LM_DBG("format error in CRL's lastUpdate field\n");
		break;
	case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
		LM_DBG("format error in CRL's nextUpdate field\n");
		break;
	case X509_V_ERR_OUT_OF_MEM:
		LM_DBG("out of memory\n");
		break;
	case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
		LM_DBG("self signed certificate\n");
		break;
	case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
		LM_DBG("self signed certificate in certificate chain\n");
		break;
	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
		LM_DBG("unable to get local issuer certificate\n");
		break;
	case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
		LM_DBG("unable to verify the first certificate\n");
		break;
	case X509_V_ERR_CERT_CHAIN_TOO_LONG:
		LM_DBG("certificate chain too long\n");
		break;
	case X509_V_ERR_CERT_REVOKED:
		LM_DBG("certificate revoked\n");
		break;
	case X509_V_ERR_INVALID_CA:
		LM_DBG("invalid CA certificate\n");
		break;
	case X509_V_ERR_PATH_LENGTH_EXCEEDED:
		LM_DBG("path length constraint exceeded\n");
		break;
	case X509_V_ERR_INVALID_PURPOSE:
		LM_DBG("unsupported certificate purpose\n");
		break;
	case X509_V_ERR_CERT_UNTRUSTED:
		LM_DBG("certificate not trusted\n");
		break;
	case X509_V_ERR_CERT_REJECTED:
		LM_DBG("certificate rejected\n");
		break;
	case X509_V_ERR_SUBJECT_ISSUER_MISMATCH:
		LM_DBG("subject issuer mismatch\n");
		break;
	case X509_V_ERR_AKID_SKID_MISMATCH:
		LM_DBG("authority and subject key identifier mismatch\n");
		break;
	case X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH:
		LM_DBG("authority and issuer serial number mismatch\n");
		break;
	case X509_V_ERR_KEYUSAGE_NO_CERTSIGN:
		LM_DBG("key usage does not include certificate signing\n");
		break;
	case X509_V_ERR_APPLICATION_VERIFICATION:
		LM_DBG("application verification failure\n");
		break;
	}
}

/*
 * Wrapper around SSL_accept, returns -1 on error, 0 on success 
 */
static int
tls_accept(struct tcp_connection *c, short *poll_events)
{
	int ret, err;
	SSL *ssl;
	X509* cert;

	if (c->state != S_CONN_ACCEPT) {
		LM_ERR("invalid connection state (bug in TLS code)\n");
		return -1;
	}

	ssl = (SSL *) c->extra_data;
#ifndef OPENSSL_NO_KRB5
	if ( ssl->kssl_ctx==NULL )
		ssl->kssl_ctx = kssl_ctx_new( );
#endif
	ret = SSL_accept(ssl);
#ifndef OPENSSL_NO_KRB5
	if ( ssl->kssl_ctx ) {
		kssl_ctx_free( ssl->kssl_ctx );
		ssl->kssl_ctx = 0;
	}
#endif
	if (ret > 0) {
		LM_DBG("TLS handshake successful\n");
		c->state = S_CONN_OK;

		LM_DBG("new connection from %s:%d using %s %s %d\n",
			ip_addr2a(&c->rcv.src_ip), c->rcv.src_port,
			SSL_get_cipher_version(ssl), SSL_get_cipher_name(ssl),
			SSL_get_cipher_bits(ssl, 0)
			);
		LM_DBG("local socket: %s:%d\n",
			ip_addr2a(&c->rcv.dst_ip), c->rcv.dst_port
			);
		cert = SSL_get_peer_certificate(ssl);
		if (cert != 0) {
			tls_dump_cert_info("tls_accept: client certificate", cert);
			if (SSL_get_verify_result(ssl) != X509_V_OK) {
				LM_WARN("client certificate verification failed!!!\n");
				tls_dump_verification_failure(SSL_get_verify_result(ssl));
			}
			X509_free(cert);
		} else {
			LM_INFO("client did not present a certificate\n");
		}
		cert = SSL_get_certificate(ssl);
		if (cert != 0) {
			tls_dump_cert_info("tls_accept: local (server) certificate", cert);
		} else {
			/* this should not happen, servers always present a cert */
			LM_ERR("local TLS server domain has no certificate\n");
		}
		return 0;
	} else {
		err = SSL_get_error(ssl, ret);
		switch (err) {
			case SSL_ERROR_ZERO_RETURN:
				LM_DBG("SSH handshake failed cleanly\n");
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
		
			default:
				LM_ERR("some error in SSL (ret=%d, err=%d, errno=%d/%s):\n",
					ret, err, errno, strerror(errno));
				c->state = S_CONN_BAD;
				tls_print_errstack();
				return -1;
		}
	}

	LM_ERR("bug\n");
	return -1;
}


/*
 * wrapper around SSL_connect, returns 0 on success, -1 on error 
 */
static int
tls_connect(struct tcp_connection *c, short *poll_events)
{
	int ret, err;
	SSL *ssl;
	X509* cert;

	if (c->state != S_CONN_CONNECT) {
		LM_ERR("invalid connection state (bug in TLS code)\n");
		return -1;
	}

	ssl = (SSL *) c->extra_data;

	ret = SSL_connect(ssl);
	if (ret > 0) {
		LM_DBG("SSL/TLS connect successuful\n");
		c->state = S_CONN_OK;
		LM_DBG("new connection to %s:%d using %s %s %d\n",
			ip_addr2a(&c->rcv.src_ip), c->rcv.src_port,
			SSL_get_cipher_version(ssl), SSL_get_cipher_name(ssl),
			SSL_get_cipher_bits(ssl, 0)
			);
		LM_DBG("sending socket: %s:%d \n",
			ip_addr2a(&c->rcv.dst_ip), c->rcv.dst_port
			);
		cert = SSL_get_peer_certificate(ssl);
		if (cert != 0) {
			tls_dump_cert_info("tls_connect: server certificate", cert);
			if (SSL_get_verify_result(ssl) != X509_V_OK) {
				LM_WARN("server certificate verification failed!!!\n");
				tls_dump_verification_failure(SSL_get_verify_result(ssl));
			}
			X509_free(cert);
		} else {
			/* this should not happen, servers always present a cert */
			LM_ERR("server did not present a certificate\n");
		}
		cert = SSL_get_certificate(ssl);
		if (cert != 0) {
			tls_dump_cert_info("tls_connect: local (client) certificate",
				cert);
		} else {
			LM_INFO("local TLS client domain does not have a certificate\n");
		}
		return 0;
	} else {
		err = SSL_get_error(ssl, ret);
		switch (err) {
			case SSL_ERROR_ZERO_RETURN:
				LM_DBG("SSL_connect failed cleanly\n");
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
				LM_ERR("something wrong in SSL: %d (ret=%d) err=%s(%d)\n",
					err,ret,strerror(errno), errno);
				c->state = S_CONN_BAD;
				tls_print_errstack();
				return -1;
		}
	}

	LM_ERR("bug\n");
	return -1;
}

/*
 * wrapper around SSL_shutdown, returns -1 on error, 0 on success 
 */
static int
tls_shutdown(struct tcp_connection *c)
{
	int             ret,
					err;
	SSL            *ssl;

	/*
	* we do not implement full ssl shutdown 
	*/
	ssl = (SSL *) c->extra_data;
	if (ssl == 0) {
		LM_ERR("no ssl data\n");
		return -1;
	}

	ret = SSL_shutdown(ssl);
	if (ret == 1) {
		LM_DBG("shutdown successful\n");
		return 0;
	} else if (ret == 0) {
		LM_DBG("first phase of 2-way handshake completed succesfuly\n");
		return 0;
	} else {
		err = SSL_get_error(ssl, ret);
		switch (err) {
			case SSL_ERROR_ZERO_RETURN:
				c->state = S_CONN_EOF;
				return 0;
		
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				c->state = S_CONN_EOF;
				return 0;
		
			default:
				LM_ERR("something wrong in SSL:\n");
				c->state = S_CONN_BAD;
				tls_print_errstack();
				return -1;
		}
	}
	
	LM_ERR("bug\n");
	return -1;
}


/*
 * Wrapper around SSL_write, returns number of bytes written on success, * 
 * -1 on error, 0 when it would block 
 */
static int
tls_write(struct tcp_connection *c, int fd, const void *buf, size_t len, short *poll_events)
{
	int             ret,
					err;
	/*
	* runs within write lock, no need to lock here 
	*/
	SSL            *ssl;

	ssl = (SSL *) c->extra_data;

	ret = SSL_write(ssl, buf, len);
	if (ret > 0) {
		LM_DBG("write was successful (%d bytes)\n", ret);
		return ret;
	} else {
		err = SSL_get_error(ssl, ret);
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
			LM_ERR("something wrong in SSL:\n");
			c->state = S_CONN_BAD;
			tls_print_errstack();
			return -1;
		}
	}

	LM_ERR("bug\n");
	return -1;
}


/*
 * Wrapper around SSL_read 
 */
/*
 * returns number of bytes read, 0 on eof and transits into S_CONN_EOF, -1 
 * on error 
 */
static int
_tls_read(struct tcp_connection *c, void *buf, size_t len)
{
	int             ret,
					err;
	SSL            *ssl;

	ssl = c->extra_data;

	ret = SSL_read(ssl, buf, len);
	if (ret > 0) {
		LM_DBG("%d bytes read\n", ret);
		return ret;
	} else {
		err = SSL_get_error(ssl, ret);
		switch (err) {
		case SSL_ERROR_ZERO_RETURN:
			LM_DBG("connection closed cleanly\n");
			/*
			* mark end of file 
			*/
			c->state = S_CONN_EOF;
			return 0;
	
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			return 0;
	
		case SSL_ERROR_SYSCALL:
			LM_ERR("SYSCALL error -> (%d) <%s>\n",errno,strerror(errno));
		default:
			LM_ERR("something wrong in SSL: %d\n",err);
			c->state = S_CONN_BAD;
			tls_print_errstack();
			return -1;
		}
	}

	LM_ERR("bug\n");
	return -1;
}



/*
 * Called when new tcp connection is accepted or connected, create ssl
 * data structures here, there is no need to acquire any lock, because the 
 * connection is being created by a new process and on other process has
 * access to it yet, this is called before adding the tcp_connection
 * structure into the hash 
 */
int
tls_tcpconn_init(struct tcp_connection *c, int sock)
{
	struct tls_domain *dom;

	struct usr_avp *avp;
	int_str val;

	/*
	* new connection within a single process, no lock necessary 
	*/
	LM_DBG("entered: Creating a whole new ssl connection\n");
	
	/*
	* do everything tcpconn_new wouldn't do when TLS 
	*/
	c->type = PROTO_TLS;
	c->rcv.proto = PROTO_TLS;
	c->flags = 0;
	c->timeout = get_ticks() + DEFAULT_TCP_CONNECTION_LIFETIME;

	if (c->state == S_CONN_ACCEPT) {
		LM_DBG("looking up socket based TLS server "
			"domain [%s:%d]\n", ip_addr2a(&c->rcv.dst_ip), c->rcv.dst_port);
		dom = tls_find_server_domain(&c->rcv.dst_ip, c->rcv.dst_port);
		if (dom) {
			LM_DBG("found socket based TLS server domain "
				"[%s:%d]\n", ip_addr2a(&dom->addr), dom->port);
				c->extra_data = SSL_new(dom->ctx);
		} else {
			LM_ERR("no TLS server domain found\n");
			return -1;
		}
	} else if (c->state == S_CONN_CONNECT) {
		avp = NULL;
		if (tls_client_domain_avp > 0) {
			avp = search_first_avp(0, tls_client_domain_avp, &val, 0);
		} else {
			LM_DBG("name based TLS client domains are disabled\n");
		}
		if (!avp) {
			LM_DBG("no TLS client doman AVP set, looking "
				"for socket based TLS client domain\n");
			dom = tls_find_client_domain(&c->rcv.src_ip, c->rcv.src_port);
			if (dom) {
				LM_DBG("found socket based TLS client domain "
					"[%s:%d]\n", ip_addr2a(&dom->addr), dom->port);
					c->extra_data = SSL_new(dom->ctx);
			} else {
				LM_ERR("no TLS client domain found\n");
				return -1;
			}
		} else {
			LM_DBG("TLS client domain AVP found = '%.*s'\n",
				val.s.len, ZSW(val.s.s));
			dom = tls_find_client_domain_name(val.s);
			if (dom) {
				LM_DBG("found name based TLS client domain "
					"'%.*s'\n", val.s.len, ZSW(val.s.s));
				c->extra_data = SSL_new(dom->ctx);
			} else {
				LM_DBG("no name based TLS client domain found, "
					"trying socket based TLS client domains\n");
				dom = tls_find_client_domain(&c->rcv.src_ip, c->rcv.src_port);
				if (dom) {
					LM_DBG("found socket based TLS client domain [%s:%d]\n",
					ip_addr2a(&dom->addr), dom->port);
					c->extra_data = SSL_new(dom->ctx);
				} else {
					LM_ERR("no TLS client domain found\n");
					return -1;
				}
			}
		}
	} else {
		LM_ERR("invalid connection state (bug in TCP code)\n");
		return -1;
	}
	if (!c->extra_data) {
		LM_ERR("failed to create SSL structure\n");
		return -1;
	}

#ifndef OPENSSL_NO_KRB5
	if ( ((SSL *)c->extra_data)->kssl_ctx ) {
		kssl_ctx_free( ((SSL *)c->extra_data)->kssl_ctx );
		((SSL *)c->extra_data)->kssl_ctx = 0;
	}
#endif

	if (c->state == S_CONN_ACCEPT) {
		LM_DBG("Setting in ACCEPT mode (server)\n");
		SSL_set_accept_state((SSL *) c->extra_data);
	} else if (c->state == S_CONN_CONNECT) {
		LM_DBG("Setting in CONNECT mode (client)\n");
		SSL_set_connect_state((SSL *) c->extra_data);
	}
	return 0;
}


/*
 * clean the extra data upon connection shut down 
 */
void
tls_tcpconn_clean(struct tcp_connection *c)
{
	/*
	* runs within global tcp lock 
	*/
	LM_DBG("entered\n");

	if (c->extra_data) {
		SSL_free((SSL *) c->extra_data);
		c->extra_data = 0;
	}
}


/*
 * perform one-way shutdown, do not wait fro notify from the remote peer 
 */
void
tls_close(struct tcp_connection *c, int fd)
{
	/*
	* runs within global tcp lock 
	*/
	LM_DBG("closing SSL connection\n");	
	tls_update_fd(c, fd);
	tls_shutdown(c);
}



/*
 * This is shamelessly stolen tsend_stream from tsend.c 
 */
/*
 * fixme: probably does not work correctly 
 */
size_t
tls_blocking_write(struct tcp_connection *c, int fd, const char *buf,
		size_t len)
{
	#define MAX_SSL_RETRIES 32
	int             written, n;
	int             timeout, retries;
	struct pollfd   pf;
	pf.fd = fd;

	written = 0;
	retries = 0;

	if (tls_update_fd(c, fd) < 0)
		goto error;

	timeout = tls_send_timeout;
again:
	n = 0;
	pf.events = 0;
	switch (c->state) {
		case S_CONN_ACCEPT:
			if (tls_accept(c, &(pf.events)) < 0)
				goto error;
			timeout = tls_handshake_timeout * 1000;
			break;
	
		case S_CONN_CONNECT:
			if (tls_connect(c, &(pf.events)) < 0)
				goto error;
			timeout = tls_handshake_timeout * 1000;
			break;
	
		case S_CONN_OK:
			n = tls_write(c, fd, buf, len, &(pf.events));
			timeout = tls_send_timeout * 1000;
			break;
	
		default:
			LM_ERR("broken connection\n");
			goto error;
	}

	if (n < 0) {
		LM_ERR("failed to send data\n");
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
		/* reset the retries if we succeded in doing something*/
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

	/*
	* 
	*/
	if (pf.events == 0)
		pf.events = POLLOUT;
		
poll_loop:
	while (1) {
		/*
		* keep tls_send_timeout in seconds to be compatible with
		* tcp_send_timeout 
		*/
		n = poll(&pf, 1, timeout);
		if (n < 0) {
			if (errno == EINTR)
				continue;	/* signal, ignore */
			else if (errno != EAGAIN && errno != EWOULDBLOCK) {
				LM_ERR("poll failed: %s [%d]\n",strerror(errno), errno);
				goto error;
			} else
				goto poll_loop;
		} else if (n == 0) {
			/*
			* timeout 
			*/
			LM_ERR("send timeout (%d)\n", timeout);
			goto error;
		}
		if (pf.revents & POLLOUT || pf.revents & POLLIN) {
			/*
			* we can read or write again 
			*/
			goto again;
		} else if (pf.revents & (POLLERR | POLLHUP | POLLNVAL)) {
			LM_ERR("bad poll flags %x\n",pf.revents);
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


/*
 * called only when a connection is in S_CONN_OK, we do not have to care
 * about accepting or connecting here, each modification of ssl data
 * structures has to be protected, another process might ask for the same
 * connection and attempt write to it which would result in updating the
 * ssl structures 
 */
size_t
tls_read(struct tcp_connection * c)
{
	/*
	* no lock acquired 
	*/
	/*
	* shamelessly stolen from tcp_read 
	*/
	int             bytes_free;
	struct tcp_req *r;
	int             fd,
					read;

	r = &c->req;
	fd = c->fd;
	bytes_free = TCP_BUF_SIZE - (int) (r->pos - r->buf);

	if (bytes_free == 0) {
		LM_ERR("buffer overrun, dropping\n");
		r->error = TCP_REQ_OVERRUN;
		return -1;
	}

	/*
	* ssl structures may be accessed from several processes, we need to
	* protect each access and modification by a lock 
	*/
	lock_get(&c->write_lock);
	tls_update_fd(c, fd);
	read = _tls_read(c, r->pos, bytes_free);
	lock_release(&c->write_lock);
	if (read > 0)
		r->pos += read;
	return read;
}


/*
 * called before tls_read, the this function should attempt tls_accept or
 * tls_connect depending on the state of the connection, if this function
 * does not transit a connection into S_CONN_OK then tcp layer would not
 * call tcp_read 
 */
int
tls_fix_read_conn(struct tcp_connection *c)
{
	/*
	* no lock acquired 
	*/
	int             ret;

	ret = 0;

	/*
	* We have to acquire the lock before testing c->state, otherwise a
	* writer could modify the structure if it gets preempted and has
	* something to write 
	*/
	lock_get(&c->write_lock);
    switch (c->state) {
		case S_CONN_ACCEPT:
			ret = tls_update_fd(c, c->fd);
			if (!ret) 
				ret = tls_accept(c, NULL);
			break;
	
		case S_CONN_CONNECT:
			ret = tls_update_fd(c, c->fd);
			if (!ret)
				ret = tls_connect(c, NULL);
			break;
	
		default:	/* fall through */
			break;
	}
	lock_release(&c->write_lock);

	return ret;
}
