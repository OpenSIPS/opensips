/* 
 * File:   tls_conn.h
 * Author: razvan
 *
 * Created on November 11, 2015, 5:26 PM
 */

#ifndef TLS_CONN_SERVER_H
#define TLS_CONN_SERVER_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <poll.h>
#include "api.h"
#include "tls_conn.h"
#include "tls_config_helper.h"
#include "../../locking.h"


static void tls_dump_cert_info(char* s,	X509* cert)
{
	char* subj;
	char* issuer;

	subj   = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
	issuer = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);

	LM_INFO("%s subject: %s, issuer: %s\n", s ? s : "", subj, issuer);
	OPENSSL_free(subj);
	OPENSSL_free(issuer);
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

/*
 * Wrapper around SSL_accept, returns -1 on error, 0 on success
 */
static int tls_accept(struct tcp_connection *c, short *poll_events)
{
	int ret, err;
	SSL *ssl;
	X509* cert;

	if ( (c->proto_flags&F_TLS_DO_ACCEPT)==0 ) {
		LM_BUG("invalid connection state (bug in TLS code)\n");
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
		LM_INFO("New TLS connection from %s:%d accepted\n",
			ip_addr2a(&c->rcv.src_ip), c->rcv.src_port);
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
		return 0;
	} else {
		err = SSL_get_error(ssl, ret);
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
			default:
				c->state = S_CONN_BAD;
				LM_ERR("New TLS connection from %s:%d failed to accept\n",
				       ip_addr2a(&c->rcv.src_ip), c->rcv.src_port);
				if (errno != 0)
					LM_ERR("TLS error: (ret=%d, err=%d, errno=%d/%s):\n",
					       ret, err, errno, strerror(errno));
				tls_print_errstack();
				return -1;
		}
	}

	LM_BUG("bug\n");
	return -1;
}


/*
 * wrapper around SSL_connect, returns 0 on success, -1 on error
 */
static int tls_connect(struct tcp_connection *c, short *poll_events)
{
	int ret, err;
	SSL *ssl;
	X509* cert;

	if ( (c->proto_flags&F_TLS_DO_CONNECT)==0 ) {
		LM_BUG("invalid connection state (bug in TLS code)\n");
		return -1;
	}

	ssl = (SSL *) c->extra_data;

	ret = SSL_connect(ssl);
	if (ret > 0) {
		LM_INFO("New TLS connection to %s:%d established\n",
			ip_addr2a(&c->rcv.src_ip), c->rcv.src_port);
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
		return 0;
	} else {
		err = SSL_get_error(ssl, ret);
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
			default:
				LM_ERR("New TLS connection to %s:%d failed\n",
					ip_addr2a(&c->rcv.src_ip), c->rcv.src_port);
				LM_ERR("TLS error: %d (ret=%d) err=%s(%d)\n",
					err,ret,strerror(errno), errno);
				c->state = S_CONN_BAD;
				tls_print_errstack();
				return -1;
		}
	}

	LM_BUG("bug\n");
	return -1;
}


/*
 * called before tls_read, the this function should attempt tls_accept or
 * tls_connect depending on the state of the connection, if this function
 * does not transit a connection into S_CONN_OK then tcp layer would not
 * call tcp_read
 */
static int tls_fix_read_conn(struct tcp_connection *c)
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

	if ( c->proto_flags & F_TLS_DO_ACCEPT ) {
		ret = tls_update_fd(c, c->fd);
		if (!ret)
			ret = tls_accept(c, NULL);
	} else if ( c->proto_flags & F_TLS_DO_CONNECT ) {
		ret = tls_update_fd(c, c->fd);
		if (!ret)
			ret = tls_connect(c, NULL);
	}

	lock_release(&c->write_lock);

	return ret;
}

/*
 * Wrapper around SSL_write, returns number of bytes written on success, *
 * -1 on error, 0 when it would block
 */
static int tls_write(struct tcp_connection *c, int fd, const void *buf,
												size_t len, short *poll_events)
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
			LM_ERR("TLS connection to %s:%d write failed\n",
				ip_addr2a(&c->rcv.src_ip), c->rcv.src_port);
			LM_ERR("TLS write error:\n");
			c->state = S_CONN_BAD;
			tls_print_errstack();
			return -1;
		}
	}

	LM_BUG("bug\n");
	return -1;
}


/*
 * This is shamelessly stolen tsend_stream from tsend.c
 */
/*
 * fixme: probably does not work correctly
 */
static int tls_blocking_write(struct tcp_connection *c, int fd, const char *buf,
										size_t len, struct tls_mgm_binds *api)
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

	lock_get(&c->write_lock);

	if (tls_update_fd(c, fd) < 0)
		goto error;

	timeout = api->get_send_timeout();
again:
	n = 0;
	pf.events = 0;

	if ( c->proto_flags & F_TLS_DO_ACCEPT ) {
		if (tls_accept(c, &(pf.events)) < 0)
			goto error;
		timeout = api->get_handshake_timeout();
	} else if ( c->proto_flags & F_TLS_DO_CONNECT ) {
		if (tls_connect(c, &(pf.events)) < 0)
			goto error;
		timeout = api->get_handshake_timeout();
	} else {
		n = tls_write(c, fd, buf, len, &(pf.events));
		timeout = api->get_send_timeout();
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
		lock_release(&c->write_lock);
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
	lock_release(&c->write_lock);
	return -1;
}



#endif /* TLS_CONN_SERVER_H */

