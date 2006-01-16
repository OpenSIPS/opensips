/*
 * $Id$
 *
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2004,2005 Free Software Foundation, Inc.
 *
 * This file is part of openser, a free SIP server.
 *
 * openser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * openser is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "../dprint.h"
#include "tls_server.h"
#include "tls_config.h"
#include "tls_init.h"
#include "tls_domain.h"
#include "../ip_addr.h"
#include <sys/poll.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "../mem/shm_mem.h"
#include "../timer.h"

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

	/* DBG("tls_update_fd: Entered\n"); //noisy */

	ssl = (SSL *) c->extra_data;

	if (!SSL_set_fd(ssl, fd)) {
		LOG(L_ERR, "tls_update_fd: Error while assigning socket to ssl\n");
		return -1;
	}

	DBG("tls_update_fd: New fd is %d\n", fd);
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
		LOG(L_ERR, "tls_error: %s\n", ERR_error_string(code, 0));
	}
}

/*
	Output some warning info in case the verification 
	fails, but no verification was requested, or it was 
	not mandatory.
 */
int tls_after_handshake (SSL * ssl ) {
	X509 *peer;
	int verify_res;
	verify_res = SSL_get_verify_result( ssl );
	
	/* If we are a client, with no verification of the server cert,
	warn in case the server certificate verification failed*/
	if( ssl->verify_mode == SSL_VERIFY_NONE 
			&& ssl->type == SSL_ST_CONNECT 
			&& verify_res != X509_V_OK ) {
		LOG( L_WARN, "tls_after_handshake: Server certificate verification failed!\n");
		return 1;
	}
	
	/* If we are a server, with only VERIFY_PEER. This flags makes
	the server request a client certificate. The handshake succeeds if:
		- the client does not send a certificate
		- if the client sends a certificate and this is correctly verified */
	if( ((ssl->verify_mode & SSL_VERIFY_PEER) == SSL_VERIFY_PEER) 
			&& ssl->type == SSL_ST_ACCEPT ) {
		peer = SSL_get_peer_certificate( ssl );
		if( peer == NULL ) {
			LOG( L_WARN, "tls_after_handshake: No client certificate presented!\n");
		} else {
			X509_free( peer );
		}
		return 1;
	}
	return 1;
}

/*
 * Wrapper around SSL_accept, returns -1 on error, 0 on success 
 */
static int
tls_accept(struct tcp_connection *c)
{
	int             ret,
					err;
	SSL            *ssl;

	/* DBG("tls_accept: Entered\n"); //very noisy debug */

	if (c->state != S_CONN_ACCEPT) {
		LOG(L_ERR,
			"tcp_accept: Invalid connection state (bug in TLS code)\n");
		return -1;
	}

	ssl = (SSL *) c->extra_data;

	ret = SSL_accept(ssl);
	if (ret > 0) {
		DBG("tls_accept: TLS handshake successful\n");
		c->state = S_CONN_OK;
		tls_after_handshake(ssl);
		return 0;
	} else {
		err = SSL_get_error(ssl, ret);
		switch (err) {
			case SSL_ERROR_ZERO_RETURN:
				DBG("tls_accept: SSH handshake failed cleanly\n");
				c->state = S_CONN_BAD;
				return -1;
		
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				
				/*DBG("tls_accept: Not complete yet, more runs necessary\n"); //noisy */
				/*
				* nothing to do here 
				*/
				return 0;
		
			default:
				LOG(L_ERR, "tls_accept: Error in SSL:\n");
				c->state = S_CONN_BAD;
				tls_print_errstack();
				return -1;
		}
	}

	LOG(L_ERR, "tls_accept: Bug in tls_accept\n");
	return -1;
}


/*
 * wrapper around SSL_connect, returns 0 on success, -1 on error 
 */
static int
tls_connect(struct tcp_connection *c)
{
	SSL            *ssl;
	int             ret,
					err;

	/* DBG("tls_connect: Entered\n"); //Very noisy debug  */

	if (c->state != S_CONN_CONNECT) {
		LOG(L_ERR,
			"tls_connect: Invalid connection state (bug in TLS code)\n");
		return -1;
	}

	ssl = (SSL *) c->extra_data;

	ret = SSL_connect(ssl);
	if (ret > 0) {
		DBG("tls_connect: SSL/TLS connect successuful\n");
		c->state = S_CONN_OK;
		tls_after_handshake(ssl);
		return 0;
    } else {
		err = SSL_get_error(ssl, ret);
		switch (err) {
			case SSL_ERROR_ZERO_RETURN:
				DBG("tls_connect: SSL_connect failed cleanly\n");
				c->state = S_CONN_BAD;
				return -1;
		
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				/* Do not use this debug ... it generates a lot of noise*/
				/*DBG("tls_connect: Not complete yet, more runs necessary\n");*/
				/*
				* nothing to do here 
				*/
				return 0;
		
			default:
				LOG(L_ERR, "tls_connect: Error in SSL:\n");
				c->state = S_CONN_BAD;
				tls_print_errstack();
				return -1;
		}
	}

	LOG(L_ERR, "tls_connect: Bug in tls_connect\n");
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

	/* DBG("tls_shutdown: Entered\n"); //noisy */

	/*
	* we do not implement full ssl shutdown 
	*/
	ssl = (SSL *) c->extra_data;
	if (ssl == 0) {
		LOG(L_ERR, "tls_shutdown: No ssl data\n");
		return -1;
	}

	ret = SSL_shutdown(ssl);
	if (ret == 1) {
		DBG("tls_shutdown: Shutdown successful\n");
		return 0;
    } else if (ret == 0) {
		DBG("tls_shutdown: First phase of 2-way handshake completed succesfuly\n");
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
				LOG(L_ERR, "tls_shutdown: Error in SSL:\n");
				c->state = S_CONN_BAD;
				tls_print_errstack();
				return -1;
		}
	}
	
	LOG(L_ERR, "tls_shutdown: Bug in tls_shutdown\n");
	return -1;
}


/*
 * Wrapper around SSL_write, returns number of bytes written on success, * 
 * -1 on error, 0 when it would block 
 */
static int
tls_write(struct tcp_connection *c, int fd, const void *buf, size_t len)
{
	int             ret,
					err;
	/*
	* runs within write lock, no need to lock here 
	*/
	SSL            *ssl;

	/* DBG("tls_write: Entered\n"); //noisy */

	ssl = (SSL *) c->extra_data;

	ret = SSL_write(ssl, buf, len);
	if (ret > 0) {
		DBG("tls_write: Write was successful (%d bytes)\n", ret);
		return ret;
	} else {
		err = SSL_get_error(ssl, ret);
		switch (err) {
		case SSL_ERROR_ZERO_RETURN:
			DBG("tls_write: Connection closed cleanly\n");
			c->state = S_CONN_EOF;
			return -1;
	
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			/* Do not use this debug ... it generates a lot of noise*/
			/*DBG("tls_write: Not completed yet, more calls to tls_write are necessary\n"); */
			return 0;
	
		default:
			LOG(L_ERR, "tls_write: Error in SSL:\n");
			c->state = S_CONN_BAD;
			tls_print_errstack();
			return -1;
		}
	}

	LOG(L_ERR, "tls_write: Bug in tls_write\n");
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

	/* DBG("_tls_read: Entered\n"); //noisy */

	ssl = c->extra_data;

	ret = SSL_read(ssl, buf, len);
	if (ret > 0) {
		DBG("_tls_read: %d bytes read\n", ret);
		return ret;
	} else {
		err = SSL_get_error(ssl, ret);
		switch (err) {
		case SSL_ERROR_ZERO_RETURN:
			DBG("_tls_read: Connection closed cleanly\n");
			/*
			* mark end of file 
			*/
			c->state = S_CONN_EOF;
			return 0;
	
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			/* Do not use this debug ... it generates a lot of noise*/
			/*DBG("_tls_read: nothing to read\n");*/
			return 0;
	
		default:
			LOG(L_ERR, "_tls_read: Error in SSL:\n");
			c->state = S_CONN_BAD;
			tls_print_errstack();
			return -1;
		}
	}

	LOG(L_ERR, "_tls_read: Bug in _tls_read\n");
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

	/*
	* new connection within a single process, no lock necessary 
	*/
	DBG("tls_tcpconn_init: Entered: Creating a whole new ssl connection\n");
	
	/*
	* do everything tcpconn_new wouldn't do when TLS 
	*/
	c->type = PROTO_TLS;
	c->rcv.proto = PROTO_TLS;
	c->flags = 0;
	c->timeout = get_ticks() + DEFAULT_TCP_CONNECTION_LIFETIME;

	if (c->state == S_CONN_ACCEPT) {
		DBG("tls_tcpconn_init: Looking up tls domain [%s:%d]\n",
			ip_addr2a(&c->rcv.dst_ip), c->rcv.dst_port);
		dom = tls_find_domain(&c->rcv.dst_ip, c->rcv.dst_port);
		if (dom) {
			DBG("tls_tcpconn_init: Found tls_domain [%s:%d]\n",
			ip_addr2a(&dom->addr), dom->port);
			c->extra_data = SSL_new(dom->ctx);
		} else {
			DBG("tls_tcpconn_init: Using default tls settings\n");
			c->extra_data = SSL_new(default_ctx);
		}
	} else if (c->state == S_CONN_CONNECT) {
		c->extra_data = SSL_new(default_ctx);
	} else {
		LOG(L_ERR,
			"tls_tcpconn_init: Invalid connection state (bug in TCP code)\n");
		return -1;
	}
	if (!c->extra_data) {
		LOG(L_ERR,
			"tls_tcpconn_init: Error while creating SSL structure\n");
		return -1;
	}

	if (c->state == S_CONN_ACCEPT) {
		DBG("tls_tcpconn_init: Setting in ACCEPT mode (server)\n");
		SSL_set_accept_state((SSL *) c->extra_data);
	} else if (c->state == S_CONN_CONNECT) {
		DBG("tls_tcpconn_init: Setting in CONNECT mode (client)\n");
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
	DBG("tls_tcpconn_clean: Entered\n");

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
	DBG("tls_close: Closing SSL connection\n");	
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
	int             written,
					n;
	int             timeout;
	struct pollfd   pf;
	pf.fd = fd;
	pf.events = POLLOUT | POLLIN;	/* we need both because of ssl
					 * library */

	/* DBG("tls_blocking_write: Entered\n"); //noisy */

	written = 0;

	if (tls_update_fd(c, fd) < 0)
		goto error;

	timeout = tls_send_timeout;
  again:
	n = 0;
	switch (c->state) {
		case S_CONN_ACCEPT:
			if (tls_accept(c) < 0)
				goto error;
			timeout = tls_handshake_timeout * 1000;
			break;
	
		case S_CONN_CONNECT:
			if (tls_connect(c) < 0)
				goto error;
			timeout = tls_handshake_timeout * 1000;
			break;
	
		case S_CONN_OK:
			n = tls_write(c, fd, buf, len);
			timeout = tls_send_timeout * 1000;
			break;
	
		default:
			LOG(L_ERR, "tls_blocking_write: Broken connection\n");
			goto error;
    }

	if (n < 0) {
		LOG(L_ERR, "tls_blocking_write: failed to send data\n");
		goto error;
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
				LOG(L_ERR, "tls_blocking_write: poll failed: %s [%d]\n",
						strerror(errno), errno);
				goto error;
			} else
				goto poll_loop;
		} else if (n == 0) {
			/*
			* timeout 
			*/
			LOG(L_ERR, "tls_blocking_write: send timeout (%d)\n", timeout);
			goto error;
		}
		if (pf.revents & POLLOUT || pf.revents & POLLIN) {
			/*
			* we can read or write again 
			*/
			goto again;
		} else if (pf.revents & (POLLERR | POLLHUP | POLLNVAL)) {
			LOG(L_ERR, "tls_blocking_write: bad poll flags %x\n",
					pf.revents);
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

	/* DBG("tls_read: Entered\n"); //noisy */

	r = &c->req;
	fd = c->fd;
	bytes_free = TCP_BUF_SIZE - (int) (r->pos - r->buf);

	if (bytes_free == 0) {
		LOG(L_ERR, "tls_read: buffer overrun, dropping\n");
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
	/* DBG("tls_fix_read_conn: Entered\n"); //noisy */

	ret = 0;

	/*
	* We have to acquire the lock before testing c->state, otherwise a
	* writer could modify the structure if it gets preempted and has
	* something to write 
	*/
	lock_get(&c->write_lock);
    switch (c->state) {
		case S_CONN_ACCEPT:
			/* DBG("tls_fix_read_conn: Running tls_accept\n"); //noisy */
			ret = tls_update_fd(c, c->fd);
			if (!ret) 
				ret = tls_accept(c);
			break;
	
		case S_CONN_CONNECT:
			/* DBG("tls_fix_read_conn: Running tls_connect\n"); //noisy */
			ret = tls_update_fd(c, c->fd);
			if (!ret)
				ret = tls_connect(c);
			break;
	
		default:	/* fall through */
			break;
	}
	lock_release(&c->write_lock);

	return ret;
}
