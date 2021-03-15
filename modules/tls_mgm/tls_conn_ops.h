/*
 * Copyright (C) 2015 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
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

#ifndef TLS_CONN_OPS_H
#define TLS_CONN_OPS_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include "tls_conn.h"
#include "tls_config_helper.h"
#include "../../locking.h"

/*
 * wrapper around SSL_shutdown, returns -1 on error, 0 on success
 */
static int tls_conn_shutdown(struct tcp_connection *c, struct tls_mgm_binds *tls_api)
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
	if (tls_api)
		tls_api->global_lock_get();
	#endif

	ERR_clear_error();

	ret = SSL_shutdown(ssl);
	if (ret == 1) {
		#ifndef NO_SSL_GLOBAL_LOCK
		if (tls_api)
			tls_api->global_lock_release();
		#endif
		LM_DBG("shutdown successful\n");
		return 0;
	} else if (ret == 0) {
		#ifndef NO_SSL_GLOBAL_LOCK
		if (tls_api)
			tls_api->global_lock_release();
		#endif
		LM_DBG("first phase of 2-way handshake completed succesfuly\n");
		return 0;
	} else {
		err = SSL_get_error(ssl, ret);
		switch (err) {
			case SSL_ERROR_ZERO_RETURN:
				#ifndef NO_SSL_GLOBAL_LOCK
				if (tls_api)
					tls_api->global_lock_release();
				#endif

				c->state = S_CONN_EOF;

				return 0;

			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				#ifndef NO_SSL_GLOBAL_LOCK
				if (tls_api)
					tls_api->global_lock_release();
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
				if (tls_api)
					tls_api->global_lock_release();
				#endif

				return -1;
		}
	}

	LM_ERR("bug\n");
	return -1;
}

static int tls_conn_init(struct tcp_connection* c, struct tls_mgm_binds *api)
{
	struct tls_domain *dom;

	/*
	* new connection within a single process, no lock necessary
	*/
	LM_DBG("Creating a whole new ssl connection\n");

	if ( c->flags&F_CONN_ACCEPTED ) {
		/* connection created as a result of an accept -> server */
		c->proto_flags = F_TLS_DO_ACCEPT;
		LM_DBG("looking up TLS server "
			"domain [%s:%d]\n", ip_addr2a(&c->rcv.dst_ip), c->rcv.dst_port);
		dom = api->find_server_domain(&c->rcv.dst_ip, c->rcv.dst_port);
		if (dom) {
			c->extra_data = SSL_new(dom->ctx[process_no]);

			/* put pointers to the tcp_connection and tls_domain structs
			 * in the SSL struct as extra data */
			if (!SSL_set_ex_data(c->extra_data, SSL_EX_CONN_IDX, c)) {
				LM_ERR("Failed to store tcp_connection pointer in SSL struct\n");
				return -1;
			}
			if (!SSL_set_ex_data(c->extra_data, SSL_EX_DOM_IDX, dom)) {
				LM_ERR("Failed to store tls_domain pointer in SSL struct\n");
				return -1;
			}
		} else {
			LM_ERR("no TLS server domain found\n");
			return -1;
		}
	} else {
		/* connection created as a result of a connect -> client */
		c->proto_flags = F_TLS_DO_CONNECT;
		dom = api->find_client_domain(&c->rcv.src_ip, c->rcv.src_port);
		if (dom) {
			c->extra_data = SSL_new(dom->ctx[process_no]);

			if (!SSL_set_ex_data(c->extra_data, SSL_EX_CONN_IDX, c)) {
				LM_ERR("Failed to store tcp_connection pointer in SSL struct\n");
				return -1;
			}
			if (!SSL_set_ex_data(c->extra_data, SSL_EX_DOM_IDX, dom)) {
				LM_ERR("Failed to store tls_domain pointer in SSL struct\n");
				return -1;
			}
		} else {
			LM_ERR("no TLS client domain found\n");
			return -1;
		}
	}

	if (!c->extra_data) {
		LM_ERR("failed to create SSL structure\n");
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
	return 0;
}


static void tls_conn_clean(struct tcp_connection* c, struct tls_mgm_binds *api)
{
	struct tls_domain *dom;

	if (c->extra_data) {
		dom = (struct tls_domain *)SSL_get_ex_data(c->extra_data, SSL_EX_DOM_IDX);

		tls_update_fd(c,c->s);
		tls_conn_shutdown(c, api);
		SSL_free((SSL *) c->extra_data);
		c->extra_data = 0;

		if (!dom)
			LM_ERR("Failed to retrieve the tls_domain pointer in the SSL struct\n");
		else
			api->release_domain(dom);
	}
}

/*
 * Wrapper around SSL_read
 *
 * returns number of bytes read, 0 on eof and transits into S_CONN_EOF, -1
 * on error
 */
static int _tls_read(struct tcp_connection *c, void *buf, size_t len,
	struct tls_mgm_binds *tls_api)
{
	int ret, err;
	SSL *ssl;

	ssl = c->extra_data;

	#ifndef NO_SSL_GLOBAL_LOCK
	if (tls_api)
		tls_api->global_lock_get();
	#endif

	ERR_clear_error();

	ret = SSL_read(ssl, buf, len);
	if (ret > 0) {
		#ifndef NO_SSL_GLOBAL_LOCK
		if (tls_api)
			tls_api->global_lock_release();
		#endif

		LM_DBG("%d bytes read\n", ret);
		return ret;
	} else if (ret == 0) {
		#ifndef NO_SSL_GLOBAL_LOCK
		if (tls_api)
			tls_api->global_lock_release();
		#endif

		/* unclean shutdown of the other peer */
		c->state = S_CONN_EOF;
		return 0;
	} else {
		err = SSL_get_error(ssl, ret);
		switch (err) {
		case SSL_ERROR_ZERO_RETURN:
			#ifndef NO_SSL_GLOBAL_LOCK
			if (tls_api)
				tls_api->global_lock_release();
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
			if (tls_api)
				tls_api->global_lock_release();
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
			if (tls_api)
				tls_api->global_lock_release();
			#endif

			return -1;
		}
	}

	LM_BUG("bug\n");
	return -1;
}



/*
 * called only when a connection is in S_CONN_OK, we do not have to care
 * about accepting or connecting here, each modification of ssl data
 * structures has to be protected, another process might ask for the same
 * connection and attempt write to it which would result in updating the
 * ssl structures
 */
static int tls_read(struct tcp_connection * c,struct tcp_req *r,
	struct tls_mgm_binds *tls_api)
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
	tls_update_fd(c, fd);
	read = _tls_read(c, r->pos, bytes_free, tls_api);
	lock_release(&c->write_lock);
	if (read > 0)
		r->pos += read;
	return read;
}


static int tls_conn_extra_match(struct tcp_connection *c, void *id)
{
	if ( (c->flags&F_CONN_ACCEPTED) ||
	(SSL_get_ex_data(c->extra_data, SSL_EX_DOM_IDX) == id) )
		return 1; /*true*/

	return 0; /*false*/
}

#endif /* TLS_CONN_OPS_H */

