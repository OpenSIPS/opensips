/* 
 * File:   tls_conn.h
 * Author: razvan
 *
 * Created on November 11, 2015, 5:26 PM
 */

#ifndef TLS_CONN_INIT_H
#define TLS_CONN_INIT_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include "tls_helper.h"
#include "tls_config_helper.h"
#include "../../locking.h"
#include "tls_conn.h"

/*
 * wrapper around SSL_shutdown, returns -1 on error, 0 on success
 */
static int tls_conn_shutdown(struct tcp_connection *c)
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
				LM_ERR("something wrong in SSL: %d, %d, %s\n",err,errno,strerror(errno));
				c->state = S_CONN_BAD;
				tls_print_errstack();
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
	LM_DBG("entered: Creating a whole new ssl connection\n");
	
	if ( c->flags&F_CONN_ACCEPTED ) {
		/* connection created as a result of an accept -> server */
		c->proto_flags = F_TLS_DO_ACCEPT;
		LM_DBG("looking up socket based TLS server "
			"domain [%s:%d]\n", ip_addr2a(&c->rcv.dst_ip), c->rcv.dst_port);
		dom = api->find_server_domain(&c->rcv.dst_ip, c->rcv.dst_port);
		if (dom) {
			LM_DBG("found socket based TLS server domain "
				"[%s:%d]\n", ip_addr2a(&dom->addr), dom->port);
				c->extra_data = SSL_new(dom->ctx);
				api->release_domain(dom);
		} else {
			LM_ERR("no TLS server domain found\n");
			return -1;
		}
	} else {
		/* connection created as a result of a connect -> client */
		c->proto_flags = F_TLS_DO_CONNECT;

		dom = api->find_client_domain(&c->rcv.src_ip, c->rcv.src_port);
		if (dom) {
			c->extra_data = SSL_new(dom->ctx);
			api->release_domain(dom);
		} else {
			LM_ERR("no TLS client domain found\n");
			return -1;
		}
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

	if ( c->proto_flags & F_TLS_DO_ACCEPT ) {
		LM_DBG("Setting in ACCEPT mode (server)\n");
		SSL_set_accept_state((SSL *) c->extra_data);
	} else {
		LM_DBG("Setting in CONNECT mode (client)\n");
		SSL_set_connect_state((SSL *) c->extra_data);
	}
	return 0;
}


static void tls_conn_clean(struct tcp_connection* c)
{
	/*
	* runs within global tcp lock
	*/
	LM_DBG("entered\n");

	if (c->extra_data) {
		tls_update_fd(c,c->s);

		tls_conn_shutdown(c);
		SSL_free((SSL *) c->extra_data);
		c->extra_data = 0;
	}
}

#endif /* TLS_CONN_INIT_H */

