/* 
 * File:   tls_conn.h
 * Author: razvan
 *
 * Created on November 11, 2015, 5:26 PM
 */

#ifndef TLS_CONN_HELPER_H
#define TLS_CONN_HELPER_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include "tls_helper.h"
#include "tls_config_helper.h"
#include "../../locking.h"

/*
 * dump ssl error stack
 */
static void tls_print_errstack(void)
{
	int             code;

	while ((code = ERR_get_error())) {
		LM_ERR("TLS errstack: %s\n", ERR_error_string(code, 0));
	}
}

/*
 * Update ssl structure with new fd
 */
static int tls_update_fd(struct tcp_connection *c, int fd)
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

#endif /* TLS_CONN_HELPER_H */

