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
static inline void tls_print_errstack(void)
{
	int             code;

	while ((code = ERR_get_error())) {
		LM_ERR("TLS errstack: %s\n", ERR_error_string(code, 0));
	}
}

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

