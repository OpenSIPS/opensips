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

struct _WOLFSSL {
	WOLFSSL *read_ssl;
	WOLFSSL *write_ssl;
};

#define _WOLFSSL_READ_SSL(_ssl) \
	(((struct _WOLFSSL *)(_ssl))->read_ssl)
#define _WOLFSSL_WRITE_SSL(_ssl) \
	(((struct _WOLFSSL *)(_ssl))->write_ssl)

#define _WOLFSSL_ERR_BUFLEN 80

#define SSL_VERSIONS_SIZE 4

typedef WOLFSSL_METHOD *(*_wolfssl_method_f)(void);

extern _wolfssl_method_f ssl_methods[SSL_VERSIONS_SIZE];
