/*
 * Copyright (C) 2021 - OpenSIPS Solutions
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

#ifndef OPENSSL_API_H
#define OPENSSL_API_H

#include "../tls_mgm/tls_lib_api.h"

/* utility functions for operations directly on a SSL_CTX */
typedef void (*tls_ctx_set_cert_store_f) (void *ctx, void *src_ctx);
typedef int (*tls_ctx_set_cert_chain_f) (void *ctx, void *src_ctx);
typedef int (*tls_ctx_set_pkey_file_f) (void *ctx, char *pkey_file);

struct openssl_binds {
    TLS_LIB_API_BINDS;
    tls_ctx_set_cert_store_f ctx_set_cert_store;
    tls_ctx_set_cert_chain_f ctx_set_cert_chain;
    tls_ctx_set_pkey_file_f ctx_set_pkey_file;
};

typedef int(*load_tls_openssl_f)(struct openssl_binds *binds);

static inline int load_tls_openssl_api(struct openssl_binds *binds) {
    load_tls_openssl_f load_tls_openssl;

    /* import the openssl auto-loading function */
    if (!(load_tls_openssl = (load_tls_openssl_f)find_export("load_tls_openssl", 0)))
        return -1;

    if (load_tls_openssl(binds) == -1)
        return -1;

    return 0;
}

#endif	/* OPENSSL_API_H */
