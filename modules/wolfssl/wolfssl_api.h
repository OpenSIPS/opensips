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

#ifndef WOLFSSL_API_H
#define WOLFSSL_API_H

#include "tls_ops_api.h"

struct wolfssl_binds {
    TLS_OPS_API_BINDS;
};

typedef int(*load_wolfssl_f)(struct wolfssl_binds *binds);

static inline int load_wolfssl_api(struct wolfssl_binds *binds) {
    load_wolfssl_f load_wolfssl;

    /* import the wolfssl auto-loading function */
    if (!(load_wolfssl = (load_wolfssl_f)find_export("load_wolfssl", 0)))
        return -1;

    if (load_wolfssl(binds) == -1)
        return -1;

    return 0;
}

#endif	/* WOLFSSL_API_H */
