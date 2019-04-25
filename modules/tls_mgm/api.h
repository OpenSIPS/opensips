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


#ifndef TLS_API_H
#define TLS_API_H

#include "../../resolve.h"

#include "tls_helper.h"

typedef struct tls_domain * (*tls_find_server_domain_f) (struct ip_addr *, unsigned short);
typedef struct tls_domain * (*tls_find_client_domain_f) (struct ip_addr *, unsigned short);
typedef struct tls_domain * (*tls_find_client_domain_name_f) (str *);
typedef int (*get_send_timeout_f) (void);
typedef int (*get_handshake_timeout_f) (void);
typedef void (*tls_release_domain_f) (struct tls_domain *);

struct tls_mgm_binds {
    get_send_timeout_f get_send_timeout;
    get_handshake_timeout_f get_handshake_timeout;
    tls_find_server_domain_f find_server_domain;
    tls_find_client_domain_f find_client_domain;
    tls_find_client_domain_name_f find_client_domain_name;
    tls_release_domain_f release_domain;
};


typedef int(*load_tls_mgm_f)(struct tls_mgm_binds *binds);

static inline int load_tls_mgm_api(struct tls_mgm_binds *binds) {
    load_tls_mgm_f load_tls;

    /* import the DLG auto-loading function */
    if (!(load_tls = (load_tls_mgm_f) find_export("load_tls_mgm", 0)))
        return -1;

    /* let the auto-loading function load all DLG stuff */
    if (load_tls(binds) == -1)
        return -1;

    return 0;
}

#endif	/* TLS_API_H */
