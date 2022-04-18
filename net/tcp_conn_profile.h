/*
 * Copyright (C) 2022 - OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef TCP_CONN_PROFILE_H
#define TCP_CONN_PROFILE_H

#include "../ip_addr.h"
#include "tcp_conn_defs.h"

/* initialize the support for customized, per-path TCP connection profiles */
void tcp_init_con_profiles(void);

/**
 * A global function for looking up TCP connection profiles based on
 * a given TCP path tuple of: (remote, local, protocol).
 *
 * By default, it always returns the same profile: a collection of all global
 * TCP connection settings (e.g. tcp_connect_timeout, tcp_con_lifetime, etc.).
 *
 * May be overridden by at most one module at a time, e.g. tcp_mgm
 *
 * Return:
 *   0 (success, but just the default TCP profile was returned)
 *   1 (success, a custom TCP profile from tcp_mgm DB was matched)
 */
extern int (*tcp_con_get_profile)(union sockaddr_union *remote,
             union sockaddr_union *local, enum sip_protos proto,
             struct tcp_conn_profile *out_profile);

#endif /* TCP_CONN_PROFILE_H */
