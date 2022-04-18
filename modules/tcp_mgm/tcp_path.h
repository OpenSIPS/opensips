/*
 * Copyright (C) 2022 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
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

#ifndef TCP_PATH_H
#define TCP_PATH_H

#include "../../rw_locking.h"
#include "../../ip_addr.h"
#include "../../net/tcp_conn_defs.h"

struct tcp_path {
	enum sip_protos proto;

	struct net remote_addr;
	unsigned short remote_port;
	char remote_any:1;

	struct net local_addr;
	unsigned short local_port;
	char local_any:1;

	int priority;
	struct tcp_conn_profile prof;
};

extern struct tcp_path *tcp_paths;
extern int *tcp_paths_sz;
extern rw_lock_t *tcp_paths_lk;

int tcp_path_init(void);
void tcp_path_destroy(void);

int tcp_store_path(int *int_vals, char **str_vals, struct tcp_path *path);

int tcp_mgm_get_profile(union sockaddr_union *remote,
         union sockaddr_union *local, enum sip_protos proto,
         struct tcp_conn_profile *out_profile);

#endif /* TCP_PATH_H */
