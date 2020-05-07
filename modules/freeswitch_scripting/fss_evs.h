/*
 * Script and MI utilities for custom FreeSWITCH interactions
 *
 * Copyright (C) 2017 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#ifndef __FSS_EVS__
#define __FSS_EVS__

#include "../freeswitch/fs_api.h"

struct fs_evs_list {
	fs_evs *sock;
	str_list *events;

	struct list_head list;
};

extern struct fs_binds fs_api;
extern struct list_head *fss_sockets;

int fss_init(void);
int subscribe_to_fs_urls(const struct list_head *urls);

int is_subscribed(fs_evs *sock, str *event);
int find_evs(fs_evs *sock);
int add_evs(fs_evs *sock);
struct fs_evs_list *mk_fs_sock_list(fs_evs *sock, str_list *events);
void free_fs_sock_list(struct list_head *sock_list);
int add_to_fss_sockets(fs_evs *sock, const str *event);
int del_from_fss_sockets(fs_evs *sock, const str *event_name);

#endif /* __FSS_EVS__ */
