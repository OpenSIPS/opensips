/*
 * FreeSWITCH API
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * --------
 *  2017-01-19 initial version (liviu)
 */

#ifndef __FREESWITCH_API__
#define __FREESWITCH_API__

#include "../../lib/list.h"

enum fs_evs_types {
	FS_GW_STAT,
};

typedef struct _fs_evs {
	enum fs_evs_types typ;
	struct ip_addr ip;
	unsigned short int port;

	struct list_head list;
	struct list_head taglist;
} fs_evs;

/* statistics contained within a FreeSWITCH "HEARTBEAT" event */
typedef struct _fs_ev_hrbeat {
	float id_cpu;
	int sess;
	int max_sess;
} fs_ev_hrbeat;

typedef struct _fs_api_t fs_api_t;
                       /* host[:port] (8021)       struct/lock/etc. */
typedef int (*ev_hrbeat_cb_f) (fs_evs *evs, char *tag, fs_ev_hrbeat *hb, void *info);
typedef fs_evs* (*add_fs_evs_f) (str *evs_str, char *tag, enum fs_evs_types typ,
                               ev_hrbeat_cb_f scb, void *info);

typedef int (*del_fs_evs_f) (fs_evs *evs, char *tag);

// XXX remove after dev
add_fs_evs_f add_fs_event_sock(str *evs_str, char *tag, enum fs_evs_types typ,
                               ev_hrbeat_cb_f scb, void *info);
del_fs_evs_f del_fs_event_sock(fs_evs *evs, char *tag);

struct _fs_api_t {
	/*
	 * Creates & registers a new FS event socket
	 *	(to be managed by the stat-fetching thread)
	 *
	 *	Return: the newly created event socket
	 */
	add_fs_evs_f add_fs_evs;

	/*
	 * Detach & free a FS event sock from the stat-fetching thread's iteration list
	 *
	 * Return: 0 on success, < 0 on failure
	 */
	del_fs_evs_f del_fs_evs;

};

int fs_bind(fs_api_t *fapi);

#endif /* __FREESWITCH_API__ */
