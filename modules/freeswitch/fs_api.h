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
#include "../../ip_addr.h"

#define FS_DEFAULT_EVS_PORT 8021

enum fs_evs_types {
	FS_GW_STATS,
};

typedef struct _fs_evs {
	enum fs_evs_types type;
	union sockaddr_union su;

	struct list_head list;    /* distinct FS boxes */
	struct list_head modlist; /* distinct module references to the same box */
} fs_evs;

/* statistics contained within a FreeSWITCH "HEARTBEAT" event */
typedef struct _fs_ev_hrbeat {
	float id_cpu;
	int sess;
	int max_sess;
} fs_ev_hrbeat;

typedef struct _fs_api_t fs_api_t;
                       /* host[:port] (8021)       struct/lock/etc. */
typedef int (*ev_hrbeat_cb_f) (fs_evs *evs, str *tag, fs_ev_hrbeat *hb, void *info);
typedef fs_evs* (*add_fs_evs_f) (str *evs_str, str *tag, enum fs_evs_types type,
                               ev_hrbeat_cb_f scb, void *info);

typedef int (*del_fs_evs_f) (fs_evs *evs, str *tag);

// XXX remove after dev
fs_evs *add_fs_event_sock(str *evs_str, str *tag, enum fs_evs_types type,
                               ev_hrbeat_cb_f scb, void *info);
int del_fs_event_sock(fs_evs *evs, str *tag);

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

extern struct list_head *fs_boxes;

int fs_bind(fs_api_t *fapi);

#endif /* __FREESWITCH_API__ */
