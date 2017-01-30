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

#include "esl/src/include/esl.h"

#define FS_DEFAULT_EVS_PORT 8021
#define FS_HEARTBEAT_ITV      20

enum fs_evs_types {
	FS_GW_STATS,
};

typedef struct _fs_evs fs_evs;
typedef struct _fs_ev_hb fs_ev_hb;

typedef int (*ev_hb_cb_f) (fs_evs *evs, str *tag, fs_ev_hb *hb, const void *priv);

typedef struct _fs_mod_ref {
	str tag;
	ev_hb_cb_f hb_cb;
	const void *priv;

	struct list_head list;
} fs_mod_ref;

struct _fs_evs {
	enum fs_evs_types type;
	str host; /* host->s is NULL-terminated */
	esl_port_t port;

	esl_handle_t *handle;

	struct list_head list;     /* distinct FS boxes */
	struct list_head modules;  /* distinct modules referencing the same box */
};

/* statistics contained within a FreeSWITCH "HEARTBEAT" event */
struct _fs_ev_hb {
	float id_cpu;
	int sess;
	int max_sess;
};

typedef struct _fs_api_t fs_api_t;
                       /* host[:port] (8021)       struct/lock/etc. */
typedef fs_evs* (*add_hb_evs_f) (str *evs_str, str *tag,
                                 ev_hb_cb_f scb, const void *priv);

typedef int (*del_hb_evs_f) (fs_evs *evs, str *tag);

// XXX remove after dev
fs_evs *add_hb_evs(str *evs_str, str *tag, ev_hb_cb_f scb, const void *priv);
int del_hb_evs(fs_evs *evs, str *tag);

struct _fs_api_t {
	/*
	 * Creates & registers a new FS "HEARTBEAT" event socket
	 *	(all FS connections will be managed by one process)
	 *
	 *	Return: the newly created event socket
	 */
	add_hb_evs_f add_hb_evs;

	/*
	 * Detach & free a FS "HEARTBEAT" event sock from the
	 * stat-fetching process' iteration list
	 *
	 * Return: 0 on success, < 0 on failure
	 */
	del_hb_evs_f del_hb_evs;
};

int fs_bind(fs_api_t *fapi);

#endif /* __FREESWITCH_API__ */
