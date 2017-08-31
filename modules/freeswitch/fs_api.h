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
#include "../../rw_locking.h"
#include "../../ip_addr.h"
#include "../../sr_module.h"

#include "esl/src/include/esl.h"

#define FS_SOCK_PREFIX        "fs://"
#define FS_SOCK_PREFIX_LEN    (sizeof(FS_SOCK_PREFIX) - 1)

#define FS_DEFAULT_EVS_PORT 8021
#define FS_HEARTBEAT_ITV       1 /* assumed value, for best performance */

enum fs_evs_types {
	FS_GW_STATS,
};

typedef struct _fs_evs fs_evs;
typedef struct _fs_ev_hb fs_ev_hb;

typedef int (*ev_hb_cb_f) (fs_evs *evs, str *tag, const void *priv);

typedef struct _fs_mod_ref {
	str tag;
	ev_hb_cb_f hb_cb;
	const void *priv;

	struct list_head list;
} fs_mod_ref;

/* statistics contained within a FreeSWITCH "HEARTBEAT" event */
struct _fs_ev_hb {
	float id_cpu;
	int sess;
	int max_sess;

	int is_valid; /* FS load stats are invalid until the first heartbeat */
};

struct _fs_evs {
	enum fs_evs_types type;
	str user;
	str pass;
	str host; /* host->s is NULL-terminated */
	esl_port_t port;

	esl_handle_t *handle;

	rw_lock_t *hb_data_lk;
	fs_ev_hb hb_data;

	int ref;

	struct list_head list;     /* distinct FS boxes */
	struct list_head modules;  /* distinct modules referencing the same box */
};

                       /* host[:port] (8021)       struct/lock/etc. */
typedef fs_evs* (*add_hb_evs_f) (str *evs_str, str *tag,
                                 ev_hb_cb_f scb, const void *priv);

typedef int (*del_hb_evs_f) (fs_evs *evs, str *tag);

struct fs_binds {
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

static inline int is_fs_url(str *in)
{
	return (in->len < FS_SOCK_PREFIX_LEN ||
	        memcmp(in->s, FS_SOCK_PREFIX, FS_SOCK_PREFIX_LEN) != 0)
	        ? 0 : 1;
}

typedef int (*bind_fs_t)(struct fs_binds *fsb);
static inline int load_fs_api(struct fs_binds *fsb)
{
	bind_fs_t bind_fs;

	bind_fs = (bind_fs_t)find_export("fs_bind", 1, 0);
	if (!bind_fs) {
		LM_ERR("can't bind fs!\n");
		return -1;
	}

	if (bind_fs(fsb) < 0)
		return -1;

	return 0;
}

#endif /* __FREESWITCH_API__ */
