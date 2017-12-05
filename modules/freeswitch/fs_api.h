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

#include "../../str_list.h"
#include "../../lib/list.h"
#include "../../rw_locking.h"
#include "../../ip_addr.h"
#include "../../sr_module.h"

#include "esl/src/include/esl.h"

#define FS_SOCK_PREFIX        "fs://"
#define FS_SOCK_PREFIX_LEN    (sizeof(FS_SOCK_PREFIX) - 1)

#define FS_DEFAULT_EVS_PORT 8021

enum fs_evs_types {
	FS_GW_STATS,
};

typedef struct _fs_evs fs_evs;
typedef struct _fs_stats fs_stats;

typedef struct _fs_mod_ref {
	str tag;

	struct list_head list;
} fs_mod_ref;

/* statistics contained within a FreeSWITCH instance */
struct _fs_stats {
	float id_cpu;
	int sess;
	int max_sess;

	int valid; /* FS stats are invalid until the first heartbeat */
};

struct _fs_evs {
	enum fs_evs_types type;
	str user;
	str pass;
	str host; /* host->s is NULL-terminated */
	esl_port_t port;

	esl_handle_t *handle;

	rw_lock_t *stats_lk;
	fs_stats stats;

	int ref;

	struct list_head list;     /* distinct FS boxes */
	struct list_head modules;  /* distinct modules referencing the same box */
};

typedef void (*fs_event_cb_f) (const fs_evs *sock, const str *ev_name,
                               const cJSON *ev_body);

typedef fs_evs* (*get_evs_f) (const str *evs_str);
typedef int (*evs_sub_f) (fs_evs *evs, const str *tag,
                          const struct str_list *events, fs_event_cb_f ev_cb);
typedef void (*evs_unsub_f) (fs_evs *evs, const str *tag,
                             const struct str_list *events);
typedef void (*put_evs_f) (fs_evs *evs);

typedef fs_evs* (*get_stats_evs_f) (str *evs_str, str *tag);
typedef int (*put_stats_evs_f) (fs_evs *evs, str *tag);

struct fs_binds {
	/*
	 * seconds-based interval at which the latest stats from a FreeSWITCH
	 * instance are expected to periodically arrive
	 */
	int stats_update_interval;

	/*
	 * Obtain a FreeSWITCH event socket corresponding to the given FreeSWITCH
	 * URL and increment its ref count. FreeSWITCH URLs are of the form:
	 *
	 *   [fs://][[username]:password@]host[:port][;EVENT1[,EVENT2[,.. ]]]
	 *
	 * NOTE: get_evs() must be paired up with an eventual put_evs()
	 *
	 * Return: required socket or NULL on internal error
	 */
	get_evs_f get_evs;

	/*
	 * Expands the set of events for FreeSWITCH instance "sock" that the
	 * current "tag" is subscribed to with the "events" list. The current
	 * event callback function for "sock" and "tag" is updated with "ev_cb".
	 *
	 * NOTE: Each event subscription is reference-counted! For each event sub,
	 * you must eventually call unsub. This helps during reloads.
	 * E.g.: Initial event set is "A B C". While keeping the current data, we
	 * hit a reload, which happens to change the event set to "A B C D", to
	 * which we immediately re-subscribe. Finally, we free the previous data,
	 * unsubscribing from "A B C" events in the process. Thanks to reference
	 * counting, the set will not become "D", rather it will remain "A B C D"!
	 *
	 * Examples of some valid events that FreeSWITCH allows subscriptions to:
	 *    * CHANNEL_STATE
	 *    * CHANNEL_ANSWER
	 *    * BACKGROUND_JOB
	 *    * DTMF
	 *    * HEARTBEAT
	 *
	 * TL;DR: each evs_sub() for event set X must be paired up with an eventual
	 * evs_unsub() for event set X
	 *
	 * Return: 0 on success, -1 on internal error
	 */
	evs_sub_f evs_sub;

	/*
	 * Unsubscribes the current "tag" from the "events" of the "sock". Event
	 * subscriptions are ref-counted, so your callback for some of these
	 * events may still get called even after calling this function.
	 *
	 * Read "evs_sub" description for more info.
	 */
	evs_unsub_f evs_unsub;

	/*
	 * Return a FreeSWITCH event socket. If its reference count reaches zero,
	 * it will get destroyed, along with any subscriptions attached to it.
	 */
	put_evs_f put_evs;

	/*
	 * Obtain a FreeSWITCH statistics event socket. The relevant statistics
	 * can be found under "evs->stats", and calling code can expect them to be
	 * updated at most every "api->stats_update_interval" seconds
	 *
	 * NOTE 1: always grab "evs->stats_lk" before reading the stats,
	 * otherwise you may read partially updated / corrupt data!
	 *
	 * NOTE 2: each get() must be paired up with an eventual put()
	 *          (e.g., put() makes sense during a reload or shutdown)
	 */
	get_stats_evs_f get_stats_evs;

	/*
	 * Return a FreeSWITCH statistics event socket.
	 *
	 * Return: 0 on success, < 0 on failure
	 */
	put_stats_evs_f put_stats_evs;
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
