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
#include "../../ipc.h"

#include "esl/src/include/esl.h"

#define FS_SOCK_PREFIX        "fs://"
#define FS_SOCK_PREFIX_LEN    (sizeof(FS_SOCK_PREFIX) - 1)

#define FS_DEFAULT_EVS_PORT 8021

typedef struct _fs_evs fs_evs;
typedef struct _fs_stats fs_stats;

typedef void (*fs_event_cb_f) (const fs_evs *sock, const str *ev_name,
                               const cJSON *ev_body);

/* statistics contained within a FreeSWITCH instance */
struct _fs_stats {
	float id_cpu;
	int sess;
	int max_sess;

	int valid; /* FS stats are invalid until the first heartbeat */
};

enum fs_event_actions {
	FS_EVENT_NOP, /* no action required */
	FS_EVENT_SUB,
	FS_EVENT_UNSUB,
};

struct fs_event_subscription {
	str tag;
	ipc_handler_type ipc_type;
	int ref;

	struct list_head list;
};

struct fs_event {
	str name;
	enum fs_event_actions action;
	int refsum; /* multiple subs from multiple modules */
	struct list_head subscriptions; /* different modules subbed to an event */

	struct list_head list;
};

struct fs_esl_reply {
	str text;
	unsigned long esl_reply_id;

	struct list_head list;
};

struct _fs_evs {
	str user;
	str pass;
	str host; /* host->s is NULL-terminated */
	esl_port_t port;

	esl_handle_t *handle;

	rw_lock_t *stats_lk;
	fs_stats stats;

	int ref;

	rw_lock_t *lists_lk;         /* protects all three internal lists */

	unsigned long esl_reply_id;  /* positive ID/counter for each FS esl cmd */
	struct list_head esl_replies;

	struct list_head events;     /* events we're successfully subscribed to */

	/* a socket may concurrently be part of up to three lists! */
	struct list_head list;           /* "fs_sockets" - all FS sockets */
	struct list_head reconnect_list; /* "fs_sockets_down" - new/failed conns */
	struct list_head esl_cmd_list;   /* "fs_sockets_esl" - pending ESL cmds */
};

typedef fs_evs* (*get_evs_f) (const str *host, unsigned short port,
                              const str *user, const str *pass);
typedef fs_evs* (*get_evs_by_url_f) (const str *fs_url);
typedef fs_evs* (*get_stats_evs_f) (str *fs_url, str *tag);

typedef int (*evs_sub_f) (fs_evs *sock, const str *tag,
                    const str_list *events, ipc_handler_type ipc_type);
typedef void (*evs_unsub_f) (fs_evs *sock, const str *tag,
                             const str_list *events);

typedef void (*put_evs_f) (fs_evs *sock);
typedef void (*put_stats_evs_f) (fs_evs *sock, str *tag);

typedef int (*fs_esl_f) (fs_evs *sock, const str *fs_cmd, str *reply);

struct fs_binds {
	/*
	 * seconds-based interval at which the latest stats from a FreeSWITCH
	 * instance are expected to periodically arrive
	 */
	int stats_update_interval;

	/*
	 * Obtain a FreeSWITCH event socket corresponding to the given FreeSWITCH
	 * host:port interface or URL and increment its ref count.
	 * FreeSWITCH URLs are of the form:
	 *
	 *   [fs://][[username]:password@]host[:port][?EVENT1[,EVENT2[,.. ]]]
	 *
	 * NOTE: get_evs() must be paired up with an eventual put_evs()
	 *
	 * Return: required socket or NULL on internal error
	 */
	get_evs_f get_evs;
	get_evs_by_url_f get_evs_by_url;

	/*
	 * Expands the set of events for FreeSWITCH instance "sock" that the
	 * current "tag" is subscribed to with the "events" list of arbitrary
	 * strings. The current event callback function for "sock" and "tag" is
	 * triggered via the "ipc_type" channel.
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
	 * Obtain a FreeSWITCH statistics event socket corresponding to the given
	 * FreeSWITCH URL and increment its ref count. URLs are of the form:
	 *
	 *   [fs://][[username]:password@]host[:port][?EVENT1[,EVENT2[,.. ]]]
	 *
	 * The relevant statistics can be found under "evs->stats", and calling
	 * code can expect them to be updated at most every
	 * "api->stats_update_interval" seconds
	 *
	 * NOTE 1: always grab "evs->stats_lk" before reading the stats,
	 * otherwise you may read partially updated / corrupt data!
	 *
	 * NOTE 2: each get() must be paired up with an eventual put()
	 *          (e.g., put() makes sense during a reload or shutdown)
	 *
	 * Return: required socket or NULL on internal error
	 */
	get_stats_evs_f get_stats_evs;

	/*
	 * Return a FreeSWITCH statistics event socket.
	 */
	put_stats_evs_f put_stats_evs;

	/*
	 * Run an arbitrary FreeSWITCH ESL command on the given "sock" socket.
	 * Blocks until an answer from FreeSWITCH arrives.
	 *
	 * Return:
	 *	0 on success. "*reply" contains a SHM string which must be freed
	 *	-1 on failure. "*reply" is zeroized
	 */
	fs_esl_f fs_esl;
};

static inline int is_fs_url(str *in)
{
	return (in->len < FS_SOCK_PREFIX_LEN ||
	        memcmp(in->s, FS_SOCK_PREFIX, FS_SOCK_PREFIX_LEN) != 0)
	        ? 0 : 1;
}

typedef int (*bind_fs_t)(struct fs_binds *fapi);
int fs_bind(struct fs_binds *fapi);

static inline int load_fs_api(struct fs_binds *fapi)
{
	bind_fs_t bind_fs;

	bind_fs = (bind_fs_t)find_export("fs_bind", 0);
	if (!bind_fs) {
		LM_ERR("can't bind fs!\n");
		return -1;
	}

	if (bind_fs(fapi) < 0)
		return -1;

	return 0;
}

#endif /* __FREESWITCH_API__ */
