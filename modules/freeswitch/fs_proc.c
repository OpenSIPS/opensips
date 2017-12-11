/*
 * Dedicated process for handling events on multiple FS ESL connections
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
 *  2017-01-26 initial version (liviu)
 */

#include <stdlib.h>

#include "../../mem/mem.h"
#include "../../reactor.h"
#include "../../timer.h"
#include "../../ut.h"
#include "../../ipc.h"

#include "esl/src/include/esl.h"

#include "fs_api.h"

#define FS_REACTOR_TIMEOUT  1 /* sec */

#define FS_STATS_EVENT_NAME "HEARTBEAT"

extern struct list_head *fs_sockets;
extern struct list_head *fs_sockets_down;
extern struct list_head *fs_sockets_esl;

extern rw_lock_t *sockets_lock;
extern rw_lock_t *sockets_down_lock;
extern rw_lock_t *sockets_esl_lock;

extern int fs_connect_timeout;

extern void evs_free(fs_evs *sock);
extern void esl_cmd_free(struct esl_cmd *cmd);

static int destroy_fs_evs(fs_evs *sock, int idx)
{
	esl_status_t rc;
	int ret = 0;

	if (reactor_del_reader(sock->handle->sock, idx, IO_WATCH_READ) != 0) {
		LM_ERR("del failed for sock %d\n", sock->handle->sock);
		ret = 1;
	}

	rc = esl_disconnect(sock->handle);
	if (rc != ESL_SUCCESS) {
		LM_ERR("disconnect error %d on FS sock %.*s:%d\n",
		       rc, sock->host.len, sock->host.s, sock->port);
		ret = 1;
	}

	list_del(&sock->list);

	if (!list_empty(&sock->reconnect_list))
		list_del(&sock->reconnect_list);

	if (!list_empty(&sock->esl_cmd_list))
		list_del(&sock->esl_cmd_list);

	evs_free(sock);

	return ret;
}

int fs_renew_stats(fs_evs *sock, const cJSON *ev)
{
	fs_stats stats;
	char *s, *end;

	memset(&stats, 0, sizeof stats);

	s = cJSON_GetObjectItem((cJSON *)ev, "Idle-CPU")->valuestring;
	stats.id_cpu = strtof(s, &end);
	if (*end) {
		LM_ERR("bad Idle-CPU: %s\n", s);
		return -1;
	}

	s = cJSON_GetObjectItem((cJSON *)ev, "Session-Count")->valuestring;
	stats.sess = strtol(s, &end, 0);
	if (*end) {
		LM_ERR("bad Session-Count: %s\n", s);
		return -1;
	}

	s = cJSON_GetObjectItem((cJSON *)ev, "Max-Sessions")->valuestring;
	stats.max_sess = strtol(s, &end, 0);
	if (*end) {
		LM_ERR("bad Max-Sessions: %s\n", s);
		return -1;
	}

	stats.valid = 1;

	LM_DBG("FS stats (%s:%d), idle cpu: %.3f, sessions: %d/%d\n%s\n",
	       sock->host.s, sock->port, stats.id_cpu, stats.sess, stats.max_sess,
	       sock->handle->last_sr_event->body);

	lock_start_write(sock->stats_lk);
	sock->stats = stats;
	lock_stop_write(sock->stats_lk);

	return 0;
}

int fs_raise_event(fs_evs *sock, const char *ev_name, const cJSON *ev_body)
{
	struct list_head *_, *__;
	struct fs_event *fs_ev;
	//struct fs_event_subscription *fs_sub;
	str _ev_name = {(char *)ev_name, strlen(ev_name)};

	lock_start_read(sock->lists_lk);

	list_for_each(_, &sock->events) {
		fs_ev = list_entry(_, struct fs_event, list);
		if (str_strcmp(&fs_ev->event_name, &_ev_name) == 0) {
			list_for_each(__, &fs_ev->subscriptions) {
				//fs_sub = list_entry(__, struct fs_event_subscription, list);
				//TODO: upgrade IPC support and submit a func() job
				//fs_sub->func(sock,
			}
			break;
		}
	}

	lock_stop_read(sock->lists_lk);

	return 0;
}

/*
 * FS socket I/O is easy, since it's read-only. So either:
 *   - the TCP connection is kaput
 *   - there is a pending FS event which needs to be read
 */
inline static int handle_io(struct fd_map *fm, int idx, int event_type)
{
	fs_evs *sock = (fs_evs *)fm->data;
	esl_status_t rc;
	cJSON *ev = NULL;
	char *s;

	LM_DBG("FS data available on sock %s:%d, ref: %d\n",
	       sock->host.s, sock->port, sock->ref);

	/* ignore the event: nobody's using this socket anymore, close it */
	lock_start_write(sockets_lock);
	if (sock->ref == 0) {
		if (destroy_fs_evs(sock, idx) != 0)
			LM_ERR("failed to destroy FS evs!\n");

		lock_stop_write(sockets_lock);
		return 0;
	}
	lock_stop_write(sockets_lock);

	switch (fm->type) {
		case F_FS_CONN:
			rc = esl_recv_event(sock->handle, 0, &sock->handle->last_sr_event);
			if (rc != ESL_SUCCESS) {
				LM_ERR("read error %d on FS sock %.*s:%d. Reconnecting...\n",
				       rc, sock->host.len, sock->host.s, sock->port);

				if (reactor_del_reader(sock->handle->sock, idx,
				                       IO_WATCH_READ) != 0) {
					LM_ERR("del failed for sock %d\n", sock->handle->sock);
					return 0;
				}

				rc = esl_disconnect(sock->handle);
				if (rc != ESL_SUCCESS) {
					LM_ERR("disconnect error %d on FS sock %.*s:%d\n",
					       rc, sock->host.len, sock->host.s, sock->port);
					sock->handle->connected = 0;
					return 0;
				}

				/* queue up a reconnect for this socket */
				lock_start_write(sockets_down_lock);
				list_add_tail(&sock->reconnect_list, fs_sockets_down);
				lock_stop_write(sockets_down_lock);
				return 0;
			}

			ev = cJSON_Parse(sock->handle->last_sr_event->body);
			if (!ev) {
				LM_ERR("oom\n");
				return 0;
			}

			s = cJSON_GetObjectItem(ev, "Event-Name")->valuestring;

			/* some generic FS event, fire it to all subscribers */
			if (strcmp(s, FS_STATS_EVENT_NAME) != 0) {
				if (fs_raise_event(sock, s, ev) != 0)
					LM_ERR("errors during event %s raise on %.*s:%d\n",
					       s, sock->host.len, sock->host.s, sock->port);
			} else {
				if (fs_renew_stats(sock, ev) != 0)
					LM_ERR("errors during stats %s renew on %s:%d\n",
					       s, sock->host.s, sock->port);
			}

			break;
		case F_IPC:
			ipc_handle_job();
			break;
		default:
			LM_CRIT("unknown fd type %d in FreeSWITCH worker\n", fm->type);
			return 0;
	}

	cJSON_Delete(ev);
	return 0;
}

int run_esl_commands(fs_evs *sock)
{
	struct list_head *_, *__;
	struct esl_cmd *cmd;

	list_for_each_safe(_, __, &sock->esl_cmds) {
		cmd = list_entry(_, struct esl_cmd, list);

		// TODO 1:
		/* -------- all commands must be "\n\n" terminated
		 *               (event sub/unsub, fs_cli)
		LM_DBG("registering for HEARTBEAT events...\n");
		if (esl_send_recv(sock->handle, "event json HEARTBEAT\n\n")
		    != ESL_SUCCESS) {
			LM_ERR("failed to register HEARTBEAT event on FS sock %s:%d\n",
			       sock->host.s, sock->port);
			ret++;
			continue;
		}

		>> print sock->handle->last_sr_reply

		LM_DBG("answer: %s\n", sock->handle->last_sr_reply);
		LM_DBG("successfully enabled HEARTBEAT events!\n");

		TODO 2:
			prepare any "struct fs_cli_reply" for blocked workers
		   */

		list_del(&cmd->list);
		esl_cmd_free(cmd);
	}

	return 0;
}

/*
 * - reconnects any socket found in the "fs_sockets_down" list
 * - applies all "sock->esl_cmds" commands of any sockets in "fs_sockets_esl"
 */
static int apply_socket_commands(int first_run)
{
	struct list_head *_, *__;
	fs_evs *sock;
	int ret = 0;
	esl_status_t rc;

	// TODO: rework this granularity mechanism to be less random and more
	//       configurable
	// now:
	//	- can skip some runs (poll t/o is 1 sec, so get_ticks()
	//	  may appear to jump from 17 -> 19
	//	- can run multiple times during a second:
	//	  say we have two FS sockets which receive events in get_ticks() == 18:
	//	   -> apply_socket_commands() will run twice
	//
	// fix to "run at most once every X seconds"
	if (!first_run && get_ticks() % 10 != 9) {
		return 0;
	}

	LM_DBG("applying FS socket commands\n");

	lock_start_write(sockets_down_lock);
	list_for_each_safe(_, __, fs_sockets_down) {
		sock = list_entry(_, fs_evs, reconnect_list);

		if (sock->handle) {
			if (sock->handle->connected &&
			      sock->handle->sock != ESL_SOCK_INVALID) {
				LM_BUG("Fake Disconnect on %s:%d", sock->host.s, sock->port);
				list_del(&sock->reconnect_list);
				INIT_LIST_HEAD(&sock->reconnect_list);
				continue;
			} else {
				rc = esl_disconnect(sock->handle);
				if (rc != ESL_SUCCESS) {
					LM_ERR("disconnect error %d on FS sock %s:%d\n",
					       rc, sock->host.s, sock->port);
				}
			}
		} else {
			sock->handle = pkg_malloc(sizeof *sock->handle);
			if (!sock->handle) {
				LM_ERR("failed to create FS handle!\n");
				ret++;
				continue;
			}
		}

		memset(sock->handle, 0, sizeof *sock->handle);
		LM_DBG("reconnecting to FS sock '%s:%d'\n", sock->host.s, sock->port);

		if (esl_connect_timeout(sock->handle, sock->host.s, sock->port,
		      sock->user.s, sock->pass.s, fs_connect_timeout) != ESL_SUCCESS) {
			LM_ERR("failed to connect to FS sock '%s:%d'\n",
			       sock->host.s, sock->port);
			ret++;
			continue;
		}

		LM_DBG("successfully connected to FS!\n");

		if (!sock->handle->connected) {
			LM_BUG("FS bad connect to %s:%d", sock->host.s, sock->port);
			continue;
		}

		if (reactor_add_reader(sock->handle->sock, F_FS_CONN,
		                       RCT_PRIO_TIMER, sock) < 0) {
			LM_ERR("failed to add FS socket %s:%d to reactor\n",
			       sock->host.s, sock->port);
			ret++;
			sock->handle->connected = 0;
			continue;
		}

		list_del(&sock->reconnect_list);
		INIT_LIST_HEAD(&sock->reconnect_list);
	}
	lock_stop_write(sockets_down_lock);

	lock_start_write(sockets_esl_lock);
	list_for_each_safe(_, __, fs_sockets_esl) {
		sock = list_entry(_, fs_evs, esl_cmd_list);

		if (!list_empty(&sock->reconnect_list))
			continue;

		if (run_esl_commands(sock) != 0)
			LM_ERR("errors while processing sock %s:%d commands\n",
			       sock->host.s, sock->port);
	}
	lock_stop_write(sockets_esl_lock);

	return ret;
}

void fs_conn_mgr_loop(int proc_no)
{
	int rc;

	LM_DBG("size: %d, method: %d\n", reactor_size, io_poll_method);

	if (init_worker_reactor("FS Manager", RCT_PRIO_MAX) != 0) {
		LM_BUG("failed to init FS reactor");
		abort();
	}

	if (reactor_add_reader(IPC_FD_READ_SHARED, F_IPC, RCT_PRIO_ASYNC, NULL)<0){
		LM_CRIT("failed to add IPC shared pipe to FS reactor\n");
		abort();
	}

	rc = apply_socket_commands(1);
	if (rc != 0)
		LM_ERR("failed to connect to %d FS boxes!\n", rc);

	reactor_main_loop(FS_REACTOR_TIMEOUT, out_err, apply_socket_commands(0));

out_err:
	destroy_io_wait(&_worker_io);
	abort();
}
