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
#include "fs_ipc.h"

#define FS_REACTOR_TIMEOUT  1 /* sec */
#define FS_STATS_EVENT_NAME "HEARTBEAT"

extern struct list_head *fs_sockets;
extern struct list_head *fs_sockets_down;
extern struct list_head *fs_sockets_esl;

extern rw_lock_t *sockets_lock;
extern rw_lock_t *sockets_down_lock;
extern rw_lock_t *sockets_esl_lock;

extern unsigned int fs_connect_timeout;

extern void fs_api_set_proc_no(void);
extern void evs_free(fs_evs *sock);
extern struct fs_event *get_event(fs_evs *sock, const str *name);

static int destroy_fs_evs(fs_evs *sock, int idx)
{
	esl_status_t rc;
	int ret = 0;

	LM_DBG("destroying sock %s:%d\n", sock->host.s, sock->port);

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

	if (!list_empty(&sock->reconnect_list)) {
		LM_DBG("unlinking from reconnect_list\n");
		list_del(&sock->reconnect_list);
	}

	if (!list_empty(&sock->esl_cmd_list)) {
		LM_DBG("unlinking from esl_cmd_list\n");
		list_del(&sock->esl_cmd_list);
	}

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

int fs_raise_event(fs_evs *sock, const char *name, const char *body)
{
	struct list_head *_;
	struct fs_event *event;
	struct fs_event_subscription *sub;
	str name_str = {(char *)name, strlen(name)};

	LM_DBG("pushing jobs for event %s\n", name);

	lock_start_read(sock->lists_lk);

	event = get_event(sock, &name_str);
	if (!event) {
		lock_stop_read(sock->lists_lk);
		LM_BUG("event %s raised with no backing subscription", name);
		return -1;
	}

	list_for_each(_, &event->subscriptions) {
		sub = list_entry(_, struct fs_event_subscription, list);
		if (sub->ref == 0 || ipc_bad_handler_type(sub->ipc_type))
			continue;

		LM_DBG("pushing event %s IPC job %d for %s\n", name,
		       sub->ipc_type, sub->tag.s);

		if (fs_ipc_dispatch_esl_event(sock, &name_str, body,
		                              sub->ipc_type) != 0) {
			LM_ERR("failed to raise %s event on %s:%d\n", name,
			       sock->host.s, sock->port);
		}
	}

	lock_stop_read(sock->lists_lk);

	return 0;
}

void prepare_reconnect(fs_evs *sock)
{
	struct list_head *_;
	struct fs_event *ev;

	/* force a resubscribe for each event */
	list_for_each (_, &sock->events) {
		ev = list_entry(_, struct fs_event, list);
		ev->action = FS_EVENT_SUB;
	}

	lock_start_write(sockets_esl_lock);
	if (list_empty(&sock->esl_cmd_list))
		list_add_tail(&sock->esl_cmd_list, fs_sockets_esl);
	lock_stop_write(sockets_esl_lock);

	lock_start_write(sockets_down_lock);
	list_add_tail(&sock->reconnect_list, fs_sockets_down);
	lock_stop_write(sockets_down_lock);
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

	switch (fm->type) {
		case F_FS_CONN:
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

			esl_event_safe_destroy(&sock->handle->last_sr_event);

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

				prepare_reconnect(sock);
				return 0;
			}

			ev = cJSON_Parse(sock->handle->last_sr_event->body);
			if (!ev) {
				LM_ERR("oom\n");
				return 0;
			}

			s = cJSON_GetObjectItem(ev, "Event-Name")->valuestring;

			/* fire event notifications to any subscribers */
			if (fs_raise_event(sock, s,
			                   sock->handle->last_sr_event->body) != 0)
				LM_ERR("errors during event %s raise on %.*s:%d\n",
				       s, sock->host.len, sock->host.s, sock->port);

			if (strcmp(s, FS_STATS_EVENT_NAME) == 0) {
				if (fs_renew_stats(sock, ev) != 0)
					LM_ERR("errors during stats %s renew on %s:%d\n",
					       s, sock->host.s, sock->port);
			}

			break;
		case F_IPC:
			LM_DBG("received IPC job!\n");
			ipc_handle_job(fm->fd);
			break;
		default:
			LM_CRIT("unknown fd type %d in FreeSWITCH worker\n", fm->type);
			return 0;
	}

	cJSON_Delete(ev);
	return 0;
}

enum esl_cmd_types {
	ESL_CMD,
	ESL_EVENT_SUB,
	ESL_EVENT_UNSUB,
};

int w_esl_send_recv(esl_handle_t *handle, const str *cmd, enum esl_cmd_types t)
{
#define ESL_BUF_SIZE 4096
#define LONGEST_CMD_EXTRA (sizeof("event json \n\n") - 1)
	static char command[BUF_SIZE];
	char *exec_cmd;

	if (cmd->len > ESL_BUF_SIZE - LONGEST_CMD_EXTRA - 1) {
		LM_ERR("refusing to run ESL commands longer than 4K bytes!\n");
		return -1;
	}

	switch (t) {
	case ESL_CMD:
		if (cmd->len >= 2 &&
		    memcmp(cmd->s + cmd->len - 2, "\n\n", 2) != 0) {
			exec_cmd = cmd->s;
		} else {
			if (cmd->s[cmd->len - 1] == '\n')
				snprintf(command, 4096, "%s\n", cmd->s);
			else
				snprintf(command, 4096, "%s\n\n", cmd->s);
			exec_cmd = command;
		}
		break;
	case ESL_EVENT_SUB:
		if (cmd->len >= 2 &&
		    memcmp(cmd->s + cmd->len - 2, "\n\n", 2) != 0) {
			snprintf(command, 4096, "event json %s", cmd->s);
		} else {
			if (cmd->s[cmd->len - 1] == '\n')
				snprintf(command, 4096, "event json %s\n", cmd->s);
			else
				snprintf(command, 4096, "event json %s\n\n", cmd->s);
		}
		exec_cmd = command;
		break;
	case ESL_EVENT_UNSUB:
		if (cmd->len >= 2 &&
		    memcmp(cmd->s + cmd->len - 2, "\n\n", 2) != 0) {
			snprintf(command, 4096, "nixevent %s", cmd->s);
		} else {
			if (cmd->s[cmd->len - 1] == '\n')
				snprintf(command, 4096, "nixevent %s\n", cmd->s);
			else
				snprintf(command, 4096, "nixevent %s\n\n", cmd->s);
		}
		exec_cmd = command;
		break;
	default:
		LM_BUG("invalid ESL command type: %d\n", t);
		return -1;
	}

	LM_DBG("running ESL command '%s'\n", exec_cmd);

	if (esl_send_recv(handle, exec_cmd) != ESL_SUCCESS) {
		LM_ERR("failed to run ESL command\n");
		return -1;
	}

	LM_DBG("success, reply is '%s'\n", handle->last_sr_reply);

	if (strncmp(handle->last_sr_reply, "-ERR", 4) == 0) {
		LM_ERR("error reply from ESL: %s\n", handle->last_sr_reply);
		return 1;
	} else if (strncmp(handle->last_sr_reply, "+OK", 3) != 0) {
		LM_DBG("unknown reply from ESL: %s\n", handle->last_sr_reply);
	}

	return 0;
}

void fs_run_esl_command(int sender, void *_cmd)
{
	fs_ipc_esl_cmd *cmd = (fs_ipc_esl_cmd *)_cmd;
	struct fs_esl_reply *reply;

	if (w_esl_send_recv(cmd->sock->handle, &cmd->fs_cmd, ESL_CMD) < 0) {
		LM_ERR("failed to run %.*s command on sock %s:%d\n",
		       cmd->fs_cmd.len, cmd->fs_cmd.s,
		       cmd->sock->host.s, cmd->sock->port);
		goto out;
	}

	LM_DBG("received reply: %s\n", cmd->sock->handle->last_sr_reply);

	reply = shm_malloc(sizeof *reply);
	if (!reply) {
		/* we already ran the command, just let the reader time out */
		LM_ERR("oom\n");
		goto out;
	}
	memset(reply, 0, sizeof *reply);

	reply->text.s = shm_strdup(cmd->sock->handle->last_sr_reply);
	if (!reply->text.s) {
		shm_free(reply);
		LM_ERR("oom\n");
		goto out;
	}
	reply->text.len = strlen(reply->text.s);
	reply->esl_reply_id = cmd->esl_reply_id;

	LM_DBG("adding to esl_replies\n");
	lock_start_write(cmd->sock->lists_lk);
	list_add_tail(&reply->list, &cmd->sock->esl_replies);
	lock_stop_write(cmd->sock->lists_lk);

out:
	shm_free(cmd->fs_cmd.s);
	shm_free(cmd);
}

int update_event_subscriptions(fs_evs *sock)
{
	struct list_head *_, *__;
	struct fs_event *event;
	int rc, ret = 0;

	lock_start_write(sock->lists_lk);

	/* handle any pending event actions */
	list_for_each_safe(_, __, &sock->events) {
		event = list_entry(_, struct fs_event, list);
		if (event->refsum > 0 && event->action == FS_EVENT_SUB) {
			LM_DBG("subscribing to %s events on %s:%d\n",
			       event->name.s, sock->host.s, sock->port);

			rc = w_esl_send_recv(sock->handle, &event->name, ESL_EVENT_SUB);
			switch (rc) {
			case -1:
				LM_ERR("error while subscribing to %s on ESL sock %s:%d\n",
				       event->name.s, sock->host.s, sock->port);
				ret++;
				continue;
			case 1:
				LM_ERR("ESL replied '%s' when we subscribed for %s on sock "
				       "%s:%d\n", sock->handle->last_sr_reply, event->name.s,
					   sock->host.s, sock->port);
				ret++;
				continue;
			}

			LM_INFO("subscribed to %s events on FS sock %s:%d\n",
			        event->name.s, sock->host.s, sock->port);
			event->action = FS_EVENT_NOP;
		}

		if (event->refsum == 0 && event->action == FS_EVENT_UNSUB) {
			LM_DBG("unsubscribing from %s events on %s:%d\n",
			       event->name.s, sock->host.s, sock->port);

			rc = w_esl_send_recv(sock->handle, &event->name, ESL_EVENT_UNSUB);
			switch (rc) {
			case -1:
				LM_ERR("error while unsubbing from %s on ESL sock %s:%d\n",
				       event->name.s, sock->host.s, sock->port);
				ret++;
				continue;
			case 1:
				LM_ERR("ESL replied '%s' when we unsubbed from %s on sock "
				       "%s:%d\n", sock->handle->last_sr_reply, event->name.s,
					   sock->host.s, sock->port);
				ret++;
				continue;
			}

			LM_INFO("unsubscribed from %s events on FS sock %s:%d\n",
			        event->name.s, sock->host.s, sock->port);
			event->action = FS_EVENT_NOP;
		}
	}

	lock_stop_write(sock->lists_lk);

	return ret;
}

/* referenced by 1+ modules or has performed at least one ESL command */
#define SHOULD_KEEP_EVS(sock) ((sock)->ref > 0 || (sock)->esl_reply_id > 1)

void handle_reconnects(void)
{
	struct list_head *_, *__;
	fs_evs *sock;

	list_for_each_safe(_, __, fs_sockets_down) {
		sock = list_entry(_, fs_evs, reconnect_list);

		LM_DBG("reconnecting sock %s:%d\n", sock->host.s, sock->port);

		if (sock->handle) {
			if (sock->handle->connected && sock->handle->sock != ESL_SOCK_INVALID) {
				if (!SHOULD_KEEP_EVS(sock)) {
					/*
					 * TODO: implement clean up for unused ESL connections here.
					 *       Currently not immediately possible because:
					 *	- reactor_del_reader() can only be called under handle_io()
					 *	- esl_disconnect() closes the fd, so handle_io() is skipped
					 */
					continue;
				}

				LM_DBG("fake disconnect on %s:%d\n", sock->host.s, sock->port);
				list_del(&sock->reconnect_list);
				INIT_LIST_HEAD(&sock->reconnect_list);
				continue;
			}
		} else {
			sock->handle = pkg_malloc(sizeof *sock->handle);
			if (!sock->handle) {
				LM_ERR("failed to create FS handle!\n");
				continue;
			}
			memset(sock->handle, 0, sizeof *sock->handle);
		}

		LM_DBG("reconnecting to FS sock '%s:%d'\n", sock->host.s, sock->port);

		if (esl_connect_timeout(sock->handle, sock->host.s, sock->port,
		      sock->user.s, sock->pass.s, fs_connect_timeout) != ESL_SUCCESS) {
			LM_ERR("failed to connect to FS sock '%s:%d'\n",
			       sock->host.s, sock->port);
			continue;
		}

		LM_DBG("successfully connected to FS %s:%d!\n", sock->host.s, sock->port);

		if (!sock->handle->connected) {
			LM_BUG("FS bad connect to %s:%d", sock->host.s, sock->port);
			esl_disconnect(sock->handle);
			continue;
		}

		if (reactor_add_reader(sock->handle->sock, F_FS_CONN,
		                       RCT_PRIO_TIMER, sock) < 0) {
			LM_ERR("failed to add FS socket %s:%d to reactor\n",
			       sock->host.s, sock->port);
			esl_disconnect(sock->handle);
			continue;
		}

		list_del(&sock->reconnect_list);
		INIT_LIST_HEAD(&sock->reconnect_list);
	}
}

/*
 * - reconnects any socket found in the "fs_sockets_down" list
 * - performs any necessary event subscribe / unsubscribe socket operations
 */
static void apply_socket_commands(void)
{
	struct list_head *_, *__;
	fs_evs *sock;
	int rc;

	LM_DBG("applying FS socket commands\n");

	lock_start_write(sockets_esl_lock);
	list_for_each_safe(_, __, fs_sockets_esl) {
		sock = list_entry(_, fs_evs, esl_cmd_list);

		/* above connect may have failed for this socket; skip it for now */
		if (SHOULD_KEEP_EVS(sock) && !list_empty(&sock->reconnect_list))
			continue;

		rc = update_event_subscriptions(sock);
		if (rc != 0) {
			LM_ERR("%d errors while processing sock %s:%d commands\n",
			       rc, sock->host.s, sock->port);
			continue;
		}

		list_del(&sock->esl_cmd_list);
		INIT_LIST_HEAD(&sock->esl_cmd_list);
	}
	lock_stop_write(sockets_esl_lock);

	/* we may also clean up some sockets */
	lock_start_write(sockets_lock);
	lock_start_write(sockets_down_lock);
	handle_reconnects();
	lock_stop_write(sockets_down_lock);
	lock_stop_write(sockets_lock);

}

void fs_conn_mgr_loop(int proc_no)
{
	fs_api_set_proc_no();

	LM_DBG("size: %d, method: %d\n", reactor_size, io_poll_method);

	if (init_worker_reactor("FS Manager", RCT_PRIO_MAX) != 0) {
		LM_BUG("failed to init FS reactor");
		abort();
	}

	if (reactor_add_reader(IPC_FD_READ_SELF, F_IPC, RCT_PRIO_ASYNC, NULL)<0){
		LM_CRIT("failed to add IPC pipe to FS reactor\n");
		abort();
	}

	/* connect to all FS sockets created on mod_init() or modparam */
	apply_socket_commands();

	reactor_main_loop(FS_REACTOR_TIMEOUT, out_err, apply_socket_commands());

out_err:
	destroy_io_wait(&_worker_io);
	abort();
}
