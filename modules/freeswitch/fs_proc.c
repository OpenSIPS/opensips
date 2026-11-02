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
#include <errno.h>
#include <limits.h>

#include "../../mem/mem.h"
#include "../../reactor.h"
#include "../../timer.h"
#include "../../ut.h"
#include "../../ipc.h"

#include "esl/src/include/esl.h"

#include "fs_api.h"
#include "fs_ipc.h"

#define FS_REACTOR_TIMEOUT  1000 /* ms */
#define FS_STATS_EVENT_NAME "HEARTBEAT"

extern struct list_head *fs_sockets;
extern struct list_head *fs_sockets_down;
extern struct list_head *fs_sockets_esl;

extern rw_lock_t *sockets_lock;
extern rw_lock_t *sockets_down_lock;
extern rw_lock_t *sockets_esl_lock;

extern unsigned int fs_connect_timeout;
extern unsigned int esl_cmd_timeout;
extern unsigned int event_heartbeat_interval;

extern void fs_api_set_proc_no(void);
extern void evs_free(fs_evs *sock);
extern struct fs_event *get_event(fs_evs *sock, const str *name);

static int fs_reconnect_backoff_v[] = {1, 5, 10, 30, 90}; /* sec */
static int fs_reconnect_backoff_n = 20; /* bump the backoff every N failures */
#define fs_reconnect_backoff_v_sz \
	(sizeof fs_reconnect_backoff_v/sizeof fs_reconnect_backoff_v[0])

/* sockets with no event subscriptions and no ESL commands ran for N seconds */
int fs_no_esl_timeout = 86400; /* sec */

#define SHOULD_KEEP_EVS(sock) ((sock)->ref > 0 || \
		/* has the script writer run at least 1 FS ESL command over it? */ \
		((sock)->handle && (sock)->esl_reply_id > 1 && \
			/* if yes, give it a reasonable # of reconnect attempts... */ \
			((!(sock)->handle->connected && (sock)->conn_attempts < \
				(fs_reconnect_backoff_n * fs_reconnect_backoff_v_sz)) \
			/* ... and also a reasonable time with no ESL commands at all */ \
			|| ((sock)->handle->connected && \
				(get_ticks() - (sock)->last_esl_jiffy) < fs_no_esl_timeout)) \
		 ))


/* ESL JSON must not be assumed to contain a string for every event key. */
static const char *fs_json_string(const cJSON *event, const char *key)
{
	cJSON *item = cJSON_GetObjectItem((cJSON *)event, key);

	if (!item || !(item->type & cJSON_String))
		return NULL;
	return item->valuestring;
}

static void fs_invalidate_stats(fs_evs *sock)
{
	lock_start_write(sock->stats_lk);
	sock->stats.valid = 0;
	lock_stop_write(sock->stats_lk);
}

static inline int fs_reactor_del_reader(int fd, int idx)
{
	int rc;

	if (idx >= 0 && (rc = reactor_del_reader(fd, idx, IO_FD_CLOSING)) != 0) {
		LM_ERR("failed to delete sock %d, idx %d\n", fd, idx);
		idx = -1;
	}

	if (idx < 0 && (rc = reactor_del_reader(fd, -1, IO_FD_CLOSING)) != 0)
		LM_DBG("failed to delete sock %d, idx -1\n", fd);

	return rc;
}

static void destroy_fs_evs(fs_evs *sock, int idx, int reactor_fd)
{
	esl_status_t rc;
	int fd;

	if (sock->invalid) {
		LM_BUG("attempting to destroy dangling socket (fd: %d, idx: %d)\n",
		       reactor_fd, idx);
		return;
	}


	if (sock->handle && reactor_fd >= 0 && reactor_fd != sock->handle->sock)
		LM_BUG("different reactor/esl-handle fds: %d/%d\n",
		       reactor_fd, sock->handle->sock);

	fd = (reactor_fd >= 0 ? reactor_fd :
	      sock->handle ? sock->handle->sock : -1);
	LM_DBG("destroying sock %s:%d (fd: %d)\n", sock->host.s, sock->port, fd);

	if (fd >= 0)
		fs_reactor_del_reader(fd, idx);

	if (sock->handle) {
		rc = esl_disconnect(sock->handle);
		if (rc != ESL_SUCCESS)
			LM_DBG("disconnect returned %d on FS sock %.*s:%d\n",
			       rc, sock->host.len, sock->host.s, sock->port);
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
}


int fs_renew_stats(fs_evs *sock, const cJSON *ev)
{
	fs_stats stats;
	const char *s;
	char *end;
	double idle;
	long num;

	memset(&stats, 0, sizeof stats);

	s = fs_json_string(ev, "Idle-CPU");
	if (!s) {
		LM_ERR("HEARTBEAT has no string Idle-CPU\n");
		return -1;
	}
	errno = 0;
	idle = strtod(s, &end);
	if (errno == ERANGE || end == s || *end || !(idle >= 0 && idle <= 100)) {
		LM_ERR("bad Idle-CPU: %s\n", s);
		return -1;
	}
	stats.id_cpu = (float)idle;

	s = fs_json_string(ev, "Session-Count");
	if (!s) {
		LM_ERR("HEARTBEAT has no string Session-Count\n");
		return -1;
	}
	errno = 0;
	num = strtol(s, &end, 10);
	if (errno == ERANGE || end == s || *end || num < 0 || num > INT_MAX) {
		LM_ERR("bad Session-Count: %s\n", s);
		return -1;
	}
	stats.sess = (int)num;

	s = fs_json_string(ev, "Max-Sessions");
	if (!s) {
		LM_ERR("HEARTBEAT has no string Max-Sessions\n");
		return -1;
	}
	errno = 0;
	num = strtol(s, &end, 10);
	if (errno == ERANGE || end == s || *end || num <= 0 || num > INT_MAX) {
		LM_ERR("bad Max-Sessions: %s\n", s);
		return -1;
	}
	stats.max_sess = (int)num;

	stats.valid = 1;
	stats.updated_jiffy = get_ticks();

	LM_DBG("FS stats (%s:%d), idle cpu: %.3f, sessions: %d/%d\n",
	       sock->host.s, sock->port, stats.id_cpu, stats.sess, stats.max_sess);

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
		LM_DBG("event %s has no local subscribers\n", name);
		return 0;
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

	/* Subscriptions may be changed concurrently by MI/script workers. */
	lock_start_write(sock->lists_lk);
	list_for_each (_, &sock->events) {
		ev = list_entry(_, struct fs_event, list);
		if (ev->refsum > 0)
			ev->action = FS_EVENT_SUB;
	}
	lock_stop_write(sock->lists_lk);

	fs_invalidate_stats(sock);
	evs_reset_flags(sock, FS_EVS_FL_CONNECTED);

	lock_start_write(sockets_esl_lock);
	if (list_empty(&sock->esl_cmd_list))
		list_add_tail(&sock->esl_cmd_list, fs_sockets_esl);
	lock_stop_write(sockets_esl_lock);

	lock_start_write(sockets_down_lock);
	if (list_empty(&sock->reconnect_list))
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
	const char *s, *subclass;
	char *custom_name;
	size_t custom_len;

	switch (fm->type) {
		case F_GEN_PROC:
			LM_DBG("FS data available on sock %s:%d, ref: %d\n",
			       sock->host.s, sock->port, sock->ref);

			lock_start_write(sockets_lock);
			if (sock->ref == 0) {
				/* ignore the event, the socket is unused */
				destroy_fs_evs(sock, idx, fm->fd);
				lock_stop_write(sockets_lock);
				return 0;
			}
			lock_stop_write(sockets_lock);

			esl_event_safe_destroy(&sock->handle->last_sr_event);

			rc = esl_recv_event(sock->handle, 0, &sock->handle->last_sr_event);
			if (rc != ESL_SUCCESS) {
				LM_ERR("read error %d on FS sock %.*s:%d. Reconnecting...\n",
				       rc, sock->host.len, sock->host.s, sock->port);

				fs_reactor_del_reader(fm->fd, idx);

				rc = esl_disconnect(sock->handle);
				if (rc != ESL_SUCCESS) {
					LM_ERR("disconnect error %d on FS sock %.*s:%d\n",
					       rc, sock->host.len, sock->host.s, sock->port);
					sock->handle->connected = 0;
				}

				prepare_reconnect(sock);
				return 0;
			}


			if (!sock->handle->last_sr_event ||
			    !sock->handle->last_sr_event->body) {
				LM_ERR("ESL returned an empty event on %s:%d\n",
				       sock->host.s, sock->port);
				break;
			}

			ev = cJSON_Parse(sock->handle->last_sr_event->body);
			if (!ev) {
				LM_ERR("bad ESL event JSON on %s:%d\n",
				       sock->host.s, sock->port);
				break;
			}

			s = fs_json_string(ev, "Event-Name");
			if (!s || !*s) {
				LM_ERR("ESL event missing string Event-Name on %s:%d\n",
				       sock->host.s, sock->port);
				break;
			}

			/*
			 * An ESL subscription can be "CUSTOM sofia::register",
			 * while the JSON Event-Name is just "CUSTOM".
			 * Deliver subclass-specific and generic CUSTOM events.
			 */
			if (strcmp(s, "CUSTOM") == 0) {
				subclass = fs_json_string(ev, "Event-Subclass");
				if (subclass && *subclass) {
					custom_len = strlen(subclass) + sizeof("CUSTOM ");
					custom_name = pkg_malloc(custom_len);
					if (!custom_name) {
						LM_ERR("oom formatting CUSTOM ESL event\n");
					} else {
						snprintf(custom_name, custom_len,
						         "CUSTOM %s", subclass);
						fs_raise_event(sock, custom_name,
						               sock->handle->last_sr_event->body);
						pkg_free(custom_name);
					}
				}
			}

			fs_raise_event(sock, s, sock->handle->last_sr_event->body);

			if (strcmp(s, FS_STATS_EVENT_NAME) == 0 &&
			    fs_renew_stats(sock, ev) != 0)
				LM_ERR("errors during stats renewal on %s:%d\n",
				       sock->host.s, sock->port);

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


/* An api/response carries its payload in the event body, not reply-text. */
static const char *fs_esl_reply_text(esl_handle_t *handle)
{
	const char *type;

	if (handle->last_sr_event && handle->last_sr_event->body) {
		type = esl_event_get_header(handle->last_sr_event, "content-type");
		if (type && strcasecmp(type, "api/response") == 0)
			return handle->last_sr_event->body;
	}
	return handle->last_sr_reply;
}

int w_esl_send_recv(esl_handle_t *handle, const str *cmd, enum esl_cmd_types t)
{
#define ESL_BUF_SIZE 4096
	char command[ESL_BUF_SIZE];
	const char *prefix, *reply;
	int len;

	if (!cmd || !cmd->s || cmd->len <= 0) {
		LM_ERR("refusing an empty ESL command\n");
		return -1;
	}

	switch (t) {
	case ESL_CMD:
		prefix = "";
		break;
	case ESL_EVENT_SUB:
		prefix = "event json ";
		break;
	case ESL_EVENT_UNSUB:
		prefix = "nixevent ";
		break;
	default:
		LM_BUG("invalid ESL command type: %d\n", t);
		return -1;
	}

	/* The ESL protocol requires a blank line to terminate each command. */
	len = snprintf(command, sizeof command, "%s%.*s",
	               prefix, cmd->len, cmd->s);
	if (len < 0 || len > (int)sizeof(command) - 3) {
		LM_ERR("refusing an ESL command longer than the buffer\n");
		return -1;
	}
	if (len < 2 || memcmp(command + len - 2, "\n\n", 2) != 0) {
		command[len++] = '\n';
		command[len++] = '\n';
		command[len] = '\0';
	}

	LM_DBG("running ESL command '%s'\n", command);
	if (esl_send_recv(handle, command) != ESL_SUCCESS) {
		LM_ERR("failed to run ESL command\n");
		return -1;
	}

	reply = fs_esl_reply_text(handle);
	LM_DBG("ESL reply: '%s'\n", reply ? reply : "");
	if (reply && strncmp(reply, "-ERR", 4) == 0) {
		LM_ERR("error reply from ESL: %s\n", reply);
		return 1;
	}
	return 0;
}

void fs_run_esl_command(int sender, void *_cmd)
{
	fs_ipc_esl_cmd *cmd = (fs_ipc_esl_cmd *)_cmd;
	struct fs_esl_reply *reply;
	const char *reply_text;
	int result;

	result = w_esl_send_recv(cmd->sock->handle, &cmd->fs_cmd, ESL_CMD);
	if (result < 0) {
		LM_ERR("failed to run %.*s command on sock %s:%d\n",
		       cmd->fs_cmd.len, cmd->fs_cmd.s,
		       cmd->sock->host.s, cmd->sock->port);
		reply_text = "-ERR ESL command failed";
	} else {
		reply_text = fs_esl_reply_text(cmd->sock->handle);
		if (!reply_text)
			reply_text = "";
	}
	LM_DBG("received reply: %s\n", reply_text);

	reply = shm_malloc(sizeof *reply);
	if (!reply) {
		/* we already ran the command, just let the reader time out */
		LM_ERR("oom\n");
		goto out;
	}
	memset(reply, 0, sizeof *reply);

	reply->text.s = shm_strdup(reply_text);
	if (!reply->text.s) {
		shm_free(reply);
		LM_ERR("oom\n");
		goto out;
	}
	reply->text.len = strlen(reply->text.s);
	reply->esl_reply_id = cmd->esl_reply_id;
	reply->status = (result == 0 ? 0 : -1);
	reply->created_at = get_ticks();

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
		LM_DBG("process event %s, refsum: %d, action: %d\n", event->name.s,
		       event->refsum, event->action);

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

void handle_reconnects(void)
{
	struct list_head *_, *__;
	fs_evs *sock;
	int first = 0, backoff = 1, i = -1;
	unsigned int now;

	list_for_each_safe(_, __, fs_sockets_down) {
		sock = list_entry(_, fs_evs, reconnect_list);

		/* Unreferenced failed sockets must not reconnect forever. */
		if (!SHOULD_KEEP_EVS(sock)) {
			destroy_fs_evs(sock, -1, -1);
			continue;
		}

		i = sock->conn_attempts / fs_reconnect_backoff_n;
		if (i >= fs_reconnect_backoff_v_sz)
			i = fs_reconnect_backoff_v_sz - 1;
		backoff =  fs_reconnect_backoff_v[i];

		now = get_ticks();
		LM_DBG("reconnect check for sock %s:%d, backoff: %d/%d, attempts: %u, "
				"last-attempt-ticks: %u/%u\n", sock->host.s, sock->port,
		        backoff, i, sock->conn_attempts, sock->last_conn_jiffy, now);

		if (sock->last_conn_jiffy && (now - sock->last_conn_jiffy < backoff)) {
			LM_DBG("  (delaying reconnect due to backoff)\n");
			continue;
		}

		if (sock->handle) {
			if (fs_evs_connected(sock)) {
				if (!SHOULD_KEEP_EVS(sock)) {
					destroy_fs_evs(sock, -1, -1);
					continue;
				}

				LM_DBG("outdated reconnect on %s:%d, skipping\n", sock->host.s, sock->port);
				sock->conn_attempts = 0;
				evs_set_flags(sock, FS_EVS_FL_CONNECTED);
				list_del(&sock->reconnect_list);
				INIT_LIST_HEAD(&sock->reconnect_list);
				continue;
			}
		} else {
			first = 1;
			sock->handle = pkg_malloc(sizeof *sock->handle);
			if (!sock->handle) {
				LM_ERR("failed to create FS handle!\n");
				continue;
			}
			memset(sock->handle, 0, sizeof *sock->handle);
			sock->handle->sock = ESL_SOCK_INVALID;
		}

		sock->conn_attempts++;
		sock->last_conn_jiffy = now;
		evs_reset_flags(sock, FS_EVS_FL_CONNECTED);
		LM_DBG("%sconnecting to FS sock '%s:%d'\n", first ? "":"re-",
		        sock->host.s, sock->port);

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

		if (reactor_add_reader(sock->handle->sock, F_GEN_PROC,
		                       RCT_PRIO_TIMER, sock) < 0) {
			LM_ERR("failed to add FS socket %s:%d to reactor\n",
			       sock->host.s, sock->port);
			esl_disconnect(sock->handle);
			continue;
		}

		sock->conn_attempts = 0;
		evs_set_flags(sock, FS_EVS_FL_CONNECTED);
		list_del(&sock->reconnect_list);
		INIT_LIST_HEAD(&sock->reconnect_list);
	}
}


/*
 * fs_esl() stops waiting after esl_cmd_timeout.  Its late replies are no
 * longer consumed, so expire them here rather than keeping them forever.
 * Two timeout intervals allow a waiting process to obtain an on-time reply.
 */
static void fs_expire_replies(fs_evs *sock, unsigned int now)
{
	struct list_head *_, *__;
	struct fs_esl_reply *reply;
	unsigned int ttl = esl_cmd_timeout > 0 ?
		(unsigned int)(esl_cmd_timeout / 1000 + 2) * 2 : 10;

	lock_start_write(sock->lists_lk);
	list_for_each_safe(_, __, &sock->esl_replies) {
		reply = list_entry(_, struct fs_esl_reply, list);
		if ((unsigned int)(now - reply->created_at) <= ttl)
			continue;

		list_del(&reply->list);
		shm_free(reply->text.s);
		shm_free(reply);
	}
	lock_stop_write(sock->lists_lk);
}

/*
 * A remote FS can disappear without sending FIN/RST.  Check the age of its
 * last heartbeat so the TCP connection gets rebuilt even across a blackhole.
 * Keep a 60-second floor because older FreeSWITCH configurations may send
 * heartbeats every 20 seconds regardless of the OpenSIPS setting.
 */
static void fs_check_heartbeats(void)
{
	struct list_head *_, *__;
	struct fs_event *event;
	fs_evs *sock;
	str heartbeat = str_init(FS_STATS_EVENT_NAME);
	unsigned int now = get_ticks(), last;
	unsigned int timeout = (event_heartbeat_interval > 20 ?
		event_heartbeat_interval * 3 : 60);
	int subscribed, fd;

	lock_start_write(sockets_lock);
	list_for_each_safe(_, __, fs_sockets) {
		sock = list_entry(_, fs_evs, list);
		fs_expire_replies(sock, now);

		if (!fs_evs_connected(sock) || sock->ref <= 0)
			continue;

		lock_start_read(sock->lists_lk);
		event = get_event(sock, &heartbeat);
		subscribed = (event && event->refsum > 0);
		lock_stop_read(sock->lists_lk);
		if (!subscribed)
			continue;

		lock_start_read(sock->stats_lk);
		last = sock->stats.valid ?
			sock->stats.updated_jiffy : sock->last_conn_jiffy;
		lock_stop_read(sock->stats_lk);
		if (!last || (unsigned int)(now - last) <= timeout)
			continue;

		LM_WARN("no HEARTBEAT from FS %s:%d in %u s; reconnecting\n",
			sock->host.s, sock->port, (unsigned int)(now - last));
		fd = sock->handle->sock;
		if (fd >= 0)
			fs_reactor_del_reader(fd, -1);
		esl_disconnect(sock->handle);
		prepare_reconnect(sock);
	}
	lock_stop_write(sockets_lock);
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

#ifdef EXTRA_DEBUG
	LM_DBG("applying FS socket commands\n");
#endif

	lock_start_write(sockets_esl_lock);
	list_for_each_safe(_, __, fs_sockets_esl) {
		sock = list_entry(_, fs_evs, esl_cmd_list);

		/* above connect may have failed for this socket; skip it for now */
		if (!SHOULD_KEEP_EVS(sock) || !list_empty(&sock->reconnect_list))
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

	/* Expire abandoned command replies and detect missing HEARTBEATs. */
	fs_check_heartbeats();

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

#ifdef EXTRA_DEBUG
	LM_DBG("size: %d, method: %d\n", reactor_size, io_poll_method);
#endif

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
