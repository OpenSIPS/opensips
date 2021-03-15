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
 *  2017-01-23 initial version (liviu)
 */

#include "../../parser/parse_uri.h"
#include "../../resolve.h"
#include "../../forward.h"
#include "../../ut.h"
#include "../../lib/url.h"

#include "fs_api.h"
#include "fs_ipc.h"

#define FS_STATS_EVENT_NAME "HEARTBEAT"
#define FS_STATS_EVENT_STR {FS_STATS_EVENT_NAME,sizeof(FS_STATS_EVENT_NAME)-1}

extern int event_heartbeat_interval;
extern int esl_cmd_polling_itv;
extern int esl_cmd_timeout;

/* SHM pointer */
unsigned int *conn_mgr_process_no;

/*
 * Any FreeSWITCH socket which is still referenced at least once
 * Both FS proc and random OpenSIPS MI reloaders may write to this list
 */
struct list_head *fs_sockets;
rw_lock_t *sockets_lock;

/*
 *	fs_sockets ⊇ fs_sockets_down (sockets which require a (re)connect)
 *	fs_sockets ⊇ fs_sockets_esl (sockets which have pending sub/unsub ESL cmds)
 */
struct list_head *fs_sockets_down;
rw_lock_t *sockets_down_lock;

struct list_head *fs_sockets_esl;
rw_lock_t *sockets_esl_lock;

/* mem reusage - unique string tags and events accumulated so far */
static str_list *all_tags;
//static str_list *all_events;

int fs_api_init(void)
{
	fs_sockets = shm_malloc(3 * sizeof *fs_sockets);
	if (!fs_sockets) {
		LM_ERR("oom\n");
		return -1;
	}
	INIT_LIST_HEAD(fs_sockets);

	fs_sockets_down = fs_sockets + 1;
	INIT_LIST_HEAD(fs_sockets_down);

	fs_sockets_esl = fs_sockets + 2;
	INIT_LIST_HEAD(fs_sockets_esl);

	sockets_lock = lock_init_rw();
	sockets_down_lock = lock_init_rw();
	sockets_esl_lock = lock_init_rw();
	if (!sockets_lock || !sockets_down_lock || !sockets_esl_lock) {
		LM_ERR("oom\n");
		return -1;
	}

	conn_mgr_process_no = shm_malloc(sizeof *conn_mgr_process_no);
	if (!conn_mgr_process_no) {
		LM_ERR("oom\n");
		return -1;
	}

	return 0;
}

int fs_api_set_proc_no(void)
{
	LM_DBG("setting global mgr process_no=%d\n", process_no);
	*conn_mgr_process_no = process_no;
	return 0;
}

/* TODO: rework this specific "PID advertising" hack
 * as part of a more reusable OpenSIPS mechanism */
int fs_api_wait_init(void)
{
	int i;

	/* time out startup after 10 sec */
	for (i = 0; i < 2000000; i++) {
		if (*conn_mgr_process_no != 0)
			return 0;

		usleep(5);
	}

	LM_ERR("FS API is not ready for use after 10 sec, aborting\n");
	return -1;
}

void evs_free(fs_evs *sock)
{
	struct list_head *_, *__;
	struct fs_event *ev;
	struct fs_esl_reply *reply;

	if (sock->ref > 0) {
		LM_BUG("non-zero ref @ free");
		return;
	}

	list_for_each_safe(_, __, &sock->events) {
		ev = list_entry(_, struct fs_event, list);
		shm_free(ev);
	}

	list_for_each_safe(_, __, &sock->esl_replies) {
		reply = list_entry(_, struct fs_esl_reply, list);
		shm_free(reply->text.s);
		shm_free(reply);
	}

	shm_free(sock->host.s);
	shm_free(sock->user.s);
	shm_free(sock->pass.s);
	pkg_free(sock->handle);

	lock_destroy_rw(sock->stats_lk);
	lock_destroy_rw(sock->lists_lk);

	memset(sock, 0, sizeof *sock);
	shm_free(sock);
}

static fs_evs *evs_init(const str *host, unsigned short port,
                        const str *user, const str *pass)
{
	fs_evs *sock;

	if (!host || !host->s || host->len == 0) {
		LM_ERR("host cannot be NULL!\n");
		return NULL;
	}

	if (!pass || !pass->s || pass->len == 0) {
		LM_ERR("the password part is mandatory for a new socket!\n");
		return NULL;
	}

	sock = shm_malloc(sizeof *sock);
	if (!sock) {
		LM_ERR("oom\n");
		return NULL;
	}
	memset(sock, 0, sizeof *sock);
	INIT_LIST_HEAD(&sock->esl_replies);
	INIT_LIST_HEAD(&sock->events);
	INIT_LIST_HEAD(&sock->reconnect_list);
	INIT_LIST_HEAD(&sock->esl_cmd_list);

	sock->stats_lk = lock_init_rw();
	if (!sock->stats_lk) {
		LM_ERR("oom\n");
		goto err_free;
	}

	sock->lists_lk = lock_init_rw();
	if (!sock->lists_lk) {
		LM_ERR("oom\n");
		goto err_free;
	}

	if (shm_nt_str_dup(&sock->host, host) != 0) {
		LM_ERR("oom\n");
		goto err_free;
	}

	if (user && shm_nt_str_dup(&sock->user, user) != 0) {
		LM_ERR("oom\n");
		goto err_free;
	}

	if (pass && shm_nt_str_dup(&sock->pass, pass) != 0) {
		LM_ERR("oom\n");
		goto err_free;
	}

	sock->port = port;
	sock->esl_reply_id = 1;

	LM_DBG("new FS sock: host=%s, port=%d, user=%s, pass=%s\n",
	       sock->host.s, sock->port, sock->user.s, sock->pass.s);

	return sock;

err_free:
	evs_free(sock);
	return NULL;
}

int evs_update(fs_evs *sock, const str *user, const str *pass)
{
	str user_dup = {NULL, 0}, pass_dup;

	if (!ZSTRP(user)) {
		if (shm_nt_str_dup(&user_dup, user) != 0) {
			LM_ERR("oom\n");
			return -1;
		}
	}

	if (!ZSTRP(pass)) {
		if (shm_nt_str_dup(&pass_dup, pass) != 0) {
			LM_ERR("oom\n");
			if (!ZSTRP(user))
				shm_free(user_dup.s);
			return -1;
		}
	}

	if (!ZSTRP(user)) {
		shm_free(sock->user.s);
		sock->user = user_dup;
	} else {
		shm_free(sock->user.s);
		memset(&sock->user, 0, sizeof sock->user);
	}

	/* never end up with an empty password */
	if (!ZSTRP(pass)) {
		shm_free(sock->pass.s);
		sock->pass = pass_dup;
	}

	return 0;
}

static fs_evs* get_evs(const str *host, unsigned short port,
                       const str *user, const str *pass)
{
	struct list_head *_;
	fs_evs *sock = NULL;

	if (!host || !host->s || host->len == 0) {
		LM_ERR("cannot locate a socket without a host!\n");
		return NULL;
	}

	if (port == 0)
		port = FS_DEFAULT_EVS_PORT;

	LM_DBG("fetching %.*s:%d, user='%.*s', pass='%.*s'\n",
	       host->len, host->s, port,
	       user ? user->len : 0, user ? user->s : NULL,
	       pass ? pass->len : 0, pass ? pass->s : NULL);

	lock_start_write(sockets_lock);

	list_for_each(_, fs_sockets) {
		sock = list_entry(_, fs_evs, list);
		if (str_strcmp(host, &sock->host) == 0 && port == sock->port)
			break;

		sock = NULL;
	}

	if (!sock) {
		sock = evs_init(host, port, user, pass);
		if (!sock) {
			lock_stop_write(sockets_lock);
			LM_ERR("failed to create FS event socket!\n");
			return NULL;
		}

		list_add(&sock->list, fs_sockets);

		lock_start_write(sockets_down_lock);
		list_add(&sock->reconnect_list, fs_sockets_down);
		lock_stop_write(sockets_down_lock);
	} else {
		evs_update(sock, user, pass);

		LM_DBG("found & updated FS sock: host=%s, port=%d, user=%s, pass=%s\n",
		       sock->host.s, sock->port, sock->user.s, sock->pass.s);
	}

	sock->ref++;

	lock_stop_write(sockets_lock);
	return sock;
}

static fs_evs *get_evs_by_url(const str *_fs_url)
{
	fs_evs *sock;
	struct url *fs_url;

	fs_url = parse_url(_fs_url, 0, 0);
	if (!fs_url) {
		LM_ERR("failed to parse FS URL '%.*s'\n", _fs_url->len, _fs_url->s);
		return NULL;
	}

	sock = get_evs(&fs_url->hosts->host, fs_url->hosts->port,
	               &fs_url->username, &fs_url->password);

	if (!sock) {
		if (!fs_url->password.s)
			LM_ERR("refusing to connect to FS '%.*s' without a password!\n",
			       _fs_url->len, _fs_url->s);
		else
			LM_ERR("internal error - oom?\n");
	}

	free_url(fs_url);
	return sock;
}

int dup_common_tag(const str *tag, str *out)
{
	str_list *t;

	if (!tag || !tag->s || tag->len == 0) {
		memset(out, 0, sizeof *out);
		return 0;
	}

	for (t = all_tags; t; t = t->next) {
		if (str_strcmp(&t->s, tag) == 0) {
			*out = t->s;
			return 0;
		}
	}

	t = shm_malloc(sizeof *t + tag->len + 1);
	if (!t) {
		LM_ERR("oom\n");
		return -1;
	}
	memset(t, 0, sizeof *t);

	t->s.s = (char *)(t + 1);
	t->s.len = tag->len;
	memcpy(t->s.s, tag->s, tag->len);
	t->s.s[t->s.len] = '\0';

	if (!all_tags) {
		all_tags = t;
	} else {
		t->next = all_tags;
		all_tags = t;
	}

	*out = t->s;
	return 0;
}

int add_event_subscription(struct fs_event *event, const str *tag,
                           ipc_handler_type ipc_type)
{
	struct list_head *_;
	struct fs_event_subscription *sub = NULL;

	list_for_each(_, &event->subscriptions) {
		sub = list_entry(_, struct fs_event_subscription, list);
		if (str_strcmp(&sub->tag, tag) == 0) {
			sub->ref++;
			if (!ipc_bad_handler_type(ipc_type))
				sub->ipc_type = ipc_type;
			break;
		}

		sub = NULL;
	}

	if (!sub) {
		sub = shm_malloc(sizeof *sub);
		if (!sub) {
			LM_ERR("oom\n");
			return -1;
		}
		memset(sub, 0, sizeof *sub);

		if (dup_common_tag(tag, &sub->tag) != 0) {
			shm_free(sub);
			LM_ERR("oom\n");
			return -1;
		}

		sub->ref = 1;
		sub->ipc_type = ipc_type;
		list_add_tail(&sub->list, &event->subscriptions);
	}

	event->refsum++;
	return 0;
}

int del_event_subscription(struct fs_event *event, const str *tag)
{
	struct list_head *_;
	struct fs_event_subscription *sub = NULL;

	list_for_each(_, &event->subscriptions) {
		sub = list_entry(_, struct fs_event_subscription, list);
		if (str_strcmp(&sub->tag, tag) == 0) {
			if (sub->ref == 0)
				return -1;

			sub->ref--;

			if (event->refsum <= 0)
				LM_BUG("del event refsum");

			event->refsum--;
			return 0;
		}
	}

	return -1;
}

struct fs_event *add_event(fs_evs *sock, const str *name)
{
	struct fs_event *event;

	event = shm_malloc(sizeof *event);
	if (!event) {
		LM_ERR("oom\n");
		return NULL;
	}
	memset(event, 0, sizeof *event);

	if (dup_common_tag(name, &event->name) != 0) {
		shm_free(event);
		LM_ERR("oom\n");
		return NULL;
	}

	event->action = FS_EVENT_SUB;
	INIT_LIST_HEAD(&event->subscriptions);

	list_add_tail(&event->list, &sock->events);
	return event;
}

struct fs_event *get_event(fs_evs *sock, const str *name)
{
	struct list_head *_;
	struct fs_event *event;

	list_for_each(_, &sock->events) {
		event = list_entry(_, struct fs_event, list);
		if (str_strcmp(&event->name, name) == 0)
			return event;
	}

	return NULL;
}

int evs_sub(fs_evs *sock, const str *tag, const str_list *name,
            ipc_handler_type ipc_type)
{
	struct fs_event *event;
	int ret = 0;

	lock_start_write(sock->lists_lk);

	for (; name; name = name->next) {
		event = NULL;

		event = get_event(sock, &name->s);
		if (!event) {
			event = add_event(sock, &name->s);
			if (!event) {
				LM_ERR("failed to alloc event\n");
				ret = -1;
				continue;
			}
		}

		if (add_event_subscription(event, tag, ipc_type) != 0) {
			LM_ERR("failed to alloc subscription\n");
			ret = -1;
			continue;
		}

		if (event->refsum == 1) {
			/* there is a pending unsub action we must cancel! */
			if (event->action == FS_EVENT_UNSUB)
				event->action = FS_EVENT_NOP;
			else
				event->action = FS_EVENT_SUB;
		}
	}

	lock_stop_write(sock->lists_lk);

	/* always place it in the ESL "todo" list; we released the lock, so we
	 * cannot guarantee that the above esl_cmd's haven't been consumed by now
	 * worst case: we mark it as "todo" with no pending cmds, which is fine */
	lock_start_write(sockets_esl_lock);
	if (list_empty(&sock->esl_cmd_list))
		list_add_tail(&sock->esl_cmd_list, fs_sockets_esl);
	lock_stop_write(sockets_esl_lock);

	if (ret != 0)
		LM_ERR("oom! some events may have been skipped\n");

	return ret;
}

void evs_unsub(fs_evs *sock, const str *tag, const str_list *name)
{
	struct fs_event *event;
	int ret = 0;

	lock_start_write(sock->lists_lk);

	for (; name; name = name->next) {
		event = get_event(sock, &name->s);
		if (!event) {
			LM_DBG("not subscribed for %.*s\n", name->s.len, name->s.s);
			continue;
		}

		if (del_event_subscription(event, tag) != 0) {
			LM_DBG("%.*s is not subscribed to %.*s\n", tag->len, tag->s,
			       name->s.len, name->s.s);
			continue;
		}

		if (event->refsum == 0) {
			/* there is a pending sub action we must cancel! */
			if (event->action == FS_EVENT_SUB)
				event->action = FS_EVENT_NOP;
			else
				event->action = FS_EVENT_UNSUB;
		}
	}

	lock_stop_write(sock->lists_lk);

	/* always place it in the ESL "todo" list; we released the lock, so we
	 * cannot guarantee that the above esl_cmd's haven't been consumed by now
	 * worst case: we mark it as "todo" with no pending cmds, which is fine */
	lock_start_write(sockets_esl_lock);
	if (list_empty(&sock->esl_cmd_list))
		list_add_tail(&sock->esl_cmd_list, fs_sockets_esl);
	lock_stop_write(sockets_esl_lock);

	if (ret != 0)
		LM_ERR("oom! some events may have been skipped\n");
}

void put_evs(fs_evs *sock)
{
	/* prevents deadlocks on shutdown.
	 *
	 * For the FreeSWITCH OpenSIPS module, "graceful shutdowns" are not
	 * possible, since the main process brutally murders the FS connection
	 * manager before it gets a chance to gracefully EOF its TCP connections.
	 */
	if (is_main)
		return;

	lock_start_write(sockets_lock);
	lock_start_write(sockets_down_lock);
	sock->ref--;
	if (sock->ref == 0) {
		if (list_empty(&sock->reconnect_list))
			list_add(&sock->reconnect_list, fs_sockets_down);
	}
	lock_stop_write(sockets_down_lock);
	lock_stop_write(sockets_lock);

	LM_DBG("sock %s:%d, ref=%d, rpl_id=%lu\n", sock->host.s, sock->port,
	       sock->ref, sock->esl_reply_id);

	/**
	 * We cannot immediately free the event socket, as the fd might be polled
	 * by the FreeSWITCH worker process. The ref == 0 check is done there
	 */
}

fs_evs *get_stats_evs(str *fs_url, str *tag)
{
	fs_evs *sock;
	str_list ev_list = {FS_STATS_EVENT_STR, NULL};

	if (!fs_url->s || fs_url->len == 0 || !tag || !tag->s || tag->len == 0) {
		LM_ERR("bad params: '%.*s', %.*s\n", fs_url->len, fs_url->s,
		       (tag ? tag->len:0), (tag ? tag->s: ""));
		return NULL;
	}

	sock = get_evs_by_url(fs_url);
	LM_DBG("getevs (%.*s): %p\n", fs_url->len, fs_url->s, sock);
	if (!sock) {
		LM_ERR("failed to create a FS socket for %.*s!\n",
		       fs_url->len, fs_url->s);
		return NULL;
	}

	if (evs_sub(sock, tag, &ev_list, IPC_TYPE_NONE) != 0) {
		LM_ERR("failed to subscribe for stats on %s:%d\n",
		       sock->host.s, sock->port);
		put_evs(sock);
		return NULL;
	}

	return sock;
}

void put_stats_evs(fs_evs *sock, str *tag)
{
	str_list ev_list = {FS_STATS_EVENT_STR, NULL};

	/* prevents deadlocks on shutdown.
	 *
	 * For the FreeSWITCH OpenSIPS module, "graceful shutdowns" are not
	 * possible, since the main process brutally murders the FS connection
	 * manager before it gets a chance to gracefully EOF its TCP connections.
	 */
	if (is_main)
		return;

	evs_unsub(sock, tag, &ev_list);
	put_evs(sock);
}

/* This function assumes that the FS worker process _cannot_ reach the OpenSIPS
 * script, thus never being in a position to call fs_api->fs_esl(). Otherwise,
 * it would immediately deadlock itself. Should the FS worker need to raise
 * script events, it should do it via IPC dispatch to other OpenSIPS procs */
int fs_esl(fs_evs *sock, const str *fs_cmd, str *reply_txt)
{
	struct list_head *_, *__;
	struct fs_esl_reply *reply = NULL;
	unsigned long reply_id;
	int total_us;

	if (ZSTRP(fs_cmd)) {
		LM_ERR("refusing to run a NULL or empty command!\n");
		return -1;
	}

	memset(reply_txt, 0, sizeof *reply_txt);

	LM_DBG("Queuing job for ESL command '%.*s' on %s:%d\n", fs_cmd->len,
	       fs_cmd->s, sock->host.s, sock->port);

	reply_id = fs_ipc_send_esl_cmd(sock, fs_cmd);
	if (reply_id == 0) {
		LM_ERR("failed to queue ESL command '%.*s' on %s:%d\n", fs_cmd->len,
		       fs_cmd->s, sock->host.s, sock->port);
		return -1;
	}

	LM_DBG("success, reply_id=%lu, waiting for reply...\n", reply_id);

	for (total_us = 0; total_us < esl_cmd_timeout * 1000;
	     total_us += esl_cmd_polling_itv) {
		lock_start_write(sock->lists_lk);
		list_for_each_safe(_, __, &sock->esl_replies) {
			reply = list_entry(_, struct fs_esl_reply, list);

			if (reply->esl_reply_id == reply_id) {
				list_del(&reply->list);
				lock_stop_write(sock->lists_lk);
				LM_DBG("got reply after %dms: %.*s!\n", total_us / 1000,
				       reply->text.len, reply->text.s);

				*reply_txt = reply->text;
				shm_free(reply);
				return 0;
			}
		}
		lock_stop_write(sock->lists_lk);

		usleep(esl_cmd_polling_itv);
	}

	LM_ERR("timed out on ESL command '%.*s' on %s:%d\n", fs_cmd->len,
	       fs_cmd->s, sock->host.s, sock->port);
	return -1;
}

int fs_bind(struct fs_binds *fapi)
{
	LM_INFO("loading FS API ...\n");

	memset(fapi, 0, sizeof *fapi);

	fapi->stats_update_interval = event_heartbeat_interval;
	fapi->get_evs               = get_evs;
	fapi->get_evs_by_url        = get_evs_by_url;
	fapi->evs_sub               = evs_sub;
	fapi->evs_unsub             = evs_unsub;
	fapi->put_evs               = put_evs;
	fapi->get_stats_evs         = get_stats_evs;
	fapi->put_stats_evs         = put_stats_evs;
	fapi->fs_esl                = fs_esl;

	return 0;
}
