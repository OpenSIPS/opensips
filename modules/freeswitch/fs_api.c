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

#define FS_STATS_EVENT_NAME "HEARTBEAT"
#define FS_STATS_EVENT_STR {FS_STATS_EVENT_NAME,sizeof(FS_STATS_EVENT_NAME)-1}

extern int event_heartbeat_interval;

/*
 * Any FreeSWITCH socket which is still referenced at least once
 * Both FS proc and random OpenSIPS MI reloaders may write to this list
 */
struct list_head *fs_sockets;
rw_lock_t *sockets_lock;

/*
 *	fs_sockets ⊇ fs_sockets_down (sockets which require a (re)connect)
 *	fs_sockets ⊇ fs_sockets_esl (sockets which have pending sub/unsub/cli cmds)
 */
struct list_head *fs_sockets_down;
rw_lock_t *sockets_down_lock;

struct list_head *fs_sockets_esl;
rw_lock_t *sockets_esl_lock;

/* mem reusage - unique string tags and events accumulated so far */
static struct str_list *all_tags;
//static struct str_list *all_events;

void esl_cmd_free(struct esl_cmd *cmd)
{
	if (!is_event_cmd(cmd->type))
		shm_free(cmd->text.s);

	/* tags are globally reused; same for text events */

	shm_free(cmd);
}


void evs_free(fs_evs *sock)
{
	struct list_head *_, *__;
	struct fs_event *ev;
	struct esl_cmd *cmd;

	if (sock->ref != 0)
		LM_BUG("non-zero ref @ free");

	list_for_each_safe(_, __, &sock->events) {
		ev = list_entry(_, struct fs_event, list);
		shm_free(ev);
	}

	list_for_each_safe(_, __, &sock->esl_cmds) {
		cmd = list_entry(_, struct esl_cmd, list);
		esl_cmd_free(cmd);
	}

	// TODO: clean up sock->cli_replies

	shm_free(sock->host.s);
	shm_free(sock->user.s);
	shm_free(sock->pass.s);

	lock_destroy_rw(sock->stats_lk);
	lock_destroy_rw(sock->lists_lk);

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
		LM_ERR("password cannot be NULL for a new socket!\n");
		return NULL;
	}

	sock = shm_malloc(sizeof *sock);
	if (!sock) {
		LM_ERR("oom\n");
		return NULL;
	}
	memset(sock, 0, sizeof *sock);
	INIT_LIST_HEAD(&sock->cli_replies);
	INIT_LIST_HEAD(&sock->events);
	INIT_LIST_HEAD(&sock->esl_cmds);
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

	LM_DBG("new FS sock: host=%s, port=%d, user=%s, pass=%s\n",
	       sock->host.s, sock->port, sock->user.s, sock->pass.s);

	return sock;

err_free:
	evs_free(sock);
	return NULL;
}

// TODO: review this a 2nd time, seems broken
//
int evs_update(fs_evs *sock, const str *user, const str *pass)
{
	str user_bak = {NULL, 0}, pass_bak = {NULL, 0};

	if (!user || !user->s || user->len == 0) {
		shm_free(sock->user.s);
		memset(&sock->user, 0, sizeof sock->user);
	} else if (str_strcmp(&sock->user, user) != 0) {
		user_bak = sock->user;
		if (shm_str_dup(&sock->user, user) != 0) {
			LM_ERR("oom\n");
			goto err_restore;
		}
	}

	if (!pass || !pass->s || pass->len == 0) {
		shm_free(sock->pass.s);
		memset(&sock->pass, 0, sizeof sock->pass);
	} else if (str_strcmp(&sock->pass, pass) != 0) {
		pass_bak = sock->pass;
		if (shm_str_dup(&sock->pass, pass) != 0) {
			LM_ERR("oom\n");
			goto err_restore;
		}
	}

	if (user_bak.s)
		shm_free(user_bak.s);

	if (pass_bak.s)
		shm_free(pass_bak.s);

	return 0;

err_restore:
	if (user_bak.s) {
		shm_free(sock->user.s);
		sock->user = user_bak;
	}
	if (pass_bak.s) {
		shm_free(sock->pass.s);
		sock->pass = pass_bak;
	}

	return -1;
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

	LM_DBG("fetching %.*s:%d, '%.*s/%.*s'\n", host->len, host->s, port,
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
	struct str_list *t;

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

	t = shm_malloc(sizeof *t + tag->len);
	if (!t) {
		LM_ERR("oom\n");
		return -1;
	}
	memset(t, 0, sizeof *t);

	t->s.s = (char *)(t + 1);
	t->s.len = tag->len;
	memcpy(t->s.s, tag->s, tag->len);

	if (!all_tags) {
		all_tags = t;
	} else {
		t->next = all_tags;
		all_tags = t;
	}

	*out = t->s;
	return 0;
}

int add_event_subscription(struct fs_event *fs_ev, const str *tag)
{
	struct fs_event_subscription *fs_sub;

	fs_sub = shm_malloc(sizeof *fs_sub);
	if (!fs_sub) {
		LM_ERR("oom\n");
		return -1;
	}
	memset(fs_sub, 0, sizeof *fs_sub);

	if (dup_common_tag(tag, &fs_sub->tag) != 0) {
		shm_free(fs_sub);
		LM_ERR("oom\n");
		return -1;
	}

	fs_sub->ref = 1;

	list_add_tail(&fs_sub->list, &fs_ev->subscriptions);
	return 0;
}

int del_pending_esl_cmd(fs_evs *sock, enum esl_cmd_types type, const str *text,
                        const str *tag)
{
	struct list_head *_, *__;
	struct esl_cmd *cmd;

	list_for_each_safe(_, __, &sock->esl_cmds) {
		cmd = list_entry(_, struct esl_cmd, list);
		if (cmd->type == type && str_strcmp(&cmd->text, text) == 0 &&
		    str_strcmp(&cmd->tag, tag) == 0) {
			if (cmd->count > 1) {
				cmd->count--;
				return 0;
			}

			// TODO: del this
			if (cmd->count < 0)
				LM_BUG("negative cmd count");

			list_del(&cmd->list);
			esl_cmd_free(cmd);
			return 0;
		}
	}

	return -1;
}

struct esl_cmd *esl_cmd_init(enum esl_cmd_types type, const str *text,
                             const str *tag)
{
	struct esl_cmd *cmd;

	cmd = shm_malloc(sizeof *cmd);
	if (!cmd) {
		LM_ERR("oom\n");
		return NULL;
	}
	memset(cmd, 0, sizeof *cmd);

	cmd->type = type;
	cmd->count = 1;

	if (dup_common_tag(tag, &cmd->tag) != 0)
		goto out_err;

	if (is_event_cmd(type)) {
		if (dup_common_tag(text, &cmd->text) != 0)
			goto out_err;
	} else {
		if (shm_str_dup(&cmd->text, text) != 0)
			goto out_err;
	}

	return cmd;

out_err:
	shm_free(cmd);
	LM_ERR("oom\n");
	return NULL;
}

int add_pending_esl_cmd(fs_evs *sock, enum esl_cmd_types type, const str *text,
                        const str *tag)
{
	struct list_head *_, *__;
	struct esl_cmd *cmd;

	list_for_each_safe(_, __, &sock->esl_cmds) {
		cmd = list_entry(_, struct esl_cmd, list);

		if (cmd->type == type && str_strcmp(&cmd->text, text) == 0 &&
		    str_strcmp(&cmd->tag, tag) == 0) {
			if (cmd->count < 0)
				LM_BUG("negative cmd count");
			cmd->count++;
			return 0;
		}
	}

	cmd = esl_cmd_init(type, text, tag);
	if (!cmd) {
		LM_ERR("failed to init esl_cmd\n");
		return -1;
	}

	list_add_tail(&cmd->list, &sock->esl_cmds);

	return 0;
}

int evs_sub(fs_evs *sock, const str *tag, const struct str_list *event)
{
	struct list_head *_, *__;
	struct fs_event *fs_ev;
	struct fs_event_subscription *fs_sub;
	int event_found, sub_found, undo_unsub;
	int ret = 0;

	lock_start_write(sock->lists_lk);

	for (; event; event = event->next) {
		event_found = 0;
		undo_unsub = 0;

		/* is this sock already ESL-subscribed to this event? */
		list_for_each(_, &sock->events) {
			fs_ev = list_entry(_, struct fs_event, list);

			/* yes! we either ref it, or make a new entry for this module */
			if (str_strcmp(&fs_ev->event_name, &event->s) == 0) {
				event_found = 1;

				sub_found = 0;
				list_for_each(__, &fs_ev->subscriptions) {
					fs_sub = list_entry(__, struct fs_event_subscription,list);
					if (str_strcmp(&fs_sub->tag, tag) == 0) {
						fs_sub->ref++;
						sub_found = 1;
						break;
					}
				}

				if (!sub_found) {
				    if (add_event_subscription(fs_ev, tag) != 0) {
						ret = -1;
					} else {
						/* there is a pending unsub command we must delete! */
						if (fs_ev->refsum++ == 0)
							undo_unsub = 1;
					}
				} else {
					if (fs_ev->refsum++ == 0)
						undo_unsub = 1;
				}

				break;
			}
		}

		/* lazy subscribe for this event */
		if (!event_found) {
			if (add_pending_esl_cmd(sock,
			            ESL_EVENT_SUB, &event->s, tag) != 0)
				ret = -1;
		} else if (undo_unsub) {
			if (del_pending_esl_cmd(sock, ESL_EVENT_UNSUB, &event->s, tag))
				LM_BUG("undo unsub");
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

void evs_unsub(fs_evs *sock, const str *tag, const struct str_list *event)
{
	struct list_head *_, *__, *___;
	struct fs_event *fs_ev;
	struct fs_event_subscription *fs_sub;
	int event_found, must_unsub;
	int ret = 0;

	lock_start_write(sock->lists_lk);

	for (; event; event = event->next) {
		event_found = 0;
		must_unsub = 1;

		/* is this sock already ESL-subscribed to this event? */
		list_for_each(_, &sock->events) {
			fs_ev = list_entry(_, struct fs_event, list);

			/* yes! unref it and unref/delete the module subscription */
			if (str_strcmp(&fs_ev->event_name, &event->s) == 0) {
				event_found = 1;
				/* an unsub cmd must already be queued! */
				if (fs_ev->refsum == 0)
					break;

				fs_ev->refsum--;
				if (fs_ev->refsum == 0) /* need to queue up an ESL unsub */
					must_unsub = 1;

				list_for_each_safe(__, ___, &fs_ev->subscriptions) {
					fs_sub = list_entry(__, struct fs_event_subscription,list);
					if (str_strcmp(&fs_sub->tag, tag) == 0) {
						fs_sub->ref--;
						if (fs_sub->ref == 0) {
							list_del(&fs_sub->list);
							shm_free(fs_sub);
						}
						break;
					}
				}

				break;
			}
		}

		if (!event_found) {
			if (del_pending_esl_cmd(sock, ESL_EVENT_SUB, &event->s, tag) == 0)
				LM_DBG("%.*s: deleted pending ESL %.*s SUB for %.*s\n",
				       tag->len, tag->s, sock->host.len, sock->host.s,
				       event->s.len, event->s.s);
			else
				LM_ERR("%.*s: failed to ESL %.*s SUB for %.*s\n",
				       tag->len, tag->s, sock->host.len, sock->host.s,
				       event->s.len, event->s.s);
		} else if (must_unsub) {
			if (add_pending_esl_cmd(sock,
			                ESL_EVENT_UNSUB, &event->s, tag) == 0)
				LM_DBG("%.*s: queued ESL %.*s UNSUB for %.*s\n",
				       tag->len, tag->s, sock->host.len, sock->host.s,
				       event->s.len, event->s.s);
			else
				LM_ERR("%.*s: failed to ESL %.*s UNSUB for %.*s\n",
				       tag->len, tag->s, sock->host.len, sock->host.s,
				       event->s.len, event->s.s);
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

	return;
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
	sock->ref--;
	lock_stop_write(sockets_lock);

	/**
	 * We cannot immediately free the event socket, as the fd might be polled
	 * by the FreeSWITCH worker process. The ref == 0 check is done there
	 */
}

fs_evs *get_stats_evs(str *fs_url, str *tag)
{
	fs_evs *sock;
	struct str_list ev_list = {FS_STATS_EVENT_STR, NULL};

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

	if (evs_sub(sock, tag, &ev_list) != 0) {
		LM_ERR("failed to subscribe for stats on %s:%d\n",
		       sock->host.s, sock->port);
		put_evs(sock);
		return NULL;
	}

	return sock;
}

void put_stats_evs(fs_evs *sock, str *tag)
{
	struct str_list ev_list = {FS_STATS_EVENT_STR, NULL};

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

int fs_cli(fs_evs *sock, const str *fs_cmd, str *reply)
{
	LM_DBG("TODO!\n");
	memset(reply, 0, sizeof *reply);
	/* the "fs_cli" API command may be called by the FS worker, during
	 * an event raise, */
	/*
	if (!is_fs_worker())
		lock_start_write(sock->lists_lk);

		add_pending_esl_cmd();

	if (!is_fs_worker())
		lock_stop_write(sock->lists_lk);
	*/

	return 0;
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
	fapi->fs_cli                = fs_cli;

	return 0;
}
