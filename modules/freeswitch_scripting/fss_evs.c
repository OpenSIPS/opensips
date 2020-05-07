/*
 * Script and MI utilities for custom FreeSWITCH interactions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#include "../../lib/list.h"
#include "../../lib/url.h"
#include "../../ut.h"

#include "../freeswitch/fs_api.h"

#include "fss_evs.h"
#include "fss_ipc.h"
#include "fss_db.h"

extern str fss_mod_tag;

struct fs_binds fs_api;

/*
 * the current list of referenced FreeSWITCH ESL sockets
 * and their event subscriptions (SHM pointer).
 *
 * This list is altered by:
 *    - "fs_subscribe" modparam
 *    - "fs_subscribe" / "fs_unsubscribe" MI commands
 *    - DB table data
 */
struct list_head *fss_sockets;

int fss_init(void)
{
	fss_sockets = shm_malloc(sizeof *fss_sockets);
	if (!fss_sockets) {
		LM_ERR("oom\n");
		return -1;
	}
	INIT_LIST_HEAD(fss_sockets);

	if (load_fs_api(&fs_api) != 0) {
		LM_ERR("failed to load the FreeSWITCH API - is freeswitch loaded?\n");
		return -1;
	}

	return 0;
}

int find_evs(fs_evs *sock)
{
	struct list_head *_;
	struct fs_evs_list *socklist;

	list_for_each(_, fss_sockets) {
		socklist = list_entry(_, struct fs_evs_list, list);
		if (socklist->sock == sock)
			return 0;
	}

	return -1;
}

int add_evs(fs_evs *sock)
{
	struct fs_evs_list *socklist;

	socklist = shm_malloc(sizeof *socklist);
	if (!socklist) {
		LM_ERR("oom\n");
		return -1;
	}
	memset(socklist, 0, sizeof *socklist);

	socklist->sock = sock;
	list_add(&socklist->list, fss_sockets);
	return 0;
}

int subscribe_to_fs_urls(const struct list_head *urls)
{
	fs_evs *sock;
	struct list_head *_;
	struct url *fs_url;
	str_dlist *url;
	str_list *evlist = NULL, *li, **last = &evlist;
	struct url_param_list *event;
	int ret = 0;

	list_for_each(_, urls) {
		url = list_entry(_, str_dlist, list);

		fs_url = parse_url(&url->s, URL_REQ_PASS, 0);
		if (!fs_url) {
			LM_ERR("failed to parse FS URL '%.*s', skipping!\n",
			       url->s.len, url->s.s);
			ret = 1;
			goto next_url;
		}

		sock = fs_api.get_evs(&fs_url->hosts->host, fs_url->hosts->port,
		                      &fs_url->username, &fs_url->password);
		if (!sock) {
			LM_ERR("API get failed for FS URL '%.*s', skipping!\n",
			       url->s.len, url->s.s);
			ret = 1;
			goto next_url;
		}

		if (find_evs(sock) != 0) {
			if (add_evs(sock) != 0) {
				fs_api.put_evs(sock);
				LM_ERR("failed to ref socket\n");
				goto next_url;
			}
		} else {
			/* we're already referencing this socket */
			fs_api.put_evs(sock);
		}

		for (event = fs_url->params; event; event = event->next) {
			if (ZSTR(event->key) ||
			    add_to_fss_sockets(sock, &event->key) <= 0)
				continue;

			li = pkg_malloc(sizeof *li);
			if (!li) {
				LM_ERR("oom\n");
				goto next_url;
			}
			memset(li, 0, sizeof *li);

			li->s = event->key;
			*last = li;
			last = &li->next;

			LM_DBG("queued up sub for %.*s\n", li->s.len, li->s.s);
		}

		if (fs_api.evs_sub(sock, &fss_mod_tag, evlist,
		                   ipc_hdl_rcv_event) != 0) {
			LM_ERR("failed to subscribe for one or more events on %s:%d\n",
			       sock->host.s, sock->port);
			fs_api.evs_unsub(sock, &fss_mod_tag, evlist);
			goto next_url;
		}

next_url:
		_free_str_list(evlist, osips_pkg_free, NULL);
		free_url(fs_url);
	}

	return ret;
}

void free_fs_sock_list(struct list_head *sock_list)
{
	struct list_head *_, *__;
	str_list *event;
	struct fs_evs_list *sock;

	list_for_each_safe(_, __, sock_list) {
		sock = list_entry(_, struct fs_evs_list, list);

		fs_api.evs_unsub(sock->sock, &fss_mod_tag, sock->events);

		for (event = sock->events; event; event = event->next) {
			shm_free(event->s.s);
			shm_free(event);
		}

		fs_api.put_evs(sock->sock);
		shm_free(sock);
	}
}

struct fs_evs_list *mk_fs_sock_list(fs_evs *sock, str_list *events)
{
	struct fs_evs_list *sock_list;

	sock_list = shm_malloc(sizeof *sock_list);
	if (!sock_list) {
		LM_ERR("oom\n");
		return NULL;
	}
	memset(sock_list, 0, sizeof *sock_list);

	sock_list->sock = sock;
	sock_list->events = events;

	return sock_list;
}

int add_to_fss_sockets(fs_evs *sock, const str *event_name)
{
	struct list_head *_;
	struct fs_evs_list *sock_list;
	str_list *slist, *event;

	LM_DBG("adding event: %.*s\n", event_name->len, event_name->s);

	list_for_each(_, fss_sockets) {
		sock_list = list_entry(_, struct fs_evs_list, list);
		if (sock_list->sock != sock)
			continue;

		for (event = sock_list->events; event; event = event->next)
			if (str_strcmp(&event->s, event_name) == 0)
				return 0;

		goto alloc_event;
	}

	LM_BUG("add_to_fss_sockets sock not found");
	return -1;

alloc_event:
	slist = shm_malloc(sizeof *slist);
	if (!slist) {
		LM_ERR("oom\n");
		return -1;
	}
	memset(slist, 0, sizeof *slist);

	if (shm_nt_str_dup(&slist->s, event_name) != 0) {
		shm_free(slist);
		LM_ERR("oom\n");
		return -1;
	}

	slist->next = sock_list->events;
	sock_list->events = slist;

	return 1;
}

int del_from_fss_sockets(fs_evs *sock, const str *event_name)
{
	struct list_head *_, *__;
	struct fs_evs_list *sock_list;
	str_list *event, *bak;

	list_for_each_safe(_, __, fss_sockets) {
		sock_list = list_entry(_, struct fs_evs_list, list);
		if (sock_list->sock != sock)
			continue;

		if (!sock_list->events)
			goto out_free;

		if (str_strcmp(&sock_list->events->s, event_name) == 0) {
			bak = sock_list->events;
			sock_list->events = sock_list->events->next;
			shm_free(bak->s.s);
			shm_free(bak);

			if (!sock_list->events)
				goto out_free;
			else
				return 0;
		}

		for (event = sock_list->events; event->next; event = event->next) {
			if (str_strcmp(&event->next->s, event_name) == 0) {
				bak = event->next;
				event->next = event->next->next;
				shm_free(bak->s.s);
				shm_free(bak);
				return 0;
			}
		}

		return -1;
	}

	LM_DBG("sock not found\n");
	return -1;

out_free:
	LM_DBG("clearing sock %s:%d\n", sock->host.s, sock->port);
	list_del(&sock_list->list);
	shm_free(sock_list);
	return 1;
}
