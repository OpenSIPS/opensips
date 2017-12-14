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

#include "../freeswitch/fs_api.h"

#include "fss_evs.h"
#include "fss_ipc.h"

#define FSS_MOD_NAME "freeswitch_scripting"
str fss_mod_name = {FSS_MOD_NAME, sizeof(FSS_MOD_NAME) - 1};

struct fs_evs_list {
	fs_evs *sock;
	struct list_head list;
};

struct fs_binds fs_api;
struct list_head *fss_sockets;

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
	struct str_dlist *url;
	struct str_list evlist;
	struct url_param_list *event;
	int ret = 0;

	memset(&evlist, 0, sizeof evlist);

	list_for_each(_, urls) {
		url = list_entry(_, struct str_dlist, list);

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

		for (event = fs_url->params; event; event = event->next) {
			evlist.s = event->key;
			if (fs_api.evs_sub(sock, &fss_mod_name, &evlist,
			                   ipc_hdl_rcv_event) != 0) {
				LM_ERR("event sub failed to FS URL '%.*s', skipping!\n",
				       url->s.len, url->s.s);
				ret = 1;
				fs_api.put_evs(sock);
				goto next_url;
			}
		}

		if (add_evs(sock) != 0) {
			LM_ERR("failed to store sock for FS URL '%.*s', skipping!\n",
			       url->s.len, url->s.s);

			for (event = fs_url->params; event; event = event->next) {
				evlist.s = event->key;
				fs_api.evs_unsub(sock, &fss_mod_name, &evlist);
			}

			ret = 1;
			fs_api.put_evs(sock);
		}

next_url:
		free_url(fs_url);
	}

	return ret;
}
