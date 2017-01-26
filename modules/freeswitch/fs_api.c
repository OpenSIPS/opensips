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

#include "fs_api.h"

struct list_head *fs_boxes;

typedef struct _fs_mod_ref {
	str tag;
	struct list_head list;
} fs_mod_ref;

static fs_mod_ref *mk_fs_mod_ref(str *tag);
static void free_fs_mod_ref(fs_mod_ref *mod_tag);
static fs_evs *find_fs_evs(union sockaddr_union *sock);

static fs_mod_ref *mk_fs_mod_ref(str *tag)
{
	fs_mod_ref *fs_tag = NULL;

	fs_tag = shm_malloc(sizeof *fs_tag + tag->len);
	if (!fs_tag) {
		LM_ERR("out of mem\n");
		return NULL;
	}

	fs_tag->tag.s = (char *)(fs_tag + 1);
	fs_tag->tag.len = tag->len;
	memcpy(fs_tag->tag.s, tag->s, tag->len);

	return fs_tag;
}

static void free_fs_mod_ref(fs_mod_ref *mod_tag)
{
	mod_tag->tag.s = NULL;
	shm_free(mod_tag);
}

static int has_tag(fs_evs *evs, str *tag)
{
	struct list_head *ele;
	fs_mod_ref *mtag;

	list_for_each(ele, &evs->modlist) {
		mtag = list_entry(ele, fs_mod_ref, list);

		if (str_strcmp(&mtag->tag, tag) == 0) {
			return 0;
		}
	}

	return -1;
}

static fs_evs *find_fs_evs(union sockaddr_union *sock)
{
	struct list_head *ele;
	fs_evs *evs;

	list_for_each(ele, fs_boxes) {
		evs = list_entry(ele, fs_evs, list);

		if (su_cmp(sock, &evs->su) == 1) {
			return evs;
		}
	}

	return NULL;
}

fs_evs *add_fs_event_sock(str *evs_str, str *tag, enum fs_evs_types type,
                               ev_hrbeat_cb_f scb, void *info)
{
	fs_evs *evs;
	fs_mod_ref *mtag;
	union sockaddr_union su;

	if (!evs_str->s || evs_str->len == 0 || !tag) {
		LM_ERR("bad params: '%.*s', %.*s\n", evs_str->len, evs_str->s,
		       tag->len, tag->s);
		return NULL;
	}

	if (resolve_hostport(evs_str, FS_DEFAULT_EVS_PORT, &su) != 0) {
		LM_ERR("bad ip[:port] string! (%.*s)\n", evs_str->len, evs_str->s);
		return NULL;
	}

	evs = find_fs_evs(&su);
	if (evs) {
		if (!has_tag(evs, tag)) {
			mtag = mk_fs_mod_ref(tag);
			if (!mtag) {
				LM_ERR("mk tag failed\n");
				return NULL;
			}

			list_add(&mtag->list, &evs->modlist);
		}
	} else {
		evs = shm_malloc(sizeof *evs);
		if (!evs) {
			LM_ERR("out of mem\n");
			return NULL;
		}
		memset(evs, 0, sizeof *evs);

		evs->type = type;
		evs->su = su;

		list_add(&evs->list, fs_boxes);
	}

	return evs;

out_free:
	shm_free(evs);
	return NULL;
}

int del_fs_event_sock(fs_evs *evs, str *tag)
{
	return 0;
}
