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
rw_lock_t *box_lock;

static fs_mod_ref *mk_fs_mod_ref(str *tag, ev_hb_cb_f cbf, const void *priv);
static void free_fs_mod_ref(fs_mod_ref *mref);
static fs_evs *get_fs_evs(str *hostport);

static fs_mod_ref *mk_fs_mod_ref(str *tag, ev_hb_cb_f cbf, const void *priv)
{
	fs_mod_ref *mref = NULL;

	mref = shm_malloc(sizeof *mref + tag->len);
	if (!mref) {
		LM_ERR("out of mem\n");
		return NULL;
	}
	memset(mref, 0, sizeof *mref);

	mref->tag.s = (char *)(mref + 1);
	mref->tag.len = tag->len;
	memcpy(mref->tag.s, tag->s, tag->len);

	mref->hb_cb = cbf;
	mref->priv = priv;

	return mref;
}

static void free_fs_mod_ref(fs_mod_ref *mref)
{
	mref->tag.s = NULL;
	shm_free(mref);
}

static fs_mod_ref *get_fs_mod_ref(fs_evs *evs, str *tag)
{
	struct list_head *ele;
	fs_mod_ref *mref;

	list_for_each(ele, &evs->modules) {
		mref = list_entry(ele, fs_mod_ref, list);

		if (str_strcmp(&mref->tag, tag) == 0) {
			return mref;
		}
	}

	return NULL;
}

static fs_evs *get_fs_evs(str *hostport)
{
	struct list_head *ele;
	fs_evs *evs;

	list_for_each(ele, fs_boxes) {
		evs = list_entry(ele, fs_evs, list);

		if (str_strcmp(hostport, &evs->host) == 0) {
			return evs;
		}
	}

	return NULL;
}

static fs_evs *mk_fs_evs(str *hostport)
{
	fs_evs *evs;
	char *p;
	str st;
	unsigned int port;

	p = memchr(hostport->s, ':', hostport->len);
	if (p != NULL) {
		st.s = p + 1;
		st.len = hostport->len - (p + 1 - hostport->s);

		if (str2int(&st, &port) != 0) {
			LM_ERR("failed to parse port '%.*s' %d in host '%.*s'\n",
			       st.len, st.s, st.len, hostport->len, hostport->s);
			return NULL;
		}

		st.s = hostport->s;
		st.len = p - hostport->s;
	} else {
		st = *hostport;
		port = FS_DEFAULT_EVS_PORT;
	}

	evs = shm_malloc(sizeof *evs + st.len + 1);
	if (!evs) {
		LM_ERR("out of mem\n");
		return NULL;
	}
	memset(evs, 0, sizeof *evs);
	INIT_LIST_HEAD(&evs->modules);

	LM_DBG("new FS box: host=%.*s, port=%d\n", st.len, st.s, port);

	evs->host.s = (char *)(evs + 1);
	evs->host.len = st.len;
	memcpy(evs->host.s, st.s, st.len);
	evs->host.s[evs->host.len] = '\0';

	evs->ref = 1;
	evs->port = port;
	return evs;
}

fs_evs *add_hb_evs(str *evs_str, str *tag, ev_hb_cb_f cbf, const void *priv)
{
	fs_evs *evs;
	fs_mod_ref *mref;

	if (!evs_str->s || evs_str->len == 0 || !tag) {
		LM_ERR("bad params: '%.*s', %.*s\n", evs_str->len, evs_str->s,
		       tag->len, tag->s);
		return NULL;
	}

	lock_start_write(box_lock);

	evs = get_fs_evs(evs_str);
	if (!evs) {
		evs = mk_fs_evs(evs_str);
		if (!evs) {
			LM_ERR("failed to create FS box!\n");
			goto out_err;
		}
		evs->type = FS_GW_STATS;

		list_add(&evs->list, fs_boxes);
	}

	if (!get_fs_mod_ref(evs, tag)) {
		mref = mk_fs_mod_ref(tag, cbf, priv);
		if (!mref) {
			LM_ERR("mk tag failed\n");
			goto out_err;
		}

		list_add(&mref->list, &evs->modules);
	}

	evs->ref++;

	lock_stop_write(box_lock);
	return evs;

out_err:
	lock_stop_write(box_lock);
	return NULL;
}

int del_hb_evs(fs_evs *evs, str *tag)
{
	fs_mod_ref *mref;

	lock_start_write(box_lock);
	mref = get_fs_mod_ref(evs, tag);
	if (!mref) {
		LM_ERR("mod ref %.*s does not exist in evs %s:%d\n", tag->len, tag->s,
		       evs->host.s, evs->port);
		goto out_err;
	}

	list_del(&mref->list);
	free_fs_mod_ref(mref);

	evs->ref--;

	lock_stop_write(box_lock);
	return 0;

out_err:
	lock_stop_write(box_lock);
	return -1;
}

int fs_bind(fs_api_t *fapi)
{
	memset(fapi, 0, sizeof *fapi);

	fapi->add_hb_evs = add_hb_evs;
	fapi->del_hb_evs = del_hb_evs;

	return 0;
}
