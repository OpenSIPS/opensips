/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <stdio.h>
#include <stdarg.h>

#include "struct_hist.h"

#include "../../mem/shm_mem.h"
#include "../../dprint.h"
#include "../../locking.h"
#include "../../pt.h"
#include "../list.h"

struct struct_hist {
	void *obj;
	char *obj_name;
	utime_t created;
	struct struct_hist_list *shlist;

	int ref;

	struct struct_hist_action *actions;
	int len;
	int max_len;
	int flush_offset;

	gen_lock_t wlock;
	int auto_logging;

	struct list_head list;
};

struct struct_hist_list {
	char *obj_name;

	struct list_head objects;
	int len;
	int win_sz;
	long long total_obj;
	int auto_logging;
	int init_actions_sz;

	gen_lock_t wlock;
};

static inline const char *verb2str(enum struct_hist_verb verb)
{
	#define __SH_VERB_TO_STRING(STRING) #STRING,
	static const char *sh_verb_strs[] = {
		"SH_VERB_ZERO",
		SH_ALL_VERBS(__SH_VERB_TO_STRING)
		"SH_VERB_LAST",
	};

	if (verb <= SH_VERB_ZERO || verb >= SH_VERB_LAST)
		return "!FOOBAR!";

	return sh_verb_strs[verb];
}

static void sh_unref_unsafe(struct struct_hist *sh);
static void sh_free(struct struct_hist *sh);

struct struct_hist_list *_shl_init(char *obj_name, int window_size,
			int auto_logging, int init_actions_sz)
{
	struct struct_hist_list *shl;

	shl = shm_malloc(sizeof *shl);
	if (!shl) {
		LM_ERR("oom\n");
		return NULL;
	}
	memset(shl, 0, sizeof *shl);

	INIT_LIST_HEAD(&shl->objects);
	lock_init(&shl->wlock);
	shl->win_sz = window_size;
	shl->obj_name = obj_name;
	shl->auto_logging = !!auto_logging;
	shl->init_actions_sz = init_actions_sz;

	return shl;
}

void sh_list_flush(struct struct_hist_list *shl)
{
	struct list_head *_;

	lock_get(&shl->wlock);

	list_for_each_prev (_, &shl->objects)
		sh_flush(list_entry(_, struct struct_hist, list));

	lock_release(&shl->wlock);
}

void shl_destroy(struct struct_hist_list *shl)
{
	struct list_head *el, *next;
	struct struct_hist *sh;

	if (!shl)
		return;

	list_for_each_safe (el, next, &shl->objects) {
		sh = list_entry(el, struct struct_hist, list);
		sh_free(sh);
	}

	shm_free(shl);
}

struct struct_hist *_sh_push(void *obj, struct struct_hist_list *list, int refs)
{
	struct struct_hist *sh, *last;

	if (!obj || !list)
		return NULL;

	sh = shm_malloc(sizeof *sh);
	if (!sh) {
		LM_ERR("oom\n");
		return NULL;
	}
	/* CAREFUL: sh is not memset, for speed reasons! */

	sh->actions = shm_malloc(list->init_actions_sz * sizeof *sh->actions);
	if (!sh->actions) {
		LM_ERR("oom2\n");
		shm_free(sh);
		return NULL;
	}
	/* CAREFUL: sh->actions is not memset, for speed reasons! */

	sh->obj = obj;
	sh->obj_name = list->obj_name;
	sh->created = get_uticks();
	sh->shlist = list;
	sh->ref = 1 + refs; /* one for "list", the rest are for the caller */
	sh->len = 0;
	sh->max_len = list->init_actions_sz;
	sh->flush_offset = 0;
	sh->auto_logging = list->auto_logging;

	lock_init(&sh->wlock);

	lock_get(&list->wlock);
	list_add(&sh->list, &list->objects);
	list->total_obj++;
	list->len++;

	if (list->win_sz && list->len > list->win_sz) {
		last = list_entry(list->objects.prev, struct struct_hist, list);
		list_del(&last->list);
		INIT_LIST_HEAD(&last->list);
		list->len--;
		sh_unref_unsafe(last);
	}
	lock_release(&list->wlock);

	return sh;
}

static void sh_free(struct struct_hist *sh)
{
	shm_free(sh->actions);
	shm_free(sh);
}

void sh_unref(struct struct_hist *sh)
{
	gen_lock_t *shl_lock = &sh->shlist->wlock;

	lock_get(shl_lock);
	sh_unref_unsafe(sh);
	lock_release(shl_lock);
}

static void _sh_flush(struct struct_hist *sh, int do_logging)
{
	int i;

	if (do_logging) {
		for (i = 0; i < sh->len; i++) {
			LM_INFO("%5d. %p-%lld | %-15s | %-12lld | %-5d | %s |\n",
			        i + 1 + sh->flush_offset,
					sh->obj,
					sh->created,
			        verb2str(sh->actions[i].verb),
			        sh->actions[i].t,
			        sh->actions[i].pid,
			        sh->actions[i].log);
		}
	}

	sh->flush_offset += sh->len;
	sh->len = 0;
}

void sh_flush(struct struct_hist *sh)
{
	lock_get(&sh->wlock);
	_sh_flush(sh, 1);
	lock_release(&sh->wlock);
}

static void sh_unref_unsafe(struct struct_hist *sh)
{
	sh->ref--;
	if (sh->ref != 0)
		return;

	if (sh->auto_logging) {
		lock_get(&sh->wlock);

		LM_INFO("%s %p free, %d actions follow\n", sh->obj_name, sh->obj, sh->len);
		LM_INFO("=====================================\n");
		_sh_flush(sh, 1);

		lock_release(&sh->wlock);
	}

	if (!list_empty(&sh->list))
		list_del(&sh->list);

	sh_free(sh);
}

int _sh_log(struct struct_hist *sh, enum struct_hist_verb verb, char *fmt, ...)
{
	va_list ap;
	int n;
	struct struct_hist_action *new, *act;

	if (!sh)
		return -1;

	va_start(ap, fmt);
	lock_get(&sh->wlock);

	if (flushable(sh)) {
		if (sh->auto_logging) {
			LM_INFO("%s %p flush, %d actions follow\n", sh->obj_name, sh->obj, sh->len);
			LM_INFO("=====================================\n");
		}

		_sh_flush(sh, sh->auto_logging);
	} else if (sh->len == sh->max_len) {
		new = shm_realloc(sh->actions, sh->max_len * 2 * sizeof *sh->actions);
		if (!new) {
			lock_release(&sh->wlock);
			LM_ERR("oom\n");
			return -1;
		}
		/* CAREFUL: newly added actions are not memset, for speed reasons! */

		sh->actions = new;
		sh->max_len *= 2;
	}

	act = &sh->actions[sh->len];
	sh->len++;

	act->verb = verb;
	act->t = get_uticks();
	act->pid = my_pid();

	n = vsnprintf(act->log, MAX_SHLOG_SIZE, fmt, ap);
	lock_release(&sh->wlock);

	if (n < 0 || n >= MAX_SHLOG_SIZE) {
		LM_INFO("formatting failed with n=%d, %s\n", n, strerror(errno));
	}

	va_end(ap);

	return 0;
}
