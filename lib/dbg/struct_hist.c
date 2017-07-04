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

static void sh_unref_unsafe(struct struct_hist *sh, struct struct_hist_list *list);
static void sh_free(struct struct_hist *sh);

struct struct_hist_list *shl_init(char *obj_name, int window_size)
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

	return shl;
}

void shl_destroy(struct struct_hist_list *shl)
{
	struct list_head *el, *next;
	struct struct_hist *sh;

	list_for_each_safe(el, next, &shl->objects) {
		sh = list_entry(el, struct struct_hist, list);
		sh_free(sh);
	}

	shm_free(shl);
}

struct struct_hist *sh_push(void *obj, struct struct_hist_list *list)
{
	struct struct_hist *sh, *last;

	if (!obj)
		return NULL;

	sh = shm_malloc(sizeof *sh);
	if (!sh) {
		LM_ERR("oom\n");
		return NULL;
	}
	memset(sh, 0, sizeof *sh);

	sh->actions = shm_malloc(ACTIONS_SIZE * sizeof *sh->actions);
	if (!sh->actions) {
		LM_ERR("oom2\n");
		shm_free(sh);
		return NULL;
	}
	memset(sh->actions, 0, ACTIONS_SIZE * sizeof *sh->actions);

	sh->obj = obj;
	sh->ref = 2; /* one for "list", one for "return sh;" */
	sh->max_len = ACTIONS_SIZE;
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
		sh_unref_unsafe(last, list);
	}
	lock_release(&list->wlock);

	return sh;
}

static void sh_free(struct struct_hist *sh)
{
	int i;

	for (i = 0; i < sh->len; i++)
		shm_free(sh->actions[i].log);

	shm_free(sh->actions);
	shm_free(sh);
}

void sh_unref(struct struct_hist *sh, struct struct_hist_list *list)
{
	lock_get(&list->wlock);
	sh_unref_unsafe(sh, list);
	lock_release(&list->wlock);
}

static void flush_sh(struct struct_hist *sh)
{
	int i;

	for (i = 0; i < sh->len; i++) {
		LM_INFO("    %5d. | %-15s | %-12lld | %-5d | %s |\n", i + 1 + sh->flush_offset,
		        verb2str(sh->actions[i].verb),
				sh->actions[i].t,
				sh->actions[i].pid,
				sh->actions[i].log);
	}

	sh->flush_offset += sh->len;
	sh->len = 0;
}

static void sh_unref_unsafe(struct struct_hist *sh, struct struct_hist_list *list)
{
	sh->ref--;
	if (sh->ref == 0) {
		if (!list_empty(&sh->list)) {
			list_del(&sh->list);
		}
		sh_free(sh);
	}
#ifdef FULL_LOGGING

	else {
		lock_get(&sh->wlock);

		LM_INFO("%s %p ended, %d actions follow\n", list->obj_name, sh->obj,
		        sh->len);
		LM_INFO("=====================================\n");
		flush_sh(sh);

		lock_release(&sh->wlock);
	}
#endif
}

int sh_log(struct struct_hist *sh, enum struct_hist_verb verb, char *fmt, ...)
{
	va_list ap;
	int n;
	struct struct_hist_action *new, *act;

	if (!sh)
		return -1;

	va_start(ap, fmt);
	lock_get(&sh->wlock);

	if (flushable(sh)) {
		LM_INFO("TCP conn %p flush, %d actions follow\n", sh->obj, sh->len);
		LM_INFO("=====================================\n");
		flush_sh(sh);
	} else if (sh->len == sh->max_len) {
		new = shm_realloc(sh->actions, sh->max_len * 2 * sizeof *sh->actions);
		if (!new) {
			lock_release(&sh->wlock);
			LM_ERR("oom\n");
			return -1;
		}
		memset(&new[sh->max_len], 0, sh->max_len * sizeof *sh->actions);

		sh->actions = new;
		sh->max_len *= 2;
	}

	act = &sh->actions[sh->len];
	sh->len++;

	act->verb = verb;
	act->t = get_uticks();
	act->pid = my_pid();
	if (act->log) {
		memset(act->log, 0, MAX_SHLOG_SIZE);
	} else {
		act->log = shm_malloc(MAX_SHLOG_SIZE);
		if (!act->log) {
			lock_release(&sh->wlock);
			LM_ERR("oom\n");
			return -1;
		}
	}

	n = vsnprintf(act->log, MAX_SHLOG_SIZE, fmt, ap);
	lock_release(&sh->wlock);

	if (n < 0 || n >= MAX_SHLOG_SIZE) {
		LM_ERR("formatting failed with n=%d, %s\n", n, strerror(errno));
	}

	va_end(ap);

	return 0;
}
