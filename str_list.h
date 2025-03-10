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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

#ifndef __STR_LIST__
#define __STR_LIST__

#include <stdlib.h>

#include "str.h"
#include "lib/osips_malloc.h"
#include "lib/list.h"
#include "ut.h"

typedef struct _str_list {
	str s;
	struct _str_list *next;
} str_list;

typedef struct _str_dlist {
	str s;
	struct list_head list;
} str_dlist;

static inline str_list *_new_str_list(str *val, osips_malloc_t alloc_item)
{
	str_list *new_el;
	if (!alloc_item)
		return NULL;
	new_el = alloc_item(sizeof *new_el + val->len + 1);
	if (!new_el)
		return NULL;
	memset(new_el, 0, sizeof *new_el);
	new_el->s.s = (char *)(new_el + 1);
	str_cpy(&new_el->s, val);
	new_el->s.s[new_el->s.len] = '\0';
	return new_el;
}

#define new_pkg_str_list(val) \
	_new_str_list(val, osips_pkg_malloc)

#define new_shm_str_list(val) \
	_new_str_list(val, osips_shm_malloc)

static inline str_list *_insert_str_list(str_list **list, str *val, osips_malloc_t alloc_item)
{
	str_list *new_el = _new_str_list(val, alloc_item);
	if (!new_el)
		return NULL;

	new_el->next = *list;
	*list = new_el;
	return *list;
}

#define insert_pkg_str_list(list, val) \
	_insert_str_list(list, val, osips_pkg_malloc)

#define insert_shm_str_list(list, val) \
	_insert_str_list(list, val, osips_shm_malloc)

static inline str_list *_add_str_list(str_list **list, str *val, osips_malloc_t alloc_item)
{
	str_list *new_el = _new_str_list(val, alloc_item);
	if (!new_el)
		return NULL;

	add_last(new_el, *list);
	return *list;
}

#define add_pkg_str_list(list, val) \
	_add_str_list(list, val, osips_pkg_malloc)

#define add_shm_str_list(list, val) \
	_add_str_list(list, val, osips_shm_malloc)


static inline void _free_str_list(str_list *list,
                        osips_free_t free_item, osips_free_t free_str)
{
	str_list *prev;

	while (list) {
		prev = list;
		list = list->next;

		if (free_str)
			free_str(prev->s.s);

		if (free_item)
			free_item(prev);
	}
}

#define free_pkg_str_list(list) \
	_free_str_list(list, osips_pkg_free, NULL)

#define free_shm_str_list(list) \
	_free_str_list(list, osips_shm_free, NULL)

static inline str_list *dup_shm_str_list(const str_list *list)
{
	str_list *item, *ret = NULL;
	const str_list *it;

	for (it = list; it; it = it->next) {
		item = new_shm_str_list((str *)&it->s);
		if (!item)
			goto oom;

		add_last(item, ret);
	}

	return ret;

oom:
	LM_ERR("oom\n");
	free_shm_str_list(ret);
	return NULL;
}

static inline void _free_str_dlist(struct list_head *dlist,
                        osips_free_t free_item, osips_free_t free_str)
{
	struct list_head *_, *__;
	str_dlist *item;

	list_for_each_safe(_, __, dlist) {
		item = list_entry(_, str_dlist, list);
		if (free_str)
			free_str(item->s.s);

		if (free_item)
			free_item(item);
	}
}

#define free_pkg_str_dlist(list) \
	_free_str_dlist(list, osips_pkg_free, osips_pkg_free)

#define free_shm_str_dlist(list) \
	_free_str_dlist(list, osips_shm_free, osips_shm_free)

#endif /* __STR_LIST__ */
