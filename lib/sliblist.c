/*
 * A simple linked list implementation.
 *
 * Copyright (C) 2013 VoIP Embedded, Inc.
 *
 * sliblist is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version
 *
 * sliblist is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History
 * ------
 * 2013-02-25 initial implementation (osas)
 */

#include <string.h>

#include "sliblist.h"

struct slinkedl_list {
	struct slinkedl_element *head;
	struct slinkedl_element *tail;
	slinkedl_alloc_f *alloc;
	slinkedl_dealloc_f *dealloc;
};

struct slinkedl_element {
	void *data;
	struct slinkedl_element *next;
};


slinkedl_list_t* slinkedl_init(slinkedl_alloc_f *alloc,
		slinkedl_dealloc_f *dealloc)
{
	slinkedl_list_t *list;
	if (alloc==NULL || dealloc==NULL) return NULL;
	list = (*alloc)(sizeof(slinkedl_list_t));
	if (list) {
		memset(list, 0, sizeof(slinkedl_list_t));
		list->alloc = alloc;
		list->dealloc = dealloc;
	}
	return list;
}


void slinkedl_list_init(slinkedl_list_t* list)
{
	if (!list) return;

	memset(list, 0, sizeof(slinkedl_list_t));
	return;
}


void *slinkedl_prepend(slinkedl_list_t *list, size_t e_size)
{
	slinkedl_element_t *element;

	if (!list || !e_size) return NULL;
	element = (slinkedl_element_t*)(list->alloc(sizeof(slinkedl_element_t) +
			e_size));
	if (!element) return NULL;

	element->next = list->head;
	element->data = (void*)(element + 1);
	list->head = element;
	if (!element->next) {
		/* This is an empty list */
		list->tail = element;
	}
	return (element->data);
}


void *slinkedl_append(slinkedl_list_t *list, size_t e_size)
{
	slinkedl_element_t *element;

	if (!list || !e_size) return NULL;
	element = (slinkedl_element_t*)(list->alloc(sizeof(slinkedl_element_t) +
			e_size));
	if (!element) return NULL;

	element->next = NULL;
	element->data = (void*)(element + 1);
	if (list->tail) {
		list->tail->next = element;
		list->tail = element;
	} else {
		/* This is an empty list */
		list->head = element;
		list->tail = element;
	}
	return (element->data);
}


int slinkedl_traverse(slinkedl_list_t *list,
		slinkedl_run_data_f func, void *data, void *r_data)
{
	int ret;
	slinkedl_element_t *element;

	if (!list) return -1;
	if (!func) return -2;

	element = list->head;
	while(element){
		ret = (*func)(element->data, data, r_data);
		if (ret!=0) return ret;
		element = element->next;
	}
	return 0;
}

void *slinkedl_peek(slinkedl_list_t *list)
{
	if (!list || !list->head)
		return NULL;

	return list->head->data;
}

void slinkedl_list_destroy(slinkedl_list_t *list)
{
	slinkedl_element_t *element;
	slinkedl_dealloc_f *dealloc;

	if (!list) return;
	element = list->head;
	while(element){
		list->head = element->next;
		list->dealloc(element);
		element = list->head;
	}
	dealloc = list->dealloc;
	(*dealloc)(list);

	return;
}

