#ifndef _URI_LIST_H
#define _URI_LIST_H

#include <string.h>
#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../ut.h"

typedef struct list_entry
{
	str *strng;
	struct list_entry *next;
} list_entry_t;

static inline list_entry_t *list_insert(str *strng, list_entry_t *list, int *duplicate)
{
	int cmp;
	list_entry_t *p, *q;

	if (duplicate != NULL)
	        *duplicate = 0;

	if (strng == NULL || strng->s == NULL || strng->len == 0)
	{
		LM_ERR("bad string\n");
		return list;
	}

	if ((p = (list_entry_t *) pkg_malloc(sizeof(list_entry_t))) == NULL)
	{
		LM_ERR("out of memory\n");
		return list;
	}
	p->strng = strng;
	p->next = NULL;

	if (list == NULL)
		return p;

	cmp = str_strcmp(list->strng, strng);

	if (cmp == 0)
        {
                if (duplicate != NULL)
                        *duplicate = 1;
		return list;
        }
	if (cmp > 0)
	{
		p->next = list;
		return p;
	}
	else
	{
		q = list;
		while (q->next != NULL && (cmp = str_strcmp(q->next->strng, strng)) < 0)
			q = q->next;

		if (cmp == 0) {
                        if (duplicate != NULL)
                                *duplicate = 1;
			return list;
		}

		p->next = q->next;
		q->next = p;
		return list;
	}
}

static inline list_entry_t *list_remove(str strng, list_entry_t *list)
{
	int cmp = -1;
	list_entry_t *p = list;

	if (list != NULL)
	{
		if (str_match(p->strng, &strng))
		{
			pkg_free(p->strng->s);
			pkg_free(p->strng);

			p = p->next;
			pkg_free(list);
			return p;
		}
                else
		{
			list_entry_t *p = list, *q;

			while (p->next != NULL && (cmp = str_strcmp(p->next->strng, &strng)) < 0)
				p = p->next;

			if (cmp == 0)
			{
				q = p->next;
				p->next = q->next;
				pkg_free(q->strng->s);
				pkg_free(q->strng);
				pkg_free(q);
			}
		}
	}
	return list;
}

static inline str *list_pop(list_entry_t **list)
{
	str *ret;
	list_entry_t *tmp;

	if (!*list)
		return NULL;

	ret = (*list)->strng;

	tmp = *list;
	*list = (*list)->next;
	pkg_free(tmp);

	return ret;
}

static inline void list_free(list_entry_t **list)
{
	str *strng;

	while ((strng = list_pop(list)) != NULL)
	{
		pkg_free(strng->s);
		pkg_free(strng);
	}
}

#endif /* _URI_LIST_H */

