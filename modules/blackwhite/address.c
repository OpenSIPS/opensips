/*
 * $Id$
 *
 * BLACKWHITE module
 *
 * Copyright (C) 2016 sa
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "address.h"
#include "funcs.h"

#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../ut.h"

#include <stdlib.h>


int data_append(const str *id, const struct net *subnet, int black, struct address *addrs, size_t *n)
{
	static struct address *cur;
	static struct address_node **last_b_node;
	static struct address_node **last_w_node;

	if (*n == 0)
	{
		cur = NULL;
	}

	if (cur == NULL || str_cmp(&(cur->id), id))
	{
		cur = addrs + (*n);

		if (shm_str_dup(&(cur->id), id) != 0)
			return -1;

		if (black)
		{
			cur->black = shm_malloc(sizeof(struct address_node));
			if (cur->black == NULL)
				return -1;

			cur->black->subnet = shm_malloc(sizeof(struct net));
			if (cur->black->subnet == NULL)
				return -1;

			memcpy(cur->black->subnet, subnet, sizeof(struct net));
			cur->black->next = NULL;
			last_b_node = &(cur->black->next);
			last_w_node = &(cur->white);
		}
		else
		{
			cur->white = shm_malloc(sizeof(struct address_node));
			if (cur->white == NULL)
				return -1;

			cur->white->subnet = shm_malloc(sizeof(struct net));
			if (cur->white->subnet == NULL)
				return -1;

			memcpy(cur->white->subnet, subnet, sizeof(struct net));
			cur->white->next = NULL;
			last_b_node = &(cur->black);
			last_w_node = &(cur->white->next);
		}
		++(*n);
	}
	else
	{
		if (black)
		{
			(*last_b_node) = shm_malloc(sizeof(struct address_node));
			if ((*last_b_node) == NULL)
				return -1;

			(*last_b_node)->subnet = shm_malloc(sizeof(struct net));
			if ((*last_b_node)->subnet == NULL)
				return -1;

			memcpy((*last_b_node)->subnet, subnet, sizeof(struct net));
			(*last_b_node)->next = NULL;
			last_b_node = &((*last_b_node)->next);
		}
		else
		{
			(*last_w_node) = shm_malloc(sizeof(struct address_node));
			if ((*last_w_node) == NULL)
				return -1;

			(*last_w_node)->subnet = shm_malloc(sizeof(struct net));
			if ((*last_w_node)->subnet == NULL)
				return -1;

			memcpy((*last_w_node)->subnet, subnet, sizeof(struct net));
			(*last_w_node)->next = NULL;
			last_w_node = &((*last_w_node)->next);
		}
	}
	return 0;
}


static inline void free_list(struct address_node* node)
{
	struct address_node *next;
	while (node)
	{
		next = node->next;
		if (node->subnet)
		{
			shm_free(node->subnet);
			node->subnet = NULL;
		}
		node->next = NULL;
		shm_free(node);
		node = next;
	}
}

void free_data(struct address *addrs, size_t *n)
{
	size_t i;

	for (i = 0; i < (*n); ++i)
	{
		free_list(addrs[i].black);
		free_list(addrs[i].white);

		addrs[i].black = NULL;
		addrs[i].white = NULL;

		if (addrs[i].id.s)
		{
			shm_free(addrs[i].id.s);
			addrs[i].id.s = NULL;
			addrs[i].id.len = 0;
		}
	}

	if (addrs)
	{
		shm_free(addrs);
		addrs = NULL;
	}
	*n = 0;
}


int cmpstringp(const void *p1, const void *p2)
{
	return str_cmp( &(((const struct address*) p1)->id), &(((const struct address*) p2)->id) );
}


/**
 * return:
 *  1 - block
 * -2 - pass
 * -3 - no id
 */
int blackwhite_(str *id, struct ip_addr *ip, const struct address *addrs, size_t data_n)
{
	const struct address what = {*id, NULL, NULL};
	struct address *p;
	struct address_node *node;
	p = bsearch(&what, addrs, data_n, sizeof(struct address), cmpstringp);

	if (p)
	{
		for (node = p->black; node; node = node->next)
		{
			if (matchnet(ip, node->subnet) > 0)
			{
				return 1;
			}
		}

		if (p->white == NULL)
			return -2;

		for (node = p->white; node; node = node->next)
		{
			if (matchnet(ip, node->subnet) > 0)
			{
				return -2;
			}
		}
		return 1;
	}

	return -3;
}
