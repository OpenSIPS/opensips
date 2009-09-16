/*
 * $Id$
 *
 * Copyright (C) 2008 Voice System SRL
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
 * History:
 * --------
 * 2009-09-16  initial version (andreidragus)
 *
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "str.h"
#include "map.h"
#include "mem/mem.h"
#include "mem/shm_mem.h"

#define avl_malloc(dest,size,shared) do		\
{						\
	if(shared)				\
		(dest) = shm_malloc(size);		\
	else					\
		(dest) = pkg_malloc(size);		\
} while(0)

#define avl_free(dest,shared)	do		\
{						\
	if(shared)				\
		shm_free(dest);			\
	else					\
		pkg_free(dest);			\
} while(0)

#define min(a,b)  ((a)<(b))?(a):(b)


static int str_cmp(str s1, str s2)
{
	int ret;

	ret = strncmp( s1.s, s2.s, min( s1.len, s2.len) );

	if( ret == 0)
		ret =  s1.len -  s2.len;

		
	return ret;
}


/* Creates and returns a new table
   with comparison function |compare| using parameter |param|
   and memory allocator |allocator|.
   Returns |NULL| if memory allocation failed. */

map_t map_create(int shared)
{
	map_t tree;

	avl_malloc(tree, sizeof *tree, shared);

	if (tree == NULL)
		return NULL;

	tree->avl_root = NULL;
	tree->shared = shared;
	tree->avl_count = 0;
	

	return tree;
}

/* Search |tree| for an item matching |item|, and return it if found.
   Otherwise return |NULL|. */
void ** map_find( map_t tree, str key)
{
	struct avl_node *p;

	for (p = tree->avl_root; p != NULL;) {
		int cmp = str_cmp(key, p->key);

		if (cmp < 0)
			p = p->avl_link[0];
		else if (cmp > 0)
			p = p->avl_link[1];
		else /* |cmp == 0| */
			return & (p->val);
	}

	return NULL;
}

/* Inserts |item| into |tree| and returns a pointer to |item|'s address.
   If a duplicate item is found in the tree,
   returns a pointer to the duplicate without inserting |item|.
   Returns |NULL| in case of memory allocation failure. */
void ** map_get( map_t tree, str key)
{
	struct avl_node *y, *z; /* Top node to update balance factor, and parent. */
	struct avl_node *p, *q; /* Iterator, and parent. */
	struct avl_node *n;	/* Newly inserted node. */
	struct avl_node *w;	/* New root of rebalanced subtree. */
	int dir;		/* Direction to descend. */

	unsigned char da[AVL_MAX_HEIGHT];	/* Cached comparison results. */
	int k = 0;				/* Number of cached results. */

	str key_copy;

	z = (struct avl_node *) & tree->avl_root;
	y = tree->avl_root;
	dir = 0;
	for (q = z, p = y; p != NULL; q = p, p = p->avl_link[dir]) {
		int cmp = str_cmp(key, p->key);
		if (cmp == 0)
			return &p->val;

		if (p->avl_balance != 0)
			z = q, y = p, k = 0;
		da[k++] = dir = cmp > 0;
	}




	avl_malloc( n, sizeof *n, tree->shared );
	q->avl_link[dir] = n ;
		
	if (n == NULL)
		return NULL;

	tree->avl_count++;

	avl_malloc(key_copy.s, key.len, tree->shared );
	
	memcpy(key_copy.s,key.s,key.len);
	key_copy.len = key.len;

	n->key = key_copy;
	n->val = NULL;
	n->avl_link[0] = n->avl_link[1] = NULL;
	n->avl_balance = 0;
	if (y == NULL)
		return &n->val;

	for (p = y, k = 0; p != n; p = p->avl_link[da[k]], k++)
		if (da[k] == 0)
			p->avl_balance--;
		else
			p->avl_balance++;

	if (y->avl_balance == -2) {
		struct avl_node *x = y->avl_link[0];
		if (x->avl_balance == -1) {
			w = x;
			y->avl_link[0] = x->avl_link[1];
			x->avl_link[1] = y;
			x->avl_balance = y->avl_balance = 0;
		} else {
			assert(x->avl_balance == +1);
			w = x->avl_link[1];
			x->avl_link[1] = w->avl_link[0];
			w->avl_link[0] = x;
			y->avl_link[0] = w->avl_link[1];
			w->avl_link[1] = y;
			if (w->avl_balance == -1)
				x->avl_balance = 0, y->avl_balance = +1;
			else if (w->avl_balance == 0)
				x->avl_balance = y->avl_balance = 0;
			else /* |w->avl_balance == +1| */
				x->avl_balance = -1, y->avl_balance = 0;
			w->avl_balance = 0;
		}
	} else if (y->avl_balance == +2) {
		struct avl_node *x = y->avl_link[1];
		if (x->avl_balance == +1) {
			w = x;
			y->avl_link[1] = x->avl_link[0];
			x->avl_link[0] = y;
			x->avl_balance = y->avl_balance = 0;
		} else {
			assert(x->avl_balance == -1);
			w = x->avl_link[0];
			x->avl_link[0] = w->avl_link[1];
			w->avl_link[1] = x;
			y->avl_link[1] = w->avl_link[0];
			w->avl_link[0] = y;
			if (w->avl_balance == +1)
				x->avl_balance = 0, y->avl_balance = -1;
			else if (w->avl_balance == 0)
				x->avl_balance = y->avl_balance = 0;
			else /* |w->avl_balance == -1| */
				x->avl_balance = +1, y->avl_balance = 0;
			w->avl_balance = 0;
		}
	} else
		return &n->val;
	z->avl_link[y != z->avl_link[0]] = w;

	
	return &n->val;
}

/* Inserts |item| into |table|.
   Returns |NULL| if |item| was successfully inserted
   or if a memory allocation error occurred.
   Otherwise, returns the duplicate item. */
void * map_put( map_t table, str key, void *item)
{
	void **p = map_get(table, key);
	void * ret;


	if( p == NULL )
		return p;

	ret = *p;
	*p = item;
	
	return ret == item ? NULL : ret;
}




/* Deletes from |tree| and returns an item matching |item|.
   Returns a null pointer if no matching item found. */
void * map_remove( map_t tree, str key)
{
	/* Stack of nodes. */
	struct avl_node * pa[AVL_MAX_HEIGHT];	/* Nodes. */
	unsigned char da[AVL_MAX_HEIGHT];	/* |avl_link[]| indexes. */
	int k;					/* Stack pointer. */
	void * val;

	struct avl_node *p;	/* Traverses tree to find node to delete. */
	int cmp;		/* Result of comparison between |item| and |p|. */



	k = 0;
	p = (struct avl_node *) & tree->avl_root;
	for (cmp = -1; cmp != 0;
		cmp = str_cmp(key, p->key)) {
		int dir = cmp > 0;

		pa[k] = p;
		da[k++] = dir;

		p = p->avl_link[dir];
		if (p == NULL)
			return NULL;
	}
	val = p->val;

	if (p->avl_link[1] == NULL)
		pa[k - 1]->avl_link[da[k - 1]] = p->avl_link[0];
	else {
		struct avl_node *r = p->avl_link[1];
		if (r->avl_link[0] == NULL) {
			r->avl_link[0] = p->avl_link[0];
			r->avl_balance = p->avl_balance;
			pa[k - 1]->avl_link[da[k - 1]] = r;
			da[k] = 1;
			pa[k++] = r;
		} else {
			struct avl_node *s;
			int j = k++;

			for (;;) {
				da[k] = 0;
				pa[k++] = r;
				s = r->avl_link[0];
				if (s->avl_link[0] == NULL)
					break;

				r = s;
			}

			s->avl_link[0] = p->avl_link[0];
			r->avl_link[0] = s->avl_link[1];
			s->avl_link[1] = p->avl_link[1];
			s->avl_balance = p->avl_balance;

			pa[j - 1]->avl_link[da[j - 1]] = s;
			da[j] = 1;
			pa[j] = s;
		}
	}

	avl_free(p->key.s,tree->shared);
	avl_free(p,tree->shared);

	assert(k > 0);
	while (--k > 0) {
		struct avl_node *y = pa[k];

		if (da[k] == 0) {
			y->avl_balance++;
			if (y->avl_balance == +1)
				break;
			else if (y->avl_balance == +2) {
				struct avl_node *x = y->avl_link[1];
				if (x->avl_balance == -1) {
					struct avl_node *w;
					assert(x->avl_balance == -1);
					w = x->avl_link[0];
					x->avl_link[0] = w->avl_link[1];
					w->avl_link[1] = x;
					y->avl_link[1] = w->avl_link[0];
					w->avl_link[0] = y;
					if (w->avl_balance == +1)
						x->avl_balance = 0, y->avl_balance = -1;
					else if (w->avl_balance == 0)
						x->avl_balance = y->avl_balance = 0;
					else /* |w->avl_balance == -1| */
						x->avl_balance = +1, y->avl_balance = 0;
					w->avl_balance = 0;
					pa[k - 1]->avl_link[da[k - 1]] = w;
				} else {
					y->avl_link[1] = x->avl_link[0];
					x->avl_link[0] = y;
					pa[k - 1]->avl_link[da[k - 1]] = x;
					if (x->avl_balance == 0) {
						x->avl_balance = -1;
						y->avl_balance = +1;
						break;
					} else
						x->avl_balance = y->avl_balance = 0;
				}
			}
		} else {
			y->avl_balance--;
			if (y->avl_balance == -1)
				break;
			else if (y->avl_balance == -2) {
				struct avl_node *x = y->avl_link[0];
				if (x->avl_balance == +1) {
					struct avl_node *w;
					assert(x->avl_balance == +1);
					w = x->avl_link[1];
					x->avl_link[1] = w->avl_link[0];
					w->avl_link[0] = x;
					y->avl_link[0] = w->avl_link[1];
					w->avl_link[1] = y;
					if (w->avl_balance == -1)
						x->avl_balance = 0, y->avl_balance = +1;
					else if (w->avl_balance == 0)
						x->avl_balance = y->avl_balance = 0;
					else /* |w->avl_balance == +1| */
						x->avl_balance = -1, y->avl_balance = 0;
					w->avl_balance = 0;
					pa[k - 1]->avl_link[da[k - 1]] = w;
				} else {
					y->avl_link[0] = x->avl_link[1];
					x->avl_link[1] = y;
					pa[k - 1]->avl_link[da[k - 1]] = x;
					if (x->avl_balance == 0) {
						x->avl_balance = +1;
						y->avl_balance = -1;
						break;
					} else
						x->avl_balance = y->avl_balance = 0;
				}
			}
		}
	}

	tree->avl_count--;
	return (void *) val;
}


/* Frees storage allocated for |tree|.
   If |destroy != NULL|, applies it to each data item in inorder. */
void map_destroy( map_t tree, value_destroy_func destroy)
{
	struct avl_node *p, *q;

	for (p = tree->avl_root; p != NULL; p = q)
		if (p->avl_link[0] == NULL) {
			q = p->avl_link[1];
			if (destroy != NULL && p->val != NULL)
				destroy(p->val);
			avl_free( p->key.s,tree->shared);
			avl_free( p, tree->shared );
		} else {
			q = p->avl_link[0];
			p->avl_link[0] = q->avl_link[1];
			q->avl_link[1] = p;
		}

	avl_free( tree, tree->shared );
}

int map_size( map_t tree )
{
	return tree->avl_count;
}


void process_all( map_t tree,  struct avl_node *p, process_each_func f, void * param );

void process_all( map_t tree,  struct avl_node *p, process_each_func f, void * param )
{
	if( tree->ret_code )
		return;

	if( p->avl_link[0] )
		process_all( tree, p->avl_link[0], f ,param );

	tree->ret_code |= f( param, p->key, p->val);

	if( p->avl_link[1] )
		process_all( tree, p->avl_link[1], f ,param );
}

int map_for_each( map_t tree, process_each_func f, void * param)
{
	tree->ret_code = 0;

	if( tree->avl_root )
		process_all( tree, tree->avl_root, f, param);

	return tree->ret_code;


}