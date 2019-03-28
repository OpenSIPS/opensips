/*
 * Copyright (C) 2009 Voice System SRL
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
#include "mem/rpm_mem.h"

#define avl_malloc(dest,size,flags) do \
{ \
	if(flags & AVLMAP_SHARED) \
		(dest) = shm_malloc(size); \
	else if (flags & AVLMAP_PERSISTENT) \
		(dest) = rpm_malloc(size); \
	else \
		(dest) = pkg_malloc(size); \
} while(0)

#define avl_free(dest,flags) do \
{ \
	if(flags & AVLMAP_SHARED) \
		shm_free(dest); \
	else if (flags & AVLMAP_PERSISTENT) \
		rpm_free(dest); \
	else \
		pkg_free(dest); \
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

map_t map_create(enum map_flags flags)
{
	map_t tree;

	avl_malloc(tree, sizeof *tree, flags);

	if (tree == NULL)
		return NULL;

	tree->avl_root = NULL;
	tree->flags = flags;
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
   Returns |NULL| in case of memory allocation failure.
 */

void ** map_get( map_t tree, str key)
{
	struct avl_node *y;     /* Top node to update balance factor, and parent. */
	struct avl_node *p, *q; /* Iterator, and parent. */
	struct avl_node *n;	/* Newly inserted node. */
	struct avl_node *w;	/* New root of rebalanced subtree. */
	int dir;		/* Direction to descend. */
	str key_copy;

	y = tree->avl_root;
	dir = 0;
	for (q = NULL, p = tree->avl_root; p != NULL; q = p, p = p->avl_link[dir]) {
		int cmp = str_cmp(key, p->key);
		if (cmp == 0)
			return &p->val;
		dir = cmp > 0;

		if (p->avl_balance != 0)
			y = p;
	}

	avl_malloc( n, sizeof *n, tree->flags );

	if (n == NULL)
		return NULL;

	tree->avl_count++;
	n->avl_link[0] = n->avl_link[1] = NULL;
	n->avl_parent = q;

	if( !( tree->flags & AVLMAP_NO_DUPLICATE ) )
	{
		avl_malloc(key_copy.s, key.len, tree->flags );
		if (!key_copy.s)
			return NULL;

		memcpy(key_copy.s,key.s,key.len);
		key_copy.len = key.len;
		n->key = key_copy;
	}
	else
		n->key = key;

	n->val = NULL;
	if (q != NULL)
		q->avl_link[dir] = n;
	else
		tree->avl_root = n;

	n->avl_balance = 0;

	if (tree->avl_root == n)
		return &n->val;

	for (p = n; p != y; p = q) {
		q = p->avl_parent;
		dir = q->avl_link[0] != p;
		if (dir == 0)
			q->avl_balance--;
		else
			q->avl_balance++;
	}

	if (y->avl_balance == -2) {
		struct avl_node *x = y->avl_link[0];
		if (x->avl_balance == -1) {
			w = x;
			y->avl_link[0] = x->avl_link[1];
			x->avl_link[1] = y;
			x->avl_balance = y->avl_balance = 0;
			x->avl_parent = y->avl_parent;
			y->avl_parent = x;
			if (y->avl_link[0] != NULL)
				y->avl_link[0]->avl_parent = y;
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
			w->avl_parent = y->avl_parent;
			x->avl_parent = y->avl_parent = w;
			if (x->avl_link[1] != NULL)
				x->avl_link[1]->avl_parent = x;
			if (y->avl_link[0] != NULL)
				y->avl_link[0]->avl_parent = y;
		}
	} else if (y->avl_balance == +2) {
		struct avl_node *x = y->avl_link[1];
		if (x->avl_balance == +1) {
			w = x;
			y->avl_link[1] = x->avl_link[0];
			x->avl_link[0] = y;
			x->avl_balance = y->avl_balance = 0;
			x->avl_parent = y->avl_parent;
			y->avl_parent = x;
			if (y->avl_link[1] != NULL)
				y->avl_link[1]->avl_parent = y;
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
			w->avl_parent = y->avl_parent;
			x->avl_parent = y->avl_parent = w;
			if (x->avl_link[0] != NULL)
				x->avl_link[0]->avl_parent = x;
			if (y->avl_link[1] != NULL)
				y->avl_link[1]->avl_parent = y;
		}
	} else
		return &n->val;
	if (w->avl_parent != NULL)
		w->avl_parent->avl_link[y != w->avl_parent->avl_link[0]] = w;
	else
		tree->avl_root = w;

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

void * delete_node(map_t tree, struct avl_node * p)
{
	struct avl_node *q;		/* Parent of |p|. */
	int dir;			/* Side of |q| on which |p| is linked. */
	void * val;

	val = p->val;

	q = p->avl_parent;
	if (q == NULL) {
		q = (struct avl_node *) & tree->avl_root;
		dir = 0;
	}
	else
	{
		if( p == q->avl_link[0] )
			dir = 0;
		else
			dir = 1;
	}

	if (p->avl_link[1] == NULL) {
		q->avl_link[dir] = p->avl_link[0];
		if (q->avl_link[dir] != NULL)
			q->avl_link[dir]->avl_parent = p->avl_parent;
	} else {
		struct avl_node *r = p->avl_link[1];
		if (r->avl_link[0] == NULL) {
			r->avl_link[0] = p->avl_link[0];
			q->avl_link[dir] = r;
			r->avl_parent = p->avl_parent;
			if (r->avl_link[0] != NULL)
				r->avl_link[0]->avl_parent = r;
			r->avl_balance = p->avl_balance;
			q = r;
			dir = 1;
		} else {
			struct avl_node *s = r->avl_link[0];
			while (s->avl_link[0] != NULL)
				s = s->avl_link[0];
			r = s->avl_parent;
			r->avl_link[0] = s->avl_link[1];
			s->avl_link[0] = p->avl_link[0];
			s->avl_link[1] = p->avl_link[1];
			q->avl_link[dir] = s;
			if (s->avl_link[0] != NULL)
				s->avl_link[0]->avl_parent = s;
			s->avl_link[1]->avl_parent = s;
			s->avl_parent = p->avl_parent;
			if (r->avl_link[0] != NULL)
				r->avl_link[0]->avl_parent = r;
			s->avl_balance = p->avl_balance;
			q = r;
			dir = 0;
		}
	}

	if(!( tree->flags & AVLMAP_NO_DUPLICATE ) )
		avl_free(p->key.s,tree->flags);

	avl_free(p,tree->flags);

	while (q != (struct avl_node *) & tree->avl_root) {
		struct avl_node *y = q;

		if (y->avl_parent != NULL)
			q = y->avl_parent;
		else
			q = (struct avl_node *) & tree->avl_root;

		if (dir == 0) {
			dir = q->avl_link[0] != y;
			y->avl_balance++;
			if (y->avl_balance == +1)
				break;
			else if (y->avl_balance == +2) {
				struct avl_node *x = y->avl_link[1];
				if (x->avl_balance == -1) {
					struct avl_node *w;

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
					w->avl_parent = y->avl_parent;
					x->avl_parent = y->avl_parent = w;
					if (x->avl_link[0] != NULL)
						x->avl_link[0]->avl_parent = x;
					if (y->avl_link[1] != NULL)
						y->avl_link[1]->avl_parent = y;
					q->avl_link[dir] = w;
				} else {
					y->avl_link[1] = x->avl_link[0];
					x->avl_link[0] = y;
					x->avl_parent = y->avl_parent;
					y->avl_parent = x;
					if (y->avl_link[1] != NULL)
						y->avl_link[1]->avl_parent = y;
					q->avl_link[dir] = x;
					if (x->avl_balance == 0) {
						x->avl_balance = -1;
						y->avl_balance = +1;
						break;
					} else {
						x->avl_balance = y->avl_balance = 0;
						y = x;
					}
				}
			}
		} else {
			dir = q->avl_link[0] != y;
			y->avl_balance--;
			if (y->avl_balance == -1)
				break;
			else if (y->avl_balance == -2) {
				struct avl_node *x = y->avl_link[0];
				if (x->avl_balance == +1) {
					struct avl_node *w;
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
					w->avl_parent = y->avl_parent;
					x->avl_parent = y->avl_parent = w;
					if (x->avl_link[1] != NULL)
						x->avl_link[1]->avl_parent = x;
					if (y->avl_link[0] != NULL)
						y->avl_link[0]->avl_parent = y;
					q->avl_link[dir] = w;
				} else {
					y->avl_link[0] = x->avl_link[1];
					x->avl_link[1] = y;
					x->avl_parent = y->avl_parent;
					y->avl_parent = x;
					if (y->avl_link[0] != NULL)
						y->avl_link[0]->avl_parent = y;
					q->avl_link[dir] = x;
					if (x->avl_balance == 0) {
						x->avl_balance = +1;
						y->avl_balance = -1;
						break;
					} else {
						x->avl_balance = y->avl_balance = 0;
						y = x;
					}
				}
			}
		}
	}

	tree->avl_count--;
	return(void *) val;

};

/* Deletes from |tree| and returns an item matching |item|.
   Returns a null pointer if no matching item found. */
void * map_remove( map_t tree, str key)
{
	struct avl_node *p; /* Traverses tree to find node to delete. */
	int dir; /* Side of |q| on which |p| is linked. */

	if (tree->avl_root == NULL)
		return NULL;

	p = tree->avl_root;
	for (;;) {
		int cmp = str_cmp(key, p->key);
		if (cmp == 0)
			break;

		dir = cmp > 0;
		p = p->avl_link[dir];
		if (p == NULL)
			return NULL;
	}

	return delete_node( tree, p );

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
			if( !(tree->flags & AVLMAP_NO_DUPLICATE ) )
				avl_free( p->key.s,tree->flags);
			avl_free( p, tree->flags );
		} else {
			q = p->avl_link[0];
			p->avl_link[0] = q->avl_link[1];
			q->avl_link[1] = p;
		}

	avl_free( tree, tree->flags );
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

int map_first( map_t map, map_iterator_t * it)
{
	if( map == NULL || it == NULL )
		return -1;

	it->map = map;

	it->node = map->avl_root;

	if( it->node )
	{
		while( it->node->avl_link[0] )
			it->node = it->node->avl_link[0];
	}

	return 0;
}


int map_last( map_t map, map_iterator_t * it)
{
	if( map == NULL || it == NULL )
		return -1;

	it->map = map;

	it->node = map->avl_root;

	if( it->node )
	{
		while( it->node->avl_link[1] )
			it->node = it->node->avl_link[1];
	}

	return 0;
}

str *	iterator_key( map_iterator_t * it )
{
	if( it == NULL )
		return NULL;

	return &it->node->key;
}

void**	iterator_val( map_iterator_t * it )
{
	if( it == NULL )
		return NULL;

	return &it->node->val;
}

int iterator_is_valid( map_iterator_t * it )
{
	if( it == NULL || it->map ==NULL || it->node == NULL)
		return 0;

	return 1;
}

int iterator_next( map_iterator_t * it  )
{

	struct avl_node *q, *p;		/* Current node and its child. */

	if( it == NULL || it->map ==NULL || it->node == NULL)
		return -1;

	if( it->node->avl_link[1] )
	{
		it->node = it->node->avl_link[1];
		while( it->node->avl_link[0] )
			it->node = it->node->avl_link[0];

	}
	else
	{

		for (p = it->node, q = p->avl_parent ; ; p = q, q = q->avl_parent)
			if (q == NULL || p == q->avl_link[0])
			{
				it->node = q;
				return 0;
			}
	}

	return 0;
}


int iterator_prev( map_iterator_t * it  )
{

	struct avl_node *q, *p;		/* Current node and its child. */

	if( it == NULL || it->map ==NULL || it->node == NULL)
		return -1;

	if( it->node->avl_link[0] )
	{
		it->node = it->node->avl_link[0];
		while( it->node->avl_link[1] )
			it->node = it->node->avl_link[1];

	}
	else
	{

		for (p = it->node, q = p->avl_parent ; ; p = q, q = q->avl_parent)
			if (q == NULL || p == q->avl_link[1])
			{
				it->node = q;
				return 0;
			}
	}

	return 0;
}

void * iterator_delete( map_iterator_t * it  )
{
	void * ret;

	if( it == NULL || it->map ==NULL || it->node == NULL)
		return NULL;

	ret = delete_node( it->map, it->node );

	it->node = NULL;

	return ret;
}

