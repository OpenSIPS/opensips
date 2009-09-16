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

#include "str.h"
#include <stddef.h>

#ifndef AVL_H
#define AVL_H 



/* Maximum AVL tree height. */
#ifndef AVL_MAX_HEIGHT
#define AVL_MAX_HEIGHT 128
#endif

/* Tree data structure. */
typedef struct avl_table {
	int shared;			/* Shared memory or private memory */
	struct avl_node *avl_root;	/* Tree's root. */
	size_t avl_count;		/* Number of items in tree. */
	int ret_code;
	
} *map_t;

/* An AVL tree node. */
struct avl_node {
	struct avl_node * avl_link[2];	/* Subtrees. */
	str key;			/* Key */
	void * val;			/* Value */
	signed char avl_balance;	/* Balance factor. */
};

/*
 * Function that will be called to destroy each
 * value in the map.
 *
 */

typedef  void (* value_destroy_func)(void *);

/*
 * Function that will be called for each value in the map
 *
 * Should return 0. A non-zero return code will cause the processing to stop
 * and the it will be returned by map_for_each();
 * 
 */

typedef  int (* process_each_func )(void * param, str key, void * value);

/* Map functions. */

/*
 * Allocates and initializes a map.
 * It can be in shared memory or in private memory.
 *
 * shared = 0 -> private memory
 * shared = 1 -> shared memory
 */

map_t	map_create ( int shared );


/*
 * Destroys a map and frees all memory used.
 * A function should be given to free the values of each node.
 * If the function is NULL or a value is NULL it will not be called.
 *
 */

void	map_destroy( map_t, value_destroy_func );

/*
 * Searches for a given key in the map.
 * A pointer to the location of the value is returned.
 * If the key is not found NULL is returned.
 *
 */
void **	map_find   ( map_t, str );


/*
 * Searches for a given key in the map.
 * If the key is not found it is inserted.
 * A pointer to the location of the value is returned.
 * NULL is returned if a memory allocation error occurs.
 *
 */

void **	map_get  ( map_t, str );

/*
 * Inserts a (key;value) pair.
 * If the key existed the value is returned so the user can free it.
 * Otherwise NULL is returned.
 *
 */

void *	map_put ( map_t, str, void *);

/*
 * Deletes a key from the map.
 * If the key is found the value is returned so the user can free it.
 * Otherwise NULL is returned.
 *
 */

void *	map_remove ( map_t, str);

/*
 * Returns the size of the map.
 *
 */

int	map_size   ( map_t );


/*
 * Function that calls f() for each key and value in the map
 * in ascending order of the keys. If f returns an error
 * the method will stop and return  what was returned by f.
 *
 */

int	map_for_each   ( map_t map, process_each_func f, void * param );


#endif