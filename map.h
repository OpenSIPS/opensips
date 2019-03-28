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

#include "str.h"
#include <stddef.h>

#ifndef AVL_H
#define AVL_H



/* Maximum AVL tree height. */
#ifndef AVL_MAX_HEIGHT
#define AVL_MAX_HEIGHT 128
#endif

/* Flags that can be passed on when creating a map */
enum map_flags
{
	AVLMAP_SHARED = 1,		/* determines if the map is to be allocated in
				shared or private memory */
	AVLMAP_NO_DUPLICATE = 2,	/* determines if the map will duplicate added keys*/
	AVLMAP_PERSISTENT = 4,	/* determines if the map will be stored in
				persistent memory */

};

/* Tree data structure. */
typedef struct avl_table {
	enum map_flags flags;		/* Shared memory or private memory */
	struct avl_node *avl_root;	/* Tree's root. */
	size_t avl_count;		/* Number of items in tree. */
	int ret_code;

} *map_t;

/* Iterator data structure. */
typedef struct avl_iterator {
	struct avl_node * node;		/* Current node. */
	map_t map;			/* The map that this iterator points to*/
} map_iterator_t;



/* An AVL tree node. */
struct avl_node {
	struct avl_node * avl_link[2];	/* Subtrees. */
	struct avl_node * avl_parent;  /* Parent node. */
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
 * Flags can be set to determine the map behaviour. Several flags can be OR-ed
 * together.
 *
 * AVLMAP_SHARED -> flag for shared memory
 * AVLMAP_NO_DUPLICATE -> flag for key duplication
 * AVLMAP_PERSISTENT -> flag for persistent shared memory
 *
 */

map_t map_create ( enum map_flags flags );


/*
 * Destroys a map and frees all memory used.
 * A function should be given to free the values of each node.
 * If the function is NULL or a value is NULL it will not be called.
 *
 */

void map_destroy( map_t, value_destroy_func );

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

void* map_put ( map_t, str, void *);

/*
 * Deletes a key from the map.
 * If the key is found the value is returned so the user can free it.
 * Otherwise NULL is returned.
 *
 */

void* map_remove ( map_t, str);

/*
 * Returns the size of the map.
 *
 */

int map_size   ( map_t );


/*
 * Function that calls f() for each key and value in the map
 * in ascending order of the keys. If f returns an error
 * the method will stop and return  what was returned by f.
 *
 */

int map_for_each   ( map_t map, process_each_func f, void * param );

/*
 * Function that initializes an iterator to the first element in the map.
 * If the map is empty it will initialize an invalid iterator.
 *
 * Returns 0 on success and -1 on error.
 *
 */

int map_first( map_t map, map_iterator_t * it);


/*
 * Function that initializes an iterator to the last element in the map.
 * If the map is empty it will initialize an invalid iterator.
 *
 * Returns 0 on success and -1 on error.
 *
 */

int map_last( map_t map, map_iterator_t * it);

/*
 * Returns a pointer to the location where the key is stored.
 * Users should copy the key if they want to modify it.
 *
 * Returns NULL on error.
 *
 */

str *	iterator_key( map_iterator_t * it );

/*
 * Returns a pointer to the location where the value is stored.
 * Returns NULL on error.
 *
 */
void ** iterator_val( map_iterator_t * it );

/*
 * Advances the iterator to the next element in alphabetical
 * order in the map.
 * If the end is reached an invalid iterator is set.
 *
 * Returns 0 on success and -1 on error.
 *
 */

int iterator_next( map_iterator_t * it  );

/*
 * Advances the iterator to the previous element in alphabetical
 * order in the map.
 * If the end is reached an invalid iterator is set.
 *
 * Returns 0 on success and -1 on error.
 *
 */

int iterator_prev( map_iterator_t * it  );

/*
 * Checks if an iterator is valid.
 * Can be used to check if the end of the map has been reached.
 * Invalid iterators may be returned from all functions that initialize
 * iterators.
 *
 * Returns 1 for valid and 0 for invalid.
 *
 */
int iterator_is_valid( map_iterator_t * it );

/*
 *
 * Deletes the node pointed by the iterator.
 *
 * The iterator itself will become invalid, and all
 * iterators that pointed to the same node should no longer be used
 * as they point to inexisting nodes.
 *
 * Returns the value stored in the node so the user can free it.
 * Returns NULL if no deletion occurred.
 *
 *
 */
void* iterator_delete( map_iterator_t * it  );


#endif

