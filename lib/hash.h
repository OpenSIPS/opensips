/*
 * Copyright (C) 2020 OpenSIPS Solutions
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

#ifndef __OSIPS_HASH__
#define __OSIPS_HASH__

#include "../map.h"
#include "../locking.h"

typedef struct gen_hash {
	unsigned int size, locks_no;
	map_t *entries;
	gen_lock_set_t *locks;
} gen_hash_t;

/* function used to destroy values in the hash */
typedef void (*hash_destroy_func)(void *);

/* function used to iterate on a hash entry
 * - a non-sero return code will cause processing to stop */
typedef  int (*hash_entry_func)(void *param, str key, void *value);

/* initializes a hash of specified size */
gen_hash_t *hash_init(unsigned int size);

/* destroyes an allocated hash
 * - uses the destroy func to call for each value found in hash */
void hash_destroy(gen_hash_t *hash, hash_destroy_func destroy);


/* returns the size of the hash map */
#define hash_size(_h) ((_h)->size)

/* returns the hash entry for a key */
#define hash_entry(_h, _k) (core_hash(&(_k), NULL, (_h)->size))

/* retrieves a value from an entry key */
#define hash_find(_h, _e, _k) \
	map_find((_h)->entries[(_e)], _k)

/* retrieves a value from a key */
#define hash_find_key(_h, _k) \
	hash_find(_h, hash_entry(_h, _k), _k)

/* same as hash_find, but inserts the key if it is not found */
#define hash_get(_h, _e, _k) \
	map_get((_h)->entries[(_e)], _k)

/* same as above, but compute entry fron key */
#define hash_get_key(_h, _k) \
	hash_get(_h, hash_entry(_h, _k), _k)

/* inserts a value in the hash
 * - if a different value exists, it is returned to be removed/freed */
#define hash_insert(_h, _e, _k) \
	map_insert((_h)->entries[(_e)], _k)

/* same as above, but compute entry fron key */
#define hash_insert_key(_h, _k) \
	hash_insert(_h, hash_entry(_h, _k), _k)

/* removes a value from the hash
 * - the existing value is returned, so it can be released */
#define hash_remove(_h, _e, _k) \
	map_remove((_h)->entries[(_e)], _k)

/* same as above, but compute entry fron key */
#define hash_remove_key(_h, _k) \
	hash_remove(_h, hash_entry(_h, _k), _k)

/* locks the operations on a specific entry */
#define hash_lock(_h, _e) \
		lock_set_get((_h)->locks, ((_e) % (_h)->locks_no))

/* releases the lock on a specific entry */
#define hash_unlock(_h, _e) \
		lock_set_release((_h)->locks, ((_e) % (_h)->locks_no))

/* runs a function for each key inside the entry */
#define hash_for_each_entry(_h, _e, _f, _p) \
		map_for_each((_h)->entries[(_e)], _f, _p)

/* same as above, but locked */
#define hash_for_each_entry_locked(_h, _e, _f, _p) \
	do { \
		hash_lock(_h, _e); \
		map_for_each((_h)->entries[(_e)], _f, _p); \
		hash_unlock(_h, _e); \
	} while(0)

/* runs a function for each value */
#define hash_for_each(_h, _f, _p) \
	do { \
		int __hi; \
		for (__hi = 0; __hi < (_h)->size; __hi++) \
			map_for_each((_h)->entries[(__hi)], _f, _p); \
	} while(0)

/* same as above, but locked */
#define hash_for_each_locked(_h, _f, _p) \
	do { \
		int __hi; \
		for (__hi = 0; __hi < (_h)->size; __hi++) \
			hash_for_each_entry_locked(_h, (__hi), _f, _p); \
	} while(0)

#endif /* __OSIPS_HASH__ */
