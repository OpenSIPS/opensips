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

#include "hash.h"
#include "../hash_func.h"
#include "../mem/rpm_mem.h"

int hash_init_locks(gen_hash_t *h)
{
	unsigned int n;
	gen_lock_set_t *locks = NULL;

	for (n = h->size; n >= 1 && !locks; n/=2) {
		locks = lock_set_alloc(n);
		if (locks && lock_set_init(locks))
			break;
	}

	if (!locks) {
		LM_ERR("could not allocate hash locks\n");
		return -1;
	}
	h->locks = locks;
	h->locks_no = n;
	return 0;
}

gen_hash_t *hash_init_flags(unsigned int size, unsigned int flags)
{
	unsigned int n;
	gen_hash_t *h;

	/* initialized the hash table */
	for (n=0 ; n<(8*sizeof(n) - 1) ; n++) {
		if (size==(1<<n))
			break;
		if (size<(1<<n)) {
			LM_WARN("hash_size is not a power "
				"of 2 as it should be -> rounding from %d to %d\n",
				size, 1<<(n-1));
			size = 1<<(n-1);
			break;
		}
	}

	if (flags & HASH_MAP_PERSIST)
		h = rpm_malloc(sizeof *h + size * sizeof(*h->entries));
	else
		h = shm_malloc(sizeof *h + size * sizeof(*h->entries));
	if (!h) {
		LM_ERR("could not alloc hash of %d elements!\n", size);
		return NULL;
	}
	memset(h, 0, sizeof *h + size * sizeof(*h->entries));
	h->entries = (map_t *)(h + 1);
	h->size = size;
	h->flags = flags;
	if (hash_init_locks(h) < 0) {
		LM_ERR("could not alloc locks for hash!\n");
		goto error;
	}

	for (n = 0; n < h->size; n++) {
		h->entries[n] = map_create(
				((flags&HASH_MAP_PERSIST)?AVLMAP_PERSISTENT:AVLMAP_SHARED));
		if (!h->entries[n]) {
			h->size = n; /* we only account for what we've already created */
			goto error;
		}
	}
	return h;
error:
	hash_destroy(h, NULL);
	return NULL;
}

void hash_destroy_locks(gen_hash_t *hash)
{
	if (!hash->locks)
		return;
	lock_set_destroy(hash->locks);
	lock_set_dealloc(hash->locks);
	hash->locks = NULL;
}

void hash_destroy(gen_hash_t *hash, hash_destroy_func destroy)
{
	unsigned int n;

	if (!hash)
		return;

	hash_destroy_locks(hash);

	for (n = 0; n < hash->size; n++)
		if (hash->entries[n])
			map_destroy(hash->entries[n], destroy);

	if (hash->flags & HASH_MAP_PERSIST)
		rpm_free(hash);
	else
		shm_free(hash);
}
