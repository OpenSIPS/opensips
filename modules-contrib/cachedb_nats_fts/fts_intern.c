/*
 * Copyright (C) 2026 OpenSIPS Solutions
 * Copyright (C) 2026 Norm Brandinger <n.brandinger@gmail.com>
 *
 * This file is part of opensips, a free SIP server.
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * Implementation of the SHM string intern table -- see header
 * for the rationale.  ~half of all opensips CPU at 100k AoRs
 * was sem_wait -> hp_shm_malloc on the watcher's entry_add_key
 * path; this module collapses those allocations into a single
 * intern-or-acquire per unique doc key, with refcounted release.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../../dprint.h"
#include "../../locking.h"
#include "../../mem/shm_mem.h"

#include "fts_intern.h"

#define NATS_INTERN_DEFAULT_BUCKETS 1024  /* fallback when caller passes <= 0 */
#define NATS_INTERN_SHARDS   32           /* lock-set size */

typedef struct nats_intern_node {
	struct nats_intern_node *next;
	unsigned int             hash;    /* cached FNV-1a; avoids re-hash on
	                                   * release and gives a 4-byte
	                                   * pre-compare before memcmp */
	int                      refcount;
	int                      len;
	char                     str[];   /* flexible array, NUL-terminated */
} nats_intern_node_t;

struct nats_intern_table {
	nats_intern_node_t **buckets;     /* SHM array of num_buckets heads */
	gen_lock_set_t      *locks;        /* SHM lock set, NATS_INTERN_SHARDS */
	int                  num_buckets;  /* power of two, sized at init */
	unsigned int         bmask;        /* num_buckets - 1 */
	int                  size;         /* live entry count, advisory */
};

static struct nats_intern_table *g_t = NULL;

/* FNV-1a over the bytes.  Cheap, decent distribution for short
 * ASCII strings like our doc keys.  We mask off the hash mod
 * NATS_INTERN_BUCKETS for the bucket; the SAME bucket is used
 * to derive the shard, so acquire and release always lock the
 * same shard for a given string. */
static inline unsigned int intern_fnv1a(const char *s, int len)
{
	unsigned int h = 2166136261u;
	int i;
	for (i = 0; i < len; i++) {
		h ^= (unsigned char)s[i];
		h *= 16777619u;
	}
	return h;
}

static inline unsigned int bucket_of(unsigned int hash)
{
	return hash & g_t->bmask;
}

static inline int intern_shard_of(unsigned int bucket)
{
	return (int)(bucket % NATS_INTERN_SHARDS);
}

/* Round @v up to the next power of two (>= 2). */
static int intern_round_pow2(int v)
{
	int p = 2;
	if (v <= 2)
		return 2;
	while (p < v && p < (1 << 30))
		p <<= 1;
	return p;
}

int nats_intern_init(int num_buckets)
{
	struct nats_intern_table *t;
	int nb;

	if (g_t) {
		LM_WARN("intern: already initialised\n");
		return 0;
	}

	/* Size the bucket table from the caller (the index_buckets modparam),
	 * so the chain length scales with the deployment instead of being
	 * pinned at 1024.  Fall back to the default when unset. */
	nb = intern_round_pow2(num_buckets > 0 ? num_buckets
	                                 : NATS_INTERN_DEFAULT_BUCKETS);

	t = shm_malloc(sizeof(*t));
	if (!t) {
		LM_ERR("intern: no SHM for table struct\n");
		return -1;
	}
	memset(t, 0, sizeof(*t));
	t->num_buckets = nb;
	t->bmask       = (unsigned int)(nb - 1);

	t->buckets = shm_malloc(sizeof(nats_intern_node_t *) * nb);
	if (!t->buckets) {
		LM_ERR("intern: no SHM for %d bucket heads\n", nb);
		shm_free(t);
		return -1;
	}
	memset(t->buckets, 0, sizeof(nats_intern_node_t *) * nb);

	t->locks = lock_set_alloc(NATS_INTERN_SHARDS);
	if (!t->locks) {
		LM_ERR("intern: lock_set_alloc(%d) failed\n",
			NATS_INTERN_SHARDS);
		shm_free(t->buckets);
		shm_free(t);
		return -1;
	}
	if (!lock_set_init(t->locks)) {
		LM_ERR("intern: lock_set_init failed for %d shards\n",
			NATS_INTERN_SHARDS);
		lock_set_dealloc(t->locks);
		shm_free(t->buckets);
		shm_free(t);
		return -1;
	}

	g_t = t;
	LM_DBG("intern: initialised (%d buckets, %d shards)\n",
		nb, NATS_INTERN_SHARDS);
	return 0;
}

void nats_intern_destroy(void)
{
	int i;
	nats_intern_node_t *n, *next;

	if (!g_t) return;

	/* Take all shard locks before walking buckets so a concurrent
	 * acquire/release blocks until we're done.  Order is increasing
	 * shard index so any future code that takes multiple shards
	 * follows the same convention. */
	for (i = 0; i < NATS_INTERN_SHARDS; i++)
		lock_set_get(g_t->locks, i);

	for (i = 0; i < g_t->num_buckets; i++) {
		for (n = g_t->buckets[i]; n; n = next) {
			next = n->next;
			shm_free(n);
		}
		g_t->buckets[i] = NULL;
	}

	for (i = NATS_INTERN_SHARDS - 1; i >= 0; i--)
		lock_set_release(g_t->locks, i);

	lock_set_destroy(g_t->locks);
	lock_set_dealloc(g_t->locks);
	shm_free(g_t->buckets);
	shm_free(g_t);
	g_t = NULL;
}

char *nats_intern_acquire(const char *s, int len)
{
	unsigned int        hash, bucket;
	int                 shard;
	nats_intern_node_t *n;

	if (!g_t || !s || len < 0)
		return NULL;

	hash   = intern_fnv1a(s, len);
	bucket = bucket_of(hash);
	shard  = intern_shard_of(bucket);

	lock_set_get(g_t->locks, shard);

	for (n = g_t->buckets[bucket]; n; n = n->next) {
		/* Cheap 4-byte hash pre-compare before the memcmp -- on a chain
		 * of mismatched keys this skips almost every memcmp. */
		if (n->hash == hash && n->len == len &&
		    memcmp(n->str, s, (size_t)len) == 0) {
			n->refcount++;
			lock_set_release(g_t->locks, shard);
			return n->str;
		}
	}

	/* Not found -- allocate one block for the header + string +
	 * trailing NUL.  Single shm_malloc per unique string; on the
	 * dominant re-register workload this branch is rare.  */
	n = shm_malloc(sizeof(*n) + (size_t)len + 1);
	if (!n) {
		LM_ERR("intern: no SHM for entry (len=%d)\n", len);
		lock_set_release(g_t->locks, shard);
		return NULL;
	}
	n->hash     = hash;
	n->refcount = 1;
	n->len      = len;
	memcpy(n->str, s, (size_t)len);
	n->str[len] = '\0';

	/* Push at the head of the bucket chain.  No ordering
	 * guarantees on chain traversal order, so head-insert is
	 * fine and avoids a tail-walk. */
	n->next               = g_t->buckets[bucket];
	g_t->buckets[bucket]  = n;
	g_t->size++;

	lock_set_release(g_t->locks, shard);
	return n->str;
}

void nats_intern_release(char *p)
{
	nats_intern_node_t  *n, **prev;
	unsigned int         hash, bucket;
	int                  shard;

	if (!p || !g_t) return;

	/* Recover the node header.  The acquire returned &n->str, so
	 * subtract the offset to get the head.  Must be a pointer
	 * obtained from acquire -- arbitrary substrings are
	 * undefined behaviour. */
	n = (nats_intern_node_t *)(p - offsetof(nats_intern_node_t, str));

	/* Use the cached hash -- no need to re-run FNV-1a over the whole key. */
	hash   = n->hash;
	bucket = bucket_of(hash);
	shard  = intern_shard_of(bucket);

	lock_set_get(g_t->locks, shard);

	/* Locate the node in its bucket chain BEFORE touching its refcount.
	 * On a double-release the first release already unlinked and freed the
	 * node, so it is no longer in the chain; decrementing n->refcount (a
	 * write into freed SHM) or freeing it again would corrupt the heap.
	 * Walking first turns a double-free into a logged no-op.  Chains are
	 * short (uniform hash, typically 1-2 nodes). */
	for (prev = &g_t->buckets[bucket]; *prev; prev = &(*prev)->next) {
		if (*prev == n) {
			if (--n->refcount > 0) {
				lock_set_release(g_t->locks, shard);
				return;
			}
			*prev = n->next;
			g_t->size--;
			lock_set_release(g_t->locks, shard);
			shm_free(n);
			return;
		}
	}

	/* Not found in chain -- a double-release or a non-interned pointer.
	 * We have NOT touched n->refcount, so no UAF write and no double-free. */
	LM_ERR("intern: release: node %p not found in bucket %u "
		"(double-release or non-interned pointer?)\n",
		(void *)n, bucket);
	lock_set_release(g_t->locks, shard);
}

char *nats_intern_retain(char *p)
{
	nats_intern_node_t *n;
	unsigned int        hash, bucket;
	int                 shard;

	if (!p || !g_t)
		return p;

	/* Recover the node header the same way release does -- the cached
	 * hash means no FNV recompute over the key. */
	n      = (nats_intern_node_t *)(p - offsetof(nats_intern_node_t, str));
	hash   = n->hash;
	bucket = bucket_of(hash);
	shard  = intern_shard_of(bucket);

	lock_set_get(g_t->locks, shard);
	n->refcount++;
	lock_set_release(g_t->locks, shard);
	return p;
}

int nats_intern_refcount(const char *p)
{
	const nats_intern_node_t *n;
	unsigned int              hash, bucket;
	int                       shard, rc;

	if (!p || !g_t)
		return 0;

	n      = (const nats_intern_node_t *)
		(p - offsetof(nats_intern_node_t, str));
	hash   = n->hash;
	bucket = bucket_of(hash);
	shard  = intern_shard_of(bucket);

	lock_set_get(g_t->locks, shard);
	rc = n->refcount;
	lock_set_release(g_t->locks, shard);
	return rc;
}

int nats_intern_size(void)
{
	return g_t ? g_t->size : 0;
}

#ifdef UNIT_TESTS
/* Puts `t` in place of this process's intern table and returns the one it
 * replaced, so the unit test suite can work on a table of its own (NULL:
 * none) and put the live one back.  Other processes keep theirs. */
void *fts_ut_intern_swap(void *t)
{
	void *old = g_t;

	g_t = t;
	return old;
}
#endif
