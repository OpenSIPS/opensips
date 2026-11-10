/*
 * Copyright (C) 2025 OpenSIPS Solutions
 * Copyright (C) 2025 Norm Brandinger <n.brandinger@gmail.com>
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
 */

/*
 * fts_index.h — the FTS/search-index storage and maintenance API
 * (moved from cachedb_nats_json.h when the index became its own module).
 */

#ifndef CDBN_FTS_INDEX_H
#define CDBN_FTS_INDEX_H

#include <stdint.h>
#include <time.h>
#include "../../str.h"

/* identical to nats.h's typedef; C11 permits the redefinition */
typedef struct __kvStore kvStore;


#include <nats/nats.h>
#include "../../cachedb/cachedb.h"
#include <pthread.h>

/*
 * Index entry — one per unique "field:value" combination.
 *
 * Stored in a singly-linked hash bucket chain.  Each entry tracks
 * the set of document keys that contain this field:value pair.
 * The keys array grows dynamically (doubled when full).
 */
/* Initial capacity of the inline keys[] array packed into the entry
 * blob.  Chosen so a typical low-fanout (field, value) entry never
 * triggers a separate keys[] allocation -- 8 doc keys cover the
 * usrloc "high-uniqueness" fields (aor, contact).  When num_keys
 * exceeds this, entry_add_key allocates a fresh keys[] from SHM
 * and the inline slots become dead memory inside the blob (~64 B
 * waste per grown entry; trivial against the index footprint). */
#define NATS_IDX_KEYS_INLINE 8

typedef struct _nats_idx_entry {
	char *field_value;          /* "field:value" string.  Points into
	                             * the same shm_malloc blob as the
	                             * entry struct itself (single-alloc
	                             * layout); not separately freed. */
	unsigned int fv_len;        /* Length of field_value in bytes
	                             * (excluding null terminator). */
	char **keys;                /* Array of document key strings (each
	                             * is an interned SHM pointer from
	                             * cachedb_nats_intern.c).  When
	                             * keys_inline=1 this points into the
	                             * same blob as the entry; otherwise
	                             * to a separately-shm_malloc'd array
	                             * (after at least one geometric
	                             * growth past NATS_IDX_KEYS_INLINE). */
	int num_keys;               /* Number of document keys currently
	                             * stored in the keys array. */
	int alloc_keys;             /* Allocated capacity of the keys array.
	                             * Doubles when num_keys == alloc_keys. */
	int keys_inline;            /* 1 if keys[] still points into the
	                             * entry blob (initial state); 0 once
	                             * it has been grown to a separate
	                             * allocation.  free_entry uses this
	                             * to decide whether to shm_free
	                             * keys[] separately. */
	struct _nats_idx_entry *next; /* Next entry in the hash bucket chain
	                               * (singly linked, NULL at tail). */
} nats_idx_entry;

/*
 * Number of hash buckets in the search index.
 *
 * The hash function distributes "field:value" strings across this many
 * buckets using a simple multiplicative hash.  256 provides a reasonable
 * trade-off between memory usage and chain length for typical deployments
 * (hundreds to low thousands of indexed documents).
 */
/*
 * Hash table sizing.
 *
 * The bucket count is now runtime-tunable via the cachedb_nats
 * modparam `index_buckets` (default 4096, rounded up to a power
 * of two at init).  Operators with > 100 000 AoRs should raise it
 * (32 768 or 65 536).  Each doubling cuts average chain length
 * in half for about 32 KB of additional SHM in the buckets array.
 * Powers of two keep `% buckets` compiled to a bitmask AND.
 *
 * NATS_IDX_SHARDS still partitions the bucket array into 16
 * contiguous slices, each guarded by its own SHM lock; bucket
 * count is forced to be a multiple of NATS_IDX_SHARDS at init
 * so each shard guards exactly buckets/16 buckets.
 */
#define NATS_IDX_DEFAULT_BUCKETS 4096
#define NATS_IDX_SHARDS          16

/* Runtime bucket count, set by nats_json_index_init from the
 * `index_buckets` modparam (rounded to power of two, minimum
 * NATS_IDX_SHARDS).  Hash + shard helpers read this at runtime;
 * a power-of-two value lets the compiler reduce `% nats_idx_buckets`
 * to a bitmask via `nats_idx_bucket_mask`. */
extern int nats_idx_buckets;
extern int nats_idx_bucket_mask;   /* nats_idx_buckets - 1, set by init */
#define NATS_IDX_SHARD_OF(bucket)  ((bucket) / (nats_idx_buckets / NATS_IDX_SHARDS))

#include "../../locking.h"

/*
 * Search index — hash table with sharded SHM-backed locks.
 *
 * Allocated once in shared memory during mod_init (pre-fork), so all
 * OpenSIPS workers see the same index instance.  Watcher updates
 * (running in rank-1) are visible to every reader immediately;
 * non-rank-1 workers no longer maintain a private copy.  This trades
 * a per-process index (~5 MB × M workers, ~40 MB at 8 workers / 50k
 * AoRs) for a single ~5 MB SHM block.
 *
 * Synchronisation is via gen_lock_set_t, a SHM-safe lock set.  Each
 * shard guards a slice of buckets[]; operations acquire only the
 * shards they touch.
 */
typedef struct _nats_search_idx {
	nats_idx_entry **buckets;   /* Dynamically allocated array of
	                             * hash bucket chain heads (length =
	                             * nats_idx_buckets, set at init from
	                             * the `index_buckets` modparam).  Each
	                             * element is NULL (empty bucket) or
	                             * points to the first nats_idx_entry in
	                             * a singly-linked chain. */
	_Atomic int num_documents;  /* Total number of unique document keys
	                             * tracked across all index entries.
	                             * Atomic so add/remove can update it
	                             * without serialising on any shard. */
	gen_lock_set_t *shard_locks;
	                            /* SHM-backed lock set with
	                             * NATS_IDX_SHARDS entries.  Single-
	                             * bucket ops lock only their owning
	                             * shard; whole-index ops acquire all
	                             * shards in index order. */
} nats_search_idx;

/*
 * Initialize the search index data structure.
 *
 * Allocates the global nats_search_idx and its bucket array in SHM
 * (shared across all workers), zeroes all bucket pointers, and
 * initialises the sharded SHM lock set.  Must be called once pre-fork
 * from mod_init, before any index operations.
 *
 * @return  0 on success, -1 on SHM allocation or lock_set init failure.
 *
 * Thread safety: NOT thread-safe.  Call once pre-fork from mod_init.
 */
int nats_json_index_init(void);

/*
 * Build the search index from existing KV data.
 *
 * Iterates all keys in the KV bucket matching the given prefix, reads
 * each JSON document, and indexes all top-level string and integer fields.
 * Called once during startup after child_init.
 *
 * @param kv      KV store handle (from nats_pool_get_kv).
 * @param prefix  Key prefix filter (e.g., "user." to index only user
 *                documents).  Pass NULL or "" to index all keys.
 * @return        0 on success, -1 on error.
 *
 * Thread safety: Acquires the per-shard SHM locks internally.
 */
int nats_json_index_build(kvStore *kv, const char *prefix);

/*
 * Clear and rebuild the search index from scratch.
 *
 * Removes all existing index entries and calls nats_json_index_build().
 * Used after a NATS reconnection, when the KV watcher is re-established
 * and the index may be stale due to missed updates during the disconnect.
 *
 * @param kv      Fresh KV store handle (post-reconnection).
 * @param prefix  Key prefix filter (same semantics as index_build).
 * @return        0 on success, -1 on error.
 *
 * Thread safety: Acquires the per-shard SHM locks internally.
 */
int nats_json_index_rebuild(kvStore *kv, const char *prefix);

/*
 * Add a JSON document to the search index.
 *
 * Parses the JSON string and creates index entries for each top-level
 * field:value pair.  Adding an already-indexed key is idempotent
 * (duplicate keys are de-duped per entry); stale (field:value) entries
 * are pruned separately via nats_json_index_remove_fields on the update
 * path.
 *
 * Called by the KV watcher thread when a key is created or updated.
 *
 * @param key       Document key string.
 * @param json_str  Raw JSON string content.
 * @param json_len  Length of json_str in bytes.
 * @return          0 on success, -1 on parse error or allocation failure.
 *
 * Thread safety: Acquires the per-shard SHM locks internally.
 */
int nats_json_index_add(const char *key, int key_len,
	const char *json_str, int json_len);

/*
 * Remove a document from the search index.
 *
 * Removes all field:value entries associated with the given key.
 * Called by the KV watcher thread when a key is deleted or purged.
 *
 * @param key  Document key string to remove.
 * @return     0 on success (or key not found — idempotent), -1 on error.
 *
 * Thread safety: Acquires the per-shard SHM locks internally.
 */
int nats_json_index_remove(const char *key, int key_len);

/*
 * [a /]: live forward-index
 * document count, for observability and the joint reaper⊕watcher e2e.
 * @return  num_documents (>= 0), or -1 if the index is not initialized.
 *          NULL-safe — never dereferences a NULL g_idx.
 */
int nats_json_index_count(void);

/*
 * Fast delete-by-key using the doc-key -> field:value reverse map: removes
 * the key from only the entries it was indexed under (O(fields)) instead
 * of walking every bucket.  Returns 0 on a hit (key removed), -1 on a miss
 * -- on -1 the caller MUST fall back to nats_json_index_remove(key).  Used
 * by the KV watcher's delete/expiry path.
 *
 * Thread safety: takes the reverse-map shard lock, then forward-index
 * shard locks (never simultaneously); safe from the watcher thread.
 */
int nats_json_index_remove_by_revmap(const char *key, int key_len);

/*
 * Targeted variant of index_remove that takes the document's old
 * JSON content and visits ONLY the (field:value) entries the key
 * appears in, rather than walking every bucket.
 *
 * Used by nats_cache_update on a successful CAS write: the
 * pre-write JSON we already fetched from kvStore_Get tells us
 * exactly which entries this key was registered against, so we
 * can remove the key with O(F) work (F = number of indexed
 * top-level string fields, typically 2-3) instead of O(N) over
 * the whole index.  Locks one shard at a time.
 *
 * Falls back to a no-op if @json_str is NULL or empty; callers
 * without the old JSON (e.g. the lazy stale-index self-heal in
 * nats_cache_query) should keep using nats_json_index_remove.
 *
 * @param key       Document key string to remove.
 * @param json_str  Raw JSON of the document the key was indexed against.
 * @param json_len  Length of json_str in bytes.
 * @return          0 on success, -1 on parse error.
 *
 * Thread safety: takes one shard at a time per field.
 */
int nats_json_index_remove_fields(const char *key, int key_len,
	const char *json_str, int json_len);

/*
 * Destroy the search index and free all resources.
 *
 * Frees all index entries, document key strings, and the mutex.
 * Called during process shutdown.
 *
 * Thread safety: NOT thread-safe.  Call only during shutdown when
 *                no other threads are accessing the index.
 */
void nats_json_index_destroy(void);


/*
 * Get a pointer to the global search index.
 *
 * Used by the KV watcher setup code to pass the index reference to
 * the watcher thread's closure.  Returns NULL if the index has not
 * been initialized.
 *
 * @return  Pointer to the global nats_search_idx instance.
 *
 * Thread safety: The returned pointer is stable after child_init.
 *                Callers must acquire the relevant per-shard SHM locks
 *                before accessing index contents.
 */
nats_search_idx *nats_json_get_index(void);


/* --- index internals shared across the FTS TUs -------------------- */

#include "../../locking.h"

/* The process-global SHM search index; the query walk reads it directly
 * (under the shard locks below).  NULL until nats_json_index_init(). */
extern nats_search_idx *g_idx;

/* djb2 over "field:value"; returns a bucket in [0, nats_idx_buckets). */
unsigned int fts_hash(const char *s, int len);

/* Locate the index entry for a composite "field:value" key.  Caller
 * must hold the entry's shard lock. */
nats_idx_entry *fts_find_entry(const char *fv, int fv_len);

/* Shard-locking helpers.  Whole-index ops acquire shards in index
 * order to keep the lock hierarchy consistent.  The lock set itself
 * is SHM-backed so cross-process synchronisation is safe. */
static inline void idx_lock_shard(nats_search_idx *idx, int shard)
{
	lock_set_get(idx->shard_locks, shard);
}
static inline void idx_unlock_shard(nats_search_idx *idx, int shard)
{
	lock_set_release(idx->shard_locks, shard);
}

#endif /* CDBN_FTS_INDEX_H */
