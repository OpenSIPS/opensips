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
 */

#ifndef CACHEDB_NATS_INTERN_H
#define CACHEDB_NATS_INTERN_H

/*
 * cachedb_nats_intern -- refcounted SHM string intern table
 *
 * Why this exists.  At 100k AoRs / 2000 RPS the watcher's
 * nats_json_index_add hot path was spending ~half of all opensips
 * CPU in sem_wait -> hp_shm_malloc paths (profiled).
 * Each indexed field on a usrloc contact triggers entry_add_key
 * -> shm_malloc(klen+1) for a duplicate of the document key,
 * which then takes a per-bucket SHM_LOCK semaphore inside
 * HP_MALLOC.  ~5 indexed fields per contact x 2000 events/s =
 * ~10k shm_mallocs/s of small strings, all on the same hot path.
 *
 * Insight: the document key is the same string across ALL
 * field-entries for a given AoR.  Today we strdup it 5 times.
 * Interning the doc key collapses those 5 strdups into 1
 * lookup-or-allocate-once, and on every subsequent re-register
 * of the same AoR (the dominant workload) the lookup hits an
 * existing entry and does NO shm_malloc at all.
 *
 * The intern table is a sharded hash table: 1024 buckets,
 * 32 lock shards.  Refcounts are bumped on acquire and
 * decremented on release; the entry is freed when the count
 * reaches zero.  Lookups under the shard lock; the shard lock
 * is independent of the index shard lock so there's no
 * deadlock with cachedb_nats_json's per-shard scheme (the
 * index lock is always taken first; intern lock is always
 * taken second; never the other way around).
 *
 * Memory: each intern node is sizeof(nats_intern_node_t) +
 * len + 1, allocated with a single shm_malloc.  At steady
 * state with 100k AoRs and ~30-byte doc keys, the intern
 * table holds 100k entries x ~70 bytes each = ~7 MB SHM --
 * trivial.
 *
 * Lifetime: nodes are kept in SHM until refcount hits zero,
 * which happens when the last index entry that referenced
 * the doc key is freed (typically via entry_remove_key when
 * an AoR de-registers, or free_entry on full index destroy).
 *
 * Thread safety: every operation locks the relevant shard.
 * Multi-process safe: the table lives in SHM, the locks are
 * gen_lock_set_t (POSIX-sem on aarch64), so the dedicated
 * watcher proc and the rank-1 pthread are equally well
 * supported.
 */

/**
 * Initialise the global intern table in SHM.  Call once from mod_init
 * pre-fork so every worker (and the dedicated watcher proc) maps the same
 * table.
 *
 * @param num_buckets Sizes the bucket array (rounded up to a power of
 *                    two; <= 0 selects the default of 1024) -- pass the
 *                    index_buckets modparam so the intern chains scale
 *                    with the deployment.
 *
 * @return 0 on success (also when already initialised -- logged WARN,
 *         no re-init), -1 on SHM exhaustion or lock-set init failure.
 *
 * Allocation: table struct, bucket array and lock set in SHM, owned by
 * this module (freed by nats_intern_destroy()).
 * Locking: none taken -- NOT thread-safe.
 * Context: mod_init (pre-fork, single process) only.
 */
int  nats_intern_init(int num_buckets);

/**
 * Tear down the intern table.  Frees all entries and the table itself;
 * safe to call when init failed (no-op).
 *
 * @return none.
 *
 * Allocation: shm_free's every node, the bucket array, the lock set
 * and the table struct.
 * Locking: takes ALL shard locks (increasing shard order) around the
 * bucket walk, then destroys the lock set.
 * Context: mod_destroy only -- after it returns no interned pointer or
 * intern call is valid in any process.
 */
void nats_intern_destroy(void);

/**
 * Look up a string in the intern table; insert and allocate it
 * if absent.  In either case the entry's refcount is bumped by
 * one and the SHM-resident NUL-terminated string pointer is
 * returned.  The caller MUST eventually balance every successful
 * acquire with a matching release.
 *
 * @param s   Bytes to intern (need not be NUL-terminated); borrowed,
 *            copied into the node on insert.
 * @param len Length of @s in bytes; negative is rejected.
 *
 * @return SHM-resident NUL-terminated string owned by the intern table
 *         (refcounted -- the caller frees NOTHING directly, it hands
 *         the pointer back via nats_intern_release()); NULL if SHM
 *         allocation fails on insert, if the table is uninitialised,
 *         or on negative @len.  The caller should treat NULL as a
 *         fatal-this-call error and propagate upward (matching the
 *         prior shm_malloc-based code).
 *
 * Locking: the entry's shard lock (derived from the FNV-1a hash) is
 * held only across the chain walk + node insert.
 * Context: any process that has mapped SHM -- SIP workers, the
 * dedicated watcher proc, and the rank-1 pthread alike (locks are
 * gen_lock_set_t).
 */
char *nats_intern_acquire(const char *s, int len);

/**
 * Release a string previously obtained from nats_intern_acquire.
 * Decrements the refcount; when it reaches zero the entry is
 * removed from its bucket chain and shm_free'd.  Safe to call
 * with NULL (no-op).
 *
 * The pointer must be the exact value returned by acquire --
 * pointer-arithmetic on the inline string (e.g., passing
 * `p + 1` from a string offset) will fail because the
 * container_of conversion needs the original head pointer.
 * A double-release (node no longer in its chain) is detected and
 * degrades to a logged no-op rather than a double-free.
 *
 * @param p Pointer from nats_intern_acquire()/nats_intern_retain(),
 *          or NULL.
 *
 * @return none.
 *
 * Locking: the entry's shard lock (cached hash, no re-hash) across the
 * chain walk; the shm_free happens after the lock is dropped.
 * Context: any process that has mapped SHM.
 */
void nats_intern_release(char *p);

/**
 * Bump the refcount of a pointer ALREADY obtained from acquire,
 * without re-hashing by content.  Used to take an extra reference on
 * an interned key the caller already holds (e.g. snapshotting an index
 * entry's key set under the index lock before releasing it), so the
 * string stays alive after the lock is dropped.  Balanced by a later
 * nats_intern_release().
 *
 * @param p Pointer from a prior acquire (exact value -- same
 *          pointer-arithmetic restriction as nats_intern_release()),
 *          or NULL.
 *
 * @return @p unchanged, for call-site convenience (still owned by the
 *         intern table); NULL-safe.
 *
 * Locking: the entry's shard lock around the refcount bump.
 * Context: any process that has mapped SHM.
 */
char *nats_intern_retain(char *p);

/**
 * Diagnostic: number of unique entries currently held in the
 * table.  Used by structural tests; not on the hot path.
 *
 * @return Live entry count, 0 if the table is uninitialised.
 *
 * Locking: none -- unlocked advisory read of the counter; the value
 * may be stale under concurrent acquire/release.
 * Context: any process that has mapped SHM.
 */
int  nats_intern_size(void);

/**
 * Diagnostic: current refcount of an interned pointer.
 * Used by tests to assert refcount balance; not on the hot path.
 *
 * @param p Pointer from a prior acquire (exact value), or NULL.
 *
 * @return The entry's refcount, 0 if @p is NULL or the table is
 *         uninitialised.
 *
 * Locking: the entry's shard lock around the read.
 * Context: any process that has mapped SHM.
 */
int  nats_intern_refcount(const char *p);

#endif /* CACHEDB_NATS_INTERN_H */
