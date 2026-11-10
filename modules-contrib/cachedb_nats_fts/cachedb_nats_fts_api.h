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

/*
 * cachedb_nats_fts_api.h — the binds API cachedb_nats uses to reach the
 * optional FTS/search-index module.  When the module is
 * not loaded every hook stays NULL and cachedb_nats runs PK-only: the
 * flagship usrloc path never touches any of this.
 */

#ifndef CACHEDB_NATS_FTS_API_H
#define CACHEDB_NATS_FTS_API_H

#include "../../cachedb/cachedb.h"

/* identical to nats.h's typedef; C11 permits the redefinition */
typedef struct __kvStore kvStore;

typedef struct cdbn_fts_api {
	/* full builds over the bucket (cachedb owns the KV handle + the
	 * doc-key prefix; the FTS module owns the index storage) */

	/**
	 * Initial index build (impl: nats_json_index_build): walk every KV
	 * key under @prefix, read each JSON doc and index its top-level
	 * fields into the module's SHM index.
	 *
	 * @param kv     Borrowed KV handle (nats_pool_get_kv); not stored
	 *               past the call.
	 * @param prefix Doc-key prefix filter (NUL-terminated; NULL/"" =
	 *               all keys).
	 * @return 0 on success, -1 on error.
	 *
	 * Allocation: index entries + interned doc keys in SHM, owned by
	 * the FTS module (freed on remove/destroy); nothing returned to
	 * the caller.  Locking: per-shard SHM locks taken internally.
	 * Context: called once by cachedb_nats from child_init rank 1,
	 * after the index was allocated in mod_init (pre-fork).
	 */
	int (*build)(kvStore *kv, const char *prefix);

	/**
	 * Clear the whole index and re-run build (impl:
	 * nats_json_index_rebuild), for when the index may be stale after
	 * missed watcher updates.
	 *
	 * @param kv     Borrowed (fresh, post-reconnect) KV handle.
	 * @param prefix Same semantics as build.
	 * @return 0 on success, -1 on error.
	 *
	 * Allocation: as build (SHM, module-owned).  Locking: the clear
	 * acquires all shard locks in index order, then per-shard locks
	 * during the rebuild.  Context: cachedb_nats's dedicated watcher
	 * process (post-reconnect) and its dedicated reaper process
	 * (periodic index resync); not called from SIP workers.
	 */
	int (*rebuild)(kvStore *kv, const char *prefix);

	/* write-side index maintenance */

	/**
	 * Index one JSON document (impl: nats_json_index_add).  Idempotent
	 * for an already-indexed key (duplicate doc keys are de-duped per
	 * entry).
	 *
	 * @param key      Doc key bytes; borrowed -- copied into the SHM
	 *                 intern table as needed.  Need NOT be
	 *                 NUL-terminated (exactly @key_len bytes
	 *                 are read; no strlen on the hot path).
	 * @param key_len  Length of @key in bytes (> 0).
	 * @param json_str Raw JSON bytes; borrowed, parsed unlocked.
	 * @param json_len Length of @json_str in bytes.
	 * @return 0 on success, -1 on parse error / SHM exhaustion /
	 *         uninitialised index.
	 *
	 * Allocation: SHM (entries + interned keys), module-owned.
	 * Locking: per-shard SHM locks taken internally, one shard at a
	 * time.  Context: cachedb_nats's dedicated watcher process (KV
	 * watch loop) and SIP workers on the update() write path.
	 */
	int  (*add)(const char *key, int key_len,
	            const char *json_str, int json_len);

	/**
	 * Remove a document from the index by walking every bucket (impl:
	 * nats_json_index_remove).  Idempotent: an unknown key is success.
	 *
	 * @param key     Doc key bytes; borrowed.  Need NOT be
	 *                NUL-terminated.
	 * @param key_len Length of @key in bytes (> 0).
	 * @return 0 on success or key not found, -1 on error.
	 *
	 * Allocation: frees SHM entries/interned refs as they empty.
	 * Locking: per-shard SHM locks, one shard at a time.  Context:
	 * watcher process (delete/expiry fallback when remove_by_revmap
	 * misses) and SIP workers (query-path stale-index self-heal).
	 */
	int  (*remove)(const char *key, int key_len);

	/**
	 * Fast delete-by-key via the doc-key -> field:value reverse map
	 * (impl: nats_json_index_remove_by_revmap): O(fields) instead of a
	 * full bucket walk.
	 *
	 * @param key     Doc key bytes; borrowed.  Need NOT be
	 *                NUL-terminated.
	 * @param key_len Length of @key in bytes (> 0).
	 * @return 0 on a hit (key removed), -1 on a miss -- the caller
	 *         MUST fall back to remove(key) on -1.
	 *
	 * Allocation: frees SHM entries/interned refs as they empty.
	 * Locking: reverse-map shard lock, then forward-index shard locks
	 * (never held simultaneously).  Context: the watcher process's
	 * delete/expiry path.
	 */
	int  (*remove_by_revmap)(const char *key, int key_len);

	/**
	 * Targeted removal given the document's OLD JSON (impl:
	 * nats_json_index_remove_fields): visits only the (field:value)
	 * entries the key was indexed under, O(F) work.  No-op (success)
	 * when @json is NULL/empty.
	 *
	 * @param key      Doc key bytes; borrowed.  Need NOT be
	 *                 NUL-terminated.
	 * @param key_len  Length of @key in bytes (> 0).
	 * @param json Pre-write JSON the key was indexed against; borrowed
	 *             and must stay live across the call.
	 * @param len  Length of @json in bytes.
	 * @return 0 on success, -1 on parse error.
	 *
	 * Locking: one shard at a time per field.  Context: SIP workers on
	 * the update() path (after a successful CAS write, paired with
	 * add() of the new JSON).
	 */
	int  (*remove_fields)(const char *key, int key_len,
	                      const char *json, int len);

	/**
	 * Live count of unique doc keys in the forward index (impl:
	 * nats_json_index_count), for observability and tests.
	 *
	 * @return num_documents (>= 0), or -1 if the index is not
	 *         initialised.
	 *
	 * Allocation: none.  Locking: none (relaxed atomic load).
	 * Context: any process or thread.
	 */
	int  (*count)(void);

	/* query side: non-PK filter -> retained doc-key snapshot.
	 * Returned keys are interned refs; hand them back via
	 * release_keyset() at every cleanup site. */

	/**
	 * Resolve an AND-chain of equality filters against the index
	 * (impl: fts_query_match_keys).  Only CDB_OP_EQ string filters are
	 * supported; non-string filters are skipped.
	 *
	 * @param filter    cdb_filter_t chain (AND logic); borrowed.
	 * @param out_keys  Out: libc-malloc'd array of interned SHM key
	 *                  pointers, each carrying one query reference.
	 *                  The caller owns the SET and MUST hand it back
	 *                  via release_keyset() exactly once at every
	 *                  cleanup site (that releases the refs and
	 *                  free()s the array).  May be NULL when
	 *                  *out_count == 0.
	 * @param out_count Out: number of surviving keys, capped at the
	 *                  fts_max_results modparam.
	 * @return 0 on success (an empty intersection is success with
	 *         *out_count == 0), -1 on unsupported operator or OOM
	 *         (nothing left for the caller to release).
	 *
	 * Locking: one shard lock per filter, dropped before the merge
	 * work; concurrent queries on different shards run in parallel.
	 * Context: SIP workers (and any process mapping SHM) via
	 * cachedb_nats's query() callback.
	 */
	int  (*query_match_keys)(const cdb_filter_t *filter,
	                         char ***out_keys, int *out_count);

	/**
	 * Release a keyset returned by query_match_keys (impl:
	 * fts_release_keyset): drops one intern reference per key and
	 * libc-free()s the array itself.  NULL-safe.
	 *
	 * @param keys  The exact array from query_match_keys (or NULL).
	 * @param count The matching *out_count.
	 *
	 * Locking: intern shard locks taken internally, one per key.
	 * Context: same callers as query_match_keys.
	 */
	void (*release_keyset)(char **keys, int count);

	/**
	 * Single-key resolve for update() (impl: fts_resolve_key): copy
	 * the first indexed doc key matching field=val into @out.
	 *
	 * @param field   Filter field name; borrowed.
	 * @param val     Filter value; borrowed.
	 * @param out     Caller-owned buffer (pkg-independent stack buffer
	 *                at the in-tree call site); NUL-terminated on hit.
	 * @param out_len Capacity of @out in bytes.
	 * @return 1 = hit (@out filled), 0 = miss (or index not
	 *         initialised), -1 = key longer than @out_len.
	 *
	 * Allocation: none; writes only into @out.  Locking: the entry's
	 * shard lock is held over lookup + copy.  Context: SIP workers on
	 * cachedb_nats's update() path.
	 */
	int  (*resolve_key)(const str *field, const str *val,
	                    char *out, int out_len);
} cdbn_fts_api_t;

/**
 * Prototype of the module's exported "cdbn_fts_bind" command, which
 * cachedb_nats resolves via find_export() and calls to populate @api
 * with the FTS module's hooks (all static functions -- nothing is
 * allocated, nothing to free; the pointers stay valid for the process
 * lifetime).
 *
 * @param api Caller-owned struct to fill.
 * @return 0 on success (@api fully populated), -1 on NULL @api.
 *
 * Locking: none.  Context: cachedb_nats's mod_init (pre-fork,
 * init_services), after cachedb_nats_fts's own mod_init allocated the
 * SHM index + intern table.  Not for post-fork use.
 */
typedef int (*cdbn_fts_bind_f)(cdbn_fts_api_t *api);

#endif /* CACHEDB_NATS_FTS_API_H */
