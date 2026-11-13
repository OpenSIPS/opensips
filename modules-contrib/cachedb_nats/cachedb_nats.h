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
 *
 */

/*
 * cachedb_nats.h — CacheDB Backend for NATS JetStream KV
 *
 * Module:  cachedb_nats
 *
 * Declares the cachedb connection wrapper and the full set of cachedb
 * API functions that map OpenSIPS cache operations onto NATS JetStream
 * KV store operations.
 *
 * Key types:
 *   nats_cachedb_con  — per-connection state wrapping a NATS KV handle
 *
 * Key functions:
 *   nats_con_refresh_kv()   — epoch-based KV handle refresh
 *   nats_cachedb_init()     — cachedb init callback
 *   nats_cachedb_destroy()  — cachedb destroy callback
 *   nats_cache_get/set/remove/add/sub/get_counter — scalar operations
 *   nats_cache_raw_query_impl — raw query (keys/purge)
 *   nats_cache_map_get/set/remove — JSON document map operations
 */

#ifndef CACHEDB_NATS_H
#define CACHEDB_NATS_H

#include <nats/nats.h>
#include "../nats/nats_bind.h"
#include "../nats/nats_epoch.h"
#include "../../cachedb/cachedb.h"
#include "../cachedb_nats_fts/cachedb_nats_fts_api.h"

/* optional FTS module binds (defined in cachedb_nats.c).
 * cdbn_fts_on == 0 -> hooks are NULL: primary-key queries go to the KV,
 * any other filter to a bucket scan (query_scan). */
extern cdbn_fts_api_t cdbn_fts;
extern int cdbn_fts_on;

/* Runs the startup checks skipped by a degraded start (NATS unavailable
 * at startup), once NATS is up: the bucket checks and the search index
 * build.  Called by the reaper process on each pass of its loop; a no-op
 * once done.  Defined in cachedb_nats.c. */
void nats_cdb_deferred_boot_checks(void);

/*
 * CacheDB connection wrapper for NATS JetStream KV.
 *
 * The first three fields (id, ref, next) form the fixed cachedb header
 * required by the OpenSIPS cachedb pooling framework.  They must appear
 * first and in this exact order.  The NATS-specific fields follow.
 */
typedef struct _nats_cachedb_con {
    /* ------ Fixed cachedb header (must be first, exact order) ------ */
    struct cachedb_id *id;              /* Parsed cachedb URL (scheme,
                                         * host, port, database). Owned by
                                         * the cachedb framework. */
    unsigned int ref;                   /* Reference count, managed by the
                                         * cachedb connection pool. */
    struct cachedb_pool_con_t *next;    /* Linked-list pointer for the
                                         * cachedb connection pool. */
    /* ------ NATS-specific fields ------ */
    kvStore *kv;                        /* NATS JetStream KV store handle.
                                         * Obtained from nats_pool_get_kv()
                                         * and cached here.  Becomes stale
                                         * after a reconnection. */
    char *bucket_name;                  /* KV bucket name string (heap
                                         * allocated, freed on destroy).
                                         * Corresponds to the "database"
                                         * portion of the cachedb URL. */
    nats_epoch_t kv_epoch;              /* epoch tag of the kv
                                         * handle (modules-contrib/nats/nats_epoch.h);
                                         * see nats_con_refresh_kv(). */
} nats_cachedb_con;

/*
 * Refresh the KV store handle if a NATS reconnection has occurred.
 *
 * Compares the connection's saved kv_epoch against the pool's current
 * reconnect epoch.  If they differ, the old KV handle is stale (the
 * underlying JetStream subscription was lost during reconnect), so this
 * function obtains a fresh handle from nats_pool_get_kv().
 *
 * Call this at the top of every cachedb operation (get, set, remove, etc.)
 * before using ncon->kv.  This is the primary mechanism for transparent
 * reconnection recovery in the cachedb layer.
 *
 * @param ncon  Pointer to the cachedb connection wrapper.
 * @return      0 on success (handle is valid), -1 if refresh failed
 *              (KV bucket could not be re-opened).
 *
 * Thread safety: Safe from OpenSIPS worker process context.  Each
 *                process has its own nats_cachedb_con instance.
 */
int nats_con_refresh_kv(nats_cachedb_con *ncon);

/* One shared, rate-limited (30s/process) WARN for the module's
 * KV-op disconnect fast-fails; the per-call lines stay DBG.  @op names
 * the failing operation class for the log line. */
void nats_cdb_disconnected_warn(const char *op);

/*
 * CacheDB init callback — called by the cachedb framework when a
 * "nats" cachedb URL is first used.
 *
 * Parses the URL, allocates a nats_cachedb_con, obtains the KV store
 * handle from the shared connection pool, and returns the wrapped
 * cachedb_con to the framework.
 *
 * @param url   Parsed cachedb URL string (e.g., "nats:///mybucket").
 * @return      cachedb_con pointer on success, NULL on error.
 */
cachedb_con* nats_cachedb_init(str *url);

/*
 * CacheDB destroy callback — releases the NATS cachedb connection.
 *
 * Frees the bucket_name string and the wrapper struct.  Does not close
 * the underlying NATS connection (that is managed by the shared pool).
 *
 * @param con   cachedb_con pointer to destroy.
 */
void nats_cachedb_destroy(cachedb_con *con);

/*
 * Get a value from the KV store by key.
 *
 * @param con     cachedb connection.
 * @param attr    Key string.
 * @param val     Output: value string (pkg_malloc'd by this function;
 *                caller must pkg_free).
 * @return        0 on success, -2 if key not found, -1 on error.
 */
int nats_cache_get(cachedb_con *con, str *attr, str *val);

/*
 * Store a key-value pair in the KV store.
 *
 * @param con      cachedb connection.
 * @param attr     Key string.
 * @param val      Value string to store.
 * @param expires  TTL in seconds (0 = use bucket default).
 *                 Note: NATS KV TTL is bucket-wide; per-key TTL is
 *                 not supported.  This parameter is accepted for API
 *                 compatibility but only takes effect at bucket creation.
 * @return         0 on success, -1 on error.
 */
int nats_cache_set(cachedb_con *con, str *attr, str *val, int expires);

/*
 * Remove a key from the KV store (soft delete / purge).
 *
 * @param con     cachedb connection.
 * @param attr    Key string.
 * @return        0 on success, -1 on error.
 */
int nats_cache_remove(cachedb_con *con, str *attr);

/*
 * _remove "unsupported" stub.
 *
 * The cachedb_funcs._remove slot (delete a federation-metadata entry by named
 * key) is only exercised in CM_FEDERATION_CACHEDB metadata maintenance, which
 * cachedb_nats does not implement.  usrloc full-sharing-cachedb never calls it.
 * It is registered NON-NULL solely so a wrong-mode/misconfigured deployment that
 * reaches it fails LOUDLY (-1 + LM_ERR) instead of dispatching through a NULL
 * function pointer and crashing.  The real federation impl (G4) is a follow-up.
 *
 * @param con   cachedb connection (ignored — never dereferenced).
 * @param attr  Value key (ignored).
 * @param key   Column/key name (ignored).
 * @return      always -1 (operation unsupported).
 */
int nats_cache_remove_unsupported(cachedb_con *con, str *attr, const str *key);

/*
 * Atomic add to a counter stored as an integer value.
 *
 * Uses compare-and-swap (CAS) with up to the nats_cas_retries modparam
 * (default 10) attempts to handle concurrent updates.
 *
 * @param con      cachedb connection.
 * @param attr     Key string.
 * @param val      Value to add (can be negative for subtraction).
 * @param expires  TTL in seconds (see nats_cache_set note).
 * @param new_val  Output: the resulting counter value after addition.
 * @return         0 on success, -1 on error (including CAS exhaustion).
 */
int nats_cache_add(cachedb_con *con, str *attr, int val, int expires, int *new_val);

/*
 * Atomic subtract from a counter stored as an integer value.
 *
 * Equivalent to nats_cache_add() with a negated value.
 *
 * @param con      cachedb connection.
 * @param attr     Key string.
 * @param val      Value to subtract.
 * @param expires  TTL in seconds (see nats_cache_set note).
 * @param new_val  Output: the resulting counter value after subtraction.
 * @return         0 on success, -1 on error.
 */
int nats_cache_sub(cachedb_con *con, str *attr, int val, int expires, int *new_val);

/*
 * Read the current value of an integer counter.
 *
 * @param con     cachedb connection.
 * @param attr    Key string.
 * @param val     Output: current counter value.
 * @return        0 on success, -2 if key not found, -1 on error.
 */
int nats_cache_get_counter(cachedb_con *con, str *attr, int *val);

/*
 * Execute a raw query against the KV store.
 *
 * Supports commands "KV KEYS", "KV PURGE <key>", and "KV BUCKET INFO".
 * Implemented in cachedb_nats_native.c.
 *
 * @param con             cachedb connection.
 * @param attr            Raw query string.
 * @param reply           Output: array of result entries (caller frees).
 * @param expected_kv_no  Expected number of key-value pairs per entry.
 * @param reply_no        Output: number of entries returned.
 * @return                0 on success, -1 on error.
 */
int nats_cache_raw_query_impl(cachedb_con *con, str *attr, cdb_raw_entry ***reply, int expected_kv_no, int *reply_no);

/*
 * Retrieve all fields of a map from the KV store.
 *
 * Lists the composite keys enc(key).enc(field) via a server-side filter
 * and appends one result row per field (each row holds a single
 * field -> value pair); no JSON document is parsed.
 * Implemented in cachedb_nats_native.c.
 *
 * @param con   cachedb connection.
 * @param key   Document key.
 * @param res   Output: result set with parsed columns.
 * @return      0 on success, -2 if not found, -1 on error.
 */
int nats_cache_map_get(cachedb_con *con, const str *key, cdb_res_t *res);

/*
 * Set fields of a map in the KV store.
 *
 * Writes each provided key-value pair unconditionally as a separate KV
 * entry under a composed, hex-escaped subject enc(key).enc(field)
 * (kvStore_PutString — no read/merge/CAS).
 * Implemented in cachedb_nats_native.c.
 *
 * @param con     cachedb connection.
 * @param key     Document key.
 * @param subkey  Sub-key filter (unused, pass NULL).
 * @param pairs   Dictionary of field-value pairs to set.
 * @return        0 on success, -1 on error.
 */
int nats_cache_map_set(cachedb_con *con, const str *key, const str *subkey,
                       const cdb_dict_t *pairs);

/*
 * Remove fields from a JSON document stored in the KV store.
 *
 * Reads the existing document, removes matching fields, and writes back.
 * If no fields remain, deletes the key entirely.
 * Implemented in cachedb_nats_native.c.
 *
 * @param con     cachedb connection.
 * @param key     Document key.
 * @param subkey  Field name to remove (NULL removes entire document).
 * @return        0 on success, -1 on error.
 */
int nats_cache_map_remove(cachedb_con *con, const str *key, const str *subkey);

#endif /* CACHEDB_NATS_H */
