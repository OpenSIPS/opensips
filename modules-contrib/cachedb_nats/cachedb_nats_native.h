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
 * cachedb_nats_native.h — NATS-Native Script Functions and Advanced Operations
 *
 * Module:  cachedb_nats
 *
 * Declares OpenSIPS script-callable functions that expose NATS-native
 * capabilities beyond the standard cachedb API:
 *
 *   - Request-reply messaging (nats_request)
 *   - KV history retrieval (nats_kv_history)
 *   - Raw query implementation (keys listing, purge)
 *   - JSON document map operations (get/set/remove fields)
 *
 * These functions are registered via the cmds[] array in the module
 * export and are available in opensips.cfg routing scripts.
 */

#ifndef CACHEDB_NATS_NATIVE_H
#define CACHEDB_NATS_NATIVE_H

#include "../../sr_module.h"
#include "../../cachedb/cachedb.h"
#include "../../pvar.h"
#include "../../mi/mi.h"

/*
 * Script function: nats_kv_history(key, $result)
 *
 * Retrieves the revision history for a KV key and stores it as a JSON
 * array string in the given pseudo-variable.  Each array element contains
 * the value, revision number, and timestamp.  Requires kv_history > 1
 * on the bucket configuration.
 *
 * @param msg         SIP message context (provided by OpenSIPS).
 * @param key         KV key to retrieve history for.
 * @param result_var  Pseudo-variable spec to store the JSON history array.
 * @return            1 on success, -1 on error or key not found.
 *
 * Thread safety: Safe from OpenSIPS worker process context.
 */
int w_nats_kv_history(struct sip_msg *msg, str *key, pv_spec_t *result_var);

/*
 * Script function: nats_kv_get(bucket, key, $value, [$revision])
 *
 * Reads a KV entry and stores the value in value_var. If rev_var is
 * provided, also stores the revision number (uint64 as int).
 *
 * @return 1 success, -1 error, -2 not found.
 */
int w_nats_kv_get(struct sip_msg *msg, str *bucket, str *key,
                  pv_spec_t *value_var, pv_spec_t *rev_var);

/*
 * Script function: nats_kv_put(bucket, key, value)
 *
 * Unconditional write (overwrites regardless of current revision).
 *
 * @return 1 success, -1 error.
 */
int w_nats_kv_put(struct sip_msg *msg, str *bucket, str *key, str *value);

/*
 * Script function: nats_kv_update(bucket, key, value, expected_revision)
 *
 * Conditional write (CAS). Only succeeds if current revision matches
 * expected_revision. Returns -2 on revision mismatch.
 *
 * @return 1 success, -1 error, -2 revision mismatch.
 */
int w_nats_kv_update(struct sip_msg *msg, str *bucket, str *key,
                     str *value, int *expected_rev);

/*
 * Script function: nats_kv_delete(bucket, key)
 *
 * Delete a key (creates a delete marker, revision incremented).
 *
 * @return 1 success, -1 error.
 */
int w_nats_kv_delete(struct sip_msg *msg, str *bucket, str *key);

/*
 * Script function: nats_kv_revision(bucket, key, $revision)
 *
 * Lightweight read of only the current revision number.
 *
 * @return 1 success, -1 error, -2 not found.
 */
int w_nats_kv_revision(struct sip_msg *msg, str *bucket, str *key,
                       pv_spec_t *rev_var);

/*
 * CacheDB raw_query implementation for NATS KV.
 *
 * Parses the query string for supported commands:
 *   - "KV KEYS"          — list all keys in the bucket
 *   - "KV PURGE <key>"   — permanently remove a key and its history
 *   - "KV BUCKET INFO"   — return bucket statistics
 *
 * @param con             cachedb connection.
 * @param attr            Raw query command string.
 * @param reply           Output: array of result entries (pkg_malloc'd;
 *                        caller must free via cachedb framework).
 * @param expected_kv_no  Expected columns per entry (typically 1 for keys).
 * @param reply_no        Output: number of entries returned.
 * @return                0 on success, -1 on error or unknown command.
 *
 * Thread safety: Safe from OpenSIPS worker process context.
 */
/*
 * The cachedb engine entry points (nats_cache_raw_query_impl,
 * nats_cache_map_get/set/remove) are forward-declared in the
 * module's primary header (cachedb_nats.h).  Re-declaring them here
 * triggers gcc's -Wredundant-decls under -Werror in CI, so the
 * canonical declarations live in cachedb_nats.h and any consumer
 * that needs them includes that header instead.
 */

#endif /* CACHEDB_NATS_NATIVE_H */
