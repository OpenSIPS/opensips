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
 * cachedb_nats_json.h — the JSON document layer's public API (query /
 * update entry points and the reaper's row projections).  The FTS
 * index declarations moved to the optional cachedb_nats_fts module
 * (see cachedb_nats_fts/fts_index.h).
 */

#ifndef CACHEDB_NATS_JSON_H
#define CACHEDB_NATS_JSON_H

#include <stdint.h>
#include <time.h>
#include "../../cachedb/cachedb.h"

/*
 * CacheDB query callback — search the index for matching documents.
 *
 * Translates cdb_filter_t conditions into index lookups.  For equality
 * filters on indexed fields, performs O(1) hash lookup per condition
 * and intersects the resulting key sets.  Fetches full documents for
 * matched keys and populates the result set.
 *
 * @param con     cachedb connection (used to fetch document values).
 * @param filter  Chain of filter conditions (field op value).
 * @param res     Output: result set with matching document rows.
 * @return        0 on success (res may have 0 rows), -1 on error.
 *
 * Thread safety: Acquires the per-shard SHM locks for the lookup phase.
 *                KV fetches happen outside the locks.
 */
int nats_cache_query(cachedb_con *con, const cdb_filter_t *filter,
                     cdb_res_t *res);

/*
 * CacheDB update callback — modify fields in matching JSON documents.
 *
 * Finds documents matching row_filter (via index lookup), reads each
 * document, merges the provided field-value pairs, writes back to KV,
 * and updates the index to reflect the new field values.
 *
 * @param con         cachedb connection.
 * @param row_filter  Filter to identify documents to update.
 * @param pairs       Dictionary of field-value pairs to set.
 * @return            0 on success, -1 on error.
 *
 * Thread safety: Acquires the per-shard SHM locks for lookup; KV
 *                operations happen outside the locks.
 */
int nats_cache_update(cachedb_con *con, const cdb_filter_t *row_filter,
                      const cdb_dict_t *pairs);


/* Reaper — pure, broker-less per-row decisions, defined in the
 * rowmeta TU; exposed here so the reaper timer host in cachedb_nats.c can drive
 * them over each stored row before any CAS write/delete.
 *   cdbn_reap_project_survivors(): drop DUE contacts, recompute row_exp, return a
 *     fresh document (caller pkg_frees); *n_survivors = survivor count (0 => the row
 *     is fully due, CAS-delete the key; -1 => not a usrloc row, skip).  NULL on
 *     malformed/OOM.
 *   cdbn_reap_row_due_json(): cheap due-gate over the stored row_exp — 1 due, 0 not
 *     due/permanent, -1 row_exp absent (legacy: treat as due). */
char *cdbn_reap_project_survivors(const char *json, int len, time_t now, int grace,
	int *n_survivors, int *out_len,
	int64_t *out_row_exp, int *out_all_same);
int cdbn_reap_row_due_json(const char *json, int len, time_t now, int grace);

#endif /* CACHEDB_NATS_JSON_H */
