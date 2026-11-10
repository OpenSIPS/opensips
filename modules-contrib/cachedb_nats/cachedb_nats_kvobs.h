/*
 * Copyright (C) 2026 OpenSIPS Solutions
 * Copyright (C) 2026 Norm Brandinger <n.brandinger@gmail.com>
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
 * cachedb_nats_kvobs.h — generic JetStream/KV introspection MI.
 * See cachedb_nats_kvobs.c for the command surface; the design
 * invariants (cachedb_nats_reg.h) apply: read-only, bind-never-create,
 * fail-loudly filters, hard-capped pagination.
 */

#ifndef CACHEDB_NATS_KVOBS_H
#define CACHEDB_NATS_KVOBS_H

#include "../../mi/mi.h"

#define KVOBS_LIMIT_DEFAULT 50
#define KVOBS_LIMIT_CAP     200   /* MI datagram size bound */

struct kvobs_filter {
	char bucket[128];
	char key_glob[256];
	char name_glob[256];
	int  kv_only;
	int  detail;
	long limit;
	long offset;
	int  format;                /* enum fmt_kind, default FMT_JSON */
	int  eol_lf;
	int  header;
};

/* pure helpers, unit-locked in test/test_kvobs_filter.c */

/**
 * Parse the filter string (';'-separated key=value: bucket key
 * name kv detail limit offset header, plus the format/eol keys).
 *
 * @param s    filter bytes (empty input yields pure defaults).
 * @param len  filter length.
 * @param f    [out] caller-owned struct, fully reset first; string
 *             values are COPIED into its fixed arrays (nothing borrowed
 *             from @s afterwards); limit clamped to KVOBS_LIMIT_CAP.
 * @return 0 ok, -1 refused (unknown key, bad value, oversize token).
 *
 * Pure function on caller memory: no allocation, no logging, no
 * locking; any process context (MI process in production).
 */
int cdbn_kvobs_filter_parse(const char *s, int len, struct kvobs_filter *f);

/**
 * Derive the KV bucket name from a backing-stream name ("KV_<bucket>").
 *
 * @param stream  stream name bytes.
 * @param len     name length.
 * @param bucket  [out] bucket-name start — BORROWED, points INTO
 *                @stream (nothing allocated, nothing to free).
 * @param blen    [out] bucket-name length.
 * @return 0 when @stream carries the "KV_" prefix; -1 otherwise
 *         (*bucket NULL, *blen 0).
 *
 * Pure: no allocation, no locking; any process context.
 */
int cdbn_kvobs_bucket_of_stream(const char *stream, int len,
	const char **bucket, int *blen);

/* MI handlers (registered in cachedb_nats.c) --------------------------
 *
 * Common contract: run in the MI process handling the command; block
 * for the broker round trips they issue over the per-process NATS pool
 * connection (lazily opened on first use).  Read-only by construction:
 * buckets are BOUND (js_KeyValue), never created.  Internal scratch is
 * libc heap, released before returning; the returned mi_response_t
 * (result or init_mi_error) is owned and freed by the MI framework
 * after sending.  @async_hdl is unused (synchronous).  No locking. */

/**
 * nats_stream_list [filter=...] — every stream on the server (name
 * glob; kv=1 restricts to KV backing streams, with the bucket name
 * derived), sorted by name, paginated.
 *
 * @param params     MI params: optional string `filter`
 *                   (cdbn_kvobs_filter_parse grammar).
 * @param async_hdl  unused.
 * @return MI result object; error responses: 400 bad filter, 503 NATS
 *         unavailable / listing failed, 500 OOM.
 */
mi_response_t *mi_nats_stream_list(const mi_params_t *params,
	struct mi_handler *async_hdl);

/**
 * nats_stream_info stream=<name> [format=...] — one stream's config +
 * state: the operator check for the TTL preconditions (allow_msg_ttl,
 * max_msgs_per_subject, marker TTL, max_age).
 *
 * @param params     MI params: required string `stream`, optional
 *                   `format`.
 * @param async_hdl  unused.
 * @return MI result object; error responses: 400 missing/bad stream or
 *         format, 404 no such stream, 503 NATS unavailable, 500 OOM.
 */
mi_response_t *mi_nats_stream_info(const mi_params_t *params,
	struct mi_handler *async_hdl);

/**
 * nats_kv_keys [filter=...] — the LIVE keys of a bucket (delete/purge
 * markers never listed), key glob + pagination; detail=1 adds
 * revision/created/size for the returned page (one kvStore_Get per
 * RETURNED key, bounded by the 200 limit cap).  The bucket is bound
 * read-only and its handle destroyed before returning; a typo'd bucket
 * name errors instead of materializing a stream.
 *
 * @param params     MI params: optional string `filter` (bucket
 *                   defaults to the module's kv_bucket).
 * @param async_hdl  unused.
 * @return MI result object; error responses: 400 bad filter, 404 no
 *         such bucket, 503 NATS unavailable / listing failed, 500 OOM.
 */
mi_response_t *mi_nats_kv_keys(const mi_params_t *params,
	struct mi_handler *async_hdl);

#endif /* CACHEDB_NATS_KVOBS_H */
