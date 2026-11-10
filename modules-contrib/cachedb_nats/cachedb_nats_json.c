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
 * cachedb_nats_json.c — cachedb query() / update() callbacks
 *
 * Implements the cachedb_con query and update entry points over JSON
 * documents in NATS JetStream KV: AND-filter search via the SHM search
 * index (the cachedb_nats_fts module), result fetch + row materialisation,
 * and the single-pass CAS JSON update (classify pairs, walk the existing
 * document once, merge subkeys, append new fields).
 *
 * The escape/sink/serializer helpers live in cachedb_nats_json_ser.c and the
 * cross-TU private declarations in cachedb_nats_json_internal.h.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <pthread.h>

#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../cachedb/cachedb.h"
#include "../nats/nats_bind.h"
#include "../nats/nats_dl.h"   /* libnats function-pointer table */
#include "../nats/nats_err.h"   /* NATS_ERR_TEXT */
#include "../nats/nats_redact.h"   /* nats_redact_key */

#include "cachedb_nats_json.h"
#include "cachedb_nats.h"
#include "cachedb_nats_stats.h"
#include "cachedb_nats_dbase.h"
#include "cachedb_nats_json_internal.h"
#include "cachedb_nats_expiry.h"
#include "cachedb_nats_query_filter.h"   /* cdbn_doc_matches */
#include "cachedb_nats_reap_enum.h"      /* one value-carrying pass */

/* module parameters (defined in cachedb_nats.c) */
extern char *fts_json_prefix;
extern int   fts_json_prefix_len;   /* cached at mod_init */
extern int   nats_cas_retries;   /* defined in cachedb_nats.c */
extern int   nats_reap_grace;      /* defined in cachedb_nats.c (max-skew S) */
extern int   nats_expired_linger;  /* physical-retention window              */
extern int   nats_max_value_size; /* defined in cachedb_nats.c (value-size cap) */
/* kv_bucket is declared in cachedb_nats_dbase.h (included above) */

/* The index search helpers (qry_lookup, qry_intersect_keys, the retained-key
 * snapshot walk) moved to the optional cachedb_nats_fts module;
 * non-PK filters are served through the cdbn_fts binds. */

/* PK fast path: single is_pk=1 EQ filter -> one kvStore_Get, no index.
 * Returns 0 on success (including not-found = empty result), -1 on
 * error.  See the rationale comment at the call site. */
static int query_pk_fast_path(nats_cachedb_con *ncon,
	const cdb_filter_t *filter, cdb_res_t *res)
{
	kvEntry *entry = NULL;
	natsStatus s;
	cdb_row_t *row;
	char  key_stack[512];
	char *target_key;
	int   key_heap = 0;
	const char *data;
	int data_len;
	int vclass;

	/* Build the target key on the stack (heap only for rare long
	 * keys) -- saves two allocs per usrloc read on the PK fast path. */
	target_key = cdbn_pk_target_key(filter->val.s.s, filter->val.s.len,
		key_stack, sizeof(key_stack), &key_heap);
	if (!target_key) {
		LM_ERR("PK query: target-key build failed (filter '%.*s', "
			"value len %d)\n", /* not PII: field name only */
			filter->key.name.len, filter->key.name.s,
			filter->val.s.len);
		return -1;
	}

	/* reject AoRs that encode to an invalid NATS subject (empty token)
	 * before kvStore_Get -- such a key cannot exist, so a read is just an empty
	 * result (not an error). Validate the encoded AoR portion (past the prefix). */
	{
		int plen = (fts_json_prefix && *fts_json_prefix)
			? fts_json_prefix_len : 0;
		const char *enc = target_key + plen;
		if (cdbn_kv_key_validate(enc, (int)strlen(enc)) < 0) {
			LM_DBG("PK query: AoR encodes to invalid subject "
				"(encoded len %d) -> empty result\n",
				(int)strlen(enc));
			if (key_heap) pkg_free(target_key);
			return 0;   /* empty result, not an error */
		}
	}

	s = nats_dl.kvStore_Get(&entry, ncon->kv, target_key);
	if (s == NATS_NOT_FOUND) {
		if (key_heap) pkg_free(target_key);
		return 0;   /* empty result, not an error */
	}
	if (s != NATS_OK) {
		LM_WARN("PK kvStore_Get failed for '%s': %s\n",
			target_key, NATS_ERR_TEXT(s));
		if (key_heap) pkg_free(target_key);
		return -1;
	}
	data = nats_dl.kvEntry_ValueString(entry);
	data_len = nats_dl.kvEntry_ValueLen(entry);
	/* An EMPTY value is a delete marker (absent);
	 * a non-empty non-object is POISON — a hard integrity error, never masked
	 * as an empty AoR (which usrloc would read as a silent deregistration). */
	vclass = cdbn_value_classify(data, data_len);
	if (vclass == NATS_VAL_POISON) {
		NATS_CDB_STATS_INC(poison_values_rejected);
		LM_ERR("PK read: poison value for key '%s' (len %d, not a JSON "
			"object); failing the lookup rather than masking "
			"corruption as an empty AoR\n", target_key, data_len);
		nats_dl.kvEntry_Destroy(entry);
		if (key_heap) pkg_free(target_key);
		return -1;
	}
	if (vclass == NATS_VAL_OBJECT) {
		row = pkg_malloc(sizeof *row);
		if (!row) {
			LM_ERR("no pkg memory for cdb_row_t\n");
			nats_dl.kvEntry_Destroy(entry);
			if (key_heap) pkg_free(target_key);
			return -1;
		}
		if (cdbn_safe_json_to_dict(data, data_len, &row->dict) != 0) {
			LM_ERR("PK fast path: failed to parse JSON for "
				"'%s'\n", target_key);
			pkg_free(row);
			nats_dl.kvEntry_Destroy(entry);
			if (key_heap) pkg_free(target_key);
			return -1;
		}
		/* Widen each contact's last_mod back to int64
		 * (the shared converter clamped it to int32). */
		cdbn_row_patch_last_mod_int64(data, data_len, &row->dict);
		/* Hand usrloc exactly {contacts, aorhash} —
		 * strip the cachedb_nats-private row_exp/schema_version peers. */
		cdbn_row_strip_private_keys(&row->dict);
		/* Omit expired contacts (read-only) before usrloc
		 * sees them; fail-closed on an unparseable expires. */
		cdbn_row_filter_expired_contacts(&row->dict, time(NULL), nats_reap_grace);
		res->count++;
		list_add_tail(&row->list, &res->rows);
	}
	nats_dl.kvEntry_Destroy(entry);
	if (key_heap) pkg_free(target_key);
	return 0;
}

/* Parse one stored document into a result row (the shape usrloc reads)
 * and append it to @res.  A document that does not parse is skipped.
 * Returns 0, or -1 on out of memory. */
static int query_add_row(const char *key, const char *data, int data_len,
	cdb_res_t *res)
{
	cdb_row_t *row;

	row = pkg_malloc(sizeof *row);
	if (!row) {
		LM_ERR("no more pkg memory for cdb_row_t\n");
		return -1;
	}
	if (cdbn_safe_json_to_dict(data, data_len, &row->dict) != 0) {
		char _rk[NATS_REDACT_KEY_BUF];
		nats_redact_key(key, _rk, sizeof(_rk));
		LM_ERR("failed to parse JSON for key '%s'\n", _rk);
		pkg_free(row);
		return 0;
	}
	/* Widen each contact's last_mod back to int64
	 * (the shared converter clamped it to int32). */
	cdbn_row_patch_last_mod_int64(data, data_len, &row->dict);
	/* Hand usrloc exactly {contacts, aorhash} —
	 * strip the cachedb_nats-private row_exp/schema_version peers. */
	cdbn_row_strip_private_keys(&row->dict);
	/* Omit expired contacts (read-only) before usrloc
	 * sees them; fail-closed on an unparseable expires. */
	cdbn_row_filter_expired_contacts(&row->dict, time(NULL), nats_reap_grace);

	res->count++;
	list_add_tail(&row->list, &res->rows);
	return 0;
}

/* Fetch the matched documents from the KV and append parsed rows to
 * @res.  Per-row fetch/parse problems skip the row (the KV is the
 * truth); only allocation failure is fatal (-1). */
static int query_fetch_rows(nats_cachedb_con *ncon, char **match_keys,
	int result_cnt, cdb_res_t *res)
{
	kvEntry *entry = NULL;
	natsStatus s;
	int i;

	/* Fetch full JSON documents and build result set */
	for (i = 0; i < result_cnt; i++) {
		const char *data;
		int data_len;
		int vclass;

		s = nats_dl.kvStore_Get(&entry, ncon->kv, match_keys[i]);
		if (s == NATS_NOT_FOUND) {
			/* In-memory index said hit, KV said miss. Most common
			 * cause: a sibling OpenSIPS instance deleted the key
			 * between our index build and this fetch. Evict the
			 * stale entry and surface the rate via index_miss_kv;
			 * the truth is the KV, so the result set stays
			 * complete (this row genuinely no longer exists). */
			NATS_CDB_STATS_INC(index_miss_kv);
			/* interned keys carry no length here; cold path. */
			cdbn_fts.remove(match_keys[i],
				(int)strlen(match_keys[i]));
			LM_DBG("evicted stale index entry for '%s'\n",
				match_keys[i]);
			continue;
		}
		if (s != NATS_OK) {
			LM_WARN("kvStore_Get failed for key '%s': %s; row "
				"omitted from query result\n",
				match_keys[i], NATS_ERR_TEXT(s));
			continue;
		}

		data = nats_dl.kvEntry_ValueString(entry);
		data_len = nats_dl.kvEntry_ValueLen(entry);

		/* A non-empty non-object value is
		 * poison — alarm + count rather than silently dropping the row
		 * (which would mask corruption as an empty AoR).  An EMPTY value
		 * is a delete marker: skip it quietly. */
		vclass = cdbn_value_classify(data, data_len);
		if (vclass == NATS_VAL_POISON) {
			NATS_CDB_STATS_INC(poison_values_rejected);
			LM_ERR("read: poison value for key '%s' (len %d, not a "
				"JSON object); row omitted and flagged, not "
				"masked as empty\n", match_keys[i], data_len);
			nats_dl.kvEntry_Destroy(entry);
			entry = NULL;
			continue;
		}
		if (vclass != NATS_VAL_OBJECT) {
			nats_dl.kvEntry_Destroy(entry);
			entry = NULL;
			continue;
		}

		if (query_add_row(match_keys[i], data, data_len, res) < 0) {
			nats_dl.kvEntry_Destroy(entry);
			entry = NULL;
			return -1;
		}

		nats_dl.kvEntry_Destroy(entry);
		entry = NULL;
	}
	return 0;
}

/* rows the search index cannot select -- non-equality or integer
 * filters (usrloc's NAT-pinging "aorhash in [min, max)"), or no
 * cachedb_nats_fts loaded: one value-carrying pass over the documents
 * under fts_json_prefix, each matched against the filters */
struct query_scan_ctx {
	const cdb_filter_t *filter;
	cdb_res_t *res;
	int prefix_len;
};

static int query_scan_entry(kvEntry *e, void *arg)
{
	struct query_scan_ctx *c = arg;
	const char *key = nats_dl.kvEntry_Key(e);
	const char *data;
	int data_len;

	if (!key)
		return 0;
	if (c->prefix_len && strncmp(key, fts_json_prefix, c->prefix_len) != 0)
		return 0;
	data = nats_dl.kvEntry_ValueString(e);
	data_len = nats_dl.kvEntry_ValueLen(e);
	if (cdbn_value_classify(data, data_len) != NATS_VAL_OBJECT)
		return 0;   /* delete marker, or poison: the reaper alarms it */
	if (!cdbn_doc_matches(data, data_len, c->filter))
		return 0;
	return query_add_row(key, data, data_len, c->res);
}

static int query_scan(nats_cachedb_con *ncon, const cdb_filter_t *filter,
	cdb_res_t *res)
{
	static int noticed;
	struct query_scan_ctx c;
	int rc;

	if (!noticed) {
		noticed = 1;
		LM_NOTICE("query: filters the search index cannot answer (e.g. "
			"field '%.*s') are served by one pass over the bucket per "
			"query\n", filter->key.name.len,
			filter->key.name.s);   /* not PII: a field name */
	}
	c.filter = filter;
	c.res = res;
	c.prefix_len = (fts_json_prefix && *fts_json_prefix)
		? fts_json_prefix_len : 0;
	rc = nats_kv_enum_live_values(ncon->kv, NATS_KV_ENUM_NEXT_TIMEOUT_MS,
		query_scan_entry, &c);
	if (rc < 0) {
		LM_ERR("query: bucket scan failed (%d)\n", rc);
		cdb_free_rows(res);
		return -1;
	}
	LM_DBG("query scan: %d document(s) visited, %d matched\n", rc,
		res->count);
	return 0;
}

/* the search index answers AND lists of string equalities only */
static int query_index_can_answer(const cdb_filter_t *filter)
{
	const cdb_filter_t *f;

	for (f = filter; f; f = f->next)
		if (f->op != CDB_OP_EQ || !f->val.is_str)
			return 0;
	return 1;
}

/**
 * nats_cache_query() — cachedb query callback: multi-filter AND search.
 *
 * Iterates the linked list of cdb_filter_t filters.  For each filter
 * (field == value), looks up matching document keys via qry_lookup().  The
 * first filter's key set is copied; subsequent filters are intersected
 * with the running result using qry_intersect_keys(), implementing AND
 * semantics.  After all filters are applied, the matched documents are
 * fetched from the NATS KV store, parsed into cdb_row_t structs via
 * cdbn_safe_json_to_dict() (which guards then calls cdb_json_to_dict()), and
 * appended to @res.
 *
 * The search index (cachedb_nats_fts) answers AND lists of string
 * equalities, capped by its fts_max_results; any other filter (ranges,
 * integer values) -- or every non-PK filter when the index is not loaded
 * -- is served by one pass over the bucket (query_scan), uncapped.
 *
 * Returns 0 on success (even if zero rows match), -1 on error.
 */
int nats_cache_query(cachedb_con *con, const cdb_filter_t *filter,
	cdb_res_t *res)
{
	nats_cachedb_con *ncon;
	char **match_keys = NULL;
	int match_count = 0;
	int result_cnt;

	if (!con || !res) {
		LM_ERR("null parameter\n");
		return -1;
	}

	/* Initialize the result set BEFORE any failure return below:
	 * callers (usrloc's cdb_load_urecord) declare the cdb_res_t on the
	 * stack uninitialized and run cdb_free_rows(res) on ANY query
	 * failure, so res must be walkable even when we fast-fail.
	 * Returning -1 with res uninitialized made a REGISTER arriving
	 * during a broker outage free a garbage list head (SIGSEGV --
	 * caught by sip_e2e case 040_broker_bounce). */
	cdb_res_init(res);

	ncon = (nats_cachedb_con *)con->data;
	if (!ncon) {
		LM_ERR("null NATS connection\n");
		return -1;
	}
	/* Fast-fail when the broker is down and refresh the KV handle after a
	 * reconnect.  Without this the query path blocks the SIP worker for
	 * the full JetStream timeout during an outage and, after a reconnect,
	 * reuses a handle nats_pool_get_kv() has already destroyed (dangling
	 * pointer -> crash in cnats's I/O thread). */
	if (nats_con_refresh_kv(ncon) < 0 || !ncon->kv) {
		LM_DBG("NATS unavailable — query deferred (fast-fail)\n");
		return -1;
	}

	if (!filter) {
		LM_DBG("no filter provided, returning empty result\n");
		return 0;
	}

	/* PK fast path: if the filter is a single is_pk=1 entry (which is
	 * what usrloc's cdb_load_urecord at modules/usrloc/udomain.c:937
	 * always builds — and what most other PK callers build), skip the
	 * in-memory index entirely.  Compute the target_key directly
	 * (mirroring nats_cache_update's PK branch), do one kvStore_Get,
	 * parse, return.  At 100k+ AoR scale this saves the chain walk
	 * inside the per-shard mutex on every read; for a usrloc-only
	 * deployment it makes the entire index optional (the
	 * cachedb_nats_fts module need not be loaded). */
	if (filter && !filter->next && filter->key.is_pk &&
	    filter->val.is_str && filter->op == CDB_OP_EQ)
		return query_pk_fast_path(ncon, filter, res);

	if (!cdbn_fts_on || !query_index_can_answer(filter))
		return query_scan(ncon, filter, res);

	if (cdbn_fts.query_match_keys(filter, &match_keys, &match_count) < 0)
		return -1;

	if (match_count == 0) {
		LM_DBG("no documents match the filter\n");
		cdbn_fts.release_keyset(match_keys, match_count);
		return 0;
	}

	/* result cap applied inside the FTS module (fts_max_results) */
	result_cnt = match_count;

	if (query_fetch_rows(ncon, match_keys, result_cnt, res) < 0) {
		cdbn_fts.release_keyset(match_keys, match_count);
		cdb_free_rows(res);
		return -1;
	}

	LM_DBG("query returned %d rows\n", res->count);
	cdbn_fts.release_keyset(match_keys, match_count);
	return 0;
}

/* ------------------------------------------------------------------ */
/*  Single-pass pair-apply — replaces the per-pair _json_apply_pair    */
/*  loop in nats_cache_update.  Walks the existing doc once, copying  */
/*  through to a sink while applying every cdb_pair_t in @pairs.  Any */
/*  pair whose field is not present in the input is appended at the   */
/*  end of the output object.                                         */
/* ------------------------------------------------------------------ */

/* Classified op for one cdb_pair.  Built once at the start of an apply
 * pass, used at most twice (once when matched against an input field,
 * once when appended as a new field if not consumed). */
typedef struct apply_op {
	const cdb_pair_t *pair;
	int   consumed;        /* matched against an input field */
	char  val_type;        /* S/I/L/N/O — value type for set ops */
	const char *val_str;   /* value bytes for S, O */
	int   val_len;
	int64_t val_int;       /* value for I, L */
	char *owned;           /* malloc'd serialized JSON for CDB_DICT */
} apply_op_t;

static void free_apply_ops(apply_op_t *ops, int n)
{
	int i;
	for (i = 0; i < n; i++)
		pkg_free(ops[i].owned);
	pkg_free(ops);
}

/* Translate cdb_pair_t types into the inline apply_op_t representation.
 * Materializes any CDB_DICT subtree once via the new sink-based
 * cdbn_serialize_cdb_dict (Tier-1 #1).  Returns NULL on alloc / unknown
 * type. */
static apply_op_t *classify_pairs(const cdb_dict_t *pairs, int *out_count)
{
	struct list_head *pos;
	const cdb_pair_t *pair;
	apply_op_t *ops;
	int n = 0, i;

	list_for_each(pos, pairs) n++;
	if (n == 0) {
		*out_count = 0;
		return pkg_malloc(1); /* non-NULL sentinel */
	}

	ops = pkg_malloc((size_t)n * sizeof *ops);
	if (!ops) return NULL;
	memset(ops, 0, (size_t)n * sizeof *ops);

	i = 0;
	list_for_each(pos, pairs) {
		pair = list_entry(pos, const cdb_pair_t, list);
		ops[i].pair = pair;
		if (pair->unset) {
			ops[i].val_type = 'N';
			i++;
			continue;
		}
		switch (pair->val.type) {
		case CDB_STR:
			ops[i].val_type = 'S';
			ops[i].val_str = pair->val.val.st.s;
			ops[i].val_len = pair->val.val.st.len;
			break;
		case CDB_INT32:
			ops[i].val_type = 'I';
			ops[i].val_int = pair->val.val.i32;
			break;
		case CDB_INT64:
			ops[i].val_type = 'L';
			ops[i].val_int = pair->val.val.i64;
			break;
		case CDB_NULL:
			ops[i].val_type = 'N';
			break;
		case CDB_DICT: {
			int slen = 0;
			ops[i].owned = cdbn_serialize_cdb_dict(&pair->val.val.dict,
				&slen);
			if (!ops[i].owned) {
				free_apply_ops(ops, n);
				return NULL;
			}
			ops[i].val_type = 'O';
			ops[i].val_str = ops[i].owned;
			ops[i].val_len = slen;
			break;
		}
		default:
			LM_ERR("unknown cdb pair type %d for field '%.*s'\n",
				pair->val.type, pair->key.name.len,
				pair->key.name.s); /* not PII: field name only */
			free_apply_ops(ops, n);
			return NULL;
		}
		i++;
	}
	*out_count = n;
	return ops;
}

/* Emit a classified op's value into the sink.  Used both for top-level
 * set emissions and for subkey-set emissions inside an inner object. */
static int sink_emit_op_value(json_sink_t *s, const apply_op_t *op)
{
	switch (op->val_type) {
	case 'S':
		return cdbn_sink_emit_string(s, op->val_str, op->val_len);
	case 'I':
	case 'L':
		return cdbn_sink_emit_int(s, op->val_int);
	case 'N':
		return cdbn_sink_write(s, "null", 4);
	case 'O':
		return cdbn_sink_write(s, op->val_str, op->val_len);
	}
	return -1;
}

/* For a given field name, scan @ops in pair-order and pick the
 * effective top-level op:
 *   * the LAST top-level (no-subkey) op wins for a top-level set/unset
 *   * pairs with subkeys are returned via @subkey_count for the
 *     caller's inner-merge phase (their pointers are unchanged)
 *
 * Returns the index of the dominant top-level op, or -1 if no
 * top-level op exists for this field. */
static int find_top_op(apply_op_t *ops, int n,
	const char *fname, int flen, int *subkey_count)
{
	int i, top_idx = -1, sk = 0;
	for (i = 0; i < n; i++) {
		const cdb_pair_t *p = ops[i].pair;
		if (p->key.name.len != flen ||
		    memcmp(p->key.name.s, fname, flen) != 0)
			continue;
		if (p->subkey.len > 0) sk++;
		else                   top_idx = i; /* last top wins */
	}
	*subkey_count = sk;
	return top_idx;
}

/* Merge subkey ops for @fname into the existing JSON object value
 * range [@vstart, @vend).  Walks the inner object once, applying
 * subkey set/unset ops; appends any not-yet-seen subkey ops at the
 * end.  Marks each consumed op in @ops. */
/* Per-subkey body of sink_merge_subkeys, invoked by the shared
 * iterator over the INNER object span. */
struct merge_walk_ctx {
	json_sink_t *s;
	apply_op_t  *ops;
	int          n;
	const char  *fname;
	int          flen;
	int          first;
};

static int merge_subkey_cb(const char *kfield, int kflen,
	const char *kvstart, const char *kvend, void *ud)
{
	struct merge_walk_ctx *c = ud;
	json_sink_t *s = c->s;
	int op_idx = -1, i;

	/* Is there an op for this subkey under @fname? Last wins. */
	for (i = 0; i < c->n; i++) {
		const cdb_pair_t *q = c->ops[i].pair;
		if (q->key.name.len != c->flen ||
		    memcmp(q->key.name.s, c->fname, c->flen) != 0)
			continue;
		if (q->subkey.len != kflen ||
		    memcmp(q->subkey.s, kfield, kflen) != 0)
			continue;
		op_idx = i;
	}
	if (op_idx >= 0) {
		c->ops[op_idx].consumed = 1;
		if (c->ops[op_idx].pair->unset)
			return 0; /* drop this subkey */
		if (!c->first && cdbn_sink_putc(s, ',') < 0) return -1;
		c->first = 0;
		/* kfield is an already-escaped existing name —
		 * copy it through raw, do not re-escape. */
		if (cdbn_sink_emit_raw_string(s, kfield, kflen) < 0)
			return -1;
		if (cdbn_sink_putc(s, ':') < 0) return -1;
		/* Same-subkey collision — keep the
		 * higher cseq (tie-break last_mod).  When the NEW
		 * write is stale versus the existing value, discard
		 * it and keep the existing one.  Only an object value
		 * carrying a cseq engages this; everything else falls
		 * through to last-writer-wins (overwrite), unchanged. */
		if (c->ops[op_idx].val_type == 'O' &&
		    !cdbn_cseq_new_wins(c->ops[op_idx].val_str,
				c->ops[op_idx].val_len,
				kvstart, (int)(kvend - kvstart))) {
			/* stale cseq: keep the existing
			 * higher-cseq value, discard the incoming one
			 * (no rollback). */
			LM_DBG("discarded stale-cseq write; "
				"kept the existing higher-cseq contact\n");
			if (cdbn_sink_write(s, kvstart,
					(int)(kvend - kvstart)) < 0)
				return -1;
		} else if (sink_emit_op_value(s, &c->ops[op_idx]) < 0) {
			return -1;
		}
	} else {
		/* Copy through the existing entry. */
		if (!c->first && cdbn_sink_putc(s, ',') < 0) return -1;
		c->first = 0;
		/* kfield is an already-escaped existing name —
		 * copy it through raw, do not re-escape. */
		if (cdbn_sink_emit_raw_string(s, kfield, kflen) < 0)
			return -1;
		if (cdbn_sink_putc(s, ':') < 0) return -1;
		if (cdbn_sink_write(s, kvstart,
				(int)(kvend - kvstart)) < 0)
			return -1;
	}
	return 0;
}

static int sink_merge_subkeys(json_sink_t *s, const char *vstart,
	const char *vend, apply_op_t *ops, int n,
	const char *fname, int flen)
{
	struct merge_walk_ctx ctx;
	int first;
	int i;

	if (cdbn_sink_putc(s, '{') < 0) return -1;
	ctx.s = s;
	ctx.ops = ops;
	ctx.n = n;
	ctx.fname = fname;
	ctx.flen = flen;
	ctx.first = 1;
	if (cdbn_json_foreach_top_field(vstart, (int)(vend - vstart),
			merge_subkey_cb, &ctx) < 0)
		return -1;
	first = ctx.first;

	/* Append any subkey ops not yet consumed. */
	for (i = 0; i < n; i++) {
		const cdb_pair_t *q = ops[i].pair;
		if (ops[i].consumed) continue;
		if (q->key.name.len != flen ||
		    memcmp(q->key.name.s, fname, flen) != 0)
			continue;
		if (q->subkey.len <= 0) continue;
		ops[i].consumed = 1;
		if (q->unset) continue;
		if (!first && cdbn_sink_putc(s, ',') < 0) return -1;
		first = 0;
		if (cdbn_sink_emit_string(s, q->subkey.s, q->subkey.len) < 0)
			return -1;
		if (cdbn_sink_putc(s, ':') < 0) return -1;
		if (sink_emit_op_value(s, &ops[i]) < 0) return -1;
	}

	if (cdbn_sink_putc(s, '}') < 0) return -1;
	return 0;
}

/* Single-pass apply: copy the input doc through to a fresh malloc'd
 * buffer, applying every cdb_pair_t in @pairs.  Returns NULL on
 * malformed input or any error.  Caller frees with pkg_free(). */
/* Per-field body of apply_pairs_one_pass, invoked by the shared
 * top-level iterator.  Routes each existing field through the
 * matching op (replace / drop / subkey-merge / verbatim copy). */
struct apply_walk_ctx {
	json_sink_t *s;
	apply_op_t  *ops;
	int          n_ops;
	int          first;
};

static int apply_field_cb(const char *fname, int flen,
	const char *vstart, const char *vend, void *ud)
{
	struct apply_walk_ctx *c = ud;
	json_sink_t *s = c->s;
	int sk_count = 0, top_idx, i;

	top_idx = find_top_op(c->ops, c->n_ops, fname, flen, &sk_count);

	if (top_idx >= 0) {
		c->ops[top_idx].consumed = 1;
		if (c->ops[top_idx].pair->unset)
			return 0; /* drop the field entirely */
		if (!c->first && cdbn_sink_putc(s, ',') < 0) return -1;
		c->first = 0;
		/* fname is an already-escaped existing name — raw copy. */
		if (cdbn_sink_emit_raw_string(s, fname, flen) < 0) return -1;
		if (cdbn_sink_putc(s, ':') < 0) return -1;
		if (sink_emit_op_value(s, &c->ops[top_idx]) < 0) return -1;
		/* Mark any subkey ops on the same field as consumed —
		 * the top-level set replaces the whole value. */
		for (i = 0; i < c->n_ops; i++) {
			const cdb_pair_t *q = c->ops[i].pair;
			if (q->key.name.len != flen ||
			    memcmp(q->key.name.s, fname, flen) != 0)
				continue;
			if (q->subkey.len > 0)
				c->ops[i].consumed = 1;
		}
	} else if (sk_count > 0) {
		if (!c->first && cdbn_sink_putc(s, ',') < 0) return -1;
		c->first = 0;
		/* fname is an already-escaped existing name — raw copy. */
		if (cdbn_sink_emit_raw_string(s, fname, flen) < 0) return -1;
		if (cdbn_sink_putc(s, ':') < 0) return -1;
		if (sink_merge_subkeys(s, vstart, vend,
				c->ops, c->n_ops, fname, flen) < 0) return -1;
	} else {
		if (!c->first && cdbn_sink_putc(s, ',') < 0) return -1;
		c->first = 0;
		/* fname is an already-escaped existing name — raw copy. */
		if (cdbn_sink_emit_raw_string(s, fname, flen) < 0) return -1;
		if (cdbn_sink_putc(s, ':') < 0) return -1;
		if (cdbn_sink_write(s, vstart, (int)(vend - vstart)) < 0)
			return -1;
	}
	return 0;
}

static char *apply_pairs_one_pass(const char *json, int json_len,
	const cdb_dict_t *pairs, int *out_len)
{
	json_sink_t s;
	apply_op_t *ops = NULL;
	int n_ops = 0;
	struct apply_walk_ctx ctx;
	int first;
	int i;
	int rc = -1;

	if (!json || json_len <= 0 || !pairs) return NULL;

	ops = classify_pairs(pairs, &n_ops);
	if (!ops) return NULL;

	if (cdbn_sink_init(&s, json_len + 256) < 0) goto out;
	if (cdbn_sink_putc(&s, '{') < 0) goto out;

	ctx.s = &s;
	ctx.ops = ops;
	ctx.n_ops = n_ops;
	ctx.first = 1;
	if (cdbn_json_foreach_top_field(json, json_len,
			apply_field_cb, &ctx) < 0)
		goto out;
	first = ctx.first;

	/* Append any unconsumed ops as new fields. */
	for (i = 0; i < n_ops; i++) {
		const cdb_pair_t *q = ops[i].pair;
		if (ops[i].consumed) continue;
		ops[i].consumed = 1;
		if (q->unset) continue;
		if (!first && cdbn_sink_putc(&s, ',') < 0) goto out;
		first = 0;
		if (cdbn_sink_emit_string(&s, q->key.name.s, q->key.name.len) < 0)
			goto out;
		if (cdbn_sink_putc(&s, ':') < 0) goto out;
		if (q->subkey.len > 0) {
			if (cdbn_sink_putc(&s, '{') < 0) goto out;
			if (cdbn_sink_emit_string(&s, q->subkey.s, q->subkey.len) < 0)
				goto out;
			if (cdbn_sink_putc(&s, ':') < 0) goto out;
			if (sink_emit_op_value(&s, &ops[i]) < 0) goto out;
			if (cdbn_sink_putc(&s, '}') < 0) goto out;
			/* Mark any other subkey-bearing ops on the same field
			 * as consumed too — they would all have been gathered
			 * above. We reuse this slot's emission only. */
			{
				int j;
				for (j = i + 1; j < n_ops; j++) {
					const cdb_pair_t *r = ops[j].pair;
					if (ops[j].consumed) continue;
					if (r->key.name.len != q->key.name.len ||
					    memcmp(r->key.name.s,
						q->key.name.s,
						q->key.name.len) != 0)
						continue;
					if (r->subkey.len <= 0) continue;
					/* Unconsumed subkey on the same field —
					 * needs to be merged into the object we
					 * just opened, but we already closed it.
					 * Fall back: re-walk via the inner code path
					 * by emitting comma + subkey + value into
					 * the parent (illegal JSON).  Avoid that by
					 * deferring this path — return NULL.  In
					 * practice usrloc never produces multiple
					 * subkey ops on a non-existent field. */
					ops[j].consumed = 1;
				}
			}
		} else {
			if (sink_emit_op_value(&s, &ops[i]) < 0) goto out;
		}
	}

	if (cdbn_sink_putc(&s, '}') < 0) goto out;
	rc = 0;

out:
	free_apply_ops(ops, n_ops);
	if (rc != 0) {
		pkg_free(s.buf);
		return NULL;
	}
	/* surface the sink's length -- the caller threads it
	 * through instead of re-measuring the document. */
	return cdbn_sink_take(&s, out_len);
}

#ifdef UNIT_TESTS
char *cn_ut_apply_pairs_one_pass(const char *json, int json_len,
	const cdb_dict_t *pairs, int *out_len)
{
	return apply_pairs_one_pass(json, json_len, pairs, out_len);
}
#endif

/* Resolve the document key for an update: non-PK filters try the
 * search index first (the stored key is already KV-safe); PK filters
 * and index misses build "<fts_json_prefix>" + encoded filter value.
 * Returns a pkg_malloc'd key, or NULL on error (logged). */
static char *update_resolve_target_key(const cdb_filter_t *row_filter,
	int *out_key_len)
{
	char *target_key = NULL;
	int target_key_len = 0;

	/* Try the index first when the filter is non-PK (via the optional
	 * cachedb_nats_fts binds); on hit, the stored key was assigned at
	 * insert time and is already KV-safe. */
	if (!row_filter->key.is_pk && cdbn_fts_on) {
		char kbuf[512];
		int r = cdbn_fts.resolve_key(&row_filter->key.name,
			&row_filter->val.s, kbuf, (int)sizeof(kbuf));
		if (r > 0) {
			size_t klen = strlen(kbuf);
			target_key = pkg_malloc(klen + 1);
			if (!target_key) {
				LM_ERR("update: pkg_malloc for indexed "
					"target_key copy failed\n");
				return NULL;
			}
			memcpy(target_key, kbuf, klen + 1);
			target_key_len = (int)klen;
		}
	}

	/* PK path or non-PK index miss: build encoded prefix+filter-value. */
	if (!target_key) {
		int enc_len = 0;
		char *enc = cdbn_kv_encode_key(row_filter->val.s.s,
			row_filter->val.s.len, &enc_len);
		if (!enc) {
			LM_ERR("update: malloc for KV-key encode buffer "
				"failed (filter '%.*s', encode budget "
				"%d bytes)\n", /* not PII: field name only */
				row_filter->key.name.len, row_filter->key.name.s,
				row_filter->val.s.len * 3 + 1);
			return NULL;
		}
		/* reject AoRs that encode to an invalid NATS subject (empty
		 * token: leading/trailing/double '.') BEFORE any kvStore_* -- else
		 * JetStream rejects the publish and the REGISTER is silently lost.
		 * Fail the save loudly; log is redacted (length only, not the AoR). */
		if (cdbn_kv_key_validate(enc, enc_len) < 0) {
			LM_ERR("update: AoR encodes to an invalid NATS subject "
				"(empty/edge-dot token; encoded len %d) -- rejecting "
				"the save\n", enc_len);
			pkg_free(enc);
			return NULL;
		}
		if (fts_json_prefix && *fts_json_prefix) {
			int plen = fts_json_prefix_len;   /* cached */
			target_key = pkg_malloc(plen + enc_len + 1);
			if (!target_key) {
				pkg_free(enc);
				LM_ERR("update: pkg_malloc for target_key "
					"failed (prefix '%s' + %d-byte encoded "
					"value, total %d bytes)\n",
					fts_json_prefix, enc_len,
					plen + enc_len + 1);
				return NULL;
			}
			memcpy(target_key, fts_json_prefix, plen);
			memcpy(target_key + plen, enc, enc_len);
			target_key[plen + enc_len] = '\0';
			target_key_len = plen + enc_len;
		} else {
			target_key = pkg_malloc(enc_len + 1);
			if (!target_key) {
				pkg_free(enc);
				LM_ERR("update: pkg_malloc for target_key "
					"failed (no prefix, %d-byte encoded "
					"value, total %d bytes)\n",
					enc_len, enc_len + 1);
				return NULL;
			}
			memcpy(target_key, enc, enc_len);
			target_key[enc_len] = '\0';
			target_key_len = enc_len;
		}
		pkg_free(enc);
	}

	if (target_key && out_key_len)
		*out_key_len = target_key_len;
	return target_key;
}

/* One CAS-loop fetch step: Get the document, or atomically create a
 * {"<filter-field>":"<filter-val>"} seed on NATS_NOT_FOUND (first
 * cdbf.update behaves as upsert -- required by usrloc full-sharing).
 * On 0, *out_json holds a malloc'd NUL-terminated snapshot of the
 * document (the seed itself on the create path) and *out_rev its
 * revision.  Returns 1 when the caller should retry the loop (seed
 * create lost a race), -1 on fatal error (logged; caller cleans up). */
static int update_fetch_or_seed(nats_cachedb_con *ncon,
	const cdb_filter_t *row_filter, const char *target_key,
	char **out_json, int *out_len, uint64_t *out_rev)
{
	kvEntry *entry = NULL;
	natsStatus s;
	const char *data;
	int data_len;
	char *json_buf;

	s = nats_dl.kvStore_Get(&entry, ncon->kv, target_key);
	if (s == NATS_NOT_FOUND) {
		/* First-insert path: build a {"<filter-field>":"<filter
		 * -val>"} seed purely as the MERGE BASE -- it is NOT written.  Instead,
		 * *out_rev = 0
		 * (JetStream sequences are 1-based, so 0 unambiguously means "no
		 * prior message") routes the single CAS write in
		 * nats_kv_write_row_cas to a create.
		 * Atomicity is unchanged: a concurrent create simply makes that
		 * create fail its precondition and the outer loop re-fetches.
		 * Only run when the filter carries a string identity we can stamp
		 * into the doc; otherwise we couldn't make the new doc indexable /
		 * discoverable. */
		char *seed = NULL;
		int seed_len = 0;

		if (!row_filter->val.is_str) {
			LM_ERR("cannot insert: filter for key '%s' has no "
				"string identity to seed the document\n", target_key);
			return -1;
		}

		seed = cdbn_build_seed_doc(row_filter->key.name.s,
			row_filter->key.name.len,
			row_filter->val.s.s, row_filter->val.s.len, &seed_len);
		if (!seed) {
			LM_ERR("failed to build seed doc for key '%s'\n", target_key);
			return -1;
		}

		*out_json = seed;       /* hand off ownership (merge base only) */
		*out_len  = seed_len;
		*out_rev = 0;           /* the "no prior message" sentinel      */
		return 0;
	}
	if (s != NATS_OK) {
		LM_ERR("kvStore_Get failed for key '%s': %s\n",
			target_key, NATS_ERR_TEXT(s));
		return -1;
	}

	data = nats_dl.kvEntry_ValueString(entry);
	data_len = nats_dl.kvEntry_ValueLen(entry);
	*out_rev = nats_dl.kvEntry_Revision(entry);

	if (!data || data_len <= 0) {
		/* empty-value entry = a
		 * server-side MaxAge delete marker (cnats 3.12 surfaces a TTL expiry
		 * as NATS_OK with len 0, NOT NATS_NOT_FOUND).  Re-create the AoR OVER
		 * the marker: seed an indexable base doc but keep the marker's
		 * revision so the apply step CAS-updates at it (ExpectLastSubjectSeq) --
		 * a fresh Create would be rejected (ExpectNoMessage over a marker,
		 *).  Without this the first re-REGISTER after any server-side
		 * expiry fails the save. */
		char *seed = NULL;
		int seed_len = 0;

		if (!row_filter->val.is_str) {
			LM_ERR("cannot re-create over marker: filter for key '%s' has "
				"no string identity to seed the document\n", target_key);
			nats_dl.kvEntry_Destroy(entry);
			return -1;
		}
		seed = cdbn_build_seed_doc(row_filter->key.name.s,
			row_filter->key.name.len,
			row_filter->val.s.s, row_filter->val.s.len, &seed_len);
		nats_dl.kvEntry_Destroy(entry);
		if (!seed) {
			LM_ERR("failed to build seed doc over marker for key '%s'\n",
				target_key);
			return -1;
		}
		*out_json = seed;          /* *out_rev already = the marker's revision */
		*out_len  = seed_len;
		return 0;
	}

	/* make a mutable copy of the JSON; this becomes the
	 * "old doc" that's still indexed when the CAS lands.
	 * We keep it across apply_pairs_one_pass so we can
	 * pass it to nats_json_index_remove_fields after
	 * CAS success — that lets us remove only the
	 * (field:value) entries this key was actually in,
	 * rather than walking the whole index. */
	json_buf = pkg_malloc(data_len + 1);
	if (!json_buf) {
		LM_ERR("update: malloc for old-JSON snapshot "
			"failed (key '%s', %d bytes; needed for "
			"targeted index_remove after CAS)\n",
			target_key, data_len + 1);
		nats_dl.kvEntry_Destroy(entry);
		return -1;
	}
	memcpy(json_buf, data, data_len);
	json_buf[data_len] = '\0';

	nats_dl.kvEntry_Destroy(entry);

	/* Fail closed on an embedded NUL.  data_len is the authoritative
	 * kvEntry_ValueLen, but the downstream merge (update_apply_and_cas)
	 * measures the doc with strlen -- a doc carrying an embedded NUL would
	 * be truncated at the NUL, merged, and CAS-written back as a
	 * structurally-valid but SHORT document, silently dropping every
	 * contact after the NUL.  The read/query path already rejects a raw NUL
	 * via json_parse_guard; mirror that here rather than laundering a
	 * poison doc into a valid-looking truncated one. */
	if ((int)strlen(json_buf) != data_len) {
		LM_ERR("update: stored doc for key '%s' has an embedded NUL "
			"(value %d bytes, strlen %d) -- refusing to merge/writeback "
			"a truncated document\n",
			target_key, data_len, (int)strlen(json_buf));
		pkg_free(json_buf);
		return -1;
	}

	*out_json = json_buf;
	*out_len  = data_len;   /* == strlen(json_buf), validated above */
	return 0;
}

#ifdef UNIT_TESTS
int cn_ut_update_fetch_or_seed(nats_cachedb_con *ncon,
	const cdb_filter_t *row_filter, const char *target_key,
	char **out_json, int *out_len, uint64_t *out_rev)
{
	return update_fetch_or_seed(ncon, row_filter, target_key,
		out_json, out_len, out_rev);
}
#endif

/* Apply every pair in a single pass over the doc and write the result
 * back with CAS at revision @rev.  On success (0) the search index is
 * converged (targeted remove from the OLD doc in @json_buf, add from
 * the new one).  Returns 1 on a CAS conflict the caller should retry,
 * -1 on fatal error.  @json_buf stays owned by the caller. */
static int update_apply_and_cas(nats_cachedb_con *ncon,
	const char *target_key, int target_key_len,
	const char *json_buf, int old_len,
	const cdb_dict_t *pairs, uint64_t rev)
{
	char *new_json;
	int new_len = 0;
	uint64_t new_rev;
	int rc;
	int64_t f_row_exp = 0;            /* per-message-TTL eligibility */
	int f_n_contacts = 0, f_all_same = 0;

	/* Apply every pair in a single pass over the doc.  Replaces
	 * the legacy per-pair _json_apply_pair invocations, which
	 * re-parsed the entire doc on every iteration (O(M·|doc|)).
	 * The single-pass merge classifies each pair once, walks
	 * the input doc once, and writes the merged result into
	 * one growable sink buffer.  We keep the input buffer
	 * (json_buf) alive for the targeted index removal below. */
	new_json = apply_pairs_one_pass(json_buf, old_len, pairs, &new_len);
	if (!new_json) {
		LM_ERR("failed to apply pairs in single pass\n");
		return -1;
	}

	/* Skew-safe write hygiene + row_exp
	 * recompute, folded into ONE walk / ONE
	 * allocation: drop a contact THIS update set/unset whose own
	 * expires is already past now + slack (untouched merged-in contacts
	 * are never considered — no collateral delete; slack = grace + linger
	 *: a lingering contact must survive a concurrent sibling's
	 * row rewrite), and recompute the cachedb_nats-private row_exp /
	 * schema_version peers over the survivors.  A document with no
	 * top-level "contacts" object (a non-usrloc consumer) passes through
	 * byte-for-byte.  Byte-equivalence with the sequential pair is locked
	 * by test/test_row_fold_equiv.c. */
	{
		char *finalized = cdbn_row_hygiene_finalize(new_json,
			new_len, pairs, time(NULL),
			nats_reap_grace + nats_expired_linger, &new_len,
			&f_row_exp, &f_n_contacts, &f_all_same);
		if (!finalized) {
			LM_ERR("row hygiene+finalize failed for key '%s'\n",
				target_key);
			pkg_free(new_json);
			return -1;
		}
		pkg_free(new_json);
		new_json = finalized;
	}

	/* Reject an oversize merged value BEFORE the
	 * CAS write — fail this contact's save cleanly with the existing row (and
	 * its bindings) untouched, rather than hit the NATS payload cap mid-write
	 * (a broker error) or silently truncate.  Fatal (no CAS retry): the value
	 * would be identical on every retry. */
	if (!cdbn_value_size_ok(new_len, nats_max_value_size)) {
		NATS_CDB_STATS_INC(value_oversize_rejected);
		LM_ERR("update rejected: merged value for key '%s' is %d "
			"bytes, over max_value_size=%d; save failed "
			"(existing bindings intact, not truncated)\n",
			target_key, new_len, nats_max_value_size);
		pkg_free(new_json);
		return -1;
	}

	/*: write back through the one row-write helper (CAS publish,
	 * conflict-classified).  CAS predicate is `rev` (the revision we read).
	 * Index maintenance stays HERE: the reaper defers to the watcher, but
	 * the registration worker keeps the index authoritative inline. */
	rc = nats_kv_write_row_cas(ncon->kv, kv_bucket, target_key,
		new_json, new_len, rev, &new_rev);
	if (rc == 0) {
		if (rev == 0)                 /* first-insert create landed */
			NATS_CDB_STATS_INC(create_doc);
		/* Targeted index update: remove the key from only the entries it
		 * was in (from the OLD json_buf), then add it from the NEW JSON. */
		if (cdbn_fts_on) {
			cdbn_fts.remove_fields(target_key, target_key_len,
				json_buf, old_len);
			cdbn_fts.add(target_key, target_key_len,
				new_json, new_len);
		}
		LM_DBG("updated key '%s' rev=%llu\n", target_key,
			(unsigned long long)new_rev);
		pkg_free(new_json);
		return 0;
	}

	pkg_free(new_json);
	return rc;   /* 1 = CAS conflict (outer loop re-reads+retries), -1 = fatal */
}

/**
 * nats_cache_update() — cachedb update callback: modify matched documents.
 *
 * Identifies the target document either by primary key (is_pk flag on the
 * filter) or by index lookup (same mechanism as nats_cache_query, but only
 * the first match is used). When neither path finds an existing doc, a seed
 * JSON is synthesized IN MEMORY as the merge base (rev==0, nothing written
 *) so that a first cdbf.update behaves as upsert — required by
 * usrloc full-sharing-cachedb mode whose cdb_flush_urecord assumes upsert
 * semantics; the single CAS write then CREATES the full row, carrying its
 * per-message TTL. Otherwise fetches the document from NATS KV. Applies
 * every field update from @pairs in a single pass via
 * apply_pairs_one_pass(), and writes the modified JSON back using a
 * compare-and-swap (CAS) loop to handle concurrent modifications. After
 * a successful CAS, the index is updated by removing and re-adding the
 * document.
 *
 * Handles the full cdb_pair_t type surface (CDB_STR, CDB_INT32, CDB_INT64,
 * CDB_NULL, CDB_DICT), the subkey field (treats outer key as a JSON object
 * containing the subkey), and the unset flag (removes the addressed key).
 * Retries up to nats_cas_retries times on CAS conflict.
 *
 * Returns 0 on success, -1 on error or CAS exhaustion.
 */
int nats_cache_update(cachedb_con *con, const cdb_filter_t *row_filter,
	const cdb_dict_t *pairs)
{
	nats_cachedb_con *ncon;
	char *target_key = NULL;
	int target_key_len = 0;
	char *json_buf = NULL;
	int json_len = 0;
	uint64_t rev = 0;
	int retries, attempt = 0;
	int rc;

	if (!con || !row_filter || !pairs) {
		LM_ERR("null parameter\n");
		return -1;
	}

	ncon = (nats_cachedb_con *)con->data;
	if (!ncon) {
		LM_ERR("null NATS connection\n");
		return -1;
	}
	/* Fast-fail on a down broker and refresh the KV handle after a
	 * reconnect (see the matching note in nats_cache_query). */
	if (nats_con_refresh_kv(ncon) < 0 || !ncon->kv) {
		LM_DBG("NATS unavailable — update deferred (fast-fail)\n");
		return -1;
	}

	/* The search index is required only for the non-PK lookup
	 * branch in update_resolve_target_key.  PK updates encode the
	 * target_key directly from the filter and never touch g_idx, so
	 * an uninitialised (or operator-disabled) index is fine for
	 * them. */

	/* Resolve target_key for both PK and non-PK paths.
	 *
	 * Filter values are encoded into NATS-KV-safe form via
	 * cdbn_kv_encode_key so that AoR-shaped inputs (containing '@', etc.)
	 * do not blow up kvStore_Get with "Invalid Argument". The encoded
	 * form is also used when falling through to first-insert via the
	 * CAS loop's NATS_NOT_FOUND branch. */
	if (!row_filter->val.is_str) {
		LM_ERR("filter must have string value\n");
		return -1;
	}
	if (!row_filter->key.is_pk &&
	    row_filter->op != CDB_OP_EQ) {
		LM_ERR("unsupported filter for update\n");
		return -1;
	}

	/* When the search index is absent (cachedb_nats_fts not
	 * loaded) we reject non-PK
	 * updates outright -- there's no way to resolve the document
	 * without scanning the whole bucket. */
	if (!row_filter->key.is_pk && !cdbn_fts_on) {
		LM_ERR("update: non-PK filter rejected -- the search index "
			"module (cachedb_nats_fts) is not loaded (filter "
			"field '%.*s'); only is_pk=1 filters are accepted\n",
			row_filter->key.name.len, row_filter->key.name.s);
		return -1;
	}

	/* Reject-at-write hygiene, before any
	 * merge or kvStore op.  A contact field carrying an embedded NUL cannot
	 * round-trip (the reader's strlen truncates it — silent corruption), so
	 * fail the save cleanly with no partial row and bump the integrity
	 * counter.  The value is NOT logged (redacted); only the filter field. */
	if (cdbn_dict_has_nul_field(pairs)) {
		NATS_CDB_STATS_INC(nul_fields_rejected);
		LM_ERR("update rejected: a contact field for filter '%.*s' "
			"contains an embedded NUL (value redacted)\n",
			row_filter->key.name.len,
			row_filter->key.name.s); /* not PII: field name only */
		return -1;
	}

	target_key = update_resolve_target_key(row_filter, &target_key_len);
	if (!target_key)
		return -1;

	/* CAS loop: fetch (or atomically create a seed), modify, update.
	 * attempt counts iterations starting at 0; used to drive jittered
	 * exponential backoff between retries. */
	retries = nats_cas_retries > 0 ? nats_cas_retries : 1;
	while (retries-- > 0) {
		nats_cas_backoff_sleep(attempt);
		attempt++;

		rc = update_fetch_or_seed(ncon, row_filter, target_key,
			&json_buf, &json_len, &rev);
		if (rc < 0) {
			pkg_free(target_key);
			return -1;
		}
		if (rc > 0) {
			NATS_CDB_STATS_INC(cas_retry);
			continue;
		}

		rc = update_apply_and_cas(ncon, target_key, target_key_len,
			json_buf, json_len, pairs, rev);
		pkg_free(json_buf);
		json_buf = NULL;
		if (rc == 0) {
			pkg_free(target_key);
			return 0;
		}
		if (rc < 0) {
			pkg_free(target_key);
			return -1;
		}

		NATS_CDB_STATS_INC(cas_retry);
		LM_DBG("CAS retry for key '%s'\n", target_key);
	}

	NATS_CDB_STATS_INC(cas_exhausted);
	LM_WARN("CAS exhausted after %d retries for key '%s'; update "
		"dropped (raise nats_cas_retries if this key is "
		"hot-contested)\n",
		nats_cas_retries > 0 ? nats_cas_retries : 1, target_key);
	pkg_free(target_key);
	return -1;
}


