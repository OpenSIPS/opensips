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
 * fts_index.c — SHM-backed JSON search index
 *
 * Owns the field:value -> document-key search index for JSON documents
 * stored in NATS JetStream KV buckets: hash table + doc-key reverse map
 * (revmap) in SHM, sharded lock set, and the index lifecycle
 * (init / build / add / remove / rebuild / destroy).  Also owns the
 * defensive JSON parse helpers (json_parse_guard and friends) used
 * before any broker-supplied document reaches the recursive cJSON
 * parser.
 *
 * Split out of cachedb_nats_json.c (proc-TU split); the query() /
 * update() cachedb callbacks live there, the escape/sink/serializer
 * helpers in cachedb_nats_json_ser.c.  Cross-TU private declarations
 * are in cachedb_nats_json_internal.h.
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

#include "fts_index.h"
#include "../cachedb_nats/cachedb_nats.h"
#include "../cachedb_nats/cachedb_nats_stats.h"
#include "../cachedb_nats/cachedb_nats_dbase.h"
#include "fts_intern.h"
#include "../cachedb_nats/cachedb_nats_json_internal.h"


/* ------------------------------------------------------------------ */
/*                       Global search index                          */
/* ------------------------------------------------------------------ */

nats_search_idx *g_idx = NULL;

/**
 * nats_json_get_index() — Return the global search index pointer.
 *
 * Other modules (e.g. MI commands, watchers) use this to inspect index
 * state such as document counts.  Returns NULL if the index has not been
 * initialised yet.
 */
nats_search_idx *nats_json_get_index(void)
{
	return g_idx;
}

/* ------------------------------------------------------------------ */
/*                       djb2 hash function                           */
/* ------------------------------------------------------------------ */

/* Runtime bucket count (set by nats_json_index_init from the
 * `index_buckets` modparam).  Default keeps current behaviour for
 * callers that don't override it. */
int nats_idx_buckets = NATS_IDX_DEFAULT_BUCKETS;
int nats_idx_bucket_mask = NATS_IDX_DEFAULT_BUCKETS - 1;

/**
 * fts_hash() — Compute a bucket index using the djb2 hash algorithm.
 *
 * Takes a byte string of length @len and produces a value in
 * [0, nats_idx_buckets).  djb2 is a fast, well-distributed hash suitable
 * for short strings such as "field:value" index keys.  The magic constant
 * 5381 and the shift-add recurrence (h * 33 + c) are from Dan Bernstein's
 * original comp.lang.c posting.  The bucket count is forced to a power
 * of two at init, so `& nats_idx_bucket_mask` replaces the modulo.
 */
unsigned int fts_hash(const char *s, int len)
{
	unsigned int h = 5381;
	int i;
	/* djb2: h = h * 33 + c, expressed as ((h << 5) + h) + c */
	for (i = 0; i < len; i++)
		h = ((h << 5) + h) + (unsigned char)s[i];
	return h & nats_idx_bucket_mask;
}

/* ------------------------------------------------------------------ */
/*                    Simple JSON field parser                         */
/* ------------------------------------------------------------------ */

/* The shared JSON walkers (cdbn_skip_ws, cdbn_parse_json_string,
 * cdbn_skip_json_value, cdbn_safe_json_to_dict) stay in cachedb_nats's JSON
 * layer (cachedb_nats_json.c) -- both sides use them via
 * cachedb_nats_json_internal.h. */


/**
 * parse_json_fields() — Extract top-level string fields from a JSON object.
 *
 * Iterates over the top-level key/value pairs of a JSON object.  For every
 * pair whose value is a JSON string, the user-supplied @callback is invoked
 * with the field name, field length, value, value length, and the opaque
 * @ctx pointer.  Non-string values (numbers, bools, nested objects/arrays)
 * are silently skipped.
 *
 * Callback mechanism:
 *   The callback signature is:
 *     void cb(const char *field, int flen, const char *val, int vlen, void *ctx)
 *   It is called synchronously for each string field while the JSON buffer
 *   is still valid.  The field/val pointers reference the original @json
 *   buffer and must not be stored beyond the callback's lifetime.
 *
 * Returns the number of string fields processed, or -1 on parse error.
 */
static int parse_json_fields(const char *json, int len,
	void (*callback)(const char *field, int flen,
		const char *val, int vlen, void *ctx),
	void *ctx)
{
	const char *p = json;
	const char *end = json + len;
	const char *field, *val;
	int flen, vlen;
	int count = 0;

	p = cdbn_skip_ws(p, end);
	if (p >= end || *p != '{')
		return -1;
	p++; /* skip '{' */

	while (1) {
		p = cdbn_skip_ws(p, end);
		if (p >= end)
			return -1;
		if (*p == '}')
			break;

		/* expect comma between pairs (skip it) */
		if (*p == ',') {
			p++;
			p = cdbn_skip_ws(p, end);
			if (p >= end)
				return -1;
		}

		/* parse field name */
		p = cdbn_parse_json_string(p, end, &field, &flen);
		if (!p)
			return -1;

		/* expect colon */
		p = cdbn_skip_ws(p, end);
		if (p >= end || *p != ':')
			return -1;
		p++;
		if (p >= end)
			return -1;

		/* check if value is a string */
		p = cdbn_skip_ws(p, end);
		if (p >= end)
			return -1;

		if (*p == '"') {
			/* string value — parse and invoke the caller's callback
			 * with field name + value slices from the original buffer */
			p = cdbn_parse_json_string(p, end, &val, &vlen);
			if (!p)
				return -1;
			callback(field, flen, val, vlen, ctx);
			count++;
		} else {
			/* non-string value — skip without invoking callback */
			p = cdbn_skip_json_value(p, end);
			if (!p)
				return -1;
		}
	}

	return count;
}

/* ------------------------------------------------------------------ */
/*                    Index entry management                          */
/* ------------------------------------------------------------------ */

/**
 * fts_find_entry() — Look up an index entry by its "field:value" key.
 *
 * Hashes @fv to select a bucket, then walks the singly-linked chain of
 * entries in that bucket comparing both length and content.  Returns the
 * matching entry or NULL.  Must be called with the entry's shard lock held.
 */
static nats_idx_entry *find_entry_in(nats_search_idx *idx,
	const char *fv, int fv_len)
{
	unsigned int bucket = fts_hash(fv, fv_len);
	nats_idx_entry *e;

	for (e = idx->buckets[bucket]; e; e = e->next) {
		if (e->fv_len == (unsigned int)fv_len
				&& memcmp(e->field_value, fv, fv_len) == 0)
			return e;
	}
	return NULL;
}

nats_idx_entry *fts_find_entry(const char *fv, int fv_len)
{
	return find_entry_in(g_idx, fv, fv_len);
}

/**
 * _get_or_create_entry() — Find or create an index entry for a field:value.
 *
 * First tries fts_find_entry(); if the entry does not exist, allocates a new
 * nats_idx_entry, copies the "field:value" string, pre-allocates the key
 * array (initial capacity 8), and inserts the entry at the head of the
 * bucket's chain.  Must be called with the entry's shard lock held.
 *
 * Returns the entry pointer, or NULL on allocation failure.
 */
static nats_idx_entry *get_or_create_entry_in(nats_search_idx *idx,
	const char *fv, int fv_len)
{
	nats_idx_entry *e;
	unsigned int bucket;

	e = find_entry_in(idx, fv, fv_len);
	if (e)
		return e;

	/* SHM allocations: the index lives in shared memory so every
	 * worker dereferences the same pointers; entry storage must
	 * follow.  Failures here are unlikely but logged loudly because
	 * they reflect SHM exhaustion rather than per-process pkg
	 * pressure. */
	/* Single-allocation layout to cut the per-new-entry shm_malloc
	 * count from 3 to 1.  The blob is sized to hold the entry
	 * struct + the field_value bytes + an inline keys[] array of
	 * NATS_IDX_KEYS_INLINE pointers.  field_value and keys are
	 * pointer-arithmetic'd into the blob; free_entry releases
	 * just the blob (no separate shm_free for fv/keys) unless
	 * keys_inline has been cleared by a later geometric-growth.
	 *
	 * Why this matters: the watcher's nats_json_index_add path was
	 * spending half of opensips CPU on hp_shm_malloc -> sem_wait at
	 * 100k AoRs (profiled).
	 * Cutting allocs from 3 to 1 per new entry gives the cold-fill
	 * path 3x fewer bucket-lock acquires; the re-register hot path
	 * was already cut to ~zero by the doc-key intern table.
	 *
	 * Memory waste: the inline keys[] occupies
	 * NATS_IDX_KEYS_INLINE * 8 = 64 bytes in the blob.  When the
	 * key array grows beyond NATS_IDX_KEYS_INLINE, entry_add_key
	 * allocates a fresh keys[] separately and clears keys_inline;
	 * the inline 64 bytes is then dead but stays in the blob until
	 * the entry itself is freed.  Trivial overhead. */
	{
		size_t entry_sz = sizeof(nats_idx_entry);
		/* fv_sz rounded up to pointer alignment: keys[] is placed
		 * directly after the fv bytes, and an unaligned char* store
		 * there is UB (UBSan: "store to misaligned address"; found
		 * by test_fts_key_len driving entry_add_key under UBSan). */
		size_t fv_sz    = ((size_t)fv_len + 1 + sizeof(char *) - 1)
		                  & ~(sizeof(char *) - 1);
		size_t keys_sz  = sizeof(char *) * NATS_IDX_KEYS_INLINE;
		size_t blob_sz  = entry_sz + fv_sz + keys_sz;
		char  *blob     = shm_malloc(blob_sz);
		if (!blob) {
			LM_ERR("no SHM for index entry blob (%zu bytes)\n",
				blob_sz);
			return NULL;
		}
		memset(blob, 0, blob_sz);
		e               = (nats_idx_entry *)blob;
		e->field_value  = blob + entry_sz;
		e->keys         = (char **)(blob + entry_sz + fv_sz);
		e->keys_inline  = 1;
	}

	memcpy(e->field_value, fv, (size_t)fv_len);
	e->field_value[fv_len] = '\0';
	e->fv_len = fv_len;

	e->alloc_keys = NATS_IDX_KEYS_INLINE;
	e->num_keys   = 0;

	bucket = fts_hash(fv, fv_len);
	e->next = idx->buckets[bucket];
	idx->buckets[bucket] = e;

	return e;
}

/* The thin wrapper _get_or_create_entry(fv, fv_len) -> get_or_create_entry_in(
 * g_idx, fv, fv_len) was removed: every call site already targets a
 * specific index (the live index OR a shadow index during rebuild),
 * so the wrapper had no callers and gcc -Wunused-function under
 * -Werror flagged it. */

#ifdef UNIT_TESTS
/* growths of an entry's key array the unit test suite makes fail, as an
 * out-of-SHM would: each one taken counts down */
int fts_ut_fail_grow;
#define GROW_FAILS() (fts_ut_fail_grow > 0 && fts_ut_fail_grow-- > 0)
#else
#define GROW_FAILS() 0
#endif

/**
 * entry_add_key() — Append a document key to an entry's key list.
 *
 * The key list is a dynamic array of interned SHM key pointers (refcount
 * released, not freed).  Duplicates are detected by a linear pointer-compare
 * scan and silently ignored.  When the array is full it is doubled in size
 * (geometric growth: 8 -> 16 -> 32 ...).  Must be called with the entry's
 * shard lock held.
 *
 * Returns 0 on success, -1 on allocation failure.
 */
static int entry_add_key(nats_idx_entry *e, const char *key, int klen)
{
	int i;
	char *interned;

	/* Intern up front so the dup check can compare pointers instead
	 * of running strcmp on every stored key.  All stored keys are
	 * already canonical (acquired through nats_intern_acquire); the
	 * intern table guarantees the same content always resolves to
	 * the same SHM pointer.  Pointer equality is therefore both
	 * correct and O(1).
	 *
	 * Cost of the upfront acquire: one hash lookup + (if hit) one
	 * refcount bump.  Cheaper than strcmp over N >= 2 stored keys,
	 * which is the common case in re-register storms where every
	 * AoR's 5 indexed fields share the same doc key. */
	interned = nats_intern_acquire(key, klen);
	if (!interned) {
		LM_ERR("no SHM for interned key string\n");
		return -1;
	}

	for (i = 0; i < e->num_keys; i++) {
		if (e->keys[i] == interned) {
			/* duplicate: drop the extra refcount we just took
			 * so the intern entry's refcount stays balanced. */
			nats_intern_release(interned);
			return 0;
		}
	}

	/* Geometric growth (double) when the key array is full.  The
	 * twist: the initial keys[] is INSIDE the entry's single-alloc
	 * blob (e->keys_inline=1) and cannot be shm_realloc'd because
	 * it isn't a separate allocation.  The first time we grow past
	 * NATS_IDX_KEYS_INLINE we shm_malloc a fresh array, copy the
	 * inline contents over, clear keys_inline.  Subsequent grows
	 * use shm_realloc on the now-separate block. */
	if (e->num_keys >= e->alloc_keys) {
		int    new_alloc = e->alloc_keys * 2;
		char **new_keys;
		if (e->keys_inline) {
			new_keys = GROW_FAILS() ? NULL :
				shm_malloc(sizeof(char *) * new_alloc);
			if (!new_keys) {
				LM_ERR("no SHM to grow inline keys array\n");
				/* release the ref acquired above so the intern
				 * entry's refcount stays balanced on OOM. */
				nats_intern_release(interned);
				return -1;
			}
			memcpy(new_keys, e->keys,
				sizeof(char *) * (size_t)e->num_keys);
			e->keys         = new_keys;
			e->keys_inline  = 0;
		} else {
			/* shm_realloc preserves contents; on failure the
			 * original block is untouched. */
			new_keys = GROW_FAILS() ? NULL : shm_realloc(e->keys,
				sizeof(char *) * new_alloc);
			if (!new_keys) {
				LM_ERR("no SHM to grow keys array\n");
				/* release the ref acquired above so the intern
				 * entry's refcount stays balanced on OOM. */
				nats_intern_release(interned);
				return -1;
			}
			e->keys = new_keys;
		}
		e->alloc_keys = new_alloc;
	}

	/* New unique key for this entry: store the canonical pointer
	 * we already acquired at the top of the function.  The intern
	 * refcount is now owned by this slot in e->keys[]; release
	 * happens in entry_remove_key. */
	e->keys[e->num_keys++] = interned;
	return 0;
}

/**
 * entry_remove_key() — Remove a document key from an entry's key list.
 *
 * Performs a linear scan for @key.  When found, releases the interned key's
 * refcount (the SHM string is freed only when no entry still references it)
 * and fills the gap by moving the last element into the vacated slot
 * (swap-remove).  This is O(n) in the key count but avoids a memmove and
 * keeps the array compact.  Returns 1 if the key was removed, 0 if not
 * found.  Must be called with the entry's shard lock held.
 */
static int entry_remove_key(nats_idx_entry *e, const char *key, int klen)
{
	int   i;
	char *interned;

	/* Intern to get the canonical pointer; subsequent scan is O(1)
	 * pointer compare.  This adds an extra acquire+release per call
	 * but eliminates the strcmp per stored key. */
	interned = nats_intern_acquire(key, klen);
	if (!interned) return 0;

	for (i = 0; i < e->num_keys; i++) {
		if (e->keys[i] == interned) {
			/* Release twice: once for the slot's ref (kept since
			 * entry_add_key), once for the acquire we just did
			 * at the top of this function. */
			nats_intern_release(e->keys[i]);
			nats_intern_release(interned);
			/* swap-remove: move the last element into this slot */
			e->num_keys--;
			if (i < e->num_keys)
				e->keys[i] = e->keys[e->num_keys];
			return 1;   /* removed */
		}
	}
	/* Not found: release our extra acquire to balance refcount. */
	nats_intern_release(interned);
	return 0;
}

/**
 * free_entry() — Free a single index entry and all its owned memory.
 *
 * Releases the interned refcount on every key, then frees the single
 * entry blob (the field_value bytes and any inline keys[] are freed with
 * it; a keys[] array grown to a separate allocation is freed first).
 * Safe to call with a NULL pointer (no-op).
 */
static void free_entry(nats_idx_entry *e)
{
	int i;
	if (!e)
		return;

	/* Release intern refcounts on every doc key.  The underlying
	 * SHM string is freed only when no other entry still
	 * references it. */
	if (e->keys) {
		for (i = 0; i < e->num_keys; i++)
			nats_intern_release(e->keys[i]);
	}

	/* Free the keys[] array only if it has been grown past the
	 * inline NATS_IDX_KEYS_INLINE slots into a separate SHM
	 * allocation.  When still inline, it is part of the entry
	 * blob and freed with the entry below. */
	if (!e->keys_inline && e->keys)
		shm_free(e->keys);

	/* The entry struct, the field_value bytes, and (if inline)
	 * the keys[] slots all live in a single shm_malloc'd blob.
	 * One free releases the lot. */
	shm_free(e);
}

/* ------------------------------------------------------------------ */
/*             Callback context for JSON field indexing                */
/* ------------------------------------------------------------------ */

typedef struct _idx_add_ctx {
	const char *doc_key;     /* the KV key for this document */
	int         doc_key_len;
	nats_search_idx *target; /* destination index — NULL means g_idx */
} idx_add_ctx;

/**
 * index_field_cb() — Callback used during JSON parsing to index fields.
 *
 * Invoked by parse_json_fields() for every top-level string field in a
 * JSON document.  Builds the composite "field:value" lookup key into a
 * stack buffer, then calls get_or_create_entry_in() + entry_add_key() to
 * record the association between this field:value pair and the document's
 * KV key (carried in ctx->doc_key).
 */
static void index_field_cb(const char *field, int flen,
	const char *val, int vlen, void *ctx)
{
	idx_add_ctx *actx = (idx_add_ctx *)ctx;
	char fv_buf[1024];
	int fv_len;
	nats_idx_entry *e;

	/* guard against negative lengths that could cause integer underflow
	 * and subsequent out-of-bounds memcpy */
	if (flen < 0 || vlen < 0)
		return;

	/* build "field:value" string */
	fv_len = flen + 1 + vlen;
	if (fv_len >= (int)sizeof(fv_buf)) {
		LM_WARN("field:value too long (%d), skipping\n", fv_len);
		return;
	}
	memcpy(fv_buf, field, flen);
	fv_buf[flen] = ':';
	memcpy(fv_buf + flen + 1, val, vlen);
	fv_buf[fv_len] = '\0';

	e = get_or_create_entry_in(actx->target ? actx->target : g_idx,
		fv_buf, fv_len);
	if (!e)
		return;

	entry_add_key(e, actx->doc_key, actx->doc_key_len);
}

/* ------------------------------------------------------------------ */
/*                      Public API functions                          */
/* ------------------------------------------------------------------ */

/**
 * nats_json_index_init() — Allocate and initialise the global search index.
 *
 * Allocates the nats_search_idx struct and its bucket array in SHM
 * (shared across all workers), zeroes the bucket array, and initialises
 * the sharded SHM lock set.  Must be called once pre-fork from mod_init
 * before any index_add / query / update operations.
 *
 * Returns 0 on success, -1 on failure.
 */
/* Round @v up to the next power of two, with a floor at @min.
 * Used to coerce the operator-supplied `index_buckets` modparam
 * into a power-of-two value so `fts_hash` can use a bitmask. */
static int idx_round_up_pow2(int v, int min)
{
	int r = 1;
	if (v < min)
		v = min;
	while (r < v)
		r <<= 1;
	return r;
}

/* ------------------------------------------------------------------ */
/*        doc-key -> field:value reverse map (fast delete)            */
/* ------------------------------------------------------------------ */
/*
 * The watcher's delete-by-key path only has the KV key (the document's
 * JSON is already gone), so it used nats_json_index_remove(), which walks
 * EVERY bucket/entry under all shard locks -- O(buckets x entries) on each
 * expiry/unregister.  This reverse map records, per doc-key, the list of
 * "field:value" strings the document was indexed under, so a delete can
 * remove the key from only those entries (O(fields)).
 *
 * Design notes:
 *   - It stores the fv STRINGS, not nats_idx_entry pointers, so there is
 *     no dangling-pointer hazard: the delete re-looks-up each entry by
 *     string under its own forward-index shard lock, exactly like
 *     nats_json_index_remove_fields().
 *   - The reverse-map lock and the forward-index shard locks are NEVER
 *     held at the same time: the delete snapshots the fv list under the
 *     reverse lock, releases it, then takes forward shard locks.  With a
 *     SEPARATE lock set there is no lock-order relationship to deadlock on.
 *   - A reverse-map miss is always safe: the caller falls back to the full
 *     nats_json_index_remove() walk (correct, just slower).  This makes
 *     the map best-effort -- the index stays the source of truth.
 */
typedef struct nats_rev_node {
	struct nats_rev_node *next;
	unsigned int          hash;
	int                   key_len;
	int                   n_fv;     /* number of fv strings in blob */
	int                   blob_len; /* bytes (each fv is NUL-terminated) */
	char                 *fv_blob;  /* SHM: n_fv NUL-terminated fv strings */
	char                  key[];    /* NUL-terminated doc key */
} nats_rev_node;

typedef struct nats_rev_map {
	nats_rev_node **buckets;        /* nats_idx_buckets heads */
	gen_lock_set_t *locks;          /* OWN lock set, NATS_IDX_SHARDS */
} nats_rev_map;

static nats_rev_map *g_rev = NULL;

static int nats_rev_init(void)
{
	nats_rev_map *r;

	if (g_rev)
		return 0;

	r = shm_malloc(sizeof(*r));
	if (!r) {
		LM_ERR("rev map: no SHM for header\n");
		return -1;
	}
	memset(r, 0, sizeof(*r));

	r->buckets = shm_malloc(sizeof(nats_rev_node *) * (size_t)nats_idx_buckets);
	if (!r->buckets) {
		LM_ERR("rev map: no SHM for %d bucket heads\n", nats_idx_buckets);
		shm_free(r);
		return -1;
	}
	memset(r->buckets, 0, sizeof(nats_rev_node *) * (size_t)nats_idx_buckets);

	r->locks = lock_set_alloc(NATS_IDX_SHARDS);
	if (!r->locks || !lock_set_init(r->locks)) {
		LM_ERR("rev map: lock_set_alloc/init(%d) failed\n", NATS_IDX_SHARDS);
		if (r->locks) lock_set_dealloc(r->locks);
		shm_free(r->buckets);
		shm_free(r);
		return -1;
	}

	g_rev = r;
	return 0;
}

static void rev_free_node(nats_rev_node *n)
{
	if (!n) return;
	if (n->fv_blob) shm_free(n->fv_blob);
	shm_free(n);
}

static void nats_rev_destroy(void)
{
	int i;
	nats_rev_node *n, *next;

	if (!g_rev) return;

	for (i = 0; i < NATS_IDX_SHARDS; i++)
		lock_set_get(g_rev->locks, i);

	for (i = 0; i < nats_idx_buckets; i++) {
		for (n = g_rev->buckets[i]; n; n = next) {
			next = n->next;
			rev_free_node(n);
		}
		g_rev->buckets[i] = NULL;
	}

	for (i = NATS_IDX_SHARDS - 1; i >= 0; i--)
		lock_set_release(g_rev->locks, i);

	lock_set_destroy(g_rev->locks);
	lock_set_dealloc(g_rev->locks);
	shm_free(g_rev->buckets);
	shm_free(g_rev);
	g_rev = NULL;
}

/* Insert-or-replace the fv blob recorded for @key.  @blob is n_fv
 * NUL-terminated "field:value" strings totalling @blob_len bytes. */
static void nats_rev_put(const char *key, int key_len,
	const char *blob, int blob_len, int n_fv)
{
	unsigned int hash, bucket;
	int shard;
	nats_rev_node *n, **pp;
	char *blob_copy;

	if (!g_rev || !key || key_len <= 0 || n_fv <= 0 || blob_len <= 0)
		return;

	blob_copy = shm_malloc((size_t)blob_len);
	if (!blob_copy) {
		LM_ERR("rev map: no SHM for fv blob (%d bytes)\n", blob_len);
		return;   /* best-effort: a miss just falls back to the full walk */
	}
	memcpy(blob_copy, blob, (size_t)blob_len);

	hash   = fts_hash(key, key_len);
	bucket = hash;
	shard  = NATS_IDX_SHARD_OF(bucket);

	lock_set_get(g_rev->locks, shard);

	for (pp = &g_rev->buckets[bucket]; *pp; pp = &(*pp)->next) {
		n = *pp;
		if (n->hash == hash && n->key_len == key_len &&
		    memcmp(n->key, key, (size_t)key_len) == 0) {
			/* replace */
			if (n->fv_blob) shm_free(n->fv_blob);
			n->fv_blob  = blob_copy;
			n->blob_len = blob_len;
			n->n_fv     = n_fv;
			lock_set_release(g_rev->locks, shard);
			return;
		}
	}

	n = shm_malloc(sizeof(*n) + (size_t)key_len + 1);
	if (!n) {
		LM_ERR("rev map: no SHM for node (key_len=%d)\n", key_len);
		shm_free(blob_copy);
		lock_set_release(g_rev->locks, shard);
		return;
	}
	n->hash     = hash;
	n->key_len  = key_len;
	n->n_fv     = n_fv;
	n->blob_len = blob_len;
	n->fv_blob  = blob_copy;
	memcpy(n->key, key, (size_t)key_len);
	n->key[key_len] = '\0';
	n->next = g_rev->buckets[bucket];
	g_rev->buckets[bucket] = n;

	lock_set_release(g_rev->locks, shard);
}

/*: is @key already in the reverse map (i.e. already indexed)?  Read-only
 * membership test under the key's shard lock, mirroring nats_rev_put's lookup.
 * Used by nats_json_index_add to count a doc-key ONCE: a node indexes its own
 * write both inline and via the watcher echo, so an unconditional num_documents
 * increment over-counts.  Returns 1 if present, 0 otherwise / not initialized. */
static int nats_rev_contains(const char *key, int key_len)
{
	unsigned int hash, bucket;
	int shard;
	nats_rev_node *n;

	if (!g_rev || !key || key_len <= 0)
		return 0;

	hash   = fts_hash(key, key_len);
	bucket = hash;
	shard  = NATS_IDX_SHARD_OF(bucket);

	lock_set_get(g_rev->locks, shard);
	for (n = g_rev->buckets[bucket]; n; n = n->next) {
		if (n->hash == hash && n->key_len == key_len &&
		    memcmp(n->key, key, (size_t)key_len) == 0) {
			lock_set_release(g_rev->locks, shard);
			return 1;
		}
	}
	lock_set_release(g_rev->locks, shard);
	return 0;
}

/* Drop the reverse-map record for @key (if any). */
static void nats_rev_remove(const char *key, int key_len)
{
	unsigned int hash, bucket;
	int shard;
	nats_rev_node *n, **pp;

	if (!g_rev || !key || key_len <= 0)
		return;

	hash   = fts_hash(key, key_len);
	bucket = hash;
	shard  = NATS_IDX_SHARD_OF(bucket);

	lock_set_get(g_rev->locks, shard);
	for (pp = &g_rev->buckets[bucket]; *pp; pp = &(*pp)->next) {
		n = *pp;
		if (n->hash == hash && n->key_len == key_len &&
		    memcmp(n->key, key, (size_t)key_len) == 0) {
			*pp = n->next;
			lock_set_release(g_rev->locks, shard);
			rev_free_node(n);
			return;
		}
	}
	lock_set_release(g_rev->locks, shard);
}

/* Drop every reverse-map record (used on a full index rebuild; the map
 * repopulates as documents are re-added). */
static void nats_rev_clear(void)
{
	int i;
	nats_rev_node *n, *next;

	if (!g_rev) return;

	for (i = 0; i < NATS_IDX_SHARDS; i++)
		lock_set_get(g_rev->locks, i);
	for (i = 0; i < nats_idx_buckets; i++) {
		for (n = g_rev->buckets[i]; n; n = next) {
			next = n->next;
			rev_free_node(n);
		}
		g_rev->buckets[i] = NULL;
	}
	for (i = NATS_IDX_SHARDS - 1; i >= 0; i--)
		lock_set_release(g_rev->locks, i);
}

/* nats_json_index_remove_by_revmap() is defined after the forward-index
 * shard-lock helpers below (it uses them). */

int nats_json_index_init(void)
{
	if (g_idx) {
		LM_WARN("search index already initialized\n");
		return 0;
	}

	/* Coerce the requested bucket count into a power of two (so the
	 * hash can use a bitmask) and at least NATS_IDX_SHARDS (so each
	 * shard guards exactly buckets/shards buckets). */
	int requested = nats_idx_buckets > 0
		? nats_idx_buckets : NATS_IDX_DEFAULT_BUCKETS;
	int rounded = idx_round_up_pow2(requested, NATS_IDX_SHARDS);
	if (rounded != requested)
		LM_INFO("index_buckets %d rounded up to power of two "
			"%d (min %d)\n",
			requested, rounded, NATS_IDX_SHARDS);
	nats_idx_buckets = rounded;
	nats_idx_bucket_mask = rounded - 1;

	/* Allocate the index header in SHM so every forked OpenSIPS
	 * worker sees the same instance.  Pre-fork allocation matters:
	 * once child_init runs, each worker maps the same SHM segment
	 * and dereferences the same pointer values. */
	g_idx = shm_malloc(sizeof(nats_search_idx));
	if (!g_idx) {
		LM_ERR("index init: shm_malloc for nats_search_idx header "
			"failed (%zu bytes; tune -m / shared memory size)\n",
			sizeof(nats_search_idx));
		return -1;
	}
	memset(g_idx, 0, sizeof(nats_search_idx));
	atomic_store(&g_idx->num_documents, 0);

	g_idx->buckets = shm_malloc(
		sizeof(nats_idx_entry *) * (size_t)nats_idx_buckets);
	if (!g_idx->buckets) {
		LM_ERR("index init: shm_malloc for buckets array failed "
			"(%d buckets, %zu bytes)\n",
			nats_idx_buckets,
			sizeof(nats_idx_entry *) * (size_t)nats_idx_buckets);
		shm_free(g_idx);
		g_idx = NULL;
		return -1;
	}
	memset(g_idx->buckets, 0,
		sizeof(nats_idx_entry *) * (size_t)nats_idx_buckets);

	g_idx->shard_locks = lock_set_alloc(NATS_IDX_SHARDS);
	if (!g_idx->shard_locks) {
		LM_ERR("index init: lock_set_alloc(%d) for shard locks "
			"failed (SHM exhausted?)\n", NATS_IDX_SHARDS);
		shm_free(g_idx->buckets);
		shm_free(g_idx);
		g_idx = NULL;
		return -1;
	}
	if (!lock_set_init(g_idx->shard_locks)) {
		LM_ERR("index init: lock_set_init failed for %d shards\n",
			NATS_IDX_SHARDS);
		lock_set_dealloc(g_idx->shard_locks);
		shm_free(g_idx->buckets);
		shm_free(g_idx);
		g_idx = NULL;
		return -1;
	}

	/* Allocate the delete-by-key reverse map.  Best-effort: on failure
	 * the watcher's delete path just falls back to the full-walk remove. */
	if (nats_rev_init() < 0)
		LM_WARN("search index: reverse map init failed; deletes will use "
			"the slower full-index walk\n");

	LM_DBG("search index initialized in SHM (%d buckets, %d shards)\n",
		nats_idx_buckets, NATS_IDX_SHARDS);
	return 0;
}

static inline void idx_lock_all(nats_search_idx *idx)
{
	int i;
	for (i = 0; i < NATS_IDX_SHARDS; i++)
		lock_set_get(idx->shard_locks, i);
}
static inline void idx_unlock_all(nats_search_idx *idx)
{
	int i;
	for (i = NATS_IDX_SHARDS - 1; i >= 0; i--)
		lock_set_release(idx->shard_locks, i);
}

/*
 * Fast delete-by-key for the watcher: if the reverse map has a record for
 * @key, remove the key from only the entries it was indexed under
 * (O(fields)) instead of walking every bucket.  Returns 0 on a hit (key
 * removed), -1 on a miss -- the caller MUST fall back to
 * nats_json_index_remove() on -1.
 *
 * The fv blob is copied + the rev node unlinked under the reverse shard
 * lock, which is released BEFORE any forward-index shard lock is taken, so
 * the two (separate) lock sets are never held simultaneously.
 */
int nats_json_index_remove_by_revmap(const char *key, int key_len)
{
	unsigned int hash, bucket;
	int shard, i;
	nats_rev_node *n, **pp;
	char *blob = NULL;
	int blob_len = 0, n_fv = 0, off;
	const char *p;

	if (!g_idx || !g_rev || !key || key_len <= 0)
		return -1;

	hash   = fts_hash(key, key_len);
	bucket = hash;
	shard  = NATS_IDX_SHARD_OF(bucket);

	lock_set_get(g_rev->locks, shard);
	for (pp = &g_rev->buckets[bucket]; *pp; pp = &(*pp)->next) {
		n = *pp;
		if (n->hash == hash && n->key_len == key_len &&
		    memcmp(n->key, key, (size_t)key_len) == 0) {
			blob = malloc((size_t)n->blob_len);
			if (blob) {
				memcpy(blob, n->fv_blob, (size_t)n->blob_len);
				blob_len = n->blob_len;
				n_fv     = n->n_fv;
			}
			*pp = n->next;
			lock_set_release(g_rev->locks, shard);
			rev_free_node(n);
			goto have_blob;
		}
	}
	lock_set_release(g_rev->locks, shard);
	return -1;   /* miss -> caller falls back to the full walk */

have_blob:
	if (!blob)
		return -1;   /* OOM copying -> fall back to the full walk */

	p   = blob;
	off = 0;
	int removed_any = 0;
	for (i = 0; i < n_fv && off < blob_len; i++) {
		int flen = (int)strlen(p);
		unsigned int fb = fts_hash(p, flen);
		int fs = NATS_IDX_SHARD_OF(fb);
		nats_idx_entry *e;

		idx_lock_shard(g_idx, fs);
		e = find_entry_in(g_idx, p, flen);
		if (e)
			removed_any |= entry_remove_key(e, key, key_len);
		idx_unlock_shard(g_idx, fs);

		off += flen + 1;
		p   += flen + 1;
	}
	free(blob);

	if (removed_any)
		atomic_fetch_sub_explicit(&g_idx->num_documents, 1,
			memory_order_relaxed);
	LM_DBG("removed key '%s' via revmap (%d field entries)\n", key, n_fv);
	return 0;
}

/* Per-entry callback type used by drain_kv_snapshot.  Return 0 to
 * keep iterating, non-zero to stop early. */
typedef int (*_kv_snapshot_cb)(const char *key,
	const char *data, int data_len, void *ctx);

/* Drain the initial snapshot phase of a kvStore_WatchAll subscription:
 * open a watcher with UpdatesOnly=false, loop on kvWatcher_Next until
 * libnats delivers the end-of-snapshot sentinel (NULL entry), invoke
 * @cb for each delivered live entry, then destroy the watcher.
 *
 * Replaces the legacy "kvStore_Keys + N × kvStore_Get" pattern: instead
 * of N round-trips serially, the broker streams every existing entry
 * through a single subscription (one round-trip latency, then
 * server-paced delivery).  For a 50k-key bucket on a typical 200 µs
 * RTT this collapses cold-start work from ~10 s to ~1-2 s.
 *
 * IgnoreDeletes is set so tombstones are skipped (we only index live
 * docs).  MetaOnly is left false because we need value bytes to parse
 * JSON.  The snapshot phase's per-call timeout is large (30 s) — the
 * broker delivers entries immediately once the subscription is
 * established; a 30-s wait is only hit if the broker is actually
 * stalled, in which case caller-bubbled error is the right outcome.
 *
 * Returns the number of entries the callback successfully indexed
 * (return value 0), or -1 on any NATS-level error — including a
 * timeout after the subscription was established but before the
 * end-of-snapshot sentinel arrived (a partial snapshot is a FAILED
 * snapshot; callers must keep their prior state and retry). */
static int drain_kv_snapshot(kvStore *kv,
	_kv_snapshot_cb cb, void *ctx)
{
	kvWatcher *w = NULL;
	kvWatchOptions opts;
	kvEntry *entry = NULL;
	natsStatus s;
	int count = 0;

	nats_dl.kvWatchOptions_Init(&opts);
	opts.IgnoreDeletes = true;
	opts.UpdatesOnly   = false;   /* include the initial snapshot */

	s = nats_dl.kvStore_WatchAll(&w, kv, &opts);
	if (s != NATS_OK) {
		LM_ERR("kvStore_WatchAll failed: %s\n",
			nats_dl.natsStatus_GetText(s));
		return -1;
	}

	for (;;) {
		const char *key, *data;
		int data_len;

		s = nats_dl.kvWatcher_Next(&entry, w, 30000);
		if (s == NATS_TIMEOUT) {
			/* Post-subscription, pre-sentinel stall: the snapshot is
			 * INCOMPLETE.  Returning the partial count here let the
			 * rebuild path swap a partial index over a good one, so
			 * non-PK queries silently missed every undelivered
			 * document until the next rebuild.  Fail instead — the
			 * caller keeps the prior index and retries. */
			LM_ERR("snapshot stalled at %d entries; failing (partial "
				"snapshot must not be treated as complete)\n", count);
			nats_dl.kvWatcher_Destroy(w);
			return -1;
		}
		if (s != NATS_OK) {
			LM_ERR("kvWatcher_Next failed: %s\n",
				nats_dl.natsStatus_GetText(s));
			nats_dl.kvWatcher_Destroy(w);
			return -1;
		}
		if (!entry)
			break;   /* end-of-snapshot sentinel */

		key      = nats_dl.kvEntry_Key(entry);
		data     = nats_dl.kvEntry_ValueString(entry);
		data_len = nats_dl.kvEntry_ValueLen(entry);

		if (key && data && data_len > 0) {
			if (cb(key, data, data_len, ctx) == 0)
				count++;
		}

		nats_dl.kvEntry_Destroy(entry);
		entry = NULL;
	}

	if (entry) nats_dl.kvEntry_Destroy(entry);
	nats_dl.kvWatcher_Destroy(w);
	return count;
}

/* Snapshot-callback adapter for nats_json_index_build: filters by
 * prefix and JSON-shape heuristic, then invokes the global-index
 * insert. */
struct _build_snapshot_ctx {
	const char *prefix;
	int prefix_len;
};

static int build_snapshot_cb(const char *key,
	const char *data, int data_len, void *ctx)
{
	struct _build_snapshot_ctx *bctx = ctx;
	if (bctx->prefix_len > 0 &&
	    strncmp(key, bctx->prefix, bctx->prefix_len) != 0)
		return -1;
	if (data[0] != '{')
		return -1;
	/* cnats snapshot keys carry no length; strlen ONCE at the boundary. */
	return nats_json_index_add(key, (int)strlen(key), data, data_len);
}

/**
 * nats_json_index_build() — Bulk-load the index from a NATS KV store.
 *
 * For each live entry whose key matches @prefix and whose value
 * starts with '{' (heuristic JSON detection), calls
 * nats_json_index_add() to parse and index every top-level string
 * field.  Used once at startup to warm the index.
 *
 * Returns the number of documents indexed, or -1 on error.
 */
int nats_json_index_build(kvStore *kv, const char *prefix)
{
	struct _build_snapshot_ctx ctx;
	int count;

	if (!g_idx) {
		LM_ERR("search index not initialized\n");
		return -1;
	}
	if (!kv) {
		LM_ERR("null KV store\n");
		return -1;
	}

	ctx.prefix = prefix;
	ctx.prefix_len = prefix ? (int)strlen(prefix) : 0;

	count = drain_kv_snapshot(kv, build_snapshot_cb, &ctx);
	if (count < 0) return -1;

	LM_INFO("search index built: %d documents indexed\n", count);
	return count;
}

/**
 * nats_json_index_add() — Parse a JSON document and add it to the index.
 *
 * Acquires the index mutex, invokes parse_json_fields() with the
 * index_field_cb callback to extract every top-level string field, and
 * creates or updates "field:value" -> key mappings in the hash table.
 * Increments the global document counter on success.
 *
 * Returns 0 on success, -1 if parsing fails or parameters are NULL.
 */
/* Parse-then-insert split for index_add: parse the document into a
 * stack/heap-backed field-value list outside the lock, then take the
 * lock briefly only to insert each (field:value, key) pair.  The
 * previous design held the index mutex for the full duration of
 * parse_json_fields, which scaled with document size and serialised
 * concurrent index work (queries, removes, other adds) on the entire
 * CPU-bound parse.
 *
 * For a typical AoR document (~500 bytes, 2-3 top-level string
 * fields) the lock-held window drops from "parse + N inserts" to
 * "N inserts", roughly a 10× reduction. */

#define _IDX_FV_INLINE 16

typedef struct {
	const char *field; int flen;
	const char *val;   int vlen;
} _idx_fv_t;

typedef struct {
	_idx_fv_t  inline_buf[_IDX_FV_INLINE];
	_idx_fv_t *items;
	int n;
	int cap;
	int oom;
} _idx_fv_list_t;

static void idx_fv_init(_idx_fv_list_t *l)
{
	l->items = l->inline_buf;
	l->n = 0;
	l->cap = _IDX_FV_INLINE;
	l->oom = 0;
}

static void idx_fv_free(_idx_fv_list_t *l)
{
	if (l->items != l->inline_buf)
		free(l->items);
	l->items = NULL;
}

static int idx_fv_grow(_idx_fv_list_t *l)
{
	int newcap = l->cap * 2;
	_idx_fv_t *next;
	if (l->items == l->inline_buf) {
		next = malloc(newcap * sizeof(_idx_fv_t));
		if (!next) return -1;
		memcpy(next, l->items, l->n * sizeof(_idx_fv_t));
	} else {
		next = realloc(l->items, newcap * sizeof(_idx_fv_t));
		if (!next) return -1;
	}
	l->items = next;
	l->cap = newcap;
	return 0;
}

static void collect_fv_cb(const char *field, int flen,
	const char *val, int vlen, void *ctx)
{
	_idx_fv_list_t *l = ctx;
	if (l->oom) return;
	if (flen < 0 || vlen < 0) return;
	if (l->n == l->cap && idx_fv_grow(l) < 0) {
		l->oom = 1;
		return;
	}
	l->items[l->n++] = (_idx_fv_t){field, flen, val, vlen};
}

int nats_json_index_add(const char *key, int key_len,
	const char *json_str, int json_len)
{
	_idx_fv_list_t list;
	int rc, i;
	int was_present;
	int add_failed = 0;

	if (!g_idx || !key || key_len <= 0 || !json_str)
		return -1;

	/*: count this doc-key ONCE.  A node indexes its own write twice —
	 * inline here in the registration worker AND via the KV watcher echo of the
	 * same Put — so an unconditional num_documents++ over-counts (the stat then
	 * read ~2x the true cardinality until a fresh build).  Capture membership
	 * BEFORE the field inserts / rev_put below; only a genuinely-new key (or a
	 * re-add after remove_fields, which dropped the rev record) increments. */
	was_present = nats_rev_contains(key, key_len);

	/* Parse the document into a flat (field, value) list with no
	 * lock held.  The parser is CPU-bound at ~bytes/cycle, so this
	 * is where the heavy lifting happens; running it unlocked lets
	 * concurrent queries / removes / adds proceed. */
	idx_fv_init(&list);
	rc = parse_json_fields(json_str, json_len, collect_fv_cb, &list);
	if (rc < 0 || list.oom) {
		idx_fv_free(&list);
		LM_WARN("failed to parse JSON for key '%s'\n", key);
		return -1;
	}

	/* Per-field shard locking.  Each collected pair hashes to one
	 * bucket → one shard; we lock only that shard for the insert,
	 * release between fields.  Two concurrent index_add calls
	 * whose fields happen to land on disjoint shards therefore
	 * proceed in parallel rather than serialising on a shared
	 * lock-all.
	 *
	 * Locking order is determined per-field by NATS_IDX_SHARD_OF
	 * so all callers acquire shards in increasing index order
	 * whenever they need more than one — but since each iteration
	 * acquires and immediately releases a single shard, the
	 * hierarchy is trivial: no thread ever holds two shard locks
	 * simultaneously here.  This means a high-fan-out doc cannot
	 * deadlock against a whole-index op (lock_all) — when lock_all
	 * is contending, our per-field lock waits behind it for that
	 * shard, then proceeds. */
	/* Accumulate the document's fv strings into a blob for the reverse
	 * map, so a later delete-by-key can target only these entries instead
	 * of walking the whole index.  Best-effort: on OOM we just skip the
	 * rev record (the delete falls back to the full walk). */
	char  rev_stack[1024];
	char *rev_blob = rev_stack;
	int   rev_cap  = (int)sizeof(rev_stack);
	int   rev_len  = 0, rev_nfv = 0, rev_oom = 0;

	for (i = 0; i < list.n; i++) {
		char fv_buf[1024];
		int  fv_len;
		unsigned int bucket;
		int shard;
		nats_idx_entry *e;
		const _idx_fv_t *p = &list.items[i];

		if (p->flen < 0 || p->vlen < 0) continue;
		fv_len = p->flen + 1 + p->vlen;
		if (fv_len >= (int)sizeof(fv_buf)) {
			LM_WARN("field:value too long (%d), skipping\n", fv_len);
			continue;
		}
		memcpy(fv_buf, p->field, p->flen);
		fv_buf[p->flen] = ':';
		memcpy(fv_buf + p->flen + 1, p->val, p->vlen);
		fv_buf[fv_len] = '\0';

		/* append "field:value\0" to the rev blob */
		if (!rev_oom) {
			int need = rev_len + fv_len + 1;
			if (need > rev_cap) {
				int newcap = rev_cap * 2;
				char *nb;
				while (newcap < need) newcap *= 2;
				nb = (rev_blob == rev_stack) ? malloc(newcap)
				                             : realloc(rev_blob, newcap);
				if (!nb) {
					rev_oom = 1;
				} else {
					if (rev_blob == rev_stack)
						memcpy(nb, rev_blob, rev_len);
					rev_blob = nb;
					rev_cap  = newcap;
				}
			}
			if (!rev_oom) {
				memcpy(rev_blob + rev_len, fv_buf, fv_len + 1);
				rev_len += fv_len + 1;
				rev_nfv++;
			}
		}

		bucket = fts_hash(fv_buf, fv_len);
		shard  = NATS_IDX_SHARD_OF(bucket);

		idx_lock_shard(g_idx, shard);
		e = get_or_create_entry_in(g_idx, fv_buf, fv_len);
		if (!e || entry_add_key(e, key, key_len) < 0) {
			/* out of SHM: this field:value does not list the key;
			 * queries on it miss the document until it is re-added
			 * (the next write or the periodic resync) */
			LM_ERR("no shm: key '%.*s' not indexed under '%s'\n",
				key_len, key, fv_buf);
			add_failed = 1;
		}
		idx_unlock_shard(g_idx, shard);
	}

	if (!was_present)
		atomic_fetch_add_explicit(&g_idx->num_documents, 1,
			memory_order_relaxed);

	/* Record (or replace) the doc's fv set for fast delete-by-key. */
	if (!rev_oom && rev_nfv > 0)
		nats_rev_put(key, key_len, rev_blob, rev_len, rev_nfv);
	if (rev_blob != rev_stack)
		free(rev_blob);

	idx_fv_free(&list);

	LM_DBG("indexed key '%s' (%d fields)\n", key, rc);
	/* the other fields stay indexed (best effort); the caller learns
	 * this document is only partly searchable */
	return add_failed ? -1 : 0;
}

/* Internal: add a parsed JSON document to a CALLER-PROVIDED index
 * struct.  No locking — caller has exclusive ownership of @target
 * (the rebuild path holds it on a thread-local shadow until the
 * atomic swap). */
static int index_add_into(nats_search_idx *target, const char *key,
	int key_len, const char *json_str, int json_len)
{
	idx_add_ctx ctx;
	int rc;

	if (!target || !key || key_len <= 0 || !json_str) return -1;
	ctx.doc_key = key;
	ctx.doc_key_len = key_len;
	ctx.target = target;
	rc = parse_json_fields(json_str, json_len, index_field_cb, &ctx);
	if (rc >= 0)
		atomic_fetch_add_explicit(&target->num_documents, 1,
			memory_order_relaxed);
	return rc < 0 ? -1 : 0;
}

/**
 * nats_json_index_remove() — Remove a document from the index by its KV key.
 *
 * Acquires all shard locks and walks every bucket/entry in the hash table,
 * calling entry_remove_key() to strip the document key from each entry's
 * key list.  This is O(entries * keys_per_entry) but is acceptable because
 * remove is infrequent compared to queries.  Decrements the document count
 * only if the key was actually indexed (guards against going negative).
 *
 * Returns 0 on success, -1 if parameters are NULL or index is uninitialised.
 */
int nats_json_index_remove(const char *key, int key_len)
{
	unsigned int b;
	nats_idx_entry *e;

	if (!g_idx || !key)
		return -1;

	idx_lock_all(g_idx);

	int removed_any = 0;
	for (b = 0; b < (unsigned int)nats_idx_buckets; b++) {
		for (e = g_idx->buckets[b]; e; e = e->next)
			removed_any |= entry_remove_key(e, key, key_len);
	}

	idx_unlock_all(g_idx);

	/* Decrement only if the key was actually indexed: removing a
	 * never-indexed key (e.g. the seed-create path, or a duplicate remove)
	 * must not drive num_documents negative. */
	if (removed_any)
		atomic_fetch_sub_explicit(&g_idx->num_documents, 1,
			memory_order_relaxed);

	/* Drop any reverse-map record so it can't go stale. */
	nats_rev_remove(key, key_len);

	LM_DBG("removed key '%s' from index\n", key);
	return 0;
}

/* [a /]: observe the live
 * forward-index document count.  Lets a joint reaper⊕watcher e2e assert that
 * the in-SHM index entry — not merely the read-path view — is dropped when
 * the server TTL-expires a key.  NULL-safe: an uninitialized index returns -1
 * (distinct from an empty index, 0); never dereferences a NULL g_idx. */
int nats_json_index_count(void)
{
	if (!g_idx)
		return -1;
	return atomic_load_explicit(&g_idx->num_documents, memory_order_relaxed);
}

/* Per-field-callback adapter for nats_json_index_remove_fields:
 * looks up the (field:value) entry, locks just its shard, removes
 * the doc-key from its keys[] array, releases the shard.  Field +
 * value byte slices alias into the caller-owned old JSON, which
 * stays live across this entire call sequence. */
typedef struct {
	const char *doc_key;	int         doc_key_len;

	int         removed_any;   /* set if any field entry actually held the key */
} _idx_remove_ctx;

static void index_remove_field_cb(const char *field, int flen,
	const char *val, int vlen, void *ctx)
{
	_idx_remove_ctx *rctx = ctx;
	char fv_buf[1024];
	int fv_len = flen + 1 + vlen;
	unsigned int bucket;
	int shard;
	nats_idx_entry *e;

	if (flen < 0 || vlen < 0) return;
	if (fv_len >= (int)sizeof(fv_buf)) return;
	memcpy(fv_buf, field, flen);
	fv_buf[flen] = ':';
	memcpy(fv_buf + flen + 1, val, vlen);
	fv_buf[fv_len] = '\0';

	bucket = fts_hash(fv_buf, fv_len);
	shard  = NATS_IDX_SHARD_OF(bucket);

	idx_lock_shard(g_idx, shard);
	e = find_entry_in(g_idx, fv_buf, fv_len);
	if (e)
		rctx->removed_any |= entry_remove_key(e, rctx->doc_key,
			rctx->doc_key_len);
	idx_unlock_shard(g_idx, shard);
}

int nats_json_index_remove_fields(const char *key, int key_len,
	const char *json_str, int json_len)
{
	_idx_remove_ctx ctx;
	int rc;

	if (!g_idx || !key || key_len <= 0 || !json_str || json_len <= 0)
		return 0;

	ctx.doc_key = key;
	ctx.doc_key_len = key_len;
	ctx.removed_any = 0;
	rc = parse_json_fields(json_str, json_len, index_remove_field_cb,
		&ctx);
	if (rc < 0)
		return -1;

	/* Only decrement if the key was actually indexed under one of these
	 * fields -- a remove of a never-indexed key must not go negative. */
	if (ctx.removed_any)
		atomic_fetch_sub_explicit(&g_idx->num_documents, 1,
			memory_order_relaxed);

	/* The doc's fv set is changing (this is the remove half of an
	 * update); drop the old reverse-map record -- the add half re-puts
	 * the new one. */
	nats_rev_remove(key, key_len);

	LM_DBG("removed key '%s' (%d field entries) from index\n",
		key, rc);
	return 0;
}

/**
 * nats_json_index_rebuild() — Rebuild the index from KV data via a shadow swap.
 *
 * Builds a FRESH shadow index from a full KV re-scan (rebuild_snapshot_cb ->
 * index_add_into on a thread-local shadow), then — holding all shard locks —
 * atomically swaps the shadow's buckets and document count into the live
 * index, releasing the locks before freeing the old buckets.  Readers
 * therefore never observe a half-cleared or half-built index (the reason this
 * is a shadow swap rather than a clear-in-place rebuild).  Used when the index
 * may have drifted from the KV contents (e.g. after a NATS reconnect or an MI
 * rebuild command).
 *
 * Returns the number of documents re-indexed, or -1 on error.
 */
/* Scratch allocator for the rebuild's two process-private
 * bucket arrays.  The rebuild runs on the MAIN thread of a dedicated
 * proc (the watcher process; the periodic resync host) -- the
 * in-worker watcher PTHREAD that once forced shm here is gone,
 * so pkg is legal, skips a global-shm-lock round-trip per array, and
 * makes leaks visible to pkg stats.  pkg OOM falls back to shm
 * (availability over the optimisation); *in_shm records the owner so
 * the matching free routes correctly. */
static void *scratch_alloc(size_t bytes, int *in_shm)
{
	void *p = pkg_malloc(bytes);

	if (p) {
		*in_shm = 0;
		return p;
	}
	LM_WARN("rebuild scratch: pkg_malloc(%zu) failed; falling back "
		"to shm\n", bytes);
	*in_shm = 1;
	return shm_malloc(bytes);
}

static void scratch_free(void *p, int in_shm)
{
	if (!p)
		return;
	if (in_shm)
		shm_free(p);
	else
		pkg_free(p);
}

/* Snapshot-callback adapter for nats_json_index_rebuild: indexes
 * into the caller-owned shadow rather than the global index. */
struct _rebuild_snapshot_ctx {
	nats_search_idx *shadow;
	const char *prefix;
	int prefix_len;
};

static int rebuild_snapshot_cb(const char *key,
	const char *data, int data_len, void *ctx)
{
	struct _rebuild_snapshot_ctx *rctx = ctx;
	if (rctx->prefix_len > 0 &&
	    strncmp(key, rctx->prefix, rctx->prefix_len) != 0)
		return -1;
	if (data[0] != '{')
		return -1;
	/* cnats snapshot keys carry no length; strlen ONCE at the boundary. */
	return index_add_into(rctx->shadow, key, (int)strlen(key),
		data, data_len);
}

int nats_json_index_rebuild(kvStore *kv, const char *prefix)
{
	nats_search_idx shadow;
	struct _rebuild_snapshot_ctx ctx;
	int count;
	nats_idx_entry **old_buckets;
	int shadow_in_shm = 0, old_in_shm = 0;
	int old_num;
	unsigned int b;
	nats_idx_entry *e, *next;
	size_t buckets_bytes;

	if (!g_idx) return -1;
	if (!kv)    { LM_ERR("null KV store\n"); return -1; }

	LM_INFO("rebuilding search index (shadow build + atomic swap)...\n");

	/* Step 1: build the new state into a thread-local shadow struct.
	 * The shadow header is on the stack but its buckets array must be
	 * heap-allocated since the bucket count is now runtime-tunable.
	 * Only this caller sees the shadow; the lock field is unused
	 * because no other thread can reach `shadow` -- we pass it
	 * explicitly through index_add_into.
	 *
	 * These scratch arrays are process-private and this
	 * function runs on the MAIN thread of a dedicated proc, so they
	 * go through scratch_alloc (pkg preferred, shm fallback). */
	memset(&shadow, 0, sizeof(shadow));
	buckets_bytes = sizeof(nats_idx_entry *) * (size_t)nats_idx_buckets;
	shadow.buckets = scratch_alloc(buckets_bytes, &shadow_in_shm);
	if (!shadow.buckets) {
		LM_ERR("rebuild: scratch alloc for shadow buckets failed "
			"(%d buckets, %zu bytes)\n",
			nats_idx_buckets, buckets_bytes);
		return -1;
	}
	memset(shadow.buckets, 0, buckets_bytes);

	ctx.shadow = &shadow;
	ctx.prefix = prefix;
	ctx.prefix_len = prefix ? (int)strlen(prefix) : 0;

	count = drain_kv_snapshot(kv, rebuild_snapshot_cb, &ctx);
	if (count < 0) {
		/* Snapshot failed (WatchAll error or a mid-stream stall):
		 * the shadow is empty or PARTIAL.  Swapping it in would
		 * silently drop documents from the live index, so keep the
		 * prior index intact and let the caller retry.  (A genuinely
		 * empty bucket is NOT this path — it delivers the sentinel
		 * and returns count == 0, which swaps normally.) */
		LM_ERR("rebuild snapshot failed; keeping the prior index\n");
		/* free whatever the callback already put into the shadow */
		for (b = 0; b < (unsigned int)nats_idx_buckets; b++) {
			e = shadow.buckets[b];
			while (e) {
				next = e->next;
				free_entry(e);
				e = next;
			}
		}
		scratch_free(shadow.buckets, shadow_in_shm);
		return -1;
	}

	/* Step 2: atomic swap under all shard locks.  Snapshot the old
	 * buckets pointer (entries remain reachable to readers up until
	 * we release the locks, after which they're disowned), then
	 * install the shadow's buckets and num_documents.  Queries
	 * arriving DURING this critical section block on whatever
	 * shard they need and see the new state when they get in.
	 *
	 * Note: we swap the pointer-to-buckets, not the buckets bytes.
	 * The old g_idx->buckets array (SHM) stays put; we copy from
	 * shadow.buckets into it.  This avoids forcing a SHM realloc
	 * while shards are locked. */
	idx_lock_all(g_idx);
	old_buckets = scratch_alloc(buckets_bytes, &old_in_shm);
	if (!old_buckets) {
		idx_unlock_all(g_idx);
		scratch_free(shadow.buckets, shadow_in_shm);
		LM_ERR("rebuild: scratch alloc for old-buckets snapshot "
			"failed (%d buckets, %zu bytes)\n",
			nats_idx_buckets, buckets_bytes);
		return -1;
	}
	memcpy(old_buckets, g_idx->buckets, buckets_bytes);
	old_num = atomic_load_explicit(&g_idx->num_documents,
		memory_order_relaxed);
	memcpy(g_idx->buckets, shadow.buckets, buckets_bytes);
	atomic_store_explicit(&g_idx->num_documents,
		atomic_load_explicit(&shadow.num_documents, memory_order_relaxed),
		memory_order_relaxed);
	idx_unlock_all(g_idx);

	/* Step 3: free the old (now-disowned) bucket entries outside
	 * the lock, so any blocked readers proceed immediately. */
	for (b = 0; b < (unsigned int)nats_idx_buckets; b++) {
		e = old_buckets[b];
		while (e) {
			next = e->next;
			free_entry(e);
			e = next;
		}
	}
	scratch_free(old_buckets, old_in_shm);
	scratch_free(shadow.buckets, shadow_in_shm);

	/* The shadow rebuild populated the forward index but not the reverse
	 * map; clear it so it can't carry stale records.  It repopulates as
	 * documents are re-added (deletes of not-yet-readded docs fall back to
	 * the full-walk remove until then). */
	nats_rev_clear();

	LM_INFO("search index rebuilt: %d docs (was %d)\n", count, old_num);
	return count;
}

/**
 * nats_json_index_destroy() — Tear down the global index and free all memory.
 *
 * Acquires all shard locks, walks every bucket, frees all entries and their
 * key lists, then destroys the shard lock set and frees the nats_search_idx
 * struct.  Sets g_idx to NULL so subsequent calls are safe no-ops.  Called
 * during OpenSIPS worker shutdown.
 */
void nats_json_index_destroy(void)
{
	unsigned int b;
	nats_idx_entry *e, *next;

	if (!g_idx)
		return;

	idx_lock_all(g_idx);

	for (b = 0; b < (unsigned int)nats_idx_buckets; b++) {
		e = g_idx->buckets[b];
		while (e) {
			next = e->next;
			free_entry(e);
			e = next;
		}
		g_idx->buckets[b] = NULL;
	}
	atomic_store_explicit(&g_idx->num_documents, 0,
		memory_order_relaxed);

	idx_unlock_all(g_idx);

	if (g_idx->shard_locks) {
		lock_set_destroy(g_idx->shard_locks);
		lock_set_dealloc(g_idx->shard_locks);
	}

	if (g_idx->buckets)
		shm_free(g_idx->buckets);
	shm_free(g_idx);
	g_idx = NULL;

	/* Tear down the delete-by-key reverse map. */
	nats_rev_destroy();

	LM_DBG("search index destroyed\n");
}

#ifdef UNIT_TESTS
/* entry_add_key(): adds `key` to entry `e`'s key list */
int fts_ut_entry_add_key(nats_idx_entry *e, const char *key, int klen)
{
	return entry_add_key(e, key, klen);
}

/* Swaps this process's search index and reverse map with *idx and *rev,
 * so the unit test suite can work on instances of its own (NULL: none,
 * for init to make) and put the live ones back.  Other processes keep
 * theirs. */
void fts_ut_index_swap(nats_search_idx **idx, void **rev)
{
	nats_search_idx *i = g_idx;
	nats_rev_map *r = g_rev;

	g_idx = *idx;
	g_rev = (nats_rev_map *)*rev;
	*idx = i;
	*rev = r;
}
#endif
