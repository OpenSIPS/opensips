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
 * cachedb_nats_dbase.c — cachedb API implementation for NATS JetStream KV
 *
 * This file implements the OpenSIPS cachedb interface backed by a NATS
 * JetStream Key-Value store.  Supported operations:
 *
 *   get          — retrieve a value by key
 *   set          — store a key-value pair (put)
 *   remove       — delete a key (purge)
 *   add / sub    — atomic counter increment / decrement via CAS
 *   get_counter  — read a numeric value stored as a string integer
 *
 * Thread safety
 * -------------
 * All functions in this file are called from OpenSIPS worker process
 * threads (UDP/TCP receivers, timer processes, etc.).  No additional
 * locking is required because each process holds its own nats_cachedb_con
 * with a per-process KV handle.  The underlying nats.c library manages
 * its own I/O thread internally.
 *
 * KV handle refresh
 * -----------------
 * After a NATS reconnection, old kvStore handles reference freed internal
 * subscriptions/consumers inside nats.c.  Every operation calls
 * nats_con_refresh_kv() which compares a per-connection epoch against the
 * global reconnect epoch maintained by the connection pool.  On mismatch,
 * the KV handle is transparently replaced with a fresh one.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>

#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../cachedb/cachedb.h"

#include "cachedb_nats_dbase.h"
#include "cachedb_nats_watch.h"
#include "cachedb_nats_stats.h"
#include "../nats/nats_bind.h"
#include "../nats/nats_pool.h"
#include "../nats/nats_redact.h"   /* nats_redact_key */
#include "../nats/nats_rl.h"   /* rate-limited outage WARN */
#include "../nats/nats_validate.h"
#include "../nats/nats_str.h"
#include "../nats/nats_err.h"   /* NATS_ERR_TEXT */

extern int nats_cas_retries;   /* defined in cachedb_nats.c */

/* One shared, rate-limited WARN for every KV-op disconnect
 * fast-fail in this module (the per-call lines stay DBG).  Before this
 * a broker outage was invisible at the default log level: all 13
 * fast-fail sites logged DBG only, and the pool's own transition
 * callbacks may only raw-write to stderr (often /dev/null under a
 * daemonized start).  One process-wide slot so an outage costs one
 * WARN line per 30s per process, whatever mix of ops is failing. */
void nats_cdb_disconnected_warn(const char *op)
{
	static time_t rl_disc;

	if (nats_rl_pass(&rl_disc, time(NULL), 30))
		LM_WARN("NATS disconnected -- failing %s fast (repeats "
			"suppressed for 30s; per-call detail at DBG)\n", op);
}

/**
 * nats_new_connection() — allocate and initialise a NATS cachedb connection.
 *
 * Called indirectly by cachedb_do_init(), which passes this function as a
 * callback.  Allocates a nats_cachedb_con, copies the cachedb_id supplied
 * by the framework, and obtains a KV store handle from the shared
 * connection pool for the configured bucket (kv_bucket module parameter).
 *
 * @param id   Parsed cachedb URL (scheme, host, group, etc.).  Ownership
 *             is retained by the cachedb framework — we just store a pointer.
 * @return     Pointer to the new connection, or NULL on failure.
 *             The caller (cachedb_do_init) wraps this in a cachedb_con.
 */
static nats_cachedb_con *nats_new_connection(struct cachedb_id *id)
{
	nats_cachedb_con *con;

	if (!id) {
		LM_ERR("null cachedb_id\n");
		return NULL;
	}

	con = pkg_malloc(sizeof(nats_cachedb_con));
	if (!con) {
		LM_ERR("no more pkg memory for nats_cachedb_con\n");
		return NULL;
	}
	memset(con, 0, sizeof(nats_cachedb_con));

	con->id = id;
	con->ref = 1;
	con->bucket_name = kv_bucket;

	/* Without a NATS connection (degraded start, see child_init), the
	 * connection is created without a KV handle: the operations get it
	 * once connected (nats_con_refresh_kv()).  A process that has not
	 * connected yet connects first: the attendant before the fork, where
	 * b2b_entities and b2b_logic restore their state from mod_init, has
	 * no child_init to do it. */
	if (!nats_pool_get() || !nats_pool_is_connected()) {
		LM_DBG("NATS unavailable; KV handle for bucket '%s' deferred\n",
			kv_bucket);
		return con;
	}

	/* get/create KV store handle from the shared pool */
	con->kv = nats_pool_get_kv(kv_bucket, kv_replicas, kv_history,
		(int64_t)kv_ttl);
	if (!con->kv) {
		LM_ERR("failed to get KV store for bucket '%s'\n", kv_bucket);
		pkg_free(con);
		return NULL;
	}
	nats_epoch_save(&con->kv_epoch);

	LM_DBG("NATS cachedb connection created for bucket '%s'\n", kv_bucket);
	return con;
}

/**
 * nats_con_refresh_kv() — refresh the KV handle if a reconnection occurred.
 *
 * Uses an epoch-based strategy: the shared connection pool maintains a
 * monotonically increasing reconnect epoch that is bumped each time nats.c
 * re-establishes the server connection.  Each nats_cachedb_con stores the
 * epoch at which its KV handle was obtained.  If the two diverge, the old
 * handle is stale (it references freed internal subscriptions/consumers
 * inside nats.c) and must be replaced.
 *
 * This function is called at the top of every cachedb operation (get, set,
 * remove, counter_op, get_counter) so that callers never use a stale handle.
 *
 * Thread safety: each OpenSIPS process has its own nats_cachedb_con, so no
 * locking is needed.  The epoch read is atomic (int assignment on all
 * supported architectures).
 *
 * @return  0 if the handle is valid (or was successfully refreshed),
 *         -1 if NATS is disconnected or the refresh failed.
 */
int nats_con_refresh_kv(nats_cachedb_con *ncon)
{
	int epoch;

	if (!ncon)
		return -1;

	/* If NATS is disconnected, fail fast.  Operations on stale handles
	 * during the disconnect window cause free(): invalid pointer in
	 * nats.c's internal I/O thread (race between reconnection cleanup
	 * and our KV operations). */
	if (!nats_pool_is_connected()) {
		nats_cdb_disconnected_warn("KV operation");
		LM_DBG("NATS disconnected — KV operation deferred\n");
		NATS_CDB_STATS_INC(fastfail_rejected);
		return -1;
	}

	/* refresh protocol: snapshot BEFORE the acquire, adopt only
	 * after success (nats_epoch.h documents why). */
	epoch = nats_epoch_snapshot();
	if (nats_epoch_current(&ncon->kv_epoch) && ncon->kv)
		return 0;  /* still valid */

	/* Reconnection occurred (or a previous refresh failed) — get a fresh
	 * KV handle.  Don't destroy the old one (other code may reference it). */
	ncon->kv = nats_pool_get_kv(ncon->bucket_name,
		kv_replicas, kv_history, (int64_t)kv_ttl);

	if (!ncon->kv) {
		/* rate-limited: a failure that lasts (no JetStream, bucket
		 * refused by the broker) meets every cache operation */
		static time_t rl_refresh;

		/* Do NOT adopt the epoch on failure: a transient pool failure
		 * right after a reconnect would otherwise latch epoch with
		 * kv == NULL, short-circuiting every subsequent call until the
		 * NEXT reconnect — a permanent per-worker outage. */
		if (nats_rl_pass(&rl_refresh, time(NULL), 30))
			LM_ERR("failed to refresh KV handle after reconnect "
				"(repeats suppressed for 30s)\n");
		NATS_CDB_STATS_INC(fastfail_rejected);
		return -1;
	}
	nats_epoch_adopt(&ncon->kv_epoch, epoch);

	LM_INFO("refreshed KV handle (epoch %d)\n", epoch);
	return 0;
}

/**
 * nats_free_connection() — release a NATS cachedb connection.
 *
 * Called by cachedb_do_close() when the cachedb framework tears down
 * this connection.  Only the nats_cachedb_con wrapper is freed here.
 *
 * Ownership semantics: the kvStore handle (ncon->kv) is owned by the
 * shared connection pool (nats_pool) and must NOT be destroyed by us.
 * The pool manages KV handle lifecycles across reconnections.
 */
#ifdef UNIT_TESTS
/* the constructor the module hands cachedb_do_init(), for the tests */
void *cn_ut_new_connection(struct cachedb_id *id)
{
	return nats_new_connection(id);
}
#endif

static void nats_free_connection(cachedb_pool_con *cpc)
{
	if (!cpc)
		return;

	LM_DBG("freeing NATS cachedb connection\n");
	pkg_free(cpc);
}

/**
 * nats_cachedb_init() — cachedb framework init callback.
 *
 * Registered as the "init" function pointer in the cachedb_engine struct.
 * Delegates to cachedb_do_init(), which parses the URL, manages the
 * connection pool, and calls nats_new_connection() to create the
 * backend-specific connection object.
 *
 * @param url  The cachedb URL from opensips.cfg (e.g. "nats://bucket_name").
 * @return     An opaque cachedb_con handle, or NULL on failure.
 */
cachedb_con *nats_cachedb_init(str *url)
{
	return cachedb_do_init(url, (void *)nats_new_connection);
}

/**
 * nats_cachedb_destroy() — cachedb framework destroy callback.
 *
 * Registered as the "destroy" function pointer in the cachedb_engine struct.
 * Delegates to cachedb_do_close(), which calls nats_free_connection() to
 * release the backend-specific connection and then frees the cachedb_con
 * wrapper.
 *
 * @param con  The cachedb_con handle returned by nats_cachedb_init().
 */
void nats_cachedb_destroy(cachedb_con *con)
{
	LM_DBG("destroying NATS cachedb connection\n");
	cachedb_do_close(con, nats_free_connection);
}

/* The str→C-string helpers now live in modules-contrib/nats/nats_str.h
 * (nats_str_to_buf). */

/**
 * validate_kv_key() — reject keys NATS KV cannot represent as a subject token.
 *
 * NATS JetStream KV maps keys onto a subject of the form "$KV.<bucket>.<key>",
 * so the key must be a valid subject token: alphanumeric plus `_`, `-`, `=`,
 * `/`, `\`, `.` (dots split into sub-tokens, no empty token) -- the same
 * alphabet nats.c's kv.c validKey() enforces.
 *
 * Returns 0 if key is valid, -1 otherwise.
 */
int validate_kv_key(const str *s)
{
	/* The rules (the nats.c key alphabet) live in the shared modules-contrib/nats
	 * validator; keep the cachedb-context log here. */
	if (!s || !s->s || s->len <= 0) {
		LM_ERR("KV key empty or NULL\n");
		return -1;
	}
	if (nats_validate(s->s, s->len, NATS_VALIDATE_KV_KEY) < 0) {
		LM_ERR("invalid KV key '%.*s': keys may contain only letters, "
			"digits and . _ - / \\ =, with no leading, trailing or "
			"double dot (hash SIP values such as a Call-ID first)\n",
			s->len, s->s);
		return -1;
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/*                       cachedb API operations                       */
/* ------------------------------------------------------------------ */

/**
 * nats_cache_get() — retrieve a value from the NATS KV store by key.
 *
 * Looks up the given key (attr) in the JetStream KV bucket and returns
 * the value in an OpenSIPS str.  The value buffer is allocated with
 * pkg_malloc and must be freed by the caller (the cachedb framework
 * handles this).
 *
 * @param con   cachedb connection handle.
 * @param attr  Key to look up (OpenSIPS str, not null-terminated).
 * @param val   [out] Receives the value; val->s is pkg_malloc'd on success.
 * @return  0  on success (val is populated),
 *         -1  on error (NATS failure, allocation failure, etc.),
 *         -2  if the key was not found in the KV store.
 */
int nats_cache_get(cachedb_con *con, str *attr, str *val)
{
	nats_cachedb_con *ncon;
	kvEntry *entry = NULL;
	natsStatus s;
	const char *data;
	int data_len;
	char key_buf[NATS_KEY_BUF_SIZE];

	if (!con || !attr || !val) {
		LM_ERR("null parameter\n");
		return -1;
	}

	/* Deterministic out-param on every path: callers only free val->s
	 * on rc == 0, but zeroing at entry turns a caller bug from a
	 * garbage-pointer free into a clean NULL and makes the miss (-2) /
	 * empty (0) paths uniform. */
	val->s = NULL;
	val->len = 0;

	ncon = (nats_cachedb_con *)con->data;
	if (!ncon) {
		LM_ERR("null NATS connection\n");
		return -1;
	}
	if (nats_con_refresh_kv(ncon) < 0 || !ncon->kv) {
		LM_ERR("KV handle unavailable\n");
		return -1;
	}

	if (validate_kv_key(attr) < 0)
		return -1;
	if (nats_str_to_buf(attr, key_buf, sizeof(key_buf)) < 0)
		return -1;

	/* kvEntry lifecycle: kvStore_Get allocates an entry that we must
	 * destroy with kvEntry_Destroy once we have extracted the value. */
	s = nats_dl.kvStore_Get(&entry, ncon->kv, key_buf);

	/* NATS_NOT_FOUND is not an error — the cachedb framework uses -2
	 * to distinguish "key absent" from "operation failed". */
	if (s == NATS_NOT_FOUND) {
		LM_DBG("key not found: '%s'\n", key_buf);
		val->s = NULL;
		val->len = 0;
		return -2;
	}
	if (s != NATS_OK) {
		char _rk[NATS_REDACT_KEY_BUF];
		nats_redact_key(key_buf, _rk, sizeof(_rk));
		LM_ERR("kvStore_Get failed for key '%s': %s\n",
			_rk, NATS_ERR_TEXT(s));
		NATS_CDB_STATS_INC(op_failed);
		return -1;
	}

	/* Read the value from the entry before destroying it — the pointer
	 * returned by kvEntry_ValueString is only valid while entry exists. */
	data = nats_dl.kvEntry_ValueString(entry);
	data_len = nats_dl.kvEntry_ValueLen(entry);

	if (!data || data_len <= 0) {
		/* key exists but empty value */
		val->s = NULL;
		val->len = 0;
		nats_dl.kvEntry_Destroy(entry);
		return 0;
	}

	/* Allocate pkg memory for the return value.  The cachedb framework
	 * will free this buffer after the script has consumed it. */
	val->s = pkg_malloc(data_len);
	if (!val->s) {
		LM_ERR("no more pkg memory for value (%d bytes)\n", data_len);
		nats_dl.kvEntry_Destroy(entry);
		return -1;
	}
	memcpy(val->s, data, data_len);
	val->len = data_len;

	nats_dl.kvEntry_Destroy(entry);
	return 0;
}

/**
 * nats_cache_set() — store a key-value pair in the NATS KV store.
 *
 * Performs a kvStore_PutString to write (or overwrite) the value for the
 * given key.  The value is copied into a null-terminated buffer before
 * passing to the NATS C API.
 *
 * @param con      cachedb connection handle.
 * @param attr     Key (OpenSIPS str).
 * @param val      Value to store (OpenSIPS str).
 * @param expires  Per-key TTL in seconds.  Accepted for API compatibility
 *                 but ignored — NATS JetStream KV only supports bucket-level
 *                 TTL, which is configured at bucket creation time.
 * @return  0 on success, -1 on error.
 */
int nats_cache_set(cachedb_con *con, str *attr, str *val, int expires)
{
	nats_cachedb_con *ncon;
	natsStatus s;
	uint64_t rev;
	char key_buf[NATS_KEY_BUF_SIZE];

	if (!con || !attr || !val) {
		LM_ERR("null parameter\n");
		return -1;
	}
	/* A negative length would reach kvStore_Put as a garbage size. */
	if (val->len < 0) {
		LM_ERR("negative value length (%d)\n", val->len);
		return -1;
	}

	ncon = (nats_cachedb_con *)con->data;
	if (!ncon) {
		LM_ERR("null NATS connection\n");
		return -1;
	}
	if (nats_con_refresh_kv(ncon) < 0 || !ncon->kv) {
		LM_ERR("KV handle unavailable\n");
		return -1;
	}

	if (validate_kv_key(attr) < 0)
		return -1;
	if (nats_str_to_buf(attr, key_buf, sizeof(key_buf)) < 0)
		return -1;

	/* Generic cache_store() path: no per-key TTL here.  usrloc rows expire
	 * through the reaper (cachedb_nats_expiry.c). */
	if (expires > 0)
		LM_DBG("per-key TTL (%d s) ignored on generic cache_store — "
			"NATS KV uses bucket-level TTL on this path\n",
			expires);

	/* length-aware write: the value travels as (ptr,len) --
	 * the old NUL-termination copy (stack or a pkg alloc per >4 KB
	 * set) existed solely to feed kvStore_PutString, which would
	 * also silently truncate an embedded-NUL value. */
	s = nats_dl.kvStore_Put(&rev, ncon->kv, key_buf,
		(val->s && val->len > 0) ? val->s : NULL,
		val->len > 0 ? val->len : 0);

	if (s != NATS_OK) {
		char _rk[NATS_REDACT_KEY_BUF];
		nats_redact_key(key_buf, _rk, sizeof(_rk));
		LM_ERR("kvStore_Put failed for key '%s': %s\n",
			_rk, NATS_ERR_TEXT(s));
		NATS_CDB_STATS_INC(op_failed);
		return -1;
	}

	LM_DBG("SET '%s' rev=%llu\n", key_buf, (unsigned long long)rev);
	return 0;
}

/**
 * nats_cache_remove() — delete a key from the NATS KV store.
 *
 * Issues a nats_dl.kvStore_Delete(soft delete / purge marker) for the given key.
 * Deleting a key that does not exist is treated as success to maintain
 * idempotent semantics expected by the cachedb framework.
 *
 * @param con   cachedb connection handle.
 * @param attr  Key to delete (OpenSIPS str).
 * @return  0 on success (including "key not found"), -1 on error.
 */
int nats_cache_remove(cachedb_con *con, str *attr)
{
	nats_cachedb_con *ncon;
	natsStatus s;
	char key_buf[NATS_KEY_BUF_SIZE];

	if (!con || !attr) {
		LM_ERR("null parameter\n");
		return -1;
	}

	ncon = (nats_cachedb_con *)con->data;
	if (!ncon) {
		LM_ERR("null NATS connection\n");
		return -1;
	}
	if (nats_con_refresh_kv(ncon) < 0 || !ncon->kv) {
		LM_ERR("KV handle unavailable\n");
		return -1;
	}

	if (validate_kv_key(attr) < 0)
		return -1;
	if (nats_str_to_buf(attr, key_buf, sizeof(key_buf)) < 0)
		return -1;

	s = nats_dl.kvStore_Delete(ncon->kv, key_buf);
	if (s != NATS_OK && s != NATS_NOT_FOUND) {
		char _rk[NATS_REDACT_KEY_BUF];
		nats_redact_key(key_buf, _rk, sizeof(_rk));
		LM_ERR("kvStore_Delete failed for key '%s': %s\n",
			_rk, NATS_ERR_TEXT(s));
		NATS_CDB_STATS_INC(op_failed);
		return -1;
	}

	LM_DBG("DELETE '%s' (%s)\n", key_buf,
		s == NATS_NOT_FOUND ? "not found" : "ok");
	return 0;
}

/**
 * nats_cache_remove_unsupported() — non-NULL "unsupported" stub for the
 * cachedb_funcs._remove slot.
 *
 * _remove deletes a federation-metadata entry by named key and is only invoked
 * in CM_FEDERATION_CACHEDB metadata maintenance (usrloc udomain.c:1315), which
 * cachedb_nats does not implement.  usrloc full-sharing-cachedb never reaches it.
 * It exists purely so a wrong-mode/misconfigured deployment that *does* call it
 * fails loudly instead of dispatching through a NULL pointer and crashing.
 *
 * Dereferences NOTHING (con/attr/key may be anything a misconfigured caller
 * passes); returns -1 unconditionally after a single LM_ERR.
 */
int nats_cache_remove_unsupported(cachedb_con *con, str *attr, const str *key)
{
	(void)con; (void)attr; (void)key;
	LM_ERR("_remove not supported by cachedb_nats (use full-sharing mode)\n");
	return -1;
}

/**
 * nats_cache_counter_op() — atomic counter increment/decrement via CAS.
 *
 * Implements an atomic read-modify-write cycle using NATS KV revisions
 * as the compare-and-swap mechanism:
 *
 *   1. Read the current value and its revision number (kvStore_Get).
 *   2. Parse the value as an integer, apply the delta.
 *   3. Write the new value back, conditioned on the revision not having
 *      changed (kvStore_UpdateString with last_rev).
 *   4. If another writer modified the key between steps 1 and 3, the
 *      update fails with a CAS conflict — retry from step 1.
 *
 * If the key does not exist yet, kvStore_CreateString is used instead
 * (initial value = delta).  Retries up to the nats_cas_retries modparam
 * (default 10) times.
 *
 * @param con      cachedb connection handle.
 * @param attr     Counter key (OpenSIPS str).
 * @param delta    Value to add (positive) or subtract (negative).
 * @param expires  Per-key TTL (ignored, see nats_cache_set).
 * @param new_val  [out] Receives the new counter value on success (may be NULL).
 * @return  0 on success, -1 on error or CAS exhaustion.
 */
/* Strictly parse a stored counter value: a pure (optionally signed,
 * whitespace-padded) base-10 integer within the 32-bit range.  Returns 0 and
 * sets *out on success; -1 if the value is non-numeric, carries trailing
 * garbage, or is out of range -- a corrupt/hostile broker value.  A NULL value
 * (the counter does not exist yet) parses as 0, the create path.  strtoll alone
 * is not enough: it returns 0 with no error for a non-numeric value like "abc",
 * which would silently RESET the counter to `delta` instead of rejecting it. */
static int nats_counter_parse(const char *s, long long *out)
{
	char *endp;
	long long v;

	if (!s) { *out = 0; return 0; }
	errno = 0;
	v = strtoll(s, &endp, 10);
	if (endp == s)                       /* no digits consumed */
		return -1;
	while (*endp == ' ' || *endp == '\t' || *endp == '\n' || *endp == '\r')
		endp++;
	if (*endp != '\0')                   /* trailing garbage after the number */
		return -1;
	if (errno == ERANGE || v < INT_MIN || v > INT_MAX)
		return -1;
	*out = v;
	return 0;
}

static int nats_cache_counter_op(cachedb_con *con, str *attr, int delta,
	int expires, int *new_val)
{
	nats_cachedb_con *ncon;
	natsStatus s;
	kvEntry *entry = NULL;
	int64_t current;
	uint64_t last_rev, new_rev;
	int max_retries = nats_cas_retries > 0 ? nats_cas_retries : 1;
	int retries = max_retries;
	char key_buf[NATS_KEY_BUF_SIZE];
	char buf[32];

	if (!con || !attr) {
		LM_ERR("null parameter\n");
		return -1;
	}

	ncon = (nats_cachedb_con *)con->data;
	if (!ncon) {
		LM_ERR("null NATS connection\n");
		return -1;
	}
	if (nats_con_refresh_kv(ncon) < 0 || !ncon->kv) {
		LM_ERR("KV handle unavailable\n");
		return -1;
	}

	if (validate_kv_key(attr) < 0)
		return -1;
	if (nats_str_to_buf(attr, key_buf, sizeof(key_buf)) < 0)
		return -1;

	if (expires > 0)
		LM_DBG("per-key TTL (%d s) ignored for counter '%s'\n",
			expires, key_buf);

	/* CAS retry loop: each iteration reads the current value and
	 * attempts a conditional write.  On conflict (another process
	 * updated the key between our read and write), we re-read and
	 * try again, up to the nats_cas_retries modparam (default 10) times.
	 * Sleep with jittered
	 * exponential backoff between attempts to avoid hot-spinning
	 * the broker under contention. */
	int attempt = 0;
	while (retries-- > 0) {
		nats_cas_backoff_sleep(attempt);
		attempt++;
		current = 0;
		last_rev = 0;

		/* Step 1: read current value.  NATS_NOT_FOUND means the
		 * counter doesn't exist yet — we'll use CreateString below. */
		s = nats_dl.kvStore_Get(&entry, ncon->kv, key_buf);
		if (s == NATS_OK) {
			/* kvEntry lifecycle: extract value + revision, then
			 * destroy immediately — we don't need it after this. */
			const char *vs = nats_dl.kvEntry_ValueString(entry);
			long long parsed = 0;
			char cur_txt[64];
			/* Parse WHILE the entry is alive (vs points into it), then
			 * snapshot the text for diagnostics before destroying it --
			 * logging vs after kvEntry_Destroy would be a use-after-free.
			 * nats_counter_parse rejects a non-numeric / out-of-32-bit-range
			 * value rather than silently treating "abc" as 0 (which would
			 * reset the counter) or wrapping an over-range value. */
			int bad = nats_counter_parse(vs, &parsed) < 0;
			last_rev = nats_dl.kvEntry_Revision(entry);
			snprintf(cur_txt, sizeof(cur_txt), "%s", vs ? vs : "(null)");
			nats_dl.kvEntry_Destroy(entry);
			entry = NULL;
			if (bad) {
				char _rk[NATS_REDACT_KEY_BUF];
				nats_redact_key(key_buf, _rk, sizeof(_rk));
				LM_ERR("counter '%s' stored value is not a valid 32-bit "
					"integer ('%s'); refusing op\n", _rk, cur_txt);
				return -1;
			}
			current = parsed;
		}
		else if (s != NATS_NOT_FOUND) {
			char _rk[NATS_REDACT_KEY_BUF];
			nats_redact_key(key_buf, _rk, sizeof(_rk));
			LM_ERR("kvStore_Get failed for counter '%s': %s\n",
				_rk, NATS_ERR_TEXT(s));
			NATS_CDB_STATS_INC(op_failed);
			return -1;
		}

		/* Step 2: compute the new value in int64 (current and delta both
		 * fit in int range, so the sum cannot overflow int64) and reject
		 * — rather than silently wrap — a result that leaves the 32-bit
		 * range, which could otherwise bypass a throttle/admission limit. */
		{
			int64_t next = current + (int64_t)delta;
			if (next < INT_MIN || next > INT_MAX) {
				LM_ERR("counter '%s' increment by %d would overflow "
					"32-bit range (current %lld); op rejected\n",
					key_buf, delta, (long long)current);
				return -1;
			}
			current = next;
		}
		snprintf(buf, sizeof(buf), "%lld", (long long)current);

		/* Step 3: conditional write.  UpdateString checks that the
		 * key's revision still matches last_rev (CAS semantics).
		 * CreateString fails if the key already exists (another
		 * process created it between our Get and this call). */
		if (last_rev > 0)
			s = nats_dl.kvStore_UpdateString(&new_rev, ncon->kv, key_buf,
				buf, last_rev);
		else
			s = nats_dl.kvStore_CreateString(&new_rev, ncon->kv, key_buf, buf);

		if (s == NATS_OK) {
			if (new_val)
				*new_val = (int)current;
			LM_DBG("counter '%s' = %lld (rev=%llu)\n",
				key_buf, (long long)current,
				(unsigned long long)new_rev);
			return 0;
		}

		/* Only an actual CAS conflict (revision mismatch / key-exists)
		 * is worth retrying.  A timeout or connection error is not a
		 * conflict -- retrying it just burns the whole budget on a
		 * degraded broker, stalling the worker -- so bail immediately. */
		if (!nats_cas_should_retry(s) || !nats_pool_is_connected()) {
			LM_WARN("counter '%s' CAS write failed (%s); not a conflict "
				"-- bailing instead of exhausting the retry budget\n",
				key_buf, NATS_ERR_TEXT(s));
			return -1;
		}

		/* CAS conflict — another writer won the race.  Re-read + retry. */
		NATS_CDB_STATS_INC(cas_retry);
		LM_DBG("CAS retry for key '%s' (attempt %d)\n",
			key_buf, max_retries - retries);
	}

	NATS_CDB_STATS_INC(cas_exhausted);
	LM_WARN("CAS exhausted for counter '%s' after %d retries; "
		"increment dropped (raise nats_cas_retries if this key "
		"is hot-contested)\n",
		key_buf, max_retries);
	return -1;
}

/**
 * nats_cache_add() — atomically increment a counter in the KV store.
 *
 * Delegates to nats_cache_counter_op() with a positive delta (val).
 * The counter is stored as a string integer in the KV bucket.
 *
 * @param con      cachedb connection handle.
 * @param attr     Counter key (OpenSIPS str).
 * @param val      Amount to add.
 * @param expires  Per-key TTL (ignored).
 * @param new_val  [out] Receives the new counter value (may be NULL).
 * @return  0 on success, -1 on error.
 */
int nats_cache_add(cachedb_con *con, str *attr, int val, int expires,
	int *new_val)
{
	return nats_cache_counter_op(con, attr, val, expires, new_val);
}

/**
 * nats_cache_sub() — atomically decrement a counter in the KV store.
 *
 * Delegates to nats_cache_counter_op() with a negated delta (-val).
 * The counter is stored as a string integer in the KV bucket.
 *
 * @param con      cachedb connection handle.
 * @param attr     Counter key (OpenSIPS str).
 * @param val      Amount to subtract.
 * @param expires  Per-key TTL (ignored).
 * @param new_val  [out] Receives the new counter value (may be NULL).
 * @return  0 on success, -1 on error.
 */
int nats_cache_sub(cachedb_con *con, str *attr, int val, int expires,
	int *new_val)
{
	return nats_cache_counter_op(con, attr, -val, expires, new_val);
}

/**
 * nats_cache_get_counter() — read a numeric counter value from the KV store.
 *
 * Retrieves the value for the given key and parses it strictly via
 * nats_counter_parse(): a non-numeric or out-of-32-bit-range stored value
 * is rejected with -1 rather than silently coerced to 0.  The value is a
 * decimal string written by nats_cache_counter_op() (via nats_cache_add /
 * nats_cache_sub).
 *
 * @param con   cachedb connection handle.
 * @param attr  Counter key (OpenSIPS str).
 * @param val   [out] Receives the integer counter value on success.
 * @return  0  on success,
 *         -1  on error,
 *         -2  if the key was not found.
 */
int nats_cache_get_counter(cachedb_con *con, str *attr, int *val)
{
	nats_cachedb_con *ncon;
	kvEntry *entry = NULL;
	natsStatus s;
	char key_buf[NATS_KEY_BUF_SIZE];

	if (!con || !attr || !val) {
		LM_ERR("null parameter\n");
		return -1;
	}

	ncon = (nats_cachedb_con *)con->data;
	if (!ncon) {
		LM_ERR("null NATS connection\n");
		return -1;
	}
	if (nats_con_refresh_kv(ncon) < 0 || !ncon->kv) {
		LM_ERR("KV handle unavailable\n");
		return -1;
	}

	if (validate_kv_key(attr) < 0)
		return -1;
	if (nats_str_to_buf(attr, key_buf, sizeof(key_buf)) < 0)
		return -1;

	/* kvEntry lifecycle: Get allocates, we read, then Destroy. */
	s = nats_dl.kvStore_Get(&entry, ncon->kv, key_buf);

	/* NATS_NOT_FOUND → return -2 so the cachedb framework knows the
	 * counter has not been initialised yet (distinct from error). */
	if (s == NATS_NOT_FOUND) {
		LM_DBG("counter not found: '%s'\n", key_buf);
		return -2;
	}
	if (s != NATS_OK) {
		char _rk[NATS_REDACT_KEY_BUF];
		nats_redact_key(key_buf, _rk, sizeof(_rk));
		LM_ERR("kvStore_Get failed for counter '%s': %s\n",
			_rk, NATS_ERR_TEXT(s));
		NATS_CDB_STATS_INC(op_failed);
		return -1;
	}

	/* Parse the string value as an integer; kvEntry_ValueString returns
	 * a pointer valid only while entry is alive.  Range-check before the
	 * 32-bit store so a broker value beyond INT range is rejected rather
	 * than silently truncated. */
	{
		const char *val_str = nats_dl.kvEntry_ValueString(entry);
		long long parsed = 0;
		/* Reject a non-numeric / out-of-32-bit-range stored value rather than
		 * silently returning 0 (strtoll's result for "abc") or a truncated
		 * int.  Parse while the entry is alive; val_str points into it. */
		if (nats_counter_parse(val_str, &parsed) < 0) {
			char _rk[NATS_REDACT_KEY_BUF];
			nats_redact_key(key_buf, _rk, sizeof(_rk));
			LM_ERR("counter '%s' value is not a valid 32-bit integer "
				"('%s')\n", _rk, val_str ? val_str : "(null)");
			nats_dl.kvEntry_Destroy(entry);
			return -1;
		}
		*val = (int)parsed;
	}
	nats_dl.kvEntry_Destroy(entry);

	LM_DBG("GET_COUNTER '%s' = %d\n", key_buf, *val);
	return 0;
}

/* raw_query moved to cachedb_nats_native.c as nats_cache_raw_query_impl() */
