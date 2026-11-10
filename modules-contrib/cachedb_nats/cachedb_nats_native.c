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
 * cachedb_nats_native.c — Advanced NATS operations beyond basic cachedb
 *
 * This file provides extended NATS functionality that goes beyond the standard
 * cachedb get/set/remove interface:
 *
 *   - KV history:  Retrieves the full version history of a NATS KV key
 *     and returns it as a JSON array (w_nats_kv_history).
 *
 *   - Raw commands:  A cachedb raw_query dispatcher that supports KV KEYS,
 *     KV PURGE, and KV BUCKET INFO commands (nats_cache_raw_query_impl).
 *
 *   - Map operations:  Composite key (prefix:subkey) operations that emulate
 *     hash-map semantics on top of flat NATS KV (nats_cache_map_get/set/remove).
 *
 * All functions in this file run on OpenSIPS worker process threads (post-fork).
 * They use pkg_malloc for per-process allocations and access shared NATS
 * connections via the nats_pool API.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <stdint.h>

#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../pvar.h"
#include "../../cachedb/cachedb.h"

#include "cachedb_nats_native.h"
#include "cachedb_nats.h"
#include "cachedb_nats_dbase.h"
#include "../nats/nats_bind.h"
#include "../nats/nats_pool.h"
#include "../nats/nats_redact.h"   /* nats_redact_key */
#include "../nats/nats_rl.h"   /* rate-limited outage WARN */
#include "cachedb_nats_expiry.h"
#include "../nats/nats_str.h"
#include "../nats/nats_err.h"   /* NATS_ERR_TEXT */
#include "../../mi/mi.h"
#include "../../mi/item.h"

#ifdef UNIT_TESTS
/* the unit tests make a pvar write fail / capture what is written */
int (*cn_ut_pv_set_value)(struct sip_msg *msg, pv_spec_p sp, int op,
	pv_value_t *value) = pv_set_value;
#define pv_set_value(m, s, o, v) cn_ut_pv_set_value((m), (s), (o), (v))
#endif

/* maximum buffer sizes (reuse from dbase.h) */
#define NATS_NATIVE_KEY_BUF   512
#define NATS_NATIVE_VAL_BUF   4096
#define NATS_MAP_KEY_BUF      1024
#define NATS_HISTORY_BUF      8192
#define NATS_RAW_CMD_BUF      256

/* Structural separator between the (hex-escaped) map key and field in a
 * composed map subject:  enc(key) '.' enc(field).  '.' is the NATS subject
 * token separator, so an exact server-side prefix filter "enc(key).>" can
 * list one map without scanning the whole bucket.  Both components are
 * hex-escaped (nats_map_encode) so they never contain a raw '.', keeping the
 * structure unambiguous and letting users put any byte in a key/field. */
#define NATS_MAP_SEP    '.'

/* nats_str_to_buf() was consolidated into modules-contrib/nats/nats_str.h as
 * nats_str_to_buf(). */

/* The synchronous request/reply script function was removed:
 * the nats_consumer module's request/reply export is the single owner
 * (headers + async support). */

/* ================================================================== */
/*               Script function: nats_kv_history                     */
/* ================================================================== */

/**
 * Retrieve the version history of a KV key as a JSON array.
 *
 * Script usage:
 *   nats_kv_history("usrloc.alice", $var(history));
 *   # $var(history) = [{"rev":1,"value":"..."},{"rev":2,"value":"..."}]
 *
 * Returns:
 *   1  success (JSON array stored in result_var)
 *  -1  error
 *  -2  key not found
 */
int w_nats_kv_history(struct sip_msg *msg, str *key, pv_spec_t *result_var)
{
	kvStore *kv;
	kvEntryList list;
	natsStatus s;
	char key_buf[NATS_NATIVE_KEY_BUF];
	char *buf;
	int buf_size = NATS_HISTORY_BUF;
	int pos, i, entry_count, hist_trunc;
	pv_value_t val;

	if (!key || !result_var) {
		LM_ERR("null parameter\n");
		return -1;
	}
	if (validate_kv_key(key) < 0)
		return -1;

	/* Fast-fail when the broker is down (see the other w_nats_kv_* ops). */
	if (!nats_pool_is_connected()) {
		nats_cdb_disconnected_warn("kv_history");
		LM_DBG("NATS disconnected — kv_history deferred (fast-fail)\n");
		return -1;
	}

	/* get KV store from the shared pool */
	kv = nats_pool_get_kv(kv_bucket, kv_replicas, kv_history,
		(int64_t)kv_ttl);
	if (!kv) {
		LM_ERR("failed to get KV store for bucket '%s'\n", kv_bucket);
		return -1;
	}

	if (nats_str_to_buf(key, key_buf, sizeof(key_buf)) < 0)
		return -1;

	memset(&list, 0, sizeof(list));
	s = nats_dl.kvStore_History(&list, kv, key_buf, NULL);

	if (s == NATS_NOT_FOUND) {
		LM_DBG("key '%s' not found in history\n", key_buf);
		return -2;
	}
	if (s != NATS_OK) {
		char _rk[NATS_REDACT_KEY_BUF];
		nats_redact_key(key_buf, _rk, sizeof(_rk));
		LM_ERR("kvStore_History failed for '%s': %s\n",
			_rk, NATS_ERR_TEXT(s));
		return -1;
	}

	entry_count = list.Count;

	/* build JSON array of historical values */
	buf = pkg_malloc(buf_size);
	if (!buf) {
		LM_ERR("no more pkg memory for history buffer\n");
		nats_dl.kvEntryList_Destroy(&list);
		return -1;
	}

	pos = 0;
	hist_trunc = 0;

	/* snprintf() returns the number of bytes it WOULD have written, which
	 * on truncation exceeds the size limit and can push `pos` past
	 * buf_size.  The next call would then compute buf_size - pos as a
	 * negative int that converts to a huge size_t, defeating the bound
	 * and overrunning the buffer.  Clamp pos after every advance so the
	 * remaining size can never underflow. */
#define HIST_ADVANCE(...) do { \
		int _w = snprintf(buf + pos, (size_t)(buf_size - pos), \
			__VA_ARGS__); \
		if (_w < 0) { pos = buf_size - 1; hist_trunc = 1; } \
		else { \
			pos += _w; \
			if (pos >= buf_size) { pos = buf_size - 1; hist_trunc = 1; } \
		} \
	} while (0)

	HIST_ADVANCE("[");

	for (i = 0; i < list.Count && pos < buf_size - 128; i++) {
		kvEntry *e = list.Entries[i];
		const char *eval = nats_dl.kvEntry_ValueString(e);
		int eval_len = nats_dl.kvEntry_ValueLen(e);

		if (i > 0)
			HIST_ADVANCE(",");

		/* JSON-encode: escape quotes in value for safety */
		HIST_ADVANCE("{\"rev\":%llu,\"value\":\"",
			(unsigned long long)nats_dl.kvEntry_Revision(e));

		/* JSON string escape.  '"' and '\' get a backslash; control chars
		 * (< 0x20) are NOT legal raw in a JSON string and would produce
		 * malformed output, so escape them as \u00xx.  The direct
		 * buf[pos++] writes bypass snprintf bounds checking; a \u00xx
		 * escape needs 6 bytes plus the closing '"}' + NUL, so keep 9
		 * bytes of headroom. */
		int j;
		static const char _hex[] = "0123456789abcdef";
		for (j = 0; eval && j < eval_len && pos < buf_size - 9; j++) {
			unsigned char vc = (unsigned char)eval[j];
			if (vc == '"' || vc == '\\') {
				buf[pos++] = '\\';
				buf[pos++] = (char)vc;
			} else if (vc < 0x20) {
				buf[pos++] = '\\';
				buf[pos++] = 'u';
				buf[pos++] = '0';
				buf[pos++] = '0';
				buf[pos++] = _hex[vc >> 4];
				buf[pos++] = _hex[vc & 0x0f];
			} else {
				buf[pos++] = (char)vc;
			}
		}

		HIST_ADVANCE("\"}");
	}

	HIST_ADVANCE("]");
#undef HIST_ADVANCE

	/* the 8 KB clamp used to truncate SILENTLY -- the script
	 * then parses an incomplete (often malformed) JSON array with no
	 * hint why.  Rate-limited WARN + per-call DBG. */
	if (i < entry_count)
		hist_trunc = 1;
	if (hist_trunc) {
		static time_t rl_trunc;
		if (nats_rl_pass(&rl_trunc, time(NULL), 30)) {
			char _rk[NATS_REDACT_KEY_BUF];
			nats_redact_key(key_buf, _rk, sizeof(_rk));
			LM_WARN("kv_history('%s'): history JSON exceeds "
				"NATS_HISTORY_BUF (%d bytes) -- result truncated "
				"at %d/%d entries (repeats suppressed for 30s)\n",
				_rk, NATS_HISTORY_BUF, i, entry_count);
		}
		LM_DBG("kv_history('%s'): truncated at %d/%d entries\n",
			key_buf, i, entry_count);
	}

	nats_dl.kvEntryList_Destroy(&list);

	/* set result variable */
	memset(&val, 0, sizeof(val));
	val.flags = PV_VAL_STR;
	val.rs.s = buf;
	val.rs.len = pos;
	if (pv_set_value(msg, result_var, 0, &val) < 0) {
		LM_ERR("failed to set history pvar — script would read a stale "
			"value as this key's history\n");
		pkg_free(buf);
		return -1;
	}
	pkg_free(buf);

	LM_DBG("kv_history for '%s': %d entries, %d bytes JSON\n",
		key_buf, entry_count, pos);
	return 1;
}

/* ================================================================== */
/*          Script functions: nats_kv_get / put / update / delete     */
/* ================================================================== */

/**
 * Get a KV entry's value and optionally its revision number.
 *
 * Script usage:
 *   nats_kv_get("opensips", "asr.model", $var(val), $var(rev));
 *   nats_kv_get("opensips", "asr.model", $var(val));  # rev is optional
 *
 * Returns:
 *   1  success (value and optionally revision stored)
 *  -1  error
 *  -2  key not found
 */
int w_nats_kv_get(struct sip_msg *msg, str *bucket, str *key,
                  pv_spec_t *value_var, pv_spec_t *rev_var)
{
	kvStore *kv;
	kvEntry *entry = NULL;
	natsStatus s;
	char bucket_buf[NATS_NATIVE_KEY_BUF];
	char key_buf[NATS_NATIVE_KEY_BUF];
	pv_value_t val;

	if (!bucket || !key || !value_var) {
		LM_ERR("null parameter\n");
		return -1;
	}
	if (validate_kv_key(key) < 0)
		return -1;

	if (nats_str_to_buf(bucket, bucket_buf, sizeof(bucket_buf)) < 0)
		return -1;
	if (nats_str_to_buf(key, key_buf, sizeof(key_buf)) < 0)
		return -1;

	/* Fast-fail when the broker is down: nats_pool_get_kv() + kvStore_*
	 * on a disconnected pool blocks the SIP worker and can hit cnats's
	 * "free(): invalid pointer" reconnect race. */
	if (!nats_pool_is_connected()) {
		nats_cdb_disconnected_warn("KV operation");
		LM_DBG("NATS disconnected — KV operation deferred (fast-fail)\n");
		return -1;
	}
	kv = nats_pool_get_kv(bucket_buf[0] ? bucket_buf : kv_bucket,
		kv_replicas, kv_history, (int64_t)kv_ttl);
	if (!kv) {
		LM_ERR("failed to get KV store for bucket '%s'\n",
			bucket_buf[0] ? bucket_buf : kv_bucket);
		return -1;
	}

	s = nats_dl.kvStore_Get(&entry, kv, key_buf);
	if (s == NATS_NOT_FOUND) {
		LM_DBG("key '%s' not found\n", key_buf);
		return -2;
	}
	if (s != NATS_OK) {
		char _rk[NATS_REDACT_KEY_BUF];
		nats_redact_key(key_buf, _rk, sizeof(_rk));
		LM_ERR("kvStore_Get failed for '%s': %s\n",
			_rk, NATS_ERR_TEXT(s));
		return -1;
	}

	/* Copy the value out of the kvEntry into worker-local memory before
	 * destroying the entry — defensive copy-before-destroy pattern.
	 * Every current OpenSIPS pvar setter copies PV_VAL_STR data, so the
	 * existing inline use was safe today, but the explicit copy keeps
	 * us robust if any future module-defined pvar setter forgets to. */
	{
		const char *entry_val = nats_dl.kvEntry_ValueString(entry);
		int entry_len = nats_dl.kvEntry_ValueLen(entry);
		uint64_t rev = nats_dl.kvEntry_Revision(entry);
		char *value_copy = pkg_malloc(entry_len + 1);
		if (!value_copy) {
			LM_ERR("no more pkg memory for kv value (%d bytes)\n",
				entry_len);
			nats_dl.kvEntry_Destroy(entry);
			return -1;
		}
		memcpy(value_copy, entry_val, entry_len);
		value_copy[entry_len] = '\0';
		nats_dl.kvEntry_Destroy(entry);
		entry = NULL;

		/* set value pvar */
		memset(&val, 0, sizeof(val));
		val.flags = PV_VAL_STR;
		val.rs.s = value_copy;
		val.rs.len = entry_len;
		if (pv_set_value(msg, value_var, 0, &val) < 0) {
			char _rk[NATS_REDACT_KEY_BUF];
			nats_redact_key(key_buf, _rk, sizeof(_rk));
			LM_ERR("failed to set value pvar — script would read a "
				"stale value as key '%s'\n", _rk);
			pkg_free(value_copy);
			return -1;
		}

		/* set revision pvar (optional)
		 *
		 * Set both PV_VAL_STR and PV_VAL_INT so the rev can drive a
		 * subsequent nats_kv_update() — that wrapper takes
		 * CMD_PARAM_INT, and core's get_cmd_fixups() rejects script
		 * vars that lack PV_VAL_INT with "Variable in param [N] is not
		 * an integer" (mod_fix.c:366-370).  Without the int flag CAS
		 * is unusable from script.
		 *
		 * Truncation: NATS revisions are uint64; OpenSIPS script ints
		 * are 32-bit.  In practice INT_MAX revisions per key is many
		 * decades of updates; we warn if we ever cross it. */
		if (rev_var) {
			char rev_buf[24];
			int rev_buf_len = snprintf(rev_buf, sizeof(rev_buf), "%llu",
				(unsigned long long)rev);
			if (rev > (uint64_t)INT_MAX) {
				LM_WARN("KV revision %llu for '%s' exceeds INT_MAX; "
					"script var will receive a truncated int — CAS using "
					"this var will fail\n",
					(unsigned long long)rev, key_buf);
			}
			memset(&val, 0, sizeof(val));
			/* PV_TYPE_INT tells pv_set_scriptvar to store the var as int
			 * (avp_val.n); without it the setter falls back to str storage
			 * and the next read will not restore PV_VAL_INT, so CAS via
			 * nats_kv_update($var(rev)) is rejected at fixup time with
			 * "Variable in param [N] is not an integer". */
			val.flags = PV_VAL_STR | PV_VAL_INT | PV_TYPE_INT;
			val.rs.s = rev_buf;
			val.rs.len = rev_buf_len;
			val.ri = (int)rev;
			if (pv_set_value(msg, rev_var, 0, &val) < 0) {
				LM_ERR("failed to set revision pvar — a CAS "
					"update from this rev would be stale\n");
				pkg_free(value_copy);
				return -1;
			}
		}

		LM_DBG("nats_kv_get '%s' = '%.*s' (rev=%llu)\n",
			key_buf, entry_len, value_copy,
			(unsigned long long)rev);

		pkg_free(value_copy);
	}
	return 1;
}

/**
 * Unconditional write to KV store.
 *
 * Script usage:
 *   nats_kv_put("opensips", "call.$ci.state", "recording");
 *
 * Returns:
 *   1  success
 *  -1  error
 */
int w_nats_kv_put(struct sip_msg *msg, str *bucket, str *key, str *value)
{
	kvStore *kv;
	natsStatus s;
	uint64_t rev;
	char bucket_buf[NATS_NATIVE_KEY_BUF];
	char key_buf[NATS_NATIVE_KEY_BUF];

	if (!bucket || !key || !value) {
		LM_ERR("null parameter\n");
		return -1;
	}
	if (validate_kv_key(key) < 0)
		return -1;

	if (nats_str_to_buf(bucket, bucket_buf, sizeof(bucket_buf)) < 0)
		return -1;
	if (nats_str_to_buf(key, key_buf, sizeof(key_buf)) < 0)
		return -1;

	/* Fast-fail when the broker is down: nats_pool_get_kv() + kvStore_*
	 * on a disconnected pool blocks the SIP worker and can hit cnats's
	 * "free(): invalid pointer" reconnect race.  Checked BEFORE the value
	 * copy — a bare return after the copy would
	 * leak the heap buffer on every call for the whole outage. */
	if (!nats_pool_is_connected()) {
		nats_cdb_disconnected_warn("KV operation");
		LM_DBG("NATS disconnected — KV operation deferred (fast-fail)\n");
		return -1;
	}

	kv = nats_pool_get_kv(bucket_buf[0] ? bucket_buf : kv_bucket,
		kv_replicas, kv_history, (int64_t)kv_ttl);
	if (!kv) {
		LM_ERR("failed to get KV store for bucket '%s'\n",
			bucket_buf[0] ? bucket_buf : kv_bucket);
		return -1;
	}

	/* length-aware write: the value travels as (ptr,len)
	 * uncopied -- the old NUL-termination copy (stack, or a pkg alloc
	 * per >4 KB value) fed kvStore_PutString, which would also
	 * silently truncate an embedded-NUL value. */
	s = nats_dl.kvStore_Put(&rev, kv, key_buf,
		(value->s && value->len > 0) ? value->s : NULL,
		value->len > 0 ? value->len : 0);
	if (s != NATS_OK) {
		char _rk[NATS_REDACT_KEY_BUF];
		nats_redact_key(key_buf, _rk, sizeof(_rk));
		LM_ERR("kvStore_Put failed for '%s': %s\n",
			_rk, NATS_ERR_TEXT(s));
		return -1;
	}

	LM_DBG("nats_kv_put '%s' rev=%llu\n", key_buf, (unsigned long long)rev);
	return 1;
}

/**
 * Conditional (CAS) write to KV store.
 *
 * Script usage:
 *   nats_kv_get("opensips", "key", $var(val), $var(rev));
 *   # ... modify $var(val) ...
 *   nats_kv_update("opensips", "key", $var(new_val), $var(rev));
 *   # returns -2 on revision mismatch (concurrent update)
 *
 * Returns:
 *   1  success (CAS succeeded)
 *  -1  error
 *  -2  revision mismatch (caller should retry)
 */
int w_nats_kv_update(struct sip_msg *msg, str *bucket, str *key,
                     str *value, int *expected_rev)
{
	kvStore *kv;
	uint64_t new_rev = 0;
	char bucket_buf[NATS_NATIVE_KEY_BUF];
	char key_buf[NATS_NATIVE_KEY_BUF];
	int rc;

	if (!bucket || !key || !value || !expected_rev) {
		LM_ERR("null parameter\n");
		return -1;
	}
	if (validate_kv_key(key) < 0)
		return -1;

	if (nats_str_to_buf(bucket, bucket_buf, sizeof(bucket_buf)) < 0)
		return -1;
	if (nats_str_to_buf(key, key_buf, sizeof(key_buf)) < 0)
		return -1;

	/* Fast-fail when the broker is down: nats_pool_get_kv() + kvStore_*
	 * on a disconnected pool blocks the SIP worker and can hit cnats's
	 * "free(): invalid pointer" reconnect race.  Checked BEFORE the value
	 * copy — a bare return after the copy would
	 * leak the heap buffer on every call for the whole outage. */
	if (!nats_pool_is_connected()) {
		nats_cdb_disconnected_warn("KV operation");
		LM_DBG("NATS disconnected — KV operation deferred (fast-fail)\n");
		return -1;
	}

	kv = nats_pool_get_kv(bucket_buf[0] ? bucket_buf : kv_bucket,
		kv_replicas, kv_history, (int64_t)kv_ttl);
	if (!kv) {
		LM_ERR("failed to get KV store for bucket '%s'\n",
			bucket_buf[0] ? bucket_buf : kv_bucket);
		rc = -1;
		goto out;
	}

	/* Route the CAS through nats_kv_put_row (js_PublishMsg with
	 * ExpectLastSubjectSeq == *expected_rev -- byte-for-byte the optimistic
	 * check kvStore_UpdateString(rev) performs) rather than
	 * kvStore_UpdateString itself.  js_PublishMsg returns the numeric
	 * jsErrCode inline, so we can distinguish a genuine revision conflict
	 * (10071 -> TTL_RETRY -> -2, the caller re-reads and retries) from a
	 * generic/transient failure (-1, not retryable).  The old path collapsed
	 * every NATS_ERR into -2, so a script CAS loop could spin on a
	 * non-retryable error.  got_entry=1: an existing row updated at rev. */
	{
		jsCtx *js = nats_pool_get_js();
		/* the value rides (ptr,len) into the CAS write
		 * uncopied -- nats_kv_put_row is length-aware end to end. */
		enum ttl_outcome o = nats_kv_put_row(js, kv,
			bucket_buf[0] ? bucket_buf : kv_bucket, key_buf,
			(value->s && value->len > 0) ? value->s : NULL,
			value->len > 0 ? value->len : 0,
			/*got_entry=*/1, (uint64_t)*expected_rev, &new_rev);

		if (o == TTL_RETRY) {
			LM_DBG("CAS mismatch for '%s' (expected rev %d)\n",
				key_buf, *expected_rev);
			rc = -2;
			goto out;
		}
		if (o != TTL_DONE) {
			char _rk[NATS_REDACT_KEY_BUF];
			nats_redact_key(key_buf, _rk, sizeof(_rk));
			LM_ERR("kv update CAS failed for '%s' (outcome %d)\n",
				_rk, (int)o);
			rc = -1;
			goto out;
		}
	}

	LM_DBG("nats_kv_update '%s' rev=%llu (was %d)\n",
		key_buf, (unsigned long long)new_rev, *expected_rev);
	rc = 1;
out:
	return rc;
}

/**
 * Delete a key from the KV store.
 *
 * Script usage:
 *   nats_kv_delete("opensips", "call.$ci.state");
 *
 * Returns:
 *   1  success
 *  -1  error
 */
int w_nats_kv_delete(struct sip_msg *msg, str *bucket, str *key)
{
	kvStore *kv;
	natsStatus s;
	char bucket_buf[NATS_NATIVE_KEY_BUF];
	char key_buf[NATS_NATIVE_KEY_BUF];

	if (!bucket || !key) {
		LM_ERR("null parameter\n");
		return -1;
	}
	if (validate_kv_key(key) < 0)
		return -1;

	if (nats_str_to_buf(bucket, bucket_buf, sizeof(bucket_buf)) < 0)
		return -1;
	if (nats_str_to_buf(key, key_buf, sizeof(key_buf)) < 0)
		return -1;

	/* Fast-fail when the broker is down: nats_pool_get_kv() + kvStore_*
	 * on a disconnected pool blocks the SIP worker and can hit cnats's
	 * "free(): invalid pointer" reconnect race. */
	if (!nats_pool_is_connected()) {
		nats_cdb_disconnected_warn("KV operation");
		LM_DBG("NATS disconnected — KV operation deferred (fast-fail)\n");
		return -1;
	}
	kv = nats_pool_get_kv(bucket_buf[0] ? bucket_buf : kv_bucket,
		kv_replicas, kv_history, (int64_t)kv_ttl);
	if (!kv) {
		LM_ERR("failed to get KV store for bucket '%s'\n",
			bucket_buf[0] ? bucket_buf : kv_bucket);
		return -1;
	}

	s = nats_dl.kvStore_Delete(kv, key_buf);
	if (s != NATS_OK) {
		char _rk[NATS_REDACT_KEY_BUF];
		nats_redact_key(key_buf, _rk, sizeof(_rk));
		LM_ERR("kvStore_Delete failed for '%s': %s\n",
			_rk, NATS_ERR_TEXT(s));
		return -1;
	}

	LM_DBG("nats_kv_delete '%s'\n", key_buf);
	return 1;
}

/**
 * Read only the revision number of a KV key (lightweight check).
 *
 * Script usage:
 *   nats_kv_revision("opensips", "asr.model", $var(rev));
 *
 * Returns:
 *   1  success (revision stored)
 *  -1  error
 *  -2  key not found
 */
int w_nats_kv_revision(struct sip_msg *msg, str *bucket, str *key,
                       pv_spec_t *rev_var)
{
	kvStore *kv;
	kvEntry *entry = NULL;
	natsStatus s;
	char bucket_buf[NATS_NATIVE_KEY_BUF];
	char key_buf[NATS_NATIVE_KEY_BUF];
	pv_value_t val;

	if (!bucket || !key || !rev_var) {
		LM_ERR("null parameter\n");
		return -1;
	}
	if (validate_kv_key(key) < 0)
		return -1;

	if (nats_str_to_buf(bucket, bucket_buf, sizeof(bucket_buf)) < 0)
		return -1;
	if (nats_str_to_buf(key, key_buf, sizeof(key_buf)) < 0)
		return -1;

	/* Fast-fail when the broker is down: nats_pool_get_kv() + kvStore_*
	 * on a disconnected pool blocks the SIP worker and can hit cnats's
	 * "free(): invalid pointer" reconnect race. */
	if (!nats_pool_is_connected()) {
		nats_cdb_disconnected_warn("KV operation");
		LM_DBG("NATS disconnected — KV operation deferred (fast-fail)\n");
		return -1;
	}
	kv = nats_pool_get_kv(bucket_buf[0] ? bucket_buf : kv_bucket,
		kv_replicas, kv_history, (int64_t)kv_ttl);
	if (!kv) {
		LM_ERR("failed to get KV store for bucket '%s'\n",
			bucket_buf[0] ? bucket_buf : kv_bucket);
		return -1;
	}

	s = nats_dl.kvStore_Get(&entry, kv, key_buf);
	if (s == NATS_NOT_FOUND) {
		LM_DBG("key '%s' not found\n", key_buf);
		return -2;
	}
	if (s != NATS_OK) {
		char _rk[NATS_REDACT_KEY_BUF];
		nats_redact_key(key_buf, _rk, sizeof(_rk));
		LM_ERR("kvStore_Get failed for '%s': %s\n",
			_rk, NATS_ERR_TEXT(s));
		return -1;
	}

	uint64_t rev = nats_dl.kvEntry_Revision(entry);
	char rev_buf[24];
	int rev_buf_len;
	nats_dl.kvEntry_Destroy(entry);

	rev_buf_len = snprintf(rev_buf, sizeof(rev_buf), "%llu",
		(unsigned long long)rev);
	if (rev > (uint64_t)INT_MAX) {
		LM_WARN("KV revision %llu for '%s' exceeds INT_MAX; "
			"script var will receive a truncated int — CAS using "
			"this var will fail\n",
			(unsigned long long)rev, key_buf);
	}
	memset(&val, 0, sizeof(val));
	/* See the matching block in w_nats_kv_get for the rationale on
	 * PV_TYPE_INT — without it pv_set_scriptvar stores the var as a
	 * string and a subsequent CMD_PARAM_INT read fails. */
	val.flags = PV_VAL_STR | PV_VAL_INT | PV_TYPE_INT;
	val.rs.s = rev_buf;
	val.rs.len = rev_buf_len;
	val.ri = (int)rev;
	if (pv_set_value(msg, rev_var, 0, &val) < 0) {
		char _rk[NATS_REDACT_KEY_BUF];
		nats_redact_key(key_buf, _rk, sizeof(_rk));
		LM_ERR("failed to set revision pvar — script would read a "
			"stale revision for key '%s'\n", _rk);
		return -1;
	}

	LM_DBG("nats_kv_revision '%s' = %llu\n",
		key_buf, (unsigned long long)rev);
	return 1;
}

/* ================================================================== */
/*                     cachedb raw_query                              */
/* ================================================================== */

/* Forward declarations for raw_query sub-commands */
static int raw_kv_keys(kvStore *kv, cdb_raw_entry ***reply,
                       int expected_kv_no, int *reply_no);
static int raw_kv_purge(kvStore *kv, const char *key);
static int raw_kv_bucket_info(kvStore *kv, cdb_raw_entry ***reply,
                              int expected_kv_no, int *reply_no);

/**
 * nats_cache_raw_query_impl() — Dispatch raw NATS-specific commands.
 *
 * Implements the cachedb raw_query callback, providing a text-based command
 * interface for NATS operations that do not map to standard cachedb verbs.
 * The command string is tokenized with strtok_r (up to 3 space-delimited
 * tokens) and dispatched to the appropriate handler.
 *
 * Supported commands:
 *   "KV KEYS"              - list all keys in the bucket (raw_kv_keys)
 *   "KV PURGE <key>"       - purge all revisions of a key (raw_kv_purge)
 *   "KV BUCKET INFO"       - return bucket statistics (raw_kv_bucket_info)
 *   "STREAM INFO <name>"   - placeholder (not implemented)
 *   "STREAM PURGE <name>"  - placeholder (not implemented)
 *
 * Returns: 0 on success, -1 on error.
 */
int nats_cache_raw_query_impl(cachedb_con *con, str *attr,
                              cdb_raw_entry ***reply, int expected_kv_no,
                              int *reply_no)
{
	nats_cachedb_con *ncon;
	char cmd_buf[NATS_RAW_CMD_BUF];
	char *tok1, *tok2, *tok3, *saveptr;

	/* Zero the out-params FIRST so every failure return below leaves
	 * them deterministic -- the API contract does not require callers
	 * to pre-initialize them, and a -1 with garbage *reply_no / *reply
	 * is a latent crash in any caller that checks them before rc (see
	 * the matching cdb_res_init fix in nats_cache_query). */
	if (reply)
		*reply = NULL;
	if (reply_no)
		*reply_no = 0;

	if (!con || !attr || !attr->s || attr->len <= 0) {
		LM_ERR("null or empty raw_query command\n");
		return -1;
	}

	ncon = (nats_cachedb_con *)con->data;
	if (!ncon) {
		LM_ERR("null NATS connection\n");
		return -1;
	}
	/* Fast-fail on a down broker and refresh the KV handle after a
	 * reconnect; otherwise this op blocks the worker during an outage and
	 * can reuse a destroyed handle after reconnect (see nats_con_refresh_kv). */
	if (nats_con_refresh_kv(ncon) < 0 || !ncon->kv) {
		LM_DBG("NATS unavailable — operation deferred (fast-fail)\n");
		return -1;
	}

	if (nats_str_to_buf(attr, cmd_buf, sizeof(cmd_buf)) < 0)
		return -1;

	/* Tokenize the command string using strtok_r (reentrant).  We parse
	 * up to 3 space/tab-delimited tokens from the local cmd_buf copy.
	 * strtok_r modifies cmd_buf in place, inserting NUL terminators.
	 * tok1 = command group (e.g. "KV"), tok2 = sub-command (e.g. "KEYS"),
	 * tok3 = optional argument (e.g. key name for PURGE). */
	tok1 = strtok_r(cmd_buf, " \t", &saveptr);
	tok2 = strtok_r(NULL, " \t", &saveptr);
	tok3 = strtok_r(NULL, " \t", &saveptr);

	if (!tok1) {
		LM_ERR("empty raw_query command\n");
		return -1;
	}

	if (strcasecmp(tok1, "KV") == 0) {
		if (!tok2) {
			LM_ERR("KV sub-command missing\n");
			return -1;
		}

		if (strcasecmp(tok2, "KEYS") == 0) {
			return raw_kv_keys(ncon->kv, reply, expected_kv_no,
				reply_no);
		}

		if (strcasecmp(tok2, "PURGE") == 0) {
			if (!tok3) {
				LM_ERR("KV PURGE requires a key argument\n");
				return -1;
			}
			return raw_kv_purge(ncon->kv, tok3);
		}

		if (strcasecmp(tok2, "BUCKET") == 0) {
			if (tok3 && strcasecmp(tok3, "INFO") == 0) {
				return raw_kv_bucket_info(ncon->kv, reply,
					expected_kv_no, reply_no);
			}
			LM_ERR("unknown KV BUCKET sub-command: %s\n",
				tok3 ? tok3 : "(none)");
			return -1;
		}

		LM_ERR("unknown KV sub-command: %s\n", tok2);
		return -1;
	}

	if (strcasecmp(tok1, "STREAM") == 0) {
		LM_ERR("STREAM commands not yet implemented (got: STREAM %s %s)\n",
			tok2 ? tok2 : "", tok3 ? tok3 : "");
		return -1;
	}

	LM_ERR("unknown raw_query command: %s\n", tok1);
	return -1;
}

/**
 * raw_kv_keys() — List all keys in the NATS KV bucket.
 *
 * Calls nats_dl.kvStore_Keys() to enumerate every key in the bucket, then builds
 * a cdb_raw_entry result set with one row per key.  Each row contains a
 * single CDB_STR column holding the key name.  The caller (cachedb core)
 * owns the returned memory and is responsible for freeing it.
 *
 * Returns: 0 on success (even if bucket is empty), -1 on error.
 */
static int raw_kv_keys(kvStore *kv, cdb_raw_entry ***reply,
                       int expected_kv_no, int *reply_no)
{
	kvKeysList keys;
	natsStatus s;
	cdb_raw_entry **rows;
	int i, key_count;
	int ncols_per_row;

	memset(&keys, 0, sizeof(keys));
	s = nats_dl.kvStore_Keys(&keys, kv, NULL);

	if (s == NATS_NOT_FOUND) {
		/* empty bucket */
		if (reply_no)
			*reply_no = 0;
		return 0;
	}
	if (s != NATS_OK) {
		LM_ERR("kvStore_Keys failed: %s\n", NATS_ERR_TEXT(s));
		return -1;
	}

	key_count = keys.Count;

	if (key_count <= 0) {
		nats_dl.kvKeysList_Destroy(&keys);
		if (reply_no)
			*reply_no = 0;
		return 0;
	}

	/* The cachedb core frees expected_kv_no columns per row, so each row
	 * MUST have at least that many cdb_raw_entry slots -- allocating only
	 * the single column we fill leaves the core's free loop reading past
	 * the row (OOB free) when the caller asked for more columns.  The
	 * extra slots are zero-initialised (type 0, NULL val), so the core
	 * frees them harmlessly. */
	ncols_per_row = (expected_kv_no >= 1) ? expected_kv_no : 1;

	/* Allocate the cdb_raw_entry reply array.  The cachedb core expects
	 * a two-level allocation: an array of row pointers (rows[]), where
	 * each row is a separately allocated array of cdb_raw_entry structs
	 * (one per column).  For KV KEYS we have 1 column per row.  Each
	 * string value gets its own pkg_malloc'd buffer that the cachedb
	 * core will free after consuming the results. */
	rows = pkg_malloc(key_count * sizeof(cdb_raw_entry *));
	if (!rows) {
		LM_ERR("no more pkg memory for keys reply\n");
		nats_dl.kvKeysList_Destroy(&keys);
		return -1;
	}

	/* Iterate over kvKeysList: keys.Keys[i] is a C string owned by
	 * the NATS client library.  We must copy each key before calling
	 * nats_dl.kvKeysList_Destroy() which frees the underlying storage. */
	for (i = 0; i < key_count; i++) {
		rows[i] = pkg_malloc(ncols_per_row * sizeof(cdb_raw_entry));
		if (!rows[i]) {
			LM_ERR("no more pkg memory for key entry %d\n", i);
			/* free what we allocated so far */
			int j;
			for (j = 0; j < i; j++)
				pkg_free(rows[j]);
			pkg_free(rows);
			nats_dl.kvKeysList_Destroy(&keys);
			return -1;
		}
		memset(rows[i], 0, ncols_per_row * sizeof(cdb_raw_entry));

		rows[i][0].type = CDB_STR;
		int klen = strlen(keys.Keys[i]);
		rows[i][0].val.s.s = pkg_malloc(klen + 1);
		if (!rows[i][0].val.s.s) {
			LM_ERR("no more pkg memory for key string %d\n", i);
			pkg_free(rows[i]);
			int j;
			for (j = 0; j < i; j++) {
				if (rows[j][0].val.s.s)
					pkg_free(rows[j][0].val.s.s);
				pkg_free(rows[j]);
			}
			pkg_free(rows);
			nats_dl.kvKeysList_Destroy(&keys);
			return -1;
		}
		memcpy(rows[i][0].val.s.s, keys.Keys[i], klen);
		rows[i][0].val.s.s[klen] = '\0';
		rows[i][0].val.s.len = klen;
	}

	nats_dl.kvKeysList_Destroy(&keys);

	if (reply)
		*reply = rows;
	if (reply_no)
		*reply_no = key_count;

	LM_DBG("KV KEYS returned %d keys\n", key_count);
	return 0;
}

/**
 * raw_kv_purge() — Purge all revisions of a key from the NATS KV bucket.
 *
 * Removes the key and all of its historical revisions from the underlying
 * JetStream stream.  This is a destructive operation — purged data cannot
 * be recovered.  The operation is idempotent: purging a non-existent key
 * returns success (0).
 *
 * Returns: 0 on success, -1 on error.
 */
static int raw_kv_purge(kvStore *kv, const char *key)
{
	natsStatus s;
	str key_s;

	/* Reject wildcards ('*'/'>') and other illegal tokens before Purge: a
	 * wildcard key would purge EVERY matching entry (a mass delete). */
	key_s.s = (char *)key;
	key_s.len = key ? (int)strlen(key) : 0;
	if (validate_kv_key(&key_s) < 0) {
		char _rk[NATS_REDACT_KEY_BUF];
		nats_redact_key(key, _rk, sizeof(_rk));
		LM_ERR("KV PURGE: refusing invalid/wildcard key '%s'\n", _rk);
		return -1;
	}

	s = nats_dl.kvStore_Purge(kv, key, NULL);
	if (s == NATS_NOT_FOUND) {
		LM_DBG("KV PURGE: key '%s' not found\n", key);
		return 0; /* idempotent */
	}
	if (s != NATS_OK) {
		char _rk[NATS_REDACT_KEY_BUF];
		nats_redact_key(key, _rk, sizeof(_rk));
		LM_ERR("kvStore_Purge failed for key '%s': %s\n",
			_rk, NATS_ERR_TEXT(s));
		return -1;
	}

	LM_DBG("KV PURGE: purged key '%s'\n", key);
	return 0;
}

/**
 * raw_kv_bucket_info() — Return bucket statistics as a JSON-like result set.
 *
 * Queries the NATS KV bucket status and returns a single-row result with
 * six columns describing the bucket configuration and usage:
 *   col 0: bucket name (CDB_STR)
 *   col 1: number of live values (CDB_INT32)
 *   col 2: max history depth per key (CDB_INT32)
 *   col 3: TTL in seconds (CDB_INT32, converted from NATS nanoseconds)
 *   col 4: replica count (CDB_INT32)
 *   col 5: total bytes stored (CDB_INT32)
 *
 * Returns: 0 on success, -1 on error.
 */
static int raw_kv_bucket_info(kvStore *kv, cdb_raw_entry ***reply,
                              int expected_kv_no, int *reply_no)
{
	kvStatus *sts = NULL;
	natsStatus s;
	cdb_raw_entry **rows;
	const char *bname;
	int blen;

	s = nats_dl.kvStore_Status(&sts, kv);
	if (s != NATS_OK) {
		LM_ERR("kvStore_Status failed: %s\n", NATS_ERR_TEXT(s));
		return -1;
	}

	/* Allocate 1 row.  We fill 6 fixed columns, but the cachedb core frees
	 * expected_kv_no columns per row (free_raw_fetch), so the row MUST have
	 * at least that many cdb_raw_entry slots -- a caller asking for > 6
	 * output vars would otherwise make the core read+free past the row (heap
	 * OOB).  Size to max(expected_kv_no, 6); the extra slots are zeroed so
	 * they free harmlessly as NULL.  (Mirrors the raw_kv_keys ncols_per_row
	 * fix.) */
	int bi_ncols = (expected_kv_no > 6) ? expected_kv_no : 6;
	rows = pkg_malloc(sizeof(cdb_raw_entry *));
	if (!rows) {
		nats_dl.kvStatus_Destroy(sts);
		return -1;
	}
	rows[0] = pkg_malloc(bi_ncols * sizeof(cdb_raw_entry));
	if (!rows[0]) {
		pkg_free(rows);
		nats_dl.kvStatus_Destroy(sts);
		return -1;
	}
	memset(rows[0], 0, bi_ncols * sizeof(cdb_raw_entry));

	/* col 0: bucket name */
	bname = nats_dl.kvStatus_Bucket(sts);
	blen = bname ? strlen(bname) : 0;
	rows[0][0].type = CDB_STR;
	if (blen > 0) {
		rows[0][0].val.s.s = pkg_malloc(blen);
		if (rows[0][0].val.s.s) {
			memcpy(rows[0][0].val.s.s, bname, blen);
			rows[0][0].val.s.len = blen;
		}
	}

	/* col 1: values count */
	rows[0][1].type = CDB_INT32;
	rows[0][1].val.n = (int)nats_dl.kvStatus_Values(sts);

	/* col 2: history */
	rows[0][2].type = CDB_INT32;
	rows[0][2].val.n = (int)nats_dl.kvStatus_History(sts);

	/* col 3: ttl (in nanoseconds from NATS, convert to seconds) */
	rows[0][3].type = CDB_INT32;
	rows[0][3].val.n = (int)(nats_dl.kvStatus_TTL(sts) / 1000000000LL);

	/* col 4: replicas */
	rows[0][4].type = CDB_INT32;
	rows[0][4].val.n = (int)nats_dl.kvStatus_Replicas(sts);

	/* col 5: bytes */
	rows[0][5].type = CDB_INT32;
	rows[0][5].val.n = (int)nats_dl.kvStatus_Bytes(sts);

	nats_dl.kvStatus_Destroy(sts);

	if (reply)
		*reply = rows;
	if (reply_no)
		*reply_no = 1;

	LM_DBG("KV BUCKET INFO returned successfully\n");
	return 0;
}

/* ================================================================== */
/*                       Map operations                               */
/* ================================================================== */


/* nats_map_encode() — hex-escape a map key/field component into a single
 * NATS subject token.  Bytes outside the subject-safe set [0-9A-Za-z-_/\]
 * are written as "=HH"; '.' (the separator) and '=' (the escape char) are
 * therefore always escaped, so an encoded component never contains a raw
 * '.' and decodes unambiguously.  Returns the encoded length (excl. NUL),
 * or -1 if the output buffer is too small. */
static int map_char_safe(unsigned char c)
{
	if ((c >= '0' && c <= '9') ||
	    (c >= 'A' && c <= 'Z') ||
	    (c >= 'a' && c <= 'z'))
		return 1;
	switch (c) {
	case '-': case '_': case '/': case '\\':
		return 1;
	}
	return 0;
}

static int nats_map_encode(const char *in, int in_len, char *out, int out_size)
{
	static const char hex[] = "0123456789ABCDEF";
	int i, pos = 0;

	if (in_len < 0)
		return -1;
	for (i = 0; i < in_len; i++) {
		unsigned char c = (unsigned char)in[i];
		if (map_char_safe(c)) {
			if (pos + 1 >= out_size)
				return -1;
			out[pos++] = (char)c;
		} else {
			if (pos + 3 >= out_size)
				return -1;
			out[pos++] = '=';
			out[pos++] = hex[c >> 4];
			out[pos++] = hex[c & 0x0f];
		}
	}
	if (pos >= out_size)
		return -1;
	out[pos] = '\0';
	return pos;
}

static int map_hexval(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	return -1;
}

/* nats_map_decode() — inverse of nats_map_encode().  Returns the decoded
 * length (excl. NUL), or -1 on a malformed escape or overflow. */
static int nats_map_decode(const char *in, int in_len, char *out, int out_size)
{
	int i = 0, pos = 0;

	if (in_len < 0)
		return -1;
	while (i < in_len) {
		char c = in[i];
		if (c == '=') {
			int hi, lo;
			if (i + 2 >= in_len)
				return -1;
			hi = map_hexval(in[i + 1]);
			lo = map_hexval(in[i + 2]);
			if (hi < 0 || lo < 0)
				return -1;
			if (pos + 1 >= out_size)
				return -1;
			out[pos++] = (char)((hi << 4) | lo);
			i += 3;
		} else {
			if (pos + 1 >= out_size)
				return -1;
			out[pos++] = c;
			i++;
		}
	}
	if (pos >= out_size)
		return -1;
	out[pos] = '\0';
	return pos;
}

/*
 * The CacheDB map API, as cachedb_redis defines it and b2b_entities /
 * b2b_logic use it:
 *
 *   map_set(key, subkey, pairs)  set the fields of the map at key (the
 *                                others are kept); a subkey makes key a
 *                                member of the group subkey
 *   map_get(key, res)            one row per map: a single pair named after
 *                                the map key (is_pk) whose value is a dict
 *                                of the fields; key NULL returns every map
 *   map_remove(key, NULL)        delete the map
 *   map_remove(key, subkey)      delete the map and its group membership
 *   map_remove(NULL, subkey)     delete every map of the group
 *
 * Layout in the bucket (both components hex-escaped, see nats_map_encode):
 *
 *   _map.enc(key).enc(field)       one entry per field, so map_set writes
 *                                  fields independently (no read-modify-
 *                                  write); the value is type-tagged:
 *                                  'S' + bytes, 'I' + decimal int32, 'N'
 *   _mapgrp.enc(subkey).enc(key)   group membership
 */
#define NATS_MAP_NS        "_map"
#define NATS_MAP_GROUP_NS  "_mapgrp"
#define NATS_MAP_VAL_STR   'S'
#define NATS_MAP_VAL_INT32 'I'
#define NATS_MAP_VAL_NULL  'N'

/* map_subject() — "ns.enc(a)[.enc(b)]" into out; with b == NULL and
 * wildcard set, "ns.enc(a).>" (or "ns.>" when a is NULL too).  Returns
 * the length, or -1 on an empty component or overflow. */
static int map_subject(char *out, int out_size, const char *ns,
		const str *a, const char *b, int b_len, int wildcard)
{
	int pos, n;

	pos = snprintf(out, out_size, "%s", ns);
	if (pos < 0 || pos >= out_size)
		return -1;
	if (a) {
		if (a->len <= 0 || pos + 1 >= out_size)
			return -1;
		out[pos++] = NATS_MAP_SEP;
		n = nats_map_encode(a->s, a->len, out + pos, out_size - pos);
		if (n < 0)
			return -1;
		pos += n;
	}
	if (b) {
		if (b_len <= 0 || pos + 1 >= out_size)
			return -1;
		out[pos++] = NATS_MAP_SEP;
		n = nats_map_encode(b, b_len, out + pos, out_size - pos);
		if (n < 0)
			return -1;
		pos += n;
	} else if (wildcard) {
		if (pos + 2 >= out_size)
			return -1;
		out[pos++] = NATS_MAP_SEP;
		out[pos++] = '>';
	}
	out[pos] = '\0';
	return pos;
}

/* map_list() — the live keys matching filter.  NATS_NOT_FOUND (empty
 * bucket) is an empty list.  Returns 0, or -1 on a listing error. */
#ifdef UNIT_TESTS
int cn_ut_map_encode(const char *in, int in_len, char *out, int out_size)
{ return nats_map_encode(in, in_len, out, out_size); }
int cn_ut_map_decode(const char *in, int in_len, char *out, int out_size)
{ return nats_map_decode(in, in_len, out, out_size); }
int cn_ut_map_subject(char *out, int out_size, const char *ns,
		const str *a, const char *b, int b_len, int wildcard)
{ return map_subject(out, out_size, ns, a, b, b_len, wildcard); }
#endif

static int map_list(kvStore *kv, const char *filter, kvKeysList *keys)
{
	const char *filters[1] = { filter };
	natsStatus s;

	memset(keys, 0, sizeof(*keys));
	s = nats_dl.kvStore_KeysWithFilters(keys, kv, filters, 1, NULL);
	if (s == NATS_NOT_FOUND) {
		memset(keys, 0, sizeof(*keys));
		return 0;
	}
	if (s != NATS_OK) {
		LM_ERR("map: listing '%s' failed: %s\n", filter, NATS_ERR_TEXT(s));
		return -1;
	}
	return 0;
}

/* map_delete_keys() — delete every key matching filter. */
static int map_delete_keys(kvStore *kv, const char *filter)
{
	kvKeysList keys;
	natsStatus s;
	int i, rc = 0;

	if (map_list(kv, filter, &keys) < 0)
		return -1;
	for (i = 0; i < keys.Count; i++) {
		s = nats_dl.kvStore_Delete(kv, keys.Keys[i]);
		if (s != NATS_OK && s != NATS_NOT_FOUND) {
			LM_ERR("map: failed to delete '%s': %s\n", keys.Keys[i],
				NATS_ERR_TEXT(s));
			rc = -1;
		}
	}
	if (keys.Keys)
		nats_dl.kvKeysList_Destroy(&keys);
	return rc;
}

/* map_delete() — delete every field of the map at key. */
static int map_delete(kvStore *kv, const str *key)
{
	char filter[NATS_MAP_KEY_BUF];

	if (map_subject(filter, sizeof(filter), NATS_MAP_NS, key, NULL, 0, 1) < 0) {
		LM_ERR("map: key too long\n");
		return -1;
	}
	return map_delete_keys(kv, filter);
}

static int map_keycmp(const void *a, const void *b)
{
	return strcmp(*(char *const *)a, *(char *const *)b);
}

/* map_field_value() — decode a type-tagged field value into pair->val.
 * Returns 0, or -1 if the value is not a map value (skip it). */
static int map_field_value(cdb_pair_t *pair, const char *v, int len)
{
	str s;

	if (len < 1)
		return -1;
	switch (v[0]) {
	case NATS_MAP_VAL_NULL:
		pair->val.type = CDB_NULL;
		return 0;
	case NATS_MAP_VAL_INT32:
		/* 64-bit accumulator: str2sint() overflows on INT_MIN */
		{
			int64_t n = 0;
			int i = 1, neg = 0;

			if (i < len && v[i] == '-') {
				neg = 1;
				i++;
			}
			if (i >= len || len - i > 10)
				return -1;
			for (; i < len; i++) {
				if (v[i] < '0' || v[i] > '9')
					return -1;
				n = n * 10 + (v[i] - '0');
			}
			if (neg)
				n = -n;
			if (n < INT32_MIN || n > INT32_MAX)
				return -1;
			pair->val.val.i32 = (int32_t)n;
		}
		pair->val.type = CDB_INT32;
		return 0;
	case NATS_MAP_VAL_STR:
		s.s = (char *)v + 1;
		s.len = len - 1;
		if (pkg_str_dup(&pair->val.val.st, &s) < 0)
			return -1;
		pair->val.type = CDB_STR;
		return 0;
	}
	return -1;
}

/**
 * nats_cache_map_get() — the maps at key (key NULL: every map).
 *
 * One row per map, holding a single CDB_DICT pair named after the map key.
 * The listed keys are sorted so the fields of each map are consecutive.
 *
 * Returns: 0 on success (even if nothing matches), -1 on error.
 */
int nats_cache_map_get(cachedb_con *con, const str *key, cdb_res_t *res)
{
	nats_cachedb_con *ncon;
	char filter[NATS_MAP_KEY_BUF];
	char mkey[NATS_MAP_KEY_BUF], field[NATS_MAP_KEY_BUF];
	kvKeysList keys;
	cdb_pair_t *map = NULL, *pair;
	cdb_row_t *row;
	cdb_key_t ck;
	kvEntry *entry;
	const char *cur_enc = NULL;
	int cur_enc_len = 0, ns_len = sizeof(NATS_MAP_NS) - 1;
	int i, mlen, flen;

	if (!con || !res) {
		LM_ERR("null parameter\n");
		return -1;
	}
	/* Init the result set BEFORE any failure return: callers may
	 * cdb_free_rows(res) on failure (see the matching fix + rationale
	 * in nats_cache_query, sip_e2e case 040_broker_bounce). */
	cdb_res_init(res);
	ncon = (nats_cachedb_con *)con->data;
	if (!ncon) {
		LM_ERR("null NATS connection\n");
		return -1;
	}
	if (nats_con_refresh_kv(ncon) < 0 || !ncon->kv) {
		LM_DBG("NATS unavailable — operation deferred (fast-fail)\n");
		return -1;
	}
	if (map_subject(filter, sizeof(filter), NATS_MAP_NS, key, NULL, 0, 1) < 0) {
		LM_ERR("map_get: invalid or too long map key\n");
		return -1;
	}
	if (map_list(ncon->kv, filter, &keys) < 0)
		return -1;
	if (keys.Count > 1)
		qsort(keys.Keys, keys.Count, sizeof(char *), map_keycmp);

	for (i = 0; i < keys.Count; i++) {
		const char *k = keys.Keys[i], *enc_key, *enc_field;
		int enc_key_len;

		/* "_map." enc(key) "." enc(field) */
		if (strncmp(k, NATS_MAP_NS, ns_len) || k[ns_len] != NATS_MAP_SEP)
			continue;
		enc_key = k + ns_len + 1;
		enc_field = strchr(enc_key, NATS_MAP_SEP);
		if (!enc_field || enc_field == enc_key || !enc_field[1])
			continue;
		enc_key_len = enc_field - enc_key;
		enc_field++;

		if (!map || enc_key_len != cur_enc_len ||
				memcmp(enc_key, cur_enc, enc_key_len)) {
			/* a new map: its row */
			mlen = nats_map_decode(enc_key, enc_key_len, mkey, sizeof(mkey));
			if (mlen <= 0) {
				LM_WARN("map_get: undecodable key '%s' skipped\n", k);
				continue;
			}
			row = pkg_malloc(sizeof *row);
			if (!row)
				goto oom;
			INIT_LIST_HEAD(&row->dict);
			ck.name.s = mkey;
			ck.name.len = mlen;
			ck.is_pk = 1;
			map = cdb_mk_pair(&ck, NULL);
			if (!map) {
				pkg_free(row);
				goto oom;
			}
			map->val.type = CDB_DICT;
			INIT_LIST_HEAD(&map->val.val.dict);
			list_add_tail(&map->list, &row->dict);
			list_add_tail(&row->list, &res->rows);
			res->count++;
			cur_enc = enc_key;
			cur_enc_len = enc_key_len;
		}

		flen = nats_map_decode(enc_field, strlen(enc_field), field,
			sizeof(field));
		if (flen <= 0) {
			LM_WARN("map_get: undecodable field in '%s' skipped\n", k);
			continue;
		}
		entry = NULL;
		if (nats_dl.kvStore_Get(&entry, ncon->kv, k) != NATS_OK || !entry)
			continue;   /* deleted since the listing */
		ck.name.s = field;
		ck.name.len = flen;
		ck.is_pk = 0;
		pair = cdb_mk_pair(&ck, NULL);
		if (!pair) {
			nats_dl.kvEntry_Destroy(entry);
			goto oom;
		}
		if (map_field_value(pair, nats_dl.kvEntry_ValueString(entry),
				nats_dl.kvEntry_ValueLen(entry)) < 0) {
			LM_DBG("map_get: '%s' holds no map value, skipped\n", k);
			pkg_free(pair);
		} else {
			list_add_tail(&pair->list, &map->val.val.dict);
		}
		nats_dl.kvEntry_Destroy(entry);
	}
	if (keys.Keys)
		nats_dl.kvKeysList_Destroy(&keys);

	LM_DBG("map_get: %d map(s)\n", res->count);
	return 0;

oom:
	LM_ERR("no more pkg memory\n");
	if (keys.Keys)
		nats_dl.kvKeysList_Destroy(&keys);
	cdb_free_rows(res);
	return -1;
}

/**
 * nats_cache_map_set() — set fields of the map at key; with a subkey,
 * also record key as a member of the group subkey.
 *
 * Every value is checked first (string, int32 or null), so an unsupported
 * one fails the call before anything is written.
 *
 * Returns: 0 on success, -1 on error.
 */
int nats_cache_map_set(cachedb_con *con, const str *key, const str *subkey,
                       const cdb_dict_t *pairs)
{
	nats_cachedb_con *ncon;
	char subject[NATS_MAP_KEY_BUF];
	char ibuf[INT2STR_MAX_LEN + 1];
	cdb_pair_t *pair;
	struct list_head *it;
	natsStatus s;
	char *val;
	int len, n;

	if (!con || !key || !pairs || key->len <= 0) {
		LM_ERR("null parameter or empty map key\n");
		return -1;
	}
	list_for_each(it, (struct list_head *)pairs) {
		pair = list_entry(it, cdb_pair_t, list);
		if (pair->key.name.len <= 0) {
			LM_ERR("map_set: empty field name\n");
			return -1;
		}
		if (pair->val.type != CDB_STR && pair->val.type != CDB_INT32 &&
				pair->val.type != CDB_NULL) {
			LM_ERR("map_set: unsupported type %d for field '%.*s'\n",
				pair->val.type, pair->key.name.len,
				pair->key.name.s);   /* not PII: a column name */
			return -1;
		}
	}

	ncon = (nats_cachedb_con *)con->data;
	if (!ncon) {
		LM_ERR("null NATS connection\n");
		return -1;
	}
	/* Fast-fail on a down broker and refresh the KV handle after a
	 * reconnect; otherwise this op blocks the worker during an outage and
	 * can reuse a destroyed handle after reconnect (see nats_con_refresh_kv). */
	if (nats_con_refresh_kv(ncon) < 0 || !ncon->kv) {
		LM_DBG("NATS unavailable — operation deferred (fast-fail)\n");
		return -1;
	}

	list_for_each(it, (struct list_head *)pairs) {
		pair = list_entry(it, cdb_pair_t, list);
		if (map_subject(subject, sizeof(subject), NATS_MAP_NS, key,
				pair->key.name.s, pair->key.name.len, 0) < 0) {
			LM_ERR("map_set: key or field too long\n");
			return -1;
		}
		val = ibuf;
		switch (pair->val.type) {
		case CDB_STR:
			len = pair->val.val.st.len + 1;
			val = pkg_malloc(len);
			if (!val) {
				LM_ERR("no more pkg memory\n");
				return -1;
			}
			val[0] = NATS_MAP_VAL_STR;
			if (pair->val.val.st.len)
				memcpy(val + 1, pair->val.val.st.s, pair->val.val.st.len);
			break;
		case CDB_INT32:
			n = snprintf(ibuf + 1, sizeof(ibuf) - 1, "%d", pair->val.val.i32);
			ibuf[0] = NATS_MAP_VAL_INT32;
			len = n + 1;
			break;
		default:   /* CDB_NULL */
			ibuf[0] = NATS_MAP_VAL_NULL;
			len = 1;
			break;
		}
		s = nats_dl.kvStore_Put(NULL, ncon->kv, subject, val, len);
		if (val != ibuf)
			pkg_free(val);
		if (s != NATS_OK) {
			LM_ERR("map_set: put '%s' failed: %s\n", subject,
				NATS_ERR_TEXT(s));
			return -1;
		}
	}

	if (subkey && subkey->len > 0) {
		if (map_subject(subject, sizeof(subject), NATS_MAP_GROUP_NS, subkey,
				key->s, key->len, 0) < 0) {
			LM_ERR("map_set: group or key too long\n");
			return -1;
		}
		s = nats_dl.kvStore_Put(NULL, ncon->kv, subject, "1", 1);
		if (s != NATS_OK) {
			LM_ERR("map_set: group put '%s' failed: %s\n", subject,
				NATS_ERR_TEXT(s));
			return -1;
		}
	}
	return 0;
}

/**
 * nats_cache_map_remove() — delete the map at key, its membership of the
 * group subkey, or (key NULL) every map of the group subkey.  Deleting
 * what does not exist is not an error.
 *
 * Returns: 0 on success, -1 on error.
 */
int nats_cache_map_remove(cachedb_con *con, const str *key,
                          const str *subkey)
{
	nats_cachedb_con *ncon;
	char subject[NATS_MAP_KEY_BUF], member[NATS_MAP_KEY_BUF];
	kvKeysList keys;
	natsStatus s;
	str mkey;
	int i, glen, rc = 0;

	if (subkey && subkey->len <= 0)
		subkey = NULL;
	if (!con || (!key && !subkey) || (key && key->len <= 0)) {
		LM_ERR("null parameter or empty key\n");
		return -1;
	}
	ncon = (nats_cachedb_con *)con->data;
	if (!ncon) {
		LM_ERR("null NATS connection\n");
		return -1;
	}
	/* Fast-fail on a down broker and refresh the KV handle after a
	 * reconnect; otherwise this op blocks the worker during an outage and
	 * can reuse a destroyed handle after reconnect (see nats_con_refresh_kv). */
	if (nats_con_refresh_kv(ncon) < 0 || !ncon->kv) {
		LM_DBG("NATS unavailable — operation deferred (fast-fail)\n");
		return -1;
	}

	if (!subkey)
		return map_delete(ncon->kv, key);

	if (key) {
		/* the map, and its membership of the group */
		if (map_subject(subject, sizeof(subject), NATS_MAP_GROUP_NS, subkey,
				key->s, key->len, 0) < 0) {
			LM_ERR("map_remove: group or key too long\n");
			return -1;
		}
		s = nats_dl.kvStore_Delete(ncon->kv, subject);
		if (s != NATS_OK && s != NATS_NOT_FOUND) {
			LM_ERR("map_remove: delete '%s' failed: %s\n", subject,
				NATS_ERR_TEXT(s));
			rc = -1;
		}
		return map_delete(ncon->kv, key) < 0 ? -1 : rc;
	}

	/* every map of the group, then the membership entries */
	glen = map_subject(subject, sizeof(subject), NATS_MAP_GROUP_NS, subkey,
		NULL, 0, 1);
	if (glen < 0) {
		LM_ERR("map_remove: group too long\n");
		return -1;
	}
	if (map_list(ncon->kv, subject, &keys) < 0)
		return -1;
	glen -= 1;   /* "_mapgrp.enc(subkey)." -- the members follow */
	for (i = 0; i < keys.Count; i++) {
		const char *k = keys.Keys[i];

		if ((int)strlen(k) <= glen || strncmp(k, subject, glen))
			continue;
		mkey.len = nats_map_decode(k + glen, strlen(k + glen), member,
			sizeof(member));
		if (mkey.len <= 0) {
			LM_WARN("map_remove: undecodable member '%s' skipped\n", k);
			continue;
		}
		mkey.s = member;
		if (map_delete(ncon->kv, &mkey) < 0)
			rc = -1;
		s = nats_dl.kvStore_Delete(ncon->kv, k);
		if (s != NATS_OK && s != NATS_NOT_FOUND) {
			LM_ERR("map_remove: delete '%s' failed: %s\n", k,
				NATS_ERR_TEXT(s));
			rc = -1;
		}
	}
	if (keys.Keys)
		nats_dl.kvKeysList_Destroy(&keys);
	return rc;
}

