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
 * cachedb_nats_expiry.c — the module's single expiry translation unit
 * (consolidation of cachedb_nats_ttl.c, cachedb_nats_ttl_put.c,
 * cachedb_nats_reaper.c and cachedb_nats_json_reap.c).
 *
 * Contents:
 *   - pure decision helpers for the CAS row write (predicate, jsErrCode
 *     classification, key->subject mapping) and the mod_init guards;
 *   - nats_kv_put_row()/nats_kv_write_row_cas(): the single-shot CAS
 *     publish EVERY usrloc-row write goes through;
 *   - the reaper decision logic (due-gate, per-row action) and the
 *     survivor projection used by the reaper timer host in
 *     cachedb_nats.c.
 *
 * The reaper is the module's SINGLE expiry mechanism: the native
 * per-message-TTL path was removed.
 */

#include <stdio.h>   /* snprintf */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>  /* getpid/getppid/sleep (reaper proc) */

#include <nats/nats.h>

#include "../../dprint.h"
#include "../../mem/mem.h"   /* pkg buffers on the projection path */
#include "../nats/nats_bind.h"
#include "../nats/nats_dl.h"
#include "../nats/nats_pool.h"     /* nats_pool_get_js */
#include "../nats/nats_redact.h"   /* nats_redact_key */
#include "cachedb_nats.h"          /* cdbn_fts_on (resync gate) */
#include "cachedb_nats_dbase.h"    /* kv_bucket / kv_replicas / ... */
#include "cachedb_nats_watch.h"    /* proc guard + resync body */
#include "cachedb_nats_reg.h"      /* cdbn_reg_row_scan (reaper due-check) */
#include "cachedb_nats_stats.h"    /* NATS_CDB_STATS_* (reaper counters) */
#include "cachedb_nats_reap_gauges.h"   /* reap_publish_pass */
#include "cachedb_nats_expiry.h"
#include "cachedb_nats_reap_enum.h"   /* value-carrying watch pass */
#include "cachedb_nats_json_internal.h"   /* walkers, json_sink_t, _contact_*, cdbn_row_finalize_metadata */
#include "cachedb_nats_json.h"            /* cdbn_reap_project_survivors / cdbn_reap_row_due_json decls */

/* ==================================================================== */
/* pure decisions                                                       */
/* ==================================================================== */

/* marker-aware CAS predicate. */
enum ttl_cas_pred cdbn_ttl_cas_predicate(int got_entry, int value_len,
	uint64_t entry_rev, uint64_t head_seq, uint64_t *out_seq)
{
	(void)value_len;   /* empty (marker) and non-empty both CAS at the rev */
	if (got_entry) {
		*out_seq = entry_rev;
		return TTL_CAS_LAST_SEQ;
	}
	if (head_seq > 0) {
		/* NOT_FOUND but a DEL/PURGE marker sits at the head — CAS there,
		 * never ExpectNoMessage (the server rejects it over a marker). */
		*out_seq = head_seq;
		return TTL_CAS_LAST_SEQ;
	}
	*out_seq = 0;
	return TTL_CAS_NO_MESSAGE;   /* provably empty subject */
}

/* js_PublishMsg outcome classification. */
enum ttl_outcome cdbn_ttl_classify(enum ttl_pub_status st, int jerr)
{
	if (st == TTL_PUB_OK)
		return TTL_DONE;
	if (st == TTL_PUB_CONN_DOWN)
		return TTL_FAIL_SAVE;            /* down: any jerr is stale/meaningless */
	if (jerr == 10071)                  /* JSStreamWrongLastSequenceErr */
		return TTL_RETRY;               /* CAS conflict: re-read+retry  */
	/* an unrecognized JS error => fail the save. */
	return TTL_FAIL_SAVE;
}

/* KV-Operation value for a publish-delete. */
const char *cdbn_ttl_delete_op(int purge)
{
	return purge ? NATS_KV_OP_PURGE : NATS_KV_OP_DEL;
}

/* kv_ttl==0 startup guard. */
int cdbn_kv_ttl_guard(int kv_ttl)
{
	return (kv_ttl == 0) ? 0 : -1;
}

/* nats_expired_linger range guard: negative is meaningless,
 * > 1 day is almost certainly a typo'd epoch pasted into the config. */
int cdbn_linger_guard(int linger)
{
	return (linger >= 0 && linger <= 86400) ? 0 : -1;
}

/* Policy for a PRE-EXISTING bucket whose backing
 * stream already carries a non-zero MaxAge (created by an older deployment or
 * another tool — the cdbn_kv_ttl_guard modparam check above only stops THIS module
 * from creating one).  A non-zero stream MaxAge expires EVERY key after that
 * age, including PERMANENT contacts (expires==0) — silent registration loss.
 * @maxage_ns: the bound bucket's backing-stream MaxAge in ns.
 * @return 1 => warn (non-zero MaxAge; never silent), 0 => clean (MaxAge==0). */
int cdbn_kv_legacy_bucket_maxage_warn(int64_t maxage_ns)
{
	return maxage_ns != 0 ? 1 : 0;
}

/* build "$KV.<bucket>.<key>" — one mapping, three consumers. */
int nats_kv_key_to_subject(const char *bucket, const char *key,
	char *buf, int buflen)
{
	int n = snprintf(buf, buflen, "$KV.%s.%s", bucket, key);
	if (n < 0 || n >= buflen)
		return -1;
	return n;
}


/* ==================================================================== */
/* the single-shot CAS row write                                        */
/* ==================================================================== */

/* natsStatus -> ttl_pub_status, so the classifier stays free of nats.h coupling. */
static enum ttl_pub_status pub_status(natsStatus s)
{
	if (s == NATS_OK)
		return TTL_PUB_OK;
	if (s == NATS_TIMEOUT || s == NATS_CONNECTION_CLOSED ||
	    s == NATS_CONNECTION_DISCONNECTED || s == NATS_NOT_YET_CONNECTED)
		return TTL_PUB_CONN_DOWN;
	return TTL_PUB_JS_ERR;
}

/* Write `json` (json_len bytes) to the usrloc row at `key`, preserving
 * optimistic concurrency.  Single-shot.
 *
 *   js/kv       : pool-owned JetStream ctx + KV store (both call sites hold them)
 *   got_entry   : the caller's prior read found an entry (NATS_OK)
 *   entry_rev   : its revision (CAS predicate target)
 *   out_rev     : new revision on success (may be NULL)
 *
 * Returns an enum ttl_outcome (TTL_DONE/RETRY/FAIL_SAVE); the caller maps
 * RETRY to its re-read loop.
 */
enum ttl_outcome nats_kv_put_row(jsCtx *js, kvStore *kv,
	const char *bucket, const char *key,
	const char *json, int json_len,
	int got_entry, uint64_t entry_rev, uint64_t *out_rev)
{
	char subj[512];
	uint64_t cas_seq = 0, rev = 0;
	enum ttl_cas_pred pred;
	natsMsg *m = NULL;
	jsPubAck *pa = NULL;
	jsErrCode je = 0;
	jsPubOptions o;
	natsStatus s;

	/* one mapping, three consumers: never publish to a truncated
	 * subject -- that would land the value where the reader never queries
	 * (silent split-brain).  Fail the save instead. */
	if (nats_kv_key_to_subject(bucket, key, subj, sizeof(subj)) < 0) {
		char _rk[NATS_REDACT_KEY_BUF];
		nats_redact_key(key, _rk, sizeof(_rk));
		LM_ERR("nats_kv_put_row: subject overflow for key '%s' -- failing "
			"the save\n", _rk);
		return TTL_FAIL_SAVE;
	}

	/* head_seq=0: js_GetLastMsg is unbound, so an absent entry resolves to
	 * NO_MESSAGE and is serviced with kvStore_CreateString -- which re-creates
	 * over a server-side DEL/PURGE marker first-attempt (avoids the
	 * re-REGISTER lockout). */
	pred = cdbn_ttl_cas_predicate(got_entry, json_len, entry_rev, 0, &cas_seq);

	if (pred == TTL_CAS_NO_MESSAGE) {
		/* length-aware create: json_len is already in hand;
		 * the *String form re-measured the full document.
		 * A TTL of 0 makes CreateWithTTL identical to kvStore_Create. */
		s = nats_dl.kvStore_CreateWithTTL(&rev, kv, key, json, json_len, 0);
		if (s == NATS_OK) {
			if (out_rev)
				*out_rev = rev;
			return TTL_DONE;
		}
		if (pub_status(s) == TTL_PUB_CONN_DOWN) {
			/* outage itself is covered by the pool transition
			 * + rate-limited fast-fail WARNs; per-write detail DBG */
			LM_DBG("nats_kv_put_row: create of '%s.%s' failed, "
				"broker down: %s\n", bucket, key,
				nats_dl.natsStatus_GetText(s));
			return TTL_FAIL_SAVE;
		}
		/* key already exists (a concurrent create won) -> re-read + retry */
		LM_DBG("nats_kv_put_row: create of '%s.%s' lost to a concurrent "
			"create (%s); retrying\n", bucket, key,
			nats_dl.natsStatus_GetText(s));
		return TTL_RETRY;
	}

	/* update OR create-over-empty-marker: CAS-publish.
	 * ExpectLastSubjectSeq == the revision we read is byte-for-byte the
	 * optimistic check kvStore_UpdateString(rev) performed. */
	if (nats_dl.natsMsg_Create(&m, subj, NULL, json, json_len) != NATS_OK)
		return TTL_FAIL_SAVE;
	nats_dl.jsPubOptions_Init(&o);
	o.ExpectLastSubjectSeq = cas_seq;

	s = nats_dl.js_PublishMsg(&pa, js, m, &o, &je);
	if (s == NATS_OK && pa && out_rev)
		*out_rev = pa->Sequence;           /* KV revision == stream seq */
	nats_dl.jsPubAck_Destroy(pa);
	nats_dl.natsMsg_Destroy(m);

	{
		enum ttl_outcome out = cdbn_ttl_classify(pub_status(s), je);

		/* this is the PRIMARY usrloc write path -- a failed
		 * save used to produce zero diagnostics.  A CAS conflict is
		 * normal contention (DBG); broker-down is covered by the
		 * transition WARNs (DBG here); anything else fails the save
		 * and gets the full libnats detail: status text + jsErrCode
		 * (10077 = message-TTL unsupported, 10052 = bad request --
		 * the classes that bit during the 2.11 TTL bring-up) +
		 * bucket + redacted key (stable hash: correlates repeat
		 * failures without logging the AoR) to find the row. */
		if (out == TTL_RETRY) {
			LM_DBG("nats_kv_put_row: CAS conflict on '%s.%s' at rev "
				"%llu; retrying\n", bucket, key,
				(unsigned long long)cas_seq);
		} else if (out == TTL_FAIL_SAVE) {
			if (pub_status(s) == TTL_PUB_CONN_DOWN)
				LM_DBG("nats_kv_put_row: CAS write of '%s.%s' "
					"failed, broker down: %s\n", bucket, key,
					nats_dl.natsStatus_GetText(s));
			else {
				char _rk[NATS_REDACT_KEY_BUF];
				nats_redact_key(key, _rk, sizeof(_rk));
				LM_ERR("nats_kv_put_row: CAS write of '%s.%s' "
					"failed: %s (jsErrCode %d) -- failing the "
					"save\n", bucket, _rk,
					nats_dl.natsStatus_GetText(s), (int)je);
			}
		}
		return out;
	}
}

/* The usrloc-row write entry point.  All writers (registration update,
 * first insert, reaper survivor-write) go through this; no caller calls
 * kvStore_UpdateString on the row path directly.
 *
 * `rev == 0` is the "no prior message" sentinel (JetStream sequences
 * are 1-based): the write routes to a CREATE (kvStore_CreateString via the
 * NO_MESSAGE predicate).  `rev > 0` CAS-updates at that revision (a live doc
 * or a marker rev).
 *
 * Returns 0 = committed, 1 = CAS conflict (caller re-reads + retries),
 * -1 = fatal/fail-the-save.  *out_rev set on success. */
int nats_kv_write_row_cas(kvStore *kv, const char *bucket, const char *key,
	const char *json, int json_len, uint64_t rev, uint64_t *out_rev)
{
	enum ttl_outcome o;

	o = nats_kv_put_row(nats_pool_get_js(), kv, bucket,
		key, json, json_len, rev != 0, rev, out_rev);
	if (o == TTL_DONE)
		return 0;
	if (o == TTL_RETRY)
		return 1;
	return -1;
}


/* ==================================================================== */
/* reaper decision logic                                                */
/* ==================================================================== */

/* row-due selection. */
int cdbn_reap_row_due(int64_t row_exp, time_t now, int grace)
{
	return row_exp != 0 && (row_exp + (int64_t)grace) <= (int64_t)now;
}

/* per-row action after pruning expired contacts. */
enum reap_action cdbn_reap_row_action(int n_live_survivors)
{
	return (n_live_survivors > 0) ? REAP_WRITE_SURVIVORS : REAP_DELETE_EMPTY;
}

/* Reaper-off guard.  The reaper is the SINGLE expiry
 * mechanism, so a
 * non-positive interval leaves nothing to reclaim expired records and is
 * refused unconditionally. */
int cdbn_reap_interval_guard(int interval)
{
	return (interval > 0) ? 0 : -1;
}


/* ==================================================================== */
/* reaper row projection                                                */
/* ==================================================================== */

/* Cheap reaper due-gate over a STORED row: read the top-level
 * `row_exp` (= min contact expiry, 0 = permanent) and apply the grace-padded
 * due test.  1 = due (worth a full projection), 0 = not due / permanent (skip),
 * -1 = `row_exp` absent (legacy/pre-row_exp row) which the caller MUST
 * treat as due (fail-closed: project it rather than leave it unreaped). */
int cdbn_reap_row_due_json(const char *json, int len, time_t now, int grace)
{
	int64_t row_exp;
	if (!json || len <= 0)
		return -1;
	if (cdbn_contact_field_int64(json, json + len, "row_exp", 7, &row_exp) != 0)
		return -1;                          /* absent => caller treats as due */
	return cdbn_reap_row_due(row_exp, now, grace);
}

/* A JSON contact is DUE (the reaper drops it) iff expired OR carrying no
 * parseable integer `expires` -- fail-closed: a binding we cannot prove is live
 * is reaped, never retained.  expires==0 is permanent and never due
 * (cdbn_reap_row_due returns 0 for it). */
static int reap_contact_due(const char *cvs, const char *cve, time_t now, int grace)
{
	int64_t e;
	if (cdbn_contact_expires(cvs, cve, &e) != 0)
		return 1;                          /* unprovable => fail-closed due */
	return cdbn_reap_row_due(e, now, grace);
}

/* Emit a "contacts" object holding only the surviving (non-due) contacts of
 * [c_vs,c_ve), verbatim, and report the survivor count via *n_surv.  Returns 0
 * ok / -1 on sink OOM or malformed input. */
static int emit_survivor_contacts(json_sink_t *s, const char *c_vs,
	const char *c_ve, time_t now, int grace, int *n_surv)
{
	const char *p = cdbn_skip_ws(c_vs, c_ve);
	int first = 1, kept = 0;

	if (p >= c_ve || *p != '{')
		return -1;
	if (cdbn_sink_putc(s, '{') < 0)
		return -1;
	p++;
	while (p < c_ve) {
		const char *name, *cvs;
		int nlen;
		p = cdbn_skip_ws(p, c_ve);
		if (p >= c_ve)
			return -1;
		if (*p == '}')
			break;
		if (*p == ',') { p++; continue; }
		p = cdbn_parse_json_string(p, c_ve, &name, &nlen);
		if (!p)
			return -1;
		p = cdbn_skip_ws(p, c_ve);
		if (p >= c_ve || *p != ':')
			return -1;
		p++;
		p = cdbn_skip_ws(p, c_ve);
		cvs = p;
		p = cdbn_skip_json_value(p, c_ve);
		if (!p)
			return -1;
		if (reap_contact_due(cvs, p, now, grace))
			continue;                      /* drop a due contact */
		if (!first && cdbn_sink_putc(s, ',') < 0)
			return -1;
		first = 0;
		kept++;
		if (cdbn_sink_emit_raw_string(s, name, nlen) < 0)
			return -1;
		if (cdbn_sink_putc(s, ':') < 0)
			return -1;
		if (cdbn_sink_write(s, cvs, (int)(p - cvs)) < 0)
			return -1;
	}
	if (cdbn_sink_putc(s, '}') < 0)
		return -1;
	*n_surv = kept;
	return 0;
}

/* Reaper survivor projection.  From a stored usrloc row
 * @json, drop every DUE contact, recompute `row_exp` over the survivors, and
 * return a fresh document (caller frees).  *n_survivors is set to the survivor
 * count (0 => the row is fully due and the caller must CAS-DELETE the key), or
 * to -1 when @json has no top-level "contacts" (not a usrloc row -> returned
 * unchanged so the reaper skips it).  NULL on malformed input / OOM.
 *
 * Two stages: (1) copy the doc with the contacts object filtered to survivors,
 * then (2) hand it to cdbn_row_finalize_metadata() which recomputes row_exp +
 * schema_version over exactly those survivors — so the 0=permanent sentinel and
 * int64 arithmetic have a single owner (the rowmeta TU). */
/* pass-1: is this a usrloc row?  (has a top-level "contacts") */
static int find_contacts_flag_cb(const char *name, int nlen,
	const char *vstart, const char *vend, void *ud)
{
	int *has = ud;

	(void)vstart; (void)vend;
	if (nlen == 8 && memcmp(name, "contacts", 8) == 0)
		*has = 1;
	return 0;
}

/* stage-1: copy every top-level field, filtering the contacts
 * object down to its surviving members. */
struct project_walk_ctx {
	json_sink_t *s;
	time_t       now;
	int          grace;
	int          n_surv;
	int          first;
};

static int project_field_cb(const char *name, int nlen,
	const char *vstart, const char *vend, void *ud)
{
	struct project_walk_ctx *c = ud;

	if (!c->first && cdbn_sink_putc(c->s, ',') < 0)
		return -1;
	c->first = 0;
	if (cdbn_sink_emit_raw_string(c->s, name, nlen) < 0)
		return -1;
	if (cdbn_sink_putc(c->s, ':') < 0)
		return -1;
	if (nlen == 8 && memcmp(name, "contacts", 8) == 0) {
		if (emit_survivor_contacts(c->s, vstart, vend,
				c->now, c->grace, &c->n_surv) < 0)
			return -1;
	} else {
		if (cdbn_sink_write(c->s, vstart, (int)(vend - vstart)) < 0)
			return -1;
	}
	return 0;
}

char *cdbn_reap_project_survivors(const char *json, int len, time_t now, int grace,
	int *n_survivors, int *out_len,
	int64_t *out_row_exp, int *out_all_same)
{
	int has_contacts = 0;
	int n_surv = 0, tmp_len = 0;
	char *tmp, *final;
	json_sink_t s;

	if (n_survivors)
		*n_survivors = 0;
	if (out_row_exp)            /* TTL eligibility of the projected survivors */
		*out_row_exp = 0;
	if (out_all_same)
		*out_all_same = 0;
	if (!json || len <= 0)
		return NULL;
	/* pass 1: is this a usrloc row at all? */
	if (cdbn_json_foreach_top_field(json, len,
			find_contacts_flag_cb, &has_contacts) < 0)
		return NULL;
	if (!has_contacts) {                       /* non-usrloc doc -> skip */
		char *copy = pkg_malloc(len + 1);
		if (!copy)
			return NULL;
		memcpy(copy, json, len);
		copy[len] = '\0';
		if (n_survivors)
			*n_survivors = -1;
		if (out_len)
			*out_len = len;
		return copy;
	}
	/* stage 1: copy every top-level field, filtering the contacts object to
	 * survivors.  Stale row_exp/schema_version are copied through and then
	 * replaced by stage 2's finalize. */
	if (cdbn_sink_init(&s, len + 16) < 0)
		return NULL;
	if (cdbn_sink_putc(&s, '{') < 0)
		goto fail;
	{
		struct project_walk_ctx pw = { &s, now, grace, 0, 1 };
		if (cdbn_json_foreach_top_field(json, len,
				project_field_cb, &pw) < 0)
			goto fail;
		n_surv = pw.n_surv;
	}
	if (cdbn_sink_putc(&s, '}') < 0)
		goto fail;
	tmp = cdbn_sink_take(&s, &tmp_len);
	if (!tmp)
		return NULL;

	/* stage 2: recompute row_exp + schema_version over the survivors, and
	 * expose the TTL eligibility inputs (n_survivors == n_contacts). */
	final = cdbn_row_finalize_metadata(tmp, tmp_len, out_len,
		out_row_exp, NULL, out_all_same);
	pkg_free(tmp);
	if (!final)
		return NULL;
	if (n_survivors)
		*n_survivors = n_surv;
	return final;
fail:
	pkg_free(s.buf);
	return NULL;
}

/* Module globals owned by cachedb_nats.c (modparams + FTS prefix),
 * consumed by the reaper timer body moved here. */
extern int   nats_reap_grace;
extern int   nats_expired_linger;
extern char *fts_json_prefix;
extern int   fts_json_prefix_len;   /* cached at mod_init */

/* CAS-guarded publish-delete of a KV key.  Publishes a KV-Operation:DEL
 * marker for "$KV.<bucket>.<key>" with ExpectLastSubjectSeq=@rev, so a
 * concurrent re-REGISTER that bumped the head between our read and this delete
 * makes the delete FAIL (jerr 10071) instead of destroying the renew.  A blind
 * kvStore_Delete() would lose that race -- never use it here.
 * Returns 0 deleted, 1 CAS-lost (a renew won -- leave the key), -1 on error. */
static int reap_cas_delete(jsCtx *js, const char *bucket, const char *key,
	uint64_t rev)
{
	char subj[512];
	natsMsg *m = NULL;
	jsPubAck *pa = NULL;
	jsErrCode je = 0;
	jsPubOptions o;
	natsStatus s;

	if (nats_kv_key_to_subject(bucket, key, subj, sizeof subj) < 0)
		return -1;
	if (nats_dl.natsMsg_Create(&m, subj, NULL, NULL, 0) != NATS_OK)
		return -1;
	if (nats_dl.natsMsgHeader_Set(m, "KV-Operation", NATS_KV_OP_DEL) != NATS_OK) {
		nats_dl.natsMsg_Destroy(m);
		return -1;
	}
	nats_dl.jsPubOptions_Init(&o);
	o.ExpectLastSubjectSeq = rev;             /* CAS predicate */
	s = nats_dl.js_PublishMsg(&pa, js, m, &o, &je);
	nats_dl.jsPubAck_Destroy(pa);
	nats_dl.natsMsg_Destroy(m);
	if (s == NATS_OK)
		return 0;
	if (je == 10071)                          /* JSStreamWrongLastSequenceErr */
		return 1;                         /* a concurrent renew won the race */
	LM_DBG("reaper: CAS-delete '%s' failed: %s (jerr=%d)\n",
		key, nats_dl.natsStatus_GetText(s), je);
	return -1;
}

/* Per-pass context threaded through nats_kv_enum_live_values(). */
struct reap_pass_ctx {
	kvStore *kv;
	jsCtx *js;
	time_t now;
	int slack;
	int prefix_len;
	int reaped;
	struct reap_pass_gauges g;
};

/* One bucket entry of the watch pass: the DUE usrloc rows are either
 * CAS-rewritten to their survivors or CAS-deleted when nothing
 * survives.  The entry (key/val) is owned by the enumerator and valid
 * for the duration of this call only; proj is independent of val.
 * Always returns 0: per-row problems skip the row, never the pass. */
static int reap_pass_entry(kvEntry *e, void *arg)
{
	struct reap_pass_ctx *c = arg;
	const char *key = nats_dl.kvEntry_Key(e);
	const char *val;
	int vlen, n_surv = 0, plen = 0, p_all_same = 0, n_before = 0;
	int64_t p_row_exp = 0;            /* survivors' TTL eligibility */
	uint64_t rev;
	char *proj;

	if (!key)
		return 0;                     /* malformed / header-only entry */
	/* only our usrloc rows; never touch another consumer's keys. */
	if (c->prefix_len && strncmp(key, fts_json_prefix, c->prefix_len) != 0)
		return 0;
	c->g.keys++;
	val = nats_dl.kvEntry_ValueString(e);
	vlen = nats_dl.kvEntry_ValueLen(e);
	rev = nats_dl.kvEntry_Revision(e);

	/* pass gauges (visibility semantics: grace only); n_before
	 * feeds the contacts_pruned tally in the survivors branch. */
	n_before = 0;
	{
		struct reg_row_info g_ri;
		if (val && vlen > 0 &&
		    cdbn_reg_row_scan(val, vlen, c->now, nats_reap_grace,
				NULL, 0, NULL, 0, &g_ri) == 0) {
			c->g.aors++;
			c->g.contacts += g_ri.n_contacts;
			c->g.active   += g_ri.n_active;
			c->g.perm     += g_ri.n_perm;
			n_before = g_ri.n_contacts;
		}
	}

	/* cheap due-gate: skip permanent / not-yet-due rows without a
	 * full reprojection (row_exp == min contact expiry). */
	if (cdbn_reap_row_due_json(val, vlen, c->now, c->slack) == 0)
		return 0;
	c->g.due++;
	proj = cdbn_reap_project_survivors(val, vlen, c->now, c->slack,
		&n_surv, &plen, &p_row_exp, &p_all_same);
	if (!proj)
		return 0;                     /* malformed/poison: read path alarms it */
	if (n_surv < 0) {                     /* not a usrloc row */
		pkg_free(proj);
		return 0;
	}
	if (n_surv == 0) {
		if (reap_cas_delete(c->js, kv_bucket, key, rev) == 0) {
			NATS_CDB_STATS_INC(rows_reaped);
			c->reaped++;
		}
	} else {
		/*: WRITE-SURVIVORS through the one row-write helper so
		 * the pruned row goes through the one row-write helper (CAS
		 * publish, conflict-classified).  The reaper defers index
		 * convergence to the watcher (no index code). */
		uint64_t newrev = 0;
		if (nats_kv_write_row_cas(c->kv, kv_bucket, key, proj, plen, rev,
				&newrev) == 0) {
			NATS_CDB_STATS_INC(rows_reaped);
			/* bindings physically removed by this survivor-write */
			if (n_before > n_surv)
				NATS_CDB_STATS_ADD(contacts_pruned,
					n_before - n_surv);
			c->reaped++;
		}
		/* CAS conflict / error: a concurrent writer won; retry next tick */
	}
	pkg_free(proj);
	return 0;
}

/* The reaper pass: scan the bucket once, and for each DUE usrloc row either
 * CAS-rewrite it to its survivors or CAS-delete it when nothing survives.
 * Runs in the dedicated reaper process (nats_cdb_reaper_proc_main
 * below).  It still does not gate on nats_pool_is_connected(): a NULL KV/JS
 * handle means the broker is down and we skip just this pass.
 *
 * Independent of the search index: enumeration is ONE
 * value-carrying watch pass (nats_kv_enum_live_values), so the reaper works
 * without the cachedb_nats_fts module.  The watch pass replaced the previous
 * kvStore_Keys() + per-key kvStore_Get() sweep: that pattern issued
 * O(bucket) synchronous round trips per tick, and the 30k-AoR bench
 * (2026-07-07) measured it dragging REGISTER p99/max from ~1 ms to
 * 27-88 ms for the 7-17 s the sweep overlapped live traffic.
 * Malformed/poison rows are LEFT in place (the read path alarms them);
 * permanent and not-yet-due rows are skipped by the cheap row_exp
 * due-gate. */
void nats_cdb_reaper_tick(unsigned int ticks, void *param)
{
	kvStore *kv;
	jsCtx *js;
	struct reap_pass_ctx c;
	int rc;
	struct timespec g_t0, g_t1;

	(void)ticks; (void)param;
	clock_gettime(CLOCK_MONOTONIC, &g_t0);

	kv = nats_pool_get_kv(kv_bucket, kv_replicas, kv_history, (int64_t)kv_ttl);
	if (!kv) {
		LM_DBG("reaper: no KV handle (broker down?); skipping tick\n");
		return;
	}
	js = nats_pool_get_js();
	if (!js) {
		LM_DBG("reaper: no JetStream ctx; skipping tick\n");
		return;
	}

	memset(&c, 0, sizeof(c));
	c.kv = kv;
	c.js = js;
	c.now = time(NULL);
	/* physical-reclamation slack: the skew margin plus the
	 * operator's retention window -- without the linger term the reaper
	 * would reclaim rows the TTL path was told to keep. */
	c.slack = nats_reap_grace + nats_expired_linger;
	c.prefix_len = (fts_json_prefix && *fts_json_prefix)
		? fts_json_prefix_len : 0;

	rc = nats_kv_enum_live_values(kv, NATS_KV_ENUM_NEXT_TIMEOUT_MS,
		reap_pass_entry, &c);
	if (rc < 0)
		/* watch create failed or the pass ended early (broker stall):
		 * whatever was visited is already handled; the reaper is
		 * idempotent, the next tick simply rescans.  The gauges keep
		 * the last complete pass (see reap_publish_pass()). */
		LM_DBG("reaper: enumeration ended early (%d); next tick rescans\n",
			rc);

	/* publish the pass gauges (single writer: this process) */
	clock_gettime(CLOCK_MONOTONIC, &g_t1);
	reap_publish_pass(rc, &c.g, (unsigned long)time(NULL),
		(g_t1.tv_sec - g_t0.tv_sec) * 1000
		+ (g_t1.tv_nsec - g_t0.tv_nsec) / 1000000);

	if (c.reaped)
		LM_INFO("cachedb_nats reaper: reclaimed %d row(s) this pass\n",
			c.reaped);
}

/* ── dedicated reaper process ─────────────────────────────── */

/* Owned by cachedb_nats.c (modparams / mod_init state). */
extern int nats_reap_interval;
extern int index_resync_interval_secs;

/*
 * nats_cdb_reaper_proc_main() -- dedicated-process host for the
 * module's periodic O(bucket) jobs: the reaper pass (one value-carrying
 * watch pass + CAS prune) and, when the FTS module is bound and
 * index_resync_interval_secs > 0, the periodic index resync.
 *
 * Both used to run as register_timer callbacks in the SHARED
 * core timer process; at 100k AoRs one pass holds that process for
 * tens of seconds, stalling usrloc/tm/dialog timers system-wide.
 * Here they stall only this process, and a slow pass simply delays
 * the next one (the due-scheduler resets stamps to "now", so there is
 * never a catch-up burst).
 *
 * Single instance, single thread against the connection pool -- the
 * same safety argument as the watcher proc.  Never returns; shutdown
 * rides the core's SIGTERM delivery, orphaning is prevented by the
 * shared PDEATHSIG guard.
 */
void nats_cdb_reaper_proc_main(int rank)
{
	nats_cdb_proc_sched_t sc;
	int run_reap, run_resync;
	/* resync is a config-time constant per process lifetime: modparams
	 * and the FTS bind both happen in mod_init, pre-fork. */
	const int resync_iv = (cdbn_fts_on && index_resync_interval_secs > 0)
		? index_resync_interval_secs : 0;

	(void)rank;

	LM_INFO("NATS reaper proc starting (pid=%d, ppid=%d): reap every "
		"%d s%s\n", (int)getpid(), (int)getppid(), nats_reap_interval,
		resync_iv > 0 ? ", index resync hosted here too" : "");

	if (nats_cdb_dedicated_proc_guard("reaper") < 0)
		return;

	/* register_timer semantics preserved: first fire one full interval
	 * after startup, not immediately.  The reap stamp additionally
	 * carries a per-instance jitter (<= interval/4, pid-derived) so
	 * the reapers of a multi-proxy deployment do not all start their
	 * first O(bucket) pass at the same uptime; steady-state cadence
	 * is untouched (the stamp resets to "now" on every fire). */
	sc.last_reap = sc.last_resync = time(NULL);
	sc.last_reap += nats_cdb_reap_first_jitter(nats_reap_interval,
		(unsigned int)getpid());

	for (;;) {
		sleep(1);
		nats_cdb_deferred_boot_checks();
		nats_cdb_proc_sched_due(&sc, time(NULL), nats_reap_interval,
			resync_iv, &run_reap, &run_resync);
		if (run_reap)
			nats_cdb_reaper_tick(0, NULL);
		if (run_resync)
			nats_cdb_periodic_resync(0, NULL);
	}
}
