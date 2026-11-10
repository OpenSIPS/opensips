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
 * cachedb_nats_kvobs.c — generic JetStream/KV introspection MI.
 *
 * The registration MI commands (cachedb_nats_reg.c) answer usrloc questions; these
 * answer the layer below, for ANY stream or bucket on the connected server:
 *
 *   nats_stream_list [filter]        streams (name glob, kv=1 for KV backing
 *                                    streams with the bucket name derived)
 *   nats_stream_info stream=<name>   one stream's config + state — the
 *                                    operator check for the TTL preconditions
 *                                    (allow_msg_ttl, max_msgs_per_subject,
 *                                    marker TTL, max_age)
 *   nats_kv_keys [filter]            LIVE keys of a bucket (markers never
 *                                    listed), key glob + pagination;
 *                                    detail=1 adds revision/created/size for
 *                                    the returned page (one Get per returned
 *                                    key, bounded by the 200 limit cap)
 *
 * Read-only by construction: buckets are BOUND (js_KeyValue), never created,
 * so a typo'd bucket name errors instead of materializing a stream.  The
 * filter parser is unit-locked in test/test_kvobs_filter.c.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fnmatch.h>

#include "../../dprint.h"
#include "../nats/nats_bind.h"
#include "../nats/nats_dl.h"
#include "../nats/nats_pool.h"
#include "cachedb_nats_dbase.h"          /* kv_bucket default                */
#include "cachedb_nats_reg.h"            /* cdbn_reg_page (shared pagination)    */
#include "cachedb_nats_fmt.h"            /* csv/txt table rendering          */
#include "cachedb_nats_emit.h"           /* one-walk row emitter             */
#include "cachedb_nats_kvobs.h"

/* ==================================================================== */
/* pure helpers — byte-identical to the carried copies in tests/        */
/* ==================================================================== */

static int kvobs_filter_kv(struct kvobs_filter *f, const char *k, int klen,
	const char *v, int vlen)
{
	char num[24];
	long n;
	char *end;

	if (vlen <= 0)
		return -1;
	/* an MI string may carry \u0000: the value is copied into C strings
	 * (bucket name, globs) that would silently stop at it */
	if (memchr(v, '\0', vlen))
		return -1;

#define KEQ(s) (klen == (int)sizeof(s)-1 && memcmp(k, s, klen) == 0)
#define CPY(dst) do { \
		if (vlen >= (int)sizeof(dst)) return -1; \
		memcpy(dst, v, vlen); dst[vlen] = '\0'; } while (0)

	if (KEQ("bucket")) { CPY(f->bucket);    return 0; }
	if (KEQ("key"))    { CPY(f->key_glob);  return 0; }
	if (KEQ("name"))   { CPY(f->name_glob); return 0; }
	if (KEQ("format")) {
		int fk = cdbn_fmt_kind_parse(v, vlen);
		if (fk < 0)
			return -1;
		f->format = fk;
		return 0;
	}
	if (KEQ("eol")) {
		if (vlen == 2 && memcmp(v, "lf", 2) == 0) f->eol_lf = 1;
		else if (vlen == 4 && memcmp(v, "crlf", 4) == 0) f->eol_lf = 0;
		else return -1;
		return 0;
	}
	if (vlen >= (int)sizeof(num))
		return -1;
	memcpy(num, v, vlen); num[vlen] = '\0';
	n = strtol(num, &end, 10);
	if (*end != '\0')
		return -1;
	if (KEQ("kv"))     { if (n != 0 && n != 1) return -1; f->kv_only = (int)n; return 0; }
	if (KEQ("detail")) { if (n != 0 && n != 1) return -1; f->detail  = (int)n; return 0; }
	if (KEQ("limit")) {
		if (n <= 0) return -1;
		f->limit = n > KVOBS_LIMIT_CAP ? KVOBS_LIMIT_CAP : n;
		return 0;
	}
	if (KEQ("offset")) { if (n < 0) return -1; f->offset = n; return 0; }
	if (KEQ("header")) { if (n != 0 && n != 1) return -1; f->header = (int)n; return 0; }
	return -1;
#undef KEQ
#undef CPY
}

int cdbn_kvobs_filter_parse(const char *s, int len, struct kvobs_filter *f)
{
	const char *p = s, *end = s + len;

	memset(f, 0, sizeof(*f));
	f->limit = KVOBS_LIMIT_DEFAULT;
	f->header = 1;

	while (p < end) {
		const char *tok = p, *eq, *te;
		while (p < end && *p != ';')
			p++;
		te = p;
		if (p < end)
			p++;
		while (tok < te && (*tok == ' ' || *tok == '\t')) tok++;
		while (te > tok && (te[-1] == ' ' || te[-1] == '\t')) te--;
		if (tok == te)
			continue;
		for (eq = tok; eq < te && *eq != '='; eq++)
			;
		if (eq == te || eq == tok)
			return -1;
		if (kvobs_filter_kv(f, tok, (int)(eq - tok),
				eq + 1, (int)(te - eq - 1)) < 0)
			return -1;
	}
	return 0;
}

int cdbn_kvobs_bucket_of_stream(const char *stream, int len,
	const char **bucket, int *blen)
{
	if (len > 3 && memcmp(stream, "KV_", 3) == 0) {
		*bucket = stream + 3;
		*blen = len - 3;
		return 0;
	}
	*bucket = NULL; *blen = 0;
	return -1;
}

/* ==================================================================== */
/* MI handlers                                                          */
/* ==================================================================== */

static const char *kvobs_storage_name(int st)
{
	return st == js_MemoryStorage ? "memory" : "file";
}

static const char *retention_name(int r)
{
	switch (r) {
	case js_InterestPolicy:  return "interest";
	case js_WorkQueuePolicy: return "workqueue";
	default:                 return "limits";
	}
}

/* ---- nats_stream_list ---------------------------------------------- */

static int stream_name_cmp(const void *a, const void *b)
{
	const jsStreamInfo *sa = *(jsStreamInfo * const *)a;
	const jsStreamInfo *sb = *(jsStreamInfo * const *)b;
	const char *na = (sa && sa->Config && sa->Config->Name) ? sa->Config->Name : "";
	const char *nb = (sb && sb->Config && sb->Config->Name) ? sb->Config->Name : "";
	return strcmp(na, nb);
}

mi_response_t *mi_nats_stream_list(const mi_params_t *params,
	struct mi_handler *async_hdl)
{
	mi_response_t *resp = NULL;
	mi_item_t *obj;
	str fstr = {NULL, 0};
	struct kvobs_filter f;
	jsCtx *js;
	jsStreamInfoList *list = NULL;
	jsStreamInfo **match = NULL;
	jsErrCode jerr = 0;
	long n = 0, start, count, i;

	(void)async_hdl;
	if (try_get_mi_string_param(params, "filter", &fstr.s, &fstr.len) < 0)
		fstr.s = NULL;
	if (cdbn_kvobs_filter_parse(fstr.s ? fstr.s : "", fstr.s ? fstr.len : 0,
			&f) < 0)
		return init_mi_error(400, MI_SSTR("bad filter (keys: name kv "
			"limit offset; ';'-separated key=value)"));

	js = nats_pool_get_js();
	if (!js)
		return init_mi_error(503, MI_SSTR("NATS unavailable"));

	if (nats_dl.js_Streams(&list, js, NULL, &jerr) != NATS_OK || !list)
		return init_mi_error(503, MI_SSTR("stream listing failed"));

	match = malloc((list->Count > 0 ? list->Count : 1) * sizeof(*match));
	if (!match) {
		nats_dl.jsStreamInfoList_Destroy(list);
		return init_mi_error(500, MI_SSTR("out of memory"));
	}
	for (i = 0; i < list->Count; i++) {
		jsStreamInfo *si = list->List[i];
		const char *name;
		const char *bk; int bl;

		if (!si || !si->Config || !si->Config->Name)
			continue;
		name = si->Config->Name;
		if (f.kv_only &&
		    cdbn_kvobs_bucket_of_stream(name, (int)strlen(name), &bk, &bl) != 0)
			continue;
		if (f.name_glob[0] && fnmatch(f.name_glob, name, 0) != 0)
			continue;
		match[n++] = si;
	}
	qsort(match, n, sizeof(*match), stream_name_cmp);
	cdbn_reg_page(n, f.limit, f.offset, &start, &count);

	resp = init_mi_result_object(&obj);
	if (!resp)
		goto oom;
	if (add_mi_number(obj, MI_SSTR("matched"), n) < 0 ||
	    add_mi_number(obj, MI_SSTR("returned"), count) < 0 ||
	    add_mi_number(obj, MI_SSTR("offset"), start) < 0)
		goto oom;
	{
		/* ONE walk; json rows land in the `streams` array,
		 * table rows in the format/data blob */
		static const char *COLS[] = {"name", "kv_bucket", "messages",
			"bytes", "subjects", "consumers", "storage"};
		struct nats_emit em;
		int rc = 0;

		if (nats_emit_open(&em, obj, MI_SSTR("streams"),
				f.format, f.eol_lf, f.header, COLS, 7) < 0)
			goto oom;
		for (i = start; i < start + count && rc == 0; i++) {
			jsStreamInfo *si = match[i];
			const char *name = si->Config->Name;
			const char *stn = kvobs_storage_name(si->Config->Storage);
			const char *bk; int bl;

			rc |= nats_emit_rec(&em);
			rc |= nats_emit_str(&em, MI_SSTR("name"),
				name, (int)strlen(name));
			if (cdbn_kvobs_bucket_of_stream(name, (int)strlen(name),
					&bk, &bl) == 0)
				rc |= nats_emit_str(&em, MI_SSTR("kv_bucket"),
					bk, bl);
			else
				rc |= nats_emit_absent(&em, MI_SSTR("kv_bucket"));
			rc |= nats_emit_i64(&em, MI_SSTR("messages"),
				(long long)si->State.Msgs);
			rc |= nats_emit_i64(&em, MI_SSTR("bytes"),
				(long long)si->State.Bytes);
			rc |= nats_emit_i64(&em, MI_SSTR("subjects"),
				(long long)si->State.NumSubjects);
			rc |= nats_emit_i64(&em, MI_SSTR("consumers"),
				(long long)si->State.Consumers);
			rc |= nats_emit_str(&em, MI_SSTR("storage"),
				stn, (int)strlen(stn));
			rc |= nats_emit_end(&em);
		}
		if (rc < 0) {
			nats_emit_abort(&em);
			goto oom;
		}
		if (nats_emit_close(&em, obj) < 0)
			goto oom;
	}
	free(match);
	nats_dl.jsStreamInfoList_Destroy(list);
	return resp;

oom:
	free(match);
	nats_dl.jsStreamInfoList_Destroy(list);
	if (resp)
		free_mi_response(resp);
	return init_mi_error(500, MI_SSTR("out of memory"));
}

/* ---- nats_stream_info ---------------------------------------------- */

mi_response_t *mi_nats_stream_info(const mi_params_t *params,
	struct mi_handler *async_hdl)
{
	mi_response_t *resp = NULL;
	mi_item_t *obj, *cfg, *st, *subj;
	str name = {NULL, 0};
	char sname[160];
	jsCtx *js;
	jsStreamInfo *si = NULL;
	jsErrCode jerr = 0;
	int i;
	int fk, f_eol, f_hdr;

	(void)async_hdl;
	if (get_mi_string_param(params, "stream", &name.s, &name.len) < 0)
		return init_mi_error(400, MI_SSTR("missing stream"));
	if (nats_mi_fmt_param(params, &fk, &f_eol, &f_hdr) < 0)
		return init_mi_error(400, MI_SSTR("bad format (json|csv|txt"
			"[;eol=lf|crlf][;header=0|1])"));
	if (name.len <= 0 || name.len >= (int)sizeof(sname))
		return init_mi_error(400, MI_SSTR("bad stream name"));
	memcpy(sname, name.s, name.len);
	sname[name.len] = '\0';

	js = nats_pool_get_js();
	if (!js)
		return init_mi_error(503, MI_SSTR("NATS unavailable"));
	if (nats_dl.js_GetStreamInfo(&si, js, sname, NULL, &jerr) != NATS_OK ||
	    !si || !si->Config)
		return init_mi_error(404, MI_SSTR("no such stream"));

	resp = init_mi_result_object(&obj);
	if (!resp)
		goto oom;
	if (add_mi_string(obj, MI_SSTR("name"), name.s, name.len) < 0)
		goto oom;
	{
		const char *bk; int bl;
		if (cdbn_kvobs_bucket_of_stream(sname, name.len, &bk, &bl) == 0 &&
		    add_mi_string(obj, MI_SSTR("kv_bucket"), (char *)bk, bl) < 0)
			goto oom;
	}

	if (fk != FMT_JSON) {
		/* csv: one flattened record; txt: field<TAB>value lines
		 * */
		struct fmt_table t;
		char *blob;
		int blen;
		const char *bk = NULL; int bl = 0;
		const char *stn = kvobs_storage_name(si->Config->Storage);
		const char *rtn = retention_name(si->Config->Retention);

		cdbn_kvobs_bucket_of_stream(sname, name.len, &bk, &bl);
		if (fk == FMT_CSV) {
			static const char *COLS[] = {"name", "kv_bucket", "storage",
				"retention", "replicas", "max_msgs_per_subject",
				"max_age_s", "allow_msg_ttl",
				"subject_delete_marker_ttl_s", "messages", "bytes",
				"first_seq", "last_seq", "subjects", "deleted",
				"consumers"};
			fmt_init(&t, fk, f_eol, f_hdr, COLS, 16);
			fmt_str(&t, sname, name.len);
			if (bk) fmt_str(&t, bk, bl); else fmt_empty(&t);
			fmt_str(&t, stn, (int)strlen(stn));
			fmt_str(&t, rtn, (int)strlen(rtn));
			fmt_int(&t, (long long)si->Config->Replicas);
			fmt_int(&t, (long long)si->Config->MaxMsgsPerSubject);
			fmt_int(&t, (long long)(si->Config->MaxAge / 1000000000LL));
			fmt_int(&t, si->Config->AllowMsgTTL ? 1 : 0);
			fmt_int(&t, (long long)(si->Config->SubjectDeleteMarkerTTL
				/ 1000000000LL));
			fmt_int(&t, (long long)si->State.Msgs);
			fmt_int(&t, (long long)si->State.Bytes);
			fmt_int(&t, (long long)si->State.FirstSeq);
			fmt_int(&t, (long long)si->State.LastSeq);
			fmt_int(&t, (long long)si->State.NumSubjects);
			fmt_int(&t, (long long)si->State.NumDeleted);
			fmt_int(&t, (long long)si->State.Consumers);
			fmt_end_record(&t);
		} else {
			static const char *COLS[] = {"field", "value"};
			fmt_init(&t, fk, f_eol, f_hdr, COLS, 2);
#define KVLINE_S(nm, v, vl) do { fmt_str(&t, nm, (int)sizeof(nm)-1); 			fmt_str(&t, v, vl); fmt_end_record(&t); } while (0)
#define KVLINE_I(nm, v) do { fmt_str(&t, nm, (int)sizeof(nm)-1); 			fmt_int(&t, (long long)(v)); fmt_end_record(&t); } while (0)
			KVLINE_S("name", sname, name.len);
			if (bk)
				KVLINE_S("kv_bucket", bk, bl);
			KVLINE_S("storage", stn, (int)strlen(stn));
			KVLINE_S("retention", rtn, (int)strlen(rtn));
			KVLINE_I("replicas", si->Config->Replicas);
			KVLINE_I("max_msgs_per_subject", si->Config->MaxMsgsPerSubject);
			KVLINE_I("max_age_s", si->Config->MaxAge / 1000000000LL);
			KVLINE_I("allow_msg_ttl", si->Config->AllowMsgTTL ? 1 : 0);
			KVLINE_I("subject_delete_marker_ttl_s",
				si->Config->SubjectDeleteMarkerTTL / 1000000000LL);
			KVLINE_I("messages", si->State.Msgs);
			KVLINE_I("bytes", si->State.Bytes);
			KVLINE_I("first_seq", si->State.FirstSeq);
			KVLINE_I("last_seq", si->State.LastSeq);
			KVLINE_I("subjects", si->State.NumSubjects);
			KVLINE_I("deleted", si->State.NumDeleted);
			KVLINE_I("consumers", si->State.Consumers);
#undef KVLINE_S
#undef KVLINE_I
		}
		blob = fmt_take(&t, &blen);
		if (nats_emit_attach_blob(obj, fk, blob, blen) < 0)
			goto oom;
		nats_dl.jsStreamInfo_Destroy(si);
		return resp;
	}

	cfg = add_mi_object(obj, MI_SSTR("config"));
	if (!cfg)
		goto oom;
	subj = add_mi_array(cfg, MI_SSTR("subjects"));
	if (!subj)
		goto oom;
	for (i = 0; i < si->Config->SubjectsLen; i++)
		if (si->Config->Subjects[i] &&
		    add_mi_string(subj, NULL, 0, (char *)si->Config->Subjects[i],
				(int)strlen(si->Config->Subjects[i])) < 0)
			goto oom;
	if (add_mi_string(cfg, MI_SSTR("storage"),
			(char *)kvobs_storage_name(si->Config->Storage),
			(int)strlen(kvobs_storage_name(si->Config->Storage))) < 0 ||
	    add_mi_string(cfg, MI_SSTR("retention"),
			(char *)retention_name(si->Config->Retention),
			(int)strlen(retention_name(si->Config->Retention))) < 0 ||
	    add_mi_number(cfg, MI_SSTR("replicas"),
			(double)si->Config->Replicas) < 0 ||
	    add_mi_number(cfg, MI_SSTR("max_msgs_per_subject"),
			(double)si->Config->MaxMsgsPerSubject) < 0 ||
	    add_mi_number(cfg, MI_SSTR("max_age_s"),
			(double)(si->Config->MaxAge / 1000000000LL)) < 0 ||
	    add_mi_bool(cfg, MI_SSTR("allow_msg_ttl"),
			si->Config->AllowMsgTTL ? 1 : 0) < 0 ||
	    add_mi_number(cfg, MI_SSTR("subject_delete_marker_ttl_s"),
			(double)(si->Config->SubjectDeleteMarkerTTL
				/ 1000000000LL)) < 0)
		goto oom;

	st = add_mi_object(obj, MI_SSTR("state"));
	if (!st)
		goto oom;
	if (add_mi_number(st, MI_SSTR("messages"), (double)si->State.Msgs) < 0 ||
	    add_mi_number(st, MI_SSTR("bytes"), (double)si->State.Bytes) < 0 ||
	    add_mi_number(st, MI_SSTR("first_seq"),
			(double)si->State.FirstSeq) < 0 ||
	    add_mi_number(st, MI_SSTR("last_seq"),
			(double)si->State.LastSeq) < 0 ||
	    add_mi_number(st, MI_SSTR("subjects"),
			(double)si->State.NumSubjects) < 0 ||
	    add_mi_number(st, MI_SSTR("deleted"),
			(double)si->State.NumDeleted) < 0 ||
	    add_mi_number(st, MI_SSTR("consumers"),
			(double)si->State.Consumers) < 0)
		goto oom;

	nats_dl.jsStreamInfo_Destroy(si);
	return resp;

oom:
	nats_dl.jsStreamInfo_Destroy(si);
	if (resp)
		free_mi_response(resp);
	return init_mi_error(500, MI_SSTR("out of memory"));
}

/* ---- nats_kv_keys ---------------------------------------------------- */

static int key_name_cmp(const void *a, const void *b)
{
	return strcmp(*(const char * const *)a, *(const char * const *)b);
}

/* glob-filter + sort the live keys into a fresh malloc'd view (may stay
 * NULL when there is nothing to match).  Match count, or -1 on OOM. */
static long kv_keys_match(const kvKeysList *keys, int have_keys,
	const struct kvobs_filter *f, const char ***match_out)
{
	const char **match;
	long n = 0, i;

	*match_out = NULL;
	if (!have_keys || keys->Count <= 0)
		return 0;
	match = malloc(keys->Count * sizeof(*match));
	if (!match)
		return -1;
	for (i = 0; i < keys->Count; i++) {
		if (!keys->Keys[i])
			continue;
		if (f->key_glob[0] &&
		    fnmatch(f->key_glob, keys->Keys[i], 0) != 0)
			continue;
		match[n++] = keys->Keys[i];
	}
	qsort(match, n, sizeof(*match), key_name_cmp);
	*match_out = match;
	return n;
}

/* the kv_keys response envelope: bucket + counts + page.  0/-1. */
static int kv_keys_meta(mi_item_t *obj, const char *bucket, long live,
	long n, long start, long count)
{
	if (add_mi_string(obj, MI_SSTR("bucket"),
			(char *)bucket, (int)strlen(bucket)) < 0 ||
	    add_mi_number(obj, MI_SSTR("live_keys"), (double)live) < 0 ||
	    add_mi_number(obj, MI_SSTR("matched"), n) < 0 ||
	    add_mi_number(obj, MI_SSTR("returned"), count) < 0 ||
	    add_mi_number(obj, MI_SSTR("offset"), start) < 0)
		return -1;
	return 0;
}

/* detail=1: one Get for @key -- revision/created/size; a key that vanished
 * mid-scan gets three empty table cells, or a json `note`. */
static int kv_key_detail(struct nats_emit *em, kvStore *kv, const char *key)
{
	kvEntry *e = NULL;
	int rc = 0;

	if (nats_dl.kvStore_Get(&e, kv, key) == NATS_OK) {
		rc |= nats_emit_i64(em, MI_SSTR("revision"),
			(long long)nats_dl.kvEntry_Revision(e));
		rc |= nats_emit_i64(em, MI_SSTR("created"),
			(long long)(nats_dl.kvEntry_Created(e) / 1000000000LL));
		rc |= nats_emit_i64(em, MI_SSTR("size"),
			nats_dl.kvEntry_ValueLen(e));
		nats_dl.kvEntry_Destroy(e);
	} else if (em->table) {
		rc |= nats_emit_absent(em, MI_SSTR("revision"));
		rc |= nats_emit_absent(em, MI_SSTR("created"));
		rc |= nats_emit_absent(em, MI_SSTR("size"));
	} else {
		rc |= nats_emit_str(em, MI_SSTR("note"),
			MI_SSTR("vanished mid-scan"));
	}
	return rc;
}

mi_response_t *mi_nats_kv_keys(const mi_params_t *params,
	struct mi_handler *async_hdl)
{
	mi_response_t *resp = NULL;
	mi_item_t *obj, *arr;
	str fstr = {NULL, 0};
	struct kvobs_filter f;
	const char *bucket;
	jsCtx *js;
	kvStore *kv = NULL;
	kvKeysList keys;
	natsStatus s;
	const char **match = NULL;
	long n = 0, start, count, i;

	(void)async_hdl;
	if (try_get_mi_string_param(params, "filter", &fstr.s, &fstr.len) < 0)
		fstr.s = NULL;
	if (cdbn_kvobs_filter_parse(fstr.s ? fstr.s : "", fstr.s ? fstr.len : 0,
			&f) < 0)
		return init_mi_error(400, MI_SSTR("bad filter (keys: bucket key "
			"detail limit offset; ';'-separated key=value)"));
	bucket = f.bucket[0] ? f.bucket : kv_bucket;

	js = nats_pool_get_js();
	if (!js)
		return init_mi_error(503, MI_SSTR("NATS unavailable"));
	/* BIND, never create: a typo'd bucket must error, not materialize. */
	if (nats_dl.js_KeyValue(&kv, js, bucket) != NATS_OK)
		return init_mi_error(404, MI_SSTR("no such bucket"));

	memset(&keys, 0, sizeof(keys));
	s = nats_dl.kvStore_Keys(&keys, kv, NULL);
	if (s != NATS_OK && s != NATS_NOT_FOUND) {
		nats_dl.kvStore_Destroy(kv);
		return init_mi_error(503, MI_SSTR("key listing failed"));
	}

	n = kv_keys_match(&keys, s == NATS_OK, &f, &match);
	if (n < 0) {
		nats_dl.kvKeysList_Destroy(&keys);
		nats_dl.kvStore_Destroy(kv);
		return init_mi_error(500, MI_SSTR("out of memory"));
	}
	cdbn_reg_page(n, f.limit, f.offset, &start, &count);

	resp = init_mi_result_object(&obj);
	if (!resp)
		goto oom;
	if (kv_keys_meta(obj, bucket, s == NATS_OK ? keys.Count : 0,
			n, start, count) < 0)
		goto oom;
	if (f.format == FMT_JSON && !f.detail) {
		/* the plain page is a BARE string array, not objects */
		arr = add_mi_array(obj, MI_SSTR("keys"));
		if (!arr)
			goto oom;
		for (i = start; i < start + count; i++)
			if (add_mi_string(arr, NULL, 0, (char *)match[i],
					(int)strlen(match[i])) < 0)
				goto oom;
	} else {
		/* ONE walk for the table pages and the json detail
		 * page; detail=1 does one Get per RETURNED key (bounded by
		 * the limit cap) */
		static const char *COLS1[] = {"key"};
		static const char *COLS4[] = {"key", "revision", "created", "size"};
		struct nats_emit em;
		int rc = 0;

		if (nats_emit_open(&em, obj, MI_SSTR("keys"),
				f.format, f.eol_lf, f.header,
				f.detail ? COLS4 : COLS1, f.detail ? 4 : 1) < 0)
			goto oom;
		for (i = start; i < start + count && rc == 0; i++) {
			rc |= nats_emit_rec(&em);
			rc |= nats_emit_str(&em, MI_SSTR("key"),
				match[i], (int)strlen(match[i]));
			if (f.detail)
				rc |= kv_key_detail(&em, kv, match[i]);
			rc |= nats_emit_end(&em);
		}
		if (rc < 0) {
			nats_emit_abort(&em);
			goto oom;
		}
		if (nats_emit_close(&em, obj) < 0)
			goto oom;
	}
	free(match);
	if (s == NATS_OK)
		nats_dl.kvKeysList_Destroy(&keys);
	nats_dl.kvStore_Destroy(kv);
	return resp;

oom:
	free(match);
	if (s == NATS_OK)
		nats_dl.kvKeysList_Destroy(&keys);
	nats_dl.kvStore_Destroy(kv);
	if (resp)
		free_mi_response(resp);
	return init_mi_error(500, MI_SSTR("out of memory"));
}
