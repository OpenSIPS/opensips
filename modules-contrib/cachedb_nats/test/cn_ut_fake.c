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
 *
 * Fixture of the cachedb_nats tests (cn_ut_fake.h).
 */

#include <tap.h>
#include <stdio.h>
#include <string.h>

#include "../../nats/nats_bind.h"
#include "../../../mem/shm_mem.h"
#include "../../../evi/evi_modules.h"
#include "../cachedb_nats.h"
#include "../cachedb_nats_watch.h"
#include "../cachedb_nats_json.h"
#include "../../../cachedb/cachedb.h"

#include "cn_ut_fake.h"
#include "../../nats/test/nats_ut_log.h"

struct cn_ut_fake cf;

static struct nats_binds real_api;
static cdbn_fts_api_t real_fts;
static int real_fts_on, real_resync;
static event_id_t real_evi;
static int (*real_dispatch)(void (*)(int, void *), void *);
static nats_dl_funcs_t fake_dl;
static int obj_kv, obj_w, obj_js, obj_msg;
static jsPubAck fake_ack;

extern int index_resync_on_reconnect;
extern event_id_t evi_kv_change_id;

void *cn_ut_fake_kv(void) { return &obj_kv; }

static void rec(const char *what, const char *arg)
{
	size_t n = strlen(cf.seq);

	snprintf(cf.seq + n, sizeof cf.seq - n, arg ? "%s:%s," : "%s,", what, arg);
}

/* ── pool ───────────────────────────────────────────────────────── */

static int f_is_connected(void)
{
	/* polled while down after a teardown: the loop would wait for a
	 * reconnect that never comes -- end it (bounds a broken teardown) */
	if (!cf.connected && strstr(cf.seq, "stop,"))
		cn_ut_watcher_stop();
	return cf.connected;
}
static int f_epoch(void) { return cf.epoch; }
static jsCtx *f_get_js(void) { return (jsCtx *)&obj_js; }
static kvStore *f_get_kv(const char *bucket, int replicas, int history,
	int64_t ttl)
{
	(void)bucket; (void)replicas; (void)history; (void)ttl;
	rec("get_kv", NULL);
	return cf.kv_null ? NULL : (kvStore *)&obj_kv;
}

/* ── libnats ────────────────────────────────────────────────────── */

static const char *f_GetText(natsStatus s) { (void)s; return "fake"; }
static const char *f_LastError(natsStatus *s) { if (s) *s = NATS_OK; return NULL; }

static natsStatus f_WatchOptions_Init(kvWatchOptions *o)
{ memset(o, 0, sizeof *o); return NATS_OK; }

static natsStatus f_WatchMulti(kvWatcher **w, kvStore *kv, const char **keys,
	int n, const kvWatchOptions *o)
{
	(void)kv; (void)keys; (void)n;
	rec("watch", NULL);
	cf.updates_only = o && o->UpdatesOnly;
	cf.resume_from = o ? o->ResumeFromRevision : 0;
	if (cf.watch_status == NATS_OK)
		*w = (kvWatcher *)&obj_w;
	return cf.watch_status;
}

static natsStatus f_WatchAll(kvWatcher **w, kvStore *kv, const kvWatchOptions *o)
{ return f_WatchMulti(w, kv, NULL, 0, o); }

static natsStatus f_Next(kvEntry **e, kvWatcher *w, int64_t timeout)
{
	struct cn_ut_entry *x;

	(void)w; (void)timeout;
	if (cf.i_next >= cf.n_next) {
		/* script over: end the loop */
		cn_ut_watcher_stop();
		*e = NULL;
		return NATS_ERR;
	}
	x = &cf.next[cf.i_next++];
	if (x->disconnect)
		cf.connected = 0;
	if (x->reconnect)
		cf.epoch++;
	*e = x->status == NATS_OK && (x->key || x->op) ? (kvEntry *)x : NULL;
	return x->status;
}

static natsStatus f_Stop(kvWatcher *w) { (void)w; rec("stop", NULL); return NATS_OK; }
static void f_WDestroy(kvWatcher *w)
{
	(void)w;
	rec("destroy", NULL);
	if (cf.stop_on_destroy)
		cn_ut_watcher_stop();
}

#define E(e) ((const struct cn_ut_entry *)(const void *)(e))
static const char *f_Key(const kvEntry *e) { return E(e)->key; }
static kvOperation f_Op(const kvEntry *e) { return (kvOperation)E(e)->op; }
static const char *f_ValStr(const kvEntry *e) { return E(e)->val; }
static int f_ValLen(const kvEntry *e) { return E(e)->val_len; }
static uint64_t f_Rev(const kvEntry *e) { return E(e)->rev; }
static void f_EDestroy(kvEntry *e)
{
	/* a freed entry's buffer is garbage: show it, so a read after
	 * destroy is visible without ASan */
	if (cf.scribble && E(e)->val == cf.val_buf)
		memset(cf.val_buf, 'X', sizeof cf.val_buf - 1);
	cf.n_entry_destroy++;
}

static natsStatus f_Get(kvEntry **e, kvStore *kv, const char *key)
{
	(void)kv;
	rec("get", key);
	if (cf.get.status == NATS_OK)
		*e = (kvEntry *)&cf.get;
	return cf.get.status;
}

/* the row writes */
static void keep(const void *data, int len)
{
	if (len < 0 || (size_t)len >= sizeof cf.published)
		len = (int)sizeof cf.published - 1;
	memcpy(cf.published, data, (size_t)len);
	cf.published[len] = '\0';
}

static natsStatus f_CreateWithTTL(uint64_t *rev, kvStore *kv, const char *key,
	const void *data, int len, int64_t ttl)
{
	(void)kv; (void)ttl;
	rec("create", key);
	keep(data, len);
	if (cf.create_status == NATS_OK && rev)
		*rev = 1;
	return cf.create_status;
}

static natsStatus f_MsgCreate(natsMsg **m, const char *subj, const char *reply,
	const char *data, int len)
{
	(void)reply;
	rec("msg", subj);
	cf.msg_data = data;
	cf.msg_len = len;
	keep(data, len);
	*m = (natsMsg *)&obj_msg;
	return NATS_OK;
}

static natsStatus f_HeaderSet(natsMsg *m, const char *k, const char *v)
{
	char kv[96];

	(void)m;
	snprintf(kv, sizeof kv, "%s=%s", k, v);
	rec("header", kv);
	return NATS_OK;
}

static natsStatus f_PubOptInit(jsPubOptions *o) { memset(o, 0, sizeof *o); return NATS_OK; }

static natsStatus f_PublishMsg(jsPubAck **pa, jsCtx *js, natsMsg *m,
	jsPubOptions *o, jsErrCode *je)
{
	char at[32];

	(void)js; (void)m;
	cf.expect_last_seq = o ? o->ExpectLastSubjectSeq : 0;
	snprintf(at, sizeof at, "%llu", (unsigned long long)cf.expect_last_seq);
	rec("publish", at);
	if (je)
		*je = (jsErrCode)cf.publish_jerr;
	if (cf.publish_status == NATS_OK) {
		memset(&fake_ack, 0, sizeof fake_ack);
		fake_ack.Sequence = cf.publish_seq;
		*pa = &fake_ack;
	}
	return cf.publish_status;
}

static jsStreamInfo fake_si;
static natsStatus f_StreamInfo(jsStreamInfo **si, jsCtx *js, const char *stream,
	jsOptions *o, jsErrCode *je)
{
	(void)js; (void)o; (void)je;
	rec("stream_info", stream);
	if (!cf.have_stream_last)
		return NATS_ERR;
	memset(&fake_si, 0, sizeof fake_si);
	fake_si.State.LastSeq = cf.stream_last;
	*si = &fake_si;
	return NATS_OK;
}
static void f_SIDestroy(jsStreamInfo *si) { (void)si; }

static natsStatus f_History(kvEntryList *l, kvStore *kv, const char *key,
	const kvWatchOptions *o)
{
	(void)kv; (void)o;
	rec("history", key);
	memset(l, 0, sizeof *l);
	return NATS_NOT_FOUND;
}

static void f_AckDestroy(jsPubAck *pa) { (void)pa; }
static void f_MsgDestroyW(natsMsg *m) { (void)m; }

/* forbidden on the row path: recorded so a test can see it */
static natsStatus f_UpdateString(uint64_t *rev, kvStore *kv, const char *key,
	const char *data, uint64_t last)
{
	(void)kv; (void)last;
	rec("update_string", key);
	keep(data, (int)strlen(data));
	if (rev)
		*rev = last + 1;
	return cf.create_status;
}
static natsStatus f_CreateString(uint64_t *rev, kvStore *kv, const char *key,
	const char *data)
{
	(void)kv;
	rec("create_string", key);
	keep(data, (int)strlen(data));
	if (rev)
		*rev = 1;
	return cf.create_status;
}
static natsStatus f_PutString(uint64_t *rev, kvStore *kv, const char *key,
	const char *data)
{
	(void)rev; (void)kv; (void)data;
	rec("put_string", key);
	return NATS_OK;
}

/* ── FTS binds ──────────────────────────────────────────────────── */

static int f_rebuild(kvStore *kv, const char *prefix)
{ (void)kv; (void)prefix; rec("rebuild", NULL); return cf.rebuild_rc; }
static int f_add(const char *key, int key_len, const char *val, int val_len)
{ (void)key_len; (void)val; (void)val_len; rec("add", key); return 0; }
static int f_remove(const char *key, int key_len)
{ (void)key_len; rec("remove", key); return 0; }
static int f_revmap(const char *key, int key_len)
{ (void)key_len; rec("revmap", key); return cf.revmap_rc; }
static int f_remove_fields(const char *key, int key_len, const char *json,
	int json_len)
{ (void)key_len; (void)json; (void)json_len; rec("remove_fields", key); return 0; }
static int f_count(void) { return 0; }
static int f_query(const cdb_filter_t *f, char ***keys, int *count)
{
	(void)f;
	rec("query", NULL);
	*keys = cf.match;
	*count = cf.n_match;
	return 0;
}
static void f_release(char **keys, int count)
{ (void)keys; (void)count; cf.n_release++; }

/* ── the watcher's event dispatch ───────────────────────────────── */

static int f_dispatch(void (*rpc)(int, void *), void *ev)
{
	int op = -1, val_len = -1;
	const char *key = NULL;

	(void)rpc;
	rec("event", NULL);
	cn_ut_kv_change_ev(ev, &op, &key, &val_len);
	if (cf.n_events < CN_UT_MAX_EVENTS) {
		cf.ev_op[cf.n_events] = op;
		snprintf(cf.ev_key[cf.n_events], sizeof cf.ev_key[0], "%s",
			key ? key : "(null)");
		cf.ev_val_len[cf.n_events] = val_len;
		cf.n_events++;
	}
	shm_free(ev);
	return 0;
}

/* ── scenarios ──────────────────────────────────────────────────── */

void cn_ut_fake_begin(void)
{
	real_api = nats_api;
	real_fts = cdbn_fts;
	real_fts_on = cdbn_fts_on;
	real_resync = index_resync_on_reconnect;
	real_evi = evi_kv_change_id;
	real_dispatch = cn_ut_kv_change_dispatch;

	memset(&cf, 0, sizeof cf);
	cf.connected = 1;
	cf.watch_status = NATS_OK;
	cf.get.status = NATS_NOT_FOUND;
	cf.revmap_rc = -1;
	cf.create_status = NATS_OK;
	cf.publish_status = NATS_OK;
	cf.publish_seq = 42;

	memset(&fake_dl, 0, sizeof fake_dl);
	fake_dl.natsStatus_GetText = f_GetText;
	fake_dl.nats_GetLastError = f_LastError;
	fake_dl.kvWatchOptions_Init = f_WatchOptions_Init;
	fake_dl.kvStore_WatchMulti = f_WatchMulti;
	fake_dl.kvStore_WatchAll = f_WatchAll;
	fake_dl.kvWatcher_Next = f_Next;
	fake_dl.kvWatcher_Stop = f_Stop;
	fake_dl.kvWatcher_Destroy = f_WDestroy;
	fake_dl.kvEntry_Key = f_Key;
	fake_dl.kvEntry_Operation = f_Op;
	fake_dl.kvEntry_ValueString = f_ValStr;
	fake_dl.kvEntry_ValueLen = f_ValLen;
	fake_dl.kvEntry_Revision = f_Rev;
	fake_dl.kvEntry_Destroy = f_EDestroy;
	fake_dl.kvStore_Get = f_Get;
	fake_dl.kvStore_CreateWithTTL = f_CreateWithTTL;
	fake_dl.natsMsg_Create = f_MsgCreate;
	fake_dl.natsMsgHeader_Set = f_HeaderSet;
	fake_dl.jsPubOptions_Init = f_PubOptInit;
	fake_dl.js_PublishMsg = f_PublishMsg;
	fake_dl.jsPubAck_Destroy = f_AckDestroy;
	fake_dl.natsMsg_Destroy = f_MsgDestroyW;
	fake_dl.kvStore_UpdateString = f_UpdateString;
	fake_dl.kvStore_PutString = f_PutString;
	fake_dl.kvStore_CreateString = f_CreateString;
	fake_dl.js_GetStreamInfo = f_StreamInfo;
	fake_dl.kvStore_History = f_History;
	fake_dl.jsStreamInfo_Destroy = f_SIDestroy;

	nats_api.dl = &fake_dl;
	nats_api.pool_is_connected = f_is_connected;
	nats_api.pool_get_reconnect_epoch = f_epoch;
	nats_api.pool_get_js = f_get_js;
	nats_api.pool_get_kv = f_get_kv;

	memset(&cdbn_fts, 0, sizeof cdbn_fts);
	cdbn_fts.rebuild = f_rebuild;
	cdbn_fts.add = f_add;
	cdbn_fts.remove = f_remove;
	cdbn_fts.remove_by_revmap = f_revmap;
	cdbn_fts.count = f_count;
	cdbn_fts.remove_fields = f_remove_fields;
	cdbn_fts.query_match_keys = f_query;
	cdbn_fts.release_keyset = f_release;
	cdbn_fts_on = 1;
	index_resync_on_reconnect = 1;
	evi_kv_change_id = EVI_ERROR;   /* a test turns events on */
	cn_ut_kv_change_dispatch = f_dispatch;
	ut_log_start(L_DBG);
}

void cn_ut_fake_end(void)
{
	ut_log_stop();
	nats_api = real_api;
	cdbn_fts = real_fts;
	cdbn_fts_on = real_fts_on;
	index_resync_on_reconnect = real_resync;
	evi_kv_change_id = real_evi;
	cn_ut_kv_change_dispatch = real_dispatch;
}

const char *cn_ut_fake_log(void) { return ut_log(); }
void cn_ut_fake_log_clear(void) { ut_log_clear(); }
unsigned long cn_ut_fake_log_raw(char *buf, unsigned long size) { return ut_log_raw(buf, size); }

static int dict_count(const cdb_dict_t *d)
{
	struct list_head *it;
	int n = 0;

	list_for_each(it, d)
		n++;
	return n;
}

int cn_ut_pk_read(const char *aor, const char *stored, int *n_contacts,
	int *n_private)
{
	cachedb_con con;
	nats_cachedb_con ncon;
	cdb_filter_t f;
	cdb_res_t res;
	struct list_head *it;
	int rc;

	*n_contacts = -1;
	*n_private = 0;
	memset(&con, 0, sizeof con);
	memset(&ncon, 0, sizeof ncon);
	ncon.kv = (kvStore *)&obj_kv;
	con.data = &ncon;
	memset(&f, 0, sizeof f);
	f.key.name.s = "aor";
	f.key.name.len = 3;
	f.key.is_pk = 1;
	f.op = CDB_OP_EQ;
	f.val.is_str = 1;
	f.val.s.s = (char *)aor;
	f.val.s.len = (int)strlen(aor);
	cf.get.status = stored ? NATS_OK : NATS_NOT_FOUND;
	cf.get.val = stored;
	cf.get.val_len = stored ? (int)strlen(stored) : 0;
	cf.get.rev = 5;
	rc = nats_cache_query(&con, &f, &res);
	if (rc < 0)
		return -1;
	if (res.count > 0) {
		cdb_row_t *row = list_entry(res.rows.next, cdb_row_t, list);

		list_for_each(it, &row->dict) {
			cdb_pair_t *p = list_entry(it, cdb_pair_t, list);

			if (p->key.name.len == 8 && !memcmp(p->key.name.s, "contacts", 8)
					&& p->val.type == CDB_DICT)
				*n_contacts = dict_count(&p->val.val.dict);
			if ((p->key.name.len == 7 && !memcmp(p->key.name.s, "row_exp", 7)) ||
			    (p->key.name.len == 14 && !memcmp(p->key.name.s, "schema_version", 14)))
				(*n_private)++;
		}
	}
	rc = res.count;
	cdb_free_rows(&res);
	return rc;
}
