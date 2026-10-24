/*
 * cachedb_perf - DB persistence
 *
 * Copyright (C) 2026 Yury Kirsanov
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
 * cachedb_perf - DB persistence (see pcache_db.h).
 */
#include <time.h>

#include "../../dprint.h"
#include "../../timer.h"
#include <sys/time.h>
#include "../../db/db.h"
#include "../../db/db_cap.h"
#include "../../config.h"        /* SHUTDOWN_TIMEOUT */

/* warn well before a shutdown save would hit SHUTDOWN_TIMEOUT */
#define PCACHE_DB_SLOW_SAVE_SECS  10.0

#include "pcache_db.h"
#include "pcache_htable.h"
#include "../../mem/mem.h"

static db_func_t pcache_dbf;
static int pcache_db_bound;
static str pcache_db_url;
static str pcache_db_table;

/*
 * On SQL backends (raw_query) a snapshot runs in one transaction: this
 * avoids a commit per row and makes delete+insert atomic, so a failed or
 * killed save rolls back and leaves the previous snapshot intact.
 */
static int pcache_db_raw(db_con_t *dbh, const char *what)
{
	str q;

	q.s = (char *)what;
	q.len = strlen(what);
	return pcache_dbf.raw_query(dbh, &q, NULL);
}

static int pcache_db_txn_begin(db_con_t *dbh)
{
	if (!DB_CAPABILITY(pcache_dbf, DB_CAP_RAW_QUERY) || !pcache_dbf.raw_query)
		return -1;

	/* SQLite/PostgreSQL take "BEGIN TRANSACTION", MySQL "START TRANSACTION".
	 * A bare "BEGIN" is too short for db_sqlite's raw_query, which would
	 * treat it as a SELECT. */
	if (pcache_db_raw(dbh, "BEGIN TRANSACTION") == 0)
		return 0;
	if (pcache_db_raw(dbh, "START TRANSACTION") == 0)
		return 0;

	LM_DBG("backend did not accept a transaction - saving without one\n");
	return -1;
}

static int pcache_db_txn_commit(db_con_t *dbh)
{
	return pcache_db_raw(dbh, "COMMIT");
}

/* one row per cache entry: (collection, pkey, pvalue, expires) */
static str col_collection = str_init("collection");
static str col_pkey       = str_init("pkey");
static str col_pvalue     = str_init("pvalue");
static str col_expires    = str_init("expires");

int pcache_db_enabled(void)
{
	return pcache_db_bound;
}

/* read a TEXT/BLOB column as a str whatever type the driver reports;
 * -1 if NULL or unsupported */
static int db_col_str(const db_val_t *v, str *out)
{
	if (VAL_NULL(v))
		return -1;
	switch (VAL_TYPE(v)) {
	case DB_STR:
		*out = VAL_STR(v);
		break;
	case DB_BLOB:
		*out = VAL_BLOB(v);
		break;
	case DB_STRING:
		out->s = (char *)VAL_STRING(v);
		out->len = out->s ? strlen(out->s) : 0;
		break;
	default:
		return -1;
	}
	return 0;
}

int pcache_db_init(const str *db_url, const str *db_table)
{
	if (db_bind_mod(db_url, &pcache_dbf) < 0) {
		LM_ERR("cannot bind to a database module for <%.*s> - is the "
			"matching db_* module loaded?\n", db_url->len, db_url->s);
		return -1;
	}
	if (!DB_CAPABILITY(pcache_dbf,
	        DB_CAP_QUERY | DB_CAP_INSERT | DB_CAP_DELETE)) {
		LM_ERR("the database backend lacks query/insert/delete support\n");
		return -1;
	}
	pcache_db_url = *db_url;
	pcache_db_table = *db_table;
	pcache_db_bound = 1;
	LM_INFO("DB persistence bound to <%.*s>, table <%.*s>\n",
		db_url->len, db_url->s, db_table->len, db_table->s);
	return 0;
}

/*
 * A walk may hand a key over twice: a split, or the leg drain moving a
 * record, while it runs.  Each key a save writes is remembered by a 64-bit
 * fingerprint, so the count is of keys; with replace a repeat rewrites its
 * row, without it a repeat is skipped, as an insert would fail on a unique
 * (collection, pkey).
 */
struct db_save_ctx {
	db_con_t *dbh;
	str *coll;
	unsigned int now_ticks;
	long now_wall;
	int n, err;
	int replace;
	uint64_t *seen;                 /* open addressing, 0 = empty */
	unsigned int seen_cap, seen_n;
	int seen_full;                  /* no memory to grow: not tracked */
};

/* set only by the selftest: write with insert although replace exists */
static int st_no_replace;

static void seen_put(uint64_t *tab, unsigned int cap, uint64_t h)
{
	unsigned int i;

	for (i = h & (cap - 1); tab[i]; i = (i + 1) & (cap - 1))
		;
	tab[i] = h;
}

/* 1 = first time in this save, 0 = handed over before, -1 = not tracked */
static int seen_add(struct db_save_ctx *sc, const str *key)
{
	uint64_t h = 0xcbf29ce484222325ULL, *tab;
	unsigned int i, cap;
	int k;

	if (sc->seen_full)
		return -1;
	for (k = 0; k < key->len; k++)
		h = (h ^ (unsigned char)key->s[k]) * 0x100000001b3ULL;
	if (!h)
		h = 1;
	if (2 * (sc->seen_n + 1) > sc->seen_cap) {      /* at most half full */
		cap = sc->seen_cap ? 2 * sc->seen_cap : 1024;
		tab = pkg_malloc(cap * sizeof *tab);
		if (!tab) {
			LM_WARN("no pkg memory to track the keys of this save - a "
				"key handed over twice may be counted twice%s\n",
				sc->replace ? "" : " or fail on a unique key");
			sc->seen_full = 1;
			return -1;
		}
		memset(tab, 0, cap * sizeof *tab);
		for (i = 0; i < sc->seen_cap; i++)
			if (sc->seen[i])
				seen_put(tab, cap, sc->seen[i]);
		if (sc->seen)
			pkg_free(sc->seen);
		sc->seen = tab;
		sc->seen_cap = cap;
	}
	for (i = h & (sc->seen_cap - 1); sc->seen[i];
	        i = (i + 1) & (sc->seen_cap - 1))
		if (sc->seen[i] == h)
			return 0;
	sc->seen[i] = h;
	sc->seen_n++;
	return 1;
}

static int db_save_cb(const str *key, const str *val, unsigned int exp,
		void *p)
{
	struct db_save_ctx *sc = p;
	static db_key_t cols[4] =
		{ &col_collection, &col_pkey, &col_pvalue, &col_expires };
	db_val_t vals[4];
	int first, rc;

	if (exp && exp <= sc->now_ticks)
		return 0;
	first = seen_add(sc, key);
	if (!first && !sc->replace)
		return 0;

	memset(vals, 0, sizeof vals);
	VAL_TYPE(&vals[0]) = DB_STR;   VAL_STR(&vals[0])  = *sc->coll;
	VAL_TYPE(&vals[1]) = DB_STR;   VAL_STR(&vals[1])  = *(str *)key;
	VAL_TYPE(&vals[2]) = DB_BLOB;  VAL_BLOB(&vals[2]) = *(str *)val;
	VAL_TYPE(&vals[3]) = DB_INT;
	/* monotonic ticks -> absolute wall clock, so the TTL survives a reboot */
	VAL_INT(&vals[3]) = exp ?
		(int)(sc->now_wall + (long)(exp - sc->now_ticks)) : 0;

	rc = sc->replace ? pcache_dbf.replace(sc->dbh, cols, vals, 4) :
		pcache_dbf.insert(sc->dbh, cols, vals, 4);
	if (rc < 0) {
		LM_ERR("%s failed for key <%.*s>\n", sc->replace ? "replace" :
			"insert", key->len, key->s);
		sc->err = 1;
		return -1;                        /* stop the walk */
	}
	if (first)
		sc->n++;
	return 0;
}

int pcache_db_save(pcache_col_t *col)
{
	db_con_t *dbh;
	db_key_t wk[1] = { &col_collection };
	db_val_t wv[1];
	struct db_save_ctx sc;
	struct timeval t0, t1;
	double secs;
	int txn;

	if (!pcache_db_bound) {
		LM_ERR("no DB backend configured (set db_url)\n");
		return -1;
	}
	dbh = pcache_dbf.init(&pcache_db_url);
	if (!dbh) {
		LM_ERR("cannot open the DB connection\n");
		return -1;
	}
	if (pcache_dbf.use_table(dbh, &pcache_db_table) < 0) {
		LM_ERR("use_table <%.*s> failed\n",
			pcache_db_table.len, pcache_db_table.s);
		pcache_dbf.close(dbh);
		return -1;
	}

	gettimeofday(&t0, NULL);

	txn = pcache_db_txn_begin(dbh) == 0;

	memset(wv, 0, sizeof wv);
	VAL_TYPE(&wv[0]) = DB_STR;
	VAL_STR(&wv[0]) = col->col_name;
	if (pcache_dbf.delete(dbh, wk, NULL, wv, 1) < 0) {
		LM_ERR("failed to clear old rows for <%.*s>\n",
			col->col_name.len, col->col_name.s);
		/* closing without COMMIT rolls back - the old snapshot survives */
		pcache_dbf.close(dbh);
		return -1;
	}

	memset(&sc, 0, sizeof sc);
	sc.dbh = dbh;
	sc.coll = &col->col_name;
	sc.now_ticks = get_ticks();
	sc.now_wall = (long)time(NULL);
	sc.replace = DB_CAPABILITY(pcache_dbf, DB_CAP_REPLACE) && !st_no_replace;
	pcache_ht_iter(col->htable, db_save_cb, &sc);
	if (sc.seen)
		pkg_free(sc.seen);

	if (sc.err) {
		LM_ERR("collection <%.*s>: save failed after %d rows - the previous "
			"snapshot is left in place\n",
			col->col_name.len, col->col_name.s, sc.n);
		pcache_dbf.close(dbh);
		return -1;
	}
	if (txn && pcache_db_txn_commit(dbh) < 0) {
		LM_ERR("collection <%.*s>: could not commit %d rows - the previous "
			"snapshot is left in place\n",
			col->col_name.len, col->col_name.s, sc.n);
		pcache_dbf.close(dbh);
		return -1;
	}
	pcache_dbf.close(dbh);

	gettimeofday(&t1, NULL);
	secs = (t1.tv_sec - t0.tv_sec) + (t1.tv_usec - t0.tv_usec) / 1e6;
	LM_INFO("collection <%.*s>: saved %d entries in %.2f s (%.0f rows/s)%s\n",
		col->col_name.len, col->col_name.s, sc.n, secs,
		secs > 0 ? sc.n / secs : 0.0,
		txn ? "" : " [no transaction - backend has no raw_query]");

	if (secs > PCACHE_DB_SLOW_SAVE_SECS)
		LM_WARN("collection <%.*s>: the snapshot took %.1f s for %d entries%s. "
			"A save on shutdown has to finish within %d s or the core aborts "
			"the process; the snapshot itself is safe (it is rolled back, "
			"leaving the previous one) but no new one is written. Persist "
			"fewer entries, or move to a backend that can hold the snapshot "
			"in one transaction.\n",
			col->col_name.len, col->col_name.s, secs, sc.n,
			txn ? "" : " - and this backend took no transaction, so every "
			"row was committed separately",
			SHUTDOWN_TIMEOUT);

	return sc.n;
}

#define DCHK(cond, ...) \
	do { \
		if (!(cond)) { \
			LM_ERR("db selftest FAILED: " __VA_ARGS__); \
			return -1; \
		} \
	} while (0)

static void st_drain_mid_walk(pcache_htable_t *ht)
{
	unsigned long p0 = pcache_ht_drain_passes(ht);

	pcache_ht_selftest_walk_hook(NULL);
	do
		pcache_ht_drain_leg(ht, 1024);
	while (pcache_ht_drain_passes(ht) == p0 && pcache_ht_overflow(ht));
}

/* a save while the leg drain moves records under its walk writes every key
 * once, with replace and with insert; rows go to the configured table
 * under a collection of their own and are removed afterwards */
int pcache_db_selftest(void)
{
	static const char cname[] = "cachedb_perf-selftest";
	db_key_t wk[1] = { &col_collection };
	db_val_t wv[1];
	pcache_col_t col;
	db_con_t *dbh;
	unsigned int i, miss;
	char kb[32];
	str k, v;
	int pass, rc;

	memset(&col, 0, sizeof col);
	col.col_name.s = (char *)cname;
	col.col_name.len = sizeof cname - 1;
	v.s = "v"; v.len = 1;
	for (pass = 0; pass < 2; pass++) {
		col.htable = pcache_htable_new(4);
		DCHK(col.htable != NULL, "table creation failed\n");
		for (i = 0; i < 300; i++) {
			k.len = snprintf(kb, sizeof kb, "dbst-%03u", i); k.s = kb;
			DCHK(pcache_ht_store(col.htable, &k, &v, 0) == 0,
				"store %u failed\n", i);
		}
		DCHK(pcache_ht_overflow(col.htable) > 0, "nothing in the leg\n");
		pcache_ht_grow(col.htable, 2, 100000);      /* room to drain into */

		st_no_replace = pass;
		pcache_ht_selftest_walk_hook(st_drain_mid_walk);
		rc = pcache_db_save(&col);
		pcache_ht_selftest_walk_hook(NULL);
		st_no_replace = 0;
		DCHK(col.htable->drain_moved > 0, "the drain moved nothing "
			"during the save\n");
		DCHK(rc == 300, "a save with records moving under it (%s) "
			"wrote %d of 300 keys\n", pass ? "insert" : "replace if "
			"available", rc);

		col.htable = pcache_htable_new(4);
		DCHK(col.htable != NULL, "table creation failed\n");
		rc = pcache_db_load(&col);
		DCHK(rc == 300, "%d rows came back, 300 expected\n", rc);
		for (i = 0, miss = 0; i < 300; i++) {
			k.len = snprintf(kb, sizeof kb, "dbst-%03u", i); k.s = kb;
			miss += pcache_ht_probe(col.htable, &k, NULL, NULL, NULL) != 0;
		}
		DCHK(!miss, "%u of 300 keys missing after the reload\n", miss);
	}

	dbh = pcache_dbf.init(&pcache_db_url);
	DCHK(dbh != NULL, "cannot open the DB connection\n");
	if (pcache_dbf.use_table(dbh, &pcache_db_table) == 0) {
		memset(wv, 0, sizeof wv);
		VAL_TYPE(&wv[0]) = DB_STR;
		VAL_STR(&wv[0]) = col.col_name;
		pcache_dbf.delete(dbh, wk, NULL, wv, 1);
	}
	pcache_dbf.close(dbh);
	LM_NOTICE("db selftest: PASS - saves with records moving under the "
		"walk wrote every key once (%s)\n",
		DB_CAPABILITY(pcache_dbf, DB_CAP_REPLACE) ? "replace, then insert" :
		"insert twice: the backend has no replace");
	return 0;
}

int pcache_db_load(pcache_col_t *col)
{
	db_con_t *dbh;
	db_key_t qcols[3] = { &col_pkey, &col_pvalue, &col_expires };
	db_key_t wk[1] = { &col_collection };
	db_val_t wv[1];
	db_res_t *res = NULL;
	db_row_t *rows;
	db_val_t *v;
	str key, val;
	unsigned int now_ticks;
	long now_wall;
	int i, expires, remaining, n = 0, stale = 0;

	if (!pcache_db_bound) {
		LM_ERR("no DB backend configured (set db_url)\n");
		return -1;
	}
	dbh = pcache_dbf.init(&pcache_db_url);
	if (!dbh) {
		LM_ERR("cannot open the DB connection\n");
		return -1;
	}
	if (pcache_dbf.use_table(dbh, &pcache_db_table) < 0) {
		LM_ERR("use_table <%.*s> failed\n",
			pcache_db_table.len, pcache_db_table.s);
		pcache_dbf.close(dbh);
		return -1;
	}

	memset(wv, 0, sizeof wv);
	VAL_TYPE(&wv[0]) = DB_STR;
	VAL_STR(&wv[0]) = col->col_name;
	if (pcache_dbf.query(dbh, wk, NULL, wv, qcols, 1, 3, NULL, &res) < 0) {
		LM_ERR("query for <%.*s> failed\n",
			col->col_name.len, col->col_name.s);
		pcache_dbf.close(dbh);
		return -1;
	}

	now_ticks = get_ticks();
	now_wall = (long)time(NULL);
	rows = RES_ROWS(res);
	for (i = 0; i < RES_ROW_N(res); i++) {
		v = ROW_VALUES(rows + i);
		if (db_col_str(&v[0], &key) < 0 || db_col_str(&v[1], &val) < 0)
			continue;
		expires = VAL_NULL(&v[2]) ? 0 : VAL_INT(&v[2]);

		if (expires == 0) {
			remaining = 0;
		} else {
			remaining = expires - (int)now_wall;
			if (remaining <= 0) {
				stale++;
				continue;
			}
		}
		if (pcache_ht_store(col->htable, &key, &val,
		        remaining ? now_ticks + (unsigned int)remaining : 0) < 0) {
			LM_ERR("store of <%.*s> failed during load\n",
				key.len, key.s);
			continue;
		}
		n++;
	}
	pcache_dbf.free_result(dbh, res);

	/* drop expired rows, which no later save may rewrite (e.g. db_mode=1);
	 * expires=0 means "never" and must be excluded from the <= match */
	if (stale > 0) {
		db_key_t dk[3] = { &col_collection, &col_expires, &col_expires };
		db_op_t  dop[3] = { OP_EQ, OP_GT, OP_LEQ };
		db_val_t dv[3];

		memset(dv, 0, sizeof dv);
		VAL_TYPE(&dv[0]) = DB_STR;  VAL_STR(&dv[0]) = col->col_name;
		VAL_TYPE(&dv[1]) = DB_INT;  VAL_INT(&dv[1]) = 0;
		VAL_TYPE(&dv[2]) = DB_INT;  VAL_INT(&dv[2]) = (int)now_wall;

		if (pcache_dbf.delete(dbh, dk, dop, dv, 3) < 0)
			LM_WARN("collection <%.*s>: could not remove %d stale entries "
				"- they are ignored, but will be retried on the next "
				"load and cleared by the next save\n",
				col->col_name.len, col->col_name.s, stale);
		else
			LM_INFO("collection <%.*s>: removed %d stale entries\n",
				col->col_name.len, col->col_name.s, stale);
	}

	pcache_dbf.close(dbh);
	LM_INFO("collection <%.*s>: loaded %d entries\n",
		col->col_name.len, col->col_name.s, n);
	return n;
}
