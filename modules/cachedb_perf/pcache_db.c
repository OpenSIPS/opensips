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

struct db_save_ctx {
	db_con_t *dbh;
	str *coll;
	unsigned int now_ticks;
	long now_wall;
	int n, err;
};

static int db_save_cb(const str *key, const str *val, unsigned int exp,
		void *p)
{
	struct db_save_ctx *sc = p;
	static db_key_t cols[4] =
		{ &col_collection, &col_pkey, &col_pvalue, &col_expires };
	db_val_t vals[4];

	if (exp && exp <= sc->now_ticks)
		return 0;

	memset(vals, 0, sizeof vals);
	VAL_TYPE(&vals[0]) = DB_STR;   VAL_STR(&vals[0])  = *sc->coll;
	VAL_TYPE(&vals[1]) = DB_STR;   VAL_STR(&vals[1])  = *(str *)key;
	VAL_TYPE(&vals[2]) = DB_BLOB;  VAL_BLOB(&vals[2]) = *(str *)val;
	VAL_TYPE(&vals[3]) = DB_INT;
	/* monotonic ticks -> absolute wall clock, so the TTL survives a reboot */
	VAL_INT(&vals[3]) = exp ?
		(int)(sc->now_wall + (long)(exp - sc->now_ticks)) : 0;

	if (pcache_dbf.insert(sc->dbh, cols, vals, 4) < 0) {
		LM_ERR("insert failed for key <%.*s>\n", key->len, key->s);
		sc->err = 1;
		return -1;                        /* stop the walk */
	}
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
	pcache_ht_iter(col->htable, db_save_cb, &sc);

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
