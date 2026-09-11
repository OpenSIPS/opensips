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

/* warn when a snapshot takes longer than this - well inside the 60 s
 * shutdown watchdog, so the warning arrives before the cliff */
#define PCACHE_DB_SLOW_SAVE_SECS  10.0

#include "pcache_db.h"
#include "pcache_htable.h"

static db_func_t pcache_dbf;
static int pcache_db_bound;
static str pcache_db_url;
static str pcache_db_table;

/*
 * A snapshot is one statement per row, so on a backend that commits (and
 * fsyncs) each one separately it is slow enough to matter: a 30k-entry
 * collection took ~60 s on db_sqlite and did not finish inside the shutdown
 * watchdog, against ~5 s on db_redis.  Wrapping the whole snapshot in one
 * transaction removes the per-row commit, and - more importantly - makes it
 * atomic: a save begins by deleting the collection, so an interrupted save
 * would otherwise leave a partially written table where a complete one used
 * to be.  Uncommitted work is rolled back when the connection closes, so a
 * failure or a kill leaves the previous snapshot intact.
 *
 * Only used where the driver exposes raw_query (SQL backends).  Backends
 * without it - db_redis - do not need it: they have no per-row commit to
 * amortise.
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

	/* No one spelling works everywhere: SQLite and PostgreSQL take
	 * "BEGIN TRANSACTION", MySQL takes "START TRANSACTION".  Try both rather
	 * than sniff the driver.  (The bare "BEGIN" both would accept is not an
	 * option: db_sqlite's raw_query only reaches its exec path for
	 * statements at least as long as "select", so a 5-character statement is
	 * mis-parsed as a SELECT.) */
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

/* read a column as a str regardless of how the backend typed it - a TEXT
 * column comes back DB_STRING from some drivers (sqlite), DB_STR from
 * others, and the value is DB_BLOB.  Returns -1 if NULL/unsupported. */
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

/* --- save --- */

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
		return 0;                         /* skip already-expired */

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

	/* One transaction for the whole snapshot where the backend supports it:
	 * it removes the per-row commit AND makes the delete+insert atomic, so an
	 * interrupted save cannot leave a half-written table behind. */
	txn = pcache_db_txn_begin(dbh) == 0;

	/* a snapshot replaces the previous one: clear this collection's rows */
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
		/* leave the transaction uncommitted: the previous snapshot stands */
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

	/* A shutdown save runs inside SHUTDOWN_TIMEOUT (60 s); overrun it and the
	 * core aborts the process mid-write.  Warn well before that, because the
	 * symptom otherwise is a snapshot that silently stops part-way. */
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

/* --- load --- */

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
			remaining = 0;                /* never expires */
		} else {
			remaining = expires - (int)now_wall;
			if (remaining <= 0) {
				stale++;                  /* already expired in the DB */
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

	/* Rows whose wall-clock expiry has passed are dead weight: nothing will
	 * ever load them, and without a save to rewrite the snapshot (a crash, or
	 * db_mode=1 which never writes) they would sit there forever.  Drop them
	 * in one ranged delete now that the result set is released.  expires=0
	 * means "never expires", so it must be excluded explicitly - it would
	 * otherwise match the <= comparison. */
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
