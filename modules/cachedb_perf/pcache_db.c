/*
 * cachedb_perf - DB persistence (see pcache_db.h).
 */
#include <time.h>

#include "../../dprint.h"
#include "../../timer.h"
#include "../../db/db.h"
#include "pcache_db.h"
#include "pcache_htable.h"

static db_func_t pcache_dbf;
static int pcache_db_bound;
static str pcache_db_url;
static str pcache_db_table;

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

	/* a snapshot replaces the previous one: clear this collection's rows */
	memset(wv, 0, sizeof wv);
	VAL_TYPE(&wv[0]) = DB_STR;
	VAL_STR(&wv[0]) = col->col_name;
	if (pcache_dbf.delete(dbh, wk, NULL, wv, 1) < 0) {
		LM_ERR("failed to clear old rows for <%.*s>\n",
			col->col_name.len, col->col_name.s);
		pcache_dbf.close(dbh);
		return -1;
	}

	memset(&sc, 0, sizeof sc);
	sc.dbh = dbh;
	sc.coll = &col->col_name;
	sc.now_ticks = get_ticks();
	sc.now_wall = (long)time(NULL);
	pcache_ht_iter(col->htable, db_save_cb, &sc);

	pcache_dbf.close(dbh);
	if (sc.err) {
		LM_ERR("collection <%.*s>: save incomplete after %d rows\n",
			col->col_name.len, col->col_name.s, sc.n);
		return -1;
	}
	LM_INFO("collection <%.*s>: saved %d entries\n",
		col->col_name.len, col->col_name.s, sc.n);
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
	int i, expires, remaining, n = 0;

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
			if (remaining <= 0)
				continue;                 /* already expired in the DB */
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
	pcache_dbf.close(dbh);
	LM_INFO("collection <%.*s>: loaded %d entries\n",
		col->col_name.len, col->col_name.s, n);
	return n;
}
