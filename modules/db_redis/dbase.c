/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../ut.h"
#include "../../db/db.h"
#include "../../db/db_pool.h"
#include "db_redis.h"
#include "redis_con.h"
#include "schema.h"
#include "dbase.h"

#define RDB_KEY_MAX   320   /* <table> + ':' + <pk value> */
#define RDB_NUM_MAX   32    /* printed numeric value */

enum rdb_opc {
	RDB_OP_EQ, RDB_OP_LT, RDB_OP_GT, RDB_OP_LEQ, RDB_OP_GEQ, RDB_OP_NEQ
};

struct rdb_filter {
	int col;                /* schema column index */
	enum rdb_opc op;
	const db_val_t *val;
};

/* one matched row while collecting; vals[i].s==NULL means SQL NULL,
 * non-NULL pointers are individual pkg allocations (NUL-terminated) */
struct rdb_irow {
	struct rdb_irow *next;
	str *vals;
};


db_con_t* db_redis_init(const str* _url)
{
	return db_do_init(_url, (void *)db_redis_new_connection);
}

void db_redis_close(db_con_t* _h)
{
	db_do_close(_h, db_redis_free_connection);
}

int db_redis_use_table(db_con_t* _h, const str* _t)
{
	return db_use_table(_h, _t);
}

int db_redis_free_result(db_con_t* _h, db_res_t* _r)
{
	if (!_r)
		return -1;
	return db_free_result(_r);
}


static int rdb_parse_opc(const db_op_t op, enum rdb_opc *out)
{
	if (!op || strcmp(op, OP_EQ) == 0)
		*out = RDB_OP_EQ;
	else if (strcmp(op, OP_LT) == 0)
		*out = RDB_OP_LT;
	else if (strcmp(op, OP_GT) == 0)
		*out = RDB_OP_GT;
	else if (strcmp(op, OP_LEQ) == 0)
		*out = RDB_OP_LEQ;
	else if (strcmp(op, OP_GEQ) == 0)
		*out = RDB_OP_GEQ;
	else if (strcmp(op, OP_NEQ) == 0)
		*out = RDB_OP_NEQ;
	else {
		LM_ERR("unsupported operator <%s>\n", op);
		return -1;
	}
	return 0;
}


/* render a db value as its storage string; numeric types print into buf */
static int rdb_val2str(const db_val_t *v, str *out, char *buf)
{
	if (VAL_NULL(v)) {
		out->s = NULL;
		out->len = 0;
		return 0;
	}

	switch (VAL_TYPE(v)) {
	case DB_INT:
		out->len = snprintf(buf, RDB_NUM_MAX, "%d", VAL_INT(v));
		out->s = buf;
		break;
	case DB_BIGINT:
		out->len = snprintf(buf, RDB_NUM_MAX, "%lld", VAL_BIGINT(v));
		out->s = buf;
		break;
	case DB_BITMAP:
		out->len = snprintf(buf, RDB_NUM_MAX, "%u", VAL_BITMAP(v));
		out->s = buf;
		break;
	case DB_DOUBLE:
		out->len = snprintf(buf, RDB_NUM_MAX, "%.17g", VAL_DOUBLE(v));
		out->s = buf;
		break;
	case DB_DATETIME:
		out->len = snprintf(buf, RDB_NUM_MAX, "%lld",
			(long long)VAL_TIME(v));
		out->s = buf;
		break;
	case DB_STRING:
		out->s = (char *)VAL_STRING(v);
		out->len = out->s ? strlen(out->s) : 0;
		break;
	case DB_STR:
		out->s = VAL_STR(v).s;
		out->len = VAL_STR(v).len;
		break;
	case DB_BLOB:
		out->s = VAL_BLOB(v).s;
		out->len = VAL_BLOB(v).len;
		break;
	default:
		LM_ERR("unsupported value type %d\n", VAL_TYPE(v));
		return -1;
	}
	return 0;
}


static inline int rdb_row_key(const str *table, const str *pkval,
		char *buf, str *out)
{
	if (table->len + 1 + pkval->len >= RDB_KEY_MAX) {
		LM_ERR("row key too long for table <%.*s>\n",
			table->len, table->s);
		return -1;
	}
	memcpy(buf, table->s, table->len);
	buf[table->len] = ':';
	memcpy(buf + table->len + 1, pkval->s, pkval->len);
	out->s = buf;
	out->len = table->len + 1 + pkval->len;
	return 0;
}


/* look up a field in a HGETALL reply; returns 0 and fills out when
 * present, -1 when the field is absent (SQL NULL) */
static int rdb_reply_field(redisReply *hg, const str *name, str *out)
{
	size_t i;

	for (i = 0; i+1 < hg->elements; i += 2) {
		if (hg->element[i]->type != REDIS_REPLY_STRING)
			continue;
		if ((int)hg->element[i]->len == name->len &&
		memcmp(hg->element[i]->str, name->s, name->len) == 0) {
			if (hg->element[i+1]->type != REDIS_REPLY_STRING)
				return -1;
			out->s = hg->element[i+1]->str;
			out->len = hg->element[i+1]->len;
			return 0;
		}
	}
	return -1;
}


static inline int rdb_col_is_numeric(const struct rdb_col *col)
{
	return col->type == DB_INT || col->type == DB_BIGINT ||
	       col->type == DB_DOUBLE || col->type == DB_DATETIME ||
	       col->type == DB_BITMAP;
}


/* evaluate one filter against a fetched row; SQL comparison semantics:
 * NULL compares false to everything, except "= NULL" (IS NULL) and
 * "!= NULL" (IS NOT NULL) */
static int rdb_eval_one(redisReply *hg, const struct rdb_schema *sch,
		const struct rdb_filter *f)
{
	const struct rdb_col *col = &sch->cols[f->col];
	str field, want;
	char buf[RDB_NUM_MAX];
	int c, have;

	have = (rdb_reply_field(hg, &col->name, &field) == 0);

	if (VAL_NULL(f->val)) {
		if (f->op == RDB_OP_EQ)
			return !have;
		if (f->op == RDB_OP_NEQ)
			return have;
		return 0;
	}
	if (!have)
		return f->op == RDB_OP_NEQ ? 0 : 0;

	if (rdb_val2str(f->val, &want, buf) < 0)
		return 0;

	if (rdb_col_is_numeric(col)) {
		if (col->type == DB_DOUBLE) {
			double a = strtod(field.s, NULL);
			double b = strtod(want.s, NULL);
			c = (a < b) ? -1 : (a > b) ? 1 : 0;
		} else {
			long long a = strtoll(field.s, NULL, 10);
			long long b = strtoll(want.s, NULL, 10);
			c = (a < b) ? -1 : (a > b) ? 1 : 0;
		}
	} else {
		int min = field.len < want.len ? field.len : want.len;
		c = memcmp(field.s, want.s, min);
		if (c == 0)
			c = (field.len < want.len) ? -1 :
			    (field.len > want.len) ? 1 : 0;
	}

	switch (f->op) {
	case RDB_OP_EQ:  return c == 0;
	case RDB_OP_NEQ: return c != 0;
	case RDB_OP_LT:  return c < 0;
	case RDB_OP_GT:  return c > 0;
	case RDB_OP_LEQ: return c <= 0;
	case RDB_OP_GEQ: return c >= 0;
	}
	return 0;
}


static int rdb_eval(redisReply *hg, const struct rdb_schema *sch,
		const struct rdb_filter *flt, int nf, int is_or)
{
	int i, m;

	if (nf == 0)
		return 1;

	for (i = 0; i < nf; i++) {
		m = rdb_eval_one(hg, sch, &flt[i]);
		if (is_or && m)
			return 1;
		if (!is_or && !m)
			return 0;
	}
	return is_or ? 0 : 1;
}


/* build the filter array out of _k/_op/_v; returns 0 or -1 */
static int rdb_build_filters(const struct rdb_schema *sch,
		const db_key_t* _k, const db_op_t* _op, const db_val_t* _v,
		int _n, struct rdb_filter *flt)
{
	int i;

	for (i = 0; i < _n; i++) {
		flt[i].col = rdb_schema_col(sch, _k[i]);
		if (flt[i].col < 0) {
			LM_ERR("unknown column <%.*s> in table <%.*s>\n",
				_k[i]->len, _k[i]->s, sch->table.len, sch->table.s);
			return -1;
		}
		if (rdb_parse_opc(_op ? _op[i] : NULL, &flt[i].op) < 0)
			return -1;
		flt[i].val = &_v[i];
	}
	return 0;
}


/* single "pk = value" fast path detector: returns the filter index of
 * the pk-EQ filter usable for direct addressing, or -1 */
static int rdb_pk_fastpath(const struct rdb_schema *sch,
		const struct rdb_filter *flt, int nf, int is_or)
{
	int i;

	if (nf == 0)
		return -1;
	/* with OR semantics a single condition behaves like AND */
	if (is_or && nf > 1)
		return -1;

	for (i = 0; i < nf; i++)
		if (flt[i].col == sch->pk && flt[i].op == RDB_OP_EQ &&
		    !VAL_NULL(flt[i].val))
			return i;
	return -1;
}


/* fetch one row hash by its key; returns reply (may be empty array
 * when the row does not exist) or NULL on transport error */
static redisReply *rdb_fetch_row(struct redis_con *con, const str *rowkey)
{
	const char *argv[2];
	size_t argvlen[2];
	redisReply *reply;

	argv[0] = "HGETALL"; argvlen[0] = 7;
	argv[1] = rowkey->s; argvlen[1] = rowkey->len;

	reply = rdb_cmd_key(con, rowkey, 2, argv, argvlen);
	if (reply && reply->type == REDIS_REPLY_ERROR) {
		LM_ERR("HGETALL <%.*s> failed: %s\n",
			rowkey->len, rowkey->s, reply->str);
		freeReplyObject(reply);
		return NULL;
	}
	return reply;
}


/* ---------------- table scanning ---------------- */

typedef int (*rdb_scan_cb)(struct redis_con *con, const str *rowkey,
		redisReply *hg, void *arg);

/* walk all rows of a table across all masters, invoking cb for each
 * existing row hash; cb return <0 aborts the scan */
static int rdb_scan_table(struct redis_con *con, const str *table,
		rdb_scan_cb cb, void *arg)
{
	redis_node *node;
	redisReply *reply, *hg;
	char pattern[RDB_KEY_MAX], cursor[24];
	const char *argv[6];
	size_t argvlen[6], k;
	char countbuf[16];
	str rowkey;
	int rc;

	if (table->len + 2 >= RDB_KEY_MAX) {
		LM_ERR("table name too long\n");
		return -1;
	}
	memcpy(pattern, table->s, table->len);
	pattern[table->len] = ':';
	pattern[table->len+1] = '*';

	snprintf(countbuf, sizeof countbuf, "%d", rdb_scan_count);

	for (node = con->nodes; node; node = node->next) {
		strcpy(cursor, "0");
		do {
			argv[0] = "SCAN";    argvlen[0] = 4;
			argv[1] = cursor;    argvlen[1] = strlen(cursor);
			argv[2] = "MATCH";   argvlen[2] = 5;
			argv[3] = pattern;   argvlen[3] = table->len + 2;
			argv[4] = "COUNT";   argvlen[4] = 5;
			argv[5] = countbuf;  argvlen[5] = strlen(countbuf);

			reply = rdb_cmd_node(con, node, 6, argv, argvlen);
			if (!reply || reply->type != REDIS_REPLY_ARRAY ||
			reply->elements < 2 ||
			reply->element[0]->type != REDIS_REPLY_STRING ||
			reply->element[1]->type != REDIS_REPLY_ARRAY) {
				LM_ERR("SCAN failed on %s:%u\n", node->host, node->port);
				if (reply)
					freeReplyObject(reply);
				return -1;
			}

			strncpy(cursor, reply->element[0]->str, sizeof(cursor)-1);
			cursor[sizeof(cursor)-1] = 0;

			for (k = 0; k < reply->element[1]->elements; k++) {
				if (reply->element[1]->element[k]->type !=
				    REDIS_REPLY_STRING)
					continue;
				rowkey.s = reply->element[1]->element[k]->str;
				rowkey.len = reply->element[1]->element[k]->len;

				hg = rdb_fetch_row(con, &rowkey);
				if (!hg)
					continue;
				if (hg->type == REDIS_REPLY_ARRAY && hg->elements) {
					rc = cb(con, &rowkey, hg, arg);
					if (rc < 0) {
						freeReplyObject(hg);
						freeReplyObject(reply);
						return -1;
					}
				}
				freeReplyObject(hg);
			}
			freeReplyObject(reply);
		} while (strcmp(cursor, "0") != 0);
	}

	return 0;
}


/* ---------------- query ---------------- */

struct rdb_query_ctx {
	const struct rdb_schema *sch;
	const struct rdb_filter *flt;
	int nf;
	int is_or;
	const int *rescols;      /* schema col index per result column */
	int nrescols;
	struct rdb_irow *head, *tail;
	int count;
};

static void rdb_free_irows(struct rdb_irow *head, int ncols)
{
	struct rdb_irow *next;
	int i;

	while (head) {
		next = head->next;
		for (i = 0; i < ncols; i++)
			if (head->vals[i].s)
				pkg_free(head->vals[i].s);
		pkg_free(head);
		head = next;
	}
}

/* copy the requested columns of a row-hash reply into an irow */
static struct rdb_irow *rdb_extract_row(redisReply *hg,
		const struct rdb_schema *sch, const int *rescols, int nrescols)
{
	struct rdb_irow *row;
	str field;
	int i;

	row = pkg_malloc(sizeof *row + nrescols * sizeof(str));
	if (!row) {
		LM_ERR("no more pkg memory for result row\n");
		return NULL;
	}
	memset(row, 0, sizeof *row + nrescols * sizeof(str));
	row->vals = (str *)(row + 1);

	for (i = 0; i < nrescols; i++) {
		if (rdb_reply_field(hg, &sch->cols[rescols[i]].name, &field) < 0)
			continue; /* stays NULL */
		row->vals[i].s = pkg_malloc(field.len + 1);
		if (!row->vals[i].s) {
			LM_ERR("no more pkg memory for column value\n");
			rdb_free_irows(row, nrescols);
			return NULL;
		}
		memcpy(row->vals[i].s, field.s, field.len);
		row->vals[i].s[field.len] = 0;
		row->vals[i].len = field.len;
	}
	return row;
}

static int rdb_query_scan_cb(struct redis_con *con, const str *rowkey,
		redisReply *hg, void *arg)
{
	struct rdb_query_ctx *ctx = (struct rdb_query_ctx *)arg;
	struct rdb_irow *row;

	if (!rdb_eval(hg, ctx->sch, ctx->flt, ctx->nf, ctx->is_or))
		return 0;

	row = rdb_extract_row(hg, ctx->sch, ctx->rescols, ctx->nrescols);
	if (!row)
		return -1;

	if (ctx->tail)
		ctx->tail->next = row;
	else
		ctx->head = row;
	ctx->tail = row;
	ctx->count++;
	return 0;
}

/* qsort context for ORDER BY (each process is single-threaded) */
static int rdb_sort_idx;
static int rdb_sort_desc;
static int rdb_sort_numeric;

static int rdb_sort_cmp(const void *pa, const void *pb)
{
	const struct rdb_irow *a = *(struct rdb_irow * const *)pa;
	const struct rdb_irow *b = *(struct rdb_irow * const *)pb;
	const str *va = &a->vals[rdb_sort_idx];
	const str *vb = &b->vals[rdb_sort_idx];
	int c, min;

	/* NULLs sort first */
	if (!va->s || !vb->s)
		c = (!va->s && !vb->s) ? 0 : (!va->s ? -1 : 1);
	else if (rdb_sort_numeric) {
		double da = strtod(va->s, NULL), db_ = strtod(vb->s, NULL);
		c = (da < db_) ? -1 : (da > db_) ? 1 : 0;
	} else {
		min = va->len < vb->len ? va->len : vb->len;
		c = memcmp(va->s, vb->s, min);
		if (c == 0)
			c = (va->len < vb->len) ? -1 : (va->len > vb->len) ? 1 : 0;
	}
	return rdb_sort_desc ? -c : c;
}

/* fill one db_res value from its stored string representation */
static int rdb_fill_val(db_val_t *val, db_type_t type, str *stored)
{
	VAL_TYPE(val) = type;
	VAL_FREE(val) = 0;

	if (!stored->s) {
		VAL_NULL(val) = 1;
		return 0;
	}
	VAL_NULL(val) = 0;

	switch (type) {
	case DB_INT:
		VAL_INT(val) = (int)strtol(stored->s, NULL, 10);
		break;
	case DB_BIGINT:
		VAL_BIGINT(val) = strtoll(stored->s, NULL, 10);
		break;
	case DB_DOUBLE:
		VAL_DOUBLE(val) = strtod(stored->s, NULL);
		break;
	case DB_DATETIME:
		VAL_TIME(val) = (time_t)strtoll(stored->s, NULL, 10);
		break;
	case DB_STR:
		VAL_STR(val).s = stored->s;
		VAL_STR(val).len = stored->len;
		VAL_FREE(val) = 1;
		stored->s = NULL; /* ownership moved to the result */
		break;
	case DB_BLOB:
		VAL_BLOB(val).s = stored->s;
		VAL_BLOB(val).len = stored->len;
		VAL_FREE(val) = 1;
		stored->s = NULL;
		break;
	default:
		LM_ERR("unsupported column type %d\n", type);
		VAL_NULL(val) = 1;
		return -1;
	}
	return 0;
}


int db_redis_query(const db_con_t* _h, const db_key_t* _k, const db_op_t* _op,
	const db_val_t* _v, const db_key_t* _c, const int _n, const int _nc,
	const db_key_t _o, db_res_t** _r)
{
	struct redis_con *con;
	struct rdb_schema *sch;
	struct rdb_filter *flt = NULL;
	struct rdb_query_ctx ctx;
	struct rdb_irow **sorted = NULL, *irow;
	db_res_t *res = NULL;
	redisReply *hg;
	int *rescols = NULL;
	int i, r, fp, is_or, order_idx;
	char numbuf[RDB_NUM_MAX], keybuf[RDB_KEY_MAX];
	str pkval, rowkey, ocol;
	char *p;

	if (!_h || !CON_TABLE(_h) || !_r) {
		LM_ERR("invalid query parameters\n");
		return -1;
	}
	*_r = NULL;
	memset(&ctx, 0, sizeof ctx);

	con = CON_REDIS(_h);
	is_or = (_h->flags & CON_OR_OPERATOR) ? 1 : 0;
	CON_OR_RESET(_h);

	rdb_maybe_refresh(con);

	sch = rdb_get_schema(con, CON_TABLE(_h));
	if (!sch)
		return -1;

	/* the result column set */
	if (_c && _nc > 0) {
		rescols = pkg_malloc(_nc * sizeof(int));
		if (!rescols)
			goto oom;
		for (i = 0; i < _nc; i++) {
			rescols[i] = rdb_schema_col(sch, _c[i]);
			if (rescols[i] < 0) {
				LM_ERR("unknown column <%.*s> in table <%.*s>\n",
					_c[i]->len, _c[i]->s,
					sch->table.len, sch->table.s);
				goto error;
			}
		}
		ctx.nrescols = _nc;
	} else {
		rescols = pkg_malloc(sch->nr_cols * sizeof(int));
		if (!rescols)
			goto oom;
		for (i = 0; i < sch->nr_cols; i++)
			rescols[i] = i;
		ctx.nrescols = sch->nr_cols;
	}

	if (_n > 0) {
		flt = pkg_malloc(_n * sizeof *flt);
		if (!flt)
			goto oom;
		if (rdb_build_filters(sch, _k, _op, _v, _n, flt) < 0)
			goto error;
	}

	ctx.sch = sch;
	ctx.flt = flt;
	ctx.nf = _n;
	ctx.is_or = is_or;
	ctx.rescols = rescols;

	fp = flt ? rdb_pk_fastpath(sch, flt, _n, is_or) : -1;
	if (fp >= 0) {
		/* direct row addressing by primary key */
		if (rdb_val2str(flt[fp].val, &pkval, numbuf) < 0 ||
		rdb_row_key(CON_TABLE(_h), &pkval, keybuf, &rowkey) < 0)
			goto error;

		hg = rdb_fetch_row(con, &rowkey);
		if (!hg)
			goto error;
		if (hg->type == REDIS_REPLY_ARRAY && hg->elements) {
			if (rdb_query_scan_cb(con, &rowkey, hg, &ctx) < 0) {
				freeReplyObject(hg);
				goto error;
			}
		}
		freeReplyObject(hg);
	} else {
		if (rdb_scan_table(con, CON_TABLE(_h),
		rdb_query_scan_cb, &ctx) < 0)
			goto error;
	}

	/* ORDER BY: single column, optional ASC/DESC */
	if (_o && _o->s && ctx.count > 1) {
		ocol.s = _o->s;
		p = memchr(_o->s, ' ', _o->len);
		ocol.len = p ? (int)(p - _o->s) : _o->len;

		order_idx = -1;
		for (i = 0; i < ctx.nrescols; i++)
			if (sch->cols[rescols[i]].name.len == ocol.len &&
			memcmp(sch->cols[rescols[i]].name.s, ocol.s, ocol.len) == 0) {
				order_idx = i;
				break;
			}
		if (order_idx < 0) {
			LM_WARN("order-by column <%.*s> not in the result set, "
				"ignoring ordering\n", ocol.len, ocol.s);
		} else {
			rdb_sort_idx = order_idx;
			rdb_sort_numeric =
				rdb_col_is_numeric(&sch->cols[rescols[order_idx]]);
			rdb_sort_desc = 0;
			if (p) {
				while (p < _o->s + _o->len && *p == ' ') p++;
				if (_o->s + _o->len - p >= 4 &&
				strncasecmp(p, "DESC", 4) == 0)
					rdb_sort_desc = 1;
			}

			sorted = pkg_malloc(ctx.count * sizeof *sorted);
			if (!sorted)
				goto oom;
			for (irow = ctx.head, i = 0; irow; irow = irow->next)
				sorted[i++] = irow;
			qsort(sorted, ctx.count, sizeof *sorted, rdb_sort_cmp);
			/* relink in sorted order */
			for (i = 0; i < ctx.count-1; i++)
				sorted[i]->next = sorted[i+1];
			sorted[ctx.count-1]->next = NULL;
			ctx.head = sorted[0];
			pkg_free(sorted);
			sorted = NULL;
		}
	}

	/* build the db_res_t */
	res = db_new_result();
	if (!res)
		goto oom;
	RES_COL_N(res) = ctx.nrescols;
	if (db_allocate_columns(res, ctx.nrescols) < 0)
		goto oom;
	for (i = 0; i < ctx.nrescols; i++) {
		RES_NAMES(res)[i] = &sch->cols[rescols[i]].name;
		RES_TYPES(res)[i] = sch->cols[rescols[i]].type;
	}

	if (ctx.count > 0) {
		if (db_allocate_rows(res, ctx.count) < 0)
			goto oom;
		for (irow = ctx.head, r = 0; irow; irow = irow->next, r++) {
			ROW_N(&RES_ROWS(res)[r]) = ctx.nrescols;
			for (i = 0; i < ctx.nrescols; i++)
				rdb_fill_val(&ROW_VALUES(&RES_ROWS(res)[r])[i],
					sch->cols[rescols[i]].type, &irow->vals[i]);
		}
	}
	RES_ROW_N(res) = ctx.count;
	RES_NUM_ROWS(res) = ctx.count;
	RES_LAST_ROW(res) = ctx.count;

	rdb_free_irows(ctx.head, ctx.nrescols);
	if (flt)
		pkg_free(flt);
	pkg_free(rescols);

	*_r = res;
	return 0;

oom:
	LM_ERR("no more pkg memory while running query\n");
error:
	if (res)
		db_free_result(res);
	if (sorted)
		pkg_free(sorted);
	rdb_free_irows(ctx.head, ctx.nrescols);
	if (flt)
		pkg_free(flt);
	if (rescols)
		pkg_free(rescols);
	return -1;
}


/* ---------------- write operations ---------------- */

/* fetch the next auto-increment value for a table */
static int rdb_next_id(struct redis_con *con, const str *table,
		char *numbuf, str *out)
{
	char keybuf[RDB_KEY_MAX];
	str key;
	const char *argv[2];
	size_t argvlen[2];
	redisReply *reply;

	if (table->len + 4 >= RDB_KEY_MAX)
		return -1;
	memcpy(keybuf, "seq:", 4);
	memcpy(keybuf + 4, table->s, table->len);
	key.s = keybuf;
	key.len = 4 + table->len;

	argv[0] = "INCR";  argvlen[0] = 4;
	argv[1] = key.s;   argvlen[1] = key.len;

	reply = rdb_cmd_key(con, &key, 2, argv, argvlen);
	if (!reply || reply->type != REDIS_REPLY_INTEGER) {
		LM_ERR("INCR on <%.*s> failed\n", key.len, key.s);
		if (reply)
			freeReplyObject(reply);
		return -1;
	}
	con->last_insert_id = reply->integer;
	out->len = snprintf(numbuf, RDB_NUM_MAX, "%lld", reply->integer);
	out->s = numbuf;
	freeReplyObject(reply);
	return 0;
}


#define RDB_STORE_INSERT  0  /* fail when the row already exists */
#define RDB_STORE_REPLACE 1  /* delete any existing row first */
#define RDB_STORE_MERGE   2  /* merge fields into any existing row */

static int rdb_store_row(const db_con_t* _h, const db_key_t* _k,
		const db_val_t* _v, const int _n, int store_mode)
{
	struct redis_con *con;
	struct rdb_schema *sch;
	redisReply *reply;
	const char **argv = NULL;
	size_t *argvlen = NULL;
	char (*numbufs)[RDB_NUM_MAX] = NULL;
	char keybuf[RDB_KEY_MAX], pknum[RDB_NUM_MAX];
	str pkval = STR_NULL, rowkey, v;
	int i, c, argc, pk_arg = -1, rc = -1;

	if (!_h || !CON_TABLE(_h) || !_k || !_v || _n <= 0) {
		LM_ERR("invalid insert parameters\n");
		return -1;
	}

	con = CON_REDIS(_h);
	rdb_maybe_refresh(con);

	sch = rdb_get_schema(con, CON_TABLE(_h));
	if (!sch)
		return -1;

	/* locate the primary key among the given columns */
	for (i = 0; i < _n; i++) {
		c = rdb_schema_col(sch, _k[i]);
		if (c < 0) {
			LM_ERR("unknown column <%.*s> in table <%.*s>\n",
				_k[i]->len, _k[i]->s, sch->table.len, sch->table.s);
			return -1;
		}
		if (c == sch->pk && !VAL_NULL(&_v[i]))
			pk_arg = i;
	}

	if (pk_arg >= 0) {
		if (rdb_val2str(&_v[pk_arg], &pkval, pknum) < 0)
			return -1;
	} else {
		if (!sch->cols[sch->pk].is_auto) {
			LM_ERR("no value for primary key <%.*s> of table <%.*s>\n",
				sch->cols[sch->pk].name.len, sch->cols[sch->pk].name.s,
				sch->table.len, sch->table.s);
			return -1;
		}
		if (rdb_next_id(con, CON_TABLE(_h), pknum, &pkval) < 0)
			return -1;
	}

	if (rdb_row_key(CON_TABLE(_h), &pkval, keybuf, &rowkey) < 0)
		return -1;

	argv = pkg_malloc((4 + 2*_n) * sizeof *argv);
	argvlen = pkg_malloc((4 + 2*_n) * sizeof *argvlen);
	numbufs = pkg_malloc(_n * sizeof *numbufs);
	if (!argv || !argvlen || !numbufs) {
		LM_ERR("no more pkg memory for insert\n");
		goto out;
	}

	if (store_mode == RDB_STORE_REPLACE) {
		argv[0] = "DEL";     argvlen[0] = 3;
		argv[1] = rowkey.s;  argvlen[1] = rowkey.len;
		reply = rdb_cmd_key(con, &rowkey, 2, argv, argvlen);
		if (!reply) {
			LM_ERR("failed to clear row for replace\n");
			goto out;
		}
		freeReplyObject(reply);
	}

	if (store_mode != RDB_STORE_MERGE) {
		/* reserve the row: HSETNX <key> <pkcol> <pkval> doubles as
		 * both the uniqueness check and the guaranteed first field */
		argv[0] = "HSETNX";  argvlen[0] = 6;
		argv[1] = rowkey.s;  argvlen[1] = rowkey.len;
		argv[2] = sch->cols[sch->pk].name.s;
		argvlen[2] = sch->cols[sch->pk].name.len;
		argv[3] = pkval.s;   argvlen[3] = pkval.len;

		reply = rdb_cmd_key(con, &rowkey, 4, argv, argvlen);
		if (!reply || reply->type != REDIS_REPLY_INTEGER) {
			LM_ERR("row reservation failed for <%.*s>\n",
				rowkey.len, rowkey.s);
			if (reply)
				freeReplyObject(reply);
			goto out;
		}
		if (reply->integer == 0) {
			LM_ERR("duplicate primary key <%.*s> in table <%.*s>\n",
				pkval.len, pkval.s, sch->table.len, sch->table.s);
			freeReplyObject(reply);
			goto out;
		}
		freeReplyObject(reply);
	}

	/* store the remaining non-NULL fields */
	argc = 2;
	argv[0] = "HSET";    argvlen[0] = 4;
	argv[1] = rowkey.s;  argvlen[1] = rowkey.len;

	if (store_mode == RDB_STORE_MERGE) {
		/* the pk field is written here instead of via HSETNX */
		argv[argc] = sch->cols[sch->pk].name.s;
		argvlen[argc] = sch->cols[sch->pk].name.len;
		argc++;
		argv[argc] = pkval.s;
		argvlen[argc] = pkval.len;
		argc++;
	}

	for (i = 0; i < _n; i++) {
		if (i == pk_arg || VAL_NULL(&_v[i]))
			continue;
		if (rdb_val2str(&_v[i], &v, numbufs[i]) < 0)
			goto out;
		argv[argc] = _k[i]->s;
		argvlen[argc] = _k[i]->len;
		argc++;
		argv[argc] = v.s ? v.s : "";
		argvlen[argc] = v.len;
		argc++;
	}

	if (argc > 2) {
		reply = rdb_cmd_key(con, &rowkey, argc, argv, argvlen);
		if (!reply || reply->type == REDIS_REPLY_ERROR) {
			LM_ERR("failed to store row <%.*s> (%s)\n",
				rowkey.len, rowkey.s, reply ? reply->str : "io error");
			if (reply)
				freeReplyObject(reply);
			goto out;
		}
		freeReplyObject(reply);
	}

	rc = 0;
out:
	if (argv) pkg_free(argv);
	if (argvlen) pkg_free(argvlen);
	if (numbufs) pkg_free(numbufs);
	return rc;
}


int db_redis_insert(const db_con_t* _h, const db_key_t* _k,
		const db_val_t* _v, const int _n)
{
	return rdb_store_row(_h, _k, _v, _n, RDB_STORE_INSERT);
}

int db_redis_replace(const db_con_t* _h, const db_key_t* _k,
		const db_val_t* _v, const int _n)
{
	return rdb_store_row(_h, _k, _v, _n, RDB_STORE_REPLACE);
}

int db_redis_insert_update(const db_con_t* _h, const db_key_t* _k,
		const db_val_t* _v, const int _n)
{
	return rdb_store_row(_h, _k, _v, _n, RDB_STORE_MERGE);
}

int db_redis_last_inserted_id(const db_con_t* _h)
{
	if (!_h)
		return -1;
	return (int)CON_REDIS(_h)->last_insert_id;
}


/* ---------------- delete ---------------- */

static int rdb_del_key(struct redis_con *con, const str *rowkey)
{
	const char *argv[2];
	size_t argvlen[2];
	redisReply *reply;

	argv[0] = "DEL";     argvlen[0] = 3;
	argv[1] = rowkey->s; argvlen[1] = rowkey->len;

	reply = rdb_cmd_key(con, rowkey, 2, argv, argvlen);
	if (!reply || reply->type == REDIS_REPLY_ERROR) {
		LM_ERR("DEL <%.*s> failed\n", rowkey->len, rowkey->s);
		if (reply)
			freeReplyObject(reply);
		return -1;
	}
	freeReplyObject(reply);
	return 0;
}

struct rdb_del_ctx {
	const struct rdb_schema *sch;
	const struct rdb_filter *flt;
	int nf;
	int is_or;
	int failed;
};

static int rdb_delete_scan_cb(struct redis_con *con, const str *rowkey,
		redisReply *hg, void *arg)
{
	struct rdb_del_ctx *ctx = (struct rdb_del_ctx *)arg;

	if (!rdb_eval(hg, ctx->sch, ctx->flt, ctx->nf, ctx->is_or))
		return 0;
	if (rdb_del_key(con, rowkey) < 0)
		ctx->failed = 1;
	return 0;
}

int db_redis_delete(const db_con_t* _h, const db_key_t* _k,
		const db_op_t* _o, const db_val_t* _v, const int _n)
{
	struct redis_con *con;
	struct rdb_schema *sch;
	struct rdb_filter *flt = NULL;
	struct rdb_del_ctx ctx;
	char numbuf[RDB_NUM_MAX], keybuf[RDB_KEY_MAX];
	str pkval, rowkey;
	int i, is_or, all_pk_eq, rc = -1;

	if (!_h || !CON_TABLE(_h)) {
		LM_ERR("invalid delete parameters\n");
		return -1;
	}

	con = CON_REDIS(_h);
	is_or = (_h->flags & CON_OR_OPERATOR) ? 1 : 0;
	CON_OR_RESET(_h);

	rdb_maybe_refresh(con);

	sch = rdb_get_schema(con, CON_TABLE(_h));
	if (!sch)
		return -1;

	if (_n > 0) {
		flt = pkg_malloc(_n * sizeof *flt);
		if (!flt) {
			LM_ERR("no more pkg memory for delete\n");
			return -1;
		}
		if (rdb_build_filters(sch, _k, _o, _v, _n, flt) < 0)
			goto out;

		/* pk-only deletes go straight to the row keys: a single
		 * "pk=X", or an OR-list of "pk=X" conditions (bulk delete) */
		all_pk_eq = 1;
		for (i = 0; i < _n; i++)
			if (flt[i].col != sch->pk || flt[i].op != RDB_OP_EQ ||
			VAL_NULL(flt[i].val)) {
				all_pk_eq = 0;
				break;
			}

		if (all_pk_eq && (_n == 1 || is_or)) {
			for (i = 0; i < _n; i++) {
				if (rdb_val2str(flt[i].val, &pkval, numbuf) < 0 ||
				rdb_row_key(CON_TABLE(_h), &pkval, keybuf,
						&rowkey) < 0)
					goto out;
				if (rdb_del_key(con, &rowkey) < 0)
					goto out;
			}
			rc = 0;
			goto out;
		}
	}

	ctx.sch = sch;
	ctx.flt = flt;
	ctx.nf = _n;
	ctx.is_or = is_or;
	ctx.failed = 0;

	if (rdb_scan_table(con, CON_TABLE(_h), rdb_delete_scan_cb, &ctx) < 0)
		goto out;

	rc = ctx.failed ? -1 : 0;
out:
	if (flt)
		pkg_free(flt);
	return rc;
}


/* ---------------- update ---------------- */

struct rdb_upd_ctx {
	const struct rdb_schema *sch;
	const struct rdb_filter *flt;
	int nf;
	int is_or;
	/* collected row keys (own pkg copies) */
	str *keys;
	int count;
	int alloc;
};

static int rdb_update_scan_cb(struct redis_con *con, const str *rowkey,
		redisReply *hg, void *arg)
{
	struct rdb_upd_ctx *ctx = (struct rdb_upd_ctx *)arg;
	str *newkeys;

	if (!rdb_eval(hg, ctx->sch, ctx->flt, ctx->nf, ctx->is_or))
		return 0;

	if (ctx->count == ctx->alloc) {
		ctx->alloc = ctx->alloc ? 2*ctx->alloc : 16;
		newkeys = pkg_realloc(ctx->keys, ctx->alloc * sizeof(str));
		if (!newkeys) {
			LM_ERR("no more pkg memory for update targets\n");
			return -1;
		}
		ctx->keys = newkeys;
	}
	ctx->keys[ctx->count].s = pkg_malloc(rowkey->len);
	if (!ctx->keys[ctx->count].s) {
		LM_ERR("no more pkg memory for update target key\n");
		return -1;
	}
	memcpy(ctx->keys[ctx->count].s, rowkey->s, rowkey->len);
	ctx->keys[ctx->count].len = rowkey->len;
	ctx->count++;
	return 0;
}

/* apply the SET clause to one row: HSET the non-NULL values,
 * HDEL the NULL ones */
static int rdb_apply_update(struct redis_con *con, const str *rowkey,
		const db_key_t* _uk, const db_val_t* _uv, int _un,
		char (*numbufs)[RDB_NUM_MAX])
{
	const char *argv[2 + 2*_un];
	size_t argvlen[2 + 2*_un];
	redisReply *reply;
	str v;
	int i, argc;

	/* HSET phase */
	argc = 2;
	argv[0] = "HSET";    argvlen[0] = 4;
	argv[1] = rowkey->s; argvlen[1] = rowkey->len;
	for (i = 0; i < _un; i++) {
		if (VAL_NULL(&_uv[i]))
			continue;
		if (rdb_val2str(&_uv[i], &v, numbufs[i]) < 0)
			return -1;
		argv[argc] = _uk[i]->s;
		argvlen[argc] = _uk[i]->len;
		argc++;
		argv[argc] = v.s ? v.s : "";
		argvlen[argc] = v.len;
		argc++;
	}
	if (argc > 2) {
		reply = rdb_cmd_key(con, rowkey, argc, argv, argvlen);
		if (!reply || reply->type == REDIS_REPLY_ERROR) {
			LM_ERR("failed to update row <%.*s> (%s)\n", rowkey->len,
				rowkey->s, reply ? reply->str : "io error");
			if (reply)
				freeReplyObject(reply);
			return -1;
		}
		freeReplyObject(reply);
	}

	/* HDEL phase for NULL assignments */
	argc = 2;
	argv[0] = "HDEL";    argvlen[0] = 4;
	argv[1] = rowkey->s; argvlen[1] = rowkey->len;
	for (i = 0; i < _un; i++) {
		if (!VAL_NULL(&_uv[i]))
			continue;
		argv[argc] = _uk[i]->s;
		argvlen[argc] = _uk[i]->len;
		argc++;
	}
	if (argc > 2) {
		reply = rdb_cmd_key(con, rowkey, argc, argv, argvlen);
		if (!reply || reply->type == REDIS_REPLY_ERROR) {
			LM_ERR("failed to clear columns of row <%.*s>\n",
				rowkey->len, rowkey->s);
			if (reply)
				freeReplyObject(reply);
			return -1;
		}
		freeReplyObject(reply);
	}

	return 0;
}

int db_redis_update(const db_con_t* _h, const db_key_t* _k,
		const db_op_t* _o, const db_val_t* _v, const db_key_t* _uk,
		const db_val_t* _uv, const int _n, const int _un)
{
	struct redis_con *con;
	struct rdb_schema *sch;
	struct rdb_filter *flt = NULL;
	struct rdb_upd_ctx ctx;
	redisReply *hg;
	char (*numbufs)[RDB_NUM_MAX] = NULL;
	char numbuf[RDB_NUM_MAX], keybuf[RDB_KEY_MAX];
	str pkval, rowkey;
	int i, c, fp, is_or, rc = -1;

	if (!_h || !CON_TABLE(_h) || !_uk || !_uv || _un <= 0) {
		LM_ERR("invalid update parameters\n");
		return -1;
	}

	con = CON_REDIS(_h);
	is_or = (_h->flags & CON_OR_OPERATOR) ? 1 : 0;
	CON_OR_RESET(_h);

	rdb_maybe_refresh(con);

	sch = rdb_get_schema(con, CON_TABLE(_h));
	if (!sch)
		return -1;

	/* validate the SET columns; updating the pk would require a key
	 * rename and is not supported */
	for (i = 0; i < _un; i++) {
		c = rdb_schema_col(sch, _uk[i]);
		if (c < 0) {
			LM_ERR("unknown column <%.*s> in table <%.*s>\n",
				_uk[i]->len, _uk[i]->s, sch->table.len, sch->table.s);
			return -1;
		}
		if (c == sch->pk) {
			LM_ERR("updating the primary key column <%.*s> is "
				"not supported\n", _uk[i]->len, _uk[i]->s);
			return -1;
		}
	}

	memset(&ctx, 0, sizeof ctx);
	ctx.sch = sch;
	ctx.is_or = is_or;

	if (_n > 0) {
		flt = pkg_malloc(_n * sizeof *flt);
		if (!flt) {
			LM_ERR("no more pkg memory for update\n");
			return -1;
		}
		if (rdb_build_filters(sch, _k, _o, _v, _n, flt) < 0)
			goto out;
		ctx.flt = flt;
		ctx.nf = _n;
	}

	numbufs = pkg_malloc(_un * sizeof *numbufs);
	if (!numbufs) {
		LM_ERR("no more pkg memory for update values\n");
		goto out;
	}

	fp = flt ? rdb_pk_fastpath(sch, flt, _n, is_or) : -1;
	if (fp >= 0) {
		if (rdb_val2str(flt[fp].val, &pkval, numbuf) < 0 ||
		rdb_row_key(CON_TABLE(_h), &pkval, keybuf, &rowkey) < 0)
			goto out;

		hg = rdb_fetch_row(con, &rowkey);
		if (!hg)
			goto out;
		if (hg->type == REDIS_REPLY_ARRAY && hg->elements &&
		rdb_eval(hg, sch, flt, _n, is_or)) {
			freeReplyObject(hg);
			if (rdb_apply_update(con, &rowkey, _uk, _uv, _un,
			numbufs) < 0)
				goto out;
		} else {
			/* no matching row - not an error, zero rows updated */
			freeReplyObject(hg);
		}
		rc = 0;
		goto out;
	}

	if (rdb_scan_table(con, CON_TABLE(_h), rdb_update_scan_cb, &ctx) < 0)
		goto out;

	rc = 0;
	for (i = 0; i < ctx.count; i++)
		if (rdb_apply_update(con, &ctx.keys[i], _uk, _uv, _un,
		numbufs) < 0)
			rc = -1;

out:
	for (i = 0; i < ctx.count; i++)
		if (ctx.keys[i].s)
			pkg_free(ctx.keys[i].s);
	if (ctx.keys)
		pkg_free(ctx.keys);
	if (numbufs)
		pkg_free(numbufs);
	if (flt)
		pkg_free(flt);
	return rc;
}
