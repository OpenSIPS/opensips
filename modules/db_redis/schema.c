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

#include <string.h>

#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../ut.h"
#include "schema.h"

#define SCHEMA_KEY_PREFIX     "schema:"
#define SCHEMA_KEY_PREFIX_LEN (sizeof(SCHEMA_KEY_PREFIX)-1)

static int rdb_parse_type(const char *s, size_t len, struct rdb_col *col)
{
	const char *p, *end = s + len;

	col->nullable = 0;
	col->is_auto = 0;

	p = memchr(s, ',', len);
	if (!p)
		p = end;

	if (p-s == 3 && strncmp(s, "int", 3) == 0)
		col->type = DB_INT;
	else if (p-s == 6 && strncmp(s, "bigint", 6) == 0)
		col->type = DB_BIGINT;
	else if (p-s == 6 && strncmp(s, "double", 6) == 0)
		col->type = DB_DOUBLE;
	else if (p-s == 6 && strncmp(s, "string", 6) == 0)
		col->type = DB_STR;
	else if (p-s == 4 && strncmp(s, "blob", 4) == 0)
		col->type = DB_BLOB;
	else if (p-s == 8 && strncmp(s, "datetime", 8) == 0)
		col->type = DB_DATETIME;
	else
		return -1;

	while (p < end) {
		p++; /* skip ',' */
		if (end-p >= 4 && strncmp(p, "null", 4) == 0)
			col->nullable = 1;
		else if (end-p >= 4 && strncmp(p, "auto", 4) == 0)
			col->is_auto = 1;
		p = memchr(p, ',', end-p);
		if (!p)
			break;
	}

	return 0;
}


static struct rdb_schema *rdb_load_schema(struct redis_con *con,
		const str *table)
{
	struct rdb_schema *sch = NULL;
	redisReply *reply = NULL, *k, *v;
	char keybuf[SCHEMA_KEY_PREFIX_LEN + 64];
	str key;
	const char *argv[2];
	size_t argvlen[2];
	str cols_spec = STR_NULL, pk_name = STR_NULL;
	str name;
	char *p, *end;
	size_t i;
	int c;

	if (table->len > 64) {
		LM_ERR("table name too long <%.*s>\n", table->len, table->s);
		return NULL;
	}

	memcpy(keybuf, SCHEMA_KEY_PREFIX, SCHEMA_KEY_PREFIX_LEN);
	memcpy(keybuf + SCHEMA_KEY_PREFIX_LEN, table->s, table->len);
	key.s = keybuf;
	key.len = SCHEMA_KEY_PREFIX_LEN + table->len;

	argv[0] = "HGETALL";      argvlen[0] = 7;
	argv[1] = key.s;          argvlen[1] = key.len;

	reply = rdb_cmd_key(con, &key, 2, argv, argvlen);
	if (!reply) {
		LM_ERR("failed to fetch schema for table <%.*s>\n",
			table->len, table->s);
		return NULL;
	}
	if (reply->type != REDIS_REPLY_ARRAY || reply->elements == 0) {
		LM_ERR("no schema provisioned for table <%.*s> "
			"(missing hash <%.*s>)\n",
			table->len, table->s, key.len, key.s);
		goto error;
	}

	/* first pass: locate __cols and __pk */
	for (i = 0; i+1 < reply->elements; i += 2) {
		k = reply->element[i];
		v = reply->element[i+1];
		if (k->type != REDIS_REPLY_STRING || v->type != REDIS_REPLY_STRING)
			continue;
		if (k->len == 6 && strncmp(k->str, "__cols", 6) == 0) {
			cols_spec.s = v->str;
			cols_spec.len = v->len;
		} else if (k->len == 4 && strncmp(k->str, "__pk", 4) == 0) {
			pk_name.s = v->str;
			pk_name.len = v->len;
		}
	}
	if (!cols_spec.s || !pk_name.s) {
		LM_ERR("schema of table <%.*s> lacks __cols or __pk\n",
			table->len, table->s);
		goto error;
	}

	sch = pkg_malloc(sizeof *sch + table->len);
	if (!sch)
		goto oom;
	memset(sch, 0, sizeof *sch);
	sch->table.s = (char *)(sch + 1);
	sch->table.len = table->len;
	memcpy(sch->table.s, table->s, table->len);
	sch->pk = -1;

	/* count columns in __cols */
	p = cols_spec.s;
	end = cols_spec.s + cols_spec.len;
	while (p < end) {
		while (p < end && *p == ' ') p++;
		if (p == end) break;
		sch->nr_cols++;
		while (p < end && *p != ' ') p++;
	}
	if (sch->nr_cols == 0) {
		LM_ERR("empty __cols in schema of table <%.*s>\n",
			table->len, table->s);
		goto error;
	}

	sch->cols = pkg_malloc(sch->nr_cols * sizeof *sch->cols);
	if (!sch->cols)
		goto oom;
	memset(sch->cols, 0, sch->nr_cols * sizeof *sch->cols);

	/* second pass: fill the ordered columns, resolving each type */
	p = cols_spec.s;
	c = 0;
	while (p < end && c < sch->nr_cols) {
		while (p < end && *p == ' ') p++;
		if (p == end) break;
		name.s = p;
		while (p < end && *p != ' ') p++;
		name.len = p - name.s;

		sch->cols[c].name.s = pkg_malloc(name.len + 1);
		if (!sch->cols[c].name.s)
			goto oom;
		memcpy(sch->cols[c].name.s, name.s, name.len);
		sch->cols[c].name.s[name.len] = 0;
		sch->cols[c].name.len = name.len;

		/* find the matching type field */
		sch->cols[c].type = DB_INT;
		for (i = 0; i+1 < reply->elements; i += 2) {
			k = reply->element[i];
			v = reply->element[i+1];
			if (k->type != REDIS_REPLY_STRING ||
			    v->type != REDIS_REPLY_STRING)
				continue;
			if ((int)k->len == name.len &&
			memcmp(k->str, name.s, name.len) == 0) {
				if (rdb_parse_type(v->str, v->len, &sch->cols[c]) < 0) {
					LM_ERR("bad type <%.*s> for column <%.*s> in "
						"table <%.*s>\n", (int)v->len, v->str,
						name.len, name.s, table->len, table->s);
					goto error;
				}
				break;
			}
		}
		if (i+1 >= reply->elements) {
			LM_ERR("column <%.*s> in __cols has no type field in "
				"schema of table <%.*s>\n",
				name.len, name.s, table->len, table->s);
			goto error;
		}

		if (name.len == pk_name.len &&
		memcmp(name.s, pk_name.s, name.len) == 0)
			sch->pk = c;
		c++;
	}

	if (sch->pk < 0) {
		LM_ERR("__pk column <%.*s> is not part of __cols in "
			"table <%.*s>\n", pk_name.len, pk_name.s,
			table->len, table->s);
		goto error;
	}

	freeReplyObject(reply);

	sch->next = con->schemas;
	con->schemas = sch;

	LM_DBG("loaded schema for table <%.*s>: %d columns, pk <%.*s>\n",
		table->len, table->s, sch->nr_cols,
		sch->cols[sch->pk].name.len, sch->cols[sch->pk].name.s);
	return sch;

oom:
	LM_ERR("no more pkg memory while loading schema for <%.*s>\n",
		table->len, table->s);
error:
	if (reply)
		freeReplyObject(reply);
	if (sch) {
		if (sch->cols) {
			for (c = 0; c < sch->nr_cols; c++)
				if (sch->cols[c].name.s)
					pkg_free(sch->cols[c].name.s);
			pkg_free(sch->cols);
		}
		pkg_free(sch);
	}
	return NULL;
}


struct rdb_schema *rdb_get_schema(struct redis_con *con, const str *table)
{
	struct rdb_schema *sch;

	for (sch = con->schemas; sch; sch = sch->next)
		if (sch->table.len == table->len &&
		memcmp(sch->table.s, table->s, table->len) == 0)
			return sch;

	return rdb_load_schema(con, table);
}


int rdb_schema_col(const struct rdb_schema *sch, const str *name)
{
	int i;

	for (i = 0; i < sch->nr_cols; i++)
		if (sch->cols[i].name.len == name->len &&
		memcmp(sch->cols[i].name.s, name->s, name->len) == 0)
			return i;
	return -1;
}


void rdb_free_schemas(struct redis_con *con)
{
	struct rdb_schema *sch, *next;
	int c;

	for (sch = con->schemas; sch; sch = next) {
		next = sch->next;
		if (sch->cols) {
			for (c = 0; c < sch->nr_cols; c++)
				if (sch->cols[c].name.s)
					pkg_free(sch->cols[c].name.s);
			pkg_free(sch->cols);
		}
		pkg_free(sch);
	}
	con->schemas = NULL;
}
