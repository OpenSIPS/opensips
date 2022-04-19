/*
 * Copyright (C) 2022 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
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

#include "tcp_db.h"

#define TCP_TABLE_VERSION 1

str tcp_db_url;
str tcp_db_table = str_init("tcp_mgm");

db_con_t *db_hdl; /* DB handle */
db_func_t db;     /* DB API */

db_col_t tcp_mgm_cols[] = {
	{str_init("id"), DB_INT, 0, 0},
	{str_init("proto"), DB_STR, 0, 0},
	{str_init("remote_addr"), DB_STR, 0, 1},
	{str_init("remote_port"), DB_INT, 0, 0},
	{str_init("local_addr"), DB_STR, 0, 1},
	{str_init("local_port"), DB_INT, 0, 0},
	{str_init("priority"), DB_INT, 0, 0},
	{str_init("connect_timeout"), DB_INT, 0, 0},
	{str_init("con_lifetime"), DB_INT, 0, 0},
	{str_init("msg_read_timeout"), DB_INT, 0, 0},
	{str_init("send_threshold"), DB_INT, 0, 0},
	{str_init("no_new_conn"), DB_INT, 0, 0},
	{str_init("alias_mode"), DB_INT, 0, 0},
	{str_init("parallel_read"), DB_INT, 0, 0},
	{str_init("keepalive"), DB_INT, 0, 0},
	{str_init("keepcount"), DB_INT, 0, 0},
	{str_init("keepidle"), DB_INT, 0, 0},
	{str_init("keepinterval"), DB_INT, 0, 0},
	{STR_NULL, 0, 0, 0},
};

int tcp_db_init(void)
{
	if (db_bind_mod(&tcp_db_url, &db)) {
		LM_ERR("cannot bind to database module! "
		         "Did you forget to load a database module?\n");
		return -1;
	}

	/* init DB connection */
	if (!(db_hdl = db.init(&tcp_db_url))) {
		LM_ERR("cannot initialize database connection\n");
		return -1;
	}

	/* cache all DB data - we're still at mod_init(), no locking needed */
	if (tcp_reload_paths(&tcp_paths, tcp_paths_sz) < 0) {
		LM_ERR("failed to load TCP data\n");
		return -1;
	}

	return 0;
}


int db_row_decode(db_row_t *row, db_col_t *cols,
               int *int_vals, char **str_vals, str *blob_vals)
{
	db_val_t *val;
	db_col_t *col;
	int i, iv = 0, sv = 0;

	for (i = 0; cols[i].name.s; i++) {
		val = ROW_VALUES(row) + i;
		col = &cols[i];

		if (VAL_NULL(val)) {
			if (!col->allow_null) {
				LM_ERR("column %.*s is NULL, but this is not allowed\n",
				       col->name.len, col->name.s);
				return -1;
			}

			switch (col->type) {
			case DB_STRING:
			case DB_STR:
				str_vals[sv++] = NULL;
				break;
			case DB_INT:
			case DB_BIGINT:
				int_vals[iv++] = 0;
				break;
			default:
				LM_BUG("TODO: unsupported column type, at least for now");
				return -2;
			}

			continue;
		}

		if (col->is_strict_type) {
			if (val->type != col->type)
				goto error_type;

			switch (col->type) {
			case DB_STRING:
				str_vals[sv++] = (char *)VAL_STRING(val);
				break;
			case DB_STR:
				str_vals[sv++] = VAL_STR(val).s; /* should be NT */
				break;
			case DB_INT:
				int_vals[iv++] = VAL_INT(val);
				break;
			case DB_BIGINT:
				int_vals[iv++] = (int)VAL_BIGINT(val);
				break;
			default:
				LM_BUG("TODO: unsupported column type, at least for now");
				return -2;
			}
		} else {
			switch (col->type) {
			case DB_STRING:
				switch (val->type) {
				case DB_STRING:
					str_vals[sv++] = (char *)VAL_STRING(val);
					break;
				case DB_STR:
					str_vals[sv++] = VAL_STR(val).s; /* should be NT */
					break;
				default:
					goto error_type;
				}
				break;

			case DB_STR:
				switch (val->type) {
				case DB_STRING:
					str_vals[sv++] = (char *)VAL_STRING(val);
					break;
				case DB_STR:
					str_vals[sv++] = VAL_STR(val).s; /* should be NT */
					break;
				default:
					goto error_type;
				}
				break;

			case DB_INT:
				if (val->type != DB_INT && val->type != DB_BIGINT)
					goto error_type;
				switch (val->type) {
				case DB_INT:
					int_vals[iv++] = VAL_INT(val);
					break;
				case DB_BIGINT:
					int_vals[iv++] = (int)VAL_BIGINT(val);
					break;
				default:
					goto error_type;
				}

			case DB_BIGINT:
				switch (val->type) {
				case DB_INT:
					int_vals[iv++] = VAL_INT(val);
					break;
				case DB_BIGINT:
					int_vals[iv++] = (int)VAL_BIGINT(val);
					break;
				default:
					goto error_type;
				}
				break;

			default:
				LM_BUG("TODO: unsupported column type, at least for now");
				return -2;
			}
		}
	}

	return 0;

error_type:
	LM_ERR("bad value type for col %.*s: have %d, need %d\n",
	       col->name.len, col->name.s, val->type, col->type);
	return -1;
}


/**
 * Path sorting rules & tie-breaking:
 *   1. priority: higher priority evaluates last
 *   2. protocol: if exactly one path has "any" protocol, it evaluates last
 *   3. remote: if exactly one path has NULL remote, it evaluates last
 *   4. remote prefix: if equal, lower remote network prefix is last
 *   5. remote port: if equal and one path has "any" remote port, it's last
 *   6. local: if exactly one path has NULL local, it evaluates last
 *   7. local prefix: if equal, lower local network prefix is last
 *   8. local port: if equal, and one path has "any" local port, it's last
 */
int tcp_path_comparator(const void *_a, const void *_b)
{
	const struct tcp_path *a = _a, *b = _b;

	if (a->priority > b->priority)
		return 1;
	else if (a->priority < b->priority)
		return -1;

	/* they are equal, since they refer to different protocols! */
	if (a->proto != PROTO_NONE && b->proto != PROTO_NONE
	        && a->proto != b->proto)
		return 0;

	if (a->proto == PROTO_NONE && b->proto != PROTO_NONE)
		return 1;
	else if (a->proto != PROTO_NONE && b->proto == PROTO_NONE)
		return -1;

	if (a->remote_any && !b->remote_any)
		return 1;
	else if (!a->remote_any && b->remote_any)
		return -1;

	if (!a->remote_any) {
		int i, lim = a->remote_addr.ip.len;
		for (i = 0; i < lim; i++) {
			if (a->remote_addr.mask.u.addr[i] > b->remote_addr.mask.u.addr[i])
				return -1;
			else if (a->remote_addr.mask.u.addr[i] < b->remote_addr.mask.u.addr[i])
				return 1;
		}
	}

	if (!a->remote_port && b->remote_port)
		return 1;
	else if (a->remote_port && !b->remote_port)
		return -1;

	if (a->local_any && !b->local_any)
		return 1;
	else if (!a->local_any && b->local_any)
		return -1;

	if (!a->local_any) {
		int i, lim = a->local_addr.ip.len;
		for (i = 0; i < lim; i++) {
			if (a->local_addr.mask.u.addr[i] > b->local_addr.mask.u.addr[i])
				return -1;
			else if (a->local_addr.mask.u.addr[i] < b->local_addr.mask.u.addr[i])
				return 1;
		}
	}

	if (!a->local_port && b->local_port)
		return 1;
	else if (a->local_port && !b->local_port)
		return -1;

	return 0;
}


int tcp_reload_paths(struct tcp_path **new_paths, int *new_paths_sz)
{
	struct tcp_path *paths = NULL;
	int paths_sz = 0;
	int int_vals[NO_INT_VALS];
	char *str_vals[NO_STR_VALS];
	int i, n, no_rows = 5, db_cols = NO_DB_COLS;

	/* the columns from the db table */
	db_key_t columns[NO_DB_COLS];
	db_row_t *row;
	db_res_t *res = NULL;

	for (i = 0; i < NO_DB_COLS; i++)
		columns[i] = &tcp_mgm_cols[i].name;

	/* checking if the table version is up to date */
	if (db_check_table_version(&db, db_hdl, &tcp_db_table, TCP_TABLE_VERSION) != 0)
		goto error;

	/* table to use */
	if (db.use_table(db_hdl, &tcp_db_table) < 0) {
		LM_ERR("cannot select table \"%.*s\"\n", tcp_db_table.len, tcp_db_table.s);
		goto error;
	}

	if (DB_CAPABILITY(db, DB_CAP_FETCH)) {
		if (db.query(db_hdl, 0, 0, 0, columns, 0, db_cols, 0, 0) < 0) {
			LM_ERR("DB query failed - retrieve valid connections\n");
			goto error;
		}

		no_rows = estimate_available_rows(8 + 42 + 42 + 3 + 4 * NO_INT_VALS,
								db_cols);
		if (no_rows == 0) no_rows = 5;
		if (db.fetch_result(db_hdl, &res, no_rows) < 0) {
			LM_ERR("Error fetching rows\n");
			goto error;
		}
	} else {
		if (db.query(db_hdl, 0, 0, 0, columns, 0, db_cols, 0, &res) < 0) {
			LM_ERR("DB query failed - retrieve valid connections\n");
			goto error;
		}
	}

	LM_DBG("%d rows found in %.*s\n",
		RES_ROW_N(res), tcp_db_table.len, tcp_db_table.s);

	do {
		for (n = 0, i = 0; i < RES_ROW_N(res); i++) {
			row = RES_ROWS(res) + i;
			n++;

			if (n > paths_sz) {
				paths_sz = (paths_sz == 0 ? 16 : (2 * paths_sz));
				paths = shm_realloc(paths, paths_sz * sizeof *paths);
				if (!paths) {
					LM_ERR("failed to allocate TCP paths array\n");
					goto error;
				}
			}

			if (db_row_decode(row, tcp_mgm_cols, int_vals, str_vals, NULL) != 0) {
				LM_ERR("failed to decode row, skipping\n");
				continue;
			}

			if (tcp_store_path(int_vals, str_vals, &paths[i]) < 0) {
				LM_ERR("failed to validate TCP path with id: %d, skipping\n",
				       int_vals[TCPCOL_ID]);
				continue;
			}
		}

		if (DB_CAPABILITY(db, DB_CAP_FETCH)) {
			if (db.fetch_result(db_hdl, &res, no_rows) < 0) {
				LM_ERR("fetching rows\n");
				goto error;
			}
		} else {
			break;
		}

	} while (RES_ROW_N(res) > 0);

	LM_INFO("%d records found in %.*s table\n", n,
	        tcp_db_table.len, tcp_db_table.s);
	db.free_result(db_hdl, res);

	paths_sz = n;
	qsort(paths, paths_sz, sizeof *paths, tcp_path_comparator);

	*new_paths = paths;
	*new_paths_sz = paths_sz;
	return 0;

error:
	LM_ERR("failed to load TCP paths from DB\n");
	*new_paths = NULL;
	*new_paths_sz = 0;
	return -1;
}
