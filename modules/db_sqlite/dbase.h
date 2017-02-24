/**
 *
 * Copyright (C) 2015 - OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History
 * -------
 *  2015-02-18  initial version (Ionut Ionita)
*/
#ifndef SQLITE_DBASE_H
#define SQLITE_DBASE_H

#define ALLOC_NEW(_call) alloc_new_##_call

db_con_t* db_sqlite_init(const str* _url);
void db_sqlite_close(db_con_t* _h);
int db_sqlite_use_table(db_con_t* _h, const str* _t);
int db_sqlite_query(const db_con_t* _h, const db_key_t* _k, const db_op_t* _op,
	     const db_val_t* _v, const db_key_t* _c, const int _n, const int _nc,
	     const db_key_t _o, db_res_t** _r);
int db_sqlite_fetch_result(const db_con_t* _h, db_res_t** _r, const int nrows);
int db_sqlite_raw_query(const db_con_t* _h, const str* _s, db_res_t** _r);
int db_sqlite_insert(const db_con_t* _h, const db_key_t* _k, const db_val_t* _v, const int _n);
int db_sqlite_delete(const db_con_t* _h, const db_key_t* _k, const db_op_t* _o,
	const db_val_t* _v, const int _n);
int db_sqlite_update(const db_con_t* _h, const db_key_t* _k, const db_op_t* _o,
	const db_val_t* _v, const db_key_t* _uk, const db_val_t* _uv, const int _n,
	const int _un);
int db_sqlite_replace(const db_con_t* _h, const db_key_t* _k, const db_val_t* _v, const int _n);
int db_last_inserted_id(const db_con_t* _h);
 int db_insert_update(const db_con_t* _h, const db_key_t* _k, const db_val_t* _v,
	const int _n);
int db_sqlite_free_result(db_con_t* _h, db_res_t* _r);
#endif
