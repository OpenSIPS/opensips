/*
 * Copyright (C) 2013 OpenSIPS Solutions
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
 *
 * history:
 * ---------
 *  2013-02-xx  created (vlad-paiu)
 */

#include "../../mem/mem.h"
#include "../../dprint.h"
#include "../../db/db_query.h"
#include "../../db/db_ut.h"
#include "../../db/db_id.h"
#include "../../timer.h"
#include "../../cachedb/cachedb.h"

#include "dbase.h"

extern struct cachedb_url *db_cachedb_script_urls;

db_con_t* db_cachedb_init(const str* _url)
{
	char *p;
	int len;
	struct cachedb_url *it;
	cachedb_funcs cdbf;
	cachedb_con *cdbc = NULL;
	struct db_cachedb_con* ptr;
	db_con_t *res;

	if (!_url) {
		LM_ERR("invalid parameter value\n");
		return 0;
	}

	res = pkg_malloc(sizeof(db_con_t));
	if (!res) {
		LM_ERR("No more pkg mem\n");
		return NULL;
	}

	memset(res,0,sizeof(db_con_t));

	p=_url->s+sizeof("cachedb:/");
	len=_url->len-sizeof("cachedb:/");

	for (it=db_cachedb_script_urls;it;it=it->next) {
		if (memcmp(it->url.s,p,len) == 0) {
			LM_DBG("Found matching URL : [%.*s]\n",it->url.len,it->url.s);

			if (cachedb_bind_mod(&it->url,&cdbf) < 0) {
				LM_ERR("Cannot bind cachedb functions for URL [%.*s]\n",
						it->url.len,it->url.s);
				return NULL;
			}

			cdbc = cdbf.init(&it->url);
			if (cdbc == NULL) {
				LM_ERR("Failed to connect to the cachedb back-end\n");
				return NULL;
			}

			ptr = pkg_malloc(sizeof(struct db_cachedb_con));
			if (!ptr) {
				LM_ERR("no private memory left\n");
				pkg_free(res);
				return 0;
			}

			memset(ptr, 0, sizeof(struct db_cachedb_con));
			ptr->ref = 1;

			ptr->cdbc = cdbc;
			ptr->cdbf = cdbf;

			res->tail = (unsigned long)ptr;
			LM_DBG("Successfully initiated connection to [%.*s] \n",len,p);

			return res;
		}
	}

	LM_ERR("No match for url [%.*s]\n",_url->len,_url->s);
	return NULL;
}

void db_cachedb_close(db_con_t* _h)
{
	struct db_cachedb_con* ptr = (struct db_cachedb_con *)_h->tail;

	LM_DBG("closing db_cachedb con \n");
	ptr->cdbf.destroy(ptr->cdbc);
	pkg_free(_h);
}


int db_cachedb_free_result(db_con_t* _h, db_res_t* _r)
{
	struct db_cachedb_con* ptr = (struct db_cachedb_con *)_h->tail;

	if (ptr->cdbf.db_free_trans == NULL) {
		LM_ERR("The selected NoSQL driver cannot convert free result queries\n");
		return -1;
	}

	return ptr->cdbf.db_free_trans(ptr->cdbc,_r);
}

int db_cachedb_query(const db_con_t* _h, const db_key_t* _k, const db_op_t* _op,
		const db_val_t* _v, const db_key_t* _c, const int _n, const int _nc,
		const db_key_t _o, db_res_t** _r)
{
	struct db_cachedb_con* ptr = (struct db_cachedb_con *)_h->tail;

	if (ptr->cdbf.db_query_trans == NULL) {
		LM_ERR("The selected NoSQL driver cannot convert select queries\n");
		return -1;
	}

	return ptr->cdbf.db_query_trans(ptr->cdbc,_h->table,_k,_op,_v,_c,_n,_nc,_o,_r);
}

int db_cachedb_insert(const db_con_t* _h, const db_key_t* _k, const db_val_t* _v, const int _n)
{
	struct db_cachedb_con* ptr = (struct db_cachedb_con *)_h->tail;

	if (ptr->cdbf.db_insert_trans == NULL) {
		LM_ERR("The selected NoSQL driver cannot convert insert queries\n");
		return -1;
	}

	return ptr->cdbf.db_insert_trans(ptr->cdbc,_h->table,_k,_v,_n);
}

int db_cachedb_delete(const db_con_t* _h, const db_key_t* _k, const
        db_op_t* _o, const db_val_t* _v, const int _n)
{
	struct db_cachedb_con* ptr = (struct db_cachedb_con *)_h->tail;

	if (ptr->cdbf.db_delete_trans == NULL) {
		LM_ERR("The selected NoSQL driver cannot convert delete queries\n");
		return -1;
	}

	return ptr->cdbf.db_delete_trans(ptr->cdbc,_h->table,_k,_o,_v,_n);
}

int db_cachedb_update(const db_con_t* _h, const db_key_t* _k, const db_op_t* _o,
        const db_val_t* _v, const db_key_t* _uk, const db_val_t* _uv, const int _n,
        const int _un)
{
	struct db_cachedb_con* ptr = (struct db_cachedb_con *)_h->tail;

	if (ptr->cdbf.db_update_trans == NULL) {
		LM_ERR("The selected NoSQL driver cannot convert update queries\n");
		return -1;
	}

	return ptr->cdbf.db_update_trans(ptr->cdbc,_h->table,_k,_o,_v,_uk,_uv,_n,_un);
}

int db_cachedb_use_table(db_con_t* _h, const str* _t)
{
	if (!_h || !_t || !_t->s) {
		LM_ERR("invalid parameter value %p, %p\n", _h, _t);
		return -1;
	}

	CON_TABLE(_h) = _t;
	return 0;
}

int db_cachedb_raw_query(const db_con_t* _h, const str* _s, db_res_t** _r)
{
	/* This will most likely never be supported :( */
	LM_ERR("RAW query not support by db_cachedb \n");
	return -1;
}
