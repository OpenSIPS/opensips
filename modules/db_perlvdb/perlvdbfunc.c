/*
 * Perl virtual database module interface
 *
 * Copyright (C) 2007 Collax GmbH
 *                    (Bastian Friedrich <bastian.friedrich@collax.com>)
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
 */

#include <string.h>
#include <ctype.h>
#include <stdio.h>

#include "perlvdb.h"
#include "perlvdbfunc.h"
#include "../../str.h"


/*
 * Simple conversion IV -> int
 * including decreasing ref cnt
 */

static inline long IV2int(SV *in) {
	int ret = -1;

	if (SvOK(in)) {
		if (SvIOK(in)) {
			ret = SvIV(in);
		}
		SvREFCNT_dec(in);
	}

	return ret;
}

/*
 * Returns the class part of the URI
 */
str *parseurl(const str* url) {
	static str cn;

	cn.s = q_memchr(url->s,':',url->len);
	if (cn.s && ((cn.s+1)<(url->s+url->len)) ) {
		cn.s++;
		cn.len = url->len - (cn.s-url->s);
		return &cn;
	}
	return NULL;
}


SV *newvdbobj(const str* cn) {
	SV* obj;
	SV *class;

	class = newSVpvn(cn->s, cn->len);

	obj = perlvdb_perlmethod(class, PERL_CONSTRUCTOR_NAME,
			NULL, NULL, NULL, NULL);

	return obj;
}

SV *getobj(db_con_t *con) {
	return ((SV*)CON_TAIL(con));
}

/*
 * Checks whether the passed SV is a valid VDB object:
 * - not null
 * - not undef
 * - an object
 * - derived from OpenSIPS::VDB
 */
int checkobj(SV* obj) {
	if (obj != NULL) {
		if (obj != &PL_sv_undef) {
			if (sv_isobject(obj)) {
				if (sv_derived_from(obj, PERL_VDB_BASECLASS)) {
					return 1;
				}
			}
		}
	}

	return 0;
}

/*
 * Initialize database module
 * No function should be called before this
 */
db_con_t* perlvdb_db_init(const str* url) {
	db_con_t* res;
	str *cn;
	SV *obj = NULL;
	int consize = sizeof(db_con_t) + sizeof(SV);

	if (!url || !url->s | !url->len) {
		LM_ERR("invalid parameter value\n");
		return NULL;
	}

	cn = parseurl(url);
	if (!cn) {
		LM_ERR("invalid perl vdb url.\n");
		return NULL;
	}

	obj = newvdbobj(cn);
	if (!checkobj(obj)) {
		LM_ERR("could not initialize module. Not inheriting from %s?\n",
				PERL_VDB_BASECLASS);
		return NULL;
	}

	res = pkg_malloc(consize);
	if (!res) {
		LM_ERR("no pkg memory left\n");
		return NULL;
	}
	memset(res, 0, consize);
	CON_TAIL(res) = (unsigned long)obj;

	return res;
}


/*
 * Store name of table that will be used by
 * subsequent database functions
 */
int perlvdb_use_table(db_con_t* h, const str* t) {
	SV *ret;
	SV *table;
	int res = -1;
	if (!h || !t || !t->s) {
		LM_ERR("invalid parameter value\n");
		return -1;
	}
	table = newSVpv(t->s, t->len);
	ret = perlvdb_perlmethod(getobj(h), PERL_VDB_USETABLEMETHOD,
			table, NULL, NULL, NULL);
	SvREFCNT_dec(table);
	res = IV2int(ret);
	return res;
}


void perlvdb_db_close(db_con_t* h) {
	if (!h) {
		LM_ERR("invalid parameter value\n");
		return;
	}

	pkg_free(h);
}


/*
 * Insert a row into specified table
 * h: structure representing database connection
 * k: key names
 * v: values of the keys
 * n: number of key=value pairs
 */
int perlvdb_db_insertreplace(db_con_t* h, db_key_t* k, db_val_t* v,
		int n, char *insertreplace) {
	AV *arr;
	SV *arrref;
	SV *ret;

	arr = pairs2perlarray(k, v, n);
	arrref = newRV_noinc((SV*)arr);
	ret = perlvdb_perlmethod(getobj(h), insertreplace,
			arrref, NULL, NULL, NULL);

	av_undef(arr);

	return IV2int(ret);
}

int perlvdb_db_insert(db_con_t* h, db_key_t* k, db_val_t* v, int n) {
	return perlvdb_db_insertreplace(h, k, v, n, PERL_VDB_INSERTMETHOD);
}

/*
 * Just like insert, but replace the row if it exists
 */
int perlvdb_db_replace(db_con_t* h, db_key_t* k, db_val_t* v, int n) {
	return perlvdb_db_insertreplace(h, k, v, n, PERL_VDB_REPLACEMETHOD);
}

/*
 * Delete a row from the specified table
 * h: structure representing database connection
 * k: key names
 * o: operators
 * v: values of the keys that must match
 * n: number of key=value pairs
 */
int perlvdb_db_delete(db_con_t* h, db_key_t* k, db_op_t* o, db_val_t* v,
		int n) {
	AV *arr;
	SV *arrref;
	SV *ret;

	arr = conds2perlarray(k, o, v, n);
	arrref = newRV_noinc((SV*)arr);
	ret = perlvdb_perlmethod(getobj(h), PERL_VDB_DELETEMETHOD,
			arrref, NULL, NULL, NULL);

	av_undef(arr);

	return IV2int(ret);
}


/*
 * Update some rows in the specified table
 * _h: structure representing database connection
 * _k: key names
 * _o: operators
 * _v: values of the keys that must match
 * _uk: updated columns
 * _uv: updated values of the columns
 * _n: number of key=value pairs
 * _un: number of columns to update
 */
int perlvdb_db_update(db_con_t* h, db_key_t* k, db_op_t* o, db_val_t* v,
	      db_key_t* uk, db_val_t* uv, int n, int un) {

	AV *condarr;
	AV *updatearr;

	SV *condarrref;
	SV *updatearrref;

	SV *ret;

	condarr = conds2perlarray(k, o, v, n);
	updatearr = pairs2perlarray(uk, uv, un);

	condarrref = newRV_noinc((SV*)condarr);
	updatearrref = newRV_noinc((SV*)updatearr);

	ret = perlvdb_perlmethod(getobj(h), PERL_VDB_UPDATEMETHOD,
			condarrref, updatearrref, NULL, NULL);

	av_undef(condarr);
	av_undef(updatearr);

	return IV2int(ret);
}

/*
 * Query table for specified rows
 * h: structure representing database connection
 * k: key names
 * op: operators
 * v: values of the keys that must match
 * c: column names to return
 * n: number of key=values pairs to compare
 * nc: number of columns to return
 * o: order by the specified column
 */
int perlvdb_db_query(db_con_t* h, db_key_t* k, db_op_t* op, db_val_t* v,
			db_key_t* c, int n, int nc,
			db_key_t o, db_res_t** r) {


	AV *condarr;
	AV *retkeysarr;
	SV *order;

	SV *condarrref;
	SV *retkeysref;

	SV *resultset;

	int retval = 0;
	/* Create parameter set */
	condarr = conds2perlarray(k, op, v, n);

	retkeysarr = keys2perlarray(c, nc);

	if (o) order = newSVpv(o->s, o->len);
	else order = &PL_sv_undef;

	condarrref = newRV_noinc((SV*)condarr);
	retkeysref = newRV_noinc((SV*)retkeysarr);

	/* Call perl method */
	resultset = perlvdb_perlmethod(getobj(h), PERL_VDB_QUERYMETHOD,
			condarrref, retkeysref, order, NULL);

	SvREFCNT_dec(condarrref);
	SvREFCNT_dec(retkeysref);
	if(SvOK(order))
		SvREFCNT_dec(order);

	/* Transform perl result set to OpenSIPS result set */
	if (!resultset) {
		/* No results. */
		retval = -1;
	} else {
		if (sv_isa(resultset, "OpenSIPS::VDB::Result")) {
			retval = perlresult2dbres(resultset, r);
		/* Nested refs are decreased/deleted inside the routine */
			SvREFCNT_dec(resultset);
		} else {
			LM_ERR("invalid result set retrieved from perl call.\n");
			retval = -1;
		}
	}
	return retval;
}


/*
 * Release a result set from memory
 */
int perlvdb_db_free_result(db_con_t* _h, db_res_t* _r) {
	int i,j;
	/* free result set
	 * use the order of allocation
	 * first free values
	*/
	if(_r){
		/* for each row */
		for(i=0; i < RES_ROW_N(_r); i++){
			/* for each column in row i */
			for(j=0; j < RES_ROWS(_r)[i].n; j++){
                                switch ( (RES_ROWS(_r)[i].values)[j].type ) { /* the type of a value j in row i */
                                        case DB_STRING:
                                        case DB_STR:
						pkg_free((RES_ROWS(_r)[i].values)[j].val.str_val.s);
                                                break;
                                        case DB_BLOB:
                                                pkg_free((RES_ROWS(_r)[i].values)[j].val.blob_val.s) ;
                                                break;
					case DB_INT:
					case DB_BIGINT:
					case DB_DOUBLE:
					case DB_BITMAP:
					case DB_DATETIME:
						break;
                                }
			} /* for each column in row i*/
		} /* for each row */

		for(i=0; i< RES_COL_N(_r); i++){
			pkg_free(RES_NAMES(_r)[i]->s);
		}
		db_free_result(_r);
	}
	return 0;
}
