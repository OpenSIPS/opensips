/*
 * Copyright (C) 2004-2006 Voice Sistem SRL
 *
 * This file is part of Open SIP Server (opensips).
 *
 * opensips is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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
 * History:
 * ---------
 *  2004-10-04  first version (ramona)
 *  2004-11-11  added support for db schemes for avp_db_load (ramona)
 */


#include <stdlib.h>
#include <string.h>

#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../db/db.h"
#include "../../db/db_insertq.h"
#include "../../dprint.h"
#include "../../route.h"
#include "avpops_parse.h"
#include "avpops_db.h"


static str       def_table;    /* default DB table */
static str      **db_columns;  /* array with names of DB columns */

static db_key_t   keys_cmp[3]; /* array of keys and values used in selection */
static db_val_t   vals_cmp[3]; /* statement as in "select" and "delete" */

/* linked list with all defined DB schemes */
static struct db_scheme  *db_scheme_list=0;

struct db_url *default_db_url = NULL;

/* array of db urls */
static struct db_url *db_urls = NULL;  /* array of database urls */
static unsigned int no_db_urls = 0;


struct db_url* get_db_url(unsigned int idx)
{
	unsigned int i;

	for (i=0;i<no_db_urls;i++) {
		if (db_urls[i].idx == idx)
			return &db_urls[i];
	}
	return NULL;
}


struct db_url* get_default_db_url(void)
{
	struct db_url *url;

	url = get_db_url( 0 );
	if (url!=NULL)
		return url;
	if (no_db_urls==0)
		return NULL;
	return &db_urls[0];
}


int add_db_url(modparam_t type, void *val)
{
	char *param=(char*)val, *url=0;;
	long idx;

	if(!param)
		return E_UNSPEC;
	if(STR_PARAM & (type != STR_PARAM)){
		LM_ERR("Expected string type parameter for DBX URL.\n");
		return E_CFG;
	}

	idx = strtol(param, &url, 10);
	if(param==url) {
		/* default URL */
		idx = 0;
	}

	while(isspace(*url)) url++;

	if (no_db_urls==0) {
		db_urls = (struct db_url*)pkg_malloc(sizeof(struct db_url));
	} else {
		if (get_db_url(idx)!=NULL) {
			LM_ERR("db_url idx %ld overwritten (multiple definitions)\n",idx);
			return E_CFG;
		}
		db_urls = (struct db_url*)pkg_realloc
			(db_urls, (no_db_urls+1)*sizeof(struct db_url));
	}

	if (db_urls==NULL) {
		LM_ERR("failed to alloc pkg array\n");
		return E_OUT_OF_MEM;
	}

	memset(&db_urls[no_db_urls], '\0', sizeof *db_urls);

	db_urls[no_db_urls].url.s = url;
	db_urls[no_db_urls].url.len = strlen(url);
	db_urls[no_db_urls].idx = idx;

	no_db_urls++;

	return 0;
}



int avpops_db_bind(void)
{
	unsigned int i;

	for(i=0;i<no_db_urls;i++) {
		if (db_bind_mod(&db_urls[i].url, &db_urls[i].dbf )) {
			LM_CRIT("cannot bind to database module for %.*s! "
				"Did you load a database module ?\n",
				db_urls[i].url.len,db_urls[i].url.s);
			return -1;
		}

		if (!DB_CAPABILITY(db_urls[i].dbf, DB_CAP_ALL)) {
			LM_CRIT("database modules (%.*s) does not "
				"provide all functions needed by avpops module\n",
				db_urls[i].url.len,db_urls[i].url.s);
			return -1;
		}
	}

	/*
	 * we cannot catch the default DB url usage at fixup time
	 * as we do with the other bunch of extra avpops DB URLs
	 *
	 * so just dig through the whole script tree
	 */
	if (is_script_func_used("avp_db_query", 1) ||
	    is_script_func_used("avp_db_query", 2)) {
		if (!DB_CAPABILITY(default_db_url->dbf, DB_CAP_RAW_QUERY)) {
			LM_ERR("driver for DB URL [default] does not support "
				   "raw queries!\n");
			return -1;
		}
	}

	if (is_script_async_func_used("avp_db_query", 1) ||
	    is_script_async_func_used("avp_db_query", 2)) {
		if (!DB_CAPABILITY(default_db_url->dbf, DB_CAP_ASYNC_RAW_QUERY))
			LM_WARN("async() calls for DB URL [default] will work "
			        "in normal mode due to driver limitations\n");
	}

	return 0;
}


int avpops_db_init(const str* db_table, str** db_cols)
{
	int i;

	for(i=0;i<no_db_urls;i++) {
		db_urls[i].hdl = db_urls[i].dbf.init( &db_urls[i].url );
		if (db_urls[i].hdl==0) {
			LM_ERR("cannot initialize database connection for %s\n",
				db_urls[i].url.s);
			goto error;
		}
		if (db_urls[i].dbf.use_table(db_urls[i].hdl, db_table)<0) {
			LM_ERR("cannot select table \"%.*s\"\n",
				db_table->len, db_table->s);
			goto error;
		}
	}

	def_table.s = db_table->s;
	def_table.len = db_table->len;
	db_columns = db_cols;

	return 0;
error:
	for(--i;i>=0;i--){
		if (db_urls[i].hdl) {
			db_urls[i].dbf.close(db_urls[i].hdl);
			db_urls[i].hdl = NULL;
		}
	}
	return -1;
}


int avp_add_db_scheme( modparam_t type, void* val)
{
	struct db_scheme *scheme;

	scheme = (struct db_scheme*)pkg_malloc( sizeof(struct db_scheme) );
	if (scheme==0)
	{
		LM_ERR("no more pkg memory\n");
		goto error;
	}
	memset( scheme, 0, sizeof(struct db_scheme));

	/* parse the scheme */
	if ( parse_avp_db_scheme( (char*)val, scheme)!=0 )
	{
		LM_ERR("failed to parse scheme\n");
		goto error;
	}

	/* check for duplicates */
	if ( avp_get_db_scheme(&scheme->name)!=0 )
	{
		LM_ERR("duplicated scheme name <%.*s>\n",
			scheme->name.len,scheme->name.s);
		goto error;
	}

	/* print scheme */
	LM_DBG("new scheme <%.*s> added\n"
		"\t\tuuid_col=<%.*s>\n\t\tusername_col=<%.*s>\n"
		"\t\tdomain_col=<%.*s>\n\t\tvalue_col=<%.*s>\n"
		"\t\tdb_flags=%d\n\t\ttable=<%.*s>\n",
		scheme->name.len,scheme->name.s,
		scheme->uuid_col.len, scheme->uuid_col.s, scheme->username_col.len,
		scheme->username_col.s, scheme->domain_col.len, scheme->domain_col.s,
		scheme->value_col.len, scheme->value_col.s, scheme->db_flags,
		scheme->table.len, scheme->table.s);

	scheme->next = db_scheme_list;
	db_scheme_list = scheme;

	return 0;
error:
	return -1;
}


struct db_scheme *avp_get_db_scheme (str *name)
{
	struct db_scheme *scheme;

	for( scheme=db_scheme_list ; scheme ; scheme=scheme->next )
		if ( name->len==scheme->name.len &&
		!strcasecmp( name->s, scheme->name.s) )
			return scheme;
	return 0;
}


static inline int set_table( struct db_url *url, const str *table, char *func)
{
	if (table && table->s) {
		if ( url->dbf.use_table( url->hdl, table)<0 ) {
			LM_ERR("db-%s: cannot set table \"%.*s\"\n",
				func, table->len, table->s);
			return -1;
		}
	} else {
		if ( url->dbf.use_table( url->hdl, &def_table)<0 ) {
			LM_ERR("db-%s: cannot set table \"%.*s\"\n",
				func, def_table.len, def_table.s);
			return -1;
		}
	}
	return 0;
}



static inline int prepare_selection( str *uuid, str *username, str *domain,
										char *attr, struct db_scheme *scheme)
{
	unsigned int nr_keys_cmp;

	nr_keys_cmp = 0;
	if (uuid)
	{
		/* uuid column */
		keys_cmp[ nr_keys_cmp ] =
			(scheme&&scheme->uuid_col.s)?&scheme->uuid_col:db_columns[0];
		vals_cmp[ nr_keys_cmp ].type = DB_STR;
		vals_cmp[ nr_keys_cmp ].nul  = 0;
		vals_cmp[ nr_keys_cmp ].val.str_val = *uuid;
		nr_keys_cmp++;
	} else {
		if (username)
		{
			/* username column */
			keys_cmp[ nr_keys_cmp ] =
			(scheme&&scheme->username_col.s)?&scheme->username_col:db_columns[4];
			vals_cmp[ nr_keys_cmp ].type = DB_STR;
			vals_cmp[ nr_keys_cmp ].nul  = 0;
			vals_cmp[ nr_keys_cmp ].val.str_val = *username;
			nr_keys_cmp++;
		}
		if (domain)
		{
			/* domain column */
			keys_cmp[ nr_keys_cmp ] =
			(scheme&&scheme->domain_col.s)?&scheme->domain_col:db_columns[5];
			vals_cmp[ nr_keys_cmp ].type = DB_STR;
			vals_cmp[ nr_keys_cmp ].nul  = 0;
			vals_cmp[ nr_keys_cmp ].val.str_val = *domain;
			nr_keys_cmp++;
		}
	}
	if (attr && scheme==0)
	{
		/* attribute name column */
		keys_cmp[ nr_keys_cmp ] = db_columns[1];
		vals_cmp[ nr_keys_cmp ].type = DB_STRING;
		vals_cmp[ nr_keys_cmp ].nul  = 0;
		vals_cmp[ nr_keys_cmp ].val.string_val = attr;
		nr_keys_cmp++;
	}
	return nr_keys_cmp;
}


db_res_t *db_load_avp(struct db_url *url, str *uuid, str *username,str *domain,
					char *attr, const str *table, struct db_scheme *scheme)
{
	static db_key_t   keys_ret[3];
	unsigned int      nr_keys_cmp;
	unsigned int      nr_keys_ret;
	db_res_t          *res = NULL;

	/* prepare DB query */
	nr_keys_cmp = prepare_selection( uuid, username, domain, attr, scheme);

	/* set table */
	if (set_table( url, scheme?&scheme->table:table ,"load")!=0)
		return 0;

	/* return keys */
	if (scheme==0)
	{
		keys_ret[0] = db_columns[2]; /*value*/
		keys_ret[1] = db_columns[1]; /*attribute*/
		keys_ret[2] = db_columns[3]; /*type*/
		nr_keys_ret = 3;
	} else {
		/* value */
		keys_ret[0] = scheme->value_col.s?&scheme->value_col:db_columns[2];
		nr_keys_ret = 1;
	}

	/* do the DB query */
	if ( url->dbf.query( url->hdl, keys_cmp, 0/*op*/, vals_cmp, keys_ret,
			nr_keys_cmp, nr_keys_ret, 0/*order*/, &res) < 0)
		return 0;

	return res;
}


void db_close_query(struct db_url *url, db_res_t *res )
{
	LM_DBG("close avp query\n");
	url->dbf.free_result( url->hdl, res);
}


int db_store_avp(struct db_url *url, db_key_t *keys, db_val_t *vals,
													int n, const str *table)
{
	int r;
	static query_list_t *ins_list = NULL;

	if (set_table( url, table ,"store")!=0)
		return -1;

	if (con_set_inslist(&url->dbf,url->hdl,&ins_list,keys,n) < 0 )
		CON_RESET_INSLIST(url->hdl);

	r = url->dbf.insert( url->hdl, keys, vals, n);
	if (r<0) {
		LM_ERR("insert failed\n");
		return -1;
	}
	return 0;
}



int db_delete_avp(struct db_url *url, str *uuid, str *username, str *domain,
												char *attr, const str *table)
{
	unsigned int  nr_keys_cmp;

	/* prepare DB query */
	nr_keys_cmp = prepare_selection( uuid, username, domain, attr, 0);

	/* set table */
	if (set_table( url, table ,"delete")!=0)
		return -1;

	/* do the DB query */
	if ( url->dbf.delete( url->hdl, keys_cmp, 0, vals_cmp, nr_keys_cmp) < 0)
		return 0;

	return 0;
}


int db_query_avp(struct db_url *url, struct sip_msg *msg, str *query,
														pvname_list_t* dest)
{
	db_res_t* db_res = NULL;

	if(query==NULL)
	{
		LM_ERR("bad parameter\n");
		return -1;
	}

	if(url->dbf.raw_query( url->hdl, query, &db_res)!=0)
	{
		const str *t = url->hdl&&url->hdl->table&&url->hdl->table->s
			? url->hdl->table : 0;
		LM_ERR("raw_query failed: db%d(%.*s) %.*s...\n",
		  url->idx, t?t->len:0, t?t->s:"", query->len > 40 ? 40 : query->len,
		  query->s);
		return -1;
	}

	if(db_res==NULL || RES_ROW_N(db_res)<=0 || RES_COL_N(db_res)<=0)
	{
		LM_DBG("no result after query\n");
		db_close_query( url, db_res );
		return 1;
	}

	if (db_query_avp_print_results(msg, db_res, dest) != 0) {
		LM_ERR("failed to print results\n");
		db_close_query( url, db_res );
		return -1;
	}

	db_close_query( url, db_res );
	return 0;
}

int db_query_avp_print_results(struct sip_msg *msg, const db_res_t *db_res,
								pvname_list_t *dest)
{
	int_str avp_val;
	int_str avp_name;
	unsigned short avp_type;
	int i, j;
	pvname_list_t* crt;

	LM_DBG("rows [%d]\n", RES_ROW_N(db_res));
	/* reverse order of rows so that first row get's in front of avp list */
	for(i = RES_ROW_N(db_res)-1; i >= 0; i--)
	{
		LM_DBG("row [%d]\n", i);
		crt = dest;
		for(j = 0; j < RES_COL_N(db_res); j++)
		{
			avp_type = 0;
			if(crt==NULL)
			{
				avp_name.s.s = int2str(j+1, &avp_name.s.len);
				avp_name.n = get_avp_id(&avp_name.s);
				if (avp_name.n < 0) {
					LM_ERR("cannot convert avp %d\n", j+1);
					goto next_avp;
				}
			} else {
				if(pv_get_avp_name(msg, &crt->sname.pvp, &avp_name.n,
							&avp_type)!=0)
				{
					LM_ERR("cant get avp name [%d/%d]\n", i, j);
					goto next_avp;
				}
			}
			if(RES_ROWS(db_res)[i].values[j].nul) {
				avp_type |= AVP_VAL_STR;
				/* keep the NULL value in sync with str_null as
				 * defined in pvar.c !! */
				avp_val.s.s = "<null>";
				avp_val.s.len = 6;
			} else {
				switch(RES_ROWS(db_res)[i].values[j].type) {
				case DB_STRING:
					avp_type |= AVP_VAL_STR;
					avp_val.s.s=
						(char*)RES_ROWS(db_res)[i].values[j].val.string_val;
					avp_val.s.len=strlen(avp_val.s.s);
					if(avp_val.s.len<0)
						goto next_avp;
				break;
				case DB_STR:
					avp_type |= AVP_VAL_STR;
					avp_val.s.len=
						RES_ROWS(db_res)[i].values[j].val.str_val.len;
					avp_val.s.s=
						(char*)RES_ROWS(db_res)[i].values[j].val.str_val.s;
					if(avp_val.s.len<0)
						goto next_avp;
				break;
				case DB_BLOB:
					avp_type |= AVP_VAL_STR;
					avp_val.s.len =
						RES_ROWS(db_res)[i].values[j].val.blob_val.len;
					avp_val.s.s =
						(char*)RES_ROWS(db_res)[i].values[j].val.blob_val.s;
					if(avp_val.s.len<0)
						goto next_avp;
				break;
				case DB_INT:
					avp_val.n =
						(int)RES_ROWS(db_res)[i].values[j].val.int_val;
				break;
				case DB_DATETIME:
					avp_val.n =
						(int)RES_ROWS(db_res)[i].values[j].val.time_val;
				break;
				case DB_BITMAP:
					avp_val.n =
						(int)RES_ROWS(db_res)[i].values[j].val.bitmap_val;
				break;
				case DB_BIGINT:
					avp_val.n =
						(int)RES_ROWS(db_res)[i].values[j].val.bigint_val;
				break;
				case DB_DOUBLE:
					avp_type |= AVP_VAL_STR;
					avp_val.s.s = double2str(
					        RES_ROWS(db_res)[i].values[j].val.double_val,
					        &avp_val.s.len);
				break;
				default:
					LM_WARN("Unknown type %d\n",
						RES_ROWS(db_res)[i].values[j].type);
					goto next_avp;
				}
			}
			if(add_avp(avp_type, avp_name.n, avp_val)!=0)
			{
				LM_ERR("unable to add avp\n");
				return -1;
			}
next_avp:
			if(crt)
			{
				crt = crt->next;
				if(crt==NULL)
					break;
			}
		}
	}

	return 0;
}
