 /*
￼ * Trie Module
￼ *
￼ * Copyright (C) 2024 OpenSIPS Project
￼ *
￼ * opensips is free software; you can redistribute it and/or modify
￼ * it under the terms of the GNU General Public License as published by
￼ * the Free Software Foundation; either version 2 of the License, or
￼ * (at your option) any later version.
￼ *
￼ * opensips is distributed in the hope that it will be useful,
￼ * but WITHOUT ANY WARRANTY; without even the implied warranty of
￼ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
￼ * GNU General Public License for more details.
￼ *
￼ * You should have received a copy of the GNU General Public License
￼ * along with this program; if not, write to the Free Software
￼ * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
￼ *
￼ * History:
￼ * --------
￼ * 2024-12-03 initial release (vlad)
￼ */

#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>


#include "../../dprint.h"
#include "../../route.h"
#include "../../db/db.h"
#include "../../mem/shm_mem.h"
#include "../../mem/rpm_mem.h"
#include "../../time_rec.h"
#include "../../socket_info.h"

#include "trie_load.h"
#include "prefix_tree.h"
#include "trie_db_def.h"


#define check_val2( _col, _val, _type1, _type2, _not_null, _is_empty_str) \
	do{\
		if ((_val)->type!=_type1 && (_val)->type!=_type2) { \
			LM_ERR("column %.*s has a bad type [%d], accepting only [%d,%d]\n",\
				_col.len, _col.s, (_val)->type, _type1, _type2); \
			goto error;\
		} \
		if (_not_null && (_val)->nul) { \
			LM_ERR("column %.*s is null\n", _col.len, _col.s); \
			goto error;\
		} \
		if (_is_empty_str && VAL_STRING(_val)==0) { \
			LM_ERR("column %.*s (str) is empty\n", _col.len, _col.s); \
			goto error;\
		} \
	}while(0)

#define check_val( _col, _val, _type, _not_null, _is_empty_str) \
	do{\
		if ((_val)->type!=_type) { \
			LM_ERR("column %.*s has a bad type [%d], accepting only [%d]\n",\
				_col.len, _col.s, (_val)->type, _type); \
			goto error;\
		} \
		if (_not_null && (_val)->nul) { \
			LM_ERR("column %.*s is null\n", _col.len, _col.s); \
			goto error;\
		} \
		if (_is_empty_str && VAL_STRING(_val)==0) { \
			LM_ERR("column %.*s (str) is empty\n", _col.len, _col.s); \
			goto error;\
		} \
	}while(0)


void hash_rule(str* prefix, trie_info_t* rule, MD5_CTX* hash_ctx, FILE* fp)
{
	if (prefix->s && prefix->len) {
		MD5Update(hash_ctx, prefix->s, prefix->len);
		if (fp)
			fprintf(fp, " %.*s",prefix->len,prefix->s);
	}

	if (rule->attrs.s && rule->attrs.len) {
		MD5Update(hash_ctx, rule->attrs.s, rule->attrs.len);
		if (fp)
			fprintf(fp, " %.*s",rule->attrs.len,rule->attrs.s);
	}

	if (fp)
		fprintf(fp,"\n");
}

static int add_rule(trie_data_t *rdata, str *prefix,
		trie_info_t *rule, osips_malloc_f malloc_f, osips_free_f free_f,MD5_CTX *hash_ctx, FILE *fp)
{
	if ( add_trie_prefix(rdata->pt, prefix, rule,malloc_f, free_f)!=0 ) {
		LM_ERR("failed to add prefix route\n");
		goto error;
	}

	hash_rule(prefix,rule,hash_ctx,fp);

	return 0;
error:
	return -1;
}

/* loads trie info for given partition; if partition_name is NULL
 * loads all partitions
 */

trie_data_t* trie_load_info(struct head_db *current_partition, MD5_CTX* hash_ctx, FILE *fp)
{
	db_func_t *trie_dbf;
	db_con_t* db_hdl;
	str *trie_table = &current_partition->trie_table;
	db_key_t columns[3];
	db_res_t* res;
	db_row_t* row;
	trie_info_t *ri;
	trie_data_t *rdata;
	int i,n;
	int no_rows = 10;
	str prefix,attrs;

	trie_dbf = &current_partition->db_funcs;
	db_hdl = *current_partition->db_con;

	res = 0;
	ri = 0;
	rdata = 0;

	/* init new data structure */
	if ( (rdata=build_trie_data(current_partition))==0 ) {
		LM_ERR("failed to build rdata\n");
		goto error;
	}


	/* read the routing rules */
	if (trie_dbf->use_table( db_hdl, trie_table) < 0) {
		LM_ERR("cannot select table \"%.*s\"\n", trie_table->len, trie_table->s);
		goto error;
	}

	columns[0] = &prefix_trie_col;
	columns[1] = &attrs_trie_col;
	columns[2] = &enabled_trie_col;

	if (DB_CAPABILITY(*trie_dbf, DB_CAP_FETCH)) {
		if ( trie_dbf->query( db_hdl, 0, 0, 0, columns, 0, 3, 0, 0) < 0) {
			LM_ERR("DB query failed\n");
			goto error;
		}
		no_rows = estimate_available_rows( 32+128+4, 3/*cols*/);
		if (no_rows==0) no_rows = 10;
		if(trie_dbf->fetch_result(db_hdl, &res, no_rows)<0) {
			LM_ERR("Error fetching rows\n");
			goto error;
		}
	} else {
		if ( trie_dbf->query( db_hdl, 0, 0, 0, columns, 0, 3, 0, &res) < 0) {
			LM_ERR("DB query failed\n");
			goto error;
		}
	}

	if (RES_ROW_N(res) == 0) {
		LM_WARN("table \"%.*s\" is empty\n", trie_table->len, trie_table->s);
	}

	LM_DBG("initial %d records found in %.*s\n", RES_ROW_N(res),
			trie_table->len, trie_table->s);

	n = 0;
	do {
		for(i=0; i < RES_ROW_N(res); i++) {
			row = RES_ROWS(res) + i;
			/* PREFIX column */
			check_val( prefix_trie_col, ROW_VALUES(row), DB_STRING, 1, 1);

			prefix.s = (char *)VAL_STRING(ROW_VALUES(row));
			prefix.len = strlen(prefix.s);

			if ((ROW_VALUES(row)+1)->nul || VAL_STRING(ROW_VALUES(row)+1) == NULL) {
				attrs.s = NULL;
				attrs.len = 0;
			} else {
				attrs.s = (char *)VAL_STRING(ROW_VALUES(row)+1);
				attrs.len = strlen(attrs.s);
			}	

			LM_DBG("Fetched %.*s prefix \n",VAL_STR(ROW_VALUES(row)).len,VAL_STR(ROW_VALUES(row)).s);

			/* build the routing rule */
			if ((ri = build_trie_info( 
					&attrs,
					VAL_INT(ROW_VALUES(row)+2),
					current_partition->malloc,
					current_partition->free))== 0 ) {
				LM_ERR("failed to add routing info for rule prefix %.*s\n", VAL_STR(ROW_VALUES(row)+1).len,VAL_STR(ROW_VALUES(row)+1).s);
				continue;
			}
			/* add the rule */
			if (add_rule(
				rdata, 
				&prefix,
				ri,
				current_partition->malloc, 
				current_partition->free,hash_ctx, fp)!=0) {

				LM_ERR("failed to add routing info for rule prefix %.*s\n", VAL_STR(ROW_VALUES(row)+1).len,VAL_STR(ROW_VALUES(row)+1).s);
				free_trie_info(ri, current_partition->free);
				continue;
			}
			n++;
		}
		if (DB_CAPABILITY(*trie_dbf, DB_CAP_FETCH)) {
			if(trie_dbf->fetch_result(db_hdl, &res, no_rows)<0) {
				LM_ERR( "fetching rows (1)\n");
				goto error;
			}
			LM_DBG("additional %d records found in %.*s\n", RES_ROW_N(res),
					trie_table->len, trie_table->s);
		} else {
			break;
		}
	} while(RES_ROW_N(res)>0);

	trie_dbf->free_result(db_hdl, res);
	res = 0;

	LM_DBG("%d total records loaded from table %.*s\n", n,
			trie_table->len, trie_table->s);
	return rdata;
error:
	if (res)
		trie_dbf->free_result(db_hdl, res);
	if (rdata)
		free_trie_data(rdata, current_partition->free);
	rdata = NULL;
	return 0;
}
