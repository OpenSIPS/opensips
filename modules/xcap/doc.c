/*
 * xcap module - XCAP operations module
 *
 * Copyright (C) 2012 AG Projects
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


#include "doc.h"
#include "xcap_mod.h"


int get_xcap_doc(str* user, str* domain, int type, str* filename, str* match_etag, str** doc, str** etag)
{
	db_key_t query_cols[5];
	db_val_t query_vals[5];
	db_key_t result_cols[3];
	int etag_col, doc_col;
	int n_query_cols = 0;
	int n_result_cols = 0;
	db_res_t *result = 0;
	db_row_t *row;
	db_val_t *row_vals;
	str db_body;
	str db_etag;
	str* doc_tmp = NULL;
	str* etag_tmp = NULL;

	*doc = NULL;
	*etag = NULL;

	query_cols[n_query_cols] = &xcap_username_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = *user;
	n_query_cols++;

	query_cols[n_query_cols] = &xcap_domain_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = *domain;
	n_query_cols++;

	query_cols[n_query_cols] = &xcap_doc_type_col;
	query_vals[n_query_cols].type = DB_INT;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.int_val= type;
	n_query_cols++;

	if (filename != NULL && filename->s != NULL && filename->len != 0)
        {
                query_cols[n_query_cols] = &xcap_doc_uri_col;
                query_vals[n_query_cols].type = DB_STR;
                query_vals[n_query_cols].nul = 0;
                query_vals[n_query_cols].val.str_val = *filename;
                n_query_cols++;
        }

	if (match_etag != NULL && match_etag->s != NULL && match_etag->len != 0)
        {
                query_cols[n_query_cols] = &xcap_doc_etag_col;
                query_vals[n_query_cols].type = DB_STR;
                query_vals[n_query_cols].nul = 0;
                query_vals[n_query_cols].val.str_val = *match_etag;
                n_query_cols++;
        }

	result_cols[doc_col = n_result_cols++] = &xcap_doc_col;
	result_cols[etag_col = n_result_cols++] = &xcap_doc_etag_col;

	if (xcap_dbf.use_table(xcap_db, &xcap_table) < 0)
	{
		LM_ERR("in use_table-[table]= %.*s\n", xcap_table.len, xcap_table.s);
		return -1;
	}

	if (xcap_dbf.query(xcap_db, query_cols, 0 , query_vals, result_cols,
			   n_query_cols, n_result_cols, 0, &result) < 0)
	{
		LM_ERR("while querying table xcap for [user]=%.*s\t[domain]= %.*s\n",
		       user->len, user->s,	domain->len, domain->s);
		if(result)
			xcap_dbf.free_result(xcap_db, result);
		return -1;
	}

	if(result == NULL)
		return -1;

	if(result->n <= 0)
	{
		LM_DBG("No document found in db table for %.*s@%.*s of type %d\n",
		       user->len, user->s, domain->len, domain->s, type);
		xcap_dbf.free_result(xcap_db, result);
		return 0;
	}

	row = &result->rows[0];
	row_vals = ROW_VALUES(row);

        /* Get XCAP document body */
	switch (row_vals[doc_col].type) {
		case DB_STRING:
			LM_DBG("extracted db_string\n");
			db_body.s = (char*)row_vals[0].val.string_val;
			if (db_body.s)
				db_body.len = strlen(db_body.s);
			break;
		case DB_STR:
			LM_DBG("extracted db_str\n");
			db_body = row_vals[0].val.str_val;
			break;
		case DB_BLOB:
			LM_DBG("extracted db_blob\n");
			db_body = row_vals[0].val.blob_val;
			break;
		default:
			LM_ERR("unexpected column type %d\n", row_vals[0].type);
			goto error;
	}

	if(db_body.s == NULL || db_body.len == 0)
	{
		LM_ERR("no XCAP body found\n");
		goto error;
	}

        /* Get XCAP document etag */
	switch (row_vals[etag_col].type) {
		case DB_STRING:
			LM_DBG("extracted db_string\n");
			db_etag.s = (char*)row_vals[0].val.string_val;
			if (db_etag.s)
				db_etag.len = strlen(db_etag.s);
			break;
		case DB_STR:
			LM_DBG("extracted db_str\n");
			db_etag = row_vals[0].val.str_val;
			break;
		default:
			LM_ERR("unexpected column type %d\n", row_vals[0].type);
			goto error;
	}

	if(db_etag.s == NULL || db_etag.len == 0)
	{
		LM_ERR("no XCAP etag found\n");
		goto error;
	}

	doc_tmp = pkg_malloc(sizeof(*doc_tmp));
	if(doc_tmp == NULL)
	{
		LM_ERR("No more pkg memory\n");
		goto error;
	}
	doc_tmp->s = pkg_malloc(db_body.len);
	if(doc_tmp->s == NULL)
	{
		pkg_free(doc_tmp);
		LM_ERR("No more pkg memory\n");
		goto error;
	}
	memcpy(doc_tmp->s, db_body.s, db_body.len);
	doc_tmp->len = db_body.len;

	etag_tmp = pkg_malloc(sizeof(*etag_tmp));
	if(etag_tmp == NULL)
	{
		LM_ERR("No more pkg memory\n");
		goto error;
	}
	etag_tmp->s = pkg_malloc(db_etag.len);
	if(etag_tmp->s == NULL)
	{
		pkg_free(etag_tmp);
		LM_ERR("No more pkg memory\n");
		goto error;
	}
	memcpy(etag_tmp->s, db_etag.s, db_etag.len);
	etag_tmp->len = db_etag.len;

        *etag = etag_tmp;
	*doc = doc_tmp;

	if(result)
		xcap_dbf.free_result(xcap_db, result);

	return 0;

error:
        if (doc_tmp)
        {
                if (doc_tmp->s)
                        pkg_free(doc_tmp->s);
                pkg_free(doc_tmp);
        }

        if (etag_tmp)
        {
                if (etag_tmp->s)
                        pkg_free(etag_tmp->s);
                pkg_free(etag_tmp);
        }

	if(result)
		xcap_dbf.free_result(xcap_db, result);

	return -1;

}

