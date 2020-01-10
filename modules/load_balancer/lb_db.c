/*
 * load balancer module - complex call load balancing
 *
 * Copyright (C) 2009 Voice Sistem SRL
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
 *
 */




#include "../../db/db.h"
#include "lb_db.h"

#define LB_TABLE_VERSION  3

str lb_id_column			=	str_init(LB_ID_COL);
str lb_grpid_column			=	str_init(LB_GRP_ID_COL);
str lb_dsturi_column		=	str_init(LB_DST_URI_COL);
str lb_resource_column		=	str_init(LB_RESOURCES_COL);
str lb_pmode_column			=	str_init(LB_PMODE_COL);
str lb_attrs_column			=	str_init(LB_ATTRS_COL);
str lb_table_name			=	str_init(LB_TABLE_NAME);


static db_con_t* lb_db_handle    = 0; /* database connection handle */
static db_func_t lb_dbf;


#define check_val( _val, _type, _not_null, _is_empty_str) \
	do{\
		if ((_val)->type!=_type) { \
			LM_ERR("bad column type\n");\
			goto error;\
		} \
		if (_not_null && (_val)->nul) { \
			LM_ERR("nul column\n");\
			goto error;\
		} \
		if (_is_empty_str && VAL_STRING(_val)==0) { \
			LM_ERR("empty str column\n");\
			goto error;\
		} \
	}while(0)


int lb_connect_db(const str *db_url)
{
	if (lb_db_handle) {
		LM_CRIT("BUG - db connection found already open\n");
		return -1;
	}
	if ((lb_db_handle = lb_dbf.init(db_url)) == 0)
		return -1;

	return 0;
}

void lb_close_db(void)
{
	if (lb_db_handle==NULL)
		return;

	lb_dbf.close(lb_db_handle);
	lb_db_handle = NULL;
}


int init_lb_db(const str *db_url, char *table)
{
	/* Find a database module */
	if (db_bind_mod(db_url, &lb_dbf) < 0){
		LM_ERR("Unable to bind to a database driver\n");
		return -1;
	}

	if (lb_connect_db(db_url)!=0){
		LM_ERR("unable to connect to the database\n");
		return -1;
	}

	if (table) {
		lb_table_name.s = table;
		lb_table_name.len = strlen(table);
	}

	if(db_check_table_version(&lb_dbf, lb_db_handle,
	&lb_table_name, LB_TABLE_VERSION) < 0) {
		LM_ERR("error during table version check.\n");
		return -1;
	}

	return 0;
}


int lb_db_load_data( struct lb_data *data)
{
	db_key_t columns[LB_NO_COLS];
	db_res_t* res = NULL;
	db_row_t* row;
	int i, n;
	char *resource, *uri, *attrs;
	int id, group, pmode;
	unsigned int flags;
	int no_rows = 10;


	lb_dbf.use_table( lb_db_handle, &lb_table_name);

	columns[0] = &lb_id_column;
	columns[1] = &lb_grpid_column;
	columns[2] = &lb_dsturi_column;
	columns[3] = &lb_resource_column;
	columns[4] = &lb_pmode_column;
	columns[5] = &lb_attrs_column;

	if (0/*DB_CAPABILITY(lb_dbf, DB_CAP_FETCH))*/) {
		if (lb_dbf.query(lb_db_handle, 0, 0, 0, columns, 0, LB_NO_COLS, 0, 0) < 0) {
			LM_ERR("DB query failed\n");
			return -1;
		}
		no_rows = estimate_available_rows( 4+4+64+256+8+256, LB_NO_COLS/*cols*/);
		if (no_rows==0) no_rows = 10;
		if(lb_dbf.fetch_result( lb_db_handle, &res, no_rows)<0) {
			LM_ERR("Error fetching rows\n");
			return -1;
		}
	} else {
		if (lb_dbf.query(lb_db_handle, 0, 0, 0, columns, 0, LB_NO_COLS, 0, &res)<0) {
			LM_ERR("DB query failed\n");
			return -1;
		}
	}

	if (res == NULL || RES_ROW_N(res) == 0) {
		LM_WARN("table \"%.*s\" empty\n", lb_table_name.len,lb_table_name.s );
		return 0;
	}

	LM_DBG("%d records found in %.*s\n",
		RES_ROW_N(res), lb_table_name.len,lb_table_name.s );
	n = 0;

	do {
		for(i=0; i < RES_ROW_N(res); i++) {
			row = RES_ROWS(res) + i;
			flags = 0;
			/* ID column */
			check_val( ROW_VALUES(row), DB_INT, 1, 0);
			id = VAL_INT(ROW_VALUES(row));
			/* GRP_ID column */
			check_val( ROW_VALUES(row)+1, DB_INT, 1, 0);
			group = VAL_INT(ROW_VALUES(row)+1);
			/* DST_URI column */
			check_val( ROW_VALUES(row)+2, DB_STRING, 1, 1);
			uri = (char*)VAL_STRING(ROW_VALUES(row)+2);
			/* RESOURCES column */
			check_val( ROW_VALUES(row)+3, DB_STRING, 1, 1);
			resource = (char*)VAL_STRING(ROW_VALUES(row)+3);
			/* PROBING_MODE column */
			check_val( ROW_VALUES(row)+4, DB_INT, 1, 0);
			pmode = VAL_INT(ROW_VALUES(row)+4);
			if (pmode==0) {
				flags |= LB_DST_PING_DSBL_FLAG;
			} else if (pmode>=2) {
				flags |= LB_DST_PING_PERM_FLAG;
			}
			/* ATTRS column */
			check_val( ROW_VALUES(row)+5, DB_STRING, 0, 0);
			attrs = (char*)VAL_STRING(ROW_VALUES(row)+5);

			/* add the destinaton definition in */
			if ( add_lb_dsturi( data, id, group, uri, resource, attrs, flags)<0 ) {
				LM_ERR("failed to add destination %d -> skipping\n",n);
				continue;
			}
			n++;
		}
		if (DB_CAPABILITY( lb_dbf, DB_CAP_FETCH)) {
			if(lb_dbf.fetch_result(lb_db_handle, &res, no_rows)<0) {
				LM_ERR( "fetching rows (1)\n");
				return -1;
			}
		} else {
			break;
		}
	} while(RES_ROW_N(res)>0);

	lb_dbf.free_result(lb_db_handle, res);
	res = 0;

	return 0;
error:
	if (res)
		lb_dbf.free_result(lb_db_handle, res);
	return -1;
}


