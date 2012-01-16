/*
 * $Id$
 *
 * reg_db_handler module
 *
 * Copyright (C) 2011 VoIP Embedded, Inc.
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 *  2011-12-16  initial version (Ovidiu Sas)
 */

#include "../../dprint.h"
#include "../../db/db.h"
#include "../../str.h"

#include "reg_db_handler.h"

str registrar_column = str_init(REGISTRAR_COL);
str proxy_column = str_init(PROXY_COL);
str aor_column = str_init(AOR_COL);
str third_party_registrant_column = str_init(THIRD_PARTY_REGISTRANT_COL);
str username_column = str_init(USERNAME_COL);
str password_column = str_init(PASSWORD_COL);
str binding_URI_column = str_init(BINDING_URI_COL);
str binding_params_column = str_init(BINDING_PARAMS_COL);
str expiry_column = str_init(EXPIRY_COL);
str forced_socket_column = str_init(FORCED_SOCKET_COL);

str reg_table_name = str_init(REG_TABLE_NAME);

static db_con_t *reg_db_handle = NULL;
static db_func_t reg_dbf;


int connect_reg_db(const str *db_url)
{
	if (reg_db_handle) {
		LM_CRIT("BUG - db connection found already open\n");
		return -1;
	}
	if ((reg_db_handle = reg_dbf.init(db_url)) == NULL)
		return -1;
	return 0;
}


static int use_reg_table(void)
{
	if(!reg_db_handle){
		LM_ERR("invalid database handle\n");
		return -1;
	}
	reg_dbf.use_table(reg_db_handle, &reg_table_name);
	return 0;
}


static int load_reg_info_from_db(void)
{
	db_res_t * res = NULL;
	db_val_t * values;
	db_row_t * rows;
	int i, nr_rows;
	unsigned int n_result_cols = 0;
	unsigned int registrar_col;
	unsigned int proxy_col;
	unsigned int aor_col;
	unsigned int third_party_registrant_col;
	unsigned int username_col;
	unsigned int password_col;
	unsigned int binding_URI_col;
	unsigned int binding_params_col;
	unsigned int expiry_col;
	unsigned int forced_socket_col;
	db_key_t q_cols[REG_TABLE_TOTAL_COL_NO];

	char *p = NULL;
	int len = 0;
	str now = {NULL, 0};
	struct sip_uri uri;
	str forced_socket, host;
	int port, proto;
	uac_reg_map_t uac_param;

	p = int2str((unsigned long)(time(0)), &len);
	if (p && len>0) {
		now.s = (char *)pkg_malloc(len);
		if(now.s) {
			memcpy(now.s, p, len); now.len = len;
		} else {
			LM_ERR("oom\n"); return -1;
		}
	}

	if(use_reg_table()) return -1;

	q_cols[registrar_col = n_result_cols++] = &registrar_column;
	q_cols[proxy_col = n_result_cols++] = &proxy_column;
	q_cols[aor_col = n_result_cols++] = &aor_column;
	q_cols[third_party_registrant_col = n_result_cols++] =
					&third_party_registrant_column;
	q_cols[username_col = n_result_cols++] = &username_column;
	q_cols[password_col = n_result_cols++] = &password_column;
	q_cols[binding_URI_col = n_result_cols++] = &binding_URI_column;
	q_cols[binding_params_col = n_result_cols++] = &binding_params_column;
	q_cols[expiry_col = n_result_cols++] = &expiry_column;
	q_cols[forced_socket_col = n_result_cols++] = &forced_socket_column;

	/* select the whole tabel and all the columns */
	if (DB_CAPABILITY(reg_dbf, DB_CAP_FETCH)) {
		if(reg_dbf.query(reg_db_handle, 0, 0, 0, q_cols, 0,
				REG_TABLE_TOTAL_COL_NO, 0, 0) < 0) {
			LM_ERR("Error while querying (fetch) database\n");
			return -1;
		}
		if(reg_dbf.fetch_result(reg_db_handle, &res, REG_FETCH_SIZE)<0){
			LM_ERR("fetching rows failed\n");
			return -1;
		}
	} else {
		if(reg_dbf.query(reg_db_handle, 0, 0, 0, q_cols, 0,
				REG_TABLE_TOTAL_COL_NO, 0, &res) < 0) {
			LM_ERR("Error while querying database\n");
			return -1;
		}
	}

	nr_rows = RES_ROW_N(res);

	do {
		LM_NOTICE("loading [%i] records from db\n", nr_rows);
		rows = RES_ROWS(res);
		/* for every row/record */
		for(i=0; i<nr_rows; i++){
			values = ROW_VALUES(rows + i);
			if (VAL_NULL(values+registrar_col) ||
				VAL_NULL(values+aor_col) ||
				VAL_NULL(values+binding_URI_col)) {
				LM_ERR("columns [%.*s] or/and [%.*s] or/and [%.*s]"
					" cannot be null -> skipping\n",
					registrar_column.len, registrar_column.s,
					aor_column.len, aor_column.s,
					binding_URI_column.len, binding_URI_column.s);
				continue;
			}

			memset(&uac_param, 0, sizeof(uac_reg_map_t));

			/* Get the registrar (mandatory parameter) */
			uac_param.registrar_uri.s =
				(char*)values[registrar_col].val.string_val;
			uac_param.registrar_uri.len =
				strlen(uac_param.registrar_uri.s);
			if (parse_uri(uac_param.registrar_uri.s,
					uac_param.registrar_uri.len, &uri)<0) {
				LM_ERR("cannot parse registrar uri [%.*s]\n",
					uac_param.registrar_uri.len,
					uac_param.registrar_uri.s);
				continue;
			}
			if (uri.user.s && uri.user.len) {
				LM_ERR("registrant uri must not have user [%.*s]\n",
					uri.user.len, uri.user.s);
				continue;
			}

			/* Get the proxy */
			uac_param.proxy_uri.s =
				(char*)values[proxy_col].val.string_val;
			uac_param.proxy_uri.len =
				strlen(uac_param.proxy_uri.s);
			if (uac_param.proxy_uri.len) {
				if (parse_uri(uac_param.proxy_uri.s,
						uac_param.proxy_uri.len, &uri)<0) {
					LM_ERR("cannot parse proxy uri [%.*s]\n",
						uac_param.proxy_uri.len,
						uac_param.proxy_uri.s);
					continue;
				}
				if (uri.user.s && uri.user.len) {
					LM_ERR("proxy uri must not have user [%.*s]\n",
						uri.user.len, uri.user.s);
					continue;
				}
			} else {
				uac_param.proxy_uri.s = NULL;
			}

			/* Get the AOR (mandatory parameter) */
			uac_param.to_uri.s =
				(char*)values[aor_col].val.string_val;
			uac_param.to_uri.len =
				strlen(uac_param.to_uri.s);
			if (parse_uri(uac_param.to_uri.s,uac_param.to_uri.len,&uri)<0) {
				LM_ERR("cannot parse aor uri [%.*s]\n",
					uac_param.to_uri.len, uac_param.to_uri.s);
				continue;
			}
			uac_param.hash_code =
				core_hash(&uac_param.to_uri, NULL, reg_hsize);

			/* Get the third party registrant */
			uac_param.from_uri.s =
				(char*)values[third_party_registrant_col].val.string_val;
			uac_param.from_uri.len = strlen(uac_param.from_uri.s);
			if (uac_param.from_uri.len) {
				if (parse_uri(uac_param.from_uri.s,
						uac_param.from_uri.len, &uri)<0) {
					LM_ERR("cannot parse third party registrant"
						" uri [%.*s]\n",
						uac_param.from_uri.len,
						uac_param.from_uri.s);
					continue;
				}
			} else {
				uac_param.from_uri.s = NULL;
			}

			/* Get the binding (manadatory parameter) */
			uac_param.contact_uri.s =
				(char*)values[binding_URI_col].val.string_val;
			uac_param.contact_uri.len =
				strlen(uac_param.contact_uri.s);
			if (parse_uri(uac_param.contact_uri.s,
					uac_param.contact_uri.len, &uri)<0) {
				LM_ERR("cannot parse contact uri [%.*s]\n",
					uac_param.contact_uri.len,
					uac_param.contact_uri.s);
				continue;
			}

			/* Get the authentication user */
			uac_param.auth_user.s =
				(char*)values[username_col].val.string_val;
			uac_param.auth_user.len = strlen(uac_param.auth_user.s);
			if (uac_param.auth_user.len == 0) uac_param.auth_user.s = NULL;

			/* Get the authentication password */
			uac_param.auth_password.s =
				(char*)values[password_col].val.string_val;
			uac_param.auth_password.len = strlen(uac_param.auth_password.s);
			if (uac_param.auth_password.len == 0)
				uac_param.auth_password.s = NULL;

			/* Get the binding params */
			uac_param.contact_params.s =
				(char*)values[binding_params_col].val.string_val;
			uac_param.contact_params.len =
				strlen(uac_param.contact_params.s);
			if (uac_param.contact_params.len == 0)
				uac_param.contact_params.s = NULL;

			/* Get the expiration param */
			uac_param.expires = values[expiry_col].val.int_val;

			/* Get the socket */
			if (values[forced_socket_col].val.string_val) {
				forced_socket.s =
					(char*)values[forced_socket_col].val.string_val;
				forced_socket.len = strlen(forced_socket.s);
				if (parse_phostport(forced_socket.s, forced_socket.len,
						&host.s, &host.len, &port, &proto)<0) {
					LM_ERR("cannot parse forced socket [%.*s]\n",
						forced_socket.len, forced_socket.s);
					continue;
				}
				uac_param.send_sock = grep_sock_info(&host,
							(unsigned short) port,
							(unsigned short) proto);
				if (uac_param.send_sock==NULL) {
					LM_ERR("invalid forced socket [%.*s]\n",
						forced_socket.len, forced_socket.s);
					continue;
				}
			}
			LM_NOTICE("registrar=[%.*s] AOR=[%.*s] auth_user=[%.*s] "
				"password=[%.*s] expire=[%d] proxy=[%.*s] "
				"contact=[%.*s] third_party=[%.*s]\n",
				uac_param.registrar_uri.len, uac_param.registrar_uri.s,
				uac_param.to_uri.len, uac_param.to_uri.s,
				uac_param.auth_user.len, uac_param.auth_user.s,
				uac_param.auth_password.len, uac_param.auth_password.s,
				uac_param.expires,
				uac_param.proxy_uri.len, uac_param.proxy_uri.s,
				uac_param.contact_uri.len, uac_param.contact_uri.s,
				uac_param.from_uri.len, uac_param.from_uri.s);
			if(add_record(&uac_param, &now)<0) {
				LM_ERR("can't load registrant\n");
				continue;
			}
		}

		/* any more data to be fetched ?*/
		if (DB_CAPABILITY(reg_dbf, DB_CAP_FETCH)) {
			if (reg_dbf.fetch_result(reg_db_handle, &res, REG_FETCH_SIZE)<0) {
				LM_ERR("fetching more rows failed\n");
				goto error;
			}
			nr_rows = RES_ROW_N(res);
		} else {
			nr_rows = 0;
		}
	}while (nr_rows>0);

	reg_dbf.free_result(reg_db_handle, res);
	if (now.s) pkg_free(now.s);
	return 0;
error:
	reg_dbf.free_result(reg_db_handle, res);
	if (now.s) pkg_free(now.s);
	return -1;
}


int init_reg_db(const str *db_url)
{
	/* Find a database module */
	if (db_bind_mod(db_url, &reg_dbf) < 0) {
		LM_ERR("Unable to bind to a database driver\n");
		return -1;
	}
	if (connect_reg_db(db_url)!=0){
		LM_ERR("unable to connect to the database\n");
		return -1;
	}
	if(db_check_table_version(&reg_dbf, reg_db_handle,
			&reg_table_name, REG_TABLE_VERSION) < 0) {
		LM_ERR("error during table version check.\n");
		return -1;
	}
	if(load_reg_info_from_db() !=0){
		LM_ERR("unable to load the sca data\n");
		return -1;
	}

	reg_dbf.close(reg_db_handle);
	reg_db_handle = NULL;

	return 0;
}


void destroy_reg_db(void)
{
	if (reg_db_handle) {
		reg_dbf.close(reg_db_handle);
		reg_db_handle = NULL;
	}
}
