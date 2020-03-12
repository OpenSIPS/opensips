/*
 * JWT Authentication Module
 *
 * Copyright (C) 2020 OpenSIPS Project
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
 * History:
 * --------
 * 2020-03-12 initial release (vlad)
 */

#include <string.h>
#include "../../ut.h"
#include "../../str.h"
#include "../../db/db.h"
#include "../../dprint.h"
#include "../../parser/digest/digest.h"
#include "../../parser/hf.h"
#include "../../parser/parser_f.h"
#include "../../usr_avp.h"
#include "../../mod_fix.h"
#include "../../mem/mem.h"
#include "jwt_avps.h"
#include "authjwt_mod.h"

#include <jwt.h>

#define RAW_QUERY_BUF_LEN	1024
#define DEC_AND_CHECK_LEN(_curr,_size)				\
	 do {							\
		if (_size < 0) {				\
			LM_ERR("Failed to build query \n");	\
			return -1;				\
		}						\
		_curr-=_size; 					\
		if (_curr < 0) { 				\
			LM_ERR("Buffer overflow  \n"); 		\
			return -1; 				\
		}						\
	} while(0)						\

int jwt_authorize(struct sip_msg* _msg, str* jwt_token, 
		pv_spec_t* decoded_jwt, pv_spec_t* auth_user)
{
	char raw_query_s[RAW_QUERY_BUF_LEN], *p;
	int n,len, i,j;
	str raw_query,secret;
	struct jwt_avp *cred;
	char *jwt_token_buf = NULL,*tag_s;
	jwt_t *jwt = NULL,*jwt_dec=NULL;
	str tag;
	db_res_t *res = NULL;
	db_row_t *row;
	pv_value_t pv_val;
	int_str ivalue;

	jwt_token_buf = pkg_malloc(jwt_token->len + 1);
	if (!jwt_token_buf) {
		LM_ERR("No more pkg mem \n");
		goto err_out;
	}
	memcpy(jwt_token_buf,jwt_token->s,jwt_token->len);
	jwt_token_buf[jwt_token->len] = 0;

	if (jwt_decode(&jwt, jwt_token_buf, NULL,0) != 0 || jwt == NULL) {
		LM_ERR("Failed to decode jwt \n");
		goto err_out;
	}

	tag_s = (char *)jwt_get_grant(jwt,(const char *)jwt_tag_claim.s);
	if (!tag_s) {
		LM_ERR("Failed to find claim %s\n",jwt_tag_claim.s);
		goto err_out;
	}

	LM_DBG("Decoded JWT and found claim %s with value %s \n",jwt_tag_claim.s,tag_s);
	
	tag.s = tag_s;
	tag.len = strlen(tag_s);

	raw_query.s = raw_query_s;
	p = raw_query_s;	
	len = RAW_QUERY_BUF_LEN;

	n = snprintf(p,len,"SELECT a.%.*s,b.%.*s",
	username_column.len,username_column.s,
	secret_column.len,secret_column.s);
	DEC_AND_CHECK_LEN(len, n);
	p+=n;

	for (i=0,cred=jwt_credentials; cred; i++,cred=cred->next) {
		n = snprintf(p,len,",a.%.*s",cred->attr_name.len,cred->attr_name.s);
		DEC_AND_CHECK_LEN(len,n);
		p+=n;
	}
	
	n = snprintf(p,len," from %.*s a inner join %.*s b on a.%.*s = b.%.*s  where a.%.*s=\"%.*s\" and UNIX_TIMESTAMP() >= b.%.*s and UNIX_TIMESTAMP() < b.%.*s",
	profiles_table.len,profiles_table.s,
	secrets_table.len,secrets_table.s,	
	tag_column.len,tag_column.s,
	secret_tag_column.len,secret_tag_column.s,
	tag_column.len,tag_column.s,
	tag.len,tag.s,
	start_ts_column.len,start_ts_column.s,
	end_ts_column.len,end_ts_column.s);

	DEC_AND_CHECK_LEN(len,n);
	p+=n;

	raw_query.len = (int)(p-raw_query_s);
	
	LM_DBG("built JWT raw db query [%.*s]\n",raw_query.len,raw_query.s);
	if (auth_dbf.raw_query(auth_db_handle, &raw_query, &res) < 0) {
		LM_ERR("raw_query failed\n");
		goto err_out;
	}

	if (RES_ROW_N(res) == 0) {
		LM_DBG("No matching JWT profiles for tag [%.*s]\n",tag.len,tag.s);
		goto err_out;
	}

	LM_DBG("Found %d record for tag %.*s\n",RES_ROW_N(res),tag.len,tag.s);
	for (i = 0; i < RES_ROW_N(res); i++) {
		row = RES_ROWS(res) + i;
		secret.s = (char *)VAL_STRING(ROW_VALUES(row) + 1);
		secret.len = strlen(secret.s);

		if (jwt_dec) {
			jwt_free(jwt_dec);
			jwt_dec = NULL;
		}

		if (jwt_decode(&jwt_dec, jwt_token_buf, (const unsigned char *)secret.s,secret.len) != 0 || 
		jwt_dec == NULL) {
			LM_DBG("Failed to decode jwt with DB secret \n");
			continue;
		}

		pv_val.flags = PV_VAL_STR;
		pv_val.rs.s =  jwt_dump_str(jwt_dec,0);
		pv_val.rs.len = strlen(pv_val.rs.s);
		if (pv_set_value(_msg,decoded_jwt,0,&pv_val) != 0) {
			LM_ERR("Failed to set decoded JWT pvar \n");
			auth_dbf.free_result(auth_db_handle, res);
			goto err_out;
		} 
	
		pv_val.rs.s = (char *)VAL_STRING(ROW_VALUES(row));
		pv_val.rs.len = strlen(pv_val.rs.s);
		if (pv_set_value(_msg,auth_user,0,&pv_val) != 0) {
			LM_ERR("Failed to set decoded JWT auth user \n");
			auth_dbf.free_result(auth_db_handle, res);
			goto err_out;
		} 

		for (j=2,cred=jwt_credentials; cred; j++,cred=cred->next) {
			switch (res->col.types[j]) {
				case DB_STR:
				case DB_BLOB:
					ivalue.s = VAL_STR(&(res->rows[i].values[j]));
					if (VAL_NULL(&(res->rows[i].values[j])) ||
					ivalue.s.s == NULL || ivalue.s.len==0)
						continue;

					if (add_avp(cred->avp_type|AVP_VAL_STR,
					cred->avp_name,ivalue)!=0){
						LM_ERR("failed to add extra AVP\n");
						auth_dbf.free_result(auth_db_handle, res);
						goto err_out;
					}

					break;
				case DB_STRING:
					ivalue.s.s = (char *)VAL_STRING(&(res->rows[i].values[j]));
					ivalue.s.len = strlen(ivalue.s.s);

					if (VAL_NULL(&(res->rows[i].values[j])) ||
					ivalue.s.s == NULL || ivalue.s.len==0)
						continue;

					if (add_avp(cred->avp_type|AVP_VAL_STR,
					cred->avp_name,ivalue)!=0){
						LM_ERR("failed to add extra AVP\n");
						auth_dbf.free_result(auth_db_handle, res);
						goto err_out;
					}

					break;
				case DB_INT:
					ivalue.n = (int)VAL_INT(&(res->rows[i].values[j]));
					if (VAL_NULL(&(res->rows[i].values[j])))
						continue;
					if (add_avp(cred->avp_type, 
					cred->avp_name, ivalue)!=0) {
						LM_ERR("failed to add AVP\n");
						auth_dbf.free_result(auth_db_handle, res);
						goto err_out;
					}
					break;
				default:
					LM_ERR("Unsupported column type \n");
					break;
			}
		}

		LM_INFO("Validated jwt %s with key %.*s\n",jwt_dump_str(jwt_dec,0),secret.len,secret.s);
		auth_dbf.free_result(auth_db_handle, res);
		if (jwt_token_buf)
			pkg_free(jwt_token_buf);
		if (jwt)
			jwt_free(jwt);
		if (jwt_dec)
			jwt_free(jwt_dec);
		return 1;
	}

	auth_dbf.free_result(auth_db_handle, res);

err_out:
	if (jwt_token_buf)
		pkg_free(jwt_token_buf);
	if (jwt)
		jwt_free(jwt);
	if (jwt_dec)
		jwt_free(jwt_dec);
	return -1;
}
