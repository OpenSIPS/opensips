/*
 * Digest Authentication - Database support
 *
 * Copyright (C) 2001-2003 FhG Fokus
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
 * history:
 * ---------
 * 2003-02-28 scratchpad compatibility abandoned
 * 2003-01-27 next baby-step to removing ZT - PRESERVE_ZT (jiri)
 * 2004-06-06 updated to the new DB api, added auth_db_{init,bind,close,ver}
 *             (andrei)
 * 2005-05-31 general definition of AVPs in credentials now accepted - ID AVP,
 *            STRING AVP, AVP aliases (bogdan)
 * 2006-03-01 pseudo variables support for domain name (bogdan)
 * 2009-01-25 added prepared statements support in running the DB queries
 *             (bogdan)
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
#include "../../lib/digest_auth/digest_auth.h"
#include "aaa_avps.h"
#include "authdb_mod.h"


static str auth_500_err = str_init("Server Internal Error");

static str *get_cred_column(alg_t alg)
{
	str *rval;

	static db_ps_t auth_ha1_ps = NULL;
	static db_ps_t auth_ha1_sha256_ps = NULL;
	static db_ps_t auth_ha1_sha512t256_ps = NULL;

	if (calc_ha1) {
		rval = &pass_column;
		CON_SET_CURR_PS(auth_db_handle, &auth_ha1_ps);
		return rval;
	}
	switch(alg) {
	case ALG_UNSPEC:
	case ALG_MD5:
	case ALG_MD5SESS:
		rval = &pass_column;
		CON_SET_CURR_PS(auth_db_handle, &auth_ha1_ps);
		break;
	case ALG_SHA256:
	case ALG_SHA256SESS:
		rval = &hash_column_sha256;
		CON_SET_CURR_PS(auth_db_handle, &auth_ha1_sha256_ps);
		break;
	case ALG_SHA512_256:
	case ALG_SHA512_256SESS:
		rval = &hash_column_sha512t256;
		CON_SET_CURR_PS(auth_db_handle, &auth_ha1_sha512t256_ps);
		break;
	default:
		rval = NULL;
	}
	return (rval);
}

static inline int get_ha1(dig_cred_t* digest, const str* _domain,
    const str* _table, HASHHEX* _ha1, db_res_t** res)
{
	struct aaa_avp *cred;
	db_key_t keys[2];
	db_val_t vals[2];
	db_key_t *col;
	str result;
	struct username* _username = &digest->username;

	int n, nc;

	if (auth_dbf.use_table(auth_db_handle, _table) < 0) {
		LM_ERR("failed to use_table\n");
		goto e0;
	}

	col = pkg_malloc(sizeof(*col) * (credentials_n + 1));
	if (col == NULL) {
		LM_ERR("no more pkg memory\n");
		goto e0;
	}

	keys[0] = &user_column;
	keys[1] = &domain_column;

	col[0] = get_cred_column(digest->alg.alg_parsed);
	if (col[0] == NULL) {
		LM_ERR("unsupported algorithm: %d\n", digest->alg.alg_parsed);
		goto e1;
	}

	for (n = 0, cred=credentials; cred ; n++, cred=cred->next) {
		col[1 + n] = &cred->attr_name;
	}

	VAL_TYPE(vals) = VAL_TYPE(vals + 1) = DB_STR;
	VAL_NULL(vals) = VAL_NULL(vals + 1) = 0;

	VAL_STR(vals).s = _username->user.s;
	VAL_STR(vals).len = _username->user.len;

	if (_username->domain.len) {
		VAL_STR(vals + 1) = _username->domain;
	} else {
		VAL_STR(vals + 1) = *_domain;
	}

	n = (use_domain ? 2 : 1);
	nc = 1 + credentials_n;
	if (auth_dbf.query(auth_db_handle, keys, 0, vals, col, n, nc, 0, res) < 0) {
		LM_ERR("failed to query database\n");
		goto e1;
	}
	pkg_free(col);

	if (RES_ROW_N(*res) == 0) {
		LM_DBG("no result for user \'%.*s@%.*s\'\n",
				_username->user.len, ZSW(_username->user.s),
			(use_domain ? (_domain->len) : 0), ZSW(_domain->s));
		return 1;
	}

	result.s = (char*)ROW_VALUES(RES_ROWS(*res))[0].val.string_val;
	result.len = strlen(result.s);

	struct calc_HA1_arg cprms = {.alg = digest->alg.alg_parsed};
	if (calc_ha1) {
		/* Only plaintext passwords are stored in database,
		 * we have to calculate HA1 */
		cprms.creds.open = &(const struct digest_auth_credential){
		    .realm = *_domain, .user = _username->whole, .passwd = result};
		cprms.use_hashed = 0;
	} else {
		cprms.creds.ha1 = &result;
		cprms.use_hashed = 1;
	}
	cprms.nonce = &digest->nonce;
	cprms.cnonce = &digest->cnonce;
	if (auth_api.calc_HA1(&cprms, _ha1) != 0)
		return (-1);
	if (calc_ha1)
		LM_DBG("HA1 string calculated: %s\n", _ha1->_start);

	return 0;
e1:
	pkg_free(col);
e0:
	return -1;
}


/*
 * Generate AVPs from the database result
 */
static int generate_avps(db_res_t* result)
{
	struct aaa_avp *cred;
	int_str ivalue;
	int i;

	for (cred=credentials, i=1; cred; cred=cred->next, i++) {
		switch (result->col.types[i]) {
		case DB_STR:
			ivalue.s = VAL_STR(&(result->rows[0].values[i]));

			if (VAL_NULL(&(result->rows[0].values[i])) ||
			ivalue.s.s == NULL || ivalue.s.len==0)
				continue;

			if (add_avp(cred->avp_type|AVP_VAL_STR,cred->avp_name,ivalue)!=0){
				LM_ERR("failed to add AVP\n");
				return -1;
			}

			LM_DBG("set string AVP %d = \"%.*s\"\n",
					cred->avp_name, ivalue.s.len, ZSW(ivalue.s.s));
			break;
		case DB_STRING:
			ivalue.s.s = (char*)VAL_STRING(&(result->rows[0].values[i]));

			if (VAL_NULL(&(result->rows[0].values[i])) ||
			ivalue.s.s == NULL || (ivalue.s.len=strlen(ivalue.s.s))==0 )
				continue;

			if (add_avp(cred->avp_type|AVP_VAL_STR,cred->avp_name,ivalue)!=0){
				LM_ERR("failed to add AVP\n");
				return -1;
			}

			LM_DBG("set string AVP %d = \"%.*s\"\n",
					cred->avp_name, ivalue.s.len, ZSW(ivalue.s.s));
			break;
		case DB_INT:
			if (VAL_NULL(&(result->rows[0].values[i])))
				continue;

			ivalue.n = (int)VAL_INT(&(result->rows[0].values[i]));

			if (add_avp(cred->avp_type, cred->avp_name, ivalue)!=0) {
				LM_ERR("failed to add AVP\n");
				return -1;
			}

			LM_DBG("set int AVP %d = %d\n",cred->avp_name, ivalue.n);
			break;
		default:
			LM_ERR("subscriber table column %d `%.*s' has unsupported type. "
				"Only string/str or int columns are supported by"
				"load_credentials.\n", i,
				result->col.names[i]->len, result->col.names[i]->s);
			break;
		}
	}

	return 0;
}


/*
 * Authorize digest credentials
 */
static inline int authorize(struct sip_msg* _m, str *domain,
    str* table, hdr_types_t _hftype)
{
	HASHHEX ha1;
	int res;
	struct hdr_field* h;
	auth_body_t* cred;
	str msg_body;
	auth_result_t ret;
	db_res_t* result = NULL;

	ret = auth_api.pre_auth(_m, domain, _hftype, &h);

	if (ret != DO_AUTHORIZATION)
		return ret;

	cred = (auth_body_t*)h->parsed;

	res = get_ha1(&cred->digest, domain, table, &ha1, &result);
	if (res < 0) {
		/* Error while accessing the database */
		if (sigb.reply(_m, 500, &auth_500_err, NULL) == -1) {
			LM_ERR("failed to send 500 reply\n");
		}
		return ERROR;
	}
	if (res > 0) {
		/* Username not found in the database */
		auth_dbf.free_result(auth_db_handle, result);
		return USER_UNKNOWN;
	}

	if (cred->digest.qop.qop_parsed == QOP_AUTHINT_D &&
		get_body(_m, &msg_body) < 0) {
		LM_ERR("Failed to get body of SIP message\n");
		return ERROR;
	}

	/* Recalculate response, it must be same to authorize successfully */
	if (!auth_api.check_response(&(cred->digest),
	    &_m->first_line.u.request.method, &msg_body, &ha1)) {
		ret = auth_api.post_auth(_m, h);
		if (ret == AUTHORIZED)
			generate_avps(result);
		auth_dbf.free_result(auth_db_handle, result);
		return ret;
	}

	auth_dbf.free_result(auth_db_handle, result);
	return INVALID_PASSWORD;
}


/*
 * Authorize using Proxy-Authorize header field
 */
int proxy_authorize(struct sip_msg* _m, str* _realm, str* _table)
{
	return authorize(_m, _realm, _table, HDR_PROXYAUTH_T);
}


/*
 * Authorize using WWW-Authorize header field
 */
int www_authorize(struct sip_msg* _m, str* _realm, str* _table)
{
	return authorize(_m, _realm, _table, HDR_AUTHORIZATION_T);
}
