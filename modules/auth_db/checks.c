/*
 * Various URI checks
 *
 * Copyright (C) 2001-2004 FhG FOKUS
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
 * History:
 * --------
 * 2003-02-26: Created by janakj
 * 2004-03-20: has_totag introduced (jiri)
 * 2004-06-07  updated to the new DB api, added uridb_db_{bind,init,close,ver}
 *              (andrei)
 * 2008-11-07: Added statistics to module: positive_checks and negative_checks (saguti)
 * 2009-03-13: Added get_auth_id() function to retrieve auth id and realm for a given uri
 *             (overturn technologies GmbH, Andreas Westermaier)
 */

#include <string.h>
#include "../../str.h"
#include "../../dprint.h"               /* Debugging */
#include "../../parser/digest/digest.h" /* get_authorized_cred */
#include "../../parser/parse_from.h"
#include "../../parser/parse_uri.h"
#include "../../ut.h"                   /* Handy utilities */
#include "../../db/db.h"                /* Database API */
#include "../../pvar.h"
#include "../../script_var.h"
#include "../../mod_fix.h"
#include "authdb_mod.h"
#include "checks.h"

/* Return codes reference */
#define OK 		 	 1		/* success */
#define ERR_INTERNAL		-1		/* Internal Error */
#define ERR_CREDENTIALS 	-2		/* No credentials error */
#define ERR_DBUSE  		-3		/* Data Base Use error */
#define ERR_USERNOTFOUND  	-4		/* No found username error */
#define ERR_DBEMTPYRES		-5		/* Emtpy Query Result */

#define ERR_DBACCESS	   	-7     		/* Data Base Access Error */
#define ERR_DBQUERY	  	-8		/* Data Base Query Error */
#define ERR_SPOOFEDUSER   	-9		/* Spoofed User Error */
#define ERR_NOMATCH	    	-10		/* No match Error */


/*
 * Check if a header field contains the same username
 * as digest credentials
 */
static inline int check_username(struct sip_msg* _m, str* _table,
													struct sip_uri *_uri)
{
	static db_ps_t my_ps = NULL;
	struct hdr_field* h;
	auth_body_t* c;
	db_key_t keys[3];
	db_val_t vals[3];
	db_key_t cols[1];
	db_res_t* res = NULL;

	if (_uri == NULL) {
		LM_ERR("Bad parameter\n");
		return ERR_INTERNAL;
	}

	/* Get authorized digest credentials */
	get_authorized_cred(_m->authorization, &h);
	if (h == NULL) {
		get_authorized_cred(_m->proxy_auth, &h);
		if (h == NULL) {
			LM_ERR("No authorized credentials found (error in scripts)\n");
			LM_ERR("Call {www,proxy}_authorize before calling check_* functions!\n");
			return ERR_CREDENTIALS;
		}
	}

	c = (auth_body_t*)(h->parsed);

	/* Parse To/From URI */
	/* Make sure that the URI contains username */
	if (_uri->user.len == 0) {
		LM_ERR("Username not found in URI\n");
		return ERR_USERNOTFOUND;
	}

	/* Use URI table to determine if Digest username
	 * and To/From username match. URI table is a table enumerating all allowed
	 * usernames for a single, thus a user can have several different usernames
	 * (which are different from digest username and it will still match)
	 */
	keys[0] = &uri_user_column;
	keys[1] = &uri_domain_column;
	keys[2] = &uri_uriuser_column;
	cols[0] = &uri_user_column;

	/* The whole fields are type DB_STR, and not null */
	VAL_TYPE(vals) = VAL_TYPE(vals + 1) = VAL_TYPE(vals + 2) = DB_STR;
	VAL_NULL(vals) = VAL_NULL(vals + 1) = VAL_NULL(vals + 2) = 0;

	VAL_STR(vals) = c->digest.username.user;
	VAL_STR(vals + 1) = *GET_REALM(&c->digest);
	VAL_STR(vals + 2) = _uri->user;

	auth_dbf.use_table(auth_db_handle, _table);
	CON_PS_REFERENCE(auth_db_handle) = &my_ps;

	if (auth_dbf.query(auth_db_handle, keys, 0, vals, cols, 3, 1, 0, &res) < 0)
	{
		LM_ERR("Error while querying database\n");
		return ERR_DBQUERY;
	}

	/* If the previous function returns at least one row, it means
	 * there is an entry for given digest username and URI username
	 * and thus this combination is allowed and the function will match
	 */
	if (RES_ROW_N(res) == 0) {
		LM_DBG("From/To user '%.*s' is spoofed\n",
			   _uri->user.len, ZSW(_uri->user.s));
		auth_dbf.free_result(auth_db_handle, res);
		return ERR_SPOOFEDUSER;
	} else {
		LM_DBG("From/To user '%.*s' and auth user match\n",
			   _uri->user.len, ZSW(_uri->user.s));
		auth_dbf.free_result(auth_db_handle, res);
		return OK;
	}
}


/*
 * Check username part in To header field
 */
int check_to(struct sip_msg* _m, str* _table)
{
	if (!_m->to && ((parse_headers(_m, HDR_TO_F, 0) == -1) || (!_m->to))) {
		LM_ERR("Error while parsing To header field\n");
		return ERR_INTERNAL;
	}
	if(parse_to_uri(_m)==NULL) {
		LM_ERR("Error while parsing To header URI\n");
		return ERR_INTERNAL;
	}

	return check_username(_m, _table, &get_to(_m)->parsed_uri);
}


/*
 * Check username part in From header field
 */
int check_from(struct sip_msg* _m, str* _table)
{
	if (parse_from_header(_m) < 0) {
		LM_ERR("Error while parsing From header field\n");
		return ERR_INTERNAL;
	}
	if(parse_from_uri(_m)==NULL) {
		LM_ERR("Error while parsing From header URI\n");
		return ERR_INTERNAL;
	}

	return check_username(_m, _table, &get_from(_m)->parsed_uri);
}


/*
 * Check if uri belongs to a local user
 */
int does_uri_exist(struct sip_msg* _msg, str* uri, str* _table)
{
	static db_ps_t my_ps = NULL;
	db_key_t keys[2];
	db_val_t vals[2];
	db_key_t cols[1];
	db_res_t* res = NULL;
	struct sip_uri p_uri;

	if (uri->len==0) {
		LM_DBG("empty URI parameter\n");
		return ERR_INTERNAL;
	}

	if (parse_uri( uri->s, uri->len, &p_uri)) {
		LM_DBG("URI parameter is not a valid SIP URI <%.*s>\n",
			uri->len, uri->s);
		return ERR_INTERNAL;
	}

	auth_dbf.use_table(auth_db_handle, _table);
	keys[0] = &user_column;
	keys[1] = &domain_column;
	cols[0] = &user_column;

	VAL_TYPE(vals) = VAL_TYPE(vals + 1) = DB_STR;
	VAL_NULL(vals) = VAL_NULL(vals + 1) = 0;
	VAL_STR(vals) = p_uri.user;
	VAL_STR(vals + 1) = p_uri.host;

	CON_PS_REFERENCE(auth_db_handle) = &my_ps;

	if (auth_dbf.query(auth_db_handle, keys, 0, vals, cols, (use_domain ? 2 : 1),
				1, 0, &res) < 0) {
		LM_ERR("Error while querying database\n");
		return ERR_USERNOTFOUND;
	}

	if (RES_ROW_N(res) == 0) {
		LM_DBG("User in request uri does not exist\n");
		auth_dbf.free_result(auth_db_handle, res);
		return ERR_DBEMTPYRES;
	} else {
		LM_DBG("User in request uri does exist\n");
		auth_dbf.free_result(auth_db_handle, res);
		return OK;
	}
}

/**
 * Set result pvs
 */
static int set_result_pv(struct sip_msg* _msg, unsigned short _avp_type,
					int_str _avp_val, pv_spec_t* _avp)
{
	int avp_name;
	unsigned short avp_type;


	switch (_avp->type) {
		case PVT_AVP:
			if (pv_get_avp_name(_msg, &(_avp->pvp), &avp_name, &avp_type) != 0) {
				LM_CRIT("BUG in getting AVP name\n");
				return -1;
			}

			avp_type |= _avp_type;

			if (add_avp(avp_type, avp_name, _avp_val) < 0) {
				LM_ERR("cannot add AVP\n");
				return -1;
			}
			break;

		case PVT_SCRIPTVAR:
			if(_avp->pvp.pvn.u.dname == 0){
				LM_ERR("cannot find svar name\n");
				return -1;
			}

			if (!set_var_value((script_var_t*) _avp->pvp.pvn.u.dname,
			&_avp_val, VAR_VAL_STR)) {
				LM_ERR("cannot set svar\n");
				return -1;
			}
			break;

		default:
			LM_CRIT("BUG: invalid pvar type\n");
			return -1;
	}

	return OK;
}


/**
 * Retrieves authentication id and realm from uri_table for a given sip uri
 */
int get_auth_id(struct sip_msg* _msg, str *_table, str* uri,
			pv_spec_t* _auth_user, pv_spec_t* _auth_realm)
{
	struct sip_uri sip_uri;
	int_str ret_authuser, ret_authrealm;
	static db_ps_t my_ps = NULL;
	db_key_t keys[2];
	db_val_t vals[2];
	db_key_t cols[2];
	db_res_t* dbres = NULL;
	db_row_t* dbres_row;

	/* check if we really have a valid uri as parameter */
	if (parse_uri(uri->s, uri->len, &sip_uri) < 0
	&& (sip_uri.user.s == NULL || sip_uri.user.len <= 0)) {
		LM_ERR("First parameter must be a URI with username (val = '%.*s').",
			uri->len, uri->s);
		return -1;
	}

	auth_dbf.use_table(auth_db_handle, _table);
	keys[0] = &uri_uriuser_column;
	keys[1] = &uri_domain_column;
	cols[0] = &uri_user_column;
	cols[1] = &uri_domain_column;

	VAL_TYPE(vals) = DB_STR;
	VAL_NULL(vals) = 0;
	VAL_STR(vals) = sip_uri.user;

	VAL_TYPE(vals + 1) = DB_STR;
	VAL_NULL(vals + 1) = 0;
	VAL_STR(vals + 1) = sip_uri.host;

	CON_PS_REFERENCE(auth_db_handle) = &my_ps;

	/* if use_domain is set also the domain column of the database table will
	   be honoured in the following query (see sixth parameter) */
	if (auth_dbf.query(auth_db_handle, keys, 0, vals, cols, (use_domain ? 2 : 1),
	2, 0, &dbres) < 0) {
		LM_ERR("Error while querying database\n");
		return ERR_DBQUERY;
	}

	if (RES_ROW_N(dbres) == 0) {
		LM_DBG("User in given uri is not local.\n");
		auth_dbf.free_result(auth_db_handle, dbres);
		return ERR_USERNOTFOUND;
	}

	/* if more than one matching db entry is found, there is either a 
	 * duplicate or a wrong tuple in the database. or maybe just the 
	 * 'use_domain' parameter should be set. */
	if (RES_ROW_N(dbres) > 1) {
		LM_WARN("Multiple entries are matching the given uri. "
			"Consider setting the 'use_domain' param.");
	}

	LM_DBG("User in request uri does exist\n");

	/* in the case there is more than a single match, the above warning 
	 * is presented to the user. anyway we continue by just using the 
	 * first result row only. */
	dbres_row = RES_ROWS(dbres);

	/* check the datatypes of the results of the database query */
	if (ROW_VALUES(dbres_row)->type != DB_STRING) {
		LM_ERR("Database '%s' column is not of type string.",
			((str*) cols[0])->s);
		return ERR_DBUSE;
	}
	if ((ROW_VALUES(dbres_row)+1)->type != DB_STRING) {
		LM_ERR("Database '%s' column is not of type string.",
			((str*) cols[1])->s);
		return ERR_DBUSE;
	}

	/* set result parameters  */
	ret_authuser.s.s = (char*) VAL_STRING(ROW_VALUES(dbres_row));
	ret_authuser.s.len = strlen(ret_authuser.s.s);
	ret_authrealm.s.s = (char*) VAL_STRING(ROW_VALUES(dbres_row)+1);
	ret_authrealm.s.len = strlen(ret_authrealm.s.s);
	set_result_pv(_msg, AVP_VAL_STR, ret_authuser, _auth_user);
	set_result_pv(_msg, AVP_VAL_STR, ret_authrealm, _auth_realm);

	auth_dbf.free_result(auth_db_handle, dbres);

	return OK;
}



