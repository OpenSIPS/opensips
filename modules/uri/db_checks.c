/*
 * $Id: checks.c 5901 2009-07-21 07:45:05Z bogdan_iancu $
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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
#include "uri_mod.h"
#include "db_checks.h"

static db_con_t* db_handle = NULL;   /* Database connection handle */
static db_func_t uridb_dbf;

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
static inline int check_username(struct sip_msg* _m, struct sip_uri *_uri)
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
			update_stat(negative_checks, 1);
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

	/* If use_uri_table is set, use URI table to determine if Digest username
	 * and To/From username match. URI table is a table enumerating all allowed
	 * usernames for a single, thus a user can have several different usernames
	 * (which are different from digest username and it will still match)
	 */
	if (use_uri_table != 0) {
		keys[0] = &uridb_user_col;
		keys[1] = &uridb_domain_col;
		keys[2] = &uridb_uriuser_col;
		cols[0] = &uridb_user_col;

		/* The whole fields are type DB_STR, and not null */
		VAL_TYPE(vals) = VAL_TYPE(vals + 1) = VAL_TYPE(vals + 2) = DB_STR;
		VAL_NULL(vals) = VAL_NULL(vals + 1) = VAL_NULL(vals + 2) = 0;

		VAL_STR(vals) = c->digest.username.user;
		VAL_STR(vals + 1) = *GET_REALM(&c->digest);
		VAL_STR(vals + 2) = _uri->user;

		uridb_dbf.use_table(db_handle, &db_table);
		CON_PS_REFERENCE(db_handle) = &my_ps;

		if (uridb_dbf.query(db_handle, keys, 0, vals, cols, 3, 1, 0, &res) < 0)
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
			uridb_dbf.free_result(db_handle, res);
			update_stat(negative_checks, 1);
			return ERR_SPOOFEDUSER;
		} else {
			LM_DBG("From/To user '%.*s' and auth user match\n",
				   _uri->user.len, ZSW(_uri->user.s));
			uridb_dbf.free_result(db_handle, res);
			update_stat(positive_checks, 1);
			return OK;
		}
	} else {
		/* URI table not used, simply compare digest username and From/To
		 * username, the comparison is case insensitive
		 */
		if (_uri->user.len == c->digest.username.user.len) {
			if (!strncasecmp(_uri->user.s, c->digest.username.user.s,
			_uri->user.len)) {
				LM_DBG("Digest username and URI username match\n");
				update_stat(positive_checks, 1);
				return OK;
			}
		}

		LM_DBG("Digest username and URI username do NOT match\n");
		update_stat(negative_checks, 1);
		return ERR_NOMATCH;
	}
}


/*
 * Check username part in To header field
 */
int check_to(struct sip_msg* _m, char* _s1, char* _s2)
{
	if (!_m->to && ((parse_headers(_m, HDR_TO_F, 0) == -1) || (!_m->to))) {
		LM_ERR("Error while parsing To header field\n");
		return ERR_INTERNAL;
	}
	if(parse_to_uri(_m)==NULL) {
		LM_ERR("Error while parsing To header URI\n");
		return ERR_INTERNAL;
	}

	return check_username(_m, &get_to(_m)->parsed_uri);
}


/*
 * Check username part in From header field
 */
int check_from(struct sip_msg* _m, char* _s1, char* _s2)
{
	if (parse_from_header(_m) < 0) {
		LM_ERR("Error while parsing From header field\n");
		return ERR_INTERNAL;
	}
	if(parse_from_uri(_m)==NULL) {
		LM_ERR("Error while parsing From header URI\n");
		return ERR_INTERNAL;
	}

	return check_username(_m, &get_from(_m)->parsed_uri);
}


/*
 * Check if uri belongs to a local user
 */
int does_uri_exist(struct sip_msg* _msg, char* _s1, char* _s2)
{
	static db_ps_t my_ps = NULL;
	db_key_t keys[2];
	db_val_t vals[2];
	db_key_t cols[1];
	db_res_t* res = NULL;

	if (parse_sip_msg_uri(_msg) < 0) {
		LM_ERR("Error while parsing URI\n");
		return ERR_INTERNAL;
	}

	if (use_uri_table != 0) {
		uridb_dbf.use_table(db_handle, &db_table);
		keys[0] = &uridb_uriuser_col;
		keys[1] = &uridb_domain_col;
		cols[0] = &uridb_uriuser_col;
	} else {
		uridb_dbf.use_table(db_handle, &db_table);
		keys[0] = &uridb_user_col;
		keys[1] = &uridb_domain_col;
		cols[0] = &uridb_user_col;
	}

	VAL_TYPE(vals) = VAL_TYPE(vals + 1) = DB_STR;
	VAL_NULL(vals) = VAL_NULL(vals + 1) = 0;
	VAL_STR(vals) = _msg->parsed_uri.user;
	VAL_STR(vals + 1) = _msg->parsed_uri.host;

	CON_PS_REFERENCE(db_handle) = &my_ps;

	if (uridb_dbf.query(db_handle, keys, 0, vals, cols, (use_domain ? 2 : 1),
				1, 0, &res) < 0) {
		LM_ERR("Error while querying database\n");
		return ERR_USERNOTFOUND;
	}

	if (RES_ROW_N(res) == 0) {
		LM_DBG("User in request uri does not exist\n");
		uridb_dbf.free_result(db_handle, res);
		return ERR_DBEMTPYRES;
	} else {
		LM_DBG("User in request uri does exist\n");
		uridb_dbf.free_result(db_handle, res);
		return OK;
	}
}


/**
 * Retrieves authentication id and realm from uri_table for a given sip uri
 */
int get_auth_id(struct sip_msg* _msg, char* _uri, char* _auth_user, char* _auth_realm)
{
	str uri, sip_user, sip_domain;
	struct sip_uri sip_uri;
	int_str ret_authuser, ret_authrealm;
	static db_ps_t my_ps = NULL;
	db_key_t keys[2];
	db_val_t vals[2];
	db_key_t cols[2];
	db_res_t* dbres = NULL;
	db_row_t* dbres_row;


	// retrieve the string value of the given uri (pseudo variables will also be
	// already substituted with their proper values)
	if (_uri == NULL || pv_printf_s(_msg, (pv_elem_t *) _uri, &uri) != 0 ||
	uri.len == 0 || uri.s == NULL) {
		LM_WARN("cannot get string for value\n");
		return -1;
	}

	// check if we really have a valid uri as parameter
	// TODO: check Bug ID 2685700
	if (parse_uri(uri.s, strlen(uri.s), &sip_uri) < 0
			&& (sip_uri.user.s == NULL || sip_uri.user.len <= 0)) {
		LM_ERR("First parameter must be a URI (val = '%s').", uri.s);
		return -1;
	}

	// split uri into user and realm part
	sip_user.s = strtok(sip_uri.user.s, "@");
	sip_domain.s = strtok(NULL, "@");
	sip_user.len = strlen(sip_user.s);
	sip_domain.len = strlen(sip_domain.s);

	if (use_uri_table != 0) {
		uridb_dbf.use_table(db_handle, &db_table);
		keys[0] = &uridb_uriuser_col;
		keys[1] = &uridb_domain_col;
		cols[0] = &uridb_user_col;
		cols[1] = &uridb_domain_col;
	} else {
		uridb_dbf.use_table(db_handle, &db_table);
		keys[0] = &uridb_user_col;
		keys[1] = &uridb_domain_col;
		cols[0] = &uridb_user_col;
		cols[1] = &uridb_domain_col;
	}

	VAL_TYPE(vals) = DB_STR;
	VAL_NULL(vals) = 0;
	VAL_STR(vals) = sip_user;

	VAL_TYPE(vals + 1) = DB_STR;
	VAL_NULL(vals + 1) = 0;
	VAL_STR(vals + 1) = sip_domain;

	CON_PS_REFERENCE(db_handle) = &my_ps;

	// if use_domain is set also the domain column of the database table will
	// be honoured in the following query (see sixth parameter)
	if (uridb_dbf.query(db_handle, keys, 0, vals, cols, (use_domain ? 2 : 1), 2, 0, &dbres) < 0) {
		LM_ERR("Error while querying database");
		return ERR_DBQUERY;
	}

	if (RES_ROW_N(dbres) == 0) {
		LM_DBG("User in given uri is not local.");
		uridb_dbf.free_result(db_handle, dbres);
		return ERR_USERNOTFOUND;
	}

	// if more than one matching db entry is found, there is either a duplicate or a
	// wrong tuple in the database. or maybe just the 'use_domain' paramter should be set.
	if (RES_ROW_N(dbres) > 1) {
		LM_WARN("Multiple entries are matching the given uri. Consider setting the 'use_domain' param.");
	}

	LM_DBG("User in request uri does exist");

	// in the case there is more than a single match, the above warning is presented
	// to the user. anyway we continue by just using the first result row only.
	dbres_row = RES_ROWS(dbres);

	// check the datatypes of the results of the database query
	if (ROW_VALUES(dbres_row)->type != DB_STRING) {
		LM_ERR("Database '%s' column is not of type string.", ((str*) cols[0])->s);
		return ERR_DBUSE;
	}
	if ((ROW_VALUES(dbres_row)+1)->type != DB_STRING) {
		LM_ERR("Database '%s' column is not of type string.", ((str*) cols[1])->s);
		return ERR_DBUSE;
	}

	// set result parameters
	ret_authuser.s.s = (char*) VAL_STRING(ROW_VALUES(dbres_row));
	ret_authuser.s.len = strlen(ret_authuser.s.s);
	ret_authrealm.s.s = (char*) VAL_STRING(ROW_VALUES(dbres_row)+1);
	ret_authrealm.s.len = strlen(ret_authrealm.s.s);
	set_result_pv(_msg, AVP_VAL_STR, ret_authuser, _auth_user);
	set_result_pv(_msg, AVP_VAL_STR, ret_authrealm, _auth_realm);

	uridb_dbf.free_result(db_handle, dbres);

	return OK;
}


/**
 * Set result pvs
 */
int set_result_pv(struct sip_msg* _msg, unsigned short _avp_type, int_str _avp_val, char* _res_avp)
{
	pv_spec_t* _avp = (pv_spec_t*) _res_avp;
	int avp_name;
	unsigned short avp_type;


	switch (_avp->type) {
		case PVT_AVP:
			if (pv_get_avp_name(_msg, &(_avp->pvp), &avp_name, &avp_type) != 0) {
				LM_CRIT("BUG in getting AVP name");
				return -1;
			}

			avp_type |= _avp_type;

			if (add_avp(avp_type, avp_name, _avp_val) < 0) {
				LM_ERR("cannot add AVP");
				return -1;
			}
			break;

		case PVT_SCRIPTVAR:
			if(_avp->pvp.pvn.u.dname == 0){
				LM_ERR("cannot find svar name");
				return -1;
			}

			if (!set_var_value((script_var_t*) _avp->pvp.pvn.u.dname, &_avp_val, VAR_VAL_STR)) {
				LM_ERR("cannot set svar");
				return -1;
			}
			break;

		default:
			LM_CRIT("BUG: invalid pvar type");
			return -1;
	}

	return OK;
}


int uridb_db_init(const str* db_url)
{
	if (uridb_dbf.init==0){
		LM_CRIT("BUG: null dbf\n");
		return -1;
	}

	db_handle=uridb_dbf.init(db_url);
	if (db_handle==NULL){
		LM_ERR("unable to connect to the database\n");
		return -1;
	}
	return 0;
}



int uridb_db_bind(const str* db_url)
{
	if (db_bind_mod(db_url, &uridb_dbf)<0){
		LM_ERR("unable to bind to the database module\n");
		return -1;
	}

	if (!DB_CAPABILITY(uridb_dbf, DB_CAP_QUERY)) {
		LM_ERR("Database module does not implement the 'query' function\n");
		return -1;
	}

	return 0;
}


void uridb_db_close(void)
{
	if (db_handle != NULL && uridb_dbf.close != 0){
		uridb_dbf.close(db_handle);
		db_handle=NULL;
	}
}
