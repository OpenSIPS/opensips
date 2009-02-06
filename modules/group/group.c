/*
 * $Id$
 *
 * Group membership
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 * 2003-02-25 - created by janakj
 * 2004-06-07   updated to the new DB api, added group_db_{bind,init,close,ver}
 *               (andrei)
 * 2008-12-26 - pseudovariable argument for group parameter at is_user_in (saguti).
 *
 */


#include <string.h>
#include "../../dprint.h"               /* Logging */
#include "../../db/db.h"                /* Generic database API */
#include "../../ut.h"
#include "../../parser/digest/digest.h" /* get_authorized_cred */
#include "../../parser/hf.h"            /* Header Field types */
#include "../../parser/parse_from.h"    /* From parser */
#include "../../parser/parse_uri.h"
#include "../../mod_fix.h"
#include "group.h"
#include "group_mod.h"                   /* Module parameters */

static group_check_p get_hf( char *str1);

int get_username_domain(struct sip_msg *msg, group_check_p gcp,
											str *username, str *domain)
{
	struct sip_uri puri;
	struct sip_uri *turi;
	struct hdr_field* h;
	struct auth_body* c = 0; /* Makes gcc happy */
	pv_value_t value;

	turi = NULL;

	switch(gcp->id) {
		case 1: /* Request-URI */
			if(parse_sip_msg_uri(msg)<0) {
				LM_ERR("failed to get Request-URI\n");
				return -1;
			}
			turi = &msg->parsed_uri;
			break;

		case 2: /* To */
			if((turi=parse_to_uri(msg))==NULL) {
				LM_ERR("failed to get To URI\n");
				return -1;
			}
			break;

		case 3: /* From */
			if((turi=parse_from_uri(msg))==NULL) {
				LM_ERR("failed to get From URI\n");
				return -1;
			}
			break;

		case 4: /* Credentials */
			get_authorized_cred( msg->authorization, &h);
			if (!h) {
				get_authorized_cred( msg->proxy_auth, &h);
				if (!h) {
					LM_ERR("no authorized credentials found "
							"(error in scripts)\n");
					return -1;
				}
			}
			c = (auth_body_t*)(h->parsed);
			break;

		case 5: /* AVP spec */
			if(pv_get_spec_value( msg, &gcp->sp, &value)!=0 
				|| value.flags&PV_VAL_NULL || value.rs.len<=0)
			{
				LM_ERR("no AVP found (error in scripts)\n");
				return -1;
			}
			if (parse_uri(value.rs.s, value.rs.len, &puri) < 0) {
				LM_ERR("failed to parse URI <%.*s>\n",value.rs.len, value.rs.s);
				return -1;
			}
			turi = &puri;
			break;
	}

	if (gcp->id != 4) {
		*username = turi->user;
		*domain = turi->host;
	} else {
		*username = c->digest.username.user;
		*domain = *(GET_REALM(&c->digest));
	}
	return 0;
}



/*
 * Check if username in specified header field is in a table
 */
int is_user_in(struct sip_msg* _msg, char* _hf, char* _grp)
{
	static db_ps_t my_ps = NULL;
	db_key_t keys[3];
	db_val_t vals[3];
	db_key_t col[1];
	db_res_t* res = NULL;

	keys[0] = &user_column;
	keys[1] = &group_column;
	keys[2] = &domain_column;
	col[0]  = &group_column;

	str hf_s = { NULL, 0 };
	str grp_s = { NULL, 0 };

	if(_hf ==  NULL || fixup_get_svalue(_msg, (gparam_p)_hf, &hf_s) != 0) {
		LM_ERR("Invalid parameter URI\n");
		return -1;
	}

	if(_grp == NULL || fixup_get_svalue(_msg, (gparam_p)_grp, &grp_s) != 0) {
		LM_ERR("Invalid parameter grp\n");
		return -1;
	}

	group_check_p hfPtr = get_hf(hf_s.s);
	if (hfPtr==NULL) {
		LM_ERR("unable to get user/dom source\n");
		return -1;
	}

	if ( get_username_domain( _msg, hfPtr, &(VAL_STR(vals)),
	&(VAL_STR(vals+2)))!=0) {
		LM_ERR("failed to get username@domain\n");
		return -1;
	}

	if (VAL_STR(vals).s==NULL || VAL_STR(vals).len==0 ) {
		LM_DBG("no username part\n");
		return -1;
	}

	VAL_TYPE(vals) = VAL_TYPE(vals + 1) = VAL_TYPE(vals + 2) = DB_STR;
	VAL_NULL(vals) = VAL_NULL(vals + 1) = VAL_NULL(vals + 2) = 0;

	VAL_STR(vals + 1) = *(&grp_s);

	group_dbf.use_table(group_dbh, &table);
	CON_PS_REFERENCE(group_dbh) = &my_ps;

	if (group_dbf.query(group_dbh, keys, 0, vals, col, (use_domain) ? (3): (2),
				1, 0, &res) < 0) {
		LM_ERR("failed to query database\n");
		return -5;
	}

	if (RES_ROW_N(res) == 0) {
		LM_DBG("user is not in group '%.*s'\n", 
		    (grp_s.len), ZSW((grp_s.s)));
		group_dbf.free_result(group_dbh, res);
		return -6;
	} else {
		LM_DBG("user is in group '%.*s'\n", 
			(grp_s.len), ZSW((grp_s.s)));
		group_dbf.free_result(group_dbh, res);
		return 1;
	}
}


int group_db_init(const str* db_url)
{
	if (group_dbf.init==0){
		LM_CRIT("null dbf \n");
		goto error;
	}
	group_dbh=group_dbf.init(db_url);
	if (group_dbh==0){
		LM_ERR("unable to connect to the database\n");
		goto error;
	}
	return 0;
error:
	return -1;
}


int group_db_bind(const str* db_url)
{
	if (db_bind_mod(db_url, &group_dbf)<0){
		LM_ERR("unable to bind to the database module\n");
		return -1;
	}

	if (!DB_CAPABILITY(group_dbf, DB_CAP_QUERY)) {
		LM_ERR("database module does not implement 'query' function\n");
		return -1;
	}

	return 0;
}


void group_db_close(void)
{
	if (group_dbh && group_dbf.close){
		group_dbf.close(group_dbh);
		group_dbh=0;
	}
}

/*
 *  * Convert HF description string to hdr_field pointer
 *  *                                                   
 *  * Supported strings:                                
 *  * "Request-URI", "To", "From", "Credentials"        
 *  * It is a copy from get_hf at group_mod.c     
*/
static group_check_p get_hf( char *str1)
{
	group_check_p gcp=NULL;
	str s;

	gcp = (group_check_p)pkg_malloc(sizeof(group_check_t));
	if(gcp == NULL) {
		LM_ERR("no pkg more memory\n");
		return NULL;
	}
	memset(gcp, 0, sizeof(group_check_t));

	if (!strcasecmp( str1, "Request-URI")) {
		gcp->id = 1;
	} else if (!strcasecmp( str1, "To")) {
		gcp->id = 2;
	} else if (!strcasecmp( str1, "From")) {
		gcp->id = 3;
	} else if (!strcasecmp( str1, "Credentials")) {
		gcp->id = 4;
	} else {
		s.s = str1; s.len = strlen(s.s);
		if(pv_parse_spec( &s, &gcp->sp)==NULL || gcp->sp.type!=PVT_AVP)
		{
			LM_ERR("unsupported User Field identifier\n");
			pkg_free( gcp );
			return NULL;
		}
		gcp->id = 5;
	}

	/* do not free all the time, needed by pseudo-variable spec */
	if(gcp->id!=5)
		pkg_free(str1);

	return gcp;
}
