/*
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
 * 2009-02-07 Initial version of closeddial module (saguti)
 */


#include <string.h>

#include "../../dprint.h"
#include "../../action.h"
#include "../../config.h"
#include "../../ut.h"
#include "../../mod_fix.h"
#include "../../parser/parse_uri.h"
#include "../../parser/parse_from.h"
#include "../../db/db.h"

#include "closeddial.h"
#include "cdlookup.h"

#define MAX_USERURI_SIZE	256
static char useruri_buf[MAX_USERURI_SIZE];

/* Global variable where table name will be stored */
str table_s = {NULL, 0};

/* Internal function which returns the group_id of from user */
str _get_group(struct sip_uri *user);

/**
 * cd_lookup tries to find a corresponding uri in the database,
 * given the group which from user belongs to, and the abbreviated
 * dial in original R-URI.
 * Returns:
 * -1: In case of any error.
 *  0: If R-URI is left unchanged.
 *  1: If a match was found and R-URI was changed.
 */
int cd_lookup(struct sip_msg* _msg, char* _table, char* _group)
{
	/* Variable to hold the group returned by _get_group() */
	str group = {NULL, 0};

	/* Variable to hold the result from query */
	str user_s;

	/* Index of keys which will be used on query */
	int key_count=0;

	/* Query to execute: select new_uri from closeddial
 	 * where cd_username='username' and group='group'
 	 * [ and domain='domain' ]
 	 */

	struct sip_uri *from_uri = NULL;

	db_key_t colsToCompare[3];
	db_val_t valsToMatch[3];
	db_key_t colsToReturn[1];
	db_res_t* result = NULL;
	static db_ps_t my_ps = NULL;

	if(_table==NULL || fixup_get_svalue(_msg, (gparam_p)_table, &table_s)!=0) {
		LM_ERR("Invalid table parameter");
		return -1;
	}

	/* take username@domain from From header */
	if ( (from_uri = parse_from_uri(_msg ))==NULL ) {
		LM_ERR("Failed to parse FROM header\n");
		return -1;
	}

	/* If group was not passed from script, tries to find it on database */
	if(_group == NULL) {
		group=_get_group(from_uri);
	}
	else {
		if(fixup_get_svalue(_msg, (gparam_p)_group, &group) != 0) {
			LM_ERR("Invalid group parameter");
			return -1;
		}
	}

	/* In case of failure in _get_group, len field is set to -1  */
	if(group.len == -1) {
		return -1;
	}

	/* No group_id found; keeps uri */
	if(group.len == 0) {
		return -2;
	}

	/* ... where cd_username ... */
	colsToCompare[0]=&cd_user_column;

	/* ... and group_id ... */
	colsToCompare[1]=&group_id_column;

	if(parse_sip_msg_uri(_msg) < 0){
		return -1;
	}

	/* The request uri parsed */
	valsToMatch[key_count].type=DB_STR;
	valsToMatch[key_count].nul=0;
	valsToMatch[key_count].val.str_val.s=_msg->parsed_uri.user.s;
	valsToMatch[key_count].val.str_val.len=_msg->parsed_uri.user.len;
	key_count++;

	/* The group_id as returned previously or taken from script*/
	valsToMatch[key_count].type=DB_STR;
	valsToMatch[key_count].nul=0;
	valsToMatch[key_count].val.str_val.s=group.s;
	valsToMatch[key_count].val.str_val.len=group.len;
	key_count++;

	if(use_domain > 0) {
		/* ... and domain= ... */
		colsToCompare[key_count]=&domain_column;

		/* domain as taken from host in from_uri */
		valsToMatch[key_count].type=DB_STR;
		valsToMatch[key_count].nul=0;
		valsToMatch[key_count].val.str_val.s=from_uri->host.s;
		valsToMatch[key_count].val.str_val.len=from_uri->host.len;
		key_count++;
	}

	colsToReturn[0]=&new_uri_column;

	if(db_functions.use_table(db_connection, &table_s) < 0) {
		LM_ERR("Error trying to use table %s\n", table_s.s);
		return -1;
	}

	CON_PS_REFERENCE(db_connection) = &my_ps;

	if(db_functions.query(db_connection, colsToCompare, NULL, valsToMatch, colsToReturn,
		key_count, 1 /* Columns to return */, NULL, &result)!=0) {

		LM_ERR("failed to query database\n");
		return -1;
	}

	if (RES_ROW_N(result)<=0 || RES_ROWS(result)[0].values[0].nul != 0) {
		LM_DBG("No sip address found for R-URI\n");

		/* Tries to free result */
		if(result != NULL) {
			if(db_functions.free_result(db_connection, result) < 0) {
				LM_DBG("Failed to free_result\n");

			}
		}

		return -1;
	}

	user_s.s = useruri_buf+4;
	switch(RES_ROWS(result)[0].values[0].type)
	{
		case DB_STRING:
			strcpy(user_s.s,
				(char*)RES_ROWS(result)[0].values[0].val.string_val);
			user_s.len = strlen(user_s.s);
		break;
		case DB_STR:
			strncpy(user_s.s,
				(char*)RES_ROWS(result)[0].values[0].val.str_val.s,
				RES_ROWS(result)[0].values[0].val.str_val.len);
			user_s.len = RES_ROWS(result)[0].values[0].val.str_val.len;
			user_s.s[user_s.len] = '\0';
		break;
		case DB_BLOB:
			strncpy(user_s.s,
				(char*)RES_ROWS(result)[0].values[0].val.blob_val.s,
				RES_ROWS(result)[0].values[0].val.blob_val.len);
			user_s.len = RES_ROWS(result)[0].values[0].val.blob_val.len;
			user_s.s[user_s.len] = '\0';
		default:
			LM_ERR("unknown type of DB new_uri column\n");
			if (result != NULL && db_functions.free_result(db_connection, result) < 0)
			{
				LM_DBG("failed to free result of query\n");
			}
			return -1;
	}

	/* check 'sip:' */
	if(user_s.len<4 || strncasecmp(user_s.s, "sip:", 4))
	{
		memcpy(useruri_buf, "sip:", 4);
		user_s.s -= 4;
		user_s.len += 4;
	}

	/**
	 * Free the result because it is not longer needed
	 */
	if (result!=NULL && db_functions.free_result(db_connection, result) < 0)
		LM_DBG("failed to free result of query\n");

	/* set the URI */
	LM_DBG("URI of cd from R-URI [%.*s]\n", user_s.len,user_s.s);
	if(set_ruri(_msg, &user_s)<0)
	{
		LM_ERR("failed to replace the R-URI\n");
		return -1;
	}

	return 1;
}

/*
 * Internal function which is used to return user group from database
 * when it is not passwd from script.
 * Returns a str struct; in case of any error, len member of struct
 * is set to -1.
 */
str _get_group(struct sip_uri *from_uri)
{
	str returnValue = {NULL, 0};
	db_res_t *result = NULL;
	static db_ps_t my_ps = NULL;

	/* Query to exec is:
	 * select group_id from closeddial where username='value'
	 */

	db_key_t colsToCompare[1];
	db_val_t valsToMatch[1];
	db_key_t colsToReturn[1];

	/* where username... */
	colsToCompare[0]=&user_column;

	/* username=? */
	valsToMatch[0].type=DB_STR;
	valsToMatch[0].nul=0;
	valsToMatch[0].val.str_val.s=from_uri->user.s;
	valsToMatch[0].val.str_val.len=from_uri->user.len;

	/* select group_id from ... */
	colsToReturn[0]=&group_id_column;

	if(db_use_table(db_connection, &table_s) != 0) {
		LM_ERR("Error using table %s\n", table_s.s);
		returnValue.len=-1;
		return returnValue;
	}

	CON_PS_REFERENCE(db_connection) = &my_ps;

	db_functions.query(db_connection, colsToCompare, NULL, valsToMatch, colsToReturn,
				1, 1, NULL, &result);


	if(result == NULL) {
		LM_ERR("Error executing query\n");
		returnValue.len=-1;
		return returnValue;
	}

	if(RES_ROW_N(result) == 0) {
		LM_DBG("No group_id for username %s\n", from_uri->user.s);
	}
	else {

		switch(RES_ROWS(result)[0].values[0].type) {
			case DB_STRING:
				returnValue.s = (char*)RES_ROWS(result)[0].values[0].val.string_val;
				returnValue.len = strlen(returnValue.s);
				break;

			case DB_STR:
				returnValue.s=(char*)RES_ROWS(result)[0].values[0].val.str_val.s;
				returnValue.len=strlen(returnValue.s);
				break;

			default:
				LM_ERR("Unknown type of DB new_uri column\n");
				returnValue.len=-1;
		}
	}

	if(result != NULL) {
		db_functions.free_result(db_connection, result);
	}

	return returnValue;
}
