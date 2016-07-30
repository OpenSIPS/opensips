/*
 * rls module - resource list server
 *
 * Copyright (C) 2007 Voice Sistem S.R.L.
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
 *  2007-09-11  initial version (Anca Vamanu)
 */

#ifndef _RLS_H_
#define _RLS_H_

#include "../../str.h"
#include "../xcap/api.h"
#include "../xcap_client/xcap_functions.h"
#include "../pua/send_subscribe.h"
#include "../pua/send_publish.h"
#include "../pua/pidf.h"
#include "../presence/hash.h"
#include "../presence/event_list.h"
#include "../signaling/signaling.h"
#include "../../db/db_con.h"
#include "../../db/db.h"

#define NO_UPDATE_TYPE     -1
#define UPDATED_TYPE        1

#define NOT_KNOWN_STATE     0
#define ACTIVE_STATE        1<<1
#define PENDING_STATE       1<<2
#define TERMINATED_STATE    1<<3

typedef struct dialog_id
{
	str callid;
	str to_tag;
	str from_tag;

}dialog_id_t;

/*
	rls_presentity table structure:

	- LIST URI       (string)
	- presentity URI (string)
	- presence state (string)
	/-- the following ones needed when updating in db on timer --/
	- auth_state     (int)
	- reason		 (string)
	- updated        (int)
*/
typedef struct rls_resource
{
	str pres_uri;
	int auth_state;
	str reason;
	int updated;
	str* instance_id;
	str* cid;
	struct rls_resource* next;
	/* the last 2 parameters say if a query in database is needed */
}rls_res_t;


extern char* xcap_root;
extern unsigned int xcap_port;
extern str server_address;
extern str presence_server;
extern int waitn_time;
extern str rlsubs_table;
extern str rlpres_table;
extern int hash_size;
extern shtable_t rls_table;
extern int pid;
extern int rls_max_expires;
extern int rls_events;
extern int to_presence_code;

/* database connection */
extern db_con_t *rls_db;
extern db_func_t rls_dbf;

extern struct tm_binds tmb;
extern struct sig_binds rls_sigb;

/* xcap API */
extern str db_url;
extern str rls_xcap_table;
extern int rls_integrated_xcap_server;
extern normalize_sip_uri_t normalizeSipUri;
extern parse_xcap_uri_t xcapParseUri;
extern get_xcap_doc_t xcapDbGetDoc;

/** libxml api */
extern xmlDocGetNodeByName_t XMLDocGetNodeByName;
extern xmlNodeGetNodeByName_t XMLNodeGetNodeByName;
extern xmlNodeGetNodeContentByName_t XMLNodeGetNodeContentByName;
extern xmlNodeGetAttrContentByName_t XMLNodeGetAttrContentByName;

/* functions imported from presence to handle subscribe hash table */
extern new_shtable_t pres_new_shtable;
extern insert_shtable_t pres_insert_shtable;
extern search_shtable_t pres_search_shtable;
extern update_shtable_t pres_update_shtable;
extern delete_shtable_t pres_delete_shtable;
extern destroy_shtable_t pres_destroy_shtable;
extern mem_copy_subs_t  pres_copy_subs;
extern extract_sdialog_info_t pres_extract_sdialog_info;

/* functions imported from pua module*/
extern send_subscribe_t pua_send_subscribe;
extern get_record_id_t pua_get_record_id;
extern get_subs_list_t pua_get_subs_list;

/* functions imported from presence module */
extern contains_event_t pres_contains_event;
extern search_event_t pres_search_event;
extern get_event_list_t pres_get_ev_list;

/* xcap client functions */
extern xcapGetNewDoc_t xcap_GetNewDoc;

extern str str_rlsubs_did_col;
extern str str_resource_uri_col;
extern str str_updated_col;
extern str str_auth_state_col;
extern str str_reason_col;
extern str str_content_type_col;
extern str str_presence_state_col;
extern str str_expires_col;
extern str str_presentity_uri_col;
extern str str_event_col;
extern str str_event_id_col;
extern str str_to_user_col;
extern str str_to_domain_col;
extern str str_watcher_username_col;
extern str str_watcher_domain_col;
extern str str_callid_col;
extern str str_to_tag_col;
extern str str_from_tag_col;
extern str str_local_cseq_col;
extern str str_remote_cseq_col;
extern str str_record_route_col;
extern str str_socket_info_col;
extern str str_contact_col;
extern str str_local_contact_col;
extern str str_version_col;
extern str str_status_col;
extern str str_username_col;
extern str str_domain_col;
extern str str_doc_type_col;
extern str str_etag_col;
extern str str_doc_col;
extern str str_doc_uri_col;

#define DID_SEP_LEN   strlen(DID_SEP)
#define DID_SEP       ";"
#define DID_INIT_LEN  (2* sizeof(DID_SEP))

/* did_str= *callid*DID_SEP*from_tag*DID_SEP*to_tag* */
#define MAX_DID_LEN    255 /* not to exceed db field length */

static inline int CONSTR_RLSUBS_DID(subs_t* subs, str *did)
{
	int len;

	len= (DID_INIT_LEN+ subs->callid.len+ subs->to_tag.len+
			subs->from_tag.len+ 10)* sizeof(char);
	if(len > MAX_DID_LEN)
	{
		LM_ERR("Max length exceeded [%d]\n", len);
		return -1;
	}
	did->s= (char*)pkg_malloc(len);
	if(did->s== NULL)
	{
		ERR_MEM(PKG_MEM_STR);
	}

	did->len= sprintf(did->s, "%.*s%s%.*s%s%.*s", subs->callid.len,
			subs->callid.s, DID_SEP,subs->from_tag.len, subs->from_tag.s,
			DID_SEP, subs->to_tag.len, subs->to_tag.s);

	if(did->len>= len)
	{
		LM_ERR("ERROR buffer size overflown\n");
		pkg_free(did->s);
		return -1;
	}
	did->s[did->len]= '\0';

	LM_DBG("did= %s\n", did->s);
	return 0;
error:
	return -1;
}

#endif
