/*
 * presence module -presence server implementation
 *
 * Copyright (C) 2006 Voice Sistem S.R.L.
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
 *  2006-08-15  initial version (Anca Vamanu)
 *  2010-10-19  support for extra headers (osas)
 */

#include "../../str.h"
#include "../tm/dlg.h"
#include "subscribe.h"
#include "presentity.h"

#ifndef NOTIFY_H
#define NOTIFY_H

#define FULL_STATE_FLAG (1<<0)
#define PARTIAL_STATE_FLAG (1<<1)

#define PRES_LEN 8
#define PWINFO_LEN 14
#define BLA_LEN 10

#define FAKED_BODY   ((str *) -1)


typedef struct watcher
{
	str uri;
	str id;
	int status;
	str display_name;
	str expiration;
	str duration_subscribed;
	struct watcher* next;
}watcher_t;

typedef struct wid_cback
{
	str pres_uri;
	str ev_name;
	str to_tag;   /* to identify the exact record */
}c_back_param;

extern str str_to_user_col;
extern str str_username_col;
extern str str_domain_col;
extern str str_body_col;
extern str str_extra_hdrs_col;
extern str str_to_domain_col;
extern str str_watcher_username_col;
extern str str_watcher_domain_col;
extern str str_event_id_col;
extern str str_event_col;
extern str str_etag_col;
extern str str_from_tag_col;
extern str str_to_tag_col;
extern str str_callid_col;
extern str str_local_cseq_col;
extern str str_remote_cseq_col;
extern str str_record_route_col;
extern str str_contact_col;
extern str str_expires_col;
extern str str_status_col;
extern str str_reason_col;
extern str str_socket_info_col;
extern str str_local_contact_col;
extern str str_sharing_tag_col;
extern str str_version_col;
extern str str_presentity_uri_col;
extern str str_inserted_time_col;
extern str str_received_time_col;
extern str str_id_col;
extern str str_sender_col;

void PRINT_DLG(FILE* out, dlg_t* _d);

void printf_subs(subs_t* subs);

int query_db_notify(str* pres_uri,pres_ev_t* event, subs_t* watcher_subs );

int publ_notify(presentity_t* p, str pres_uri, str* body, str* offline_etag,
		str* rules_doc, str* dialog_publish, int from_publish, str **sh_tags);

int virtual_notify(str *pres_uri, pres_ev_t *ev, str *body);

int notify(subs_t* subs, subs_t* watcher_subs, str* n_body,
		int force_null_body, str* extra_hdrs, int from_publish);

int send_notify_request(subs_t* subs, subs_t * watcher_subs,
		str* n_body,int force_null_body, str* extra_hdrs, int from_publish);

char* get_status_str(int flag);
void free_watcher_list(watcher_t* w);
int add_watcher_list(subs_t* s, watcher_t* watchers);
subs_t* get_subs_dialog(str* pres_uri, pres_ev_t* event,
	str* sender, str **sh_tag);

int presentity_has_subscribers(str* pres_uri, pres_ev_t* event);

db_res_t* pres_search_db(struct sip_uri* uri,str* ev_name, int* body_col,
		int* extra_hdrs_col, int* expires_col, int* etag_col);

str* create_winfo_xml(watcher_t* watchers, char* version,
		str resource, str event, int STATE_FLAG );
str* xml_dialog2presence(str* pres_uri, str* body);
str* build_offline_presence(str* pres_uri);

#endif
