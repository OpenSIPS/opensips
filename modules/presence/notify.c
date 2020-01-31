/*
 * presence module- presence server implementation
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libxml/parser.h>

#include "../../trim.h"
#include "../../ut.h"
#include "../../globals.h"
#include "../../str.h"
#include "../../db/db.h"
#include "../../db/db_val.h"
#include "../../socket_info.h"
#include "../tm/tm_load.h"
#include "../pua/hash.h"
#include "presentity.h"
#include "presence.h"
#include "notify.h"
#include "utils_func.h"
#include "clustering.h"

#define MAX_FORWARD 70

c_back_param* shm_dup_cbparam(subs_t*);
void free_cbparam(c_back_param* cb_param);

void p_tm_callback( struct cell *t, int type, struct tmcb_params *ps);
int add_waiting_watchers(watcher_t* watchers, str pres_uri, str event);

str str_to_user_col = str_init("to_user");
str str_username_col = str_init("username");
str str_domain_col = str_init("domain");
str str_body_col = str_init("body");
str str_extra_hdrs_col = str_init("extra_hdrs");
str str_to_domain_col = str_init("to_domain");
str str_watcher_username_col = str_init("watcher_username");
str str_watcher_domain_col = str_init("watcher_domain");
str str_event_id_col = str_init("event_id");
str str_event_col = str_init("event");
str str_etag_col = str_init("etag");
str str_from_tag_col = str_init("from_tag");
str str_to_tag_col = str_init("to_tag");
str str_callid_col = str_init("callid");
str str_local_cseq_col = str_init("local_cseq");
str str_remote_cseq_col = str_init("remote_cseq");
str str_record_route_col = str_init("record_route");
str str_contact_col = str_init("contact");
str str_expires_col = str_init("expires");
str str_status_col = str_init("status");
str str_reason_col = str_init("reason");
str str_socket_info_col = str_init("socket_info");
str str_local_contact_col = str_init("local_contact");
str str_sharing_tag_col = str_init("sharing_tag");
str str_version_col = str_init("version");
str str_presentity_uri_col = str_init("presentity_uri");
str str_inserted_time_col = str_init("inserted_time");
str str_received_time_col = str_init("received_time");
str str_id_col = str_init("id");
str str_sender_col = str_init("sender");

char* get_status_str(int status_flag)
{
	switch(status_flag)
	{
		case ACTIVE_STATUS: return "active";
		case PENDING_STATUS: return "pending";
		case TERMINATED_STATUS: return "terminated";
		case WAITING_STATUS: return "waiting";

	}
	return NULL;
}

static void pkg_free_w(char* s)
{
	pkg_free(s);
}

inline void printf_subs(subs_t* subs)
{
	LM_DBG("\n\t[pres_uri]= %.*s\n\t[to_user]= %.*s\t[to_domain]= %.*s"
		"\n\t[w_user]= %.*s\t[w_domain]= %.*s\n\t[event]= %.*s\n\t[status]= %s"
		"\n\t[expires]= %u\n\t[callid]= %.*s\t[local_cseq]=%d"
		"\n\t[to_tag]= %.*s\t[from_tag]= %.*s""\n\t[contact]= %.*s"
		"\t[record_route]= %.*s\n",subs->pres_uri.len,subs->pres_uri.s,
		subs->to_user.len,subs->to_user.s,subs->to_domain.len,
		subs->to_domain.s,subs->from_user.len,subs->from_user.s,
		subs->from_domain.len,subs->from_domain.s,subs->event->name.len,
		subs->event->name.s,get_status_str(subs->status),subs->expires,
		subs->callid.len,subs->callid.s,subs->local_cseq,subs->to_tag.len,
		subs->to_tag.s,subs->from_tag.len, subs->from_tag.s,subs->contact.len,
		subs->contact.s,subs->record_route.len,subs->record_route.s);
}

int build_str_hdr(subs_t* subs, int is_body, str* hdr, str *ct_body,
															str* extra_hdrs)
{
	int len = 0;
	int extra_len = 0;
	int lexpire_len;
	char* lexpire_s;
	char* p;
	str status;
	int lexpire;

	if(hdr == NULL)
	{
		LM_ERR("NULL pointer\n");
		return -1;
	}
	lexpire = subs->expires - expires_offset;
	if(lexpire < 0 )
		lexpire = 0;

	lexpire_s = int2str(lexpire, &lexpire_len);

	status.s= get_status_str(subs->status);
	if(status.s== NULL)
	{
		LM_ERR("bad status flag= %d\n", subs->status);
		pkg_free(hdr->s);
		return -1;
	}
	status.len = strlen(status.s);

	len = 7 /*Event: */ + subs->event->name.len + 4 /*;id=*/ +
		subs->event_id.len + CRLF_LEN +
		10 /*Contact: <*/ + subs->local_contact.len + 1/*>*/ + CRLF_LEN +
		20 /*Subscription-State: */ +
		status.len + ((subs->status== TERMINATED_STATUS)?(10/*;reason=*/+
		subs->reason.len):9/*expires=*/ + lexpire_len) + CRLF_LEN +
		(is_body ? (14 /*Content-Type: */+
			(ct_body->len?ct_body->len:subs->event->content_type.len)+CRLF_LEN):0);

	if(extra_hdrs && extra_hdrs->s && extra_hdrs->len)
		extra_len = extra_hdrs->len;

	hdr->s = (char*)pkg_malloc(extra_len + len);
	if(hdr->s== NULL)
	{
		LM_ERR("while allocating memory\n");
		return -1;
	}

	p = hdr->s;

	if (extra_len)
	{
		memcpy(p, extra_hdrs->s, extra_len);
		p+= extra_hdrs->len;
	}

	memcpy(p ,"Event: ", 7);
	p+= 7;
	memcpy(p, subs->event->name.s, subs->event->name.len);
	p+= subs->event->name.len;
	if(subs->event_id.len && subs->event_id.s)
	{
 		memcpy(p, ";id=", 4);
 		p += 4;
 		memcpy(p, subs->event_id.s, subs->event_id.len);
 		p += subs->event_id.len;
 	}

	memcpy(p ,CRLF "Contact: <", CRLF_LEN+10);
	p += CRLF_LEN+10;
	memcpy(p, subs->local_contact.s, subs->local_contact.len);
	p +=  subs->local_contact.len;

	memcpy(p, ">" CRLF "Subscription-State: " , 1+CRLF_LEN+20);
	p += 1+CRLF_LEN+20;

	memcpy(p, status.s, status.len);
	p += status.len;

	if(subs->status== TERMINATED_STATUS)
	{
		LM_DBG("state = terminated\n");
		memcpy(p,";reason=", 8);
		p+= 8;
		memcpy(p, subs->reason.s ,subs->reason.len );
		p+= subs->reason.len;
		memcpy(p, CRLF, CRLF_LEN);
		p+= CRLF_LEN;
	}
	else
	{
		memcpy(p,";expires=", 9);
		p += 9;
		memcpy(p, lexpire_s ,lexpire_len );
		p += lexpire_len;
		memcpy(p, CRLF, CRLF_LEN);
		p += CRLF_LEN;
	}

	if (!ct_body->len &&
		subs->event->content_type.s && subs->event->content_type.len)
		ct_body = &subs->event->content_type;

	if(is_body && ct_body->len)
	{
		memcpy(p,"Content-Type: ", 14);
		p += 14;
		memcpy(p, ct_body->s , ct_body->len);
		p += ct_body->len;
		memcpy(p, CRLF, CRLF_LEN);
		p += CRLF_LEN;
	}

	hdr->len = p - hdr->s;

	return 0;
}

int get_wi_subs_db(subs_t* subs, watcher_t* watchers)
{
//	static db_ps_t my_ps = NULL;
	db_key_t query_cols[6];
	db_op_t  query_ops[6];
	db_val_t query_vals[6];
	db_key_t result_cols[6];
	db_res_t *result = NULL;
	db_row_t *row = NULL ;
	db_val_t *row_vals = NULL;
	int n_result_cols = 0;
	int n_query_cols = 0;
	int i;
	int status_col, expires_col, from_user_col, from_domain_col, callid_col;
	subs_t s;

	query_cols[n_query_cols] = &str_presentity_uri_col;
	query_ops[n_query_cols] = OP_EQ;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val= subs->pres_uri;
	n_query_cols++;

	query_cols[n_query_cols] = &str_event_col;
	query_ops[n_query_cols] = OP_EQ;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = subs->event->wipeer->name;
	n_query_cols++;

	result_cols[status_col=n_result_cols++] = &str_status_col;
	result_cols[expires_col=n_result_cols++] = &str_expires_col;
	result_cols[from_user_col=n_result_cols++] = &str_watcher_username_col;
	result_cols[from_domain_col=n_result_cols++] = &str_watcher_domain_col;
	result_cols[callid_col=n_result_cols++] = &str_callid_col;

	if (pa_dbf.use_table(pa_db, &active_watchers_table) < 0)
	{
		LM_ERR("in use_table\n");
		goto error;
	}

//	CON_PS_REFERENCE(pa_db) = &my_ps;
	if (pa_dbf.query (pa_db, query_cols, query_ops, query_vals,
		 result_cols, n_query_cols, n_result_cols, 0,  &result) < 0)
	{
		LM_ERR("querying active_watchers db table\n");
		goto error;
	}

	if(result== NULL )
	{
		goto error;
	}

	if(result->n <= 0)
	{
		LM_DBG("The query in db table for active subscription"
				" returned no result\n");
		pa_dbf.free_result(pa_db, result);
		return 0;
	}

	for(i=0; i<result->n; i++)
	{
		row = &result->rows[i];
		row_vals = ROW_VALUES(row);

		s.from_user.s= (char*)row_vals[from_user_col].val.string_val;
		s.from_user.len= strlen(s.from_user.s);

		s.from_domain.s= (char*)row_vals[from_domain_col].val.string_val;
		s.from_domain.len= strlen(s.from_domain.s);

		s.callid.s= (char*)row_vals[callid_col].val.string_val;
		s.callid.len= strlen(s.callid.s);

		s.event =subs->event->wipeer;
		s.status= row_vals[status_col].val.int_val;

		if(add_watcher_list(&s, watchers) <0)
		{
			LM_ERR("failed to add watcher to list\n");
			goto error;
		}
	}

	pa_dbf.free_result(pa_db, result);
	return 0;

error:
	if(result)
		pa_dbf.free_result(pa_db, result);
	return -1;
}

str* get_wi_notify_body(subs_t* subs, subs_t* watcher_subs)
{
	str* notify_body = NULL;
	char* version_str;
	watcher_t *watchers = NULL;
	int len = 0;
	unsigned int hash_code;
	subs_t* s= NULL;
	int state = FULL_STATE_FLAG;

	hash_code = 0;
	version_str = int2str(subs->version, &len);
	if(version_str ==NULL)
	{
		LM_ERR("converting int to str\n");
		goto error;
	}

	watchers= (watcher_t*)pkg_malloc(sizeof(watcher_t));
	if(watchers== NULL)
	{
		ERR_MEM(PKG_MEM_STR);
	}
	memset(watchers, 0, sizeof(watcher_t));

	if(watcher_subs != NULL)
	{
		if(add_watcher_list(watcher_subs, watchers)< 0)
		{
			LM_ERR("failed to add watcher to list\n");
			goto error;
		}
		state = PARTIAL_STATE_FLAG;
		goto done;
	}

	if(fallback2db)
	{
		if(get_wi_subs_db(subs, watchers)< 0)
		{
			LM_ERR("getting watchers from database\n");
			goto error;
		}
	}

	hash_code= core_hash(&subs->pres_uri, &subs->event->wipeer->name,
            shtable_size);
	lock_get(&subs_htable[hash_code].lock);

	s= subs_htable[hash_code].entries;

    while(s->next)
	{
		s= s->next;

		if(s->expires< (int)time(NULL))
		{
			LM_DBG("expired record\n");
			continue;
		}

		if(fallback2db && s->db_flag!= INSERTDB_FLAG)
		{
			LM_DBG("record already found in database\n");
			continue;
		}

        if(s->event== subs->event->wipeer &&
			s->pres_uri.len== subs->pres_uri.len &&
			strncmp(s->pres_uri.s, subs->pres_uri.s,subs->pres_uri.len)== 0)
		{
			if(add_watcher_list(s, watchers)< 0)
			{
				LM_ERR("failed to add watcher to list\n");
				lock_release(&subs_htable[hash_code].lock);
				goto error;
			}
		}
	}

	if( add_waiting_watchers(watchers, subs->pres_uri,
				subs->event->wipeer->name)< 0 )
	{
		LM_ERR("failed to add waiting watchers\n");
		goto error;
	}

done:
	notify_body = create_winfo_xml(watchers,version_str,subs->pres_uri,
			subs->event->wipeer->name, state );

	if(watcher_subs == NULL)
		lock_release(&subs_htable[hash_code].lock);

	if(notify_body== NULL)
	{
		LM_ERR("in function create_winfo_xml\n");
		goto error;
	}
	free_watcher_list(watchers);
	return notify_body;

error:
	free_watcher_list(watchers);
	return NULL;
}

void free_watcher_list(watcher_t* watchers)
{
	watcher_t* w;

	while(watchers)
	{
		w= watchers;
		if(w->uri.s !=NULL)
			pkg_free(w->uri.s);
		if(w->id.s !=NULL)
			pkg_free(w->id.s);

		watchers= watchers->next;
		pkg_free(w);
	}
}


int add_watcher_list(subs_t* s, watcher_t* watchers)
{
	watcher_t* w;

	w= (watcher_t*)pkg_malloc(sizeof(watcher_t));
	if(w== NULL)
	{
		LM_ERR("No more private memory\n");
		return -1;
	}
	w->status= s->status;
	if(uandd_to_uri(s->from_user, s->from_domain, &w->uri)<0)
	{
		LM_ERR("failed to create uri\n");
		goto error;
	}
	w->id.s = (char*)pkg_malloc(s->callid.len+ 1);
	if(w->id.s == NULL)
	{
		LM_ERR("no more memory\n");
		goto error;
	}
	memcpy(w->id.s, s->callid.s, s->callid.len);
	w->id.len = s->callid.len;
	w->id.s[w->id.len] = '\0';

	w->next= watchers->next;
	watchers->next= w;

	return 0;

error:
	if(w)
	{
		if(w->uri.s)
			pkg_free(w->uri.s);
		pkg_free(w);
	}
	return -1;
}


int watcher_found_in_list(watcher_t * watchers, str wuri)
{
	watcher_t * w;

	w = watchers->next;

	while(w)
	{
		if(w->uri.len == wuri.len && strncmp(w->uri.s, wuri.s, wuri.len)== 0)
			return 1;
		w= w->next;
	}

	return 0;
}

int add_waiting_watchers(watcher_t* watchers, str pres_uri, str event)
{
//	static db_ps_t my_ps = NULL;
	watcher_t * w;
	db_key_t query_cols[3];
	db_val_t query_vals[3];
	db_key_t result_cols[2];
	db_res_t *result = NULL;
	db_row_t *row= NULL ;
	db_val_t *row_vals;
	int n_result_cols = 0;
	int n_query_cols = 0;
	int wuser_col, wdomain_col;
	str wuser, wdomain, wuri;
	int i;

	/* select from watchers table the users that have subscribed to the presentity
	 * and have status pending */

	query_cols[n_query_cols] = &str_presentity_uri_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = pres_uri;
	n_query_cols++;

	query_cols[n_query_cols] = &str_event_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = event;
	n_query_cols++;

	query_cols[n_query_cols] = &str_status_col;
	query_vals[n_query_cols].type = DB_INT;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.int_val = PENDING_STATUS;
	n_query_cols++;

	result_cols[wuser_col=n_result_cols++] = &str_watcher_username_col;
	result_cols[wdomain_col=n_result_cols++] = &str_watcher_domain_col;

	if (pa_dbf.use_table(pa_db, &watchers_table) < 0)
	{
		LM_ERR("sql use table 'watchers_table' failed\n");
		return -1;
	}

//	CON_PS_REFERENCE(pa_db) = &my_ps;

	if (pa_dbf.query (pa_db, query_cols, 0, query_vals,
		 result_cols, n_query_cols, n_result_cols, 0, &result) < 0)
	{
		LM_ERR("failed to query %.*s table\n", watchers_table.len, watchers_table.s);
		if(result)
			pa_dbf.free_result(pa_db, result);
		return -1;
	}

	if(result== NULL)
	{
		LM_ERR("mysql query failed - null result\n");
		return -1;
	}

	if (result->n<=0 )
	{
		LM_DBG("The query returned no result\n");
		pa_dbf.free_result(pa_db, result);
		return 0;
	}

	for(i=0; i< result->n; i++)
	{
		row = &result->rows[i];
		row_vals = ROW_VALUES(row);

		wuser.s = (char*)row_vals[wuser_col].val.string_val;
		wuser.len = strlen(wuser.s);

		wdomain.s = (char*)row_vals[wdomain_col].val.string_val;
		wdomain.len = strlen(wdomain.s);

		if(uandd_to_uri(wuser, wdomain, &wuri)<0)
		{
			LM_ERR("creating uri from username and domain\n");
			goto error;
		}

		if(watcher_found_in_list(watchers, wuri))
		{
			pkg_free(wuri.s);
			continue;
		}

		w= (watcher_t*)pkg_malloc(sizeof(watcher_t));
		if(w== NULL)
		{
			ERR_MEM(PKG_MEM_STR);
		}
		memset(w, 0, sizeof(watcher_t));

		w->status= WAITING_STATUS;
		w->uri = wuri;
		w->id.s = (char*)pkg_malloc(w->uri.len*2 +1);
		if(w->id.s== NULL)
		{
			pkg_free(w->uri.s);
			pkg_free(w);
			ERR_MEM(PKG_MEM_STR);
		}

		to64frombits((unsigned char *)w->id.s,
			(const unsigned char*)w->uri.s, w->uri.len);
		w->id.len = strlen(w->id.s);

		w->next= watchers->next;
		watchers->next= w;
	}

	pa_dbf.free_result(pa_db, result);
	return 0;

error:
	if(result)
		pa_dbf.free_result(pa_db, result);
	return -1;

}

str* build_empty_bla_body(str pres_uri)
{
	xmlDocPtr doc;
	xmlNodePtr node;
	xmlAttrPtr attr;
	str* body= NULL;
	char* text;
	int len;
	char* entity= NULL;

	doc = xmlNewDoc(BAD_CAST "1.0");
	if(doc== NULL)
	{
		LM_ERR("failed to construct xml document\n");
		return NULL;
	}

	node = xmlNewNode(NULL, BAD_CAST "dialog-info");
	if(node== NULL)
	{
		LM_ERR("failed to initialize node\n");
		goto error;
	}
	xmlDocSetRootElement(doc, node);

	attr = xmlNewProp(node, BAD_CAST "xmlns",
			BAD_CAST "urn:ietf:params:xml:ns:dialog-info");
	if(attr== NULL)
	{
		LM_ERR("failed to initialize node attribute\n");
		goto error;
	}
	attr = xmlNewProp(node, BAD_CAST "version", BAD_CAST "1");
	if(attr== NULL)
	{
		LM_ERR("failed to initialize node attribute\n");
		goto error;
	}

	attr = xmlNewProp(node, BAD_CAST "state", BAD_CAST "full");
	if(attr== NULL)
	{
		LM_ERR("failed to initialize node attribute\n");
		goto error;
	}

	entity = (char*)pkg_malloc(pres_uri.len+1);
	if(entity== NULL)
	{
		LM_ERR("no more memory\n");
		goto error;
	}
	memcpy(entity, pres_uri.s, pres_uri.len);
	entity[pres_uri.len]= '\0';

	attr = xmlNewProp(node, BAD_CAST "entity", BAD_CAST entity);
	if(attr== NULL)
	{
		LM_ERR("failed to initialize node attribute\n");
		pkg_free(entity);
		goto error;
	}

	body = (str*) pkg_malloc(sizeof(str));
	if(body== NULL)
	{
		LM_ERR("no more private memory\n");
		pkg_free(entity);
		goto error;
	}

	xmlDocDumpMemory(doc,(xmlChar**)(void*)&text, &len);
	body->s = (char*) pkg_malloc(len);
	if(body->s == NULL)
	{
		LM_ERR("no more private memory\n");
		pkg_free(body);
		pkg_free(entity);
		goto error;
	}
	memcpy(body->s, text, len);
	body->len= len;


	pkg_free(entity);
	xmlFreeDoc(doc);
	xmlFree(text);

	return body;

error:
	xmlFreeDoc(doc);
	return NULL;

}


db_res_t* pres_search_db(struct sip_uri* uri,str* ev_name, int* body_col,
		int* extra_hdrs_col, int* expires_col, int* etag_col)
{
/*	static db_ps_t my_ps = NULL; */
	db_key_t query_cols[5];
	db_val_t query_vals[5];
	db_key_t result_cols[5];
	db_res_t *result = NULL;
	int n_result_cols = 0;
	int n_query_cols = 0;
	int i;

	static str query_str = str_init("received_time");

	query_cols[n_query_cols] = &str_domain_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = uri->host;
	n_query_cols++;

	query_cols[n_query_cols] = &str_username_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = uri->user;
	n_query_cols++;

	query_cols[n_query_cols] = &str_event_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val= *ev_name;
	n_query_cols++;

	result_cols[n_result_cols] = &str_body_col;
	*body_col=n_result_cols++;
	result_cols[n_result_cols] = &str_extra_hdrs_col;
	*extra_hdrs_col=n_result_cols++;
	result_cols[n_result_cols] = &str_expires_col;
	*expires_col=n_result_cols++;
	result_cols[n_result_cols] = &str_etag_col;
	*etag_col=n_result_cols++;

	if (pa_dbf.use_table(pa_db, &presentity_table) < 0)
	{
		LM_ERR("in use_table\n");
		return NULL;
	}

	for(i= 0; i< n_query_cols; i++)
	{
		LM_DBG("qval [%i] = %.*s\n",i, query_vals[i].val.str_val.len,
				query_vals[i].val.str_val.s);
	}

/*	CON_PS_REFERENCE(pa_db) = &my_ps; */
	if (pa_dbf.query (pa_db, query_cols, 0, query_vals,
		 result_cols, n_query_cols, n_result_cols, &query_str, &result) < 0)
	{
		LM_ERR("failed to query %.*s table\n", presentity_table.len, presentity_table.s);
		if(result)
			pa_dbf.free_result(pa_db, result);
		return NULL;
	}
	return result;
}

str* get_presence_from_dialog(str* pres_uri, struct sip_uri* uri,
		unsigned int hash_code)
{
	db_res_t *result = NULL;
	int body_col, extra_hdrs_col, expires_col, etag_col;
	str body;
	str* dialog_body;
	db_row_t *row= NULL ;
	db_val_t *row_vals;
	int i;
	int ringing_index = -1;
	int ringing_state = 0;
	int dlg_state;
	int state;
	pres_entry_t* p;

	lock_get(&pres_htable[hash_code].lock);
	p= search_phtable(pres_uri, (*dialog_event_p)->evp->parsed, hash_code);
	lock_release(&pres_htable[hash_code].lock);

	if(p == NULL)
	{
		LM_DBG("No record exists in hashtable, pres_uri=[%.*s] event=[dialog]\n",
				pres_uri->len, pres_uri->s);
		if(!fallback2db)
			return NULL;
	}

	result = pres_search_db(uri, &((*dialog_event_p)->name),
			&body_col, &extra_hdrs_col, &expires_col, &etag_col);
	if(result== NULL)
		return NULL;

	if (result->n<=0 )
	{
		LM_DBG("The query returned no result, pres_uri=[%.*s] event=[dialog]\n",
				pres_uri->len, pres_uri->s);
		pa_dbf.free_result(pa_db, result);
		return NULL;
	}

	/* if there are more records - go through them until you find one with a dialog */
	for(i = result->n -1; i>=0 ; i--)
	{
		row = &result->rows[i];
		row_vals = ROW_VALUES(row);
		body.s = (char*)row_vals[body_col].val.string_val;
		if(body.s == NULL)
		{
			LM_ERR("NULL notify body record\n");
			goto error;
		}
		body.len= strlen(body.s);
		if(get_dialog_state(body, &dlg_state) < 0)
		{
			LM_ERR("get dialog state failed\n");
			goto error;
		}
		LM_DBG("dlg_state = %d = DLG_CONFIRMED= %d\n", dlg_state, DLG_CONFIRMED);
		if(dlg_state == DLG_CONFIRMED)
			break;
		if(dlg_state == DLG_DESTROYED)
			continue;
		if(ringing_index < 0)
		{
			ringing_index = i;
			ringing_state = dlg_state;
		}
	}
	pa_dbf.free_result(pa_db, result);

	LM_DBG("i = %d, ringing_inde = %d\n", i, ringing_index);

	if(i >= 0) /* if a confirmed index was found */
	{
		state = dlg_state;
	}
	else
	{
		if(ringing_index > 0)  /* if a ringind dialog was found */
			state = ringing_state;
		else
			return FAKED_BODY;
	}

	dialog_body = xml_dialog_gen_presence(pres_uri, state);

	return dialog_body;

error:
	if(result)
		pa_dbf.free_result(pa_db, result);
	return NULL;
}

static str* get_p_notify_body(str pres_uri, pres_ev_t* event, str* etag,
		str* publ_body, str* contact, str* dbody, str* extra_hdrs,
		free_body_t** free_fct, int from_publish, int query_cluster)
{
	int body_col, extra_hdrs_col, expires_col, etag_col= 0;
	db_res_t *result = NULL;
	db_row_t *row= NULL ;
	db_val_t *row_vals;
	str** body_array= NULL;
	str* notify_body= NULL;
	int i, n= 0, len;
	int build_off_n= -1;
	str etags;
	str* body;
	int size= 0;
	struct sip_uri uri;
	unsigned int hash_code;
	int body_cnt = 0;
	str* dialog_body= NULL, *local_dialog_body = NULL;
	int init_i = 0;
	pres_entry_t* p;

	if(parse_uri(pres_uri.s, pres_uri.len, &uri)< 0)
	{
		LM_ERR("while parsing uri\n");
		return NULL;
	}
	hash_code= core_hash(&pres_uri, NULL, phtable_size);

	if(mix_dialog_presence && event->evp->parsed == EVENT_PRESENCE)
	{
		if(!dbody || dbody==FAKED_BODY)
		{
			if(*dialog_event_p == NULL)
			{
				LM_ERR("You required mixing dialog and presence but you have"
						" not loaded 'dialog' event module (presence_dialoginfo)\n");
				return NULL;
			}
			if(!event->agg_nbody)
			{
				LM_ERR("Conflict - If you want to mix dialog info with presence"
						" you have to keep the default 'presence' event configuration"
						" with aggregation enabled\n");
				return NULL;
			}
			/* search also for 'dialog' event publications */
			local_dialog_body = get_presence_from_dialog(&pres_uri, &uri, hash_code);
			dialog_body = (local_dialog_body==FAKED_BODY)?NULL:local_dialog_body;
		}
		else
			dialog_body = (dbody==FAKED_BODY)?NULL:dbody;

		if(dialog_body)
		{
			LM_DBG("Presence from 'dialog': %.*s\n", dialog_body->len, dialog_body->s);
			body_array = &dialog_body; /* only for the case no other presence info is found */
			body_cnt = 1;
		}
	}

	/* search in hash table if any record exists */
	lock_get(&pres_htable[hash_code].lock);
	p= search_phtable(&pres_uri, event->evp->parsed, hash_code);
	lock_release(&pres_htable[hash_code].lock);

	if( !etag && p== NULL)
	{
		LM_DBG("No record exists in hash_table\n");
		if(!fallback2db)
		{
			/* we do not have the presentity */
			if (query_cluster && is_federation_full_sharing())
				query_cluster_for_presentity(&pres_uri, event->evp);

			/* for pidf manipulation && dialog-presence mixing */
			if(event->agg_nbody)
			{
				/* broken - it will not work with pidf manipulation */
				if(body_cnt == 0 && (mix_dialog_presence||notify_offline_body) && event->evp->parsed == EVENT_PRESENCE)
				{
					local_dialog_body = build_offline_presence(&pres_uri);
					if(local_dialog_body == NULL)
					{
						LM_ERR("Failed to build offline presence body\n");
						goto error;
					}
					dialog_body= local_dialog_body;
					body_array = &dialog_body; /* only for the case no other presence info is found */
					body_cnt = 1;
				}
				notify_body = event->agg_nbody(&uri.user, &uri.host, body_array, body_cnt, -1);
				if(notify_body)
					goto done;
			}
			if (event->build_empty_pres_info)
			{
				notify_body = event->build_empty_pres_info(&pres_uri, extra_hdrs);
				if(notify_body == NULL && event->mandatory_body)
				{
					LM_ERR("Failed to construct body\n");
					return NULL;
				}
				if(notify_body)
					LM_DBG("Built empty pres info %p\n", notify_body->s);
				goto done;
			}
			return NULL;
		}
	}

	result = pres_search_db(&uri,&event->name,&body_col,&extra_hdrs_col,&expires_col,&etag_col);
	if(result== NULL)
		return NULL;
	if (result->n<=0 )
	{
		LM_DBG("The query returned no result: [username]='%.*s'"
			" [domain]='%.*s' [event]='%.*s'\n",uri.user.len, uri.user.s,
			uri.host.len, uri.host.s, event->name.len, event->name.s);

		pa_dbf.free_result(pa_db, result);
		result= NULL;

		/* we do not have the presentity */
		if (query_cluster && is_federation_full_sharing() &&
		is_event_clustered(event->evp->parsed))
			query_cluster_for_presentity(&pres_uri, event->evp);

		if(event->agg_nbody)
		{
			/* broken - it will not work with pidf manipulation */
			if(body_cnt == 0 && (mix_dialog_presence||notify_offline_body) && event->evp->parsed == EVENT_PRESENCE)
			{
				local_dialog_body = build_offline_presence(&pres_uri);
				if(local_dialog_body == NULL)
				{
					LM_ERR("Failed to build offline presence body\n");
					goto error;
				}
				dialog_body= local_dialog_body;
				body_array = &dialog_body; /* only for the case no other presence info is found */
				body_cnt = 1;
			}

			notify_body = event->agg_nbody(&uri.user, &uri.host, body_array, body_cnt, -1);
			if(notify_body)
			{
				goto done;
			}
		}
		LM_DBG("build empty pres info\n");
		if(event->build_empty_pres_info)
		{
			notify_body = event->build_empty_pres_info(&pres_uri, extra_hdrs);
			if(notify_body == NULL && event->mandatory_body)
			{
				LM_ERR("Failed to construct body\n");
				return NULL;
			}
			goto done;
		}
		return NULL;
	}
	else
	{
		n= result->n;
		if(event->agg_nbody== NULL )
		{
			LM_DBG("Event does not require aggregation\n");
			row = &result->rows[n-1];
			row_vals = ROW_VALUES(row);

			if(row_vals[extra_hdrs_col].val.string_val!= NULL)
			{
				len = strlen(row_vals[extra_hdrs_col].val.string_val);
				if (len > 0 && extra_hdrs && !extra_hdrs->s)
				{
					extra_hdrs->s = (char*)pkg_malloc(len);
					if (extra_hdrs->s == NULL)
					{
						ERR_MEM(PKG_MEM_STR);
					}
					memcpy(extra_hdrs->s, row_vals[extra_hdrs_col].val.string_val, len);
					extra_hdrs->len = len;
				}
			}

			if(row_vals[body_col].val.string_val== NULL)
			{
				if (event->mandatory_body)
					LM_ERR("NULL notify body record\n");
				goto error;
			}
			len= strlen(row_vals[body_col].val.string_val);
			if(len== 0)
			{
				if (event->mandatory_body)
					LM_ERR("Empty notify body record\n");
				goto error;
			}
			notify_body= (str*)pkg_malloc(sizeof(str));
			if(notify_body== NULL)
			{
				ERR_MEM(PKG_MEM_STR);
			}
			memset(notify_body, 0, sizeof(str));
			notify_body->s= (char*)pkg_malloc(len);
			if(notify_body->s== NULL)
			{
				pkg_free(notify_body);
				ERR_MEM(PKG_MEM_STR);
			}
			memcpy(notify_body->s, row_vals[body_col].val.string_val, len);
			notify_body->len= len;
			pa_dbf.free_result(pa_db, result);
			*free_fct = (free_body_t*)pkg_free_w;

			return notify_body;
		}

		body_array =(str**)pkg_malloc( (n+3) *sizeof(str*));
		if(body_array == NULL)
		{
			ERR_MEM(PKG_MEM_STR);
		}
		memset(body_array, 0, (n+3) *sizeof(str*));

		init_i = body_cnt;
		if(etag!= NULL)
		{
			LM_DBG("searched etag = %.*s len= %d\n",
					etag->len, etag->s, etag->len);
			LM_DBG("etag not NULL\n");
			for(i= 0; i< n; i++)
			{
				row = &result->rows[i];
				row_vals = ROW_VALUES(row);
				etags.s = (char*)row_vals[etag_col].val.string_val;
				etags.len = strlen(etags.s);

				if(row_vals[extra_hdrs_col].val.string_val!= NULL)
				{
					len = strlen(row_vals[extra_hdrs_col].val.string_val);
					if (len > 0 && extra_hdrs && !extra_hdrs->s)
					{
						extra_hdrs->s = (char*)pkg_malloc(len);
						if (extra_hdrs->s == NULL)
						{
							ERR_MEM(PKG_MEM_STR);
						}
						memcpy(extra_hdrs->s, row_vals[extra_hdrs_col].val.string_val, len);
						extra_hdrs->len = len;
					}
				}

				LM_DBG("etag = %.*s len= %d\n", etags.len, etags.s, etags.len);
				if( (etags.len == etag->len) && (strncmp(etags.s,
								etag->s,etags.len)==0 ) )
				{
					LM_DBG("found etag\n");
					build_off_n= body_cnt;
				}
				len= strlen((char*)row_vals[body_col].val.string_val);
				if(len== 0)
				{
					if (event->mandatory_body)
						LM_ERR("Empty notify body record\n");
					goto error;
				}

				size= sizeof(str)+ len;
				body= (str*)pkg_malloc(size);
				if(body== NULL)
				{
					ERR_MEM(PKG_MEM_STR);
				}
				memset(body, 0, size);
				size= sizeof(str);
				body->s= (char*)body+ size;
				memcpy(body->s, (char*)row_vals[body_col].val.string_val, len);
				body->len= len;

				body_array[body_cnt++]= body;
			}
		}
		else
		{
			for(i=0; i< n; i++)
			{
				row = &result->rows[i];
				row_vals = ROW_VALUES(row);

				if(row_vals[extra_hdrs_col].val.string_val!= NULL)
				{
					len = strlen(row_vals[extra_hdrs_col].val.string_val);
					if (len > 0 && extra_hdrs && !extra_hdrs->s)
					{
						extra_hdrs->s = (char*)pkg_malloc(len);
						if (extra_hdrs->s == NULL)
						{
							ERR_MEM(PKG_MEM_STR);
						}
						memcpy(extra_hdrs->s, row_vals[extra_hdrs_col].val.string_val, len);
						extra_hdrs->len = len;
					}
				}

				len= strlen((char*)row_vals[body_col].val.string_val);
				if(len== 0)
				{
					if (event->mandatory_body)
						LM_ERR("Empty notify body record\n");
					goto error;
				}

				size= sizeof(str)+ len;
				body= (str*)pkg_malloc(size);
				if(body== NULL)
				{
					ERR_MEM(PKG_MEM_STR);
				}
				memset(body, 0, size);
				size= sizeof(str);
				body->s= (char*)body+ size;
				memcpy(body->s, row_vals[body_col].val.string_val, len);
				body->len= len;

				body_array[body_cnt++]= body;
			}
		}

		pa_dbf.free_result(pa_db, result);
		result= NULL;

		/* put the dialog info extracted body if present */
		if(dialog_body)
		{
			body_array[body_cnt++] = dialog_body;
		}

		/* if the Publish with expires=0 has body -> use this one */
		if(etag && publ_body && build_off_n>=0)
		{
			pkg_free(body_array[build_off_n]);
			body_array[build_off_n] = publ_body;
			build_off_n = -1;
		}

		/* RFC 4235 states that a NOTIFY generated after an initial
 		 * or refreshed SUBSCRIBE request must contain a full-state notification.
 		 * In other cases, only the modified state should be notified using
 		 * a partial state notification.
 		 */
		if (event->evp->parsed == EVENT_DIALOG && from_publish && publ_body) {

			/* Presence dialoginfo knows that special n value of -2 means we publish
 			 * a partial state. Calling the agg_nbody method is however required because
 			 * it builds the full NOTIFY body as described in the RFC (it adds the version
 			 * field to the body, defines if state is partial or full, ...).
 			 */
			notify_body = event->agg_nbody(&uri.user, &uri.host, &publ_body, -2, build_off_n);
			if(notify_body) {
				goto done;
			}
		}

		notify_body = event->agg_nbody(&uri.user, &uri.host, body_array, body_cnt, build_off_n);
		if(notify_body == NULL)
		{
			LM_ERR("Failed to aggregate notify body\n");
			goto error;
		}
	}

done:
	if(body_array!=NULL && body_array!=&dialog_body)
	{
		for(i= init_i; i< init_i + n; i++)
		{
			if( body_array[i] && body_array[i] != publ_body )
				pkg_free(body_array[i]);
		}
		pkg_free(body_array);
	}

	if(local_dialog_body && local_dialog_body!=FAKED_BODY
			&& local_dialog_body->s)
	{
		xmlFree(local_dialog_body->s);
		pkg_free(local_dialog_body);
	}

	*free_fct = event->free_body;
	return notify_body;

error:
	if(result!=NULL)
		pa_dbf.free_result(pa_db, result);

	if(local_dialog_body && local_dialog_body!=FAKED_BODY
			&& local_dialog_body->s)
	{
		xmlFree(local_dialog_body->s);
		pkg_free(local_dialog_body);
	}

	if(body_array!=NULL && body_array!=&dialog_body)
	{
		for(i= init_i; i< init_i + n; i++)
		{
			if( body_array[i] && body_array[i] != publ_body )
				pkg_free(body_array[i]);
			else
				break;
		}
		pkg_free(body_array);
	}
	return NULL;
}

int free_tm_dlg(dlg_t *td)
{
	if(td)
	{
		if(td->loc_uri.s)
			pkg_free(td->loc_uri.s);
		if(td->rem_uri.s)
			pkg_free(td->rem_uri.s);

		if(td->route_set)
			free_rr(&td->route_set);
		pkg_free(td);
	}
	return 0;
}

dlg_t* build_dlg_t(subs_t* subs)
{
	dlg_t* td =NULL;
	int found_contact = 1;

	td = (dlg_t*)pkg_malloc(sizeof(dlg_t));
	if(td == NULL)
	{
		ERR_MEM(PKG_MEM_STR);
	}
	memset(td, 0, sizeof(dlg_t));

	td->loc_seq.value = subs->local_cseq;
	td->loc_seq.is_set = 1;

	td->id.call_id = subs->callid;
	td->id.rem_tag = subs->from_tag;
	td->id.loc_tag =subs->to_tag;

	uandd_to_uri(subs->to_user, subs->to_domain, &td->loc_uri);
	if(td->loc_uri.s== NULL)
	{
		LM_ERR("while creating uri\n");
		goto error;
	}

	if(subs->contact.len ==0 || subs->contact.s == NULL )
	{
		found_contact = 0;
	}
	else
	{
		LM_DBG("CONTACT = %.*s\n", subs->contact.len , subs->contact.s);
		td->rem_target = subs->contact;
	}

	uandd_to_uri(subs->from_user, subs->from_domain, &td->rem_uri);
	if(td->rem_uri.s ==NULL)
	{
		LM_ERR("while creating uri\n");
		goto error;
	}

	if(found_contact == 0)
	{
		td->rem_target = td->rem_uri;
	}
	if(subs->record_route.s && subs->record_route.len)
	{
		if(parse_rr_body(subs->record_route.s, subs->record_route.len,
			&td->route_set)< 0)
		{
			LM_ERR("in function parse_rr_body\n");
			goto error;
		}
	}
	td->state= DLG_CONFIRMED ;
	td->send_sock = subs->sockinfo;

	return td;

error:
	free_tm_dlg(td);
	return NULL;
}

int get_subs_db(str* pres_uri, pres_ev_t* event, str* sender,
		subs_t** s_array, int* n, str **sh_tags)
{
//	static db_ps_t my_ps = NULL;
	db_key_t query_cols[8];
	db_op_t  query_ops[8];
	db_val_t query_vals[8];
	db_key_t result_cols[19];
	int n_result_cols = 0, n_query_cols = 0;
	db_row_t *row ;
	db_val_t *row_vals ;
	db_res_t *result = NULL;
	int from_user_col, from_domain_col, from_tag_col;
	int to_user_col, to_domain_col, to_tag_col;
	int expires_col= 0,callid_col, cseq_col, i, reason_col;
	int version_col= 0, record_route_col = 0, contact_col = 0;
	int sockinfo_col= 0, local_contact_col= 0, event_id_col = 0;
	subs_t s, *s_new;
	int inc= 0;
	str sockinfo_str;
	int port, proto;
	str host;
	unsigned int tag_no = 0;

	if (pa_dbf.use_table(pa_db, &active_watchers_table) < 0)
	{
		LM_ERR("in use_table\n");
		return -1;
	}

	LM_DBG("querying database table = active_watchers\n");
	query_cols[n_query_cols] = &str_presentity_uri_col;
	query_ops[n_query_cols] = OP_EQ;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = *pres_uri;
	n_query_cols++;

	query_cols[n_query_cols] = &str_event_col;
	query_ops[n_query_cols] = OP_EQ;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = event->name;
	n_query_cols++;

	query_cols[n_query_cols] = &str_status_col;
	query_ops[n_query_cols] = OP_EQ;
	query_vals[n_query_cols].type = DB_INT;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.int_val = ACTIVE_STATUS;
	n_query_cols++;

	query_cols[n_query_cols] = &str_contact_col;
	query_ops[n_query_cols] = OP_NEQ;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	if(sender)
	{
		LM_DBG("Do not send Notify to:[uri]= %.*s\n",sender->len,sender->s);
		query_vals[n_query_cols].val.str_val = *sender;
	}
	else
	{
		query_vals[n_query_cols].val.str_val.s = "";
		query_vals[n_query_cols].val.str_val.len = 0;
	}
	n_query_cols++;

	/* this must be the last select key! */
	if (sh_tags) {
		query_cols[n_query_cols] = &str_sharing_tag_col;
		query_ops[n_query_cols] = OP_EQ;
		query_vals[n_query_cols].type = DB_STR;
		query_vals[n_query_cols].nul = 0;
		n_query_cols++;
		/* the tag value is filled during the 'while' loop ; we rely on the
		 * fact that there is at least one tag in the list !! */
	}

	result_cols[to_user_col=n_result_cols++]      =   &str_to_user_col;
	result_cols[to_domain_col=n_result_cols++]    =   &str_to_domain_col;
	result_cols[from_user_col=n_result_cols++]    =   &str_watcher_username_col;
	result_cols[from_domain_col=n_result_cols++]  =   &str_watcher_domain_col;
	result_cols[event_id_col=n_result_cols++]     =   &str_event_id_col;
	result_cols[from_tag_col=n_result_cols++]     =   &str_from_tag_col;
	result_cols[to_tag_col=n_result_cols++]       =   &str_to_tag_col;
	result_cols[callid_col=n_result_cols++]       =   &str_callid_col;
	result_cols[cseq_col=n_result_cols++]         =   &str_local_cseq_col;
	result_cols[record_route_col=n_result_cols++] =   &str_record_route_col;
	result_cols[contact_col=n_result_cols++]      =   &str_contact_col;
	result_cols[expires_col=n_result_cols++]      =   &str_expires_col;
	result_cols[reason_col=n_result_cols++]       =   &str_reason_col;
	result_cols[sockinfo_col=n_result_cols++]     =   &str_socket_info_col;
	result_cols[local_contact_col=n_result_cols++]=   &str_local_contact_col;
	result_cols[version_col=n_result_cols++]      =   &str_version_col;

	do {

		if (sh_tags)
			query_vals[n_query_cols-1].val.str_val = *sh_tags[tag_no];

		//CON_PS_REFERENCE(pa_db) = &my_ps;
		if (pa_dbf.query(pa_db, query_cols, query_ops, query_vals,result_cols,
				n_query_cols, n_result_cols, 0, &result) < 0)
		{
			LM_ERR("while querying database\n");
			if(result)
				pa_dbf.free_result(pa_db, result);
			return -1;
		}

		if(result== NULL)
			return -1;

		if(result->n <=0 )
		{
			LM_DBG("The query for subscribtion for [uri]= %.*s for [event]= %.*s"
				" returned no result\n",pres_uri->len, pres_uri->s,
				event->name.len, event->name.s);
			pa_dbf.free_result(pa_db, result);
			return 0;
		}
		LM_DBG("found %d dialogs\n", result->n);

		for(i=0; i<result->n; i++)
		{
			row = &result->rows[i];
			row_vals = ROW_VALUES(row);

			//	if(row_vals[expires_col].val.int_val< (int)time(NULL))
			//		continue;

			if(row_vals[reason_col].val.string_val)
			{
				if(strlen(row_vals[reason_col].val.string_val) != 0)
					continue;
			}
			//	s.reason.len= strlen(s.reason.s);

			memset(&s, 0, sizeof(subs_t));
			s.status= ACTIVE_STATUS;

			s.pres_uri= *pres_uri;
			s.to_user.s= (char*)row_vals[to_user_col].val.string_val;
			s.to_user.len= strlen(s.to_user.s);

			s.to_domain.s= (char*)row_vals[to_domain_col].val.string_val;
			s.to_domain.len= strlen(s.to_domain.s);

			s.from_user.s= (char*)row_vals[from_user_col].val.string_val;
			s.from_user.len= strlen(s.from_user.s);

			s.from_domain.s= (char*)row_vals[from_domain_col].val.string_val;
			s.from_domain.len= strlen(s.from_domain.s);

			s.event_id.s=(char*)row_vals[event_id_col].val.string_val;
			s.event_id.len= (s.event_id.s)?strlen(s.event_id.s):0;

			s.to_tag.s= (char*)row_vals[to_tag_col].val.string_val;
			s.to_tag.len= strlen(s.to_tag.s);

			s.from_tag.s= (char*)row_vals[from_tag_col].val.string_val;
			s.from_tag.len= strlen(s.from_tag.s);

			s.callid.s= (char*)row_vals[callid_col].val.string_val;
			s.callid.len= strlen(s.callid.s);

			s.record_route.s=  (char*)row_vals[record_route_col].val.string_val;
			s.record_route.len= (s.record_route.s)?strlen(s.record_route.s):0;

			s.contact.s= (char*)row_vals[contact_col].val.string_val;
			s.contact.len= strlen(s.contact.s);

			sockinfo_str.s = (char*)row_vals[sockinfo_col].val.string_val;
			if (sockinfo_str.s)
			{
				sockinfo_str.len = strlen(sockinfo_str.s);
				if (parse_phostport (sockinfo_str.s, sockinfo_str.len,&host.s,
						&host.len, &port, &proto )< 0)
				{
					LM_ERR("bad format for stored sockinfo string\n");
					goto error;
				}
				s.sockinfo = grep_sock_info(&host, (unsigned short) port,
						(unsigned short) proto);
			}

			s.local_contact.s = (char*)row_vals[local_contact_col].val.string_val;
			s.local_contact.len = s.local_contact.s?strlen(s.local_contact.s):0;

			s.event= event;
			s.local_cseq = row_vals[cseq_col].val.int_val;

			if(row_vals[expires_col].val.int_val < (int)time(NULL))
				s.expires = 0;
			else
				s.expires = row_vals[expires_col].val.int_val -(int)time(NULL);
			s.version = row_vals[version_col].val.int_val;

			s_new= mem_copy_subs(&s, PKG_MEM_TYPE);
			if(s_new== NULL)
			{
				LM_ERR("while copying subs_t structure\n");
				goto error;
			}
			s_new->next= (*s_array);
			(*s_array)= s_new;

			printf_subs(s_new);
			inc++;
		}
		pa_dbf.free_result(pa_db, result);

	} while(sh_tags && sh_tags[++tag_no]);

	*n= inc;

	return 0;

error:
	if(result)
		pa_dbf.free_result(pa_db, result);

	return -1;
}

int update_in_list(subs_t* s, subs_t* s_array, int new_rec_no, int n)
{
	int i= 0;
	subs_t* ls;

	ls= s_array;

	while(i< new_rec_no)
	{
		i++;
		ls= ls->next;
	}

	for(i = 0; i< n; i++)
	{
		if(ls== NULL)
		{
			LM_ERR("wrong records count\n");
			return -1;
		}
		printf_subs(ls);

		if(ls->callid.len== s->callid.len &&
		strncmp(ls->callid.s, s->callid.s, s->callid.len)== 0 &&
		ls->to_tag.len== s->to_tag.len &&
		strncmp(ls->to_tag.s, s->to_tag.s, s->to_tag.len)== 0 &&
		ls->from_tag.len== s->from_tag.len &&
		strncmp(ls->from_tag.s, s->from_tag.s, s->from_tag.len)== 0 )
		{
			ls->local_cseq= s->local_cseq;
			ls->expires= s->expires- (int)time(NULL);
			ls->version= s->version;
			ls->status= s->status;
			return 1;
		}
		ls= ls->next;
	}
	return -1;
}

int presentity_has_subscribers(str* pres_uri, pres_ev_t* event)
{
	static db_ps_t ps = NULL;
	unsigned int hash_code;
	subs_t* s;
	time_t now;
	db_key_t keys[3];
	db_val_t vals[3];
	db_key_t cols[1];
	db_res_t *res;

	/* first check the in-memory hash, maybe we are lucky */
	hash_code= core_hash(pres_uri, &event->name, shtable_size);

	lock_get(&subs_htable[hash_code].lock);
	s = subs_htable[hash_code].entries;
	now = time(NULL);

	while (s->next) {
		s= s->next;

		/* expired & active ? */
		if ( (s->expires<(int)now) || (s->status!=ACTIVE_STATUS) ||
		(s->reason.len!=0) )
			continue;

		if (s->event==event && s->pres_uri.len== pres_uri->len &&
		strncmp(s->pres_uri.s, pres_uri->s, pres_uri->len)==0) {
			/* found a subscriber for our presentity*/
			lock_release(&subs_htable[hash_code].lock);
			return 1;
		}

	}
	lock_release(&subs_htable[hash_code].lock);

	/* presentity has no subscriber in hash. Check db ?? */
	if(fallback2db==0)
		return 0;

	keys[0] = &str_presentity_uri_col;
	vals[0].type = DB_STR;
	vals[0].nul = 0;
	vals[0].val.str_val = *pres_uri;

	keys[1] = &str_event_col;
	vals[1].type = DB_STR;
	vals[1].nul = 0;
	vals[1].val.str_val = event->name;

	keys[2] = &str_status_col;
	vals[2].type = DB_INT;
	vals[2].nul = 0;
	vals[2].val.int_val = ACTIVE_STATUS;

	cols[0] = &str_watcher_username_col;

	if (pa_dbf.use_table(pa_db, &active_watchers_table) < -1) {
		LM_ERR("in use_table\n");
		goto error;
	}
	CON_PS_REFERENCE(pa_db) = ps;

	if ( pa_dbf.query(pa_db, keys, 0, vals, cols, 3, 1, 0, &res) < 0) {
		LM_ERR("DB query failed\n");
		goto error;
	}

	if ( RES_ROW_N(res)>0 ) {
		pa_dbf.free_result(pa_db, res);
		return 1;
	}

	pa_dbf.free_result(pa_db, res);

	/* no subscriber for presentity + event */
	return 0;
error:
	return 0;
}


static int is_in_shtag_list(str *tag, str **list)
{
	unsigned int n = 0;

	while( list[n] ) {
		if (list[n]->len==tag->len &&
		strncasecmp(list[n]->s,tag->s,tag->len)==0)
			return 1;
		n++;
	}

	return 0;
}


subs_t* get_subs_dialog(str* pres_uri, pres_ev_t* event, str* sender,
															str **sh_tags)
{
	unsigned int hash_code;
	subs_t* s= NULL, *s_new;
	subs_t* s_array= NULL;
	int n= 0, i= 0;

	/* if tag filtering is enabled but not active tag is present
	 * in the list, simply return a 0 len list */
	if (sh_tags && sh_tags[0]==NULL) {
		return 0;
	}

	/* if fallback2db -> should take all dialogs from db
	 * and the only those dialogs from cache with db_flag= INSERTDB_FLAG */

	if(fallback2db)
	{
		if(get_subs_db(pres_uri, event, sender, &s_array, &n, sh_tags)< 0)
		{
			LM_ERR("getting dialogs from database\n");
			goto error;
		}
	}
	else
	{
		/* get records from hash table */
		hash_code= core_hash(pres_uri, &event->name, shtable_size);

		lock_get(&subs_htable[hash_code].lock);

		s= subs_htable[hash_code].entries;

		while(s->next)
		{
			s= s->next;

			printf_subs(s);

			if(s->expires< (int)time(NULL))
			{
				LM_DBG("expired subs\n");
				continue;
			}

			if((!(s->status== ACTIVE_STATUS &&
				s->reason.len== 0 &&
				s->event== event && s->pres_uri.len== pres_uri->len &&
				strncmp(s->pres_uri.s, pres_uri->s, pres_uri->len)== 0)) ||
				(sender && sender->len== s->contact.len &&
				strncmp(sender->s, s->contact.s, sender->len)== 0) ||
				(sh_tags && !is_in_shtag_list(&s->sh_tag, sh_tags) ) )
				continue;

			s_new= mem_copy_subs(s, PKG_MEM_TYPE);
			if(s_new== NULL)
			{
				LM_ERR("copying subs_t structure\n");
				lock_release(&subs_htable[hash_code].lock);
				goto error;
			}
			s_new->expires-= (int)time(NULL);
			s_new->next= s_array;
			s_array= s_new;
			i++;
		}
		lock_release(&subs_htable[hash_code].lock);
		n = i;
	}

	LM_DBG("found %d dialogs\n",n);

	return s_array;

error:
	free_subs_list(s_array, PKG_MEM_TYPE, 0);
	return NULL;
}

int publ_notify(presentity_t* p, str pres_uri, str* body, str* offline_etag,
		str* rules_doc, str* dialog_body, int from_publish, str **sh_tags)
{
	str *notify_body = NULL;
	str notify_extra_hdrs = {NULL, 0};
	subs_t* subs_array= NULL, *s= NULL;
	int ret_code= -1;
	free_body_t* free_fct = 0;

	subs_array= get_subs_dialog(&pres_uri, p->event , p->sender, sh_tags);
	if(subs_array == NULL)
	{
		LM_DBG("Could not find subs_dialog\n");
		ret_code= 0;
		goto done;
	}

	/* if the event does not require aggregation - we have the final body */
	if(p->event->agg_nbody)
	{
		notify_body = get_p_notify_body(pres_uri, p->event , offline_etag, body,
				NULL, dialog_body,
				p->extra_hdrs?p->extra_hdrs:&notify_extra_hdrs, &free_fct,
				from_publish, 0);
	}

	s= subs_array;
	while(s)
	{
		s->auth_rules_doc= rules_doc;
		LM_INFO("notify\n");
		if(notify(s, NULL, notify_body?notify_body:body,
			0, p->extra_hdrs?p->extra_hdrs:&notify_extra_hdrs, from_publish)< 0 )
		{
			LM_ERR("Could not send notify for %.*s\n",
					p->event->name.len, p->event->name.s);
		}
		s= s->next;
	}
	ret_code= 0;

done:
	free_subs_list(subs_array, PKG_MEM_TYPE, 0);

	if (notify_extra_hdrs.s)
		pkg_free(notify_extra_hdrs.s);

	if(notify_body!=NULL)
	{
		if(notify_body->s)
		{
			if( free_fct)
				free_fct(notify_body->s);
			else
				p->event->free_body(notify_body->s);
		}
		pkg_free(notify_body);
	}
	return ret_code;
}


int virtual_notify(str *pres_uri, pres_ev_t *ev, str *body)
{
	presentity_t pres;
	str l_pres_uri;

	memset( &pres, 0, sizeof(presentity_t) );
	pres.event = ev;

	l_pres_uri = *pres_uri;

	return publ_notify( &pres, l_pres_uri, body, NULL /*offline_etag*/,
		NULL/*rules_doc*/, NULL/*dialog_body*/,
		1 /*from_publish*/, NULL/*sh_tag*/);
}


int query_db_notify(str* pres_uri, pres_ev_t* event, subs_t* watcher_subs)
{
	subs_t* subs_array = NULL, *s= NULL;
	str notify_extra_hdrs = {NULL, 0};
	str* notify_body = NULL;
	int ret_code= -1;
	free_body_t* free_fct = 0;

	subs_array= get_subs_dialog(pres_uri, event , NULL, NULL);
	if(subs_array == NULL)
	{
		LM_DBG("Could not get subscription dialog\n");
		ret_code= 1;
		goto done;
	}

	if(event->type & PUBL_TYPE)
	{
		notify_body = get_p_notify_body(*pres_uri, event, 0, 0, 0, 0,
				&notify_extra_hdrs, &free_fct, 0, 1);
	}

	s= subs_array;

	while(s)
	{
		LM_INFO("notify\n");
		if(notify(s, watcher_subs, notify_body, 0, NULL, 0)< 0 )
		{
			LM_ERR("Could not send notify for [event]=%.*s\n",
					event->name.len, event->name.s);
		}
		s= s->next;
	}

	ret_code= 1;

done:
	free_subs_list(subs_array, PKG_MEM_TYPE, 0);

	if (notify_extra_hdrs.s)
		pkg_free(notify_extra_hdrs.s);

	if(notify_body!=NULL)
	{
		if(notify_body->s)
		{
			if(event->type & WINFO_TYPE)
				pkg_free(notify_body->s);
			else
			if (free_fct)
				free_fct(notify_body->s);
			else
				event->free_body(notify_body->s);
		}
		pkg_free(notify_body);
	}

	return ret_code;
}

int send_notify_request(subs_t* subs, subs_t * watcher_subs,
		str* n_body,int force_null_body, str* extra_hdrs, int from_publish)
{
	dlg_t* td = NULL;
	str met = {"NOTIFY", 6};
	str str_hdr = {NULL, 0};
	str notify_extra_hdrs = {NULL, 0};
	str* notify_body = NULL;
	int result= 0;
	c_back_param *cb_param= NULL;
	str* final_body= NULL;
	str* aux_body = 0;
	free_body_t* free_fct = 0;
	str ct_body = {NULL,0};
	int suppress_notify = 0;

	LM_DBG("enter: have_body=%d force_null=%d dialog info:\n",
	  (n_body!=0&&n_body->s!=0)?1:0, force_null_body);
	printf_subs(subs);

	/* getting the status of the subscription */

	if(force_null_body)
	{
		goto jump_over_body;
	}

	if(n_body!= 0 && n_body->s!= 0 && subs->status== ACTIVE_STATUS)
	{
		if( subs->event->req_auth)
		{
			if(subs->auth_rules_doc && subs->event->apply_auth_nbody )
			{
				if(subs->event->apply_auth_nbody(n_body, subs, &notify_body)< 0)
				{
					LM_ERR("in function apply_auth_nbody\n");
					goto error;
				}
			}
			if(notify_body== NULL)
				notify_body= n_body;
		}
		else
			notify_body= n_body;
	}
	else
	{
		if(subs->status== TERMINATED_STATUS ||
				subs->status== PENDING_STATUS)
		{
			LM_DBG("state terminated or pending- notify body NULL\n");
			notify_body = NULL;
		}
		else
		{
			if(subs->event->type & WINFO_TYPE)
			{
				notify_body = get_wi_notify_body(subs, watcher_subs);
				if(notify_body == NULL)
				{
					LM_DBG("Could not get notify_body\n");
					goto error;
				}
			}
			else
			{
				if (from_publish && n_body!= 0 && n_body->s!= 0) {
					notify_body = n_body;
				} else if (subs->event->build_notify_body) {
					notify_body = subs->event->build_notify_body(&subs->pres_uri,
						&subs->subs_body, &ct_body, &suppress_notify);
					if (suppress_notify)
						return 0;
					free_fct = subs->event->free_body;
				} else {
					notify_body = get_p_notify_body(subs->pres_uri,
							subs->event, 0, 0, (subs->contact.s)?&subs->contact:NULL,
							NULL, extra_hdrs?extra_hdrs:&notify_extra_hdrs,
							&free_fct, from_publish, 1);
				}
				if(notify_body == NULL || notify_body->s== NULL)
				{
					LM_DBG("Could not get the notify_body\n");
				}
				else		/* apply authorization rules if exists */
				{
					if(subs->event->req_auth)
					{
						if(subs->auth_rules_doc && subs->event->apply_auth_nbody &&
						subs->event->apply_auth_nbody(notify_body,subs,&final_body)<0)
						{
							LM_ERR("in function apply_auth\n");
							goto error;
						}
						if(final_body)
						{
							free_fct(notify_body->s);
							pkg_free(notify_body);
							notify_body= final_body;
						}
					}
					LM_DBG("built notify_body %p\n", notify_body->s);
				}
			}
		}
	}


jump_over_body:

	if(subs->expires<= 0)
	{
        subs->expires= 0;
		subs->status= TERMINATED_STATUS;
		subs->reason.s= "timeout";
		subs->reason.len= 7;
	}

	/* build extra headers */
	if( build_str_hdr( subs, notify_body?1:0, &str_hdr,
				&ct_body, extra_hdrs?extra_hdrs:&notify_extra_hdrs)< 0 )
	{
		LM_ERR("while building headers\n");
		goto error;
	}
	LM_DBG("headers:\n%.*s\n", str_hdr.len, str_hdr.s);

	/* construct the dlg_t structure */
	td = build_dlg_t(subs);
	if(td ==NULL)
	{
		LM_ERR("while building dlg_t structure\n");
		goto error;
	}

	cb_param = shm_dup_cbparam(subs);
	if(cb_param == NULL)
	{
		LM_ERR("failed to duplicate cb_param in share memory\n");
		goto error;
	}

	if (notify_body && subs->event->aux_body_processing)
		aux_body = subs->event->aux_body_processing(subs, notify_body);

	/* don't open new TCP connections if connection is down */
	tcp_no_new_conn = 1;

	result = tmb.t_request_within
		(&met,                          /* method*/
		&str_hdr,                       /* extra headers*/
		aux_body?aux_body:notify_body,  /* body*/
		td,                             /* dialog structure*/
		p_tm_callback,                  /* callback function*/
		(void*)cb_param,                /* callback parameter*/
		NULL);

	tcp_no_new_conn = 0;

	if(aux_body) {
		if(aux_body->s)
			subs->event->aux_free_body(aux_body->s);
		pkg_free(aux_body);
	}

	if(result< 0)
	{
		LM_ERR("tmb.t_request_within failed\n");
		free_cbparam(cb_param);
		goto error;
	}

	LM_INFO("NOTIFY %.*s via %.*s on behalf of %.*s for event %.*s, to_tag=%.*s, cseq=%d\n",
		td->rem_uri.len, td->rem_uri.s, td->hooks.next_hop->len, td->hooks.next_hop->s,
		td->loc_uri.len, td->loc_uri.s, subs->event->name.len, subs->event->name.s,
		td->id.loc_tag.len, td->id.loc_tag.s, td->loc_seq.value);

	free_tm_dlg(td);

	pkg_free(str_hdr.s);

	if (notify_extra_hdrs.s)
		pkg_free(notify_extra_hdrs.s);

	if((int)(long)n_body!= (int)(long)notify_body)
	{
		if(notify_body!=NULL)
		{
			if(notify_body->s!=NULL)
			{
				if(subs->event->type& WINFO_TYPE )
					xmlFree(notify_body->s);
				else
				if(free_fct)
					free_fct(notify_body->s);
				else
					subs->event->free_body(notify_body->s);
			}
			pkg_free(notify_body);
		}
	}
	return 0;

error:
	if(td)
		free_tm_dlg(td);
	if(str_hdr.s)
		pkg_free(str_hdr.s);
	if (notify_extra_hdrs.s)
		pkg_free(notify_extra_hdrs.s);
	if (ct_body.s)
		pkg_free(ct_body.s);

	if((int)(long)n_body!= (int)(long)notify_body)
	{
		if(notify_body!=NULL)
		{
			if(notify_body->s!=NULL)
			{
				if(subs->event->type& WINFO_TYPE)
					xmlFree(notify_body->s);
				else
				if(free_fct)
					free_fct(notify_body->s);
				else
				subs->event->free_body(notify_body->s);
			}
			pkg_free(notify_body);
		}
	}
	return -1;
}


int notify(subs_t* subs, subs_t * watcher_subs, str* n_body, int force_null_body, str* extra_hdrs, int from_publish)
{
	/* update first in hash table and the send Notify */
	if(subs->expires!= 0 && subs->status != TERMINATED_STATUS)
	{
		unsigned int hash_code;
		hash_code= core_hash(&subs->pres_uri, &subs->event->name, shtable_size);

		if(update_shtable(subs_htable, hash_code, subs, LOCAL_TYPE)< 0)
		{
			LM_DBG("record not found in subs htable\n");
		}
		if(fallback2db)
		{
			if(update_subs_db(subs, LOCAL_TYPE)< 0)
			{
				LM_ERR("updating subscription in database\n");
				return -1;
			}
		}
	}

	if(subs->reason.s && subs->status== ACTIVE_STATUS &&
		subs->reason.len== 12 && strncmp(subs->reason.s, "polite-block", 12)== 0)
	{
		force_null_body = 1;
	}

	if(send_notify_request(subs, watcher_subs, n_body, force_null_body, extra_hdrs, from_publish)< 0)
	{
		LM_ERR("sending Notify not successful\n");
		return -1;
	}

	return 0;
}

void p_tm_callback( struct cell *t, int type, struct tmcb_params *ps)
{
	c_back_param* cb;

	if(ps->param==NULL || *ps->param==NULL ||
			((c_back_param*)(*ps->param))->pres_uri.s == NULL ||
			((c_back_param*)(*ps->param))->ev_name.s== NULL ||
			((c_back_param*)(*ps->param))->to_tag.s== NULL)
	{
		LM_DBG("message id not received\n");
		if(ps->param!=NULL && *ps->param !=NULL  )
			free_cbparam((c_back_param*)(*ps->param));
		return;
	}

	cb = (c_back_param*)(*ps->param);

	if(ps->code == 200)
	{
		LM_DBG("completed with status [%d] and to_tag [%.*s]\n",
			ps->code, cb?cb->to_tag.len:0, cb?cb->to_tag.s:"");
	}
	else
	{
		LM_WARN("completed with status [%d] and to_tag [%.*s], cseq [%.*s]\n",
			ps->code, cb?cb->to_tag.len:0, cb?cb->to_tag.s:"", t->cseq_n.len, t->cseq_n.s);
	}

	if(ps->code == 481 || (end_sub_on_timeout && (ps->code==408)) )
	{
		unsigned int hash_code;

		hash_code= core_hash(&cb->pres_uri, &cb->ev_name, shtable_size);
		delete_shtable(subs_htable, hash_code, cb->to_tag);
		delete_db_subs(cb->pres_uri, cb->ev_name, cb->to_tag);
	}

	if(cb != NULL)
		free_cbparam(cb);
	return ;
}

void free_cbparam(c_back_param* cb_param)
{
	if(cb_param!= NULL)
		shm_free(cb_param);
}

c_back_param* shm_dup_cbparam(subs_t* subs)
{
	int size;
	c_back_param* cb_param = NULL;

	size = sizeof(c_back_param)+ subs->pres_uri.len+
			subs->event->name.len+ subs->to_tag.len;

	cb_param= (c_back_param*)shm_malloc(size);
	if(cb_param== NULL)
	{
		LM_ERR("no more shared memory\n");
		return 0;
	}
	memset(cb_param, 0, size);

	size= sizeof(c_back_param);
	CONT_COPY(cb_param, cb_param->pres_uri, subs->pres_uri);
	CONT_COPY(cb_param, cb_param->ev_name, subs->event->name);
	CONT_COPY(cb_param, cb_param->to_tag, subs->to_tag);

	return cb_param;
}


str* create_winfo_xml(watcher_t* watchers, char* version,
		str resource, str event, int STATE_FLAG )
{
	xmlDocPtr doc = NULL;
    xmlNodePtr root_node = NULL, node = NULL;
	xmlNodePtr w_list_node = NULL;
	char content[200];
	str *body= NULL;
	char* buffer= NULL;
	watcher_t* w;

	LIBXML_TEST_VERSION;

	doc = xmlNewDoc(BAD_CAST "1.0");
	root_node = xmlNewNode(NULL, BAD_CAST "watcherinfo");
	xmlDocSetRootElement(doc, root_node);

	xmlNewProp(root_node, BAD_CAST "xmlns",
			BAD_CAST "urn:ietf:params:xml:ns:watcherinfo");
	xmlNewProp(root_node, BAD_CAST "version", BAD_CAST version );

	if(STATE_FLAG & FULL_STATE_FLAG)
	{
		if( xmlNewProp(root_node, BAD_CAST "state", BAD_CAST "full") == NULL)
		{
			LM_ERR("while adding new attribute\n");
			goto error;
		}
	}
	else
	{
		if( xmlNewProp(root_node, BAD_CAST "state", BAD_CAST "partial")==NULL)
		{
			LM_ERR("while adding new attribute\n");
			goto error;
		}
	}

	w_list_node =xmlNewChild(root_node, NULL, BAD_CAST "watcher-list",NULL);
	if( w_list_node == NULL)
	{
		LM_ERR("while adding child\n");
		goto error;
	}
	buffer= (char*)pkg_malloc(resource.len+ 1);
	if(buffer== NULL)
	{
		ERR_MEM(PKG_MEM_STR);
	}
	memcpy(buffer, resource.s, resource.len);
	buffer[resource.len]= '\0';
	xmlNewProp(w_list_node, BAD_CAST "resource", BAD_CAST buffer);
	pkg_free(buffer);

	buffer= (char*)pkg_malloc(event.len+1);
	if(buffer== NULL)
	{
		ERR_MEM(PKG_MEM_STR);
	}
	memcpy(buffer, event.s, event.len);
	buffer[event.len]= '\0';
	xmlNewProp(w_list_node, BAD_CAST "package", BAD_CAST buffer);
	pkg_free(buffer);

	w= watchers->next;
	while(w)
	{
		strncpy( content,w->uri.s, w->uri.len);
		content[ w->uri.len ]='\0';
		node = xmlNewChild(w_list_node, NULL, BAD_CAST "watcher",
				BAD_CAST content) ;
		if( node ==NULL)
		{
			LM_ERR("while adding child\n");
			goto error;
		}
		if(xmlNewProp(node, BAD_CAST "id", BAD_CAST w->id.s)== NULL)
		{
			LM_ERR("while adding new attribute\n");
			goto error;
		}

		if(xmlNewProp(node, BAD_CAST "event", BAD_CAST "subscribe")== NULL)
		{
			LM_ERR("while adding new attribute\n");
			goto error;
		}

		if(xmlNewProp(node, BAD_CAST "status",
					BAD_CAST get_status_str(w->status))== NULL)
		{
			LM_ERR("while adding new attribute\n");
			goto error;
		}
		w= w->next;
	}
    body = (str*)pkg_malloc(sizeof(str));
	if(body == NULL)
	{
		ERR_MEM(PKG_MEM_STR);
	}
	memset(body, 0, sizeof(str));

	xmlDocDumpMemory(doc,(xmlChar**)(void*)&body->s, &body->len);

	xmlFreeDoc(doc);

	xmlCleanupParser();

    xmlMemoryDump();

    return body;

error:
    if(doc)
		xmlFreeDoc(doc);
	return NULL;
}

