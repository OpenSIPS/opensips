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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "../../dprint.h"
#include "../../data_lump_rpl.h"
#include "../../parser/msg_parser.h"
#include "../../parser/parse_event.h"
#include "../../parser/parse_expires.h"
#include "../../parser/parse_cseq.h"
#include "../../parser/parse_from.h"
#include "../../parser/parse_supported.h"
#include "../../parser/contact/parse_contact.h"
#include "../../parser/parse_rr.h"
#include "../presence/subscribe.h"
#include "../presence/utils_func.h"
#include "../presence/hash.h"
#include "subscribe.h"
#include "notify.h"
#include "rls.h"

int counter= 0;

static str su_200_rpl     = str_init("OK");
//static str pu_421_rpl     = str_init("Extension Required");
static str pu_400_rpl     = str_init("Bad request");
static str pu_500_rpl     = str_init("Server Error");
static str stale_cseq_rpl = str_init("Stale Cseq Value");
static str pu_489_rpl     = str_init("Bad Event");
static str pu_404_rpl     = str_init("Not Found");

#define Stale_cseq_code 401
#define SUBS_EXTRA_HDRS  "Supported: eventlist\r\nAccept: application/pidf+xml, application/rlmi+xml, application/watcherinfo+xml, multipart/related, application/xcap-diff+xml\r\n"
#define SUBS_EXTRA_HDRS_LEN  sizeof(SUBS_EXTRA_HDRS) -1

subs_t* constr_new_subs(struct sip_msg* msg, struct to_body *pto,
		pres_ev_t* event);

int update_rlsubs( subs_t* subs,unsigned int hash_code,
		int* reply_code, str* reply_str, int just_check);


xmlNodePtr search_service_uri(xmlDocPtr doc, str* service_uri)
{
	xmlNodePtr rl_node, node;
	struct sip_uri sip_uri;
	str uri, uri_str;
	str *normalized_uri;

	rl_node= XMLDocGetNodeByName(doc, "rls-services", NULL);
	if(rl_node== NULL)
	{
		LM_ERR("while extracting rls-services node\n");
		return NULL;
	}
	for(node= rl_node->children; node; node= node->next)
	{
		if(xmlStrcasecmp(node->name,(unsigned char*)"service")== 0)
		{
			uri.s = XMLNodeGetAttrContentByName(node, "uri");
			if (uri.s == NULL)
			{
			        LM_DBG("failed to fetch 'uri' in service [invalid XML from XCAP]\n");
			        continue;
			}
			uri.len = strlen(uri.s);

			normalized_uri = normalizeSipUri(&uri);
			if (normalized_uri->s == NULL || normalized_uri->len == 0)
			{
				LM_ERR("failed to normalize service URI\n");
				xmlFree(uri.s);
				return NULL;
			}
			xmlFree(uri.s);

			if(parse_uri(normalized_uri->s, normalized_uri->len, &sip_uri)< 0)
			{
				LM_ERR("failed to parse uri\n");
				return NULL;
			}
			if(uandd_to_uri(sip_uri.user, sip_uri.host, &uri_str)< 0)
			{
				LM_ERR("failed to construct uri from user and domain\n");
				return NULL;
			}
			if(uri_str.len== service_uri->len &&
					strncmp(uri_str.s, service_uri->s, uri_str.len) == 0)
			{
				pkg_free(uri_str.s);
				return node;
			}
			LM_DBG("match not found, service-uri = [%.*s]\n", uri_str.len, uri_str.s);
			pkg_free(uri_str.s);
		}
	}
	return NULL;
}

static int http_get_resource_list(str* owner_user, str* owner_domain, str** doc)
{
	str body = {0, 0};
	str *doc_tmp;
	xcap_get_req_t req;
	xcap_doc_sel_t doc_sel;

	memset(&doc_sel, 0, sizeof(xcap_doc_sel_t));
	doc_sel.auid.s = "rls-services";
	doc_sel.auid.len = strlen(doc_sel.auid.s);
	doc_sel.doc_type = RLS_SERVICES;
	doc_sel.type = USERS_TYPE;
	if(uandd_to_uri(*owner_user, *owner_domain, &doc_sel.xid) < 0)
	{
		LM_ERR("failed to create uri from user and domain\n");
		goto error;
	}

	memset(&req, 0, sizeof(xcap_get_req_t));
	req.xcap_root = xcap_root;
	req.port = xcap_port;
	req.doc_sel = doc_sel;

	if(xcap_GetNewDoc(req, *owner_user, *owner_domain, &body) < 0)
	{
		LM_ERR("while fetching data from xcap server\n");
		pkg_free(doc_sel.xid.s);
		goto error;
	}
	pkg_free(doc_sel.xid.s);

	if (body.s == NULL)
		goto error;

	doc_tmp = pkg_malloc(sizeof(*doc_tmp));
	if(doc_tmp == NULL)
	{
		LM_ERR("No more pkg memory\n");
		goto error;
	}
	doc_tmp->s = pkg_malloc(body.len);
	if(doc_tmp->s == NULL)
	{
		pkg_free(doc_tmp);
		LM_ERR("No more pkg memory\n");
		goto error;
	}
	memcpy(doc_tmp->s, body.s, body.len);
	doc_tmp->len = body.len;
	pkg_free(body.s);

	*doc = doc_tmp;
	return 0;

error:
	if (body.s)
		pkg_free(body.s);
	return -1;
}

/*
 * Function that searches a resource list document for the user and then
 * looks in the document for the service uri
 *	returns:
 *		 0: success ( service uri found)
 *		-1: server error
 *	 doc :
 *	    NULL: document or service uri not found
 *	    pointer to xmlDocPtr structure if service uri found
 * */
int get_resource_list(str* service_uri, str owner_user, str owner_domain,
		      xmlNodePtr* service_node, xmlDocPtr* rl_doc)
{
	str *doc = NULL;
	str *etag = NULL;
	xmlDocPtr xml_doc = NULL;
	xmlNodePtr snode = NULL;

	*rl_doc = NULL;
	*service_node = NULL;

	if (xcapDbGetDoc(&owner_user, &owner_domain, RLS_SERVICES, NULL, NULL, &doc, &etag) < 0)
	{
		LM_ERR("while getting RLS document from DB\n");
		goto error;
	}

	if (doc == NULL)
	{
		LM_DBG("No rl document found in database\n");
		if (rls_integrated_xcap_server)
			goto done;
		/* Use xcap_client to try to fetch the document */
		if (http_get_resource_list(&owner_user, &owner_domain, &doc) < 0)
			goto done;
	}

	/* Document is loaded in doc either via DB or HTTP */
	LM_DBG("rls_services document:\n%.*s\n", doc->len, doc->s);
	xml_doc = xmlParseMemory(doc->s, doc->len);
	if(xml_doc == NULL)
	{
		LM_ERR("while parsing XML memory\n");
		goto error;
	}

	snode = search_service_uri(xml_doc, service_uri);
	if (snode == NULL)
	{
		LM_DBG("service uri %.*s not found in rl document for user"
			   " sip:%.*s@%.*s\n", service_uri->len, service_uri->s,
			   owner_user.len, owner_user.s, owner_domain.len, owner_domain.s);
		xmlFreeDoc(xml_doc);
		goto done;
	}

	*rl_doc = xml_doc;
	*service_node = snode;

done:
	if (doc != NULL)
	{
		if (doc->s != NULL)
			pkg_free(doc->s);
		pkg_free(doc);
	}
	if (etag != NULL)
	{
		if (etag->s != NULL)
			pkg_free(etag->s);
		pkg_free(etag);
	}
	return 0;
error:
	if (doc != NULL)
	{
		if (doc->s != NULL)
			pkg_free(doc->s);
		pkg_free(doc);
	}
	if (etag != NULL)
	{
		if (etag->s != NULL)
			pkg_free(etag->s);
		pkg_free(etag);
	}
	return -1;
}


/*
 * Not used anymore
int reply_421(struct sip_msg* msg)
{
	str hdr_append;
	char buffer[256];

	hdr_append.s = buffer;
	hdr_append.s[0]='\0';
	hdr_append.len = sprintf(hdr_append.s, "Require: eventlist\r\n");
	if(hdr_append.len < 0)
	{
		LM_ERR("unsuccessful sprintf\n");
		return -1;
	}
	hdr_append.s[hdr_append.len]= '\0';

	if (add_lump_rpl( msg, hdr_append.s, hdr_append.len, LUMP_RPL_HDR)==0 )
	{
		LM_ERR("unable to add lump_rl\n");
		return -1;
	}

	if (rls_sigb.reply(msg, 421, &pu_421_rpl, 0) == -1)
	{
		LM_ERR("failed to send reply\n");
		return -1;
	}
	return 0;
}
*/

int reply_200(struct sip_msg* msg, str* local_contact, int expires, str* rtag)
{
	char* hdr_append;
	int len;
	int lexpire_len;
	char *lexpire_s;
	char* p;

	lexpire_s = int2str((unsigned long)expires, &lexpire_len);

	len =  9 /* Expires: */ + lexpire_len + CRLF_LEN
		+ 10 /* Contact: < */ + local_contact->len + 1 /* > */ + CRLF_LEN
		+ 18 /* Require: eventlist */ + CRLF_LEN;

	hdr_append = (char *)pkg_malloc( len );
	if(hdr_append == NULL)
	{
		ERR_MEM(PKG_MEM_STR);
	}

	p = hdr_append;
	/* expires header */
	memcpy(p, "Expires: ", 9);
	p += 9;
	memcpy(p,lexpire_s,lexpire_len);
	p += lexpire_len;
	memcpy(p,CRLF,CRLF_LEN);
	p += CRLF_LEN;
	/* contact header */
	memcpy(p,"Contact: <", 10);
	p += 10;
	memcpy(p,local_contact->s,local_contact->len);
	p += local_contact->len;
	*(p++) = '>';
	memcpy(p, CRLF, CRLF_LEN);
	p += CRLF_LEN;

	memcpy(p, "Require: eventlist", 18);
	p += 18;
	memcpy(p, CRLF, CRLF_LEN);
	p += CRLF_LEN;

	if (add_lump_rpl( msg, hdr_append, p-hdr_append, LUMP_RPL_HDR)==0 )
	{
		LM_ERR("unable to add lump_rl\n");
		goto error;
	}

	if( rls_sigb.reply( msg, 200, &su_200_rpl, rtag)< 0)
	{
		LM_ERR("failed to send reply\n");
		goto error;
	}
	pkg_free(hdr_append);
	return 0;

error:
	pkg_free(hdr_append);
	return -1;
}

int reply_489(struct sip_msg * msg)
{
	str hdr_append;
	char buffer[256];
	str* ev_list;

	hdr_append.s = buffer;
	hdr_append.s[0]='\0';
	hdr_append.len = sprintf(hdr_append.s, "Allow-Events: ");
	if(hdr_append.len < 0)
	{
		LM_ERR("unsuccessful sprintf\n");
		return -1;
	}

	if(pres_get_ev_list(&ev_list)< 0)
	{
		LM_ERR("while getting ev_list\n");
		return -1;
	}
	memcpy(hdr_append.s+ hdr_append.len, ev_list->s, ev_list->len);
	hdr_append.len+= ev_list->len;
	pkg_free(ev_list->s);
	pkg_free(ev_list);
	memcpy(hdr_append.s+ hdr_append.len, CRLF, CRLF_LEN);
	hdr_append.len+=  CRLF_LEN;
	hdr_append.s[hdr_append.len]= '\0';

	if (add_lump_rpl( msg, hdr_append.s, hdr_append.len, LUMP_RPL_HDR)==0 )
	{
		LM_ERR("unable to add lump_rl\n");
		return -1;
	}
	if (rls_sigb.reply(msg, 489, &pu_489_rpl, 0) == -1)
	{
		LM_ERR("failed to send reply\n");
		return -1;
	}
	return 0;
}

/*
 *	Function called from script to process RLS SUBSCRIBE messages
 *		- returns:
 *			1  - success
 *			-1 - error
 *		- sends an appropriate reply in every case
 * */

int rls_handle_subscribe(struct sip_msg* msg, char* s1, char* s2)
{
	static char contact[MAX_URI_SIZE];
	struct to_body *pto, *pfrom = NULL;
	subs_t subs;
	pres_ev_t* event = NULL;
	xmlDocPtr doc = NULL;
	xmlNodePtr service_node = NULL;
	unsigned int hash_code = 0;
	event_t* parsed_event;
	param_t* ev_param = NULL;
	int init_req;
	int reply_code;
	str reply_str;

	/*** filter: 'For me or for presence server?' */

	reply_code = 400;
	reply_str = pu_400_rpl;

	memset(&subs, 0, sizeof(subs_t));

	if (parse_headers(msg,HDR_EOH_F, 0) == -1)
	{
		LM_ERR("parsing headers\n");
		goto error;
	}

	/* check for Support: eventlist header */
	if (!msg->supported)
	{
		LM_DBG("no supported header found\n");
		return to_presence_code;
	}

	if (parse_supported(msg) < 0)
	{
		LM_ERR("failed to parse supported headers\n");
		goto error_5xx;
	}

	if (!(get_supported(msg) & F_SUPPORTED_EVENTLIST))
	{
		LM_DBG("No 'Support: eventlist' header found\n");
		return to_presence_code;
	}

	/* inspecting the Event header field */
	if (msg->event && msg->event->body.len > 0)
	{
		if (!msg->event->parsed && (parse_event(msg->event) < 0))
		{
			LM_ERR("cannot parse Event header\n");
			goto error_5xx;
		}
		if (!(((event_t*)msg->event->parsed)->parsed & rls_events))
		{
			return to_presence_code;
		}
	}
	else
	{
		goto bad_event;
	}

	/* search event in the list */
	parsed_event = (event_t*)msg->event->parsed;
	event = pres_search_event(parsed_event);
	if (event == NULL)
	{
		goto bad_event;
	}
	subs.event = event;

	/* extract the id if any*/
	ev_param = parsed_event->params;
	while (ev_param)
	{
		if (ev_param->name.len == 2 && strncasecmp(ev_param->name.s, "id", 2) == 0)
		{
			subs.event_id = ev_param->body;
			break;
		}
		ev_param= ev_param->next;
	}

	pto = get_to(msg);
	if (pto == NULL || pto->error != PARSE_OK)
	{
		LM_ERR("parsing 'To' header failed\n");
		goto error;
	}

	if (parse_from_uri(msg) == 0)
	{
		LM_ERR("failed to parse From header\n");
		goto error;
	}

	pfrom = (struct to_body*)msg->from->parsed;
	if (pfrom->tag_value.s == NULL || pfrom->tag_value.len == 0)
	{
		LM_ERR("no from tag value present\n");
		goto error;
	}

	/* verify if the presentity URI is a resource list */
	if (pto->tag_value.s == NULL || pto->tag_value.len == 0)
		/* if an initial Subscribe */
	{
		struct sip_uri fu = ((struct to_body*)msg->from->parsed)->parsed_uri;
		if (parse_sip_msg_uri(msg) < 0)
		{
			LM_ERR("parsing Request URI failed\n");
			goto error;
		}

		/*verify if Request URI represents a list by asking xcap server*/
		if (uandd_to_uri(msg->parsed_uri.user, msg->parsed_uri.host, &subs.pres_uri) < 0)
		{
			LM_ERR("while constructing uri from user and domain\n");
			goto error_5xx;
		}

		if (get_resource_list(&subs.pres_uri, fu.user, fu.host, &service_node, &doc) < 0)
		{
			LM_ERR("failed to get resource list document\n");
			goto error_5xx;
		}

		if (doc == NULL || service_node == NULL)
		{
			LM_DBG("list not found - search for uri = %.*s\n", subs.pres_uri.len, subs.pres_uri.s);
			pkg_free(subs.pres_uri.s);
			return to_presence_code;
		}
	}
	else  /* if request inside a dialog */
	{
		if (msg->callid == NULL || msg->callid->body.s == NULL)
		{
			LM_ERR("cannot parse callid header\n");
			goto error;
		}

		/* search if a stored dialog */
		hash_code = core_hash(&msg->callid->body, &pto->tag_value, hash_size);
		lock_get(&rls_table[hash_code].lock);

		if (pres_search_shtable(rls_table,msg->callid->body, pto->tag_value, pfrom->tag_value, hash_code) == NULL)
		{
			lock_release(&rls_table[hash_code].lock);
			/* reply with Call/Transaction Does Not Exist */
			LM_DBG("No dialog match found\n");
			return to_presence_code;
		}
		lock_release(&rls_table[hash_code].lock);
	}

	/* extract dialog information from message headers */
	if (pres_extract_sdialog_info(&subs, msg, rls_max_expires, &init_req, contact_user) < 0)
	{
		LM_ERR("bad Subscribe request\n");
		goto error;
	}

	// save subs.local_contact as it uses a static buffer that is overwritten with every
	// call to get_local_contact(), which we will do for every SUBSCRIBE that we'll send
	memcpy(contact, subs.local_contact.s, subs.local_contact.len);
	subs.local_contact.s = contact;


	if (init_req) /* if an initial subscribe */
	{

		/* first, generate the To-tag, so we can double check the 
		 * to-be-created subscription */
		rls_sigb.gen_totag( msg, &subs.to_tag);

		/* be sure the SIP subscription does not exist in hash */
		if (update_rlsubs(&subs, hash_code, NULL, NULL, 1)==0) {
			/* another subscription with same SIP coordinates already
			 * exists => decline */
			LM_ERR("subscription overlapping detected, rejecting\n");
			goto error_5xx;
		}

		hash_code = core_hash(&subs.callid, &subs.to_tag, hash_size);

		subs.local_cseq = 0;

		if (subs.expires != 0)
		{
			subs.version = 1;
			if (pres_insert_shtable(rls_table, hash_code, &subs) < 0)
			{
				LM_ERR("while adding new subscription\n");
				goto error_5xx;
			}
		}

		/** reply with 200 OK*/
		if (reply_200(msg, &subs.local_contact, subs.expires, NULL) < 0)
			goto error_free;
	}
	else
	{
		if (update_rlsubs(&subs, hash_code, &reply_code, &reply_str, 0) < 0)
		{
			LM_ERR("while updating resource list subscription\n");
			goto error_5xx;
		}

		if (get_resource_list(&subs.pres_uri, subs.from_user, subs.from_domain, &service_node, &doc) < 0)
		{
			LM_ERR("when getting resource list\n");
			goto error_5xx;
		}
		if (doc == NULL || service_node == NULL)
		{
			LM_DBG("list not found( in-dialog request)- search for uri = %.*s\n", subs.pres_uri.len, subs.pres_uri.s);
			reply_code = 404;
			reply_str = pu_404_rpl;
			goto error;
		}

		/** reply with 200 OK*/
		if (reply_200(msg, &subs.local_contact, subs.expires, 0) < 0)
			goto error_free;
	}

	/* call sending Notify with full state */
	if (send_full_notify(&subs, service_node, subs.version, &subs.pres_uri,hash_code) < 0)
	{
		LM_ERR("while sending full state Notify\n");
		goto error_free;
	}

	/* send Subscribe requests for all in the list */
	if(resource_subscriptions(&subs, service_node)< 0)
	{
		LM_ERR("while sending Subscribe requests to resources in a list\n");
		goto error_free;
	}

	pkg_free(subs.pres_uri.s);
	if (subs.record_route.s)
		pkg_free(subs.record_route.s);
	xmlFreeDoc(doc);
	return 1;


bad_event:
	if (reply_489(msg) < 0)
		LM_ERR("failed to send 489 reply\n");
	goto error_free;

error_5xx:
	reply_code = 500;
	reply_str = pu_500_rpl;

error:
	if (rls_sigb.reply(msg, reply_code, &reply_str, 0) == -1)
		LM_ERR("failed to send %d reply\n", reply_code);

error_free:
	if (subs.pres_uri.s)
		pkg_free(subs.pres_uri.s);
	if (subs.record_route.s)
		pkg_free(subs.record_route.s);
	if (doc)
		xmlFreeDoc(doc);
	return -1;
}

/*
 * function that updates a subscription in hash table
 *	sets reply_code and reply_str in case of error and
 *	if different that server error
 * */
int update_rlsubs( subs_t* subs, unsigned int hash_code,
							int* reply_code, str* reply_str, int just_check)
{
	subs_t* s, *ps;

	/* search the record in hash table */
	lock_get(&rls_table[hash_code].lock);

	s= pres_search_shtable(rls_table, subs->callid,
			subs->to_tag, subs->from_tag, hash_code);
	if(s== NULL)
	{
		LM_DBG("record not found in hash table\n");
		lock_release(&rls_table[hash_code].lock);
		return -1;
	}

	if(just_check) {
		lock_release(&rls_table[hash_code].lock);
		return 0;
	}

	s->expires= subs->expires+ (int)time(NULL);

	if(s->db_flag == NO_UPDATEDB_FLAG)
		s->db_flag= UPDATEDB_FLAG;

	if(	s->remote_cseq>= subs->remote_cseq)
	{
		lock_release(&rls_table[hash_code].lock);
		LM_DBG("stale cseq stored cseq= %d - received cseq= %d\n", s->remote_cseq, subs->remote_cseq);
		*reply_code =  Stale_cseq_code;
		*reply_str = stale_cseq_rpl;
		return -1;
	}
	s->remote_cseq= subs->remote_cseq;

	subs->pres_uri.s= (char*)pkg_malloc(s->pres_uri.len* sizeof(char));
	if(subs->pres_uri.s== NULL)
	{
		ERR_MEM(PKG_MEM_STR);
	}
	memcpy(subs->pres_uri.s, s->pres_uri.s, s->pres_uri.len);
	subs->pres_uri.len= s->pres_uri.len;

	subs->local_cseq= s->local_cseq;
	subs->version= s->version;

	if(s->record_route.s && s->record_route.len)
	{
		subs->record_route.s= (char*)pkg_malloc(s->record_route.len);
		if(subs->record_route.s== NULL)
		{
			ERR_MEM(PKG_MEM_STR);
		}
		memcpy(subs->record_route.s, s->record_route.s, s->record_route.len);
		subs->record_route.len= s->record_route.len;
	}

	if(subs->expires== 0)
	{
		/* delete record from hash table */
		ps= rls_table[hash_code].entries;
		int found= 0;
		while(ps->next)
		{
			if(ps->next== s)
			{
				found= 1;
				break;
			}
			ps= ps->next;
		}
		if(found== 0)
		{
			LM_ERR("record not found\n");
			goto error;
		}
		ps->next= s->next;
		shm_free(s);

	/* delete from rls_presentity table also */
	}

	lock_release(&rls_table[hash_code].lock);

	return 0;

error:
	lock_release(&rls_table[hash_code].lock);
	return -1;
}

int send_resource_subs(char* uri, void* param)
{
	int duplicate = 0;
	str pres_uri;
	str *dest_uri, *tmp_str;
	subs_info_t *s = (subs_info_t *) ((void**)param)[0];
	list_entry_t **rls_contact_list = (list_entry_t **) ((void**)param)[1];
	struct socket_info *send_sock;
	union sockaddr_union dummy_su;
	static str contact;

	pres_uri.s= uri;
	pres_uri.len= strlen(uri);

	s->pres_uri= &pres_uri;

	dest_uri = s->outbound_proxy ? s->outbound_proxy : &pres_uri;

	// if we fail to get the local contact below, do not return -1 else the whole processing will stop.
	// instead report the error and return 1. this way we indicate failure but we allow sending to the
	// other URIs that are reachable to continue and only skip the URIs that are unreachable.

	send_sock = uri2sock(NULL, dest_uri, &dummy_su, PROTO_NONE);
	if (send_sock == NULL) {
		// if defined, s->outbound_proxy->s is null terminated because it is the presence_server modparam
		LM_ERR("Failed to get sending socket for %s (outbound proxy = %s)\n", uri, s->outbound_proxy ? s->outbound_proxy->s : "none");
		return 1;
	}

	if (get_local_contact(send_sock, &contact_user, &contact) < 0) {
		LM_ERR("Failed to get local contact for %s\n", uri);
		return 1;
	}

	s->contact = &contact;

	/* Build a list of uris checking each uri exists only once */
	if ((tmp_str = (str *)pkg_malloc(sizeof(str))) == NULL)
	{
		LM_ERR("out of private memory\n");
		return -1;
	}

	if ((tmp_str->s = (char *)pkg_malloc(sizeof(char) * pres_uri.len + 1)) == NULL)
	{
		pkg_free(tmp_str);
		LM_ERR("out of private memory\n");
		return -1;
	}

	memcpy(tmp_str->s, pres_uri.s, pres_uri.len);
	tmp_str->len = pres_uri.len;
	tmp_str->s[tmp_str->len] = '\0';
	*rls_contact_list = list_insert(tmp_str, *rls_contact_list, &duplicate);
	if (duplicate != 0)
	{
		LM_WARN("%.*s has %.*s multiple times in the same resource list\n",
				s->watcher_uri->len, s->watcher_uri->s,
				s->pres_uri->len, s->pres_uri->s);
		return 1;
	}

	return pua_send_subscribe(s);
}

int resource_subscriptions(subs_t* subs, xmlNodePtr rl_node)
{
	subs_info_t s;
	str wuri= {0, 0};
	str did_str= {0, 0};
	str *tmp_str;
	int cont_no= 0;
	static str ehdr= {SUBS_EXTRA_HDRS, SUBS_EXTRA_HDRS_LEN};
	list_entry_t *rls_contact_list = NULL;
	list_entry_t *rls_subs_list = NULL;
	void* params[2] = {&s, &rls_contact_list};

	/* if is initial send an initial Subscribe
	 * else search in hash table for a previous subscription */

	if(CONSTR_RLSUBS_DID(subs, &did_str)< 0)
	{
		LM_ERR("Failed to create did\n");
		return -1;
	}

	memset(&s, 0, sizeof(subs_info_t));

	if( uandd_to_uri(subs->from_user, subs->from_domain, &wuri)< 0)
	{
		LM_ERR("while constructing uri from user and domain\n");
		goto error;
	}
	s.id= did_str;
	s.watcher_uri= &wuri;
	s.to_uri.s=0;
	// s.contact will be set per destination in send_resource_subs
	s.event= get_event_flag(&subs->event->name);
	if(presence_server.s)
		s.outbound_proxy= &presence_server;
	if(s.event< 0)
	{
		LM_ERR("not recognized event\n");
		goto error;
	}
	s.expires= subs->expires;
	s.source_flag= RLS_SUBSCRIBE;
	s.extra_headers= &ehdr;
	s.internal_update_flag = subs->internal_update_flag;

	if (process_list_and_exec(rl_node, subs->from_user, subs->from_domain, send_resource_subs, params, &cont_no) < 0)
	{
		LM_ERR("while processing list\n");
		goto error;
	}

	LM_INFO("Subscription from %.*s for resource list uri %.*s expanded to %d contacts\n",
			wuri.len, wuri.s, subs->pres_uri.len, subs->pres_uri.s, cont_no);

	if (s.internal_update_flag)
	{
		s.internal_update_flag = 0;

		rls_subs_list = pua_get_subs_list(&did_str);

		while ((tmp_str = list_pop(&rls_contact_list)) != NULL)
		{
			rls_subs_list = list_remove(*tmp_str, rls_subs_list);
			pkg_free(tmp_str->s);
			pkg_free(tmp_str);
		}

		while ((tmp_str = list_pop(&rls_subs_list)) != NULL)
		{
			LM_DBG("Removing subscription for %.*s\n", tmp_str->len, tmp_str->s);
			s.expires = 0;
			send_resource_subs(tmp_str->s, params);
			pkg_free(tmp_str->s);
			pkg_free(tmp_str);
		}
	}

	if (rls_contact_list != NULL)
	{
		list_free(&rls_contact_list);
	}

	pkg_free(wuri.s);
	pkg_free(did_str.s);

	return 0;

error:
	if(wuri.s)
		pkg_free(wuri.s);
	if(did_str.s)
		pkg_free(did_str.s);
	return -1;

}

