/*
 * pua_xmpp module - presence SIP - XMPP Gateway
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
 *  2007-03-29  initial version (Anca Vamanu)
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libxml/parser.h>

#include "../../parser/msg_parser.h"
#include "../../parser/parse_from.h"
#include "../../parser/parse_to.h"
#include "../../parser/parse_content.h"
#include "../../mem/mem.h"
#include "../../ut.h"
#include "../pua/pua.h"
#include "../xmpp/xmpp.h"
#include "pua_xmpp.h"

int build_publish(xmlNodePtr pres_node, int expire);
int presence_subscribe(xmlNodePtr pres_node, int expires, int flag);

/*  the function registered as a callback in xmpp,
 *  to be called when a new message with presence type is received
 *  */

void pres_Xmpp2Sip(char *msg, int type, void *param)
{
	xmlDocPtr doc= NULL;
	xmlNodePtr pres_node= NULL;
	char* pres_type= NULL;

	doc= xmlParseMemory(msg, strlen(msg));
	if(doc == NULL)
	{
		LM_ERR("while parsing xml memory\n");
		return;
	}

	pres_node= XMLDocGetNodeByName(doc, "presence", NULL);
	if(pres_node == NULL)
	{
		LM_ERR("while getting node\n");
		goto error;
	}
	pres_type= XMLNodeGetAttrContentByName(pres_node, "type" );
	if(pres_type== NULL )
	{
		LM_DBG("type attribut not present\n");
		build_publish(pres_node, -1);
		if(presence_subscribe(pres_node, 3600, XMPP_SUBSCRIBE)< 0)
		{
				LM_ERR("when sending subscribe for presence\n");
				xmlFree(pres_type);
				goto error;
		}

		/* send subscribe after publish because in xmpp subscribe message
		 * comes only when a new contact is inserted in buddy list */
	}
	else
	if(strcmp(pres_type, "unavailable")== 0)
	{
		build_publish(pres_node, 0);
		if(presence_subscribe(pres_node, 3600, XMPP_SUBSCRIBE)< 0)
				/* else subscribe for one hour*/
		{
				LM_ERR("when unsubscribing for presence\n");
				xmlFree(pres_type);
				goto error;
		}

	}
	else
	if((strcmp(pres_type, "subscribe")==0)||
		( strcmp(pres_type, "unsubscribe")== 0)||
		 (strcmp(pres_type, "probe")== 0))
	{
		if(strcmp(pres_type, "subscribe")==0 ||
				strcmp(pres_type, "probe")== 0)
		{
		    LM_DBG("send Subscribe message (no time limit)\n");
			if(presence_subscribe(pres_node, -1,
						XMPP_INITIAL_SUBS)< 0)
			{
				LM_ERR("when sending subscribe for presence\n");
				xmlFree(pres_type);
				goto error;
			}
		}
		if(strcmp(pres_type, "unsubscribe")== 0)
		{
			if(presence_subscribe(pres_node, 0,
						XMPP_INITIAL_SUBS)< 0)
			{
				LM_ERR("when unsubscribing for presence\n");
				xmlFree(pres_type);
				goto error;
			}
		}
	}
	xmlFree(pres_type);

	//	else
	//		send_reply_message(pres_node);

	xmlFreeDoc(doc);
	xmlCleanupParser();
	xmlMemoryDump();
	return ;

error:

	if(doc)
		xmlFreeDoc(doc);
	xmlCleanupParser();
	xmlMemoryDump();

	return ;
}

str* build_pidf(xmlNodePtr pres_node, char* uri, char* resource)
{
	str* body= NULL;
	xmlDocPtr doc= NULL;
	xmlNodePtr root_node= NULL, status_node= NULL;
	xmlNodePtr node= NULL, person_node= NULL;
	xmlNodePtr tuple_node= NULL, basic_node= NULL;
	char* show_cont= NULL, *status_cont= NULL;
	char* entity= NULL;
	char* type= NULL;
	char* status= NULL;

	entity=(char*)pkg_malloc(7+ strlen(uri)*sizeof(char));
	if(entity== NULL)
	{
		LM_ERR("no more memory\n");
		goto error;
	}
	strcpy(entity, "pres:");
	memcpy(entity+5, uri+4, strlen(uri)-4);
	entity[1+ strlen(uri)]= '\0';

	doc= xmlNewDoc(BAD_CAST "1.0");
	if(doc== NULL)
	{
		LM_ERR("allocating new xml doc\n");
		goto error;
	}

	root_node = xmlNewNode(NULL, BAD_CAST "presence");
	if(root_node== 0)
	{
		LM_ERR("extracting presence node\n");
		goto error;
	}
    xmlDocSetRootElement(doc, root_node);

    xmlNewProp(root_node, BAD_CAST "xmlns",
			BAD_CAST "urn:ietf:params:xml:ns:pidf");
	xmlNewProp(root_node, BAD_CAST "xmlns:dm",
			BAD_CAST "urn:ietf:params:xml:ns:pidf:data-model");
	xmlNewProp(root_node, BAD_CAST  "xmlns:rpid",
			BAD_CAST "urn:ietf:params:xml:ns:pidf:rpid" );
	xmlNewProp(root_node, BAD_CAST "xmlns:c",
			BAD_CAST "urn:ietf:params:xml:ns:pidf:cipid");
	xmlNewProp(root_node, BAD_CAST "entity", BAD_CAST entity);

	tuple_node =xmlNewChild(root_node, NULL, BAD_CAST "tuple", NULL) ;
	if( tuple_node ==NULL)
	{
		LM_ERR("while adding child\n");
		goto error;
	}

	status_node = xmlNewChild(tuple_node, NULL, BAD_CAST "status", NULL) ;
	if( status_node ==NULL)
	{
		LM_ERR("while adding child\n");
		goto error;
	}

	type=  XMLNodeGetAttrContentByName(pres_node, "type");
	if(type== NULL)
	{
		basic_node = xmlNewChild(status_node, NULL, BAD_CAST "basic",
			BAD_CAST "open") ;
		if( basic_node ==NULL)
		{
			LM_ERR("while adding child\n");
			goto error;
		}
	}
	else
	{
		basic_node = xmlNewChild(status_node, NULL, BAD_CAST "basic",
				BAD_CAST "closed") ;
		if( basic_node ==NULL)
		{
			LM_ERR("while adding child\n");
			goto error;
		}
		goto done;
	}
	/*if no type present search for suplimentary information */
	status_cont= XMLNodeGetNodeContentByName(pres_node, "status", NULL);
	show_cont= XMLNodeGetNodeContentByName(pres_node, "show", NULL);

	if(show_cont)
	{
		if(strcmp(show_cont, "xa")== 0)
			status= "not available";
		else
			if(strcmp(show_cont, "chat")== 0)
				status= "free for chat";
		else
			if(strcmp(show_cont, "dnd")== 0)
				status= "do not disturb";
		else
			status= show_cont;
	}

	if(status_cont)
	{
		/*
		person_node= xmlNewChild(root_node, NULL, BAD_CAST "person", 0);
		if(person_node== NULL)
		{
			LM_ERR("while adding node\n");
			goto error;
		}
		*/
		node = xmlNewChild(root_node, NULL, BAD_CAST "note",
				BAD_CAST status_cont);
		if(node== NULL)
		{
			LM_ERR("while adding node\n");
			goto error;
		}
	}else
		if(show_cont)
		{
			node = xmlNewChild(root_node, NULL, BAD_CAST "note",
					BAD_CAST status);
			if(node== NULL)
			{
				LM_ERR("while adding node\n");
				goto error;
			}
		}

	if(show_cont)
	{
		LM_DBG("show_cont= %s\n", show_cont);
		if(person_node== NULL)
		{
			person_node= xmlNewChild(root_node, NULL, BAD_CAST "person",0 );
			if(person_node== NULL)
			{
				LM_ERR("while adding node\n");
				goto error;
			}
		}
		node=  xmlNewChild(person_node, NULL, BAD_CAST "activities",
				BAD_CAST 0);
		if(node== NULL)
		{
			LM_ERR("while adding node\n");
			goto error;
		}


		if( xmlNewChild(person_node, NULL, BAD_CAST "note",
					BAD_CAST status )== NULL)
		{
			LM_ERR("while adding node\n");
			goto error;
		}


	}


done:
	body= (str* )pkg_malloc(sizeof(str));
	if(body== NULL)
	{
		LM_ERR("no more memory\n");
		goto error;
	}
	xmlDocDumpMemory(doc,(xmlChar**)(void*)&body->s, &body->len);

	if(entity)
		pkg_free(entity);
	if(status_cont)
		xmlFree(status_cont);
	if(show_cont)
		xmlFree(show_cont);
	if(type)
		xmlFree(type);
	xmlFreeDoc(doc);

	return body;

error:
	if(entity)
		pkg_free(entity);
	if(status_cont)
		xmlFree(status_cont);
	if(show_cont)
		xmlFree(show_cont);
	if(type)
		xmlFree(type);
	if(doc)
		xmlFreeDoc(doc);

	return NULL;
}


int build_publish(xmlNodePtr pres_node, int expires)
{
	str* body= NULL;
	publ_info_t publ;
	char* resource= NULL;
	str pres_uri= {0, 0};
	char* slash;
	char buf[256];
	char* uri;

	uri = XMLNodeGetAttrContentByName(pres_node, "from");
	if(uri == NULL)
	{
		LM_DBG("getting 'from' attribute\n");
		return -1;
	}

	ENC_SIP_URI(pres_uri, buf, uri);
	xmlFree(uri);

	slash= memchr(pres_uri.s, '/', pres_uri.len);
	if(slash)
	{
		pres_uri.len= slash- pres_uri.s;
		resource= (char*)pkg_malloc((strlen(pres_uri.s)-pres_uri.len)*sizeof(char));
		if(resource== NULL)
		{
			LM_ERR("no more memory\n");
			return -1;
		}
		strcpy(resource, slash+1);
	}

	body= build_pidf(pres_node, pres_uri.s, resource);
	if(body== NULL)
	{
		LM_ERR("while constructing PUBLISH body\n");
		goto error;
	}

	/* construct the publ_info_t structure */

	memset(&publ, 0, sizeof(publ_info_t));
	publ.pres_uri= &pres_uri;

	publ.body= body;

	LM_DBG("Publish for [%s]  body:\n %.*s - %d\n", pres_uri.s, publ.body->len,
			publ.body->s, publ.body->len);

	publ.source_flag|= XMPP_PUBLISH;
	publ.expires= expires;
	publ.event= PRESENCE_EVENT;
	publ.extra_headers= NULL;
	publ.outbound_proxy = presence_server;

	if( pua_send_publish(&publ)< 0)
	{
		LM_ERR("while sending publish\n");
		goto error;
	}

	if(resource)
		pkg_free(resource);
	if(body)
	{
		if(body->s)
			xmlFree(body->s);
		pkg_free(body);
	}

	return 0;

error:

	if(resource)
		pkg_free(resource);

	if(body)
	{
		if(body->s)
			xmlFree(body->s);
		pkg_free(body);
	}

	return -1;

}

int presence_subscribe(xmlNodePtr pres_node, int expires,int  flag)
{
	subs_info_t subs;
	char *uri= NULL;
 	str to_uri= {0, 0};
 	str from_uri= {0, 0};
 	char buf_from[256];

	uri= XMLNodeGetAttrContentByName(pres_node, "to");
	if(uri== NULL)
	{
		LM_ERR("failed to get to attribute from xml doc\n");
		return -1;
	}
	to_uri.s = xmpp_uri_xmpp2sip(uri, &to_uri.len);
	if(to_uri.s == 0)
	{
		LM_ERR("failed to get from attribute from xml doc\n");
		goto error;
	}
 	xmlFree(uri);

 	uri= XMLNodeGetAttrContentByName(pres_node, "from");
 	if(uri == NULL)
 	{
 		LM_ERR("failed to get from attribute from xml doc\n");
 		goto error;
 	}

 	ENC_SIP_URI(from_uri, buf_from, uri);
 	xmlFree(uri);

	memset(&subs, 0, sizeof(subs_info_t));

	subs.pres_uri= &to_uri;
	subs.watcher_uri= &from_uri;
	subs.contact= &server_address;
	if(presence_server.s)
		subs.outbound_proxy = &presence_server;
	/*
	type= XMLNodeGetAttrContentByName(pres_node, "type" );
	if(strcmp(type, "subscribe")==0 ||strcmp(type, "probe")== 0)
		subs->flag|= INSERT_TYPE;
	else
		if(strcmp(type, "unsubscribe")== 0)
			subs->flag|= UPDATE_TYPE;
	xmlFree(type);
	type= NULL;
	*/

	subs.source_flag|= flag;
	subs.event= PRESENCE_EVENT;
	subs.expires= expires;

	if(presence_server.s && presence_server.len)
		subs.outbound_proxy = &presence_server;

	LM_DBG("XMPP subscription to [%.*s] , from [%.*s], expires= [%d]\n",
			subs.pres_uri->len,  subs.pres_uri->s,
			subs.watcher_uri->len,  subs.watcher_uri->s, expires);
	if(subs.outbound_proxy)
		LM_DBG("outbound_proxy= %.*s\n", subs.outbound_proxy->len,  subs.outbound_proxy->s);

	if(pua_send_subscribe(&subs)< 0)
	{
		LM_ERR("while sending SUBSCRIBE\n");
		goto error;
	}
	return 0;

error:
	return -1;
}

