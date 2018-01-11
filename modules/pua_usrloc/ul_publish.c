/*
 * pua_usrloc module - usrloc pua module
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
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libxml/parser.h>
#include <time.h>

#include "../../parser/parse_expires.h"
#include "../../parser/msg_parser.h"
#include "../../str.h"
#include "../../script_cb.h"
#include "../usrloc/usrloc.h"
#include "../usrloc/ul_callback.h"
#include "../tm/tm_load.h"
#include "../pua/pua.h"
#include "pua_usrloc.h"


int pul_status_idx = -1;

#define BUF_LEN   256

#define ctx_pul_set(_val) \
	context_put_int( CONTEXT_GLOBAL, current_processing_ctx, pul_status_idx, _val)

#define ctx_pul_get() \
	context_get_int( CONTEXT_GLOBAL, current_processing_ctx, pul_status_idx)


int pua_set_publish(struct sip_msg* msg , char* s1, char* s2)
{
	LM_DBG("set send publish\n");
	ctx_pul_set(1/*pua UL on*/);
	return 1;
}


/* for debug purpose only */
void print_publ(publ_info_t* p)
{
	LM_DBG("publ:\n");
	LM_DBG("uri= %.*s\n", p->pres_uri->len, p->pres_uri->s);
	LM_DBG("id= %.*s\n", p->id.len, p->id.s);
	LM_DBG("expires= %d\n", p->expires);
}

str* build_pidf(ucontact_t* c)
{
	xmlDocPtr  doc = NULL;
	xmlNodePtr root_node = NULL;
	xmlNodePtr tuple_node = NULL;
	xmlNodePtr status_node = NULL;
	xmlNodePtr basic_node = NULL;
	str *body= NULL;
	str pres_uri= {NULL, 0};
	char buf[BUF_LEN];
	char* at= NULL;

	if(c->expires< (int)time(NULL))
	{
		LM_DBG("found expired \n\n");
		return NULL;
	}

	pres_uri.s = buf;
	if(pres_prefix.s)
	{
		memcpy(pres_uri.s, pres_prefix.s, pres_prefix.len);
		pres_uri.len+= pres_prefix.len;
		memcpy(pres_uri.s+ pres_uri.len, ":", 1);
		pres_uri.len+= 1;
	}
	if(pres_uri.len + c->aor->len+ 1 > BUF_LEN)
	{
		LM_ERR("buffer size overflown\n");
		return NULL;
	}

	memcpy(pres_uri.s+ pres_uri.len, c->aor->s, c->aor->len);
	pres_uri.len+= c->aor->len;

	at = memchr(c->aor->s, '@', c->aor->len);
	if(!at)
	{
		if(pres_uri.len + 2 + default_domain.len > BUF_LEN)
		{
			LM_ERR("buffer size overflown\n");
			return NULL;
		}

		pres_uri.s[pres_uri.len++]= '@';
		memcpy(pres_uri.s+ pres_uri.len, default_domain.s, default_domain.len);
		pres_uri.len+= default_domain.len;
	}
	pres_uri.s[pres_uri.len]= '\0';

	/* create the Publish body  */
	doc = xmlNewDoc(BAD_CAST "1.0");
	if(doc==0)
		return NULL;

    root_node = xmlNewNode(NULL, BAD_CAST "presence");
	if(root_node==0)
		goto error;

	xmlDocSetRootElement(doc, root_node);

    xmlNewProp(root_node, BAD_CAST "xmlns",
			BAD_CAST "urn:ietf:params:xml:ns:pidf");
	xmlNewProp(root_node, BAD_CAST "xmlns:dm",
			BAD_CAST "urn:ietf:params:xml:ns:pidf:data-model");
	xmlNewProp(root_node, BAD_CAST  "xmlns:rpid",
			BAD_CAST "urn:ietf:params:xml:ns:pidf:rpid" );
	xmlNewProp(root_node, BAD_CAST "xmlns:c",
			BAD_CAST "urn:ietf:params:xml:ns:pidf:cipid");
	xmlNewProp(root_node, BAD_CAST "entity", BAD_CAST pres_uri.s);

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

	basic_node = xmlNewChild(status_node, NULL, BAD_CAST "basic",
		BAD_CAST "open") ;

	if( basic_node ==NULL)
	{
		LM_ERR("while adding child\n");
		goto error;
	}

	body = (str*)pkg_malloc(sizeof(str));
	if(body == NULL)
	{
		LM_ERR("while allocating memory\n");
		return NULL;
	}
	memset(body, 0, sizeof(str));

	xmlDocDumpMemory(doc,(unsigned char**)(void*)&body->s,&body->len);

	LM_DBG("new_body:\n%.*s\n",body->len, body->s);

    /*free the document */
	xmlFreeDoc(doc);
    xmlCleanupParser();

	return body;

error:
	if(doc)
		xmlFreeDoc(doc);
	return NULL;
}

void ul_contact_publish(void *binding, ul_cb_type type)
{
	ucontact_t *c = (ucontact_t *)binding;
	str* body= NULL;
	str uri= {NULL, 0};
	char* at= NULL;
	publ_info_t publ;
	int error;

	if (!(type & UL_CONTACT_EXPIRE) && ctx_pul_get()==0)
		return;

	if(type & UL_CONTACT_DELETE)
		LM_DBG("\nul_publish: DELETE type\n");
	else
		if(type & UL_CONTACT_INSERT)
			LM_DBG("\nul_publish: INSERT type\n");
		else
			if(type & UL_CONTACT_UPDATE)
				LM_DBG("\nul_publish: UPDATE type\n");
			else
				if(type & UL_CONTACT_EXPIRE)
					LM_DBG("\nul_publish: EXPIRE type\n");

	if(type & UL_CONTACT_INSERT)
	{
		body= build_pidf(c);
		if(body == NULL || body->s == NULL)
			goto error;
	}
	else
		body = NULL;

	uri.s = (char*)pkg_malloc(sizeof(char)*(c->aor->len+default_domain.len+6));
	if(uri.s == NULL)
		goto error;

	LM_DBG("aor = %.*s\n", c->aor->len, c->aor->s);

	memcpy(uri.s, "sip:", 4);
	uri.len = 4;
	memcpy(uri.s+ uri.len, c->aor->s, c->aor->len);
	uri.len+= c->aor->len;
	at = memchr(c->aor->s, '@', c->aor->len);
	if(!at)
	{
		uri.s[uri.len++]= '@';
		memcpy(uri.s+ uri.len, default_domain.s, default_domain.len);
		uri.len+= default_domain.len;
	}

	LM_DBG("uri= %.*s\n", uri.len, uri.s);

	memset(&publ, 0, sizeof(publ_info_t));
	publ.pres_uri= &uri;
	publ.body = body;
	publ.id = c->callid;
	publ.content_type.s = "application/pidf+xml";
	publ.content_type.len = 20;

	if(type & UL_CONTACT_EXPIRE || type & UL_CONTACT_DELETE)
		publ.expires= 0;
	else
		publ.expires= c->expires - (int)time(NULL);

	if(type & UL_CONTACT_INSERT)
		publ.flag= INSERT_TYPE;
	else
		publ.flag= UPDATE_TYPE;

	publ.source_flag|= UL_PUBLISH;
	publ.event|= PRESENCE_EVENT;
	publ.extra_headers= NULL;
	publ.outbound_proxy = presence_server;

	if((error = pua_send_publish(&publ))< 0)
	{
		if((type & UL_CONTACT_UPDATE) && (error== ERR_PUBLISH_NO_BODY))
		{
			LM_DBG("Usrloc Publish for update failed - try Insert\n");
			publ.body= build_pidf(c);
			if(publ.body == NULL || publ.body->s == NULL)
			{
				LM_ERR("failed to generate publish body\n");
				goto error;
			}
			publ.flag= INSERT_TYPE;

			if(pua_send_publish(&publ)< 0)
			{
			   LM_ERR("failed to send publish\n");
			}
		}
		else
			LM_ERR("failed to send publish\n");
	}

error:

	if(body)
	{
		if(body->s)
			xmlFree(body->s);
		pkg_free(body);
	}

	if(uri.s)
		pkg_free(uri.s);
	if (!(type & UL_CONTACT_EXPIRE))
		ctx_pul_set( 0/* pua UL off*/);
	return;
}
