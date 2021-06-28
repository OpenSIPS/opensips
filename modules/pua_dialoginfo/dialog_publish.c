/*
 * pua_dialoginfo module - sending publish with dialog info from dialog module
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
#include "../../name_alias.h"
#include "../../socket_info.h"
#include "../usrloc/usrloc.h"
#include "../usrloc/ul_callback.h"
#include "../tm/tm_load.h"
#include "../pua/pua.h"
#include "pua_dialoginfo.h"

#define PRES_ID_LEN  64

/* global modul parameters */
extern int include_callid;
extern int include_localremote;
extern int include_tags;

/* for debug purpose only */
void print_publ(publ_info_t* p)
{
	LM_DBG("publ:\n");
	LM_DBG("uri= %.*s\n", p->pres_uri->len, p->pres_uri->s);
	LM_DBG("id= %.*s\n", p->id.len, p->id.s);
	LM_DBG("expires= %d\n", p->expires);
}

static str* build_dialoginfo(str *callid, char *d_id, char *state,
		struct dlginfo_part *entity, struct dlginfo_part *peer,
		unsigned int initiator, str *localtag, str *remotetag)
{
	xmlDocPtr  doc = NULL;
	xmlNodePtr root_node = NULL;
	xmlNodePtr dialog_node = NULL;
	xmlNodePtr state_node = NULL;
	xmlNodePtr remote_node = NULL;
	xmlNodePtr local_node = NULL;
	xmlNodePtr tag_node = NULL;
	xmlNodePtr id_node = NULL;
	str *body= NULL;
	char buf[MAX_URI_SIZE+1];

	if (entity->uri.len > MAX_URI_SIZE) {
		LM_ERR("entity URI '%.*s' too long, maximum=%d\n",entity->uri.len,
				entity->uri.s, MAX_URI_SIZE);
		return NULL;
	}
    memcpy(buf, entity->uri.s, entity->uri.len);
	buf[entity->uri.len]= '\0';

	/* create the Publish body  */
	doc = xmlNewDoc(BAD_CAST "1.0");
	if(doc==0)
		return NULL;

    root_node = xmlNewNode(NULL, BAD_CAST "dialog-info");
	if(root_node==0)
		goto error;

	xmlDocSetRootElement(doc, root_node);

	xmlNewProp(root_node, BAD_CAST "xmlns", BAD_CAST "urn:ietf:params:xml:ns:dialog-info");
	xmlNewProp(root_node, BAD_CAST  "state", BAD_CAST "partial" );
	xmlNewProp(root_node, BAD_CAST "entity", BAD_CAST buf);

    /* version is set by dialoginfo_process_body() */

	/* dialog tag */
	dialog_node =xmlNewChild(root_node, NULL, BAD_CAST "dialog", NULL) ;
	if( dialog_node ==NULL)
	{
		LM_ERR("while adding child\n");
		goto error;
	}
	xmlNewProp(dialog_node, BAD_CAST "id", BAD_CAST d_id);

	if (include_callid) {
		if (callid->len > MAX_URI_SIZE) {
			LM_ERR("call-id '%.*s' too long, maximum=%d\n",
				callid->len, callid->s, MAX_URI_SIZE);
			return NULL;
		}
		memcpy(buf, callid->s, callid->len);
		buf[callid->len] =  '\0';
		xmlNewProp(dialog_node, BAD_CAST "call-id", BAD_CAST buf);
	}
	if (include_tags) {
		if (localtag && localtag->s) {
			if (localtag->len > MAX_URI_SIZE) {
				LM_ERR("localtag '%.*s' too long, maximum=%d\n", localtag->len, localtag->s, MAX_URI_SIZE);
				return NULL;
			}
		    memcpy(buf, localtag->s, localtag->len);
			buf[localtag->len]= '\0';
			xmlNewProp(dialog_node, BAD_CAST "local-tag", BAD_CAST buf);
		}
		if (remotetag && remotetag->s) {
			if (remotetag->len > MAX_URI_SIZE) {
				LM_ERR("remotetag '%.*s' too long, maximum=%d\n", remotetag->len, remotetag->s, MAX_URI_SIZE);
				return NULL;
			}
		    memcpy(buf, remotetag->s, remotetag->len);
			buf[remotetag->len]= '\0';
			xmlNewProp(dialog_node, BAD_CAST "remote-tag", BAD_CAST buf);
		}
	}

	if (initiator) {
		xmlNewProp(dialog_node, BAD_CAST "direction", BAD_CAST "initiator");
	}else {
		xmlNewProp(dialog_node, BAD_CAST "direction", BAD_CAST "recipient");
	}

	/* state tag */
	state_node = xmlNewChild(dialog_node, NULL, BAD_CAST "state", BAD_CAST state) ;
	if( state_node ==NULL)
	{
		LM_ERR("while adding child\n");
		goto error;
	}

	if (include_localremote) {
		/* remote tag*/
		remote_node = xmlNewChild(dialog_node, NULL, BAD_CAST "remote", NULL) ;
		if( remote_node ==NULL)
		{
			LM_ERR("while adding child\n");
			goto error;
		}

		if (peer->uri.len > MAX_URI_SIZE) {
			LM_ERR("peer '%.*s' too long, maximum=%d\n", peer->uri.len, peer->uri.s, MAX_URI_SIZE);
			return NULL;
		}
		memcpy(buf, peer->uri.s, peer->uri.len);
		buf[peer->uri.len]= '\0';

		id_node = xmlNewChild(remote_node, NULL, BAD_CAST "identity", BAD_CAST buf) ;
		if( id_node ==NULL)
		{
			LM_ERR("while adding child\n");
			goto error;
		}

		tag_node = xmlNewChild(remote_node, NULL, BAD_CAST "target", NULL) ;
		if( tag_node ==NULL)
		{
			LM_ERR("while adding child\n");
			goto error;
		}
		xmlNewProp(tag_node, BAD_CAST "uri", BAD_CAST buf);

		/* if a display name present - add the display name information */
		if(peer->display.s)
		{
			if(peer->display.len > MAX_URI_SIZE)
			{
				LM_ERR("display '%.*s' too long, maximum=%d\n", peer->display.len,
						peer->display.s, MAX_URI_SIZE);
				return NULL;
			}
			if(peer->display.s[0] == '"')
			{
				memcpy(buf, peer->display.s+1, peer->display.len-2);
				buf[peer->display.len-2] = '\0';
			}
			else
			{
				memcpy(buf, peer->display.s, peer->display.len);
				buf[peer->display.len] = '\0';
			}
			xmlNewProp(id_node, BAD_CAST "display", BAD_CAST buf);
		}

		/* local tag */
		local_node = xmlNewChild(dialog_node, NULL, BAD_CAST "local", NULL) ;
		if( local_node ==NULL)
		{
			LM_ERR("while adding child\n");
			goto error;
		}

		memcpy(buf, entity->uri.s, entity->uri.len);
		buf[entity->uri.len]= '\0';

		id_node = xmlNewChild(local_node, NULL, BAD_CAST "identity", BAD_CAST buf) ;
		if( id_node ==NULL)
		{
			LM_ERR("while adding child\n");
			goto error;
		}
		tag_node = xmlNewChild(local_node, NULL, BAD_CAST "target", NULL) ;
		if( tag_node ==NULL)
		{
			LM_ERR("while adding child\n");
			goto error;
		}
		xmlNewProp(tag_node, BAD_CAST "uri", BAD_CAST buf);

		/* if a display name present - add the display name information */
		if(entity->display.s)
		{
			if(entity->display.len > MAX_URI_SIZE)
			{
				LM_ERR("display '%.*s' too long, maximum=%d\n", entity->display.len,
						entity->display.s, MAX_URI_SIZE);
				return NULL;
			}
			if(entity->display.s[0] == '"')
			{
				memcpy(buf, entity->display.s+1, entity->display.len-2);
				buf[entity->display.len-2] = '\0';
			}
			else
			{
				memcpy(buf, entity->display.s, entity->display.len);
				buf[entity->display.len] = '\0';
			}

			xmlNewProp(id_node, BAD_CAST "display", BAD_CAST buf);
		}
	}

	/* create the body */
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

void dialog_publish(char *state,
	struct dlginfo_part* entity, struct dlginfo_part *peer,
	str *callid, int branch, unsigned int initiator, unsigned int lifetime,
	str *localtag, str *remotetag)
{
	str* body= NULL;
	publ_info_t publ;
	int ret_code;
	int l;
	char *p;

	memset(&publ, 0, sizeof(publ_info_t));

	/* compute the dialog id as "callid.branch" format */
	publ.id.s = pkg_malloc( callid->len + 1 + 2 + 1);
	if (publ.id.s==NULL) {
		LM_ERR("failed to allocated pkg mem\n");
		goto error;
	}
	p = publ.id.s;
	memcpy( p, callid->s, callid->len);
	p += callid->len;
	*(p++) = '.';
	l = 2; /* 2 hexa digits -> 256 branches */
	int2reverse_hex( &p, &l, branch );
	publ.id.len = p - publ.id.s;
	*(p++) = '\0';

	body= build_dialoginfo(callid, publ.id.s, state, entity, peer, initiator,
		localtag, remotetag);
	if(body == NULL || body->s == NULL)
	{
		LM_ERR("failed to construct dialoginfo body\n");
		goto error;
	}

	publ.pres_uri= &entity->uri;
	publ.body = body;

	publ.content_type.s= "application/dialog-info+xml";
	publ.content_type.len= 27;

	publ.expires= lifetime;

	/* make UPDATE_TYPE, as if this "publish dialog" is not found
	   by pua it will fallback to INSERT_TYPE anyway */
	publ.flag|= UPDATE_TYPE;

	publ.source_flag|= DIALOG_PUBLISH;
	publ.event|= DIALOG_EVENT;
	publ.extra_headers= NULL;
	publ.outbound_proxy = presence_server;

	print_publ(&publ);
	ret_code = pua_send_publish(&publ);
	switch (ret_code) {
	case ERR_PUBLISH_NO_ERROR:
	case ERR_PUBLISH_NO_RECORD:
		break;
	default:
		LM_ERR("sending publish failed for pres_uri [%.*s] to server [%.*s]\n",
			publ.pres_uri->len, publ.pres_uri->s,
			publ.outbound_proxy.len, publ.outbound_proxy.s);
	}

error:

	if(body)
	{
		if(body->s)
			xmlFree(body->s);
		pkg_free(body);
	}
	if (publ.id.s)
		pkg_free(publ.id.s);

	return;
}
