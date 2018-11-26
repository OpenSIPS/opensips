/*
 * pua_bla module - pua Bridged Line Appearance
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
 *  2007-03-30  initial version (Anca Vamanu)
 */
#include <stdio.h>
#include <stdlib.h>

#include <libxml/parser.h>

#include "../../parser/parse_content.h"
#include "../../parser/contact/parse_contact.h"
#include "../../parser/parse_from.h"
#include "../pua/hash.h"
#include "pua_bla.h"

#define DEFAULT_EXPIRES  3600

static int bla_body_is_valid(str *bla_body)
{
	xmlDocPtr	doc = NULL;
	xmlNodePtr	node = NULL;
	xmlErrorPtr	xml_err = NULL;
	int		valid = 0;

	doc = xmlParseMemory(bla_body->s, bla_body->len);
	if (!doc)
	{
		xml_err = xmlGetLastError();
		LM_ERR("invalid body: %s", xml_err ? xml_err->message :
						"xmlParseMemory failed");
		LM_DBG("invalid body content: %.*s", bla_body->len, bla_body->s);

		goto done;
	}

	node = doc->children;
	if (!node)
	{
		LM_ERR("invalid body: no XML content\n");
		goto done;
	}
	if (node->next)
	{
		/* may only have one root dialog-info node */
		LM_ERR("invalid body: multiple root elements\n");
		goto done;
	}
	if (xmlStrcasecmp(node->name, BAD_CAST "dialog-info") != 0)
	{
		LM_ERR("invalid body: required dialog-info element "
			"not found (found <%s> instead)",
			(unsigned char *)node->name);
		goto done;
	}

	if (!node->children)
	{
		LM_DBG("valid blank dialog-info body\n");
		valid = 1;

		goto done;
	}

	for (node = node->children; node; node = node->next)
	{
		if (node->type == XML_ELEMENT_NODE &&
			xmlStrcasecmp(node->name, BAD_CAST "dialog") != 0)
		{
			break;
		}
	}
	if (node)
	{
		LM_ERR("invalid body: invalid element <%s> found",
			(unsigned char *)node->name);
		goto done;
	}

	LM_DBG("valid body\n");
	valid = 1;

done:
	if (doc)
		xmlFreeDoc(doc);

    	return valid;
}

int bla_handle_notify(struct sip_msg* msg, char* s1, char* s2)
{
	publ_info_t publ;
	struct to_body *pto= NULL, *pfrom = NULL;
	str body;
	ua_pres_t dialog;
	unsigned int expires= 0;
	struct hdr_field* hdr;
	str subs_state;
	str extra_headers= {0, 0};
	static char buf[255];
	str contact;

	memset(&publ, 0, sizeof(publ_info_t));
	memset(&dialog, 0, sizeof(ua_pres_t));

	if ( parse_headers(msg,HDR_EOH_F, 0)==-1 )
	{
		LM_ERR("parsing headers\n");
		return -1;
	}

	if( msg->to==NULL || msg->to->body.s==NULL)
	{
		LM_ERR("cannot parse TO header\n");
		return -1;
	}

	pto = get_to(msg);
	if (pto == NULL || pto->error != PARSE_OK) {
		LM_ERR("failed to parse TO header\n");
		return -1;
	}

	publ.pres_uri= &pto->uri;
	dialog.watcher_uri= publ.pres_uri;

	if (pto->tag_value.s==NULL || pto->tag_value.len==0 )
	{
		LM_ERR("NULL to_tag value\n");
		return -1;
	}
	dialog.from_tag= pto->tag_value;

	if( msg->callid==NULL || msg->callid->body.s==NULL)
	{
		LM_ERR("cannot parse callid header\n");
		return -1;
	}
	dialog.call_id = msg->callid->body;

	if (!msg->from || !msg->from->body.s)
	{
		LM_ERR("cannot find 'from' header!\n");
		return -1;
	}
	if (msg->from->parsed == NULL)
	{
		LM_DBG(" 'From' header not parsed\n");
		/* parsing from header */
		if ( parse_from_header( msg )<0 )
		{
			LM_DBG(" ERROR cannot parse From header\n");
			return -1;
		}
	}
	pfrom = (struct to_body*)msg->from->parsed;
	dialog.to_uri= pfrom->uri;

	if( pfrom->tag_value.s ==NULL || pfrom->tag_value.len == 0)
	{
		LM_ERR("no from tag value present\n");
		return -1;
	}
	if ( get_content_length(msg) == 0 )
	{
		LM_DBG("content length= 0\n");
		return 1;
	}
	else
	{
		if ( get_body(msg,&body)!=0 || body.len==0)
		{
			LM_ERR("cannot extract body from msg\n");
			return -1;
		}

		if (!bla_body_is_valid( &body ))
		{
			LM_ERR("bad XML body!\n");
			return -1;
		}
	}

	if(msg->contact== NULL || msg->contact->body.s== NULL)
	{
		LM_ERR("no contact header found\n");
		return -1;
	}
	if( parse_contact(msg->contact) <0 )
	{
		LM_ERR(" cannot parse contact header\n");
		return -1;
	}

	if(msg->contact->parsed == NULL)
	{
		LM_ERR("cannot parse contact header\n");
		return -1;
	}
	contact = ((contact_body_t* )msg->contact->parsed)->contacts->uri;

	dialog.to_tag= pfrom->tag_value;
	dialog.event= BLA_EVENT;
	dialog.flag= BLA_SUBSCRIBE;
	if(pua_is_dialog(&dialog)< 0)
	{
		LM_ERR("Notify in a non existing dialog\n");
		return -2;
	}

	/* parse Subscription-State and extract expires if existing */
	hdr = get_header_by_static_name( msg, "Subscription-State");
	if( hdr==NULL )
	{
		LM_ERR("No Subscription-State header found\n");
		return -1;
	}
	subs_state= hdr->body;
	if(strncasecmp(subs_state.s, "terminated", 10)== 0)
		expires= 0;
	else
	{
		if(strncasecmp(subs_state.s, "active", 6)== 0 ||
				strncasecmp(subs_state.s, "pending", 7)==0 )
		{
			expires = DEFAULT_EXPIRES;
			char* sep= NULL;
			str exp= {NULL, 0};
			sep= strchr(subs_state.s, ';');
			if(sep)
			{
				if(strncasecmp(sep+1, "expires=", 8)== 0)
				{
					exp.s= sep+ 9;
					sep= exp.s;
					while((*sep)>='0' && (*sep)<='9')
					{
						sep++;
						exp.len++;
					}
					if( str2int(&exp, &expires)< 0)
					{
						LM_ERR("while parsing int\n");
						return -1;
					}
				}
			}
		}
		else
		{
			LM_ERR("unknown Subscription-state token\n");
			return -1;
		}
	}

	/* +2 for ": " between header name and value */
	if ((header_name.len + 2 + contact.len + CRLF_LEN) >= sizeof(buf)) {
		LM_ERR("Sender header too large\n");
		return -1;
	}

	/* build extra_headers with Sender*/
	extra_headers.s= buf;
	memcpy(extra_headers.s, header_name.s, header_name.len);
	extra_headers.len= header_name.len;
	memcpy(extra_headers.s+extra_headers.len,": ",2);
	extra_headers.len+= 2;
	memcpy(extra_headers.s+ extra_headers.len, contact.s, contact.len);
	extra_headers.len+= contact.len;
	memcpy(extra_headers.s+ extra_headers.len, CRLF, CRLF_LEN);
	extra_headers.len+= CRLF_LEN;

	publ.id= contact;
	publ.body= &body;
	publ.source_flag= BLA_PUBLISH;
	publ.expires= expires;
	publ.event= BLA_EVENT;
	publ.extra_headers= &extra_headers;
	publ.outbound_proxy = presence_server;

	if(pua_send_publish(&publ)< 0)
	{
		LM_ERR("failed to send Publish message\n");
		return -1;
	}

	return 1;
}

