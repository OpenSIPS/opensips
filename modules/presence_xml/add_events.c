/*
 * presence_xml module -
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
 *  2007-04-17  initial version (anca)
 */

/*
 *	add 3 events: presence, presence.winfo, dialog;sla
 * */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libxml/parser.h>
#include "../../parser/parse_content.h"
#include "../../data_lump_rpl.h"
#include "../../ut.h"
#include "xcap_auth.h"
#include "notify_body.h"
#include "add_events.h"
#include "presence_xml.h"
#include "pidf.h"

static str pu_415_rpl  = str_init("Unsupported media type");

/*
 * in event specific publish handling - only check is good body format
 */
int	xml_publ_handl(struct sip_msg* msg, int* sent_reply)
{
	str body= {0, 0};
	xmlDocPtr doc= NULL;

	*sent_reply= 0;

	if ( get_body(msg,&body)!=0 ) {
		LM_ERR("cannot extract body from msg\n");
		return -1;
	}
	if (body.len == 0)
		return 1;

	doc= xmlParseMemory( body.s, body.len );
	if(doc== NULL)
	{
		LM_ERR("bad body format\n");
		if( xml_sigb.reply( msg, 415, &pu_415_rpl, 0)== -1)
		{
			LM_ERR("while sending '415 Unsupported media type' reply\n");
		}
		*sent_reply = 1;
		goto error;
	}
	xmlFreeDoc(doc);
	xmlCleanupParser();
	xmlMemoryDump();
	return 1;

error:
	xmlFreeDoc(doc);
	xmlCleanupParser();
	xmlMemoryDump();
	return -1;

}

str* bla_set_version(subs_t* subs, str* body)
{
	xmlNodePtr node= NULL;
	xmlDocPtr doc= NULL;
	char* version;
	str* new_body= NULL;
	int len;

	doc= xmlParseMemory(body->s, body->len );
	if(doc== NULL)
	{
		LM_ERR("while parsing xml memory\n");
		goto error;
	}
	/* change version */
	node= xmlDocGetNodeByName(doc, "dialog-info", NULL);
	if(node == NULL)
	{
		LM_ERR("while extracting dialog-info node\n");
		goto error;
	}
	version= int2str(subs->version, &len);
	version[len]= '\0';

	LM_DBG("set version %.*s %d\n", subs->callid.len, subs->callid.s, subs->version);
	if( xmlSetProp(node, (const xmlChar *)"version",(const xmlChar*)version)== NULL)
	{
		LM_ERR("while setting version attribute\n");
		goto error;
	}
	new_body= (str*)pkg_malloc(sizeof(str));
	if(new_body== NULL)
	{
		LM_ERR("NO more memory left\n");
		goto error;
	}
	memset(new_body, 0, sizeof(str));
	xmlDocDumpMemory(doc, (xmlChar**)(void*)&new_body->s, &new_body->len);

	xmlFreeDoc(doc);

	xmlMemoryDump();
	xmlCleanupParser();
	return new_body;

error:
	if(doc)
		xmlFreeDoc(doc);
	xmlMemoryDump();
	xmlCleanupParser();
	return 0;
}

int xml_add_events(void)
{
	pres_ev_t event;

	/* constructing presence event */
	memset(&event, 0, sizeof(pres_ev_t));
	event.name.s= "presence";
	event.name.len= 8;

	event.content_type.s= "application/pidf+xml";
	event.content_type.len= 20;

	event.mandatory_body = 1;
	event.mandatory_timeout_notification = 1;
	event.type= PUBL_TYPE;
	event.req_auth= 1;
	event.apply_auth_nbody= pres_apply_auth;
	event.get_auth_status= pres_watcher_allowed;
	event.agg_nbody= presence_agg_nbody;
	event.evs_publ_handl= xml_publ_handl;
	event.free_body= free_xml_body;
	event.default_expires= 3600;
	event.get_rules_doc= pres_get_rules_doc;
	if(pres_add_event(&event)< 0)
	{
		LM_ERR("while adding event presence\n");
		return -1;
	}

	/* constructing presence.winfo event */
	memset(&event, 0, sizeof(pres_ev_t));
	event.name.s= "presence.winfo";
	event.name.len= 14;

	event.content_type.s= "application/watcherinfo+xml";
	event.content_type.len= 27;
	event.mandatory_body = 1;
	event.mandatory_timeout_notification = 1;
	event.type= WINFO_TYPE;
	event.free_body= free_xml_body;
	event.default_expires= 3600;

	if(pres_add_event(&event)< 0)
	{
		LM_ERR("while adding event presence.winfo\n");
		return -1;
	}

	/* constructing bla event */
	memset(&event, 0, sizeof(pres_ev_t));
	event.name.s= "dialog;sla";
	event.name.len= 10;

	event.mandatory_body = 1;
	event.mandatory_timeout_notification = 1;
//	event.etag_not_new= 1;
	event.evs_publ_handl= xml_publ_handl;
	event.agg_nbody= dialog_agg_nbody;
	event.content_type.s= "application/dialog-info+xml";
	event.content_type.len= 27;
	event.type= PUBL_TYPE;
	event.free_body= free_xml_body;
	event.aux_body_processing = bla_set_version;
	event.aux_free_body = free_xml_body;
	event.default_expires= 3600;
	if(pres_add_event(&event)< 0)
	{
		LM_ERR("while adding event dialog;sla\n");
		return -1;
	}

	return 0;
}


