/*
 * pua module - presence user agent module
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
 *	initial version 2007-05-03 (anca)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libxml/parser.h>
#include "../../str.h"
#include "event_list.h"
#include "add_events.h"
#include "pua.h"
#include "pidf.h"

int pua_add_events(void)
{
	/* add presence */
	if(add_pua_event(PRESENCE_EVENT, "presence", "application/pidf+xml",
				pres_process_body)< 0)
	{
		LM_ERR("while adding event presence\n");
		return -1;
	}

	/* add dialog;sla */
	if(add_pua_event(BLA_EVENT, "dialog;sla", "application/dialog-info+xml", 0)< 0)
	{
		LM_ERR("while adding event presence\n");
		return -1;
	}

	/* add message-summary*/
	if(add_pua_event(MSGSUM_EVENT, "message-summary",
				"application/simple-message-summary", 0)< 0)
	{
		LM_ERR("while adding event presence\n");
		return -1;
	}

	/* add presence;winfo */
	if(add_pua_event(PWINFO_EVENT, "presence.winfo", 0, 0)< 0)
	{
		LM_ERR("while adding event presence\n");
		return -1;
	}

	return 0;
}

int pres_process_body(publ_info_t* publ, str** fin_body, int ver, str* tuple)
{

	xmlDocPtr doc= NULL;
	xmlNodePtr node= NULL;
	char* tuple_id= NULL, *person_id= NULL;
	static char buf[128];
	str* body= NULL;

	doc= xmlParseMemory(publ->body->s, publ->body->len );
	if(doc== NULL)
	{
		LM_ERR("while parsing xml memory\n");
		goto error;
	}

	node= xmlDocGetNodeByName(doc, "tuple", NULL);
	if(node == NULL)
	{
		LM_ERR("while extracting tuple node\n");
		goto error;
	}

	tuple_id= xmlNodeGetAttrContentByName(node, "id");
	if(tuple_id== NULL)
	{
		/* must be null terminated */
		if(tuple->s == 0)   /* generate a tuple_id */
		{
			tuple->s= buf;
			tuple->len= sprintf(tuple->s, "%p", publ);
		}
		tuple_id = buf;

		/* add tuple id */
		if(!xmlNewProp(node, BAD_CAST "id", BAD_CAST tuple_id))
		{
			LM_ERR("Failed to add xml node attribute\n");
			goto error;
		}
	}
	else
	{
		if(tuple->s == 0)   /* generate a tuple_id */
		{
			tuple->s= buf;
			tuple->len= sprintf(tuple->s, "%s", tuple_id);
		}
	}

	node= xmlDocGetNodeByName(doc, "person", NULL);
	if(node)
	{
		LM_DBG("found person node\n");
		person_id= xmlNodeGetAttrContentByName(node, "id");
		if(person_id== NULL)
		{
			if(!xmlNewProp(node, BAD_CAST "id", BAD_CAST tuple_id))
			{
				LM_ERR("while extracting xml"
						" node\n");
				goto error;
			}
		}
		else
		{
			xmlFree(person_id);
		}
	}
	body= (str*)pkg_malloc(sizeof(str));
	if(body== NULL)
	{
		LM_ERR("NO more memory left\n");
		goto error;
	}
	memset(body, 0, sizeof(str));
	xmlDocDumpMemory(doc,(xmlChar**)(void*)&body->s, &body->len);
	if(body->s== NULL || body->len== 0)
	{
		LM_ERR("while dumping xml format\n");
		goto error;
	}
	xmlFreeDoc(doc);
	doc= NULL;

	*fin_body= body;
	xmlMemoryDump();
	xmlCleanupParser();
	return 1;

error:
	if(doc)
		xmlFreeDoc(doc);
	if(body)
		pkg_free(body);
	return -1;
}


