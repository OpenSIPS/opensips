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
 *  2007-03-29  initial version (anca)
 */

#include <stdio.h>
#include <stdlib.h>
#include <libxml/parser.h>

#include "pua_xmpp.h"
#include "request_winfo.h"

#define PRINTBUF_SIZE 256

int request_winfo(struct sip_msg* msg, str* uri, int* expires)
{
	subs_info_t subs;
	struct sip_uri puri;

	memset(&puri, 0, sizeof(struct sip_uri));
	if(parse_uri(uri->s, uri->len, &puri)!=0)
	{
		LM_ERR("bad owner SIP address!\n");
		goto error;
	} else
	{
		LM_DBG("using user id [%.*s]\n", uri->len, uri->s);
	}
	if(puri.user.len<=0 || puri.user.s==NULL
			|| puri.host.len<=0 || puri.host.s==NULL)
	{
		LM_ERR("bad owner URI!\n");
		goto error;
	}

	memset(&subs, 0, sizeof(subs_info_t));

	subs.pres_uri= uri;

	subs.watcher_uri= uri;

	subs.contact= &server_address;

	if(presence_server.s && presence_server.len)
		subs.outbound_proxy = &presence_server;

	if (*expires == 0)
		subs.expires= 0;
	else
		subs.expires= -1;	
	/* -1 - for a subscription with no time limit */
	/*  0  -for unsubscribe */

	subs.source_flag |= XMPP_SUBSCRIBE;
	subs.event= PWINFO_EVENT;
	if(presence_server.s && presence_server.len)
		subs.outbound_proxy = &presence_server;

	if(pua_send_subscribe(&subs)< 0)
	{
		LM_ERR("while sending subscribe\n");
		goto error;
	}

	return 1;

error:
	return 0;
}

