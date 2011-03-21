/*
 * Add "call-info" event to presence module
 *
 * Copyright (C) 2010 Ovidiu Sas
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 *  2010-03-11  initial version (osas)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../parser/parse_call_info.h"
#include "../presence/event_list.h"
#include "presence_callinfo.h"


extern int call_info_timeout_notification;
extern int line_seize_timeout_notification;


static str extra_hdrs[] = {
	str_init("Call-Info"),
	{NULL,0},
};

static str dummy_header=str_init("Call-Info: <sip:localhost>;appearance-index=*;appearance-state=idle\r\n");

/*
 * event specific publish handling - check if body format is ok
 */
int callinfo_publ_handl(struct sip_msg* msg, int* sent_reply)
{
    if (parse_headers(msg,HDR_EOH_F, 0) == -1) {
	LM_ERR("parsing headers\n");
	return -1;
    }

    if (!msg->call_info)
    {
	LM_ERR("No 'Call-Info' header\n");
	return -1;
    }
    if (0 != parse_call_info_header(msg)) {
	LM_ERR("Unable to parse Call-Info\n");
	return -1;
    }

    return 1;
}

/*
 * event specific publish handling - check if body format is ok
 */
int lineseize_publ_handl(struct sip_msg* msg, int* sent_reply)
{       
    if ( parse_headers(msg,HDR_EOH_F, 0)==-1 ) {
	LM_ERR("parsing headers\n");
	return -1;
    }

    if (!msg->call_info)
    {
	LM_ERR("No 'Call-Info' header\n");
	return -1;
    }

    return 1;
}

/*
 * event specific extra headers builder - for empty notifications
 */
str* build_callinfo_dumy_header(str* pres_uri, str* extra_hdrs)
{
	if (extra_hdrs->s == NULL)
	{
		extra_hdrs->s = (char*)pkg_malloc(dummy_header.len);
		if (extra_hdrs->s == NULL)
		{
			LM_ERR("oom: no dummy header\n");
			return NULL;
		}
		memcpy(extra_hdrs->s, dummy_header.s, dummy_header.len);
		extra_hdrs->len = dummy_header.len;
	}
	return NULL;
}

int callinfo_add_events(void)
{
	pres_ev_t event;

	/* constructing call-info event */
	memset(&event, 0, sizeof(pres_ev_t));
	event.name.s = "call-info";
	event.name.len = 9;

	event.extra_hdrs = extra_hdrs;

	event.default_expires= 3600;
	event.mandatory_timeout_notification = call_info_timeout_notification;
	event.type = PUBL_TYPE;
	event.evs_publ_handl = callinfo_publ_handl;

	/* register the dummy Call-Info header builder */
	event.build_empty_pres_info = build_callinfo_dumy_header;


	if (pres_add_event(&event) < 0) {
		LM_ERR("failed to add event \"call-info\"\n");
		return -1;
	}

	/* constructing line-seize-info event */
	memset(&event, 0, sizeof(pres_ev_t));
	event.name.s = "line-seize";
	event.name.len = 10;

	event.default_expires= 15;
	event.mandatory_timeout_notification = line_seize_timeout_notification;
	event.type = PUBL_TYPE;
	event.evs_publ_handl = lineseize_publ_handl;

	if (pres_add_event(&event) < 0) {
		LM_ERR("failed to add event \"line-seize\"\n");
		return -1;
	}

	return 0;
}

