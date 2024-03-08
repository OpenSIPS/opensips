/*
 * pua_reginfo module - Presence-User-Agent Handling of reg events
 *
 * Copyright (C) 2011, 2023 Carsten Bock, carsten@ng-voice.com
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

#include "subscribe.h"
#include "../../pvar.h"
#include "../../mod_fix.h"
#include "../pua/send_subscribe.h"
#include "../pua/pua.h"
#include "pua_reginfo.h"

int reginfo_subscribe(struct sip_msg *msg, str * uri_str, int expires)
{
	subs_info_t subs;

	if(pua.send_subscribe == NULL) {
		LM_ERR("Not bound to PUA, unable to send SUBSCRIBE\n");
		return -1;
	}

	LM_DBG("Subscribing to %.*s\n", uri_str->len, uri_str->s);

	memset(&subs, 0, sizeof(subs_info_t));

	subs.remote_target = uri_str;
	subs.pres_uri = uri_str;
	subs.watcher_uri = &server_address;
	subs.expires = expires;

	subs.source_flag = REGINFO_SUBSCRIBE;
	subs.event = REGINFO_EVENT;
	subs.contact = &server_address;

	if(outbound_proxy.s && outbound_proxy.len)
		subs.outbound_proxy = &outbound_proxy;

	subs.flag |= UPDATE_TYPE;

	if(pua.send_subscribe(&subs) < 0) {
		LM_ERR("while sending subscribe\n");
	}

	return 1;
}