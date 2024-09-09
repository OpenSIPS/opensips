/*
 * Copyright (C) 2011 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *
 * history:
 * ---------
 *  2011-05-xx  created (razvancrainea)
 */

#include "evi_modules.h"
#include "evi_core.h"
#include "../ut.h"
#include "evi_transport.h"
#include "event_route.h"

/* static events exported by the core */
static str evi_core_table[] = {
	CORE_EVENT_STR(THRESHOLD),
	/* FIXME - if no statistics, the EVI ids will not be working anymore,
	 * since we don't save the actual ID registered in EVI */
#ifdef STATISTICS
	CORE_EVENT_STR(SHM_THRESHOLD),
#endif
	CORE_EVENT_STR(PKG_THRESHOLD),
	CORE_EVENT_STR(PROC_AUTO_SCALE),
	CORE_EVENT_STR(TCP_DISCONNECT),
};

int evi_register_core(void)
{
	char buffer[EV_SCRIPTROUTE_MAX_SOCK];
	str sock_name;
	str event_name;
	int idx;

	int i, size = sizeof(evi_core_table) / sizeof(str);

	for (i = 0; i < size; i++) {
		if (EVI_ERROR == evi_publish_event(evi_core_table[i]))

			return -1;
	}

	if (register_event_mod(&trans_export_scriptroute)) {
		LM_ERR("cannot register transport functions for SCRIPTROUTE\n");
		return -1;
	}

	/* init the socket buffer */
	sock_name.s = buffer;
	memcpy(buffer, SCRIPTROUTE_NAME, sizeof(SCRIPTROUTE_NAME) - 1);
	buffer[sizeof(SCRIPTROUTE_NAME) - 1] = COLON_C;

	/* subscribe the route events - idx starts at 1 */
	for (idx = 1; sroutes->event[idx].a && sroutes->event[idx].name; idx++) {
		/* build the socket */
		event_name.s = sroutes->event[idx].name;
		event_name.len = strlen(sroutes->event[idx].name);

		/* first check if the event exists */
		if (evi_get_id(&event_name)<=EVI_ERROR && evi_publish_event(event_name)<=EVI_ERROR) {
			LM_ERR("Event %s not registered\n", event_name.s);
			return -1;
		}
		LM_DBG("Registering event %s\n", sroutes->event[idx].name);

		if (sizeof(SCRIPTROUTE_NAME)+event_name.len > EV_SCRIPTROUTE_MAX_SOCK) {
			LM_ERR("socket name too big %d (max: %d)\n",
				   (int)(sizeof(SCRIPTROUTE_NAME) + event_name.len),
				   EV_SCRIPTROUTE_MAX_SOCK);
			return -1;
		}
		memcpy(buffer + sizeof(SCRIPTROUTE_NAME), event_name.s, event_name.len);
		sock_name.len = event_name.len + sizeof(SCRIPTROUTE_NAME);

		/* register the subscriber - does not expire */
		if (evi_event_subscribe(event_name, sock_name, 0, 0) < 0) {
			LM_ERR("cannot subscribe to event %s\n", event_name.s);
			return -1;
		}
	}
	return 0;
}


