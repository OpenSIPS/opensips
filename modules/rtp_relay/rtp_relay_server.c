/*
 * Copyright (C) 2021 OpenSIPS Solutions
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
 */

#include "rtp_relay.h"
#include "../../ut.h"

OSIPS_LIST_HEAD(rtp_relays);

struct rtp_relay *rtp_relay_get(str *name)
{
	struct list_head *it;
	struct rtp_relay *relay;

	list_for_each(it, &rtp_relays) {
		relay = list_entry(it, struct rtp_relay, list);
		if (str_strcmp(name, &relay->name) == 0)
			return relay;
	}
	return NULL;
}

int rtp_relay_reg(char *name, struct rtp_relay_binds *binds)
{
	struct rtp_relay *relay;
	str name_s;

	init_str(&name_s, name);
	relay = rtp_relay_get(&name_s);
	if (relay) {
		LM_ERR("RTP relay module %s registered twice!\n", name);
		return -1;
	}
	/* if not found, add it */
	relay = pkg_malloc(sizeof *relay + name_s.len);
	if (!relay) {
		LM_ERR("oom for allocating a new RTP relay!\n");
		return -2;
	}
	relay->name.len = name_s.len;
	relay->name.s = relay->_name_s;
	memcpy(relay->name.s, name_s.s, name_s.len);
	memcpy(&relay->binds, binds, sizeof *binds);

	list_add(&relay->list, &rtp_relays);
	LM_INFO("Adding RTP relay %.*s\n", relay->name.len, relay->name.s);
	return 0;
}
