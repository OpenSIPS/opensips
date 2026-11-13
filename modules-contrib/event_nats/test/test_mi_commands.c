/*
 * Copyright (C) 2026 OpenSIPS Solutions
 * Copyright (C) 2026 Norm Brandinger <n.brandinger@gmail.com>
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
 * The MI commands this module registers, and those it leaves to the
 * modules that own them: a name registered by two modules is answered by
 * whichever was loaded first.
 *
 *   - the JetStream consumer commands are nats_js_consumer_*:
 *     nats_consumer_* belongs to the nats_consumer module;
 *   - nats_stream_list and nats_stream_info belong to cachedb_nats; this
 *     module keeps the commands that change a stream.
 *
 * The suite loads event_nats alone, so every command found is its own.
 */

#include <tap.h>
#include <string.h>

#include "../../../mi/mi.h"

#include "en_ut.h"

static int registered(const char *name)
{
	return lookup_mi_cmd((char *)name, (int)strlen(name)) != NULL;
}

void en_ut_mi_commands(void)
{
	static const char *own[] = {
		"nats_status", "nats_stats", "nats_reconnect", "nats_account_info",
		"nats_stream_create", "nats_stream_delete", "nats_stream_purge",
		"nats_js_consumer_list", "nats_js_consumer_info",
		"nats_js_consumer_create", "nats_js_consumer_delete",
		"nats_msg_get", "nats_msg_delete",
	};
	static const char *not_own[] = {
		/* the nats_consumer module's handle commands */
		"nats_consumer_list", "nats_consumer_info",
		"nats_consumer_create", "nats_consumer_delete",
		/* cachedb_nats */
		"nats_stream_list", "nats_stream_info",
	};
	unsigned i;

	for (i = 0; i < sizeof own / sizeof own[0]; i++)
		ok(registered(own[i]), "%s is registered", own[i]);
	for (i = 0; i < sizeof not_own / sizeof not_own[0]; i++)
		ok(!registered(not_own[i]), "%s is left to its owner", not_own[i]);
}
