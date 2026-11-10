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
 */

/*
 * nats_srv_core.c -- the DNS SRV lookup of the nats module (nats_srv.h) through
 * the OpenSIPS core resolver (get_record(), which honours the core DNS
 * settings and the dns_cache module).  Kept apart from nats_pool.c so the
 * unit tests that link the pool without the core use their own resolver.
 */

#include <stdio.h>
#include <string.h>

#include "../../resolve.h"
#include "nats_srv.h"

int nats_srv_core_resolve(const char *qname, nats_srv_rec *out, int max,
	void *ctx);

int nats_srv_core_resolve(const char *qname, nats_srv_rec *out, int max,
	void *ctx)
{
	struct rdata *head, *rd;
	struct srv_rdata *srv;
	char name[MAX_DNS_NAME];
	int n = 0;

	(void)ctx;
	if (!qname || snprintf(name, sizeof name, "%s", qname) >= (int)sizeof name)
		return -1;
	head = get_record(name, T_SRV);
	if (!head)
		return -1;
	for (rd = head; rd && n < max; rd = rd->next) {
		if (rd->type != T_SRV || !(srv = (struct srv_rdata *)rd->rdata))
			continue;
		out[n].priority = srv->priority;
		out[n].weight = srv->weight;
		out[n].port = srv->port;
		snprintf(out[n].target, sizeof out[n].target, "%.*s",
			(int)srv->name_len, srv->name);
		n++;
	}
	free_rdata_list(head);
	return n;
}
