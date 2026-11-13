/*
 * Copyright (C) 2025 OpenSIPS Solutions
 * Copyright (C) 2025 Norm Brandinger <n.brandinger@gmail.com>
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
 * Publishing the reaper's per-pass gauges (reap_last_*).
 *
 * The gauges describe the last COMPLETE pass.  A pass whose enumeration
 * failed or stopped early (broker stall, JetStream leader election) saw
 * only part of the bucket -- often nothing -- so publishing its totals
 * would report a shrunken or empty registration set.  Such a pass keeps
 * the previous gauges and counts in reap_enum_failures instead.
 */

#ifndef CACHEDB_NATS_REAP_GAUGES_H
#define CACHEDB_NATS_REAP_GAUGES_H

#include "cachedb_nats_stats.h"

struct reap_pass_gauges {
	long keys, aors, contacts, active, perm, due;
};

/* @rc: the enumeration's result (< 0: failed or partial pass);
 * @now: epoch of the pass; @ms: its duration */
static inline void reap_publish_pass(int rc, const struct reap_pass_gauges *g,
		unsigned long now, unsigned long ms)
{
	if (rc < 0) {
		NATS_CDB_STATS_INC(reap_enum_failures);
		return;
	}
	NATS_CDB_STATS_SET(reap_last_run, now);
	NATS_CDB_STATS_SET(reap_last_ms, ms);
	NATS_CDB_STATS_SET(reap_last_keys, g->keys);
	NATS_CDB_STATS_SET(reap_last_aors, g->aors);
	NATS_CDB_STATS_SET(reap_last_contacts, g->contacts);
	NATS_CDB_STATS_SET(reap_last_active, g->active);
	NATS_CDB_STATS_SET(reap_last_permanent, g->perm);
	NATS_CDB_STATS_SET(reap_last_due, g->due);
}

#endif
