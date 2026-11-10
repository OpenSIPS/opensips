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
 * A snapshot of the module's publish counters (summed over the
 * processes), to assert what a scenario added to them.
 */

#ifndef EN_UT_STATS_H
#define EN_UT_STATS_H

#include "../nats_stats.h"

struct en_ut_counters {
	unsigned long published, failed, evi_published, script_published,
		js_ack_ok, js_ack_failed, js_retried, js_duplicate,
		reconnect_buf_dropped, js_pending_dropped;
};

static inline struct en_ut_counters en_ut_counters_now(void)
{
	struct en_ut_counters c;

	c.published = NATS_STATS_SUM(published);
	c.failed = NATS_STATS_SUM(failed);
	c.evi_published = NATS_STATS_SUM(evi_published);
	c.script_published = NATS_STATS_SUM(script_published);
	c.js_ack_ok = NATS_STATS_SUM(js_ack_ok);
	c.js_ack_failed = NATS_STATS_SUM(js_ack_failed);
	c.js_retried = NATS_STATS_SUM(js_retried);
	c.js_duplicate = NATS_STATS_SUM(js_duplicate);
	c.reconnect_buf_dropped = NATS_STATS_SUM(reconnect_buf_dropped);
	c.js_pending_dropped = NATS_STATS_SUM(js_pending_dropped);
	return c;
}

/* what was added since @before: all ten counters, in the order of the
 * structure */
static inline int en_ut_counters_added(struct en_ut_counters before,
	unsigned long published, unsigned long failed,
	unsigned long evi_published, unsigned long script_published,
	unsigned long js_ack_ok, unsigned long js_ack_failed,
	unsigned long js_retried, unsigned long js_duplicate,
	unsigned long reconnect_buf_dropped, unsigned long js_pending_dropped)
{
	struct en_ut_counters now = en_ut_counters_now();

	return now.published - before.published == published
		&& now.failed - before.failed == failed
		&& now.evi_published - before.evi_published == evi_published
		&& now.script_published - before.script_published == script_published
		&& now.js_ack_ok - before.js_ack_ok == js_ack_ok
		&& now.js_ack_failed - before.js_ack_failed == js_ack_failed
		&& now.js_retried - before.js_retried == js_retried
		&& now.js_duplicate - before.js_duplicate == js_duplicate
		&& now.reconnect_buf_dropped - before.reconnect_buf_dropped
			== reconnect_buf_dropped
		&& now.js_pending_dropped - before.js_pending_dropped
			== js_pending_dropped;
}

#endif /* EN_UT_STATS_H */
