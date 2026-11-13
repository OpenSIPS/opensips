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
 * A broker that is down when OpenSIPS starts must not keep it from
 * starting: child_init() never fails -- its failure ends the whole
 * instance, turning the outage of an eventing side-car into an outage of
 * call processing.  The process starts without a connection (or without a
 * JetStream context) and its publishes fail cleanly, counted, until the
 * broker is there.
 *
 * The suite itself is the first case: its opensips.cfg points at a port
 * nothing listens on.  The others drive the module's child_init() against
 * the fake pool of en_ut_fake.c.
 */

#include <tap.h>
#include <string.h>

#include "../../../sr_module.h"
#include "../../../mi/mi.h"
#include "../../../lib/cJSON.h"
#include "../../nats/nats_bind.h"
#include "../nats_producer.h"
#include "../nats_stats.h"
#include "../event_nats.h"

#include "en_ut.h"
#include "en_ut_stats.h"

static int s_no_connection(void)
{
	struct en_ut_counters c = en_ut_counters_now();

	ef.pool_nc = NULL;
	if (event_nats_test_child_init(1) != 0 || ef.n_pool_get != 1)
		return 0;
	if (!strstr(en_ut_log(), "starting degraded"))
		return 0;
	/* the publish fails, is counted, and reaches no libnats call */
	return nats_publish("ut.subject", "x", 1) == -1
		&& ef.n_publish == 0
		&& en_ut_counters_added(c, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0)
		&& strstr(en_ut_log(), "connection not initialized") != NULL;
}

static int s_rank_not_admitted(void)
{
	/* a process the pool does not serve: nothing asked, nothing logged */
	ef.should_init = 0;
	return event_nats_test_child_init(-4) == 0 && ef.n_pool_get == 0
		&& en_ut_log()[0] == '\0';
}

static int s_connection(void)
{
	struct en_ut_counters c = en_ut_counters_now();

	ef.pool_nc = en_ut_nc();
	return event_nats_test_child_init(1) == 0 && ef.n_pool_get == 1
		&& ef.n_pool_get_js == 0             /* jetstream is off */
		&& nats_publish("ut.subject", "x", 1) == 0 && ef.n_publish == 1
		&& en_ut_counters_added(c, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0)
		&& en_ut_log()[0] == '\0';
}

static int s_no_jetstream_context(void)
{
	struct en_ut_counters c = en_ut_counters_now();
	int saved = nats_jetstream, good;

	nats_jetstream = 1;
	ef.pool_nc = en_ut_nc();
	ef.pool_js = NULL;
	good = event_nats_test_child_init(1) == 0 && ef.n_pool_get_js == 1
		&& strstr(en_ut_log(), "JetStream publishes will fail") != NULL
		/* without a context a JetStream publish goes out as a core
		 * one: delivered, though not stored */
		&& nats_js_publish_async("ut.subject", "x", 1, NULL) == 0
		&& ef.n_js_publish == 0 && ef.n_publish == 1
		&& en_ut_counters_added(c, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0);
	nats_jetstream = saved;
	return good;
}

static int s_jetstream_context(void)
{
	int saved = nats_jetstream, good;

	nats_jetstream = 1;
	ef.pool_nc = en_ut_nc();
	ef.pool_js = en_ut_js();
	good = event_nats_test_child_init(1) == 0
		&& nats_js_publish_async("ut.subject", "x", 1, "id-1") == 0
		&& ef.n_js_publish == 1 && ef.n_publish == 0
		&& en_ut_log()[0] == '\0';
	nats_jetstream = saved;
	return good;
}

void en_ut_degraded(void)
{
	mi_response_t *resp;
	cJSON *result, *item;

	/* this very process: started by the core with the broker down */
	pass("the instance started with no broker to connect to");
	ok(!nats_api.pool_is_connected(), "...and is not connected");
	resp = mi_nats_status(NULL, NULL);
	result = resp ? cJSON_GetObjectItem(resp, "result") : NULL;
	item = result ? cJSON_GetObjectItem(result, "connected") : NULL;
	ok(item && !strcmp(item->valuestring, "no"),
		"nats_status reports it as not connected");
	if (resp)
		free_mi_response(resp);

	en_ut_run("no connection: child_init succeeds, publishes fail and are "
		"counted", s_no_connection);
	en_ut_run("a process the pool does not serve is left alone",
		s_rank_not_admitted);
	en_ut_run("a connection: publishes go out", s_connection);
	en_ut_run("jetstream=1 without a JetStream context: child_init succeeds, "
		"publishes go out as core publishes", s_no_jetstream_context);
	en_ut_run("jetstream=1 with a context: JetStream publishes",
		s_jetstream_context);
}
