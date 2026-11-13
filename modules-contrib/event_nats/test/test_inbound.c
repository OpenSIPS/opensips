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
 * Messages arriving on a subscription: each is copied into shared memory
 * and handed to a SIP worker, which raises the subscription's event.  A
 * flood must not exhaust the shared memory or queue work without bound:
 *
 *   - a payload over 1 MiB is dropped and counted (inbound_dropped_oversize);
 *   - with 4096 events on their way to the workers, further ones are
 *     dropped and counted (inbound_dropped_backpressure);
 *   - a drop is warned about once in 30 s, from the libnats thread, with a
 *     plain write(2);
 *   - whatever happens to it, the libnats message is destroyed, once.
 *
 * The module's own message callback, called as libnats calls it, with the
 * fake libnats of en_ut_fake.c as the message; the accepted events go to
 * the real worker of the test instance.
 */

#include <tap.h>
#include <string.h>
#include <unistd.h>

#include "../../nats/nats_bind.h"
#include "../event_nats_sub.h"

#include "en_ut.h"

#define MAX_DATA      (1 * 1024 * 1024)
#define MAX_INFLIGHT  4096

static nats_subscription_t *sub0(void)
{
	return &nats_subscriptions[0];
}

static void deliver(const char *subject, const char *data, int len)
{
	ef.msg_subject = subject;
	ef.msg_data = data;
	ef.msg_len = len;
	event_nats_test_msg_handler(en_ut_msg(), sub0());
}

/* the events handed to the workers are raised and freed: wait for it */
static int drained(void)
{
	int i;

	for (i = 0; i < 400 && nats_inbound_inflight() > 0; i++)
		usleep(5000);
	return nats_inbound_inflight() == 0;
}

static int s_configured(void)
{
	/* the two subscriptions of the suite's opensips.cfg */
	return nats_subscription_count == 2
		&& strcmp(nats_subscriptions[0].subject, "ut.events.>") == 0
		&& strcmp(nats_subscriptions[0].event_name, "E_NATS_UT") == 0
		&& nats_subscriptions[0].queue_group[0] == '\0'
		&& strcmp(nats_subscriptions[1].subject, "ut.work") == 0
		&& strcmp(nats_subscriptions[1].queue_group, "workers") == 0
		&& nats_subscriptions[0].event_id != EVI_ERROR
		&& nats_subscriptions[1].event_id != EVI_ERROR
		&& nats_subscriptions[0].event_id != nats_subscriptions[1].event_id;
}

static int s_accepted(void)
{
	unsigned long over = nats_inbound_dropped_oversize(),
		bp = nats_inbound_dropped_backpressure();

	if (!drained())
		return 0;
	deliver("ut.events.calls", "{\"k\":\"a\\\\b\"}", 13);
	/* destroyed once, by the callback; the event goes to a worker,
	 * which raises it and takes it off the in-flight count */
	return ef.n_msg_destroy == 1 && drained()
		&& nats_inbound_dropped_oversize() == over
		&& nats_inbound_dropped_backpressure() == bp
		&& en_ut_log()[0] == '\0';
}

static int s_odd_messages_accepted(void)
{
	unsigned long over = nats_inbound_dropped_oversize(),
		bp = nats_inbound_dropped_backpressure();
	static const char binary[] = "a\0b\\c\"\r\n\xff";

	/* no payload, no subject, a negative length, bytes that are not
	 * text: each is an event (or none), never a crash or a leak */
	deliver("ut.events.empty", NULL, 0);
	deliver("ut.events.empty", "", 0);
	deliver(NULL, "data", 4);
	deliver("ut.events.neg", "data", -5);
	deliver("ut.events.bin", binary, (int)sizeof binary - 1);
	deliver("", "", 0);
	return ef.n_msg_destroy == 6 && drained()
		&& nats_inbound_dropped_oversize() == over
		&& nats_inbound_dropped_backpressure() == bp;
}

static int s_largest_payload_accepted(void)
{
	static char big[MAX_DATA];
	unsigned long over = nats_inbound_dropped_oversize();

	memset(big, 'p', sizeof big);
	deliver("ut.events.big", big, MAX_DATA);
	return ef.n_msg_destroy == 1 && drained()
		&& nats_inbound_dropped_oversize() == over;
}

static int s_oversize_dropped(void)
{
	static char big[MAX_DATA + 1];
	unsigned long over = nats_inbound_dropped_oversize(),
		bp = nats_inbound_dropped_backpressure();
	int inflight = nats_inbound_inflight();

	event_nats_test_reset_drop_warnings();
	memset(big, 'p', sizeof big);
	deliver("ut.events.big", big, MAX_DATA + 1);
	if (ef.n_msg_destroy != 1
	    || nats_inbound_dropped_oversize() != over + 1
	    || nats_inbound_dropped_backpressure() != bp
	    || nats_inbound_inflight() != inflight
	    || !strstr(en_ut_log(), "dropping oversize NATS event"))
		return 0;
	/* the payload length is the broker's word: a huge one is dropped too */
	deliver("ut.events.big", big, 0x7fffffff);
	return ef.n_msg_destroy == 2
		&& nats_inbound_dropped_oversize() == over + 2
		&& nats_inbound_inflight() == inflight;
}

static int s_backpressure_dropped(void)
{
	unsigned long over = nats_inbound_dropped_oversize(),
		bp = nats_inbound_dropped_backpressure();
	int good;

	if (!drained())
		return 0;
	event_nats_test_reset_drop_warnings();
	/* 4096 events on their way: the workers are not keeping up */
	event_nats_test_set_inflight(MAX_INFLIGHT);
	deliver("ut.events.calls", "x", 1);
	good = ef.n_msg_destroy == 1
		&& nats_inbound_dropped_backpressure() == bp + 1
		&& nats_inbound_dropped_oversize() == over
		&& nats_inbound_inflight() == MAX_INFLIGHT
		&& strstr(en_ut_log(), "under backpressure") != NULL;
	/* far past the bound */
	event_nats_test_set_inflight(MAX_INFLIGHT * 2);
	deliver("ut.events.calls", "x", 1);
	good = good && nats_inbound_dropped_backpressure() == bp + 2
		&& nats_inbound_inflight() == MAX_INFLIGHT * 2;
	event_nats_test_set_inflight(0);
	return good;
}

static int s_one_below_the_bound_accepted(void)
{
	unsigned long bp = nats_inbound_dropped_backpressure();
	int i, good;

	if (!drained())
		return 0;
	event_nats_test_set_inflight(MAX_INFLIGHT - 1);
	deliver("ut.events.calls", "x", 1);
	/* taken: the count went up by one, and comes down by one once the
	 * worker has raised the event */
	for (i = 0; i < 400 && nats_inbound_inflight() != MAX_INFLIGHT - 1; i++)
		usleep(5000);
	good = ef.n_msg_destroy == 1
		&& nats_inbound_dropped_backpressure() == bp
		&& nats_inbound_inflight() == MAX_INFLIGHT - 1;
	event_nats_test_set_inflight(0);
	return good;
}

static int s_oversize_checked_first(void)
{
	static char big[MAX_DATA + 1];
	unsigned long over = nats_inbound_dropped_oversize(),
		bp = nats_inbound_dropped_backpressure();
	int good;

	/* both reasons at once: counted once, as oversize */
	event_nats_test_set_inflight(MAX_INFLIGHT);
	deliver("ut.events.big", big, MAX_DATA + 1);
	good = nats_inbound_dropped_oversize() == over + 1
		&& nats_inbound_dropped_backpressure() == bp;
	event_nats_test_set_inflight(0);
	return good;
}

static int s_drop_warning_rate_limited(void)
{
	static char big[MAX_DATA + 1];
	char raw[2048];
	size_t first;
	int i;

	event_nats_test_reset_drop_warnings();
	en_ut_log_clear();
	deliver("ut.events.big", big, MAX_DATA + 1);
	first = en_ut_log_raw(raw, sizeof raw);
	if (first == 0 || raw[first - 1] != '\n')
		return 0;
	/* a flood of them: every one counted, one line logged */
	for (i = 0; i < 1000; i++)
		deliver("ut.events.big", big, MAX_DATA + 1);
	if (en_ut_log_raw(raw, sizeof raw) != first || ef.n_msg_destroy != 1001)
		return 0;
	/* the two kinds of drop are limited apart */
	event_nats_test_set_inflight(MAX_INFLIGHT);
	deliver("ut.events.calls", "x", 1);
	deliver("ut.events.calls", "x", 1);
	event_nats_test_set_inflight(0);
	return en_ut_log_raw(raw, sizeof raw) > first
		&& strstr(en_ut_log(), "under backpressure") != NULL
		&& strstr(strstr(en_ut_log(), "under backpressure") + 1,
			"under backpressure") == NULL;
}

void en_ut_inbound(void)
{
	en_ut_run("the subscribe parameters are parsed and their events registered",
		s_configured);
	en_ut_run("a message is destroyed, handed to a worker and raised",
		s_accepted);
	en_ut_run("empty, subject-less, negative-length and binary messages",
		s_odd_messages_accepted);
	en_ut_run("a 1 MiB payload is accepted", s_largest_payload_accepted);
	en_ut_run("a payload over 1 MiB is dropped, counted and warned about",
		s_oversize_dropped);
	en_ut_run("with 4096 events in flight a message is dropped and counted",
		s_backpressure_dropped);
	en_ut_run("with 4095 in flight it is accepted", s_one_below_the_bound_accepted);
	en_ut_run("oversize and backpressure together: counted as oversize",
		s_oversize_checked_first);
	en_ut_run("a flood of drops logs one line per kind", s_drop_warning_rate_limited);
}
