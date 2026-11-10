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
 * The subscriptions of the "subscribe" parameter: each becomes a libnats
 * subscription -- a queue subscription if it names a queue group -- whose
 * callback gets the subscription it belongs to.  After a reconnect the
 * consumer process looks at each one: a subscription libnats still holds
 * valid is left alone, one that did not survive is destroyed and made
 * again.
 *
 * The module's own subscribe step and reconnect check (the body of the
 * consumer process loop), against the fake libnats and pool of
 * en_ut_fake.c; and the parser of the parameter.
 */

#include <tap.h>
#include <string.h>

#include "../../../sr_module.h"
#include "../../nats/nats_bind.h"
#include "../event_nats_sub.h"

#include "en_ut.h"

/* a scratch copy of the table: the tests do not touch the configured
 * subscriptions of the consumer process's parent */
static nats_subscription_t saved[NATS_MAX_SUBSCRIPTIONS];
static int saved_count;

static void save_table(void)
{
	memcpy(saved, nats_subscriptions, sizeof saved);
	saved_count = nats_subscription_count;
}

static void restore_table(void)
{
	memcpy(nats_subscriptions, saved, sizeof saved);
	nats_subscription_count = saved_count;
}

/* ── subscribing ────────────────────────────────────────────────── */

static int s_plain_subscription(void)
{
	nats_subscription_t s;

	memset(&s, 0, sizeof s);
	strcpy(s.subject, "ut.events.>");
	return event_nats_test_subscribe_one(&s, en_ut_nc()) == NATS_OK
		&& ef.n_subscribe == 1 && ef.n_queue_subscribe == 0
		&& strcmp(ef.sub_subject, "ut.events.>") == 0
		&& ef.sub_nc == en_ut_nc()
		&& ef.sub_closure == &s && ef.sub_handler != NULL
		&& s.sub != NULL;
}

static int s_queue_subscription(void)
{
	nats_subscription_t s;

	memset(&s, 0, sizeof s);
	strcpy(s.subject, "ut.work");
	strcpy(s.queue_group, "workers");
	return event_nats_test_subscribe_one(&s, en_ut_nc()) == NATS_OK
		&& ef.n_queue_subscribe == 1 && ef.n_subscribe == 0
		&& strcmp(ef.sub_subject, "ut.work") == 0
		&& strcmp(ef.sub_queue, "workers") == 0
		&& ef.sub_closure == &s && s.sub != NULL;
}

static int s_subscribe_fails(void)
{
	nats_subscription_t s;

	memset(&s, 0, sizeof s);
	strcpy(s.subject, "ut.events.>");
	ef.subscribe_status = NATS_CONNECTION_CLOSED;
	return event_nats_test_subscribe_one(&s, en_ut_nc())
			== NATS_CONNECTION_CLOSED
		&& s.sub == NULL;
}

static int s_callback_is_the_message_handler(void)
{
	nats_subscription_t s;

	memset(&s, 0, sizeof s);
	strcpy(s.subject, "ut.events.>");
	s.event_id = nats_subscriptions[0].event_id;
	if (event_nats_test_subscribe_one(&s, en_ut_nc()) != NATS_OK)
		return 0;
	/* libnats delivers a message: it is the handler that destroys it */
	ef.msg_subject = "ut.events.x";
	ef.msg_data = "d";
	ef.msg_len = 1;
	ef.sub_handler(en_ut_nc(), s.sub, en_ut_msg(), ef.sub_closure);
	return ef.n_msg_destroy == 1;
}

/* ── after a reconnect ──────────────────────────────────────────── */

/* two subscriptions, both made on epoch 0 */
static int two_subscribed(int *seen)
{
	save_table();
	memset(nats_subscriptions, 0, 2 * sizeof nats_subscriptions[0]);
	strcpy(nats_subscriptions[0].subject, "ut.a");
	strcpy(nats_subscriptions[1].subject, "ut.b");
	strcpy(nats_subscriptions[1].queue_group, "q");
	nats_subscription_count = 2;
	ef.epoch = 0;
	*seen = 0;
	return event_nats_test_subscribe_one(&nats_subscriptions[0], en_ut_nc())
			== NATS_OK
		&& event_nats_test_subscribe_one(&nats_subscriptions[1], en_ut_nc())
			== NATS_OK;
}

static int s_no_reconnect_no_check(void)
{
	int seen, good;

	good = two_subscribed(&seen)
		&& event_nats_test_resubscribe_pass(en_ut_nc(), &seen) == 0
		&& ef.n_is_valid == 0 && ef.n_sub_destroy == 0
		&& ef.n_subscribe == 1 && ef.n_queue_subscribe == 1
		&& seen == 0;
	restore_table();
	return good;
}

static int s_reconnect_valid_left_alone(void)
{
	int seen, good;

	good = two_subscribed(&seen);
	ef.epoch = 1;
	ef.sub_valid = 1;
	good = good
		&& event_nats_test_resubscribe_pass(en_ut_nc(), &seen) == 1
		&& ef.n_is_valid == 2 && ef.n_sub_destroy == 0
		&& ef.n_subscribe == 1 && ef.n_queue_subscribe == 1
		&& seen == 1
		/* seen once: the next pass has nothing to do */
		&& event_nats_test_resubscribe_pass(en_ut_nc(), &seen) == 0
		&& ef.n_is_valid == 2;
	restore_table();
	return good;
}

static int s_reconnect_invalid_remade(void)
{
	int seen, good;

	good = two_subscribed(&seen);
	ef.epoch = 1;
	ef.sub_valid = 0;
	good = good
		&& event_nats_test_resubscribe_pass(en_ut_nc(), &seen) == 1
		/* each destroyed, then subscribed again the way it was */
		&& ef.n_sub_destroy == 2
		&& ef.n_subscribe == 2 && ef.n_queue_subscribe == 2
		&& nats_subscriptions[0].sub != NULL
		&& nats_subscriptions[1].sub != NULL
		&& strcmp(ef.sub_queue, "q") == 0
		&& ef.sub_closure == &nats_subscriptions[1]
		&& seen == 1;
	restore_table();
	return good;
}

static int s_reconnect_never_subscribed(void)
{
	int seen, good;

	/* the first subscribe had failed: no handle to destroy, but the
	 * reconnect is the occasion to try again */
	good = two_subscribed(&seen);
	nats_subscriptions[0].sub = NULL;
	ef.epoch = 1;
	ef.sub_valid = 1;
	good = good
		&& event_nats_test_resubscribe_pass(en_ut_nc(), &seen) == 1
		&& ef.n_sub_destroy == 0
		&& ef.n_subscribe == 2            /* ut.a again */
		&& ef.n_queue_subscribe == 1      /* ut.b is valid */
		&& nats_subscriptions[0].sub != NULL;
	restore_table();
	return good;
}

static int s_resubscribe_fails_retried_next_reconnect(void)
{
	int seen, good;

	good = two_subscribed(&seen);
	ef.epoch = 1;
	ef.sub_valid = 0;
	ef.subscribe_status = NATS_TIMEOUT;
	good = good
		&& event_nats_test_resubscribe_pass(en_ut_nc(), &seen) == 1
		&& ef.n_sub_destroy == 2
		&& nats_subscriptions[0].sub == NULL
		&& nats_subscriptions[1].sub == NULL
		&& strstr(en_ut_log(), "resubscribe to 'ut.a' failed") != NULL;
	/* the old handles are gone: nothing is destroyed twice */
	ef.epoch = 2;
	ef.subscribe_status = NATS_OK;
	good = good
		&& event_nats_test_resubscribe_pass(en_ut_nc(), &seen) == 1
		&& ef.n_sub_destroy == 2
		&& nats_subscriptions[0].sub != NULL
		&& nats_subscriptions[1].sub != NULL && seen == 2;
	restore_table();
	return good;
}

static int s_reconnect_during_the_check(void)
{
	int seen, good;

	/* the epoch read before the check is the one adopted: a reconnect
	 * that lands while the subscriptions are looked at is seen by the
	 * next pass */
	good = two_subscribed(&seen);
	ef.epoch = 5;
	ef.sub_valid = 1;
	ef.reconnect_in_check = 1;         /* epoch 6 while the walk runs */
	good = good && event_nats_test_resubscribe_pass(en_ut_nc(), &seen) == 1
		&& ef.epoch == 6 && seen == 5 && ef.n_is_valid == 2;
	good = good && event_nats_test_resubscribe_pass(en_ut_nc(), &seen) == 1
		&& seen == 6 && ef.n_is_valid == 4
		&& event_nats_test_resubscribe_pass(en_ut_nc(), &seen) == 0;
	restore_table();
	return good;
}

/* ── the subscribe parameter ────────────────────────────────────── */

static int parse(const char *value)
{
	return nats_consumer_parse_subscribe(STR_PARAM, (void *)value);
}

static int s_parse_good(void)
{
	nats_subscription_t *s;
	int good;

	save_table();
	nats_subscription_count = 0;
	good = parse("subject=orders.>;event=E_ORDERS") == 0
		&& parse(" subject= pay.*; event= E_PAY;queue= billing") == 0
		&& parse("queue=q;event=E_X;subject=x.y") == 0
		&& nats_subscription_count == 3;
	s = nats_subscriptions;
	good = good
		&& !strcmp(s[0].subject, "orders.>") && !strcmp(s[0].event_name, "E_ORDERS")
		&& s[0].queue_group[0] == '\0'
		&& !strcmp(s[1].subject, "pay.*") && !strcmp(s[1].event_name, "E_PAY") && !strcmp(s[1].queue_group, "billing")
		&& !strcmp(s[2].subject, "x.y") && !strcmp(s[2].queue_group, "q");
	restore_table();
	return good;
}

static int s_parse_bad(void)
{
	char long_subject[400], value[600];
	int good;

	save_table();
	nats_subscription_count = 0;
	memset(long_subject, 's', sizeof long_subject - 1);
	long_subject[sizeof long_subject - 1] = '\0';
	snprintf(value, sizeof value, "subject=%s;event=E_X", long_subject);
	good = parse(NULL) == -1 && parse("") == -1
		&& parse("event=E_X") == -1                    /* no subject */
		&& parse("subject=x") == -1                    /* no event */
		&& parse("subject=x;subject=y;event=E_X") == -1
		&& parse("subject=x;event=E_X;event=E_Y") == -1
		&& parse("subject=x;event=E_X;queue=a;queue=b") == -1
		&& parse(value) == -1                          /* 399-byte subject */
		&& parse("nonsense") == -1
		&& parse(";;;") == -1
		/* nothing of a refused value is kept */
		&& nats_subscription_count == 0;
	restore_table();
	return good;
}

static int s_parse_value_too_long(void)
{
	char value[700];
	int good;

	save_table();
	nats_subscription_count = 0;
	memset(value, 'x', sizeof value);
	memcpy(value, "subject=a;event=E_X;queue=", 26);
	value[sizeof value - 1] = '\0';
	good = parse(value) == -1 && nats_subscription_count == 0;
	restore_table();
	return good;
}

static int s_parse_limit(void)
{
	int i, good = 1;

	save_table();
	nats_subscription_count = 0;
	for (i = 0; i < NATS_MAX_SUBSCRIPTIONS; i++)
		good = good && parse("subject=x;event=E_X") == 0;
	good = good && nats_subscription_count == NATS_MAX_SUBSCRIPTIONS
		&& parse("subject=x;event=E_X") == -1
		&& nats_subscription_count == NATS_MAX_SUBSCRIPTIONS
		&& strstr(en_ut_log(), "too many subscriptions") != NULL;
	restore_table();
	return good;
}

static int s_parse_odd_bytes(void)
{
	nats_subscription_t *s = nats_subscriptions;
	int good;

	save_table();
	nats_subscription_count = 0;
	/* a backslash, a quote and an '=' inside a value are kept */
	good = parse("subject=a\\b.\"c\";event=E=X") == 0
		&& !strcmp(s[0].subject, "a\\b.\"c\"")
		&& !strcmp(s[0].event_name, "E=X");
	restore_table();
	return good;
}

void en_ut_subscription(void)
{
	/* subscribing */
	en_ut_run("a subscription without a queue: natsConnection_Subscribe",
		s_plain_subscription);
	en_ut_run("a subscription with a queue: natsConnection_QueueSubscribe",
		s_queue_subscription);
	en_ut_run("a failed subscribe leaves no handle", s_subscribe_fails);
	en_ut_run("the callback given to libnats is the message handler",
		s_callback_is_the_message_handler);

	/* after a reconnect */
	en_ut_run("no reconnect: the subscriptions are not looked at",
		s_no_reconnect_no_check);
	en_ut_run("reconnect: a subscription still valid is left alone",
		s_reconnect_valid_left_alone);
	en_ut_run("reconnect: one that did not survive is destroyed and remade",
		s_reconnect_invalid_remade);
	en_ut_run("reconnect: one that was never made is tried again",
		s_reconnect_never_subscribed);
	en_ut_run("reconnect: a failed resubscribe is retried at the next one",
		s_resubscribe_fails_retried_next_reconnect);
	en_ut_run("a reconnect during the check is seen by the next pass",
		s_reconnect_during_the_check);

	/* the subscribe parameter */
	en_ut_run("subscribe: subject, event and queue in any order, blanks "
		"before a key or a value", s_parse_good);
	en_ut_run("subscribe: missing, doubled or over-long fields are refused",
		s_parse_bad);
	en_ut_run("subscribe: a value over 511 bytes is refused",
		s_parse_value_too_long);
	en_ut_run("subscribe: at most 32", s_parse_limit);
	en_ut_run("subscribe: backslash, quote and '=' in a value are kept",
		s_parse_odd_bytes);
}
