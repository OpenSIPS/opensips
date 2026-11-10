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
 * test_js_retry_policy.c -- the JetStream async publish retry policy
 * (nats_js_retry.h) and the table of the messages being retried
 * (nats_js_retry.c):
 *   - which ack errors are retried: no ack within the wait (timeout),
 *     no responders, JetStream temporarily unavailable; never a server
 *     refusal such as a message over the stream's size limit;
 *   - the number of retries is bounded by js_publish_retries;
 *   - a failed resend is reported by its cause (reconnect buffer full,
 *     too many publishes waiting for an ack, other);
 *   - the table counts the retries of each message, forgets it on its
 *     last outcome, and refuses a message when full instead of growing.
 */

#include <tap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../nats_js_retry.h"

#include "nats_ut.h"

#define ASSERT(cond, label) ok((cond), "%s", (label))

static void test_retryable(void)
{
	ASSERT(nats_js_ack_retryable(NATS_TIMEOUT, 0),
		"no ack within the wait is retried");
	ASSERT(nats_js_ack_retryable(NATS_NO_RESPONDERS, 0),
		"no responders (no JetStream answering yet) is retried");
	ASSERT(nats_js_ack_retryable(NATS_ERR, JSClusterNotAvailErr),
		"JetStream temporarily unavailable (10008) is retried");
	ASSERT(!nats_js_ack_retryable(NATS_ERR, JSStreamNotFoundErr),
		"stream not found is not retried");
	ASSERT(!nats_js_ack_retryable(NATS_ERR, JSStreamMessageExceedsMaximumErr),
		"message over the stream's size limit (10054) is not retried");
	ASSERT(!nats_js_ack_retryable(NATS_ERR, 0),
		"a server error without a code is not retried");
	ASSERT(!nats_js_ack_retryable(NATS_CONNECTION_CLOSED, 0),
		"a closed connection is not retried");
	ASSERT(!nats_js_ack_retryable(NATS_OK, 0),
		"NATS_OK is not an error to retry");
}

static void test_should_retry(void)
{
	ASSERT(nats_js_ack_should_retry(NATS_TIMEOUT, 0, 0, 3),
		"first timeout with 3 retries allowed: retry");
	ASSERT(nats_js_ack_should_retry(NATS_TIMEOUT, 0, 2, 3),
		"third timeout with 3 retries allowed: retry");
	ASSERT(!nats_js_ack_should_retry(NATS_TIMEOUT, 0, 3, 3),
		"fourth timeout with 3 retries allowed: give up");
	ASSERT(!nats_js_ack_should_retry(NATS_TIMEOUT, 0, 0, 0),
		"js_publish_retries=0: never retry");
	ASSERT(!nats_js_ack_should_retry(NATS_ERR, JSStreamMessageExceedsMaximumErr, 0, 3),
		"a non-retryable error is not retried even with retries left");
	ASSERT(!nats_js_ack_should_retry(NATS_TIMEOUT, 0, -1, 3),
		"a message the retry table refused (-1) is not retried");
}

static void test_resend_outcome(void)
{
	ASSERT(nats_js_resend_failed_outcome(NATS_INSUFFICIENT_BUFFER)
			== NATS_PUB_ACK_FAILED_BUFFER_FULL,
		"resend refused by a full reconnect buffer: buffer-full outcome");
	ASSERT(nats_js_resend_failed_outcome(NATS_TIMEOUT)
			== NATS_PUB_ACK_FAILED_PENDING_FULL,
		"resend stalled on too many pending acks: pending-full outcome");
	ASSERT(nats_js_resend_failed_outcome(NATS_ERR) == NATS_PUB_ACK_FAILED,
		"other resend errors: plain failure");
	ASSERT(NATS_PUB_ACK_FAILED == 0 && NATS_PUB_ACK_OK == 1,
		"FAILED and OK keep the values the old int callback used");
}

static void test_table(void)
{
	static int msgs[NATS_JS_RETRY_SLOTS + 4];
	int i, ok;

	ASSERT(nats_js_retry_tracked() == 0, "the table starts empty");

	ASSERT(nats_js_retry_track(&msgs[0]) == 0,
		"first retry of a message: 0 retries done before");
	ASSERT(nats_js_retry_track(&msgs[0]) == 1,
		"second retry of the same message: 1 retry done before");
	ASSERT(nats_js_retry_track(&msgs[1]) == 0,
		"another message has its own count");
	ASSERT(nats_js_retry_tracked() == 2, "two messages tracked");

	nats_js_retry_forget(&msgs[0]);
	ASSERT(nats_js_retry_tracked() == 1, "forget drops one message");
	ASSERT(nats_js_retry_track(&msgs[0]) == 0,
		"a forgotten message starts again from 0");
	nats_js_retry_forget(&msgs[0]);
	nats_js_retry_forget(&msgs[1]);
	nats_js_retry_forget(&msgs[2]);   /* never tracked: no effect */
	ASSERT(nats_js_retry_tracked() == 0, "forget of an untracked message is a no-op");

	/* fill the table */
	ok = 1;
	for (i = 0; i < NATS_JS_RETRY_SLOTS; i++)
		if (nats_js_retry_track(&msgs[i]) != 0)
			ok = 0;
	ASSERT(ok, "the table takes NATS_JS_RETRY_SLOTS messages");
	ASSERT(nats_js_retry_track(&msgs[NATS_JS_RETRY_SLOTS]) == -1,
		"a full table refuses a new message (-1) instead of growing");
	ASSERT(nats_js_retry_track(&msgs[5]) == 1,
		"a full table still counts a message it already tracks");

	/* removal keeps every other entry reachable (no lost entries after
	 * deleting from the middle of a probe run) */
	for (i = 0; i < NATS_JS_RETRY_SLOTS; i += 2)
		nats_js_retry_forget(&msgs[i]);
	ok = 1;
	for (i = 1; i < NATS_JS_RETRY_SLOTS; i += 2)
		if (nats_js_retry_track(&msgs[i]) != (i == 5 ? 2 : 1))
			ok = 0;
	ASSERT(ok, "after removing every other message the rest keep their counts");
	ASSERT(nats_js_retry_tracked() == NATS_JS_RETRY_SLOTS / 2,
		"half of the table is left");
	for (i = 1; i < NATS_JS_RETRY_SLOTS; i += 2)
		nats_js_retry_forget(&msgs[i]);
	ASSERT(nats_js_retry_tracked() == 0, "the table is empty again");
}

void nats_ut_js_retry_policy(void)
{
	test_retryable();
	test_should_retry();
	test_resend_outcome();
	test_table();

}
