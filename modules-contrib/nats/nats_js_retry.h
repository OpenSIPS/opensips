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
 * JetStream async publish retry policy.
 *
 * An async JetStream publish is sent with a wait for its ack
 * (jsPubOptions.MaxWait); libnats reports a missing ack as a NATS_TIMEOUT
 * error to the ack handler.  The pool's ack handler (nats_pool.c) resends
 * a message whose ack failed with a retryable error, at most
 * nats_pool_js_publish_retries times.  The resend is the same natsMsg, so
 * it keeps its Nats-Msg-Id header and the server drops it as a duplicate
 * when the first copy was stored after all (inside the stream's
 * duplicate window).
 *
 * The decisions are pure and header-inline so they are unit-testable
 * (test/test_js_retry_policy.c); the table of the messages being retried
 * is in nats_js_retry.c.
 */

#ifndef NATS_JS_RETRY_H
#define NATS_JS_RETRY_H

#include <nats/nats.h>

/* Defaults of the event_nats js_ack_timeout_ms / js_publish_retries
 * modparams.  4 attempts of 5 s each stay well inside the 2 minute
 * default duplicate window of a stream. */
#define NATS_JS_ACK_TIMEOUT_MS_DEFAULT   5000
#define NATS_JS_PUBLISH_RETRIES_DEFAULT  3
#define NATS_JS_PUBLISH_RETRIES_MAX      10
#define NATS_JS_ACK_TIMEOUT_MS_MIN       100
#define NATS_JS_ACK_TIMEOUT_MS_MAX       60000
/* the stream default (nats-server), for the startup warning */
#define NATS_JS_DEFAULT_DUPLICATE_WINDOW_MS  120000

/* Outcome of one ack, reported to the module's callback
 * (nats_pool_set_pub_ack_cb).  FAILED and OK keep the 0 / 1 of the
 * callback's earlier int "success" argument. */
typedef enum nats_pub_ack_outcome {
	NATS_PUB_ACK_FAILED = 0,             /* no ack, retries used up or not retryable */
	NATS_PUB_ACK_OK = 1,                 /* stored */
	NATS_PUB_ACK_DUPLICATE,              /* acked as a duplicate of a stored copy */
	NATS_PUB_ACK_RETRIED,                /* ack failed, message resent */
	NATS_PUB_ACK_FAILED_BUFFER_FULL,     /* resend refused: reconnect buffer full */
	NATS_PUB_ACK_FAILED_PENDING_FULL,    /* resend refused: too many acks pending */
} nats_pub_ack_outcome;

/* Is this ack error worth a resend?  No ack within the wait, no
 * responders (no JetStream server answering on the subject yet, e.g.
 * right after a restart) and "JetStream system temporarily unavailable"
 * are transient; any other server refusal (no stream, message too big,
 * ...) gets the same answer again. */
static inline int nats_js_ack_retryable(natsStatus err, int jerr)
{
	if (err == NATS_TIMEOUT || err == NATS_NO_RESPONDERS)
		return 1;
	if (err == NATS_ERR && jerr == JSClusterNotAvailErr)
		return 1;
	return 0;
}

/* @retries_done is what nats_js_retry_track() returned for the message:
 * the number of resends before this one, or -1 when the table could not
 * take it (then the message is not retried). */
static inline int nats_js_ack_should_retry(natsStatus err, int jerr,
		int retries_done, int max_retries)
{
	if (retries_done < 0 || retries_done >= max_retries)
		return 0;
	return nats_js_ack_retryable(err, jerr);
}

/* A resend that js_PublishMsgAsync() refused, by cause: the reconnect
 * buffer is full (NATS_INSUFFICIENT_BUFFER), or the MaxPending cap of
 * in-flight publishes stalled it past StallWait (NATS_TIMEOUT). */
static inline nats_pub_ack_outcome nats_js_resend_failed_outcome(natsStatus s)
{
	if (s == NATS_INSUFFICIENT_BUFFER)
		return NATS_PUB_ACK_FAILED_BUFFER_FULL;
	if (s == NATS_TIMEOUT)
		return NATS_PUB_ACK_FAILED_PENDING_FULL;
	return NATS_PUB_ACK_FAILED;
}

/*
 * Table of the messages being retried, keyed by the natsMsg pointer
 * (the resend reuses the same natsMsg).  Process-local, fixed size,
 * mutex-protected (the ack handler runs on a libnats thread).
 *
 * At most NATS_JS_PUBLISH_ASYNC_MAX_PENDING (4096) publishes are in
 * flight per process, so twice that many slots never fill in practice;
 * when they do, the message is not retried (counted as a failure).
 */
#define NATS_JS_RETRY_SLOTS 8192

/* Count one more retry of @msg.  Returns the retries done before this one
 * (0 the first time), or -1 when the table is full. */
int nats_js_retry_track(const void *msg);
/* Drop @msg from the table (its last outcome arrived); no-op if absent. */
void nats_js_retry_forget(const void *msg);
/* Number of messages in the table. */
int nats_js_retry_tracked(void);

#endif /* NATS_JS_RETRY_H */
