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
 * What the shared pool's JetStream ack handler does with each ack: a
 * stored message (or a duplicate of a stored one) is reported and
 * destroyed; a message whose ack did not arrive in time, or that no
 * JetStream server answered, is resent -- the same natsMsg, so with the
 * same Nats-Msg-Id header, and with the ack wait again -- at most
 * js_publish_retries times, then reported as failed; a resend that
 * libnats refuses is reported by its cause.
 *
 * The real pool (nats_pool.c, nats_js_retry.c) against the fake libnats
 * of nats_ut_fake.c; the handler is the one nats_pool_get_js() installs
 * in the jsOptions.  The libnats thread that calls it in production is
 * not needed: the handler is called directly, as libnats would.
 */

#include <tap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../nats_pool.h"
#include "../nats_js_retry.h"

#include "nats_ut.h"
#include "nats_ut_fake.h"

/* ── module callback: records the outcomes ─────────────────────── */

static int outcomes[8];
static int last_outcome = -1;
static void ack_cb(int outcome)
{
	if (outcome >= 0 && outcome < 8)
		outcomes[outcome]++;
	last_outcome = outcome;
}

#define ASSERT(c, m) ok((c), "%s", (m))

/* one ack, as libnats delivers it: pa on success, pae on error */
static void ack_ok(int i, bool duplicate)
{
	jsPubAck pa;

	memset(&pa, 0, sizeof pa);
	pa.Stream = "S";
	pa.Sequence = 1;
	pa.Duplicate = duplicate;
	nf.ack_handler((jsCtx *)nats_ut_fake_obj(), (natsMsg *)&nf.msgs[i], &pa, NULL, NULL);
}

static void ack_err(int i, natsStatus err, int jerr)
{
	jsPubAckErr pae;

	memset(&pae, 0, sizeof pae);
	pae.Err = err;
	pae.ErrCode = (jsErrCode)jerr;
	pae.ErrText = "fake error";
	nf.ack_handler((jsCtx *)nats_ut_fake_obj(), (natsMsg *)&nf.msgs[i], NULL, &pae, NULL);
}

static void reset(void)
{
	memset(outcomes, 0, sizeof outcomes);
	memset(nf.destroyed, 0, sizeof nf.destroyed);
	nf.n_resend = 0;
	nf.last_resent = NULL;
	nf.last_maxwait = -1;
	nf.last_msgid = "unset";
	last_outcome = -1;
	nf.resend_status = NATS_OK;
}

void nats_ut_pool_js_ack(void)
{
	int i;

	nats_ut_begin();
	nats_pool_js_ack_timeout_ms = 700;
	nats_pool_js_publish_retries = 3;
	nats_pool_set_pub_ack_cb(ack_cb);

	if (nats_pool_register("nats://127.0.0.1:4222", "test", 2000, 3) != 0 ||
	    !nats_pool_get() || !nats_pool_get_js() || !nf.ack_handler) {
		nats_ut_end();
		fail("pool setup: the ack handler was not installed");
		return;
	}

	/* stored and duplicate acks */
	reset();
	ack_ok(0, false);
	ASSERT(last_outcome == NATS_PUB_ACK_OK, "a positive ack reports OK");
	ASSERT(nf.destroyed[0] == 1 && nf.n_resend == 0, "...and destroys the message, no resend");
	reset();
	ack_ok(0, true);
	ASSERT(last_outcome == NATS_PUB_ACK_DUPLICATE,
		"an ack flagged duplicate reports DUPLICATE");
	ASSERT(nf.destroyed[0] == 1 && nf.n_resend == 0, "...and destroys the message");

	/* a missing ack is retried, bounded */
	reset();
	ack_err(1, NATS_TIMEOUT, 0);
	ASSERT(nf.n_resend == 1 && nf.last_resent == (natsMsg *)&nf.msgs[1],
		"a timed-out ack resends the same natsMsg");
	ASSERT(nf.last_maxwait == 700, "the resend waits js_ack_timeout_ms for its ack");
	ASSERT(nf.last_msgid == NULL,
		"the resend sets no new MsgId (the message keeps its Nats-Msg-Id header)");
	ASSERT(last_outcome == NATS_PUB_ACK_RETRIED && nf.destroyed[1] == 0,
		"...reports RETRIED and leaves the message to libnats");
	ack_err(1, NATS_TIMEOUT, 0);
	ack_err(1, NATS_TIMEOUT, 0);
	ASSERT(nf.n_resend == 3 && outcomes[NATS_PUB_ACK_RETRIED] == 3,
		"three timeouts, three resends (js_publish_retries=3)");
	ack_err(1, NATS_TIMEOUT, 0);
	ASSERT(nf.n_resend == 3, "the fourth timeout is not resent");
	ASSERT(last_outcome == NATS_PUB_ACK_FAILED && nf.destroyed[1] == 1,
		"...reports FAILED and destroys the message");
	ASSERT(nats_js_retry_tracked() == 0, "...and the retry table forgets it");

	/* a retried message that is then stored */
	reset();
	ack_err(2, NATS_NO_RESPONDERS, 0);
	ASSERT(nf.n_resend == 1 && last_outcome == NATS_PUB_ACK_RETRIED,
		"no responders is resent");
	ack_ok(2, true);
	ASSERT(last_outcome == NATS_PUB_ACK_DUPLICATE && nf.destroyed[2] == 1,
		"the resend acked as a duplicate reports DUPLICATE");
	ASSERT(nats_js_retry_tracked() == 0, "...and the retry table forgets it");
	reset();
	ack_err(2, NATS_ERR, JSClusterNotAvailErr);
	ASSERT(nf.n_resend == 1, "JetStream temporarily unavailable is resent");
	ack_ok(2, false);
	ASSERT(nats_js_retry_tracked() == 0 && nf.destroyed[2] == 1,
		"stored after a resend: forgotten and destroyed");
	reset();
	for (i = 0; i < 3; i++)
		ack_err(2, NATS_TIMEOUT, 0);
	ack_ok(2, false);
	ack_err(2, NATS_TIMEOUT, 0);
	ASSERT(nf.n_resend == 4,
		"a message stored after its retries starts a fresh count if reused");
	ack_ok(2, false);

	/* errors that are not retried */
	reset();
	ack_err(3, NATS_ERR, JSStreamMessageExceedsMaximumErr);
	ASSERT(nf.n_resend == 0 && last_outcome == NATS_PUB_ACK_FAILED &&
		nf.destroyed[3] == 1, "message too big: FAILED, not resent");
	reset();
	ack_err(3, NATS_ERR, JSStreamNotFoundErr);
	ASSERT(nf.n_resend == 0 && last_outcome == NATS_PUB_ACK_FAILED,
		"no stream: FAILED, not resent");

	/* a resend that libnats refuses */
	reset();
	nf.resend_status = NATS_INSUFFICIENT_BUFFER;
	ack_err(0, NATS_TIMEOUT, 0);
	ASSERT(nf.n_resend == 1 && last_outcome == NATS_PUB_ACK_FAILED_BUFFER_FULL,
		"reconnect buffer full: FAILED_BUFFER_FULL");
	ASSERT(nf.destroyed[0] == 1 && nats_js_retry_tracked() == 0,
		"...the message is destroyed and forgotten");
	reset();
	nf.resend_status = NATS_TIMEOUT;
	ack_err(0, NATS_TIMEOUT, 0);
	ASSERT(last_outcome == NATS_PUB_ACK_FAILED_PENDING_FULL && nf.destroyed[0] == 1,
		"too many acks pending: FAILED_PENDING_FULL");
	reset();
	nf.resend_status = NATS_CONNECTION_CLOSED;
	ack_err(0, NATS_TIMEOUT, 0);
	ASSERT(last_outcome == NATS_PUB_ACK_FAILED && nf.destroyed[0] == 1,
		"any other refusal: FAILED");
	ASSERT(nats_js_retry_tracked() == 0, "nothing left in the retry table");

	/* js_publish_retries=0 */
	reset();
	nats_pool_js_publish_retries = 0;
	ack_err(1, NATS_TIMEOUT, 0);
	ASSERT(nf.n_resend == 0 && last_outcome == NATS_PUB_ACK_FAILED &&
		nf.destroyed[1] == 1, "a timeout is FAILED at once");

	/* no module callback */
	reset();
	nats_pool_set_pub_ack_cb(NULL);
	ack_ok(0, false);
	ASSERT(nf.destroyed[0] == 1 && last_outcome == -1,
		"without a callback the message is still destroyed");

	nats_ut_end();
}
