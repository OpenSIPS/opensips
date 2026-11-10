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
 *
 */

/*
 * nats_producer.c -- NATS message publishing layer
 *
 * Provides the low-level publish functions used by the EVI transport
 * (nats_evi_raise) and the script function (nats_publish).  Supports
 * both core NATS publish and JetStream async publish.
 *
 * The NATS connection and JetStream context are set per-process by
 * child_init() in event_nats.c via the setter functions below.
 * All publish calls go through these process-local pointers.
 *
 * Statistics (published/failed counters) are updated in shared memory
 * via the nats_stats pointer from nats_stats.c.
 *
 * Disconnected: libnats keeps what is published while it reconnects in
 * its reconnect buffer (reconnect_buf_size) and sends it after the
 * reconnect.  A publish that the full buffer refuses fails with
 * NATS_INSUFFICIENT_BUFFER; it is counted in `failed` and in
 * `reconnect_buf_dropped`, never dropped silently.
 */

#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <nats/nats.h>
#include "../nats/nats_bind.h"
#include "../nats/nats_dl.h"   /* libnats function-pointer table */
#include "../nats/nats_pool.h" /* nats_pool_js_ack_timeout_ms */
#include "../../dprint.h"
#include "nats_producer.h"
#include "nats_stats.h"
#include "nats_msg_id.h"

/* Set by child_init via event_nats.c.  The nats_stats global is
 * declared extern in nats_stats.h (already included above), so we
 * don't repeat it here -- gcc's -Wredundant-decls under -Werror
 * would flag a second extern declaration in the same TU. */
static natsConnection *_nc = NULL;
static jsCtx *_js = NULL;

/**
 * nats_producer_set_connection() -- Store the per-process NATS connection.
 *
 * Called from child_init() after obtaining a connection from the pool.
 *
 * @param nc  NATS connection handle (owned by the pool, not freed here).
 */
void nats_producer_set_connection(natsConnection *nc) { _nc = nc; }

/**
 * nats_producer_set_js() -- Store the per-process JetStream context.
 *
 * Called from child_init() when JetStream is enabled.
 *
 * @param js  JetStream context handle (owned by the pool, not freed here).
 */
void nats_producer_set_js(jsCtx *js) { _js = js; }

/* Generated message ids: a random 64-bit prefix per process and a
 * sequence.  The prefix is drawn again whenever the pid changes, so a
 * process forked after a publish (the attendant publishing from
 * startup_route) never repeats its parent's ids. */
static uint64_t _id_prefix;
static uint64_t _id_seq;
static pid_t    _id_pid;

static uint64_t draw_prefix(void)
{
	uint64_t v = 0;
	int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);

	if (fd >= 0) {
		ssize_t n = read(fd, &v, sizeof v);
		close(fd);
		if (n == (ssize_t)sizeof v && v != 0)
			return v;
	}
	/* no /dev/urandom: time and pid, mixed */
	v = ((uint64_t)time(NULL) * 0x9E3779B97F4A7C15ULL) ^
		((uint64_t)getpid() << 32) ^ (uint64_t)(uintptr_t)&v;
	return v ? v : 1;
}

int nats_producer_next_msg_id(char *out, int size)
{
	pid_t me = getpid();

	if (_id_pid != me || _id_prefix == 0) {
		_id_prefix = draw_prefix();
		_id_seq = 0;
		_id_pid = me;
	}
	return nats_msg_id_generated(_id_prefix, ++_id_seq, out, size);
}

/* Count a publish that libnats refused, by cause. */
static void count_refused(natsStatus s, int jetstream)
{
	NATS_STATS_BUMP(failed);
	if (s == NATS_INSUFFICIENT_BUFFER)
		NATS_STATS_BUMP(reconnect_buf_dropped);
	else if (jetstream && s == NATS_TIMEOUT)
		/* js_PublishAsync stalled past StallWait on the MaxPending cap
		 * of publishes waiting for an ack */
		NATS_STATS_BUMP(js_pending_dropped);
}

/**
 * nats_publish() -- Publish a message via core NATS.
 *
 * Sends a message to the given subject using the process-local NATS
 * connection.  Updates shared-memory publish/fail counters on completion.
 *
 * @param subject  Null-terminated NATS subject string.
 * @param data     Message payload bytes.
 * @param len      Length of the payload in bytes.
 * @return         0 on success, -1 on error.
 */
int nats_publish(const char *subject, const void *data, int len)
{
    if (!_nc) {
        LM_ERR("NATS publish to '%s' failed: connection not initialized\n",
               subject ? subject : "(null)");
        NATS_STATS_BUMP(failed);
        return -1;
    }

    natsStatus s = nats_dl.natsConnection_Publish(_nc, subject, data, len);
    if (s != NATS_OK) {
        LM_ERR("NATS publish to '%s' failed: %s\n", subject, nats_dl.natsStatus_GetText(s));
        count_refused(s, 0);
        return -1;
    }
    NATS_STATS_BUMP(published);
    return 0;
}

/**
 * nats_js_publish_async() -- Publish a message via JetStream (async).
 *
 * Sends a message to the given subject using the process-local JetStream
 * context for async publish, with a Nats-Msg-Id header (@msg_id, or a
 * generated one) and a wait of js_ack_timeout_ms for its ack; the pool's
 * ack handler resends it if the ack fails (nats_js_retry.h).
 * Falls back to core NATS publish if the JetStream context is not set.
 *
 * @param subject  Null-terminated NATS subject string.
 * @param data     Message payload bytes.
 * @param len      Length of the payload in bytes.
 * @param msg_id   Null-terminated Nats-Msg-Id, or NULL for a generated one.
 * @return         0 on success, -1 on error.
 */
int nats_js_publish_async(const char *subject, const void *data, int len,
		const char *msg_id)
{
    char gen[NATS_MSG_ID_BUF];
    jsPubOptions po;

    if (!_js) return nats_publish(subject, data, len);

    if (!msg_id) {
        if (nats_producer_next_msg_id(gen, sizeof gen) < 0) {
            LM_ERR("JetStream async publish to '%s': cannot generate a "
                   "message id\n", subject);
            NATS_STATS_BUMP(failed);
            return -1;
        }
        msg_id = gen;
    }

    nats_dl.jsPubOptions_Init(&po);
    po.MsgId = msg_id;
    po.MaxWait = nats_pool_js_ack_timeout_ms;

    natsStatus s = nats_dl.js_PublishAsync(_js, subject, data, len, &po);
    if (s != NATS_OK) {
        LM_ERR("JetStream async publish to '%s' failed: %s\n",
               subject, nats_dl.natsStatus_GetText(s));
        count_refused(s, 1);
        return -1;
    }
    NATS_STATS_BUMP(published);
    return 0;
}
