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
 * JetStream context options policy — the one place the jsOptions handed
 * to natsConnection_JetStream() are decided (used by nats_pool_get_js(),
 * behaviourally locked by test/test_js_opts_policy.c).
 */

#ifndef NATS_JS_OPTS_H
#define NATS_JS_OPTS_H

#include <nats/nats.h>

/* Cap in-flight async publishes.  Left at 0 (cnats default = unlimited)
 * a degraded-but-connected JetStream would let every event queue inside
 * cnats in each SIP worker until OOM, with no fast-fail (the connection
 * is still up).  With a cap, js_PublishAsync returns an error once the
 * queue is full — counted as a drop by the producer's `failed` stat —
 * instead of growing memory. */
#define NATS_JS_PUBLISH_ASYNC_MAX_PENDING    4096
/* A small StallWait bounds how long a full queue blocks the worker
 * before erroring. */
#define NATS_JS_PUBLISH_ASYNC_STALL_WAIT_MS  50

/**
 * Apply the shared JetStream options policy to an initialized jsOptions.
 *
 * Installs the async publish ack handler, caps PublishAsync.MaxPending,
 * sets PublishAsync.StallWait, and plumbs the per-op request timeout
 * into opts->Wait.  A non-positive @kv_op_timeout_ms leaves opts->Wait
 * untouched (the cnats 5 s default — or any pre-set value — applies).
 *
 * @param opts             jsOptions to fill; caller owns it (typically
 *                         stack-allocated) and must have initialized it
 *                         (jsOptions_Init() or zeroed).  Nothing is
 *                         allocated; no one frees anything.
 * @param ack_handler      callback installed as PublishAsync.AckHandler;
 *                         stored verbatim (NULL allowed, caller's choice).
 * @param kv_op_timeout_ms per-op JetStream/KV request timeout; only a
 *                         positive value is written to opts->Wait.
 *
 * Context: any process; pure struct fill, no locking, no NATS calls.
 */
static inline void nats_pool_js_opts_apply(jsOptions *opts,
		jsPubAckHandler ack_handler, int kv_op_timeout_ms)
{
	opts->PublishAsync.AckHandler = ack_handler;
	opts->PublishAsync.MaxPending = NATS_JS_PUBLISH_ASYNC_MAX_PENDING;
	opts->PublishAsync.StallWait  = NATS_JS_PUBLISH_ASYNC_STALL_WAIT_MS;
	if (kv_op_timeout_ms > 0)
		opts->Wait = kv_op_timeout_ms;
}

#endif /* NATS_JS_OPTS_H */
