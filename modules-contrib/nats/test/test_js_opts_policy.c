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
 * Behavioural test: nats_pool_js_opts_apply() is the single place the
 * JetStream context options policy lives (modules-contrib/nats/nats_js_opts.h);
 * nats_pool_get_js() applies it to the jsOptions it hands cnats.
 *
 * Policy under test, on a real cnats jsOptions struct:
 *   - PublishAsync.MaxPending is capped (a degraded-but-connected
 *     JetStream must not queue unbounded async publishes per worker);
 *   - PublishAsync.StallWait is small and non-zero (a full queue errors
 *     out quickly instead of blocking the SIP worker);
 *   - the ack handler is installed as given;
 *   - Wait is set from kv_op_timeout_ms only when positive — 0/negative
 *     leave the field untouched (cnats default applies), so a pre-set
 *     value survives a disabled timeout.
 *
 * Replaces the source-pattern tests test_js_pending_cap.c and
 * test_kv_op_timeout.c (they grepped nats_pool.c for code shapes).
 *
 * Build:
 *   gcc -g -O0 -fsanitize=address -Wall -I.. \
 *       -o test_js_opts_policy test_js_opts_policy.c
 */

#include <tap.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#include <nats/nats.h>

#include "../nats_js_opts.h"

#include "nats_ut.h"

#define ASSERT(cond, label) ok((cond), "%s", (label))

static void _dummy_ack(jsCtx *js, natsMsg *msg, jsPubAck *pa,
		jsPubAckErr *pae, void *closure)
{
	(void)js; (void)msg; (void)pa; (void)pae; (void)closure;
}

void nats_ut_js_opts_policy(void)
{
	jsOptions o;

	/* nominal: handler installed, cap + stall set, timeout plumbed */
	memset(&o, 0, sizeof(o));
	nats_pool_js_opts_apply(&o, _dummy_ack, 750);
	ASSERT(o.PublishAsync.AckHandler == _dummy_ack, "ack handler installed");
	ASSERT(o.PublishAsync.MaxPending == NATS_JS_PUBLISH_ASYNC_MAX_PENDING,
		"MaxPending capped at the policy constant");
	ASSERT(o.PublishAsync.MaxPending > 0, "cap is a real bound (not 0/unlimited)");
	ASSERT(o.PublishAsync.StallWait == NATS_JS_PUBLISH_ASYNC_STALL_WAIT_MS,
		"StallWait set to the policy constant");
	ASSERT(o.PublishAsync.StallWait > 0 && o.PublishAsync.StallWait <= 1000,
		"StallWait small and non-zero (fast-fail, not a worker stall)");
	ASSERT(o.Wait == 750, "positive kv_op_timeout_ms lands in jsOpts.Wait");

	/* timeout 0: Wait untouched (cnats default applies) */
	memset(&o, 0, sizeof(o));
	nats_pool_js_opts_apply(&o, _dummy_ack, 0);
	ASSERT(o.Wait == 0, "timeout 0 leaves Wait at cnats default");

	/* negative timeout: also untouched */
	memset(&o, 0, sizeof(o));
	nats_pool_js_opts_apply(&o, _dummy_ack, -5);
	ASSERT(o.Wait == 0, "negative timeout leaves Wait untouched");

	/* disabled timeout does not clobber a pre-set Wait */
	memset(&o, 0, sizeof(o));
	o.Wait = 1234;
	nats_pool_js_opts_apply(&o, _dummy_ack, 0);
	ASSERT(o.Wait == 1234, "disabled timeout preserves pre-set Wait");

	/* boundary: smallest enabled timeout */
	memset(&o, 0, sizeof(o));
	nats_pool_js_opts_apply(&o, _dummy_ack, 1);
	ASSERT(o.Wait == 1, "1 ms timeout honored exactly");

	/* boundary: INT_MAX fits (Wait is int64_t; no truncation/sign trap) */
	memset(&o, 0, sizeof(o));
	nats_pool_js_opts_apply(&o, _dummy_ack, INT_MAX);
	ASSERT(o.Wait == (int64_t)INT_MAX, "INT_MAX timeout stored exactly");

	/* NULL handler is stored as-is (caller's choice), nothing else breaks */
	memset(&o, 0, sizeof(o));
	nats_pool_js_opts_apply(&o, NULL, 100);
	ASSERT(o.PublishAsync.AckHandler == NULL, "NULL handler stored verbatim");
	ASSERT(o.PublishAsync.MaxPending == NATS_JS_PUBLISH_ASYNC_MAX_PENDING,
		"cap applied independently of handler");

}
