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
 * ============================================================================
 *  IMPORTANT -- READ BEFORE TOUCHING THIS FILE
 * ----------------------------------------------------------------------------
 *  This translation unit implements the LIVE async transport only:
 *  w_nats_request_async() (the acmd entry point registered by
 *  nats_consumer.c) plus the correlation-id helpers shared with the
 *  sync path (uuidv7 mint, $nats_request_id stash/consume).  It uses
 *  the consumer-routed SHM-slot transport (nats_rpc_slot.c +
 *  nats_rpc_ipc.c, serviced in the consumer process by
 *  nats_rpc_consumer.c) and yields the worker on a private timerfd
 *  that acts as a coarse timeout guard: the consumer IPC-wakes
 *  the worker on delivery (nats_rpc_wake.c), so replies resume at
 *  wire latency and the timer only backstops lost wakes/timeouts.
 *  No libnats subscription is ever created on a SIP worker: running
 *  one on a worker is exactly the pattern that crashes libnats 3.x on
 *  aarch64 (see nats_rpc_async.h).
 *
 *  The ORIGINAL per-worker inbox-subscription state machine (ctx hash,
 *  ensure_inbox_subscription, on_inbox_reply, deliver/abandon
 *  lifecycle) was superseded by the slot transport for that reason,
 *  kept for a while as test-only ballast, and has been DELETED.
 * ============================================================================
 */

#ifdef TEST_SHIM
#include "tests/test_shim.h"
/* Stub libnats types -- the test driver never enters the libnats
 * glue; only the state machine is exercised. */
typedef struct _stub_natsMsg          natsMsg;
typedef struct _stub_natsConnection   natsConnection;
typedef struct _stub_natsSubscription natsSubscription;
typedef int                            natsStatus;
#define NATS_OK 0
#else
#include "../../mem/shm_mem.h"
#include "../../dprint.h"
#include "../../async.h"
#include "../../lib/list.h"
#include "../nats/nats_bind.h"
#include "../nats/nats_pool.h"
#include "../nats/nats_rl.h"   /* rate-limited outage WARN */
#include "../nats/nats_validate.h"
#include <nats/nats.h>
#endif

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdatomic.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/random.h>

#include "../../ipc.h"          /* ipc_send_rpc */

#include "nats_rpc.h"
#include "nats_ring.h"          /* NATS_RING_*_MAX caps */
#include "nats_rpc_async.h"
#include "nats_rpc_slot.h"
#include "nats_rpc_ipc.h"       /* nats_rpc_ipc_pack */
#include "nats_rpc_wake.h"      /* reply wake registry */
#include "nats_rpc_consumer.h"  /* nats_rpc_ipc_on_publish + counters */
#include "nats_consumer_proc.h" /* nats_consumer_proc_no */

/*
 * Per-worker stash of the most recent outbound request's UUIDv7.
 * Set by both the sync (w_nats_request) and async (w_nats_request_
 * _async) start paths after they mint the correlation id; read by
 * the $nats_request_id pvar getter.  Lives in process memory and
 * persists across an async() yield so the resume route can read
 * it back to correlate the reply against logs / traces / etc.
 * Overwritten on the next nats_request call from this worker;
 * shielded from concurrent updates by the worker single-threading
 * (only the worker thread runs script code).
 *
 * `g_request_id_user_supplied` is the consume-once flag: when set,
 * the next nats_request start path uses `g_last_request_id` as
 * the outbound id instead of minting a fresh UUIDv7.  Cleared by
 * the start path on consumption.  Set by the pvar setter when the
 * script assigns to $nats_request_id.
 *
 * Storage is sized at 64 bytes to comfortably hold any UUID
 * variant plus common trace-id formats (ULIDs, base32 hashes,
 * vendor-prefixed strings) without spilling. */
static char g_last_request_id[64];
static int  g_last_request_id_len;
static int  g_request_id_user_supplied;

/* ── helpers ──────────────────────────────────────────────────── */

/*
 * Mint a UUIDv7 into `out`.  `cap` must be >= 37
 * (36 chars + NUL).  Layout:
 *
 *     | unix_ts_ms (48b) | ver (4b) | rand_a (12b) |
 *     | var (2b) | rand_b (62b) |
 *
 * Formatted as 8-4-4-4-12 lowercase hex with version nibble = 7
 * and variant bits = 10b.  Returns the written length (always
 * 36) on success; 0 on truncation or RNG failure.
 *
 * Hot-path cost: one CLOCK_REALTIME read + one getrandom() of 10
 * bytes (the timestamp fills the first 6 bytes).  No allocations.
 *
 * If getrandom() fails (kernel < 3.17 or seccomp restriction)
 * the function returns 0; callers should treat a zero return as
 * "no correlation id available" and skip header staging rather
 * than minting a low-entropy fallback.
 */
int nats_rpc_async_uuidv7_mint(char *out, size_t cap)
{
	struct timespec ts;
	uint64_t ts_ms;
	uint8_t  rand10[10];
	ssize_t  got;
	int      n;

	if (!out || cap < 37) return 0;

	if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
		return 0;
	ts_ms = (uint64_t)ts.tv_sec * 1000u +
	        (uint64_t)(ts.tv_nsec / 1000000);

	got = getrandom(rand10, sizeof(rand10), GRND_NONBLOCK);
	if (got != (ssize_t)sizeof(rand10))
		return 0;

	/* Set version nibble (7) in the high nibble of byte 6
	 * (which becomes the first nibble of the third group). */
	rand10[0] = (uint8_t)((rand10[0] & 0x0f) | 0x70);
	/* Set variant bits (10b) in the high two bits of byte 8
	 * (first byte of the fourth group). */
	rand10[2] = (uint8_t)((rand10[2] & 0x3f) | 0x80);

	n = snprintf(out, cap,
		"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		(unsigned)((ts_ms >> 40) & 0xff),
		(unsigned)((ts_ms >> 32) & 0xff),
		(unsigned)((ts_ms >> 24) & 0xff),
		(unsigned)((ts_ms >> 16) & 0xff),
		(unsigned)((ts_ms >>  8) & 0xff),
		(unsigned)( ts_ms        & 0xff),
		rand10[0], rand10[1],     /* version 7 + 12b rand_a */
		rand10[2], rand10[3],     /* variant 10b + 14b rand_b */
		rand10[4], rand10[5], rand10[6],
		rand10[7], rand10[8], rand10[9]);

	if (n != 36) return 0;
	return n;
}

/*
 * Stash the just-minted (or already-staged) outbound id in the
 * per-worker storage so $nats_request_id can read it back later
 * (including inside the resume route, after the async() yield).
 *
 * Empty input clears the stash.  Caller is responsible for keeping
 * the lifetime of `id` >= the call; we copy.
 */
void nats_rpc_async_request_id_set(const char *id, int len)
{
	if (!id || len <= 0) {
		g_last_request_id[0] = '\0';
		g_last_request_id_len = 0;
		g_request_id_user_supplied = 0;
		return;
	}
	if (len >= (int)sizeof(g_last_request_id))
		len = (int)sizeof(g_last_request_id) - 1;
	memcpy(g_last_request_id, id, len);
	g_last_request_id[len] = '\0';
	g_last_request_id_len = len;
	/* deliberate: callers from start-path use this to record the
	 * just-used id, which is NOT a user-supplied override. */
	g_request_id_user_supplied = 0;
}

const char *nats_rpc_async_request_id_get(int *out_len)
{
	if (out_len) *out_len = g_last_request_id_len;
	return g_last_request_id_len > 0 ? g_last_request_id : NULL;
}

/*
 * Pvar-write entry: the script has assigned to $nats_request_id.
 * Stash the value so the NEXT nats_request call uses it instead
 * of minting a fresh UUIDv7.  Returns 0 on success, -1 if the
 * value is rejected (too long, contains CR/LF, etc.); the
 * setter surfaces -1 to the script.
 *
 * Empty input clears the pending override and the last-used
 * stash (so $nats_request_id then reads NULL until the next
 * mint).
 */
int nats_rpc_async_request_id_user_set(const char *id, int len)
{
	int i;

	if (!id || len <= 0) {
		g_last_request_id[0] = '\0';
		g_last_request_id_len = 0;
		g_request_id_user_supplied = 0;
		return 0;
	}
	if (len >= (int)sizeof(g_last_request_id))
		return -1;
	/* Reject control characters that would break NATS header
	 * serialisation.  Header values per the NATS wire protocol
	 * are CRLF-delimited; embedded CR/LF would inject pseudo-
	 * headers downstream.  No log here; the pvar setter in
	 * nats_rpc.c surfaces a single LM_WARN on the -1 return so
	 * we keep this function dprint-free for the unit-test
	 * shim. */
	for (i = 0; i < len; i++) {
		if (id[i] == '\r' || id[i] == '\n')
			return -1;
	}
	memcpy(g_last_request_id, id, len);
	g_last_request_id[len] = '\0';
	g_last_request_id_len = len;
	g_request_id_user_supplied = 1;
	return 0;
}

/*
 * Start-path consumer: if a user-supplied id is pending, copy it
 * to `out` (cap-sized), clear the pending flag, and return the
 * length copied.  Returns 0 if no user-supplied id is pending --
 * the caller then mints a fresh UUIDv7.
 *
 * Consume-once semantics: the user's assignment is honoured by
 * one nats_request call.  Subsequent calls revert to minting
 * unless the script writes the pvar again.
 */
int nats_rpc_async_request_id_consume_user(char *out, int cap)
{
	if (!g_request_id_user_supplied)
		return 0;
	if (!out || cap <= g_last_request_id_len)
		return 0;
	memcpy(out, g_last_request_id, g_last_request_id_len);
	out[g_last_request_id_len] = '\0';
	g_request_id_user_supplied = 0;
	return g_last_request_id_len;
}

/* ── libnats glue (production only) ───────────────────────────── */

#ifndef TEST_SHIM

/* Forward decls of helpers from nats_rpc.c that are not visible
 * in nats_rpc.h.  nats_rpc_hdr_serialize_from_reply is also
 * declared earlier in this file; nats_rpc_staged_set_if_absent
 * is in nats_rpc.h and intentionally not re-declared here. */
extern void nats_rpc_staged_apply_and_clear_on(natsMsg *out);
extern const char *nats_rpc_cstr_buf(char *buf, size_t cap,
                                      const char *src, int len);

/* Operator-configurable outbound header name carrying the per-call
 * UUIDv7.  Owned by nats_consumer.c via the `request_id_header`
 * modparam.  An empty / NULL value disables auto-staging entirely;
 * callers can still mint and read the id but no header is added
 * to the outbound natsMsg. */
extern char *nats_request_id_header;
extern int   nats_request_id_header_len;   /* cached at mod_init */

/*
 * Per-call wrapper: pairs the worker-private timerfd with the
 * SHM slot.  Lives in pkg memory (worker-local) for the duration
 * of one async() call; freed by resume_nats_request_slot on
 * completion or timeout.  The timerfd is created INSIDE the
 * worker (post-fork) so it doesn't trip the
 * OpenSIPS-reactor-can't-handle-fork-inherited-eventfds bug
 * isolated in commit 8eae39a5b1.
 */
typedef struct nats_rpc_call_wrap {
	nats_rpc_slot_t *slot;          /* SHM */
	int              timerfd;       /* worker-private, registered with reactor */
	int64_t          deadline_us;   /* CLOCK_MONOTONIC, microseconds */
	uint32_t         gen;           /* claim generation: guards the free
	                                 * against an orphan-reaped slot */
} nats_rpc_call_wrap_t;

/* How long past its deadline a worker keeps polling a slot the
 * consumer has pinned DELIVERING before giving up (the pin resolves in
 * microseconds when the delivery thread is alive). */
#ifndef NATS_RPC_DELIVERING_GRACE_US
#define NATS_RPC_DELIVERING_GRACE_US  (5LL * 1000000LL)   /* 5 s */
#endif

/* Runtime guard-tick interval in ms (modparam "async_rpc_poll_ms").
 * The reply itself arrives via the consumer's IPC wake at wire
 * latency; this timer only bounds how late a LOST wake or a timeout is
 * noticed, so the default is deliberately coarse (100 ms = 10 wakes/s
 * per in-flight call instead of the old 1000).  Clamped to [1, 1000]
 * when first used. */
int nats_rpc_async_poll_ms = 100;

static long async_poll_ns(void)
{
	int ms = nats_rpc_async_poll_ms;
	if (ms < 1)    ms = 1;
	if (ms > 1000) ms = 1000;
	return (long)ms * 1000000L;
}

static int64_t now_us_monotonic(void)
{
	struct timespec ts;
	(void)clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000000 + (int64_t)ts.tv_nsec / 1000;
}

/*
 * Resume function for the slot transport.
 *
 * Fires on the consumer's IPC wake (which pokes the per-call guard
 * timerfd -- see nats_rpc_wake.c) or on the timer's own coarse tick.
 * The slot's atomic state is the source of truth: if DELIVERED, copy
 * the reply and return 1; if still INFLIGHT and we haven't timed
 * out, ASYNC_CONTINUE to keep polling; if timed out, transition
 * to ABANDONED and return -1 (or -2 on connection lost).
 */
static int resume_nats_request_slot(int fd, struct sip_msg *msg,
                                     void *param)
{
	nats_rpc_call_wrap_t *w = (nats_rpc_call_wrap_t *)param;
	uint64_t              sink;
	ssize_t               rd;
	int                   state_obs;
	int                   rc;
	nats_rpc_slot_t      *s;

	(void)msg;

	if (!w || !w->slot) {
		LM_ERR("nats_request[async]: resume with NULL wrap/slot\n");
		async_status = ASYNC_DONE;
		return -6;
	}
	s = w->slot;

	/* Drain the timerfd counter so the next tick still wakes us. */
	do { rd = read(fd, &sink, sizeof(sink)); }
	while (rd < 0 && errno == EINTR);

	state_obs = atomic_load_explicit(&s->state, memory_order_acquire);

	if (state_obs == NATS_RPC_SLOT_DELIVERED) {
		/* Got the reply: copy into cur_msg, free everything,
		 * report success to the script. */
		nats_rpc_cur_set_from_buffers(&(nats_rpc_reply_view_t){
			.handle_idx        = 0xFFFF,
			.subject           = s->reply_subject,
			.subject_len       = s->reply_subject_len,
			.data              = s->reply_data,
			.data_len          = s->reply_data_len,
			.reply_to          = s->reply_to,
			.reply_to_len      = s->reply_to_len,
			.has_reply         = s->reply_has_reply_to,
			.headers           = s->reply_headers,
			.headers_len       = s->reply_headers_len,
			.headers_truncated = s->reply_headers_truncated,
		});

		async_status = ASYNC_DONE_CLOSE_FD;
		nats_rpc_wake_unregister(s->slot_idx);
		nats_rpc_slot_free(s, w->gen);
		pkg_free(w);
		return 1;
	}

	if (state_obs == NATS_RPC_SLOT_ABANDONED) {
		/* Consumer-side abandon (publish failed, etc.).  Tear
		 * down and report timeout / connection-lost based on
		 * pool state. */
		int disc = nats_epoch_lost(&s->epoch_at_start);

		async_status = ASYNC_DONE_CLOSE_FD;
		nats_rpc_wake_unregister(s->slot_idx);
		nats_rpc_slot_free(s, w->gen);
		pkg_free(w);
		return disc ? -2 : -1;
	}

	if (state_obs == NATS_RPC_SLOT_DELIVERING) {
		/* The consumer has pinned our claim and is writing the reply right
		 * now.  Not ready yet -- and we must NOT abandon+free the slot under
		 * the pin (that would break the consumer's exclusive DELIVERING ->
		 * DELIVERED transition).  Keep polling past the deadline: the
		 * transition is a few instructions on the consumer thread, so the
		 * next tick delivers an at-the-wire reply rather than dropping it.
		 *
		 *... but not FOREVER.  If the consumer's libnats thread
		 * dies mid-delivery the pin never resolves and this worker would
		 * poll for the process lifetime.  Past deadline + a generous
		 * grace, stop polling and surface -2; the slot is deliberately
		 * NOT freed under the pin -- the orphan reaper reclaims
		 * it (generation-guarded) once its own slack expires. */
		if (now_us_monotonic() >=
		    w->deadline_us + NATS_RPC_DELIVERING_GRACE_US) {
			LM_ERR("nats_request[async]: reply pinned DELIVERING "
				"past deadline+grace on slot %u -- consumer "
				"delivery thread gone?  Abandoning the wait "
				"(the orphan reaper reclaims the slot)\n",
				(unsigned)s->slot_idx);
			async_status = ASYNC_DONE_CLOSE_FD;
			nats_rpc_wake_unregister(s->slot_idx);
			pkg_free(w);
			return -2;
		}
		async_status = ASYNC_CONTINUE;
		return 0;
	}

	/* state == INFLIGHT.  A lost connection epoch orphans the request
	 * even if the pool has already reconnected -- the reply inbox and
	 * the consumer's subscription died with the old connection -- so
	 * waiting out timeout_ms only delays the script's failover
	 * decision.  Cancel on THIS tick (the cancellation budget is one
	 * async_rpc_poll_ms guard tick, 100 ms default), with the same
	 * CAS guard as the timeout path below: if the consumer wins the
	 * race a reply is landing -- keep polling, never drop it. */
	if (nats_epoch_lost(&s->epoch_at_start)) {
		if (nats_rpc_slot_abandon(s) != NATS_RPC_SLOT_ABANDONED) {
			async_status = ASYNC_CONTINUE;
			return 0;
		}
		async_status = ASYNC_DONE_CLOSE_FD;
		nats_rpc_wake_unregister(s->slot_idx);
		nats_rpc_slot_free(s, w->gen);
		pkg_free(w);
		return -2;
	}

	/* Check the per-call deadline so we
	 * surface -1 even though the async core has no built-in
	 * timeout for raw FDs.  Otherwise re-arm and keep polling. */
	if (now_us_monotonic() >= w->deadline_us) {
		int disc = nats_epoch_lost(&s->epoch_at_start);

		/* Claim the timeout only if we actually WIN the INFLIGHT ->
		 * ABANDONED CAS.  If abandon() reports any other state the consumer
		 * beat us and a reply is landing (DELIVERING) or landed (DELIVERED):
		 * do NOT free -- keep polling so the reply is delivered on the next
		 * tick instead of being lost exactly at the deadline. */
		if (nats_rpc_slot_abandon(s) != NATS_RPC_SLOT_ABANDONED) {
			async_status = ASYNC_CONTINUE;
			return 0;
		}
		async_status = ASYNC_DONE_CLOSE_FD;
		nats_rpc_wake_unregister(s->slot_idx);
		nats_rpc_slot_free(s, w->gen);
		pkg_free(w);
		return disc ? -2 : -1;
	}

	(void)rc;
	async_status = ASYNC_CONTINUE;
	return 0;
}

/*
 * w_nats_request_async -- async acmd entry point.
 *
 * Worker side of the consumer-process-routed transport:
 *
 *   1. Pre-flight: subject + payload bounds.
 *   2. Mint/consume UUIDv7 for $nats_request_id.
 *   3. Claim a SHM slot from the pool.  On full pool surface -5.
 *   4. Fill the slot's out_subject + out_data + corr_id +
 *      epoch_at_start.
 *   5. Transition slot CLAIMED -> INFLIGHT (release ordering --
 *      the consumer's IPC drain acquires this) and enqueue the
 *      slot_idx on the worker -> consumer IPC.
 *   6. Create a worker-private timerfd that ticks every
 *      async_rpc_poll_ms ms.  Compute the per-call deadline
 *      from timeout_ms (caps the polling loop).
 *   7. Allocate a pkg wrapper, hand control to the reactor:
 *      async_status = timerfd, ctx->resume_f =
 *      resume_nats_request_slot, ctx->resume_param = wrap.
 *
 * Headers staged via nats_hdr_set() (including the auto-staged
 * X-Request-Id) are serialized into the slot's out_headers buffer
 * using the same compact length-prefixed wire format as the ring
 * slot's headers field, and the consumer process applies them via
 * natsMsgHeader_Set() before PublishMsg in publish_cb().  Headers
 * that don't fit the 1 KB out_headers buffer set the truncated
 * flag (logged on emit); the remaining oversize names/values are
 * dropped quietly rather than silently corrupting the wire format.
 *
 * On any pre-IPC failure the slot is freed and the worker
 * returns the appropriate negative rc.  On post-IPC failure
 * (queue full) the slot is also freed; the worker returns -5
 * (capacity exhausted).
 */
int w_nats_request_async(struct sip_msg *msg, async_ctx *ctx,
                         str *subject, str *payload, int *timeout_ms)
{
	nats_rpc_slot_t        *slot = NULL;
	nats_rpc_call_wrap_t   *wrap = NULL;
	uint32_t                ipc_gen;
	int                     ipc_dst;
	struct itimerspec       its;
	int                     tfd = -1;
	int                     tmo_ms;
	char                    id_buf[64];
	int                     id_len = 0;

	(void)msg;
	(void)ctx;
	LM_DBG("nats_request[async]: ENTER subject=%p len=%d payload=%p tmo=%p ctx=%p\n",
		(void*)(subject?subject->s:NULL),
		subject?subject->len:-1,
		(void*)(payload?payload->s:NULL),
		(void*)timeout_ms, (void*)ctx);

	if (!subject || subject->len <= 0 || !subject->s) {
		LM_DBG("nats_request[async]: empty/null subject\n");
		nats_rpc_staged_clear();
		async_status = ASYNC_NO_IO;
		return -4;
	}
	if (subject->len > NATS_RING_SUBJECT_MAX) {
		LM_ERR("nats_request[async]: subject too long (%d > %d)\n",
			subject->len, NATS_RING_SUBJECT_MAX);
		nats_rpc_staged_clear();
		async_status = ASYNC_NO_IO;
		return -4;
	}
	/* Reject CR/LF, whitespace and wildcards before the subject reaches
	 * the line-oriented NATS wire (protocol-injection guard). */
	if (nats_validate_publish_subject(subject->s, subject->len) < 0) {
		LM_ERR("nats_request[async]: invalid subject '%.*s' "
			"(control/whitespace/wildcard rejected)\n",
			subject->len, subject->s);
		nats_rpc_staged_clear();
		async_status = ASYNC_NO_IO;
		return -4;
	}
	if (payload && payload->len > NATS_RING_PAYLOAD_MAX) {
		LM_ERR("nats_request[async]: payload too long (%d > %d)\n",
			payload->len, NATS_RING_PAYLOAD_MAX);
		nats_rpc_staged_clear();
		async_status = ASYNC_NO_IO;
		return -4;
	}

	tmo_ms = (timeout_ms && *timeout_ms > 0) ? *timeout_ms : 1000;

	/* Mint or consume the UUIDv7 + stage X-Request-Id. */
	id_len = nats_rpc_async_request_id_consume_user(id_buf, sizeof(id_buf));
	if (id_len == 0)
		id_len = nats_rpc_async_uuidv7_mint(id_buf, sizeof(id_buf));
	if (id_len > 0) {
		nats_rpc_async_request_id_set(id_buf, id_len);
		if (nats_request_id_header && nats_request_id_header[0]) {
			str hname = { nats_request_id_header,
				nats_request_id_header_len };
			str hval  = { id_buf, id_len };
			(void)nats_rpc_staged_set_if_absent(&hname, &hval);
		}
	}

	/* Fast-fail on a disconnected pool BEFORE claiming a slot: the
	 * publish would land on a dead connection, so the slot is
	 * guaranteed to burn its entire timeout -- during an outage every
	 * call would otherwise eat a slice of the bounded slot pool. */
	if (!nats_pool_is_connected()) {
		/* rate-limited WARN + per-call DBG (see nats_rpc.c). */
		static time_t rl_disc;
		if (nats_rl_pass(&rl_disc, time(NULL), 30))
			LM_WARN("nats_request[async]: NATS disconnected; failing "
				"fast (repeats suppressed for 30s)\n");
		LM_DBG("nats_request[async]: NATS disconnected; failing fast\n");
		nats_rpc_staged_clear();
		return -2;
	}

	LM_DBG("nats_request[async]: about to claim slot\n");
	slot = nats_rpc_slot_claim();
	LM_DBG("nats_request[async]: slot=%p idx=%u\n",
		(void*)slot, slot?slot->slot_idx:0xFFFFFFFFu);
	if (!slot) {
		LM_WARN("nats_request[async]: slot pool full (%u in flight)\n",
			nats_rpc_slot_inflight_count());
		nats_rpc_staged_clear();
		async_status = ASYNC_NO_IO;
		return -5;
	}

	/* Fill outbound + correlation. */
	memcpy(slot->out_subject, subject->s, (size_t)subject->len);
	slot->out_subject_len = (uint32_t)subject->len;
	if (payload && payload->len > 0) {
		memcpy(slot->out_data, payload->s, (size_t)payload->len);
		slot->out_data_len = (uint32_t)payload->len;
	} else {
		slot->out_data_len = 0;
	}
	{
		int hdr_trunc = 0, hdr_count = 0;
		int hdr_len = nats_rpc_staged_serialize(slot->out_headers,
			(int)sizeof(slot->out_headers),
			&hdr_trunc, &hdr_count);
		if (hdr_len < 0) hdr_len = 0;
		slot->out_headers_len = (uint16_t)hdr_len;
		if (hdr_trunc) {
			LM_WARN("nats_request[async]: staged-header buffer "
				"truncated (emitted %d/%d pairs) on slot %u\n",
				hdr_count, NATS_MAX_STAGED_HDRS,
				(unsigned)slot->slot_idx);
		}
	}
	if (id_len > 0) {
		int cp = id_len < (int)sizeof(slot->corr_id) - 1
			? id_len : (int)sizeof(slot->corr_id) - 1;
		memcpy(slot->corr_id, id_buf, (size_t)cp);
		slot->corr_id[cp] = '\0';
		slot->corr_id_len = (uint32_t)cp;
	} else {
		slot->corr_id[0] = '\0';
		slot->corr_id_len = 0;
	}
	nats_epoch_save(&slot->epoch_at_start);
	ipc_gen = atomic_load_explicit(&slot->generation,
		memory_order_relaxed);
	/* Stamp the per-call deadline into the slot BEFORE the
	 * CLAIMED->INFLIGHT release below: the consumer-side orphan
	 * reaper reclaims this slot at deadline + slack if we die and
	 * our timerfd resume never runs. */
	atomic_store_explicit(&slot->deadline_us,
		now_us_monotonic() + (int64_t)tmo_ms * 1000,
		memory_order_relaxed);
	/* Stamp ourselves as the wake destination BEFORE the
	 * CLAIMED->INFLIGHT release: the consumer IPC-signals this
	 * process the moment it delivers (or abandons) the reply. */
	atomic_store_explicit(&slot->owner_proc, process_no,
		memory_order_relaxed);

	LM_DBG("nats_request[async]: filled slot, about to publish\n");
	if (nats_rpc_slot_publish(slot) < 0) {
		LM_ERR("nats_request[async]: slot_publish failed (slot %u)\n",
			slot->slot_idx);
		nats_rpc_slot_free(slot, ipc_gen);
		nats_rpc_staged_clear();
		async_status = ASYNC_NO_IO;
		return -6;
	}

	/* Send the publish request over core IPC.  The payload --
	 * slot index + the slot's current claim generation -- travels
	 * packed in the param pointer (zero alloc); the generation lets
	 * the consumer reject this entry if the slot is freed and
	 * re-claimed before the pump (prevents a double-publish -- see
	 * nats_rpc_ipc_on_publish). */
	ipc_dst = nats_consumer_proc_no();
	LM_DBG("nats_request[async]: about to IPC-send slot_idx=%u gen=%u "
		"dst=%d\n", slot->slot_idx, ipc_gen, ipc_dst);
	if (ipc_dst < 0 ||
	    ipc_send_rpc(ipc_dst, nats_rpc_ipc_on_publish,
			nats_rpc_ipc_pack(slot->slot_idx, ipc_gen)) < 0) {
		LM_WARN("nats_request[async]: IPC send refused (pipe full or "
			"consumer proc not up) -- dropping (slot %u)\n",
			slot->slot_idx);
		nats_rpc_ipc_count_sent(0);
		(void)nats_rpc_slot_abandon(slot);
		nats_rpc_slot_free(slot, ipc_gen);
		nats_rpc_staged_clear();
		async_status = ASYNC_NO_IO;
		return -5;
	}
	nats_rpc_ipc_count_sent(1);

	/* Worker-private timerfd: created post-fork so the reactor
	 * can register it (see commit 8eae39a5b1). */
	LM_DBG("nats_request[async]: about to create timerfd\n");
	tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	if (tfd < 0) {
		LM_ERR("nats_request[async]: timerfd_create: %s\n",
			strerror(errno));
		(void)nats_rpc_slot_abandon(slot);
		nats_rpc_slot_free(slot, ipc_gen);
		nats_rpc_staged_clear();
		async_status = ASYNC_NO_IO;
		return -6;
	}
	memset(&its, 0, sizeof(its));
	{
		long poll_ns = async_poll_ns();
		its.it_value.tv_sec     = 0;
		its.it_value.tv_nsec    = poll_ns;
		its.it_interval.tv_sec  = 0;
		its.it_interval.tv_nsec = poll_ns;
	}
	if (timerfd_settime(tfd, 0, &its, NULL) < 0) {
		LM_ERR("nats_request[async]: timerfd_settime: %s\n",
			strerror(errno));
		close(tfd);
		(void)nats_rpc_slot_abandon(slot);
		nats_rpc_slot_free(slot, ipc_gen);
		nats_rpc_staged_clear();
		async_status = ASYNC_NO_IO;
		return -6;
	}

	LM_DBG("nats_request[async]: timerfd armed tfd=%d, allocating wrap\n", tfd);
	wrap = (nats_rpc_call_wrap_t *)pkg_malloc(sizeof(*wrap));
	if (!wrap) {
		LM_ERR("nats_request[async]: pkg_malloc wrap failed\n");
		close(tfd);
		(void)nats_rpc_slot_abandon(slot);
		nats_rpc_slot_free(slot, ipc_gen);
		nats_rpc_staged_clear();
		async_status = ASYNC_NO_IO;
		return -6;
	}
	wrap->slot        = slot;
	wrap->timerfd     = tfd;
	wrap->deadline_us = now_us_monotonic() + (int64_t)tmo_ms * 1000;
	wrap->gen         = ipc_gen;

	/* Track the call in the per-worker wake registry (sized
	 * from the clamped pool total, not the raw modparam) so the
	 * consumer's delivered/abandoned IPC signal can poke our guard
	 * timerfd.  Failure (OOM) is non-fatal: the reply is then picked
	 * up on the coarse guard tick, exactly as before the wake. */
	if (nats_rpc_wake_init(nats_rpc_slot_total_count()) == 0)
		(void)nats_rpc_wake_register(slot->slot_idx, ipc_gen, tfd);

	/* Hand off to the reactor.  The staged headers were
	 * "consumed" when we built the slot; clear the staging area
	 * so the next call starts fresh. */
	nats_rpc_staged_clear();

	LM_DBG("nats_request[async]: handing off ctx=%p resume_f=%p wrap=%p tfd=%d\n",
		(void*)ctx, (void*)resume_nats_request_slot,
		(void*)wrap, tfd);
	ctx->resume_f      = (void *)resume_nats_request_slot;
	ctx->resume_f_name = "resume_nats_request_slot";
	ctx->resume_param  = wrap;
	async_status       = tfd;
	return 1;
}

#ifdef UNIT_TESTS
long nc_ut_async_poll_ns(void)
{
	return async_poll_ns();
}

int64_t nc_ut_now_us(void)
{
	return now_us_monotonic();
}

/* One resume of an async request waiting on slot `s` (claim generation
 * `gen`, deadline `deadline_us`), as the reactor runs it when the call's
 * timer fd `fd` fires.  Frees the call's wrap if the resume did not. */
int nc_ut_resume_request(nats_rpc_slot_t *s, uint32_t gen,
	int64_t deadline_us, int fd)
{
	nats_rpc_call_wrap_t *w = pkg_malloc(sizeof *w);
	int rc;

	if (!w)
		return -100;
	w->slot = s;
	w->timerfd = fd;
	w->deadline_us = deadline_us;
	w->gen = gen;
	rc = resume_nats_request_slot(fd, NULL, w);
	if (async_status == ASYNC_CONTINUE)
		pkg_free(w);
	return rc;
}
#endif

#endif /* !TEST_SHIM */
