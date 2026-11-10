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
 * nats_consumer_proc.c -- dedicated JetStream pull consumer process.
 *
 *   The process owns one natsConnection (from the shared pool) and one
 *   jsCtx.  Every bound handle gets a single pull subscription owned by
 *   this process; the subscription pointer lives in process-local
 *   memory (g_subs) rather than in the SHM handle because the nats.c
 *   library's subscription objects are not SHM-safe.
 *
 *   On each iteration:
 *     1. reconcile_subs() walks the registry, creating a
 *        proc_sub_state_t + natsSubscription for any handle it has not
 *        yet seen.
 *     2. pull_one_batch() reads the SHM ring's free-slot count, clamps
 *        the request to min(fetch_batch, free_slots-1), and fetches
 *        that many messages with a `fetch_timeout_ms` timeout.  Each
 *        natsMsg is stashed under a freshly-minted ack_token, then
 *        pushed into the handle's SHM ring.  When the ring has no
 *        room, the Fetch is skipped entirely; pull-mode JetStream
 *        keeps the un-fetched messages on the broker side until the
 *        next iteration after the worker drains.
 *     3. pump_worker_ipc() runs every pending worker job from the
 *        core-IPC pipe; each ack job looks up the stashed
 *        natsMsg and calls the requested natsMsg_Ack / Nak / Term /
 *        InProgress.
 *
 *   Back-pressure model: the dynamic Fetch clamp in step (2) means
 *   a successful Fetch never produces a defer-drop on push, so the
 *   broker never sees an outstanding-then-redelivered cycle from
 *   over-fetching.  The legacy ring-full path (nats_ring_push -> -1)
 *   is still defended against (release_msg_ref + ss->total_dropped_*),
 *   but is unreachable in steady state with the clamp in place.
 *
 *   Throughput: with this design plus msg-ref sizing of
 *   max(ring_capacity, max_ack_pending) and the batch-fetch
 *   wait-loop in nats_fetch.c, sustained drain on aarch64
 *   loopback at fetch_batch=256 measures ~89 000 msgs/sec vs. ~2 000
 *   msgs/sec on the original per-message single-drain path.
 *
 *   Ack model: rather than auto-acking each pushed message, the
 *   consumer process stashes natsMsg* in a process-local ref table
 *   indexed by (handle_idx, slot_idx) and only calls
 *   natsMsg_Ack / Nak / Term / InProgress in apply_ack_action() on a
 *   worker's explicit request.  A 16-bit generation counter in each
 *   ref slot is bumped on (re)use and checked on ack to guard against
 *   ABA-style stale-token reuse after ring wrap.
 */

#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <stdatomic.h>
#include <sys/select.h>
#include <poll.h>
#include <sys/timerfd.h>

#include <nats/nats.h>

#include "../../dprint.h"
#include "../../mem/shm_mem.h"
#include "../../ipc.h"           /* IPC_FD_READ_SELF + ipc_handle_job */
#include "../../pt.h"            /* pt[] behind IPC_FD_READ_SELF */
#include "../nats/nats_bind.h"
#include "../nats/nats_pool.h"
#include "../nats/nats_str.h"

#include "nats_handle_registry.h"
#include "nats_ring.h"
#include "nats_ack_ipc.h"
#include "nats_ack.h"
#include "nats_consumer_proc.h"
#include "nats_rpc_consumer.h"
#include "nats_rpc_slot.h"
#include "nats_rpc_ipc.h"
#include "nats_consumer_proc_internal.h"

/* SHM heartbeat block -- bumped per loop iteration so a watchdog or
 * MI handler can detect a wedged or crashed consumer process.
 * Allocated by mod_init via nats_consumer_hb_init(); NULL until
 * then, so writes are guarded. */
nats_consumer_heartbeat_t *nats_consumer_hb = NULL;

int nats_consumer_hb_init(void)
{
	nats_consumer_hb = shm_malloc(sizeof(*nats_consumer_hb));
	if (!nats_consumer_hb) {
		LM_ERR("nats_consumer: shm_malloc for heartbeat failed\n");
		return -1;
	}
	memset(nats_consumer_hb, 0, sizeof(*nats_consumer_hb));
	atomic_store_explicit(&nats_consumer_hb->tick, 0, memory_order_relaxed);
	atomic_store_explicit(&nats_consumer_hb->last_tick_us, 0, memory_order_relaxed);
	atomic_store_explicit(&nats_consumer_hb->consumer_pid, 0, memory_order_relaxed);
	/* 0 is a valid pt[] index -- the "not up yet" sentinel must be -1
	 * (see nats_consumer_proc_no()) */
	atomic_store_explicit(&nats_consumer_hb->consumer_proc_no, -1,
		memory_order_relaxed);
	return 0;
}

void nats_consumer_hb_destroy(void)
{
	if (nats_consumer_hb) {
		shm_free(nats_consumer_hb);
		nats_consumer_hb = NULL;
	}
}


static inline void nats_consumer_hb_tick(void)
{
	if (!nats_consumer_hb) return;
	atomic_fetch_add_explicit(&nats_consumer_hb->tick, 1,
		memory_order_relaxed);
	atomic_store_explicit(&nats_consumer_hb->last_tick_us,
		now_monotonic_us(), memory_order_relaxed);
}

/* ── tuning ──────────────────────────────────────────────────── */

/* Fetch batch / per-Fetch timeout are operator-tunable.  Module-global
 * defaults come from the `fetch_batch` / `fetch_timeout_ms` modparams
 * (see nats_consumer.c).  Each bound handle may override either
 * value via `fetch_batch=` / `fetch_timeout_ms=` in nats_consumer_bind.
 * Resolved at every Fetch call so a runtime modparam tweak is picked
 * up without rebinding (modparams themselves are static-after-startup
 * in OpenSIPS, but this keeps the resolution logic in one place). */
static inline int eff_fetch_batch(const nats_handle_t *h)
{
	int v = (h && h->fetch_batch) ? (int)h->fetch_batch
	                              : nats_consumer_fetch_batch;
	if (v < 1)    v = 1;
	if (v > 4096) v = 4096;
	return v;
}

static inline int eff_fetch_timeout_ms(const nats_handle_t *h)
{
	int v = (h && h->fetch_timeout_ms) ? (int)h->fetch_timeout_ms
	                                   : nats_consumer_fetch_timeout_ms;
	if (v < 1)     v = 1;
	if (v > 60000) v = 60000;
	return v;
}

/* Floor on the per-fetch idle wait so we still actually block (and don't
 * busy-spin) when many handles share the budget. */
#define NATS_FETCH_MIN_BUDGET_MS  5

/*
 * Per-fetch timeout budget for one pass of the fetch sweep.  With one
 * handle, use the full configured timeout (an efficient idle wait).  With
 * N handles, divide it so the WHOLE sweep stays bounded at ~the configured
 * timeout instead of N * timeout -- otherwise a sweep over many idle
 * handles starves acks and async RPCs for num_handles * fetch_timeout
 * (head-of-line blocking).  Returns 0 ("no cap") for the single-handle
 * case so pull_one_batch uses the handle's own configured timeout.
 */
static int fetch_budget_ms(int configured, int num_subs)
{
	int b;
	if (num_subs <= 1)
		return 0;                 /* no cap: full per-handle timeout */
	b = configured / num_subs;
	if (b < NATS_FETCH_MIN_BUDGET_MS)
		b = NATS_FETCH_MIN_BUDGET_MS;
	if (b > configured)
		b = configured;
	return b;
}

/* Idle cycle: blocking select() on (core-IPC fd, retry_timerfd) instead of
 * a usleep spin.  The retry timerfd gives us a bounded upper wait so
 * a stalled subscription (e.g. broker TCP stall) does not keep us
 * asleep forever; acks still wake us immediately on any worker
 * ack-IPC enqueue. */
#define IDLE_RETRY_MS      1000   /* 1 s max idle before retry */

/* ── process-local state ─────────────────────────────────────── */


proc_sub_state_t *g_subs = NULL;

/* Dense idx -> proc_sub_state_t table maintained alongside g_subs so the
 * ack drain callback (which only carries the handle_idx via the ack
 * token) can find the owning subscription's handle in O(1) without
 * scanning the linked list per ack.  Updated under the same single-
 * producer assumption as g_subs (the consumer process only). */
proc_sub_state_t *g_subs_by_idx[NATS_REGISTRY_MAX_HANDLES] = {0};

static natsConnection   *g_nc   = NULL;
jsCtx            *g_js   = NULL;

/* SHM-handle stat bump.  All counters live in the per-handle SHM
 * struct; producers are this process only, readers are MI in the
 * attendant process (see nats_mi.c).  Use relaxed atomics so the
 * reader sees coherent increments without us paying for the per-handle
 * rwlock on every pull/push/ack.
 *
 * Wrapped in a static inline so the call sites stay terse; with NULL
 * the bump is a no-op (e.g. early TEST_SHIM init). */
/* ── forward declarations ────────────────────────────────────── */

static int  pull_one_batch(proc_sub_state_t *ss, int budget_ms);

/* ── header serialization ────────────────────────────────────── */

/*
 * Serialize the headers of `m` into `out[]` using the compact stream
 * format documented on nats_ring_slot_t.headers[]:
 *     [u16 count]
 *     repeated:  [u16 key_len][key][u16 val_len][val]
 *
 * All sizes are host-order uint16 (the ring lives in SHM shared
 * between forked workers of this process, so no endian conversion is
 * necessary).  Multi-valued keys are flattened: each value becomes a
 * separate entry with the same key.  Binary / NUL bytes in values are
 * preserved because we write `strlen(value)` and copy the bytes
 * verbatim -- nats.c does not document binary-safe headers, so this is
 * a best effort.
 *
 * Returns:
 *    the number of bytes written to `out[]` on success (0 when there
 *    were no headers to serialize -- not an error).
 *    `*truncated` is set to 1 iff at least one header was dropped
 *    because the output would have exceeded `out_cap`; the surviving
 *    prefix is still valid.
 *    `*count_out` receives the number of headers actually written.
 *
 * The count field is patched after the fact once we know how many
 * headers survived truncation.
 */
static int serialize_headers(natsMsg *m, char *out, int out_cap,
                             int *truncated, int *count_out)
{
	const char * *keys   = NULL;
	int           nkeys  = 0;
	natsStatus    s;
	int           pos    = 0;
	int           count  = 0;
	int           i;
	int           trunc  = 0;

	*truncated = 0;
	*count_out = 0;

	if (!m || !out || out_cap < 2)
		return 0;

	/* Reserve the count prefix; patched after the loop. */
	pos = 2;

	s = nats_dl.natsMsgHeader_Keys(m, &keys, &nkeys);
	if (s != NATS_OK || !keys || nkeys <= 0) {
		/* No headers -- still emit the zero count so the stream is
		 * valid.  Callers that see headers_len == 2 know the message
		 * carried no headers but was inspected. */
		out[0] = 0;
		out[1] = 0;
		if (keys) free((void *)keys);
		return 2;
	}

	for (i = 0; i < nkeys; i++) {
		const char * *vals = NULL;
		int           nvals = 0;
		natsStatus    vs;
		int           j;
		int           klen;

		if (!keys[i])
			continue;
		klen = (int)strlen(keys[i]);
		if (klen <= 0 || klen > 0xFFFF)
			continue;

		vs = nats_dl.natsMsgHeader_Values(m, keys[i], &vals, &nvals);
		if (vs != NATS_OK || !vals || nvals <= 0) {
			if (vals) free((void *)vals);
			continue;
		}

		for (j = 0; j < nvals; j++) {
			int  vlen;
			int  need;

			if (!vals[j]) continue;
			vlen = (int)strlen(vals[j]);
			if (vlen < 0 || vlen > 0xFFFF) continue;
			/* 2 (klen) + klen + 2 (vlen) + vlen */
			need = 2 + klen + 2 + vlen;
			if (pos + need > out_cap) {
				/* No room for this entry or any more; mark truncated
				 * and stop.  Header order is not specified by the
				 * NATS protocol so we don't try to skip-ahead. */
				trunc = 1;
				goto done_vals;
			}

			out[pos++] = (char)(klen & 0xFF);
			out[pos++] = (char)((klen >> 8) & 0xFF);
			memcpy(out + pos, keys[i], klen); pos += klen;
			out[pos++] = (char)(vlen & 0xFF);
			out[pos++] = (char)((vlen >> 8) & 0xFF);
			if (vlen) memcpy(out + pos, vals[j], vlen);
			pos += vlen;
			count++;
			if (count >= 0xFFFF) {
				/* u16 ceiling -- cannot encode more headers even if
				 * we had room.  Unlikely in practice but guard for
				 * correctness. */
				trunc = 1;
				goto done_vals;
			}
		}
done_vals:
		free((void *)vals);
		if (trunc)
			break;
	}

	free((void *)keys);

	out[0] = (char)(count & 0xFF);
	out[1] = (char)((count >> 8) & 0xFF);
	*truncated = trunc;
	*count_out = count;
	return pos;
}

/* ── fetch loop ──────────────────────────────────────────────── */

/* One clamped Fetch for *ss with full status triage (idle timeout,
 * connection closed, vanished-consumer rebuild flagging, transient
 * errors).  Fills *list and returns 1 when there are messages to
 * process; 0 when this pull is done (nothing fetched / flow-control
 * skip / error already accounted). */
static int proc_fetch_batch(proc_sub_state_t *ss, int budget_ms,
	natsMsgList *list)
{
	natsStatus s;

	/* Dynamic batch sizing: never request more than will fit in the
	 * ring's free slots.  Prior to this, a static fetch_batch larger
	 * than the worker's drain rate would push messages until the ring
	 * filled, then defer-drop the surplus.  Dropped messages are not
	 * acked, the broker holds them as outstanding, ack_wait expires,
	 * the broker redelivers under a NEW consumer-seq, and any later
	 * worker-driven ack of the original consumer-seq is rejected as
	 * stale -- which is what stalled the broker ack-floor at small N
	 * for fetch_batch in (16..64).
	 *
	 * Clamp to free slots so the Fetch never produces a defer-drop on
	 * push.  When the ring is completely full, skip the Fetch entirely
	 * and let the worker drain first; the next consumer-process loop
	 * iteration will re-evaluate.  This is pure flow-control: the
	 * un-fetched messages remain owned by the broker and are delivered
	 * cleanly on the next pull.
	 *
	 * Subtract one from depth so we always leave headroom for the
	 * generation-bump invariant in the ring's CAS push path. */
	{
		uint32_t cap     = nats_ring_capacity(ss->ring);
		uint32_t depth   = nats_ring_depth(ss->ring);
		int      max_fb  = eff_fetch_batch(ss->h_ref);
		int      free_sl = (cap > depth) ? (int)(cap - depth) : 0;
		int      eff_fb;

		if (free_sl <= 1) {
			/* Ring full: skip the Fetch entirely.  No message is
			 * touched -- the broker keeps the un-fetched messages and
			 * redelivers them next pull.  This is flow control, not a
			 * drop, so it has its own counter. */
			hstat_add(ss->h_ref, &ss->h_ref->fetch_skips_full, 1);
			return 0;
		}
		eff_fb = (max_fb < free_sl) ? max_fb : (free_sl - 1);
		if (eff_fb < 1)
			eff_fb = 1;

		int tmo = eff_fetch_timeout_ms(ss->h_ref);
		/* Cap the per-fetch wait to the caller's budget so a sweep over
		 * many idle handles cannot block acks / async RPCs for
		 * num_handles * fetch_timeout (head-of-line blocking). */
		if (budget_ms > 0 && budget_ms < tmo)
			tmo = budget_ms;

		memset(list, 0, sizeof(*list));
		hstat_add(ss->h_ref, &ss->h_ref->pulls_requested, 1);
		s = nats_dl.natsSubscription_Fetch(list, ss->sub,
		        eff_fb, tmo, NULL);
	}

	/* Fast path on idle: timeout is the steady-state condition when
	 * the broker has nothing to send us. */
	if (s == NATS_TIMEOUT)
		return 0;

	if (s == NATS_CONNECTION_CLOSED) {
		LM_DBG("nats_consumer_proc: connection closed during fetch "
			"on id='%.*s'\n", ss->id.len, ss->id.s);
		/* The outer loop's epoch check will observe the reconnect
		 * when the library reconnects and will flip ss->dirty then. */
		return 0;
	}

	/* Ephemeral-GC / subscription-invalidated detection.
	 *
	 * NATS_NOT_FOUND comes back when JetStream has GC'd the consumer
	 * past its inactive_threshold (the common ephemeral-GC case).
	 * NATS_INVALID_SUBSCRIPTION means the nats.c subscription object
	 * has gone into a bad state (e.g. after a server-initiated close).
	 * In both cases the right thing is to destroy the subscription
	 * and flag it dirty so the next reconcile tick rebuilds it.
	 * Ephemeral consumers get a brand-new server-side id on recreate
	 * (see the rebuild log line in ensure_subscription_for_handle). */
	if (s == NATS_NOT_FOUND || s == NATS_INVALID_SUBSCRIPTION) {
		LM_INFO("nats_consumer_proc: consumer for %.*s vanished (%s); "
			"will recreate\n",
			ss->id.len, ss->id.s, nats_dl.natsStatus_GetText(s));
		if (ss->sub) {
			nats_dl.natsSubscription_Unsubscribe(ss->sub);
			nats_dl.natsSubscription_Destroy(ss->sub);
			ss->sub = NULL;
			/* The sub is gone; any fetched-but-un-acked natsMsg still in
			 * this handle's ref row now holds a dangling msg->sub.  Purge
			 * before the recreate so a late ack can't deref a freed sub
			 * (UAF).  The broker redelivers un-acked messages on the new
			 * subscription. */
			purge_msg_ref_row(ss->handle_idx);
		}
		ss->dirty = 1;
		hstat_add(ss->h_ref, &ss->h_ref->fetch_errors, 1);
		return 0;
	}

	if (s != NATS_OK && list->Count == 0) {
		/* Non-fatal per-sub error; log at DBG to avoid flooding logs
		 * when e.g. max_ack_pending gates us out. */
		hstat_add(ss->h_ref, &ss->h_ref->fetch_errors, 1);
		LM_DBG("nats_consumer_proc: fetch id='%.*s': %s\n",
			ss->id.len, ss->id.s, nats_dl.natsStatus_GetText(s));
		return 0;
	}

	return 1;
}

/* JetStream pull-delivered messages have natsMsg_GetReply() set to the
 * per-delivery $JS.ACK.<...> subject for ack tracking, NOT to the
 * publisher's application reply.  Acks are dispatched separately via
 * the ref-table token, so the ACK subject is not useful to the script
 * via $nats_reply_to.
 *
 * The original publisher's application reply is preserved by
 * convention in the Nats-Reply-To header (set by the publisher with
 * `nats pub -H 'Nats-Reply-To: <inbox>'` or the equivalent SDK call).
 * For JS-delivered messages we extract that header and surface it as
 * the reply; without it, the message has no application reply
 * destination. */
static void resolve_app_reply(natsMsg *m, const char **reply,
	size_t *reply_len)
{
	if (*reply_len >= 8 &&
	    memcmp(*reply, "$JS.ACK.", 8) == 0) {
		const char *hdr_reply = NULL;
		natsStatus  hs;

		hs = nats_dl.natsMsgHeader_Get(m, "Nats-Reply-To", &hdr_reply);
		if (hs == NATS_OK && hdr_reply != NULL) {
			*reply     = hdr_reply;
			*reply_len = strlen(hdr_reply);
		} else {
			*reply     = NULL;
			*reply_len = 0;
		}
	}
}

/* Deliver one fetched natsMsg into the handle's SHM ring: poison
 * backstop, msg-ref stash, header serialization, ring push and the
 * full push-result dispatch (defer on ring-full, Term on oversize).
 * Always consumes @m (ownership transferred to the ref table on
 * success, destroyed otherwise).  Returns 1 iff the message was
 * pushed to the ring. */
static int push_one_msg(proc_sub_state_t *ss, natsMsg *m)
{
	const char *subject;
	const char *data;
	const char *reply;
	int         data_len;
	size_t      subject_len;
	size_t      reply_len;

	jsMsgMetaData *md = NULL;
	uint64_t  stream_seq   = 0;
	uint64_t  consumer_seq = 0;
	uint64_t  delivered    = 0;
	uint64_t  pending      = 0;
	int64_t   timestamp_ns = 0;
	uint64_t  ack_token    = 0;
	int       ref_ok       = 0;

	char     hdr_buf[NATS_RING_HEADERS_MAX];
	int      hdr_len       = 0;
	int      hdr_truncated = 0;
	int      hdr_count     = 0;

	int rc;

	subject     = nats_dl.natsMsg_GetSubject(m);
	data        = nats_dl.natsMsg_GetData(m);
	data_len    = nats_dl.natsMsg_GetDataLength(m);
	reply       = nats_dl.natsMsg_GetReply(m);
	subject_len = subject ? strlen(subject) : 0;
	reply_len   = reply   ? strlen(reply)   : 0;
	/* Keep data/data_len consistent: a NULL payload pointer with a
	 * non-zero length would feed a bogus span to the ring push. */
	if (!data || data_len < 0)
		data_len = 0;

	/* JetStream pull deliveries carry the $JS.ACK subject in the
	 * reply slot; surface the publisher's Nats-Reply-To header (if
	 * any) as the application reply instead. */
	resolve_app_reply(m, &reply, &reply_len);

	/* Serialize headers into the per-message stack buffer; ring_push
	 * copies the bytes into the slot so this local array's lifetime
	 * ends with the loop iteration. */
	hdr_len = serialize_headers(m, hdr_buf, (int)sizeof(hdr_buf),
		&hdr_truncated, &hdr_count);
	if (hdr_truncated) {
		LM_DBG("nats_consumer_proc: headers truncated on id='%.*s' "
			"(count_emitted=%d cap=%d)\n",
			ss->id.len, ss->id.s,
			hdr_count, (int)sizeof(hdr_buf));
	}

	if (nats_dl.natsMsg_GetMetaData(&md, m) == NATS_OK && md) {
		stream_seq   = md->Sequence.Stream;
		consumer_seq = md->Sequence.Consumer;
		delivered    = md->NumDelivered;
		pending      = md->NumPending;
		timestamp_ns = md->Timestamp;
		nats_dl.jsMsgMetaData_Destroy(md);
		/* Track the high-water stream sequence so a
		 * vanished+recreated durable can resume past it. */
		if (stream_seq > ss->last_stream_seq)
			ss->last_stream_seq = stream_seq;
	}

	/* Poison-message backstop.  With max_deliver=0 the broker
	 * redelivers a permanently-failing message forever with no
	 * dead-letter.  When poison_max_deliver is configured and this
	 * message has already been delivered more than that many times,
	 * Term it (stop redelivery) instead of handing it to a worker
	 * that will only fail and redeliver it again.  Counts as both a
	 * Term and a poison drop. */
	if (nats_consumer_poison_max_deliver > 0 &&
			delivered > (uint64_t)nats_consumer_poison_max_deliver) {
		LM_WARN("nats_consumer_proc: poison message on id='%.*s' "
			"(delivered=%llu > poison_max_deliver=%d); terminating\n",
			ss->id.len, ss->id.s,
			(unsigned long long)delivered,
			nats_consumer_poison_max_deliver);
		(void)nats_dl.natsMsg_Term(m, NULL);
		hstat_add(ss->h_ref, &ss->h_ref->terms, 1);
		hstat_add(ss->h_ref, &ss->h_ref->poisoned, 1);
		nats_dl.natsMsg_Destroy(m);
		return 0;
	}

	/* Stash the natsMsg under a fresh (handle, slot, gen) token.
	 * On ref-table exhaustion we leave the broker to redeliver --
	 * not acking this message means it comes back after
	 * ack_wait, by which time workers will (hopefully) have
	 * caught up on their ack backlog. */
	ack_token = store_msg_ref(ss->handle_idx,
		nats_ring_capacity(ss->ring),
		ss->h_ref ? ss->h_ref->ack_wait_ms : 0, m, &ref_ok);
	if (!ref_ok) {
		/* msg-ref table exhausted: the message was fetched but
		 * can't be tracked for ack, so leave it un-acked and let
		 * the broker redeliver after ack_wait. */
		hstat_add(ss->h_ref, &ss->h_ref->backpressure_drops, 1);
		nats_dl.natsMsg_Destroy(m);
		return 0;
	}

	rc = nats_ring_push(ss->ring, &(nats_ring_msg_t){
			.subject = subject ? subject : "",
			.subject_len = (uint32_t)subject_len,
			.data = data ? data : "",
			.data_len = (uint32_t)data_len,
			.stream_seq = stream_seq,
			.consumer_seq = consumer_seq,
			.delivered = delivered,
			.pending = pending,
			.timestamp_ns = timestamp_ns,
			.ack_token = ack_token,
			.reply_to = reply ? reply : "",
			.reply_to_len = (uint32_t)reply_len,
			.headers = hdr_len > 0 ? hdr_buf : NULL,
			.headers_len = (uint16_t)(hdr_len > 0 ? hdr_len : 0),
			.headers_truncated = (uint8_t)(hdr_truncated ? 1 : 0),
		});

	if (rc == 0) {
		hstat_add(ss->h_ref, &ss->h_ref->msgs_delivered, 1);
		if (delivered > 1)
			hstat_add(ss->h_ref, &ss->h_ref->redeliveries, 1);
		/* natsMsg stays alive in the ref table until the worker
		 * sends an ack IPC.  Do NOT destroy it here. */
	} else if (rc == -1) {
		/* Ring full: release the ref slot and do NOT ack.
		 * Broker redelivers after ack_wait. */
		(void)release_msg_ref(ack_token);
		hstat_add(ss->h_ref, &ss->h_ref->backpressure_drops, 1);
		LM_DBG("nats_consumer_proc: ring full id='%.*s', "
			"deferring message\n",
			ss->id.len, ss->id.s);
		nats_dl.natsMsg_Destroy(m);
	} else {
		/* -2 / -3: payload or subject too large.  These are
		 * permanently undeliverable on the current ring
		 * geometry; terminate the message so the broker
		 * doesn't redeliver forever.  Release the ref slot
		 * first so we don't leak it on retry. */
		(void)release_msg_ref(ack_token);
		/* This is a permanent Term, not back-pressure -- it is
		 * counted via the per-handle `terms` counter below, so do
		 * not also fold it into backpressure_drops. */
		{
			/* Rate-limit: a stream of oversize messages must not
			 * flood the log (the `terms` counter below still records
			 * every one). */
			long long now = now_monotonic_us();
			if (now - ss->last_oversize_warn_us >=
					NATS_OVERSIZE_WARN_INTERVAL_US) {
				LM_WARN("nats_consumer_proc: oversize message on "
					"id='%.*s' (subject_len=%zu data_len=%d rc=%d); "
					"terminating (rate-limited)\n",
					ss->id.len, ss->id.s,
					subject_len, data_len, rc);
				ss->last_oversize_warn_us = now;
			}
		}
		(void)nats_dl.natsMsg_Term(m, NULL);
		hstat_add(ss->h_ref, &ss->h_ref->terms, 1);
		nats_dl.natsMsg_Destroy(m);
	}

	return rc == 0 ? 1 : 0;
}

static int pull_one_batch(proc_sub_state_t *ss, int budget_ms)
{
	natsMsgList  list;
	int          pushed = 0;
	int          i;

	if (!ss || !ss->sub || !ss->ring)
		return 0;

	/* In-use guard: hold a pending_ops reference across the blocking
	 * Fetch() + push loop so unbind can defer while we're mid-pull.
	 * Paired with the dec below. */
	nats_handle_pending_inc(ss->h_ref);

	if (!proc_fetch_batch(ss, budget_ms, &list))
		goto out;

	ss->last_fetch = time(NULL);

	for (i = 0; i < list.Count; i++) {
		natsMsg *m = list.Msgs[i];
		if (!m)
			continue;
		pushed += push_one_msg(ss, m);
		/* push_one_msg always consumes the message (ref table on
		 * success, destroyed otherwise). */
		list.Msgs[i] = NULL;
	}

	/* natsMsgList_Destroy walks the Msgs array and destroys any
	 * non-NULL entries; we've already consumed (or destroyed) ours
	 * above, so this just frees the Msgs array itself. */
	nats_dl.natsMsgList_Destroy(&list);

out:
	nats_handle_pending_dec(ss->h_ref);
	return pushed;
}

/* Pump the core-IPC pipe: each pending job is one
 * worker->consumer request (an ack verb or an async-RPC publish).
 * Gated on a live broker connection so jobs wait in the pipe
 * across reconnects -- the pipe IS the queue.  The core's
 * ipc_handle_all_pending_jobs() uses recv(MSG_PEEK), which is a no-op
 * on the pipe fds pt[] actually carries, so readability is probed with
 * a zero-timeout poll per job instead.  Returns 1 if any job ran. */
static int pump_worker_ipc(void)
{
	struct pollfd pfd;
	int fd = IPC_FD_READ_SELF;
	int ran = 0;

	if (fd < 0 || !nats_pool_get())
		return 0;
	pfd.fd = fd;
	pfd.events = POLLIN;
	while (poll(&pfd, 1, 0) == 1 && (pfd.revents & POLLIN)) {
		ipc_handle_job(fd);
		ran = 1;
	}
	return ran;
}

/* ── retire teardown ─────────────────────────────────────────── */

/*
 * Walk g_subs and tear down any proc_sub_state_t whose underlying
 * handle is (a) gone from the registry entirely, or (b) still in the
 * registry but with retire=1.  For case (b) we set sub_torn_down on
 * the handle so nats_registry_reap() can free it; for case (a) the
 * handle was already freed by a parallel teardown path, so we just
 * drop our ss.
 *
 * Must NOT be called while iterating g_subs via another pointer --
 * it mutates the list.  The main loop calls this after the pull /
 * drain phases complete so the iteration pointers have gone out of
 * scope.
 */
static void tear_down_retired_subs(void)
{
	proc_sub_state_t **pp = &g_subs;

	while (*pp) {
		proc_sub_state_t *ss = *pp;
		/* Resolve the handle by IDENTITY (the pointer stashed at ss
		 * creation), not by id string.  An id-keyed weak lookup would
		 * return a freshly-rebound handle of the same id (retire==0) and
		 * we'd never tear down the old retired one it actually belongs
		 * to.  ss->h_ref is safe to deref here: while ss is on g_subs its
		 * handle has not been reaped (reap requires sub_torn_down, which
		 * only this teardown sets — and it then removes ss). */
		nats_handle_t *h = ss->h_ref;

		int should_tear_down = 0;
		if (!h) {
			/* Defensive: no handle reference (should not happen for a
			 * created ss).  Tear down the proc-local state only. */
			should_tear_down = 1;
		} else if (__atomic_load_n(&h->retire, __ATOMIC_SEQ_CST)) {
			should_tear_down = 1;
		}

		if (!should_tear_down) {
			pp = &(*pp)->next;
			continue;
		}

		LM_INFO("nats_consumer_proc: tearing down retired "
			"subscription id='%.*s'\n",
			ss->id.len, ss->id.s);

		if (ss->sub) {
			nats_dl.natsSubscription_Unsubscribe(ss->sub);
			nats_dl.natsSubscription_Destroy(ss->sub);
			ss->sub = NULL;
		}

		/* Free the C-strings and arrays we stashed when we built
		 * the natsSubscription. */
		free_proc_sub_strings(ss);

		/*
		 * Reclaim the process-local msg-ref row for this handle.  After
		 * the subscription is destroyed no more acks can arrive for it,
		 * but messages that were pushed to the ring and not yet acked
		 * still hold a live natsMsg* in g_msg_refs[handle_idx].slots[*]
		 * whose msg->sub now dangles.  purge_msg_ref_row destroys every
		 * in-use natsMsg, frees the row's slots buffer (calloc'd in
		 * ensure_row) and zeroes the row -- otherwise a later ack would
		 * deref the freed subscription and both the slots buffer and the
		 * libnats messages would leak for the process lifetime.
		 */
		purge_msg_ref_row(ss->handle_idx);

		if (h) {
			/* Publish the teardown completion so the reaper can
			 * free the handle.  This store MUST happen AFTER the
			 * subscription destroy + string free so the reaper sees
			 * a fully torn-down handle if it observes sub_torn_down=1. */
			__atomic_store_n(&h->sub_torn_down, 1, __ATOMIC_SEQ_CST);
		}

		*pp = ss->next;
		if (ss->handle_idx < NATS_REGISTRY_MAX_HANDLES &&
		    g_subs_by_idx[ss->handle_idx] == ss)
			g_subs_by_idx[ss->handle_idx] = NULL;

		/* Clear the handle's subscription publish pointer; the handle
		 * may still be on the retire list (not yet reaped) and MI
		 * could observe it.  Do this AFTER the sub_torn_down store
		 * above so there's no window where sub_torn_down=1 but the
		 * handle->subscription pointer still looks live. */
		if (h)
			h->subscription = NULL;

		free(ss->id.s);
		free(ss);
	}
}

/*
 * Mark retired handles that never got a subscription as torn down.
 *
 * tear_down_retired_subs() above only walks g_subs, so a handle that was
 * bound and then unbound before the consumer process ever built a
 * subscription for it has no g_subs entry -- its sub_torn_down is never
 * set, the reaper never frees it, and its ring (allocated at bind time)
 * leaks for the process lifetime.  Walk the registry's retire list and set
 * sub_torn_down on any retired handle that has no live proc-sub state.
 */
static int mark_orphan_retired_cb(nats_handle_t *h, void *user)
{
	(void)user;
	if (!h)
		return 0;
	/* Already torn down (or handled by the g_subs pass) -- nothing to do. */
	if (__atomic_load_n(&h->sub_torn_down, __ATOMIC_SEQ_CST))
		return 0;
	/* A live proc-sub state means the g_subs teardown pass owns this
	 * handle; only handles with NO g_subs entry were never subscribed. */
	if (h->index < NATS_REGISTRY_MAX_HANDLES &&
	    g_subs_by_idx[h->index] != NULL)
		return 0;
	/* A failed first subscribe presizes the msg-ref row BEFORE the
	 * subscribe attempt (presize_msg_ref_row), and with no g_subs entry
	 * no subscription-teardown path ever purges it — the slot buffer
	 * (up to ~1.5 MB) would leak for the process lifetime and a later
	 * handle recycling this index would inherit the stale row.  Purge
	 * it here; no-op if no row was ever presized. */
	if (h->index < NATS_REGISTRY_MAX_HANDLES)
		purge_msg_ref_row(h->index);
	__atomic_store_n(&h->sub_torn_down, 1, __ATOMIC_SEQ_CST);
	LM_INFO("nats_consumer_proc: marking never-subscribed retired handle "
		"id='%.*s' torn down so it can be reaped\n",
		h->id.len, h->id.s);
	return 0;
}

void mark_orphan_retired_handles(void)
{
	nats_registry_foreach_retired(mark_orphan_retired_cb, NULL);
}

/* ── main loop ───────────────────────────────────────────────── */

void nats_consumer_proc_main(int rank)
{
	int retry_fd;
	nats_epoch_t proc_epoch;   /* tag of the current sub set */

	LM_INFO("nats_consumer_proc: starting (pid=%d rank=%d)\n",
		(int)getpid(), rank);

	/* Publish our pt index FIRST -- before the connect-retry
	 * loop below, which can sleep for as long as the broker is down.
	 * Worker ipc_send_rpc() calls target this index; the IPC pipe
	 * exists from fork time, so jobs sent while we are still
	 * connecting simply wait in the pipe (the pump below is gated on
	 * a live connection), exactly like they used to wait in the SHM
	 * queue. */
	if (nats_consumer_hb)
		atomic_store_explicit(&nats_consumer_hb->consumer_proc_no,
			process_no, memory_order_release);

	/* Acquire the NATS connection + JetStream context.  Do NOT return on
	 * failure: an unexpected exit of this dedicated process is fatal to
	 * the whole OpenSIPS instance, so a broker that is merely down at boot
	 * would otherwise take the entire SIP server down with it.  Retry
	 * until the broker is reachable instead.  nats_pool_get() re-attempts
	 * its bounded internal connect on each call while the connection is
	 * unset, so repeated calls are safe; the sleep is interrupted by
	 * SIGTERM so shutdown remains prompt. */
	{
		int attempt = 0;
		const int boot_retry_s = 2;
		for (;;) {
			g_nc = nats_pool_get();
			if (g_nc) {
				g_js = nats_pool_get_js();
				if (g_js)
					break;
				LM_WARN("nats_consumer_proc: NATS connected but no "
					"JetStream context (attempt %d); retrying in "
					"%ds instead of exiting\n",
					++attempt, boot_retry_s);
			} else {
				LM_WARN("nats_consumer_proc: no NATS connection "
					"(broker down?, attempt %d); retrying in %ds "
					"instead of exiting (an exit would abort the "
					"instance)\n", ++attempt, boot_retry_s);
			}
			sleep(boot_retry_s);
		}
	}

	nats_epoch_save(&proc_epoch);

	/* Blocking-idle timerfd -- armed each idle round to cap how long
	 * we sleep when there is no worker ack traffic.  If timerfd_create
	 * fails we fall back to a coarse 1s select() timeout. */
	retry_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
	if (retry_fd < 0) {
		LM_WARN("nats_consumer_proc: timerfd_create failed (%s); "
			"falling back to 1s select timeout\n", strerror(errno));
	}

	/* Async nats_request: stand up the persistent inbox
	 * subscription so worker-issued RPCs can route their
	 * publish + reply through this process (libnats-safe
	 * context) instead of running directly in the SIP worker
	 * (libnats-unsafe context).  Non-fatal: if the subscribe
	 * fails the IPC drain below will surface -3 to each
	 * pending slot. */
	if (nats_rpc_consumer_subscribe() < 0) {
		LM_WARN("nats_consumer_proc: async inbox subscribe "
			"failed; async nats_request RPCs that arrive on "
			"the IPC will be marked abandoned\n");
	}

	LM_INFO("nats_consumer_proc: pool ready, ipc_fd=%d retry_fd=%d, "
		"baseline_epoch=%d, entering main loop\n",
		IPC_FD_READ_SELF, retry_fd, proc_epoch.seen);

	if (nats_consumer_hb) {
		atomic_store_explicit(&nats_consumer_hb->consumer_pid,
			(int)getpid(), memory_order_relaxed);
		nats_consumer_hb_tick();
	}

	long long last_reap_us = now_monotonic_us();

	for (;;) {
		nats_consumer_hb_tick();
		proc_sub_state_t *ss;
		int any_work = 0;
		int cur_epoch;

#ifdef UNIT_TESTS
		/* The unit test suite holds this process between iterations
		 * while it works on the shared registry, rings and RPC slots
		 * (nc_ut_hold_consumer()). */
		if (nc_ut_hold && __atomic_load_n(&nc_ut_hold[0], __ATOMIC_SEQ_CST)) {
			__atomic_store_n(&nc_ut_hold[1], 1, __ATOMIC_SEQ_CST);
			usleep(10 * 1000);
			continue;
		}
		if (nc_ut_hold)
			__atomic_store_n(&nc_ut_hold[1], 0, __ATOMIC_SEQ_CST);
#endif

		/* Periodically reclaim msg-ref slots orphaned by workers that
		 * died after popping a message but before acking (otherwise the
		 * per-handle table fills and delivery stalls). */
		{
			long long now = now_monotonic_us();
			if (now - last_reap_us >= NATS_MSG_REF_REAP_INTERVAL_US) {
				reap_orphan_msg_refs();
				/* also reclaim RPC slots whose owning
				 * worker died mid-call (nothing else returns
				 * them to the shared pool). */
				(void)nats_rpc_slot_reap_orphans(now);
				last_reap_us = now;
			}
		}

		/* 0. Reconnect-epoch check.  The nats.c library bumps
		 *    the epoch from its reconnect callback (on a library
		 *    thread); here we observe the bump and mark every live
		 *    subscription dirty so the next reconcile pass rebuilds
		 *    them.  Destroying the old subs immediately avoids the
		 *    "ghost subscription held against a new connection"
		 *    failure mode where nats.c has internally re-plumbed
		 *    everything but our old Subscription* still points at a
		 *    dead context. */
		cur_epoch = nats_epoch_snapshot();
		if (!nats_epoch_current(&proc_epoch)) {
			LM_INFO("nats_consumer_proc: reconnect detected "
				"(epoch %d -> %d); refreshing all subscriptions\n",
				proc_epoch.seen, cur_epoch);
			for (ss = g_subs; ss; ss = ss->next) {
				if (ss->sub) {
					nats_dl.natsSubscription_Unsubscribe(ss->sub);
					nats_dl.natsSubscription_Destroy(ss->sub);
					ss->sub = NULL;
					/* Old-connection subscription is dead; every fetched
					 * natsMsg still held in this handle's ref row now has a
					 * dangling msg->sub.  Purge before the rebuild so a late
					 * ack can't deref the freed sub (UAF); JetStream
					 * redelivers the un-acked messages on reconnect. */
					purge_msg_ref_row(ss->handle_idx);
				}
				ss->dirty = 1;
			}
			/* adopt the PRE-refresh snapshot: a reconnect landing
			 * mid-loop re-triggers this block next tick */
			nats_epoch_adopt(&proc_epoch, cur_epoch);
		}

		/* 0b. Async-RPC inbox retry.  The one-shot subscribe before the
		 *     loop may have failed transiently (pool not yet connected,
		 *     etc.); without a retry every async nats_request for the
		 *     rest of this process's life would publish to a deaf inbox.
		 *     Idempotent and cheap (a pointer check) once the inbox is
		 *     up; only attempts a real Subscribe while it is down. */
		if (!nats_rpc_consumer_inbox_ready()) {
			if (nats_rpc_consumer_subscribe() == 0)
				LM_INFO("nats_consumer_proc: async inbox subscription "
					"recovered\n");
		}

		/* 1. Reconcile subscriptions with the registry.  New binds
		 *    land here on the next tick; dirty subs are rebuilt in
		 *    place. The unlocked walk: reconcile runs
		 *    JetStream calls (seconds each against a slow broker),
		 *    which must not hold the registry read locks -- writer
		 *    priority would let one queued MI unbind stall every
		 *    SIP-worker fetch lookup for the duration.  Handles are
		 *    pending_ops-pinned instead; reconcile_subs_cb's retire
		 *    check covers the unbind-after-snapshot race and the
		 *    retire teardown sweep below destroys any sub a raced
		 *    ensure created for a freshly-retired handle. */
		(void)nats_registry_foreach_unlocked(reconcile_subs_cb, NULL);

		/* 2. Fetch + push for every live subscription.  A ring-full
		 *    handle contributes 0 to any_work so the idle sleep
		 *    applies and we don't burn CPU spinning on it.
		 *
		 *    The per-fetch wait is budgeted by the number of handles so
		 *    the whole sweep stays bounded at ~one fetch_timeout instead
		 *    of num_handles * fetch_timeout, and the latency-sensitive
		 *    async-RPC publish IPC is drained between fetches so an RPC
		 *    isn't stuck behind a sweep of idle handles. */
		{
			int num_subs = 0, budget;
			for (ss = g_subs; ss; ss = ss->next)
				num_subs++;
			budget = fetch_budget_ms(nats_consumer_fetch_timeout_ms,
				num_subs);
			for (ss = g_subs; ss; ss = ss->next) {
				int pushed = pull_one_batch(ss, budget);
				if (pushed > 0)
					any_work = 1;
				if (num_subs > 1 && pump_worker_ipc())
					any_work = 1;
			}
		}

		/* 3. Service worker acks + async-RPC publishes: pump the
		 *    core-IPC pipe, then honour any ACK_NEXT refill
		 *    hints the ack handlers set on this tick -- the extra
		 *    pull runs now instead of waiting for the next idle
		 *    wake-up (fallback for the missing +NXT payload API).
		 * fresh AckSync budget for this tick's drain. */
		nats_ack_ipc_tick_reset();
		if (pump_worker_ipc())
			any_work = 1;
		for (ss = g_subs; ss; ss = ss->next) {
			if (nats_ack_next_take(ss->handle_idx)) {
				/* the next message is likely already waiting: use
				 * the full timeout (0 = no cap) -- this is not part
				 * of the idle sweep */
				int pushed = pull_one_batch(ss, 0);
				if (pushed > 0)
					any_work = 1;
			}
		}

		/* 4. Retire/reap lifecycle: tear down subscriptions whose
		 *    handles are retiring, then reap any fully-drained handles.
		 *    Running these every iteration keeps the unbind latency
		 *    bounded (worst case: one iteration delay between unbind
		 *    and reap).  Both are cheap when the retire list is
		 *    empty. */
		tear_down_retired_subs();
		mark_orphan_retired_handles();
		nats_registry_reap();

		if (!any_work) {
			/* Blocking idle: wait until the core-IPC pipe becomes
			 * readable (a worker acked something or issued an async
			 * nats_request) or the retry timerfd fires
			 * (bounded stall recovery).  Avoids a busy poll
			 * so the consumer process spends ~0% CPU on empty
			 * subscriptions.  The IPC fd only joins the set while
			 * the broker connection is live -- the pump is gated on
			 * it, so selecting on it while disconnected would spin;
			 * the 1s timeout covers reconnect progress instead. */
			fd_set rfds;
			int    maxfd = -1;
			int    ipc_fd = nats_pool_get() ? IPC_FD_READ_SELF : -1;
			struct timeval tv;

			FD_ZERO(&rfds);
			if (ipc_fd >= 0) {
				FD_SET(ipc_fd, &rfds);
				if (ipc_fd > maxfd) maxfd = ipc_fd;
			}

			if (retry_fd >= 0) {
				struct itimerspec its;
				memset(&its, 0, sizeof(its));
				its.it_value.tv_sec  = IDLE_RETRY_MS / 1000;
				its.it_value.tv_nsec =
					(IDLE_RETRY_MS % 1000) * 1000000L;
				if (timerfd_settime(retry_fd, 0, &its, NULL) == 0) {
					FD_SET(retry_fd, &rfds);
					if (retry_fd > maxfd) maxfd = retry_fd;
				}
			}

			tv.tv_sec  = 1;
			tv.tv_usec = 0;
			(void)select(maxfd + 1, &rfds, NULL, NULL, &tv);

			/* Drain the retry timer so the next arm is fresh. */
			if (retry_fd >= 0 && FD_ISSET(retry_fd, &rfds)) {
				uint64_t sink;
				ssize_t r;
				do {
					r = read(retry_fd, &sink, sizeof(sink));
				} while (r < 0 && errno == EINTR);
			}

			/* A readable IPC pipe needs no rearm here -- pipes are
			 * level-triggered and the jobs are consumed by
			 * pump_worker_ipc() on the next loop iteration. */
		}
	}
}

#ifdef UNIT_TESTS
/* [0]: a hold is asked for; [1]: the consumer process is holding */
int *nc_ut_hold;

int nc_ut_hold_init(void)
{
	nc_ut_hold = shm_malloc(2 * sizeof *nc_ut_hold);
	if (!nc_ut_hold)
		return -1;
	nc_ut_hold[0] = nc_ut_hold[1] = 0;
	return 0;
}

int nc_ut_hold_consumer(int on)
{
	int i;

	if (!nc_ut_hold)
		return -1;
	__atomic_store_n(&nc_ut_hold[0], on ? 1 : 0, __ATOMIC_SEQ_CST);
	/* one loop iteration: the idle wait is at most IDLE_RETRY_MS */
	for (i = 0; i < 300; i++) {
		if (__atomic_load_n(&nc_ut_hold[1], __ATOMIC_SEQ_CST) == (on ? 1 : 0))
			return 0;
		usleep(10 * 1000);
	}
	return -1;
}

int nc_ut_fetch_budget_ms(int configured, int num_subs)
{
	return fetch_budget_ms(configured, num_subs);
}

int nc_ut_proc_fetch_batch(proc_sub_state_t *ss, int budget_ms,
	natsMsgList *list)
{
	return proc_fetch_batch(ss, budget_ms, list);
}

void nc_ut_tear_down_retired_subs(void)
{
	tear_down_retired_subs();
}

int nc_ut_push_one_msg(proc_sub_state_t *ss, natsMsg *m)
{
	return push_one_msg(ss, m);
}

void nc_ut_mark_orphan_retired_handles(void)
{
	mark_orphan_retired_handles();
}
#endif
