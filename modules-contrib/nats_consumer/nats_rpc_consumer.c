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
 * nats_rpc_consumer.c -- consumer-process side of the
 * consumer-process-routed async nats_request transport.  See
 * nats_rpc_consumer.h for the architecture rationale.
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdatomic.h>
#include <unistd.h>
#include <errno.h>

#include <nats/nats.h>

#include "../../dprint.h"
#include "../../mem/shm_mem.h"
#include "../nats/nats_bind.h"
#include "../nats/nats_pool.h"

#include "nats_rpc_consumer.h"
#include "nats_rpc_slot.h"
#include "nats_rpc_subject.h" /* reply-subject build/parse + generation */
#include "nats_rpc_ipc.h"
#include "nats_rpc_wake.h" /* IPC-wake the claiming worker */
#include "nats_ring.h"     /* NATS_RING_*_MAX */
#include "nats_rpc.h"      /* nats_rpc_hdr_deserialize_to_msg */

/* Shared headers helper -- promoted to public in nats_rpc.c so
 * the sync, async-worker, and consumer-process-routed async reply
 * paths produce byte-identical serialised header streams. */
extern int nats_rpc_hdr_serialize_from_reply(natsMsg *m, char *out, int cap,
                                              int *truncated, int *count_out);

/*
 * Persistent inbox subscription handle.  Lives only inside the
 * consumer process; the file descriptor / thread state is owned
 * by libnats.  Cleared on consumer shutdown.
 */
static natsSubscription *g_inbox_sub = NULL;

/* Cached consumer-side inbox prefix used to (a) format the
 * SUBSCRIBE subject and (b) parse the slot_idx out of incoming
 * reply subjects.  Format: "_INBOX.opensips.<pid>".  The reply
 * subject pattern is "<prefix>.<slot_idx>". */
#define NATS_RPC_INBOX_PREFIX "_INBOX.opensips"
static char g_inbox_prefix[64];
static int  g_inbox_prefix_len;

/* ── reply callback (libnats thread) ─────────────────────────── */

/*
 * libnats subscription callback.  Runs on a libnats internal
 * thread INSIDE the consumer process -- safe for libnats use
 * but MUST NOT touch OpenSIPS APIs that are worker-private.
 *
 * We only touch the SHM slot (via the slot_idx parsed from the
 * reply subject suffix): copy the reply payload into the slot,
 * transition state INFLIGHT -> DELIVERED with release ordering,
 * then IPC-wake the claiming worker so its resume runs at
 * wire latency instead of on the next guard tick (calling
 * ipc_send_rpc from a libnats thread follows the established
 * event_nats pattern).  A lost wake is covered by the worker's
 * coarse guard timerfd.
 */
static void on_inbox_reply(natsConnection *nc, natsSubscription *sub,
                            natsMsg *msg, void *closure)
{
	const char *subject;
	const char *data;
	const char *reply_to;
	int         data_len;
	int         subj_len;
	int         reply_len = 0;
	uint32_t    slot_idx = 0;
	uint32_t    gen = 0;
	char        corr[40];
	nats_rpc_slot_t *s;

	(void)nc; (void)sub; (void)closure;

	if (!msg) return;

	subject  = nats_dl.natsMsg_GetSubject(msg);
	subj_len = subject ? (int)strlen(subject) : 0;
	data     = nats_dl.natsMsg_GetData(msg);
	data_len = nats_dl.natsMsg_GetDataLength(msg);
	reply_to = nats_dl.natsMsg_GetReply(msg);
	if (reply_to) reply_len = (int)strlen(reply_to);

	if (nats_rpc_subject_parse(subject, subj_len, &slot_idx, &gen,
			corr, sizeof(corr)) < 0) {
		/* malformed reply subject -- drop quietly.  Could be
		 * an unrelated message that matched our wildcard or a
		 * malicious peer; either way, no slot to deliver to. */
		nats_dl.natsMsg_Destroy(msg);
		return;
	}

	s = nats_rpc_slot_lookup(slot_idx);
	if (!s) {
		/* slot is FREE or out of range -- either the worker
		 * timed out and freed the slot before the reply
		 * arrived, or a stale reply from a previous use of
		 * the same slot.  Drop silently. */
		nats_dl.natsMsg_Destroy(msg);
		return;
	}

	/* Generation guard: a reply echoes the generation captured when
	 * its request was published.  If the slot has since been freed and
	 * re-claimed by a different request, the slot's generation has
	 * advanced and this is a stale reply for the previous claim.  Drop
	 * it rather than deliver another request's payload to the new
	 * claimant.  (Reading state==INFLIGHT below is not sufficient: the
	 * new claim may also be INFLIGHT.) */
	if (atomic_load_explicit(&s->generation, memory_order_relaxed) != gen) {
		nats_dl.natsMsg_Destroy(msg);
		return;
	}

	/* Authenticate the reply by its correlation id.  The reply subject
	 * lives under a shared "<prefix>.>" wildcard that any broker peer can
	 * publish to; slot_idx and generation are small and guessable, so a
	 * peer could forge a reply for an in-flight slot.  The corr_id is the
	 * per-call UUIDv7 (74 bits of entropy) the worker stored on the slot;
	 * a reply whose corr_id token does not match it is a forgery (or a
	 * stale reply from a recycled slot whose generation happened to
	 * collide) and is dropped. */
	{
		size_t clen = strlen(corr);
		if (s->corr_id_len == 0 ||
		    clen != (size_t)s->corr_id_len ||
		    memcmp(corr, s->corr_id, clen) != 0) {
			nats_dl.natsMsg_Destroy(msg);
			return;
		}
	}

	/* Pin the claim BEFORE writing reply_* or re-validating the generation.
	 * CAS INFLIGHT -> DELIVERING: if it fails, the worker already ABANDONED
	 * (or the slot is otherwise non-INFLIGHT) -- drop.  While the slot is
	 * DELIVERING the worker resume treats it as not-ready and never
	 * abandons+frees it (resume_nats_request_slot), so no reclaim -- hence no
	 * generation change -- can happen under us.  This makes "confirm this is
	 * still our claim" and "publish the reply" atomic w.r.t. the worker,
	 * closing the slot-reuse misdelivery window that existed when the
	 * generation re-check was a separate step after an INFLIGHT -> DELIVERED
	 * CAS (a worker that re-claimed the slot could observe DELIVERED with the
	 * old reply in the gap before the rollback). */
	{
		int expected = NATS_RPC_SLOT_INFLIGHT;
		if (!atomic_compare_exchange_strong_explicit(
				&s->state, &expected, NATS_RPC_SLOT_DELIVERING,
				memory_order_acq_rel, memory_order_relaxed)) {
			nats_dl.natsMsg_Destroy(msg);
			return;
		}
	}

	/* Now pinned.  Re-validate the generation: if the slot was freed and
	 * re-claimed before our pin, we pinned a DIFFERENT (newer) claim -- roll
	 * back to INFLIGHT so the new claimant is undisturbed, and drop this stale
	 * reply.  Only we transition out of DELIVERING, so a plain store is safe. */
	if (atomic_load_explicit(&s->generation, memory_order_relaxed) != gen) {
		atomic_store_explicit(&s->state, NATS_RPC_SLOT_INFLIGHT,
			memory_order_release);
		nats_dl.natsMsg_Destroy(msg);
		return;
	}

	/* Copy subject (bounded). */
	if (subj_len > NATS_RING_SUBJECT_MAX) subj_len = NATS_RING_SUBJECT_MAX;
	if (subj_len > 0 && subject)
		memcpy(s->reply_subject, subject, subj_len);
	s->reply_subject_len = (uint32_t)subj_len;

	/* Copy payload (bounded). */
	if (data_len < 0) data_len = 0;
	if (data_len > NATS_RING_PAYLOAD_MAX) data_len = NATS_RING_PAYLOAD_MAX;
	if (data_len > 0 && data)
		memcpy(s->reply_data, data, data_len);
	s->reply_data_len = (uint32_t)data_len;

	/* Copy reply-to if present. */
	if (reply_to && reply_len > 0) {
		if (reply_len > NATS_RING_SUBJECT_MAX)
			reply_len = NATS_RING_SUBJECT_MAX;
		memcpy(s->reply_to, reply_to, reply_len);
		s->reply_to_len = (uint32_t)reply_len;
		s->reply_has_reply_to = 1;
	} else {
		s->reply_to_len = 0;
		s->reply_has_reply_to = 0;
	}

	/* Serialise headers using the shared helper -- same wire
	 * format as the sync nats_reply / fetch paths. */
	{
		int trunc = 0, count = 0;
		int hdr_len = nats_rpc_hdr_serialize_from_reply(msg,
			s->reply_headers, NATS_RING_HEADERS_MAX,
			&trunc, &count);
		if (hdr_len < 0) hdr_len = 0;
		s->reply_headers_len       = (uint16_t)hdr_len;
		s->reply_headers_truncated = (uint8_t)(trunc ? 1 : 0);
	}

	/* Publish: DELIVERING -> DELIVERED with release ordering so the worker
	 * observes the reply_* writes above.  The slot is pinned (only we
	 * transition out of DELIVERING) and the generation was validated while
	 * pinned, so a plain release store is correct and race-free -- the
	 * worker consumes this reply for exactly the claim it was minted for.
	 *
	 * Read the wake destination while still pinned (the worker
	 * cannot free/re-claim a DELIVERING slot, so owner_proc is stably
	 * ours here), then signal it AFTER the release store.  A refused
	 * send just means the worker resumes on its guard tick. */
	{
		int owner = atomic_load_explicit(&s->owner_proc,
			memory_order_relaxed);

		atomic_store_explicit(&s->state, NATS_RPC_SLOT_DELIVERED,
			memory_order_release);
		(void)nats_rpc_wake_send(owner, slot_idx, gen);
	}

	nats_dl.natsMsg_Destroy(msg);
}

/* ── public API ──────────────────────────────────────────────── */

int nats_rpc_consumer_subscribe(void)
{
	natsConnection *nc;
	natsStatus      s;
	char            wildcard[80];
	int             n;
	pid_t           pid;

	if (g_inbox_sub) {
		LM_DBG("nats_rpc_consumer_subscribe: already subscribed\n");
		return 0;
	}

	nc = nats_pool_get();
	if (!nc) {
		LM_ERR("nats_rpc_consumer_subscribe: no NATS connection\n");
		return -1;
	}

	pid = getpid();
	g_inbox_prefix_len = snprintf(g_inbox_prefix, sizeof(g_inbox_prefix),
		"%s.%d", NATS_RPC_INBOX_PREFIX, (int)pid);
	if (g_inbox_prefix_len <= 0 ||
	    g_inbox_prefix_len >= (int)sizeof(g_inbox_prefix)) {
		LM_ERR("nats_rpc_consumer_subscribe: prefix overflow\n");
		return -1;
	}

	n = snprintf(wildcard, sizeof(wildcard), "%s.>", g_inbox_prefix);
	if (n <= 0 || n >= (int)sizeof(wildcard)) {
		LM_ERR("nats_rpc_consumer_subscribe: wildcard overflow\n");
		return -1;
	}

	s = nats_dl.natsConnection_Subscribe(&g_inbox_sub, nc, wildcard,
		on_inbox_reply, NULL);
	if (s != NATS_OK || !g_inbox_sub) {
		LM_ERR("nats_rpc_consumer_subscribe: Subscribe(%s) failed: %s\n",
			wildcard, nats_dl.natsStatus_GetText(s));
		g_inbox_sub = NULL;
		return -1;
	}

	LM_INFO("nats_rpc_consumer: subscribed inbox %s\n", wildcard);
	return 0;
}

void nats_rpc_consumer_unsubscribe(void)
{
	if (g_inbox_sub) {
		nats_dl.natsSubscription_Unsubscribe(g_inbox_sub);
		nats_dl.natsSubscription_Destroy(g_inbox_sub);
		g_inbox_sub = NULL;
	}
}

/* Whether the reply inbox subscription is currently live.  Read by the
 * consumer main loop (to decide whether to retry the subscribe) and by
 * publish_cb (to fail a request fast instead of publishing to a deaf
 * inbox).  Both run in the single consumer process, so a plain read of the
 * process-local g_inbox_sub is sufficient. */
int nats_rpc_consumer_inbox_ready(void)
{
	return g_inbox_sub != NULL;
}

/* ── worker->consumer IPC hop ─────────────────────────── */

/* SHM counters behind the rpc_ipc_* MI stats.  The pipe itself has no
 * readable depth, so depth is derived: sent - drained. */
typedef struct nats_rpc_ipc_stats {
	_Atomic uint64_t sent;      /* worker: ipc_send_rpc succeeded */
	_Atomic uint64_t drained;   /* consumer: handler ran */
	_Atomic uint64_t dropped;   /* worker: send refused (pipe full /
	                             * consumer proc not up) */
} nats_rpc_ipc_stats_t;

static nats_rpc_ipc_stats_t *g_rpc_ipc_stats;

int nats_rpc_ipc_stats_init(void)
{
	g_rpc_ipc_stats = shm_malloc(sizeof(*g_rpc_ipc_stats));
	if (!g_rpc_ipc_stats) {
		LM_ERR("nats_rpc_consumer: shm_malloc for IPC stats failed\n");
		return -1;
	}
	memset(g_rpc_ipc_stats, 0, sizeof(*g_rpc_ipc_stats));
	return 0;
}

void nats_rpc_ipc_stats_destroy(void)
{
	if (g_rpc_ipc_stats) {
		shm_free(g_rpc_ipc_stats);
		g_rpc_ipc_stats = NULL;
	}
}

void nats_rpc_ipc_count_sent(int ok)
{
	if (!g_rpc_ipc_stats)
		return;
	atomic_fetch_add_explicit(ok ? &g_rpc_ipc_stats->sent
	                             : &g_rpc_ipc_stats->dropped,
		1, memory_order_relaxed);
}

uint64_t nats_rpc_ipc_enqueued_total(void)
{
	return g_rpc_ipc_stats ? atomic_load_explicit(&g_rpc_ipc_stats->sent,
		memory_order_relaxed) : 0;
}

uint64_t nats_rpc_ipc_drained_total(void)
{
	return g_rpc_ipc_stats ? atomic_load_explicit(
		&g_rpc_ipc_stats->drained, memory_order_relaxed) : 0;
}

uint64_t nats_rpc_ipc_dropped_total(void)
{
	return g_rpc_ipc_stats ? atomic_load_explicit(
		&g_rpc_ipc_stats->dropped, memory_order_relaxed) : 0;
}

uint32_t nats_rpc_ipc_depth(void)
{
	uint64_t s = nats_rpc_ipc_enqueued_total();
	uint64_t d = nats_rpc_ipc_drained_total();

	return s > d ? (uint32_t)(s - d) : 0;
}

/*
 * Consumer-side fail-fast: CAS INFLIGHT -> ABANDONED and, when the CAS
 * wins, IPC-wake the claiming worker so it surfaces the failure
 * immediately instead of waiting out its guard tick.  The CAS (rather
 * than a blind store) matters: the worker may have already timed out,
 * freed the slot, and another caller re-claimed it -- a blind store
 * would clobber the new claimer's state.  owner/generation are read
 * BEFORE the CAS; if the slot was re-claimed in that window the CAS
 * targets the new (also INFLIGHT) claim -- the same pre-existing
 * check-then-CAS window as before -- and the wake it emits carries a
 * generation the receiving worker's registry validates, so a stale
 * wake is dropped there.
 */
static void slot_abandon_and_wake(nats_rpc_slot_t *s)
{
	int      owner = atomic_load_explicit(&s->owner_proc,
		memory_order_relaxed);
	uint32_t gen   = atomic_load_explicit(&s->generation,
		memory_order_relaxed);
	int      expected = NATS_RPC_SLOT_INFLIGHT;

	if (atomic_compare_exchange_strong_explicit(
			&s->state, &expected, NATS_RPC_SLOT_ABANDONED,
			memory_order_release, memory_order_relaxed))
		(void)nats_rpc_wake_send(owner, s->slot_idx, gen);
}

/*
 * Build the outbound natsMsg from a slot's out_* fields and
 * publish it with reply-to pointing at our inbox subject so the
 * remote responder echoes a reply back into us.
 *
 * Headers serialized into slot->out_headers by the worker-side
 * w_nats_request_async (compact length-prefixed wire format --
 * see nats_rpc.h) are materialized onto the outbound natsMsg via
 * nats_rpc_hdr_deserialize_to_msg() before PublishMsg, so the
 * X-Request-Id auto-stage and any nats_hdr_set() calls reach the
 * remote responder verbatim.
 */
static void publish_slot(uint32_t slot_idx, uint32_t generation,
	natsConnection *nc)
{
	nats_rpc_slot_t *s;
	natsMsg         *out = NULL;
	natsStatus       st;
	char             reply_subject[128];
	char             subj_c[NATS_RING_SUBJECT_MAX + 1];
	int              n;

	if (!nc) return;

	s = nats_rpc_slot_lookup(slot_idx);
	if (!s) {
		LM_DBG("nats_rpc_consumer: drained publish for free slot %u "
			"(worker timed out?)\n", (unsigned)slot_idx);
		return;
	}

	/* Only proceed if the slot is still the SAME claim that sent this
	 * entry: INFLIGHT *and* matching generation.  A worker that
	 * ABANDONED before the pump (state no longer INFLIGHT) or a slot
	 * that was freed and re-claimed by a different request (generation
	 * advanced) must be skipped -- otherwise this stale entry would
	 * publish the new claim's request a second time. */
	if (!nats_rpc_slot_entry_is_current(s, generation)) {
		LM_DBG("nats_rpc_consumer: skipping stale IPC publish for slot "
			"%u gen %u (slot re-claimed or abandoned)\n",
			(unsigned)slot_idx, (unsigned)generation);
		return;
	}

	/* Dead-inbox fast-fail.  If our reply inbox subscription is down, a
	 * reply to this request can never route back to us -- publishing would
	 * only guarantee the worker blocks until its full timeout.  Abandon the
	 * slot now (CAS INFLIGHT -> ABANDONED, gen-safe against a re-claim) so
	 * the caller fails fast; the main loop keeps retrying the subscribe. */
	if (!nats_rpc_consumer_inbox_ready()) {
		slot_abandon_and_wake(s);
		LM_WARN("nats_rpc_consumer: reply inbox down; abandoning RPC "
			"slot %u instead of publishing to a deaf inbox\n",
			(unsigned)s->slot_idx);
		return;
	}

	/* Format the reply-to inbox subject pointing back at us, including
	 * the slot's current generation (rejects a stale reply for a recycled
	 * slot) and the per-call corr_id (authenticates the reply against a
	 * forged one -- see nats_rpc_subject.h).  A slot with no corr_id
	 * (UUID mint failed at request time) cannot be authenticated, so
	 * build returns -1 and the call is abandoned fail-closed below. */
	n = nats_rpc_subject_build(reply_subject, sizeof(reply_subject),
		g_inbox_prefix, s->slot_idx,
		atomic_load_explicit(&s->generation, memory_order_relaxed),
		s->corr_id, (int)s->corr_id_len);
	if (n < 0) {
		LM_ERR("nats_rpc_consumer: reply-subject build failed for slot %u "
			"(overflow or missing corr_id)\n", (unsigned)s->slot_idx);
		slot_abandon_and_wake(s);
		return;
	}

	/* Subject must be NUL-terminated for libnats; copy from the
	 * slot's bounded buffer with explicit NUL. */
	if (s->out_subject_len > NATS_RING_SUBJECT_MAX) {
		LM_ERR("nats_rpc_consumer: subject overflow on slot %u\n",
			(unsigned)s->slot_idx);
		slot_abandon_and_wake(s);
		return;
	}
	memcpy(subj_c, s->out_subject, s->out_subject_len);
	subj_c[s->out_subject_len] = '\0';

	st = nats_dl.natsMsg_Create(&out, subj_c, reply_subject,
		(const char *)s->out_data, (int)s->out_data_len);
	if (st != NATS_OK || !out) {
		LM_ERR("nats_rpc_consumer: natsMsg_Create failed for slot %u: %s\n",
			(unsigned)s->slot_idx, nats_dl.natsStatus_GetText(st));
		slot_abandon_and_wake(s);
		return;
	}

	/* Apply any worker-staged headers before publishing.  A malformed
	 * out_headers stream (return -1) means the worker emitted a
	 * truncated buffer; ignore the failure and publish whatever fit
	 * -- the worker already logged the truncation warning. */
	if (s->out_headers_len > 0) {
		(void)nats_rpc_hdr_deserialize_to_msg(s->out_headers,
			(int)s->out_headers_len, out);
	}

	st = nats_dl.natsConnection_PublishMsg(nc, out);
	nats_dl.natsMsg_Destroy(out);
	if (st != NATS_OK) {
		LM_ERR("nats_rpc_consumer: PublishMsg failed for slot %u: %s\n",
			(unsigned)s->slot_idx, nats_dl.natsStatus_GetText(st));
		slot_abandon_and_wake(s);
		return;
	}
	/* Slot stays INFLIGHT; the reply (matching reply_subject)
	 * will land in on_inbox_reply, transition the slot to
	 * DELIVERED and IPC-wake the claiming worker. */
}

/* The ipc_send_rpc handler for one worker->consumer publish request
 *.  Runs in the consumer process when the main loop pumps its
 * IPC fd (gated on a live connection, so nc is normally set; a
 * connection lost between the gate and this call abandons the slot
 * fail-fast, exactly like a failed PublishMsg). */
void nats_rpc_ipc_on_publish(int sender, void *param)
{
	uint32_t slot_idx, generation;
	natsConnection *nc = nats_pool_get();

	(void)sender;
	nats_rpc_ipc_unpack(param, &slot_idx, &generation);
	if (g_rpc_ipc_stats)
		atomic_fetch_add_explicit(&g_rpc_ipc_stats->drained, 1,
			memory_order_relaxed);
	if (!nc) {
		nats_rpc_slot_t *s = nats_rpc_slot_lookup(slot_idx);
		if (s && nats_rpc_slot_entry_is_current(s, generation)) {
			slot_abandon_and_wake(s);
			LM_WARN("nats_rpc_consumer: connection lost before "
				"publish; abandoning RPC slot %u\n",
				(unsigned)slot_idx);
		}
		return;
	}
	publish_slot(slot_idx, generation, nc);
}

#ifdef UNIT_TESTS
/* on_inbox_reply(), the libnats callback for replies on the inbox */
void nc_ut_on_inbox_reply(natsMsg *msg)
{
	on_inbox_reply(NULL, NULL, msg, NULL);
}

/* publish_slot(): the consumer process publishing a worker's request */
void nc_ut_publish_slot(uint32_t slot_idx, uint32_t generation,
	natsConnection *nc)
{
	publish_slot(slot_idx, generation, nc);
}
#endif
