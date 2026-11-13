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
 * nats_rpc.h -- script-callable NATS headers + reply-to + RPC.
 *
 * Entry points:
 *
 *   $nats_hdr(Name)           -- pseudo-var; reads a header from the
 *                                current message (populated by
 *                                nats_fetch / nats_fetch_batch +
 *                                nats_batch_select).  Case-insensitive
 *                                lookup, returns NULL on miss.
 *
 *   nats_hdr_set(name, value) -- stage a (name, value) pair onto the
 *                                per-worker outbound header buffer.
 *                                Replaces a staged entry with the same
 *                                name.  Cleared automatically after the
 *                                next outbound publish (nats_reply /
 *                                nats_request), even on publish failure.
 *
 *   nats_reply(payload)       -- publish `payload` on the current
 *                                message's reply subject.  Plain core
 *                                NATS publish (not JetStream); attaches
 *                                any staged headers.  Returns
 *                                -1 no current message,
 *                                -2 no reply-to on the current message,
 *                                -3 NATS connection unavailable,
 *                                -4 publish failed,
 *                                 1 on success.
 *
 *   nats_request(subj, payload, timeout_ms) -- core NATS RPC
 *                                request/reply.  Two call shapes:
 *                                  bare nats_request(...)            -- sync
 *                                  async(nats_request(...), rt)      -- async
 *                                The sync shape blocks the worker for
 *                                up to timeout_ms; the async shape
 *                                yields to the reactor on a per-call
 *                                worker-private timerfd while the
 *                                consumer process publishes the
 *                                request and awaits the reply on its
 *                                persistent inbox subscription.  On
 *                                success the reply populates the
 *                                per-worker current-message state so
 *                                the script can read $nats_data,
 *                                $nats_subject, $nats_hdr(...), etc.
 *                                Return codes (no path returns 0;
 *                                see action.c:196 -- a 0 return from
 *                                a script-callable cmd terminates
 *                                the surrounding route via
 *                                ACT_FL_EXIT, which is never what
 *                                we want for an RPC result):
 *                                   1  reply delivered.
 *                                  -1  timeout (broker still
 *                                      reachable; responder did
 *                                      not reply in time).  Script
 *                                      may retry with a longer
 *                                      timeout_ms.
 *                                  -2  connection lost mid-flight
 *                                      -- async only.  Pool epoch
 *                                      advanced or is_connected
 *                                      went false during the call.
 *                                      Distinct from -1: treat as
 *                                      broker-down rather than
 *                                      retry-with-longer-tmo.
 *                                  -3  NATS unavailable at issue
 *                                      time (no pool connection).
 *                                  -4  request error (subject
 *                                      empty / too long, msg
 *                                      create failed, publish or
 *                                      sync-request failed).
 *                                  -5  per-worker in-flight cap
 *                                      reached -- async only.
 *                                  -6  internal error (oom,
 *                                      timerfd create/arm failure,
 *                                      slot publish failure, etc.).
 */

#ifndef NATS_RPC_H
#define NATS_RPC_H

#include "../../str.h"
#include "../../parser/msg_parser.h"
#include "../../pvar.h"
#include "../../async.h"

/* Upper bound on staged-header entries per publish.  Sized generously
 * relative to real-world NATS use; each entry is a pair of `str`s
 * backed by a process-local pkg_malloc copy. */
#define NATS_MAX_STAGED_HDRS 16

/**
 * pvar glue: parse the $nats_hdr(Name) name argument and hand it to
 * the getter.  Both follow the standard pvar callback signatures.
 * Name match is case-insensitive (HTTP/NATS conventions).
 *
 * pv_parse_nats_hdr_name:
 * @param sp  pvar spec being built; the name str is stored BORROWED
 *            (no copy) -- fine for cfg-literal names, which live for
 *            the process lifetime.  Only static literals are
 *            supported; nested $pvar(...) is not expanded.
 * @param in  The literal name between the parentheses.
 * @return    0 on success, -1 on NULL / empty input.
 * Context: cfg parse time (main process, pre-fork).  No locking.
 *
 * pv_get_nats_hdr:
 * @param msg / param / res  standard pvar getter arguments.
 * @return  0 with *res set (NULL-flagged when there is no current
 *          message or the header is absent); -1 on NULL args.
 * The returned value BORROWS bytes inside the per-worker current
 * message slot -- valid until the next fetch / clear on this worker.
 * No allocation, no locking.  Context: SIP worker script context.
 */
int pv_parse_nats_hdr_name(pv_spec_p sp, const str *in);
int pv_get_nats_hdr(struct sip_msg *msg, pv_param_t *param,
                    pv_value_t *res);

/**
 * $nats_request_id pvar getter + setter.
 *
 * GET:
 * @param msg / param / res  standard pvar getter arguments.
 * @return  0 with *res set to the value used (or to-be-used) for the
 *          most recent nats_request issued by this worker, NULL-flagged
 *          when none; -1 on NULL args.  The bytes BORROW the per-worker
 *          static stash (valid until the next nats_request / write).
 *          Persists across an async() yield so it is readable from the
 *          resume route.
 *
 * SET:
 * @param msg / param / op  standard pvar setter arguments (unused).
 * @param val  Value to stash for the next nats_request call to consume
 *             instead of minting a fresh UUIDv7 (consume-once
 *             semantics); copied into the stash.  NULL clears it.
 * @return  0 on success, -1 for non-string values or values over 63
 *          bytes / containing CR/LF.
 *
 * No allocation, no locking (per-worker static stash).  Context: SIP
 * worker script context only.
 */
int pv_get_nats_request_id(struct sip_msg *msg, pv_param_t *param,
                           pv_value_t *res);
int pv_set_nats_request_id(struct sip_msg *msg, pv_param_t *param,
                           int op, pv_value_t *val);

/**
 * Stage a header onto the worker's outbound buffer iff no entry with
 * the same (case-insensitive) name is already staged.  Used by the
 * auto-stager for the per-call UUIDv7 so a deliberate
 * nats_hdr_set("X-Request-Id", ...) in the script wins.
 *
 * @param name   Header name; borrowed, deep-copied on stage.  NULL /
 *               empty returns -1.
 * @param value  Header value; borrowed, deep-copied.  NULL is staged
 *               as the empty string.
 * @return       1 on stage, 0 if an existing entry was preserved, -1
 *               on OOM or full table.
 *
 * Allocation: the copies are pkg_malloc'd into the per-worker staging
 * table, freed by nats_rpc_staged_clear() (which every publish path
 * runs).  No locking.  Context: SIP worker only, from the request
 * start paths.
 */
int nats_rpc_staged_set_if_absent(const str *name, const str *value);

/**
 * Script-callable header staging + reply + sync RPC.
 *
 * w_nats_hdr_set:
 * @param msg    Current SIP message; unused.
 * @param name   Header name; borrowed, deep-copied (pkg) on stage;
 *               replaces an existing same-name entry.
 * @param value  Header value; borrowed, deep-copied.  NULL = empty.
 * @return       1 on success, -1 on empty name / OOM / full table.
 * Context: SIP worker script context; no locking.
 *
 * w_nats_reply:
 * @param msg      Current SIP message; unused.
 * @param payload  Reply payload; borrowed (may be NULL = empty).
 * @return  1 published; -1 no current message; -2 no reply-to on the
 *          current message; -3 no NATS connection; -4 invalid
 *          reply-to subject / msg create / publish failure.
 * Publishes on the current message's reply subject via the shared pool
 * connection (plain core NATS publish, blocking library call);
 * attaches and then CLEARS the staged headers on every exit path.
 * Context: SIP worker script context; no module locking.
 *
 * w_nats_request (SYNC-ONLY -- see the file header for the full
 * return-code table):
 * @param msg         Current SIP message; unused.
 * @param subject     Publish subject; borrowed, validated (length,
 *                    control/whitespace/wildcard rejection).
 * @param payload     Request payload; borrowed (NULL = empty).
 * @param timeout_ms  Reply wait budget; NULL / <= 0 defaults to 1000.
 * @return  1 reply delivered (installed into the per-worker
 *          current-message state); -1 timeout; -3 NATS unavailable /
 *          disconnected; -4 request error (bad subject, msg create or
 *          request failure).
 * BLOCKS the calling process for up to timeout_ms in
 * natsConnection_RequestMsg; the cmd_export route mask therefore
 * restricts it to ONREPLY/LOCAL/STARTUP/TIMER/EVENT routes unless the
 * `allow_sync_anywhere` modparam widens it.  Staged headers are
 * consumed (and cleared) on every exit path.  No module locking.
 */
int w_nats_hdr_set (struct sip_msg *msg, str *name, str *value);
int w_nats_reply   (struct sip_msg *msg, str *payload);
int w_nats_request (struct sip_msg *msg, str *subject, str *payload,
                    int *timeout_ms);

/**
 * Script-callable async variant of nats_request.  Registered in the
 * module's acmd table under the same name `nats_request`, so the
 * sync vs. async dispatch is driven by call-site syntax:
 *   bare        nats_request(...)            -> w_nats_request    (sync)
 *   wrapped in  async(nats_request(...), rt) -> w_nats_request_async
 *
 * @param msg         Current SIP message; unused.
 * @param ctx         Async context; receives resume_f / resume_param.
 * @param subject     Publish subject; borrowed, validated, copied into
 *                    the SHM slot.
 * @param payload     Request payload; borrowed, copied into the slot.
 * @param timeout_ms  Reply budget; NULL / <= 0 defaults to 1000.
 * @return  1 after a successful hand-off to the reactor (the resume
 *          later reports 1 / -1 timeout / -2 connection lost to the
 *          script route); start-path failures return -2 (pool
 *          disconnected), -4 (bad subject / oversize payload), -5
 *          (slot pool full or IPC send refused) or -6 (slot publish,
 *          timerfd or pkg-OOM failure) without yielding.
 *
 * Allocation: claims a pool-owned SHM slot (returned via the resume's
 * nats_rpc_slot_free, or by the orphan reaper if this worker dies) and
 * pkg_malloc's a per-call wrapper freed by the resume; the guard
 * timerfd is worker-private and closed by the async core.  The staged
 * header table is serialized into the slot and cleared on every exit
 * path.  Locking: none (slot hand-off is atomic-state based).
 *
 * Context: SIP worker with a reactor; the publish + reply-inbox
 * subscription runs in the consumer process (the only libnats-safe
 * context).  Both entry points share the same script surface.
 */
int w_nats_request_async(struct sip_msg *msg, async_ctx *ctx,
                         str *subject, str *payload, int *timeout_ms);

/**
 * Clear the staged-header table and free the backing buffers.
 * Invoked internally by the publish paths; exposed so that a future
 * caller (e.g. a child_init reset / module destroy) can drop staging
 * state without publishing.
 *
 * @return  nothing; idempotent.
 *
 * pkg_free's every staged name/value copy owned by this worker's
 * staging table.  No locking (per-worker static).  Context: SIP worker
 * only -- the same process that staged the headers.
 */
void nats_rpc_staged_clear(void);

/**
 * Serialize the per-worker staged-header table into the compact
 * length-prefixed wire format used by ring/slot header buffers
 * (see nats_ring.h `headers[]`).  Wire layout:
 *
 *   [ count          : 2 bytes little-endian ]
 *   foreach pair (count times):
 *     [ name_len     : 2 bytes little-endian ]
 *     [ name bytes ]
 *     [ value_len    : 2 bytes little-endian ]
 *     [ value bytes ]
 *
 * @param out        Caller-owned destination buffer; nothing else is
 *                   allocated or stored.
 * @param cap        Size of @out; must be at least 2.
 * @param truncated  Optional out (may be NULL): set to 1 iff at least
 *                   one pair was dropped for lack of room -- the
 *                   emitted prefix is still valid.
 * @param count_out  Optional out (may be NULL): pairs actually emitted.
 * @return           The byte length written; an empty stage produces a
 *                   2-byte zero count and returns 2; 0 if @out is NULL
 *                   or @cap < 2.
 *
 * Does NOT clear the staging table -- pair with
 * nats_rpc_staged_clear() after the slot is published.  No locking
 * (per-worker static table).  Context: SIP worker only, from the async
 * nats_request start path.
 */
int nats_rpc_staged_serialize(char *out, int cap,
                              int *truncated, int *count_out);

/* Borrowed view of one reply's buffers -- the inputs of
 * nats_rpc_cur_set_from_buffers, which copies them into the worker's
 * current-message slot (spans only borrowed for the call).  Zeroed
 * members mean "absent". */
typedef struct nats_rpc_reply_view {
	uint32_t    handle_idx;
	const char *subject;   uint32_t subject_len;
	const char *data;      uint32_t data_len;
	const char *reply_to;  uint32_t reply_to_len;
	uint8_t     has_reply;
	const char *headers;   uint16_t headers_len;
	uint8_t     headers_truncated;
} nats_rpc_reply_view_t;

/**
 * Populate the worker's current message from stored reply buffers
 * (the natsMsg was destroyed back in the libnats callback).
 *
 * @param rv  Borrowed view of the reply's buffers (spans only need to
 *            live for the call -- every field is copied, clamped to
 *            the NATS_RING_*_MAX caps, into the per-worker static
 *            current-message slot).  ack_token is cleared: a core NATS
 *            reply is not JetStream-ackable.
 * @return    nothing.
 *
 * No allocation, no locking (per-worker static).  Context: SIP worker
 * only -- the async nats_request resume path, reading the reply out of
 * the SHM slot after observing DELIVERED.
 */
void nats_rpc_cur_set_from_buffers(const nats_rpc_reply_view_t *rv);

/**
 * Inverse of nats_rpc_staged_serialize / the reply serializer: parse a
 * wire-format header stream and apply each (name, value) pair to the
 * supplied libnats natsMsg via natsMsgHeader_Set.
 *
 * @param buf       Serialized header stream (see the wire layout on
 *                  nats_rpc_staged_serialize); borrowed, read-only.
 * @param len       Length of @buf in bytes.
 * @param msg_void  A `natsMsg *` cast through void* (avoids pulling
 *                  <nats/nats.h> into every includer); the libnats msg
 *                  copies each header internally, so @buf may be
 *                  released right after.  Caller keeps ownership of
 *                  the msg.
 * @return          The number of headers applied; 0 on NULL/empty
 *                  buffer, count=0 stream or NULL msg; -1 on malformed
 *                  input (a length prefix runs past the buffer end --
 *                  the caller may still publish, with whatever headers
 *                  were applied before the truncation point).
 *
 * Allocation: none beyond libnats' internal header copies (bounded
 * stack buffers are used per pair; oversize names/values are skipped).
 * No locking.  Context: consumer process only, on the IPC publish path
 * (publish_slot), which is the libnats-safe context for building the
 * outbound natsMsg.
 */
int nats_rpc_hdr_deserialize_to_msg(const char *buf, int len, void *msg_void);

#endif /* NATS_RPC_H */
