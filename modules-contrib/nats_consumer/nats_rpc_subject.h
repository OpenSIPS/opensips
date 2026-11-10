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
 * nats_rpc_subject.h -- reply-inbox subject grammar for the
 * consumer-process-routed async nats_request transport.
 *
 *     "<prefix>.<slot_idx>.<generation>.<corr_id>"
 *
 * The trailing <slot_idx>.<generation>.<corr_id> triple is how the
 * consumer's libnats reply callback correlates a reply to its SHM slot
 * without a hash table, AND authenticates it:
 *
 *   - <slot_idx>   locates the slot in O(1).
 *   - <generation> guards against a late reply landing on a slot that has
 *     since been freed and re-claimed by a *different* request (a
 *     cross-call data leak).  slot_idx and generation are both small and
 *     guessable, so on their own they do not authenticate the sender.
 *   - <corr_id> is the per-call UUIDv7 (74 bits of entropy).  Because the
 *     reply subject lives under a shared "<prefix>.>" wildcard that any
 *     broker peer can publish to, a peer who guesses slot_idx and
 *     generation could otherwise inject a forged reply.  on_inbox_reply
 *     requires the <corr_id> token to match the slot's stored corr_id, so
 *     a forged reply that does not know the UUID is rejected.  The
 *     corr_id is a single NATS token (hex + hyphens, no dots).
 *
 * Both functions are pure (no libnats / OpenSIPS dependencies) so they
 * can be unit-tested standalone -- see test/test_rpc_subject.c.
 */

#ifndef NATS_RPC_SUBJECT_H
#define NATS_RPC_SUBJECT_H

#include <stdint.h>
#include <stddef.h>

/**
 * Build "<prefix>.<slot>.<gen>.<corr_id>" into out[0..out_sz).
 *
 * @param out          Destination buffer, caller-owned; NUL-terminated on
 *                     success.  Nothing else is allocated or stored.
 * @param out_sz       Size of @out in bytes; must be > 0.
 * @param prefix       Reply-inbox prefix (may itself contain dots).
 * @param slot         Slot index segment.
 * @param gen          Claim-generation segment.
 * @param corr_id      Per-call correlation id; MANDATORY (the spoofing
 *                     guard depends on it) and must be a single clean
 *                     NATS token: non-empty and free of '.', whitespace,
 *                     wildcards ('*'/'>') and control bytes.
 * @param corr_id_len  Length of @corr_id in bytes; must be > 0.
 * @return             Written length (excluding the NUL) on success, or
 *                     -1 on overflow / bad arguments / invalid corr_id.
 *
 * Pure function on caller-provided memory: no allocation beyond @out, no
 * locking, no libnats / OpenSIPS dependencies.  Safe in any process or
 * thread; the production caller is the consumer process's publish path.
 */
int nats_rpc_subject_build(char *out, size_t out_sz,
                           const char *prefix, uint32_t slot, uint32_t gen,
                           const char *corr_id, int corr_id_len);

/**
 * Parse the trailing ".<slot>.<gen>.<corr_id>" off a reply subject.  The
 * prefix itself contains dots and is NOT validated -- only the final
 * three dot-separated segments are read.
 *
 * @param subject   Reply subject bytes (need not be NUL-terminated).
 * @param len       Length of @subject in bytes; must be > 0.
 * @param slot      Out: parsed slot index (clamped to INT32_MAX domain).
 * @param gen       Out: parsed generation (full uint32 domain).
 * @param corr_out  Out: corr_id copied NUL-terminated, caller-owned
 *                  buffer; nothing is allocated.
 * @param corr_sz   Size of @corr_out; must be > 0 and larger than the
 *                  corr_id.
 * @return          0 with *slot, *gen and corr_out populated on success;
 *                  -1 on malformed input (missing segments, non-digit
 *                  slot/gen, overflow, or a corr_id that does not fit
 *                  corr_sz) -- outputs are unmodified in that case.
 *
 * Pure function on caller-provided memory: no allocation, no locking.
 * Safe in any process or thread; the production caller is the consumer
 * process's libnats reply callback (cnats callback thread).
 */
int nats_rpc_subject_parse(const char *subject, int len,
                           uint32_t *slot, uint32_t *gen,
                           char *corr_out, size_t corr_sz);

#endif /* NATS_RPC_SUBJECT_H */
