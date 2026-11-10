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
 * Regression test for the consumer-process-routed async nats_request
 * reply-correlation generation guard.
 *
 * Bug: replies were correlated to their SHM slot by slot_idx ALONE
 * (reply subject "<prefix>.<slot_idx>").  A responder slower than the
 * request timeout could have its reply land after the worker timed out,
 * freed the slot, and another request re-claimed the SAME slot_idx --
 * delivering one call's reply payload to a different call (a cross-call
 * data leak).  The pre-fix INFLIGHT-state CAS did not catch this because
 * the re-claimed slot is also INFLIGHT.
 *
 * Fix: each claim bumps a per-slot generation; the reply subject is now
 * "<prefix>.<slot_idx>.<generation>", and on_inbox_reply drops a reply
 * whose generation no longer matches the slot's current claim.
 *
 * This test exercises the two pure pieces of that fix together:
 *   - nats_rpc_subject_build / _parse   (reply-subject grammar)
 *   - nats_rpc_slot generation bump on every claim
 * and asserts the exact guard on_inbox_reply applies.
 *
 * Runs in the nats_consumer unit test suite on the module's live slot
 * pool, which the suite's cfg sizes to one slot.
 */

#include <tap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdatomic.h>

#include "../nats_rpc_subject.h"
#include "../nats_rpc_slot.h"

#include "nc_ut.h"

#define ASSERT(cond, msg) ok((cond), "rpc_subject: %s", (msg))

static void test_subject_grammar(void)
{
	char     buf[128];
	char     corr[40];
	uint32_t slot, gen;
	int      n;
	const char *uuid = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";

	/* round-trip including the corr_id token */
	n = nats_rpc_subject_build(buf, sizeof(buf),
		"_INBOX.opensips.12345", 5, 7, uuid, (int)strlen(uuid));
	ASSERT(n > 0, "build returns length");
	ASSERT(strcmp(buf, "_INBOX.opensips.12345.5.7."
		"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b") == 0,
		"build emits <prefix>.<slot>.<gen>.<corr_id>");
	ASSERT(nats_rpc_subject_parse(buf, (int)strlen(buf), &slot, &gen,
		corr, sizeof(corr)) == 0,
		"parse accepts a well-formed subject");
	ASSERT(slot == 5 && gen == 7, "parse recovers slot and gen");
	ASSERT(strcmp(corr, uuid) == 0, "parse recovers the corr_id token");

	/* large values */
	n = nats_rpc_subject_build(buf, sizeof(buf), "p", 2147483647u,
		4294967295u, uuid, (int)strlen(uuid));
	ASSERT(n > 0 &&
		nats_rpc_subject_parse(buf, (int)strlen(buf), &slot, &gen,
			corr, sizeof(corr)) == 0 &&
		slot == 2147483647u && gen == 4294967295u &&
		strcmp(corr, uuid) == 0,
		"parse handles INT32_MAX slot and UINT32_MAX gen with corr_id");

	/* malformed inputs are rejected */
	ASSERT(nats_rpc_subject_parse("noslots", 7, &slot, &gen,
		corr, sizeof(corr)) < 0,
		"parse rejects subject with no dots");
	ASSERT(nats_rpc_subject_parse("_INBOX.5", 8, &slot, &gen,
		corr, sizeof(corr)) < 0,
		"parse rejects subject with only one dot");
	/* now-3-segment subjects (old grammar) lack the corr_id token */
	ASSERT(nats_rpc_subject_parse("p.5.7", 5, &slot, &gen,
		corr, sizeof(corr)) < 0,
		"parse rejects old 3-segment subject (no corr_id)");
	ASSERT(nats_rpc_subject_parse("p.b.7.uuid", 10, &slot, &gen,
		corr, sizeof(corr)) < 0,
		"parse rejects non-numeric slot");
	ASSERT(nats_rpc_subject_parse("p.5.x.uuid", 10, &slot, &gen,
		corr, sizeof(corr)) < 0,
		"parse rejects non-numeric gen");
	ASSERT(nats_rpc_subject_parse("p.5.7.", 6, &slot, &gen,
		corr, sizeof(corr)) < 0,
		"parse rejects empty corr_id segment");
	ASSERT(nats_rpc_subject_parse("p.5..uuid", 9, &slot, &gen,
		corr, sizeof(corr)) < 0,
		"parse rejects empty gen segment");
	ASSERT(nats_rpc_subject_parse("p..7.uuid", 9, &slot, &gen,
		corr, sizeof(corr)) < 0,
		"parse rejects empty slot segment");

	/* corr_id that does not fit the output buffer is rejected */
	ASSERT(nats_rpc_subject_parse("p.5.7.toolongcorr", 17, &slot, &gen,
		corr, 4) < 0,
		"parse rejects corr_id that overflows corr_out");

	/* build validation of the corr_id token */
	ASSERT(nats_rpc_subject_build(buf, sizeof(buf), "p", 1, 1, NULL, 0) < 0,
		"build rejects missing corr_id");
	ASSERT(nats_rpc_subject_build(buf, sizeof(buf), "p", 1, 1, "", 0) < 0,
		"build rejects empty corr_id");
	ASSERT(nats_rpc_subject_build(buf, sizeof(buf), "p", 1, 1,
		"has.dot", 7) < 0,
		"build rejects corr_id containing a dot");
	ASSERT(nats_rpc_subject_build(buf, sizeof(buf), "p", 1, 1,
		"has space", 9) < 0,
		"build rejects corr_id containing whitespace");
	ASSERT(nats_rpc_subject_build(buf, sizeof(buf), "p", 1, 1,
		"wild>card", 9) < 0,
		"build rejects corr_id containing a wildcard");

	/* build overflow */
	ASSERT(nats_rpc_subject_build(buf, 4, "longprefix", 1, 1,
		uuid, (int)strlen(uuid)) < 0,
		"build rejects buffer overflow");
}

/* Re-claim a specific slot index by cycling the round-robin allocator,
 * freeing every non-matching claim along the way.  Returns the slot or
 * NULL if not reached within a few full cycles. */
static nats_rpc_slot_t *reclaim_idx(uint32_t want)
{
	int k;
	for (k = 0; k < (int)nats_rpc_slot_total_count() * 3 + 4; k++) {
		nats_rpc_slot_t *c = nats_rpc_slot_claim();
		if (!c) return NULL;
		if (c->slot_idx == want) return c;
		nats_rpc_slot_free(c,
		atomic_load_explicit(&(c)->generation, memory_order_relaxed));
	}
	return NULL;
}

static void test_generation_guard(void)
{
	const char *prefix = "_INBOX.opensips.12345";
	const char *uuid   = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
	char subj_old[128], subj_new[128];
	char corr[40];
	uint32_t idx, gen_old, gen_new, pslot, pgen;
	nats_rpc_slot_t *a, *b;

	/* the live slot pool: one slot (async_rpc_slots=0 in the cfg) */
	/* claim A -- this is request #1 */
	a = nats_rpc_slot_claim();
	ASSERT(a != NULL, "claim A succeeds");
	idx     = a->slot_idx;
	gen_old = atomic_load_explicit(&a->generation, memory_order_relaxed);
	ASSERT(gen_old >= 1, "generation is set (>=1) on first claim");

	/* the consumer would publish request #1 with this reply subject */
	ASSERT(nats_rpc_subject_build(subj_old, sizeof(subj_old),
		prefix, idx, gen_old, uuid, (int)strlen(uuid)) > 0,
		"build reply subject for claim A");

	/* request #1 times out -> worker frees the slot */
	nats_rpc_slot_free(a,
		atomic_load_explicit(&(a)->generation, memory_order_relaxed));

	/* request #2 re-claims the SAME slot index */
	b = reclaim_idx(idx);
	ASSERT(b != NULL, "re-claimed the same slot index for request #2");
	gen_new = atomic_load_explicit(&b->generation, memory_order_relaxed);
	ASSERT(gen_new != gen_old,
		"re-claim of the same slot has a different generation");

	/* === the guard on_inbox_reply applies === */

	/* (1) the LATE reply for request #1 arrives carrying subj_old */
	ASSERT(nats_rpc_subject_parse(subj_old, (int)strlen(subj_old),
		&pslot, &pgen, corr, sizeof(corr)) == 0,
		"parse late reply subject");
	ASSERT(pslot == idx, "late reply maps to the same slot index");
	ASSERT(pgen == gen_old, "late reply carries request #1's generation");
	ASSERT(atomic_load_explicit(&b->generation, memory_order_relaxed) != pgen,
		"STALE reply rejected: slot generation != reply generation");

	/* (2) the genuine reply for request #2 carries the current gen */
	ASSERT(nats_rpc_subject_build(subj_new, sizeof(subj_new),
		prefix, idx, gen_new, uuid, (int)strlen(uuid)) > 0,
		"build reply subject for claim B");
	ASSERT(nats_rpc_subject_parse(subj_new, (int)strlen(subj_new),
		&pslot, &pgen, corr, sizeof(corr)) == 0,
		"parse genuine reply subject");
	ASSERT(atomic_load_explicit(&b->generation, memory_order_relaxed) == pgen,
		"FRESH reply accepted: slot generation == reply generation");

	nats_rpc_slot_free(b,
		atomic_load_explicit(&(b)->generation, memory_order_relaxed));
}

void nc_ut_rpc_subject(void)
{
	test_subject_grammar();
	test_generation_guard();

}
