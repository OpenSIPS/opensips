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
 * Regression test: the fetch path copied the entire nats_ring_slot_t
 * (~17.9 KB of fixed max-size buffers) by struct assignment 2-3x per
 * message (cur_set_from_slot, batch_push_slot) -- ~36-54 KB memcpy'd for a
 * 100-byte payload.  Fix: nats_ring_slot_copy_used() copies only the used
 * prefix (header fields + the actual subject/data/reply_to/headers bytes),
 * and clamps each variable length to its MAX before the memcpy so a
 * corrupted SHM length cannot overflow the destination (folds in the
 * pop-side clamp hardening).
 *
 * Runs in the nats_consumer unit test suite (make test-nats_consumer).
 */

#include <tap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../nats_ring.h"

#include "nc_ut.h"

#define ASSERT(cond, msg) ok((cond), "slot_prefix_copy: %s", (msg))

void nc_ut_slot_prefix_copy(void)
{
	nats_ring_slot_t *src = calloc(1, sizeof(*src));
	nats_ring_slot_t *dst = calloc(1, sizeof(*dst));

	/* Populate a representative slot. */
	src->ready_gen = 7; src->consumed_gen = 3;
	src->stream_seq = 1000; src->consumer_seq = 5; src->delivered = 2;
	src->pending = 9; src->timestamp_ns = 123456789; src->ack_token = 42;
	src->has_reply = 1;

	strcpy(src->subject, "sub.test"); src->subject_len = 8;
	memcpy(src->data, "hello-world", 11); src->data_len = 11;
	strcpy(src->reply_to, "_INBOX.x"); src->reply_to_len = 8;
	memcpy(src->headers, "h", 1); src->headers_len = 1;
	src->headers_truncated = 0;

	nats_ring_slot_copy_used(dst, src);

	ASSERT(dst->ready_gen == 7 && dst->consumed_gen == 3,
		"generation fields copied");
	ASSERT(dst->stream_seq == 1000 && dst->consumer_seq == 5 &&
	       dst->delivered == 2 && dst->pending == 9 &&
	       dst->timestamp_ns == 123456789 && dst->ack_token == 42,
		"all sequence/metadata fields copied");
	ASSERT(dst->subject_len == 8 && memcmp(dst->subject, "sub.test", 8) == 0,
		"subject prefix copied");
	ASSERT(dst->data_len == 11 && memcmp(dst->data, "hello-world", 11) == 0,
		"data prefix copied");
	ASSERT(dst->has_reply == 1 && dst->reply_to_len == 8 &&
	       memcmp(dst->reply_to, "_INBOX.x", 8) == 0,
		"reply_to prefix copied");
	ASSERT(dst->headers_len == 1 && dst->headers[0] == 'h',
		"headers prefix copied");

	/* Corrupted (oversized) lengths must be clamped, not honored. */
	{
		nats_ring_slot_t *bad = calloc(1, sizeof(*bad));
		nats_ring_slot_t *out = calloc(1, sizeof(*out));
		bad->data_len     = (uint32_t)NATS_RING_PAYLOAD_MAX + 5000;
		bad->subject_len  = (uint32_t)NATS_RING_SUBJECT_MAX + 100;
		bad->reply_to_len = (uint32_t)NATS_RING_SUBJECT_MAX + 100;
		bad->headers_len  = (uint16_t)NATS_RING_HEADERS_MAX;  /* already max */
		nats_ring_slot_copy_used(out, bad);
		ASSERT(out->data_len == (uint32_t)NATS_RING_PAYLOAD_MAX,
			"oversized data_len clamped to MAX");
		ASSERT(out->subject_len == (uint32_t)NATS_RING_SUBJECT_MAX,
			"oversized subject_len clamped to MAX");
		ASSERT(out->reply_to_len == (uint32_t)NATS_RING_SUBJECT_MAX,
			"oversized reply_to_len clamped to MAX");
		free(bad); free(out);
	}

	free(src); free(dst);
}
