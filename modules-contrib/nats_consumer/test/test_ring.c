/*
 * Copyright (C) 2026 OpenSIPS Solutions
 * Copyright (C) 2026 Norm Brandinger <n.brandinger@gmail.com>
 *
 * This file is part of opensips, a free SIP server.
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
 * test_ring.c -- unit tests for nats_ring.
 *
 * Cases covered:
 *   1. Single-thread round-trip on a capacity-2 ring.
 *   2. Full / pop-one / push-more on capacity 4.
 *   3. Single-producer / single-consumer, 100 000 messages, in-order.
 *   4. 2 producers + 2 consumers, 1 000 000 messages, no drops/dupes.
 *   5. Eventfd wake semantics (empty->non-empty edge + drain).
 *   6. Payload / subject size limits.
 *   7. Destroy while non-empty (must not deadlock or crash).
 *
 * Runs in the nats_consumer unit test suite on real SHM rings, with the
 * two concurrency cases scaled down to keep the per-commit suite light.
 * Threads inside a single process simulate cross-process producers and
 * consumers because the ring only relies on atomics -- no per-process
 * state.
 */

#include <tap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <unistd.h>
#include <stdatomic.h>
#include <time.h>
#include <errno.h>

#include "../nats_ring.h"

#include "nc_ut.h"


#define CHECK(cond) ok((cond), "ring:%d %s", __LINE__, #cond)

/* messages the single-producer consumer thread saw out of order (libtap
 * is not thread-safe: threads count, the main thread asserts) */
static int sp_sc_out_of_order;

/* ── case 1: single-thread round-trip ─────────────────────────── */

static void test_roundtrip_cap2(void)
{
	nats_ring_t *r = nats_ring_create(2);
	nats_ring_slot_t out;
	int rc;

	CHECK(r != NULL);
	CHECK(nats_ring_capacity(r) == 2);
	CHECK(nats_ring_depth(r) == 0);
	/* The ring no longer owns a process-local eventfd (it was a
	 * cross-process fd-corruption hazard); the stub returns -1. */
	CHECK(nats_ring_eventfd(r) < 0);

	rc = nats_ring_push(r, &(nats_ring_msg_t){
			.subject = "orders.new",
			.subject_len = 10,
			.data = "hello",
			.data_len = 5,
			.stream_seq = 1001,
			.consumer_seq = 2001,
			.delivered = 3,
			.pending = 7,
			.timestamp_ns = 42424242,
			.ack_token = 0xdeadbeefULL,
			.reply_to = "reply.queue",
			.reply_to_len = 11,
		});
	CHECK(rc == 0);
	CHECK(nats_ring_depth(r) == 1);

	rc = nats_ring_pop(r, &out);
	CHECK(rc == 0);
	CHECK(out.subject_len == 10);
	CHECK(memcmp(out.subject, "orders.new", 10) == 0);
	CHECK(out.data_len == 5);
	CHECK(memcmp(out.data, "hello", 5) == 0);
	CHECK(out.stream_seq == 1001);
	CHECK(out.consumer_seq == 2001);
	CHECK(out.delivered == 3);
	CHECK(out.pending == 7);
	CHECK(out.timestamp_ns == 42424242);
	CHECK(out.ack_token == 0xdeadbeefULL);
	CHECK(out.has_reply == 1);
	CHECK(out.reply_to_len == 11);
	CHECK(memcmp(out.reply_to, "reply.queue", 11) == 0);

	CHECK(nats_ring_depth(r) == 0);
	CHECK(nats_ring_pop(r, &out) == -1);

	nats_ring_destroy(r);
}

/* ── case 2: full / pop-one / push-more ───────────────────────── */

static void test_full_capacity(void)
{
	nats_ring_t *r = nats_ring_create(4);
	nats_ring_slot_t out;
	int i, rc;

	CHECK(r != NULL);

	for (i = 0; i < 4; i++) {
		rc = nats_ring_push(r, &(nats_ring_msg_t){
				.subject = "s",
				.subject_len = 1,
				.data = "x",
				.data_len = 1,
				.stream_seq = 0,
				.consumer_seq = 0,
				.delivered = 0,
				.pending = 0,
				.timestamp_ns = 0,
				.ack_token = (uint64_t)i,
			});
		CHECK(rc == 0);
	}
	CHECK(nats_ring_depth(r) == 4);

	/* 5th should fail with -1 (full). */
	rc = nats_ring_push(r, &(nats_ring_msg_t){
			.subject = "s",
			.subject_len = 1,
			.data = "x",
			.data_len = 1,
			.stream_seq = 0,
			.consumer_seq = 0,
			.delivered = 0,
			.pending = 0,
			.timestamp_ns = 0,
			.ack_token = 99,
		});
	CHECK(rc == -1);

	/* Pop one, push one, depth stays at 4. */
	rc = nats_ring_pop(r, &out);
	CHECK(rc == 0);
	CHECK(out.ack_token == 0);
	CHECK(nats_ring_depth(r) == 3);

	rc = nats_ring_push(r, &(nats_ring_msg_t){
			.subject = "s",
			.subject_len = 1,
			.data = "x",
			.data_len = 1,
			.stream_seq = 0,
			.consumer_seq = 0,
			.delivered = 0,
			.pending = 0,
			.timestamp_ns = 0,
			.ack_token = 100,
		});
	CHECK(rc == 0);
	CHECK(nats_ring_depth(r) == 4);

	/* Drain and verify order is preserved (1, 2, 3, 100). */
	for (i = 0; i < 4; i++) {
		rc = nats_ring_pop(r, &out);
		CHECK(rc == 0);
		if (i < 3)
			CHECK(out.ack_token == (uint64_t)(i + 1));
		else
			CHECK(out.ack_token == 100);
	}
	CHECK(nats_ring_depth(r) == 0);

	nats_ring_destroy(r);
}

/* ── case 3: 1P/1C, 100 000 messages, in-order ────────────────── */

struct sp_sc_ctx {
	nats_ring_t *r;
	uint64_t     n;
};

static void *sp_sc_producer(void *u)
{
	struct sp_sc_ctx *c = (struct sp_sc_ctx *)u;
	uint64_t i;
	for (i = 0; i < c->n; i++) {
		for (;;) {
			int rc = nats_ring_push(c->r, &(nats_ring_msg_t){
					.subject = "s",
					.subject_len = 1,
					.data = "x",
					.data_len = 1,
					.stream_seq = 0,
					.consumer_seq = 0,
					.delivered = 0,
					.pending = 0,
					.timestamp_ns = 0,
					.ack_token = i,
				});
			if (rc == 0)
				break;
			/* ring full, let consumer catch up */
			sched_yield();
		}
	}
	return NULL;
}

static void *sp_sc_consumer(void *u)
{
	struct sp_sc_ctx *c = (struct sp_sc_ctx *)u;
	nats_ring_slot_t slot;
	uint64_t expected = 0;
	uint64_t drained  = 0;
	while (drained < c->n) {
		int rc = nats_ring_pop(c->r, &slot);
		if (rc == -1) { sched_yield(); continue; }
		if (slot.ack_token != expected) {
			fprintf(stderr,
				"FAIL: sp_sc out of order: got %llu want %llu\n",
				(unsigned long long)slot.ack_token,
				(unsigned long long)expected);
			__atomic_add_fetch(&sp_sc_out_of_order, 1, __ATOMIC_SEQ_CST);
		}
		expected++;
		drained++;
	}
	return NULL;
}

static void test_sp_sc_100k(void)
{
	pthread_t pt, ct;
	struct sp_sc_ctx ctx;

	ctx.r = nats_ring_create(1024);
	ctx.n = 20000ULL;   /* 100 000 in the standalone test; kept light here */
	CHECK(ctx.r != NULL);

	pthread_create(&pt, NULL, sp_sc_producer, &ctx);
	pthread_create(&ct, NULL, sp_sc_consumer, &ctx);
	pthread_join(pt, NULL);
	pthread_join(ct, NULL);

	CHECK(sp_sc_out_of_order == 0);
	CHECK(nats_ring_depth(ctx.r) == 0);

	nats_ring_destroy(ctx.r);
}

/* ── case 4: 2P / 2C stress, 1M messages, no drops / dupes ────── */

#define STRESS_PRODUCERS   2
#define STRESS_CONSUMERS   2
#define STRESS_PER_PROD    50000ULL    /* total 100 000 (1 000 000 standalone) */
#define STRESS_TOTAL       (STRESS_PRODUCERS * STRESS_PER_PROD)

/*
 * Each ack_token encodes the producer id in the top 16 bits and a
 * per-producer monotonic counter in the bottom 48 bits.  After the
 * test we verify that every (pid, seq) pair was seen exactly once.
 */
#define TOKEN_MAKE(pid, seq)   (((uint64_t)(pid) << 48) | (uint64_t)(seq))
#define TOKEN_PID(t)           ((uint32_t)((t) >> 48))
#define TOKEN_SEQ(t)           ((t) & 0xffffffffffffULL)

struct stress_ctx {
	nats_ring_t *r;
	uint32_t     pid;              /* producer id (for producers only) */
	_Atomic uint64_t *consumed;    /* global consumed counter */
	uint8_t     *seen;             /* bitmap: STRESS_PRODUCERS * STRESS_PER_PROD bits */
	uint64_t     target;           /* total messages */
};

static void *stress_producer(void *u)
{
	struct stress_ctx *c = (struct stress_ctx *)u;
	uint64_t i;
	for (i = 0; i < STRESS_PER_PROD; i++) {
		uint64_t tok = TOKEN_MAKE(c->pid, i);
		for (;;) {
			int rc = nats_ring_push(c->r, &(nats_ring_msg_t){
					.subject = "s",
					.subject_len = 1,
					.data = "x",
					.data_len = 1,
					.stream_seq = 0,
					.consumer_seq = 0,
					.delivered = 0,
					.pending = 0,
					.timestamp_ns = 0,
					.ack_token = tok,
				});
			if (rc == 0)
				break;
			sched_yield();
		}
	}
	return NULL;
}

static _Atomic uint32_t dup_count;
static _Atomic uint32_t oob_count;

static void *stress_consumer(void *u)
{
	struct stress_ctx *c = (struct stress_ctx *)u;
	nats_ring_slot_t slot;
	for (;;) {
		uint64_t done = atomic_load_explicit(c->consumed,
			memory_order_relaxed);
		if (done >= c->target)
			break;
		int rc = nats_ring_pop(c->r, &slot);
		if (rc == -1) { sched_yield(); continue; }

		uint64_t tok = slot.ack_token;
		uint32_t pid = TOKEN_PID(tok);
		uint64_t seq = TOKEN_SEQ(tok);

		if (pid >= STRESS_PRODUCERS || seq >= STRESS_PER_PROD) {
			atomic_fetch_add_explicit(&oob_count, 1,
				memory_order_relaxed);
			continue;
		}

		uint64_t idx  = (uint64_t)pid * STRESS_PER_PROD + seq;
		uint64_t byte = idx >> 3;
		uint8_t  bit  = (uint8_t)(1u << (idx & 7));
		/*
		 * Set the bit atomically and check the old value; if it was
		 * already set we just observed a duplicate.
		 */
		uint8_t prev = __atomic_fetch_or(&c->seen[byte], bit,
			__ATOMIC_RELAXED);
		if (prev & bit) {
			atomic_fetch_add_explicit(&dup_count, 1,
				memory_order_relaxed);
		} else {
			atomic_fetch_add_explicit(c->consumed, 1,
				memory_order_relaxed);
		}
	}
	return NULL;
}

static double now_sec(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void test_mp_mc_stress(void)
{
	pthread_t prods[STRESS_PRODUCERS];
	pthread_t cons [STRESS_CONSUMERS];
	struct stress_ctx pctx[STRESS_PRODUCERS];
	struct stress_ctx cctx[STRESS_CONSUMERS];
	_Atomic uint64_t consumed = 0;
	size_t bitmap_bytes = (STRESS_TOTAL + 7) / 8;
	uint8_t *seen = (uint8_t *)calloc(1, bitmap_bytes);
	nats_ring_t *r;
	uint64_t i;
	double t0, t1;

	CHECK(seen != NULL);

	r = nats_ring_create(1024);
	CHECK(r != NULL);

	atomic_init(&dup_count, 0);
	atomic_init(&oob_count, 0);

	t0 = now_sec();

	for (i = 0; i < STRESS_PRODUCERS; i++) {
		pctx[i].r = r;
		pctx[i].pid = (uint32_t)i;
		pctx[i].consumed = &consumed;
		pctx[i].seen = seen;
		pctx[i].target = STRESS_TOTAL;
		pthread_create(&prods[i], NULL, stress_producer, &pctx[i]);
	}
	for (i = 0; i < STRESS_CONSUMERS; i++) {
		cctx[i].r = r;
		cctx[i].pid = 0;
		cctx[i].consumed = &consumed;
		cctx[i].seen = seen;
		cctx[i].target = STRESS_TOTAL;
		pthread_create(&cons[i], NULL, stress_consumer, &cctx[i]);
	}

	for (i = 0; i < STRESS_PRODUCERS; i++)
		pthread_join(prods[i], NULL);
	for (i = 0; i < STRESS_CONSUMERS; i++)
		pthread_join(cons[i], NULL);

	t1 = now_sec();

	CHECK(atomic_load(&consumed) == STRESS_TOTAL);
	CHECK(atomic_load(&dup_count) == 0);
	CHECK(atomic_load(&oob_count) == 0);

	/* Every token must be present. */
	uint64_t missing = 0;
	for (uint64_t idx = 0; idx < STRESS_TOTAL; idx++) {
		if (!(seen[idx >> 3] & (1u << (idx & 7))))
			missing++;
	}
	CHECK(missing == 0);

	fprintf(stderr,
		"stress: %llu msgs, %.2fs, %.2f Mmsg/s, dups=%u oob=%u miss=%llu\n",
		(unsigned long long)STRESS_TOTAL,
		t1 - t0,
		(double)STRESS_TOTAL / (t1 - t0) / 1e6,
		atomic_load(&dup_count),
		atomic_load(&oob_count),
		(unsigned long long)missing);

	nats_ring_destroy(r);
	free(seen);
}

/* ── case 5: futex wait/wake semantics (no eventfd) ───────────────
 *
 * The ring's wakeup is futex-only.  nats_ring_wait() returns 0 when the
 * ring is non-empty (no wait needed) and times out (-1) when it is
 * empty.  The cross-thread wake itself is exercised in the dedicated
 * test_ring_xproc_wakeup.c; here we pin the single-threaded contract and
 * confirm no process-local fd is exposed. */

static void test_wait_semantics(void)
{
	nats_ring_t *r = nats_ring_create(8);
	nats_ring_slot_t out;

	CHECK(r != NULL);
	/* No fd to leak/corrupt across processes. */
	CHECK(nats_ring_eventfd(r) < 0);

	/* Empty ring: a short wait must time out (return -1). */
	CHECK(nats_ring_wait(r, 50) == -1);

	/* Push one -- ring is now non-empty, so wait returns 0 at once. */
	CHECK(nats_ring_push(r, &(nats_ring_msg_t){
			.subject = "s",
			.subject_len = 1,
			.data = "x",
			.data_len = 1,
			.stream_seq = 0,
			.consumer_seq = 0,
			.delivered = 0,
			.pending = 0,
			.timestamp_ns = 0,
			.ack_token = 1,
		}) == 0);
	CHECK(nats_ring_wait(r, 1000) == 0);

	/* Pop the slot; ring empty again -> wait times out. */
	CHECK(nats_ring_pop(r, &out) == 0);
	CHECK(nats_ring_wait(r, 50) == -1);

	/* Two consecutive pushes: ring stays non-empty across both, so a
	 * wait still returns 0 immediately. */
	CHECK(nats_ring_push(r, &(nats_ring_msg_t){
			.subject = "s",
			.subject_len = 1,
			.data = "x",
			.data_len = 1,
			.stream_seq = 0,
			.consumer_seq = 0,
			.delivered = 0,
			.pending = 0,
			.timestamp_ns = 0,
			.ack_token = 2,
		}) == 0);
	CHECK(nats_ring_push(r, &(nats_ring_msg_t){
			.subject = "s",
			.subject_len = 1,
			.data = "x",
			.data_len = 1,
			.stream_seq = 0,
			.consumer_seq = 0,
			.delivered = 0,
			.pending = 0,
			.timestamp_ns = 0,
			.ack_token = 3,
		}) == 0);
	CHECK(nats_ring_wait(r, 1000) == 0);

	/* Drain both slots and return to empty. */
	CHECK(nats_ring_pop(r, &out) == 0);
	CHECK(nats_ring_pop(r, &out) == 0);
	CHECK(nats_ring_wait(r, 50) == -1);

	nats_ring_destroy(r);
}

/* ── case 6: size limits ──────────────────────────────────────── */

static void test_size_limits(void)
{
	nats_ring_t *r = nats_ring_create(4);
	char subj_ok[NATS_RING_SUBJECT_MAX];
	char data_too_big[NATS_RING_PAYLOAD_MAX + 1];
	int rc;

	CHECK(r != NULL);
	memset(subj_ok, 'a', sizeof(subj_ok));
	memset(data_too_big, 'b', sizeof(data_too_big));

	/* subject too big */
	rc = nats_ring_push(r, &(nats_ring_msg_t){
			.subject = subj_ok,
			.subject_len = NATS_RING_SUBJECT_MAX + 1,
			.data = "x",
			.data_len = 1,
			.stream_seq = 0,
			.consumer_seq = 0,
			.delivered = 0,
			.pending = 0,
			.timestamp_ns = 0,
			.ack_token = 0,
		});
	CHECK(rc == -3);

	/* data too big */
	rc = nats_ring_push(r, &(nats_ring_msg_t){
			.subject = "s",
			.subject_len = 1,
			.data = data_too_big,
			.data_len = NATS_RING_PAYLOAD_MAX + 1,
			.stream_seq = 0,
			.consumer_seq = 0,
			.delivered = 0,
			.pending = 0,
			.timestamp_ns = 0,
			.ack_token = 0,
		});
	CHECK(rc == -2);

	/* reply_to too big */
	rc = nats_ring_push(r, &(nats_ring_msg_t){
			.subject = "s",
			.subject_len = 1,
			.data = "x",
			.data_len = 1,
			.stream_seq = 0,
			.consumer_seq = 0,
			.delivered = 0,
			.pending = 0,
			.timestamp_ns = 0,
			.ack_token = 0,
			.reply_to = subj_ok,
			.reply_to_len = NATS_RING_SUBJECT_MAX + 1,
		});
	CHECK(rc == -3);

	/* exact maxima succeed */
	rc = nats_ring_push(r, &(nats_ring_msg_t){
			.subject = subj_ok,
			.subject_len = NATS_RING_SUBJECT_MAX,
			.data = "x",
			.data_len = 1,
			.stream_seq = 0,
			.consumer_seq = 0,
			.delivered = 0,
			.pending = 0,
			.timestamp_ns = 0,
			.ack_token = 0,
		});
	CHECK(rc == 0);
	CHECK(nats_ring_depth(r) == 1);

	nats_ring_destroy(r);
}

/* ── case 7: destroy while non-empty ──────────────────────────── */

static void test_destroy_nonempty(void)
{
	nats_ring_t *r = nats_ring_create(4);
	int i;

	CHECK(r != NULL);

	for (i = 0; i < 3; i++)
		CHECK(nats_ring_push(r, &(nats_ring_msg_t){
				.subject = "s",
				.subject_len = 1,
				.data = "x",
				.data_len = 1,
				.stream_seq = 0,
				.consumer_seq = 0,
				.delivered = 0,
				.pending = 0,
				.timestamp_ns = 0,
				.ack_token = (uint64_t)i,
			}) == 0);

	CHECK(nats_ring_depth(r) == 3);

	/* Destroy should not deadlock or crash; the design spec documents
	 * that any pending slots are discarded.  There is no fd to close. */
	nats_ring_destroy(r);
}

/* ── invalid capacity ─────────────────────────────────────────── */

static void test_invalid_capacity(void)
{
	CHECK(nats_ring_create(0) == NULL);
	CHECK(nats_ring_create(1) == NULL);    /* min is 2 */
	CHECK(nats_ring_create(3) == NULL);    /* not pow2 */
	CHECK(nats_ring_create(7) == NULL);    /* not pow2 */
	nats_ring_t *r = nats_ring_create(2);
	CHECK(r != NULL);
	nats_ring_destroy(r);
}

/* ── headers round-trip ───────────────────────────────────────── */

/*
 * Push a slot with a pre-serialized header stream and verify the
 * popped copy has matching headers_len, headers_truncated, and byte
 * content.  We build the stream by hand here (same shape the consumer
 * process would emit) rather than depending on natsMsgHeader_*.
 */
static int hdr_append(char *buf, int cap, int pos,
                      const char *k, const char *v)
{
	int klen = (int)strlen(k);
	int vlen = (int)strlen(v);
	int need = 2 + klen + 2 + vlen;
	if (pos + need > cap) return -1;
	buf[pos++] = (char)(klen & 0xFF);
	buf[pos++] = (char)((klen >> 8) & 0xFF);
	memcpy(buf + pos, k, klen); pos += klen;
	buf[pos++] = (char)(vlen & 0xFF);
	buf[pos++] = (char)((vlen >> 8) & 0xFF);
	memcpy(buf + pos, v, vlen); pos += vlen;
	return pos;
}

static void test_headers_roundtrip(void)
{
	nats_ring_t     *r = nats_ring_create(4);
	nats_ring_slot_t out;
	char             hdr_buf[NATS_RING_HEADERS_MAX];
	int              pos;
	int              rc;

	CHECK(r != NULL);

	/* Build a stream with two headers: X-Trace-Id -> 'abc123',
	 * Content-Type -> 'application/json'.  Count prefix goes in last. */
	pos = 2;
	pos = hdr_append(hdr_buf, sizeof(hdr_buf), pos,
		"X-Trace-Id", "abc123");
	CHECK(pos > 0);
	pos = hdr_append(hdr_buf, sizeof(hdr_buf), pos,
		"Content-Type", "application/json");
	CHECK(pos > 0);
	hdr_buf[0] = 2;
	hdr_buf[1] = 0;

	rc = nats_ring_push(r, &(nats_ring_msg_t){
			.subject = "s",
			.subject_len = 1,
			.data = "x",
			.data_len = 1,
			.stream_seq = 0,
			.consumer_seq = 0,
			.delivered = 0,
			.pending = 0,
			.timestamp_ns = 0,
			.ack_token = 7,
			.headers = hdr_buf,
			.headers_len = (uint16_t)pos,
		});
	CHECK(rc == 0);

	rc = nats_ring_pop(r, &out);
	CHECK(rc == 0);
	CHECK(out.headers_len == (uint16_t)pos);
	CHECK(out.headers_truncated == 0);
	CHECK(memcmp(out.headers, hdr_buf, pos) == 0);
	/* count field in byte 0 */
	CHECK((uint8_t)out.headers[0] == 2);
	CHECK((uint8_t)out.headers[1] == 0);

	/* Push with truncated flag propagated */
	rc = nats_ring_push(r, &(nats_ring_msg_t){
			.subject = "s",
			.subject_len = 1,
			.data = "x",
			.data_len = 1,
			.stream_seq = 0,
			.consumer_seq = 0,
			.delivered = 0,
			.pending = 0,
			.timestamp_ns = 0,
			.ack_token = 8,
			.headers = hdr_buf,
			.headers_len = (uint16_t)pos,
			.headers_truncated = 1,
		});
	CHECK(rc == 0);
	rc = nats_ring_pop(r, &out);
	CHECK(rc == 0);
	CHECK(out.headers_truncated == 1);

	/* Push with no headers -- headers_len is 0 and bytes untouched. */
	rc = nats_ring_push(r, &(nats_ring_msg_t){
			.subject = "s",
			.subject_len = 1,
			.data = "x",
			.data_len = 1,
			.stream_seq = 0,
			.consumer_seq = 0,
			.delivered = 0,
			.pending = 0,
			.timestamp_ns = 0,
			.ack_token = 9,
		});
	CHECK(rc == 0);
	rc = nats_ring_pop(r, &out);
	CHECK(rc == 0);
	CHECK(out.headers_len == 0);
	CHECK(out.headers_truncated == 0);

	/* Overflow -- reject with -4. */
	rc = nats_ring_push(r, &(nats_ring_msg_t){
			.subject = "s",
			.subject_len = 1,
			.data = "x",
			.data_len = 1,
			.stream_seq = 0,
			.consumer_seq = 0,
			.delivered = 0,
			.pending = 0,
			.timestamp_ns = 0,
			.ack_token = 10,
			.headers = hdr_buf,
			.headers_len = NATS_RING_HEADERS_MAX + 1,
		});
	CHECK(rc == -4);

	nats_ring_destroy(r);
}

void nc_ut_ring(void)
{
	test_roundtrip_cap2();
	test_full_capacity();
	test_sp_sc_100k();
	test_mp_mc_stress();
	test_wait_semantics();
	test_size_limits();
	test_destroy_nonempty();
	test_invalid_capacity();
	test_headers_roundtrip();

}
