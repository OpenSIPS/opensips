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
 * nats_ring.c -- per-handle bounded MPMC SHM ring.
 *
 * Algorithm: bounded MPMC ring with per-slot generation tags.
 * Two monotonically-increasing 64-bit indices (head and
 * tail) live in the ring header; a power-of-two capacity means the
 * actual slot index is `head & mask`.  Per-slot sequence counters
 * (ready_gen / consumed_gen) decide when a producer may write a slot
 * and when a consumer may read it.
 *
 * Push (producer):
 *   1. Load head, tail.  If head - tail >= capacity the ring is full.
 *   2. Before committing the reservation, wait until the slot's
 *      consumed_gen has caught up to the previous generation
 *      (head - capacity) so we know the slot is no longer in use by a
 *      consumer.  The very first `capacity` pushes skip this test
 *      because the slot has never been used.
 *   3. CAS head from h to h+1.  On failure, retry from (1).
 *   4. Copy payload into slots[h & mask].
 *   5. Release-store slot->ready_gen = h.  This publishes the slot.
 *   6. If the pre-push head equaled tail (i.e. the ring was empty),
 *      bump wake_seq and FUTEX_WAKE waiters.  This is the empty ->
 *      non-empty edge.
 *
 * Pop (consumer):
 *   1. Load tail, head.  If tail >= head the ring is empty.
 *   2. Acquire-load slots[tail & mask].ready_gen.  If != tail the
 *      producer hasn't published yet; cpu_relax and retry the load,
 *      but re-check head first so a concurrent consumer that has
 *      advanced tail doesn't leave us spinning forever.
 *   3. CAS tail from t to t+1.  On failure, retry from (1).
 *   4. Copy slot contents into the caller's out buffer.
 *   5. Store slot->consumed_gen = t.  This releases the slot for the
 *      next producer generation.
 *
 * Wakeup is futex-only: the producer bumps wake_seq and FUTEX_WAKEs on
 * the empty -> non-empty transition, and the consumer is expected to
 * drain everything available after wake-up.  Spurious wakes are
 * harmless -- a subsequent pop just returns -1 and the worker re-arms
 * its wait.  There is no eventfd: a per-process fd stored in SHM would
 * be written/closed by processes other than its creator, where the
 * integer maps to an unrelated descriptor.
 *
 * Memory model: all shared indices use C11 _Atomic with explicit
 * memory_order annotations.  The release/acquire pair on ready_gen
 * synchronizes the payload write with the payload read; head and
 * tail advance with memory_order_acq_rel so the CAS is a full
 * barrier for the reservation itself.
 */

#ifdef TEST_SHIM
#include "tests/test_shim.h"
#else
#include "../../mem/shm_mem.h"
#include "../../dprint.h"
#endif

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdatomic.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <time.h>
#include <limits.h>

#include "nats_ring.h"

/*
 * cpu_relax is a hint to the CPU that we are in a spin loop.  On x86
 * this emits PAUSE; on aarch64 it emits YIELD.  Wrapped in a no-op for
 * unknown targets.
 */
#if defined(__x86_64__) || defined(__i386__)
# define nats_ring_cpu_relax() __asm__ __volatile__("pause" ::: "memory")
#elif defined(__aarch64__)
# define nats_ring_cpu_relax() __asm__ __volatile__("yield" ::: "memory")
#else
# define nats_ring_cpu_relax() ((void)0)
#endif

struct nats_ring {
	uint32_t         capacity;   /* power of 2 */
	uint32_t         mask;       /* capacity - 1 */

	/* Cross-process wakeup primitive.  There is deliberately NO eventfd
	 * here: a per-process fd stored in SHM would be written/closed by
	 * processes other than its creator (push runs in the consumer proc,
	 * destroy may run elsewhere), where the integer maps to an unrelated
	 * descriptor -- cross-process fd corruption.  Instead the producer
	 * bumps wake_seq + FUTEX_WAKEs on its address, which IS valid across
	 * processes because the address lives in SHM.  Workers snapshot
	 * wake_seq before a non-blocking pop and then FUTEX_WAIT against the
	 * snapshot -- standard linux futex pattern, sub-millisecond wake-up. */
	_Atomic uint32_t wake_seq;
	/* Number of consumers currently blocked in nats_ring_wait().  The
	 * producer wakes at most ONE waiter per published message (not every
	 * waiter), so a single message no longer stampedes all N workers; a
	 * burst of K messages issues K single wakes, so up to K workers run in
	 * parallel.  The producer also skips the FUTEX_WAKE syscall entirely
	 * when no one is waiting. */
	_Atomic uint32_t waiters;

	/* producer-side force-unwedge state.  Production has a
	 * single producer per ring (the consumer process), but the ring's
	 * contract -- and the MPMC stress test -- allow concurrent
	 * producers, so the advisory tracker is atomic (relaxed: a torn
	 * arm at worst delays a force by one window, the safe direction). */
	_Atomic uint64_t  unwedge_want;      /* generation blocking push */
	_Atomic long long unwedge_since_us;  /* first observation; 0 = none */
	_Atomic uint64_t  forced_unwedges;

	/* hot counters -- head is written by producers, tail by consumers;
	 * they are placed on separate 64-bit slots so the compiler cannot
	 * coalesce them but we deliberately do not false-share-pad: in our
	 * workload the per-slot sequence counters dominate. */
	_Atomic uint64_t head;
	_Atomic uint64_t tail;

	/* flexible array of fixed-size slots; sized at create time. */
	nats_ring_slot_t slots[];
};

/* power-of-two check (>= 2). */
static int nats_ring_valid_capacity(uint32_t c)
{
	if (c < 2)
		return 0;
	return (c & (c - 1)) == 0;
}


nats_ring_t *nats_ring_create(uint32_t capacity)
{
	nats_ring_t *r;
	size_t bytes;

	if (!nats_ring_valid_capacity(capacity)) {
		LM_ERR("nats_ring: invalid capacity %u (must be pow2 >= 2)\n",
			capacity);
		return NULL;
	}

	bytes = sizeof(*r) + (size_t)capacity * sizeof(nats_ring_slot_t);
	r = (nats_ring_t *)shm_malloc(bytes);
	if (!r) {
		LM_ERR("nats_ring: oom for ring of %u slots (%zu bytes)\n",
			capacity, bytes);
		return NULL;
	}
	memset(r, 0, bytes);

	r->capacity = capacity;
	r->mask     = capacity - 1;
	atomic_init(&r->head, (uint64_t)0);
	atomic_init(&r->tail, (uint64_t)0);

	/* Pre-seed every slot so the first `capacity` pushes don't need
	 * to wait for a prior consumer.  Before the first push, slot i
	 * appears to have been consumed at "generation" i - capacity,
	 * which is the condition the push loop expects. */
	for (uint32_t i = 0; i < capacity; i++) {
		/* UINT64_MAX stands in for "never been touched"; the push
		 * loop has an explicit first-round branch that skips the
		 * wait for head < capacity, so the exact value doesn't
		 * matter as long as it can't collide with a real index. */
		r->slots[i].ready_gen    = UINT64_MAX;
		r->slots[i].consumed_gen = UINT64_MAX;
	}

#ifdef UNIT_TESTS
	nc_ut_rings_created++;
#endif
	return r;
}

void nats_ring_destroy(nats_ring_t *r)
{
	if (!r)
		return;
	/* No fd to close: wakeup is futex-only (see struct nats_ring). */
	shm_free(r);
#ifdef UNIT_TESTS
	nc_ut_rings_destroyed++;
#endif
}

/*
 * Bound on how many times push will spin waiting for a single slot's
 * previous consumer to publish consumed_gen before giving up and
 * reporting "full".  The consumer (a SIP worker) may die AFTER advancing
 * tail but BEFORE the consumed_gen release-store, leaving the slot
 * forever un-consumed while the ring still looks non-full; without a cap
 * the producer (the consumer process) would spin here forever, pinning a
 * CPU.  Bailing with -1 lets the caller back off; a merely-preempted
 * consumer that resumes within the cap is still observed on the fast path.
 */
#define NATS_RING_PUSH_SPIN_MAX  4096u

/* CLOCK_MONOTONIC microseconds for the unwedge tracker. */
#ifdef UNIT_TESTS
/* rings this process made and freed, for the unit test suite */
int nc_ut_rings_created, nc_ut_rings_destroyed;
/* the force-unwedge wait, which the suite shortens */
long long nc_ut_unwedge_us = NATS_RING_FORCE_UNWEDGE_US;

void nc_ut_ring_forge(nats_ring_t *r, uint64_t head, uint64_t tail)
{
	atomic_store_explicit(&r->head, head, memory_order_release);
	atomic_store_explicit(&r->tail, tail, memory_order_release);
}

uint32_t nc_ut_ring_waiters(const nats_ring_t *r)
{
	return atomic_load_explicit(&r->waiters, memory_order_acquire);
}
#endif

static long long ring_now_us(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000000LL + ts.tv_nsec / 1000;
}

/*
 * The push spin cap just expired waiting for consumed_gen ==
 * @want on @slot.  A live popper's release lands in nanoseconds; the
 * SAME generation keeping push blocked for the whole unwedge window
 * means the popper died between its tail-CAS and the release.  Force
 * the missing release (CAS from the observed stale value) so the
 * handle resumes delivery -- the un-popped message was never acked,
 * so JetStream redelivers it.  Returns 1 if push should retry the
 * wait (recovered), 0 to bail full as before.
 */
static int ring_try_force_unwedge(nats_ring_t *r, nats_ring_slot_t *slot,
	uint64_t want)
{
	long long now = ring_now_us();
	long long since = atomic_load_explicit(&r->unwedge_since_us,
		memory_order_relaxed);
	uint64_t got;

	if (since == 0 ||
	    atomic_load_explicit(&r->unwedge_want,
			memory_order_relaxed) != want) {
		/* first sighting of THIS stuck generation: arm the timer */
		atomic_store_explicit(&r->unwedge_want, want,
			memory_order_relaxed);
		atomic_store_explicit(&r->unwedge_since_us, now,
			memory_order_relaxed);
		return 0;
	}
#ifdef UNIT_TESTS
	if (now - since < nc_ut_unwedge_us)
		return 0;
#else
	if (now - since < NATS_RING_FORCE_UNWEDGE_US)
		return 0;
#endif

	got = __atomic_load_n(&slot->consumed_gen, __ATOMIC_ACQUIRE);
	if (got == want ||
	    __atomic_compare_exchange_n(&slot->consumed_gen, &got, want,
			0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
		if (got != want) {
			LM_WARN("nats_ring: force-unwedged slot %u at "
				"generation %llu (popper died before its "
				"release; JetStream will redeliver the lost "
				"message)\n",
				(unsigned)(want & r->mask),
				(unsigned long long)want);
			atomic_fetch_add_explicit(&r->forced_unwedges, 1,
				memory_order_relaxed);
		}
		atomic_store_explicit(&r->unwedge_since_us, 0,
			memory_order_relaxed);
		return 1;
	}
	/* CAS lost: the popper released concurrently -- recovered anyway */
	atomic_store_explicit(&r->unwedge_since_us, 0,
		memory_order_relaxed);
	return 1;
}

/* Post-copy ownership check for pop: a force-unwedge may hand
 * the slot back to the producer under a STALLED copy; if the slot was
 * republished, the copy is torn and must be dropped (the message was
 * never acked -- JetStream redelivers). */
static inline int ring_pop_still_owned(const nats_ring_slot_t *slot,
	uint64_t t)
{
	return __atomic_load_n(&slot->ready_gen, __ATOMIC_ACQUIRE) == t;
}

uint64_t nats_ring_forced_unwedges(const nats_ring_t *r)
{
	return r ? atomic_load_explicit(
		&((nats_ring_t *)r)->forced_unwedges,
		memory_order_relaxed) : 0;
}

int nats_ring_push(nats_ring_t *r, const nats_ring_msg_t *m)
{
	const char *subject, *data, *reply_to, *headers;
	uint32_t subject_len, data_len, reply_to_len;
	uint64_t stream_seq, consumer_seq, delivered, pending, ack_token;
	int64_t timestamp_ns;
	uint16_t headers_len;
	uint8_t headers_truncated;

	if (!m)
		return -2;
	subject = m->subject;           subject_len = m->subject_len;
	data = m->data;                 data_len = m->data_len;
	stream_seq = m->stream_seq;     consumer_seq = m->consumer_seq;
	delivered = m->delivered;       pending = m->pending;
	timestamp_ns = m->timestamp_ns; ack_token = m->ack_token;
	reply_to = m->reply_to;         reply_to_len = m->reply_to_len;
	headers = m->headers;           headers_len = m->headers_len;
	headers_truncated = m->headers_truncated;

	uint64_t h, t;
	nats_ring_slot_t *slot;
	unsigned spins = 0;     /* consumed_gen stall counter */
	uint64_t spin_h = 0;    /* head value the stall counter is tracking */
	int      spin_tracking = 0;

	if (!r)
		return -1;
	if (data_len > NATS_RING_PAYLOAD_MAX)
		return -2;
	if (subject_len > NATS_RING_SUBJECT_MAX)
		return -3;
	if (reply_to_len > NATS_RING_SUBJECT_MAX)
		return -3;
	if (headers_len > NATS_RING_HEADERS_MAX)
		return -4;

	for (;;) {
		h = atomic_load_explicit(&r->head, memory_order_relaxed);
		t = atomic_load_explicit(&r->tail, memory_order_acquire);
		if (h - t >= r->capacity)
			return -1;   /* full */

		slot = &r->slots[h & r->mask];

		/*
		 * If this slot has been used before, we must wait for the
		 * previous consumer to have marked it consumed at the prior
		 * generation (h - capacity).  Until then a stale ready_gen
		 * could confuse future pops.  The UINT64_MAX sentinel set in
		 * nats_ring_create() means "never used" and passes this test
		 * trivially for the first `capacity` pushes.
		 */
		if (h >= r->capacity) {
			uint64_t want = h - r->capacity;
			uint64_t got = __atomic_load_n(&slot->consumed_gen,
				__ATOMIC_ACQUIRE);
			if (got != want) {
				/* Consumer is still finishing the previous
				 * generation of this slot.  Bounded wait: if the
				 * SAME head stays blocked on an un-consumed slot
				 * for too long, the popper that reserved the
				 * previous generation likely died -- bail as full
				 * so the caller backs off rather than pinning a
				 * CPU forever.  A tail/head that advances (real
				 * progress) resets the counter. */
				if (spin_tracking && h == spin_h) {
					if (++spins >= NATS_RING_PUSH_SPIN_MAX) {
						/* dead-popper recovery
						 * before bailing full */
						if (ring_try_force_unwedge(r,
								slot, want)) {
							spins = 0;
							continue;
						}
						return -1;
					}
				} else {
					spin_tracking = 1;
					spin_h = h;
					spins  = 0;
				}
				nats_ring_cpu_relax();
				continue;
			}
		}

		spin_tracking = 0;
		atomic_store_explicit(&r->unwedge_since_us, 0,
			memory_order_relaxed);  /* progress: disarm */
		if (atomic_compare_exchange_weak_explicit(
				&r->head, &h, h + 1,
				memory_order_acq_rel,
				memory_order_relaxed)) {
			break;
		}
		/* CAS lost: another producer took this head; retry. */
	}

	/* `slot` is ours.  Fill it in. */
	slot->subject_len = subject_len;
	if (subject_len)
		memcpy(slot->subject, subject, subject_len);

	slot->data_len = data_len;
	if (data_len)
		memcpy(slot->data, data, data_len);

	slot->stream_seq   = stream_seq;
	slot->consumer_seq = consumer_seq;
	slot->delivered    = delivered;
	slot->pending      = pending;
	slot->timestamp_ns = timestamp_ns;
	slot->ack_token    = ack_token;

	if (reply_to && reply_to_len) {
		slot->has_reply    = 1;
		slot->reply_to_len = reply_to_len;
		memcpy(slot->reply_to, reply_to, reply_to_len);
	} else {
		slot->has_reply    = 0;
		slot->reply_to_len = 0;
	}

	/* Headers: raw byte-for-byte copy of the caller-serialized stream.
	 * The wire format is documented on nats_ring_slot_t.headers[]. */
	slot->headers_len        = headers_len;
	slot->headers_truncated  = headers_truncated ? 1 : 0;
	if (headers && headers_len > 0)
		memcpy(slot->headers, headers, headers_len);

	/* Publish: release-store ready_gen so the pop-side acquire-load
	 * observes the fully-written slot. */
	__atomic_store_n(&slot->ready_gen, h, __ATOMIC_RELEASE);

	(void)t;
	/*
	 * Wake exactly ONE blocked consumer for the message we just published.
	 *
	 * Bump wake_seq (release ordering) so a worker that is between its
	 * emptiness check and FUTEX_WAIT sees the change and the wait returns
	 * EAGAIN instead of blocking.  Then, only if someone is actually
	 * blocked, FUTEX_WAKE exactly 1 waiter: one message -> one woken
	 * worker, so a single message no longer stampedes all N workers, and a
	 * burst of K messages issues K single wakes (one per push) so up to K
	 * workers drain in parallel.  When no one is waiting (workers already
	 * busy popping) we skip the syscall entirely.  The futex word lives in
	 * SHM so this is valid no matter which process produced the slot.
	 */
	atomic_fetch_add_explicit(&r->wake_seq, 1, memory_order_release);
	if (atomic_load_explicit(&r->waiters, memory_order_acquire) > 0)
		syscall(SYS_futex, &r->wake_seq, FUTEX_WAKE, 1, NULL, NULL, 0);

	return 0;
}

/*
 * Bound on how many times pop will spin waiting for a single reserved
 * slot to be published (ready_gen == tail) before giving up and
 * reporting "empty".  The producer is the consumer process; if it dies
 * or is preempted for a long time AFTER bumping head but BEFORE the
 * release-store to ready_gen, the popper would otherwise spin forever
 * (head > tail, so the ring looks non-empty, but the slot never
 * publishes).  Bailing to the empty path lets the worker re-arm its
 * reactor / futex wait and try again later instead of burning a core.
 * The cap is generous so a merely-preempted producer that comes back
 * within a few microseconds is still observed on the fast path; only a
 * genuinely stalled producer trips it.  Bailing is cheap and harmless --
 * the caller just re-arms its futex wait and retries -- so the cap is
 * kept low (a stalled slot should not burn a whole scheduler quantum).
 */
#define NATS_RING_POP_SPIN_MAX  4096u

void nats_ring_slot_copy_used(nats_ring_slot_t *dst,
		const nats_ring_slot_t *src)
{
	uint32_t n;

	dst->ready_gen    = src->ready_gen;
	dst->consumed_gen = src->consumed_gen;

	n = src->subject_len;
	if (n > NATS_RING_SUBJECT_MAX) n = NATS_RING_SUBJECT_MAX;
	dst->subject_len = n;
	if (n) memcpy(dst->subject, src->subject, n);

	n = src->data_len;
	if (n > NATS_RING_PAYLOAD_MAX) n = NATS_RING_PAYLOAD_MAX;
	dst->data_len = n;
	if (n) memcpy(dst->data, src->data, n);

	dst->stream_seq   = src->stream_seq;
	dst->consumer_seq = src->consumer_seq;
	dst->delivered    = src->delivered;
	dst->pending      = src->pending;
	dst->timestamp_ns = src->timestamp_ns;
	dst->ack_token    = src->ack_token;

	dst->has_reply    = src->has_reply;
	n = src->reply_to_len;
	if (n > NATS_RING_SUBJECT_MAX) n = NATS_RING_SUBJECT_MAX;
	dst->reply_to_len = n;
	if (n) memcpy(dst->reply_to, src->reply_to, n);

	dst->headers_len       = src->headers_len;
	if (dst->headers_len > NATS_RING_HEADERS_MAX)
		dst->headers_len = NATS_RING_HEADERS_MAX;
	dst->headers_truncated = src->headers_truncated;
	dst->_hdr_pad          = 0;
	if (dst->headers_len)
		memcpy(dst->headers, src->headers, dst->headers_len);
}

int nats_ring_pop(nats_ring_t *r, nats_ring_slot_t *out)
{
	uint64_t t, h, ready;
	uint64_t spin_t;        /* tail value the spin counter is tracking */
	unsigned spins = 0;
	nats_ring_slot_t *slot;

	if (!r || !out)
		return -1;

	t = atomic_load_explicit(&r->tail, memory_order_relaxed);
	spin_t = t;

	for (;;) {
		t = atomic_load_explicit(&r->tail, memory_order_relaxed);
		h = atomic_load_explicit(&r->head, memory_order_acquire);
		if (t >= h)
			return -1;   /* empty */

		slot = &r->slots[t & r->mask];
		ready = __atomic_load_n(&slot->ready_gen, __ATOMIC_ACQUIRE);
		if (ready != t) {
			/* Producer reserved but hasn't released yet -- or a
			 * concurrent consumer already advanced tail.  Loop:
			 * the next iteration's head/tail load will tell us
			 * which case we're in. */
			if (t != spin_t) {
				/* Tail moved (a concurrent consumer made progress
				 * or we are on a fresh slot): real forward motion,
				 * reset the stall counter. */
				spin_t = t;
				spins  = 0;
			} else if (++spins >= NATS_RING_POP_SPIN_MAX) {
				/* Same slot has been un-published for too long --
				 * treat as a stalled / dead producer and report
				 * empty rather than spinning indefinitely.  The
				 * caller re-arms its wait and retries. */
				return -1;
			}
			nats_ring_cpu_relax();
			continue;
		}

		if (atomic_compare_exchange_weak_explicit(
				&r->tail, &t, t + 1,
				memory_order_acq_rel,
				memory_order_relaxed)) {
			break;
		}
		/* CAS lost: another consumer took this tail; retry. */
	}

	/* Copy only the used prefix of subject/data/reply_to/headers into the
	 * caller's buffer to avoid touching ~17.9 KB of SHM per pop. */
	nats_ring_slot_copy_used(out, slot);

	/* If a force-unwedge recycled this slot under a stalled
	 * copy, the bytes above are torn: drop them (never released, never
	 * acked -- JetStream redelivers the message). */
	if (!ring_pop_still_owned(slot, t))
		return -1;

	/* Mark the slot consumed at generation t so the matching producer
	 * (generation t + capacity) may reuse it. CAS from the
	 * deterministic prior value (t - capacity, or the create() seed on
	 * the first lap): a resurrected popper's LATE release must never
	 * regress a consumed_gen the force-unwedge already moved past. */
	{
		uint64_t prev = (t >= r->capacity) ? t - r->capacity
		                                   : UINT64_MAX;
		(void)__atomic_compare_exchange_n(&slot->consumed_gen,
			&prev, t, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
	}

	return 0;
}

int nats_ring_wait(nats_ring_t *r, int timeout_ms)
{
	uint32_t seq;
	uint64_t h, t;
	struct timespec ts;
	long rc;

	if (!r) return -1;
	if (timeout_ms <= 0) return -1;

	/* Sample the wake counter BEFORE checking emptiness; if a producer
	 * fires between our depth-check and the FUTEX_WAIT, the counter
	 * will have advanced and the syscall returns EAGAIN immediately. */
	seq = atomic_load_explicit(&r->wake_seq, memory_order_acquire);
	h = atomic_load_explicit(&r->head, memory_order_acquire);
	t = atomic_load_explicit(&r->tail, memory_order_relaxed);
	if (h > t) return 0;   /* not empty, no wait needed */

	ts.tv_sec  = timeout_ms / 1000;
	ts.tv_nsec = (timeout_ms % 1000) * 1000000L;

	/* Register as a waiter so the producer knows to issue a wake (and how
	 * many).  Re-check emptiness AFTER incrementing: a producer that
	 * published between the check above and the increment may already have
	 * skipped our wake (it saw waiters==0), so we must not block on stale
	 * emptiness.  The wake_seq snapshot still guards the block itself. */
	atomic_fetch_add_explicit(&r->waiters, 1, memory_order_acq_rel);
	h = atomic_load_explicit(&r->head, memory_order_acquire);
	t = atomic_load_explicit(&r->tail, memory_order_relaxed);
	if (h > t) {
		atomic_fetch_sub_explicit(&r->waiters, 1, memory_order_acq_rel);
		return 0;
	}

	rc = syscall(SYS_futex, &r->wake_seq, FUTEX_WAIT, seq, &ts, NULL, 0);
	atomic_fetch_sub_explicit(&r->waiters, 1, memory_order_acq_rel);
	if (rc == 0) return 0;
	/* EAGAIN means the value already differed -- producer raced us
	 * but the data is in the ring already.  Treat as success. */
	if (errno == EAGAIN) return 0;
	return -1;
}

int nats_ring_eventfd(const nats_ring_t *r)
{
	/* Compatibility stub.  The ring no longer owns an eventfd (it was a
	 * cross-process fd-corruption hazard; see struct nats_ring).  Always
	 * returns -1 so legacy callers that fetch and discard it keep
	 * compiling.  Cross-process wakeup is via nats_ring_wait(). */
	(void)r;
	return -1;
}

uint32_t nats_ring_depth(const nats_ring_t *r)
{
	uint64_t h, t;

	if (!r)
		return 0;
	/* Two relaxed loads; the result is advisory. */
	h = atomic_load_explicit(&r->head, memory_order_relaxed);
	t = atomic_load_explicit(&r->tail, memory_order_relaxed);
	if (h <= t)
		return 0;
	return (uint32_t)(h - t);
}

uint32_t nats_ring_capacity(const nats_ring_t *r)
{
	return r ? r->capacity : 0;
}
