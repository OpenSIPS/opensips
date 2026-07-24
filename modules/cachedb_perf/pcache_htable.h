/*
 * cachedb_perf - high-performance local memory cache
 *
 * Copyright (C) 2026 Yury Kirsanov
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

#ifndef _PCACHE_HTABLE_H_
#define _PCACHE_HTABLE_H_

#include <stddef.h>

#include "../../str.h"
#include "../../locking.h"

#define PCACHE_SLOTS        6
#define PCACHE_SEG_BITS     12
#define PCACHE_SEG_SIZE     (1U << PCACHE_SEG_BITS)          /* 4096 buckets */
#define PCACHE_NSEGS        (1U << (24 - PCACHE_SEG_BITS))   /* for 2^24 max */
#define PCACHE_SEQ_RETRIES  64
#define PCACHE_OVF_BUCKETS  1024
/* per-process stat shards: sized to a fixed cap, not counted_max_processes
 * (not yet final when the table is built in mod_init, pre-fork).  The
 * owner:12 bucket field already caps the system at 4096 processes. */
#define PCACHE_MAX_PROCS    1024

/*
 * The record (DESIGN 3.3).  Byte 0 is the arena class id, stamped by the
 * arena and read-only here (pcache_arena.h).  vlen and expires are
 * naturally aligned so their loads/stores are single-copy-atomic: expires
 * is the versionless-TTL-bump target (DESIGN 2.7) and vlen may be read by
 * an optimistic reader mid-update.  While a cell sits on a free list the
 * link overlays bytes 8-15 (expires/hash) - never klen/vlen, so even a
 * freed cell keeps a bounded length at the vlen offset.
 */
typedef struct pcache_rec {
	unsigned char         cls;      /* arena class - read-only */
	unsigned char         rflags;   /* PCACHE_F_INT etc. (CP-04) */
	unsigned short        klen;
	unsigned int          vlen;
	volatile unsigned int expires;  /* absolute ticks, 0 = never */
	unsigned int          hash;     /* full hash: split relink + fast reject */
	char                  data[];   /* key, then value, contiguous */
} pcache_rec_t;

#define PCACHE_REC_HDR              16
#define PCACHE_REC_SIZE(_kl, _vl)   (PCACHE_REC_HDR + (_kl) + (_vl))

/* rflags: native int64 counter (CP-04) - the value payload is 8 raw
 * bytes, arithmetic is fixed-width under the bucket lock, and every
 * user-facing read (fetch, walker) formats it as a decimal string */
#define PCACHE_F_INT                0x01

/* strict bounded decimal parse; no overflow guard - counter territory */
static inline int pcache_str2ll(const char *p, int len, long long *out)
{
	long long v = 0;
	int i = 0, neg = 0;

	if (len <= 0)
		return -1;
	if (p[0] == '-' || p[0] == '+') {
		neg = p[0] == '-';
		if (++i == len)
			return -1;
	}
	for (; i < len; i++) {
		if (p[i] < '0' || p[i] > '9')
			return -1;
		v = v * 10 + (p[i] - '0');
	}
	*out = neg ? -v : v;
	return 0;
}

_Static_assert(offsetof(pcache_rec_t, vlen) == 4 &&
               offsetof(pcache_rec_t, expires) == 8 &&
               offsetof(pcache_rec_t, data) == PCACHE_REC_HDR,
               "pcache_rec field alignment broken");

/*
 * The bucket (DESIGN 3.1): exactly one cache line.  meta packs
 * used:4 (low bits) | owner:12 (process_no+1 of the lock holder, 0 =
 * none) - the owner exists so the maintenance worker can detect a dead
 * holder (3.5b).  tags[] plus meta form one aligned 8-byte word at offset
 * 8, which the SWAR tag scan loads whole.
 */
typedef struct pcache_bucket {
	volatile unsigned int   version;  /* seqlock: odd = writer inside */
	gen_lock_t              lock;     /* writers (+ reader fallback) */
	unsigned char           tags[PCACHE_SLOTS];  /* hash>>24, never 0 */
	volatile unsigned short meta;     /* used:4 | owner:12 */
	pcache_rec_t           *slot[PCACHE_SLOTS];
} __attribute__((aligned(64))) pcache_bucket_t;

_Static_assert(sizeof(pcache_bucket_t) == 64,
	"cachedb_perf requires a 4-byte lock backend (futex/fastlock): "
	"gen_lock_t made pcache_bucket exceed one cache line");
_Static_assert(offsetof(pcache_bucket_t, tags) == 8,
	"tags+meta must form the aligned 8-byte word at offset 8");

struct povf;

/*
 * Per-process op counters (CP-06): one cache line per process per table,
 * plain increments on the owner's own line, summed only at read time.
 * NEVER update_stat() per operation - that is one shared atomic line,
 * the measured 0.72x collapse (DESIGN 2.5) installed by observability.
 */
typedef struct pcache_pstat {
	unsigned long hits, misses, stores, removes,
	              created, destroyed, retries, fallbacks;
} __attribute__((aligned(64))) pcache_pstat_t;

typedef struct pcache_ht_totals {
	unsigned long hits, misses, stores, removes,
	              created, destroyed, retries, fallbacks, entries;
} pcache_ht_totals_t;

typedef struct pcache_htable {
	/* the 3.4 routing word: (level << 32) | split, published whole.
	 * On its own line - everything else here mutates */
	volatile unsigned long  route;
	char                    _pad0[56];

	unsigned int            nbuckets;
	volatile unsigned int   ovf_count;   /* readers' overflow gate */
	gen_lock_t              ovf_lock;
	struct povf           **ovf_tab;     /* PCACHE_OVF_BUCKETS heads */

	pcache_bucket_t        *seg[PCACHE_NSEGS];

	/* per-bucket min-expires hints (CP-05), parallel to seg[]: the 64B
	 * bucket is full, and a separate array sweeps better anyway - 16
	 * hints per cache line, no bucket touched unless due.  Written under
	 * the bucket lock, only when a LOWER expiry arrives (a TTL bump only
	 * raises, so the hot bump path never writes here); a stale-low hint
	 * just costs one wasted bucket visit.  0 = nothing expiring */
	unsigned int           *hint_seg[PCACHE_NSEGS];

	/* CP-06 counters, indexed by process_no */
	pcache_pstat_t         *pstats;
	unsigned int            pstats_n;
} pcache_htable_t;

/* sum the per-process shards; entries = created - destroyed */
void pcache_ht_totals(pcache_htable_t *ht, pcache_ht_totals_t *out);

pcache_htable_t *pcache_htable_new(unsigned int size_log2);

/* 0 = stored; -1 = error.  @expires is absolute ticks, 0 = never */
int pcache_ht_store(pcache_htable_t *ht, const str *key, const str *val,
		unsigned int expires);

/* 0 = hit (val->s pkg-allocated, caller frees); -2 = miss or expired;
 * -1 = error */
int pcache_ht_fetch(pcache_htable_t *ht, const str *key, str *val);

/* 1 = removed; 0 = was absent; -1 = error */
int pcache_ht_remove(pcache_htable_t *ht, const str *key);

/* atomic counter add (CP-04): creates a native counter on an absent key,
 * accumulates fixed-width on an existing one, converts a numeric string
 * record on first touch.  0 = ok (*new_val = the result); -1 = error or
 * the existing value is not an integer.  @expires re-arms the TTL,
 * absolute ticks, 0 = never */
int pcache_ht_add(pcache_htable_t *ht, const str *key, long long delta,
		unsigned int expires, long long *new_val);

/*
 * Key/value walker: per-slot optimistic snapshots over every bucket, then
 * the overflow chains under the overflow lock.  @key/@val given to the
 * callback are stable NUL-terminated copies in walker-owned buffers,
 * valid only for the duration of the call; @expires is raw (0 = never) -
 * filtering is the callback's choice.  Return <0 from the callback to
 * stop the walk (returned through).
 *
 * Guarantees are the Redis SCAN class: an entry mutated concurrently may
 * be seen once, twice or not at all.  The overflow leg runs under the
 * overflow lock, so the callback must not re-enter this cache.
 */
typedef int (*pcache_iter_cb)(const str *key, const str *val,
		unsigned int expires, void *ctx);
int pcache_ht_iter(pcache_htable_t *ht, pcache_iter_cb cb, void *ctx);

/* expiry sweep (CP-05): visits only buckets whose hint is due, removes
 * expired records (overflow chains too whenever any overflow exists) and
 * reclaims their cells through the global pool - the sweeping process is
 * not an allocator, so private-stack frees would never drain.  Returns
 * the number of records reclaimed. */
unsigned int pcache_ht_sweep(pcache_htable_t *ht, unsigned int now);

/* linear-hash growth (CP-09): split buckets while entries/nbuckets exceeds
 * @target_lf, up to @budget splits.  Single-splitter (maintenance timer). */
unsigned int pcache_ht_grow(pcache_htable_t *ht, unsigned int target_lf,
		unsigned int budget);

/* modparam-triggered startup selftest; -1 on any mismatch */
int pcache_htable_selftest(void);

#endif /* _PCACHE_HTABLE_H_ */
