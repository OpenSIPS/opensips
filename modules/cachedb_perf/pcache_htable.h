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

#include <stdint.h>
#include <stddef.h>

#include "../../str.h"
#include "../../locking.h"

#define PCACHE_SLOTS        6
#define PCACHE_SEG_BITS     12
#define PCACHE_SEG_SIZE     (1U << PCACHE_SEG_BITS)          /* 4096 buckets */
/* largest table the segment directory can describe */
#define PCACHE_MAX_SIZE_LOG2 24
#define PCACHE_NSEGS        (1U << (PCACHE_MAX_SIZE_LOG2 - PCACHE_SEG_BITS))
#define PCACHE_SEQ_RETRIES  64
/* overflow leg chains; the head array (128 KB) fits one region slot */
#define PCACHE_OVF_BUCKETS  16384
/* stat shards; the process count is not final yet in mod_init */
#define PCACHE_MAX_PROCS    1024

/* The record.  vlen and expires are naturally aligned, so lock-free readers
 * see them single-copy-atomic.  The free-list link overlays bytes 8-15 only,
 * so a freed cell still holds a bounded vlen. */
typedef struct pcache_rec {
	unsigned char         cls;      /* arena class - read-only */
	unsigned char         rflags;   /* PCACHE_F_* */
	unsigned short        klen;
	unsigned int          vlen;
	volatile unsigned int expires;  /* absolute ticks, 0 = never */
	unsigned int          hash;     /* full hash: split relink + fast reject */
	char                  data[];   /* key, then value, contiguous */
} pcache_rec_t;

#define PCACHE_REC_HDR              16

/* the key hash (MurmurHash3 x86_32), local to this node */
unsigned int pcache_key_hash(const str *key);
#define PCACHE_REC_SIZE(_kl, _vl)   (PCACHE_REC_HDR + (_kl) + (_vl))

/* native int64 counter: 8 raw bytes, formatted as decimal on every read */
#define PCACHE_F_INT                0x01
/* passive copy that arrived through a cluster pull, not a local write;
 * not authoritative when serving peers.  A local write clears it. */
#define PCACHE_F_PASSIVE            0x02

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

/* one cache line; owner is process_no+1 of the lock holder.  tags[] + meta
 * form the 8-byte word the SWAR tag scan loads whole */
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

/* per-process op counters on the owner's own line, summed at read time */
typedef struct pcache_pstat {
	unsigned long hits, misses, stores, removes,
	              created, destroyed, expired, retries, fallbacks,
	/* stores with expires == 0: a count of operations, not live entries */
	              stores_immortal;
} __attribute__((aligned(64))) pcache_pstat_t;

typedef struct pcache_ht_totals {
	unsigned long hits, misses, stores, removes,
	              created, destroyed, expired, retries, fallbacks, entries,
	              stores_immortal;
} pcache_ht_totals_t;

typedef struct pcache_htable {
	/* routing word (level << 32) | split, published whole, on its own
	 * line; uint64_t because unsigned long is 32 bits on ILP32 */
	volatile uint64_t       route;
	char                    _pad0[56];

	unsigned int            nbuckets;
	volatile unsigned int   ovf_count;   /* readers' overflow gate */
	gen_lock_t              ovf_lock;
	struct povf           **ovf_tab;     /* PCACHE_OVF_BUCKETS heads */

	pcache_bucket_t        *seg[PCACHE_NSEGS];

	/* per-bucket min-expires hints, parallel to seg[]; written under the
	 * bucket lock, only lowered.  A stale-low hint costs one wasted visit.
	 * 0 = nothing expiring */
	unsigned int           *hint_seg[PCACHE_NSEGS];

	/* op counters, indexed by process_no */
	pcache_pstat_t         *pstats;
	unsigned int            pstats_n;

	/* shard sums at the last stats reset; the shards themselves are owned
	 * by their processes and never rewound */
	pcache_ht_totals_t      base;
} pcache_htable_t;

/* sum the per-process shards, less the reset baseline; entries is absolute */
void pcache_ht_totals(pcache_htable_t *ht, pcache_ht_totals_t *out);

/* restart the cumulative counters from zero; live gauges are unaffected */
void pcache_ht_stats_reset(pcache_htable_t *ht);

/* current bucket count (grows at runtime) */
unsigned int pcache_ht_nbuckets(pcache_htable_t *ht);
/* records in the overflow leg */
unsigned int pcache_ht_overflow(pcache_htable_t *ht);

pcache_htable_t *pcache_htable_new(unsigned int size_log2);

/* 0 = stored; -1 = error; -2 = out of memory (write dropped).
 * @expires is absolute ticks, 0 = never */
int pcache_ht_store(pcache_htable_t *ht, const str *key, const str *val,
		unsigned int expires);

/* as pcache_ht_store, stamping @rflags on the record */
int pcache_ht_store_ex(pcache_htable_t *ht, const str *key, const str *val,
		unsigned int expires, unsigned char rflags);

/* fetch_buf(): @buf too small, *needed holds the required size */
#define PCACHE_E_TOOSMALL   (-3)

/* smallest buffer fetch_buf() accepts: fits any formatted counter */
#define PCACHE_GETBUF_MIN   24

/* existence probe without copying the value; same read path as the
 * fetches.  @vlen, @expires, @is_counter are optional.
 * 0 = present and live, -2 = absent or expired, -1 = bad args */
int pcache_ht_probe(pcache_htable_t *ht, const str *key, unsigned int *vlen,
		unsigned int *expires, int *is_counter);

/* read into a caller-owned buffer, which must be process-private: it is
 * written speculatively, so its contents are undefined unless 0 is returned.
 * 0 = hit, *vlen bytes written (not NUL-terminated); -2 = miss or expired;
 * -1 = error; PCACHE_E_TOOSMALL.  @needed may be NULL */
int pcache_ht_fetch_buf(pcache_htable_t *ht, const str *key, char *buf,
		unsigned int buflen, unsigned int *vlen, unsigned int *needed);

/* 0 = hit (val->s pkg-allocated, caller frees); -2 = miss or expired;
 * -1 = error */
int pcache_ht_fetch(pcache_htable_t *ht, const str *key, str *val);

/* as pcache_ht_fetch, also returning the absolute expiry and the record
 * flags on a hit; either out pointer may be NULL */
int pcache_ht_fetch_ex(pcache_htable_t *ht, const str *key, str *val,
		unsigned int *expires, unsigned char *rflags);

/* 1 = removed; 0 = was absent; -1 = error */
int pcache_ht_remove(pcache_htable_t *ht, const str *key);

/* re-arm an existing key's TTL without rewriting the value (no version
 * bump).  1 = re-armed, 0 = absent */
int pcache_ht_touch(pcache_htable_t *ht, const str *key, unsigned int expires);

/* atomic counter add; creates the counter if absent, converts a numeric
 * string value.  0 = ok (*new_val = result); -1 = error or not an integer */
int pcache_ht_add(pcache_htable_t *ht, const str *key, long long delta,
		unsigned int expires, long long *new_val);

/* Walk every record; @key/@val are NUL-terminated copies valid during the
 * callback, <0 from it stops the walk.  Concurrently mutated entries may be
 * seen 0-2 times.  No lock is held across the callback. */
typedef int (*pcache_iter_cb)(const str *key, const str *val,
		unsigned int expires, void *ctx);
int pcache_ht_iter(pcache_htable_t *ht, pcache_iter_cb cb, void *ctx);

/* default buckets visited per perf_scan call when count is unset */
#define PCACHE_SCAN_BUCKETS 100

/* cursor bit marking a position inside the overflow leg (low bits = the
 * overflow bucket); bucket cursors never carry it */
#define PCACHE_CURSOR_OVF 0x80000000u

/* Bounded walk from *@cursor (0 to start) over up to @max_buckets buckets,
 * then the overflow leg; *@cursor = where to resume, 0 when done.  Stable
 * across a resize.  0, or <0 on error / callback stop. */
int pcache_ht_scan(pcache_htable_t *ht, unsigned int *cursor,
		unsigned int max_buckets, pcache_iter_cb cb, void *ctx);

/* called per reaped record after the bucket lock is released; @key is
 * valid only during the call */
typedef void (*pcache_expired_cb)(const str *key, void *ctx);

/* expiry sweep over buckets whose hint is due, plus the overflow leg;
 * cells go to the global pool.  Returns the number of records reaped */
unsigned int pcache_ht_sweep(pcache_htable_t *ht, unsigned int now,
		pcache_expired_cb cb, void *cb_ctx);

/* linear-hash growth: split up to @budget buckets while the load factor
 * exceeds @target_lf.  Single caller only. */
unsigned int pcache_ht_grow(pcache_htable_t *ht, unsigned int target_lf,
		unsigned int budget);

/* modparam-triggered startup selftest; -1 on any mismatch */
int pcache_htable_selftest(void);

#endif /* _PCACHE_HTABLE_H_ */
