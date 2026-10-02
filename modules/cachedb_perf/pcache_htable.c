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

/*
 * The table core: 64-byte buckets with 1-byte tags, lock-free optimistic
 * reads under a per-bucket seqlock, writers under the bucket lock.
 *
 *  - readers copy out inside the optimistic section and trust nothing until
 *    the version re-check; every length is clamped and every pointer
 *    extent-checked before use
 *  - a byte-identical set() that only refreshes the TTL is one atomic
 *    expires store under the lock, with no version bump
 *  - no allocation or free while holding a bucket lock
 *  - on a miss readers re-read the routing word (a split may have moved the
 *    key); writers re-verify routing after lock_get
 *  - full buckets overflow into a chained side table behind one lock, gated
 *    by ovf_count; a key lives in its bucket or in overflow, never both
 */

#include <string.h>

#include "../../dprint.h"
#include "../../hash_func.h"
#include "../../locking.h"
#include "../../pt.h"
#include "../../timer.h"
#include "../../mem/mem.h"

#include "pcache_arena.h"
#include "pcache_htable.h"

/*
 * MurmurHash3 x86_32 (public domain, Austin Appleby).  The core hash adds
 * per-word mixes, so numeric keys collide heavily.  Local to this node,
 * never on the wire.
 */
unsigned int pcache_key_hash(const str *key)
{
	const unsigned char *p = (const unsigned char *)key->s;
	unsigned int len = (unsigned int)key->len, n = len >> 2, i, k;
	unsigned int h = 0x9747b28cU;          /* the seed */

	for (i = 0; i < n; i++, p += 4) {
		memcpy(&k, p, 4);
		k *= 0xcc9e2d51U; k = (k << 15) | (k >> 17); k *= 0x1b873593U;
		h ^= k; h = (h << 13) | (h >> 19); h = h * 5 + 0xe6546b64U;
	}
	k = 0;
	switch (len & 3) {
	case 3: k ^= (unsigned int)p[2] << 16;   /* fall through */
	case 2: k ^= (unsigned int)p[1] << 8;    /* fall through */
	case 1: k ^= p[0];
		k *= 0xcc9e2d51U; k = (k << 15) | (k >> 17); k *= 0x1b873593U;
		h ^= k;
	}
	h ^= len;
	h ^= h >> 16; h *= 0x85ebca6bU; h ^= h >> 13; h *= 0xc2b2ae35U; h ^= h >> 16;
	return h;
}

/* set only by the selftest, pre-fork, to log its deliberate rejections at
 * debug level */
static int st_expect_reject;

#define PCACHE_REJECT_LOG(...) \
	do { \
		if (st_expect_reject) \
			LM_DBG(__VA_ARGS__); \
		else \
			LM_ERR(__VA_ARGS__); \
	} while (0)


#if defined(__x86_64__) || defined(__i386__)
#define pcache_pause() __builtin_ia32_pause()
#else
#define pcache_pause() do {} while (0)
#endif

struct povf {
	/* byte 0 is the arena class id and must never be overwritten */
	unsigned char cls_reserved;
	struct povf *next;
	pcache_rec_t *rec;
	unsigned int hash;
};

static inline unsigned char tag_of(unsigned int h)
{
	unsigned char t = (unsigned char)(h >> 24);

	return t ? t : 1;    /* never t|1 - that halves the tag alphabet */
}

static inline unsigned int route_idx(pcache_htable_t *ht, unsigned int h,
		uint64_t *route_out)
{
	/* acquire pairs with the release-publish in pcache_ht_split: seeing a
	 * new routing word implies the partner bucket's slots are visible */
	uint64_t r = __atomic_load_n(&ht->route, __ATOMIC_ACQUIRE);
	unsigned int level = (unsigned int)(r >> 32);
	unsigned int split = (unsigned int)r;
	unsigned int idx = h & ((1U << level) - 1);

	if (idx < split)
		idx = h & ((1U << (level + 1)) - 1);
	*route_out = r;
	return idx;
}

static inline pcache_bucket_t *bucket_at(pcache_htable_t *ht, unsigned int idx)
{
	return &ht->seg[idx >> PCACHE_SEG_BITS][idx & (PCACHE_SEG_SIZE - 1)];
}

static inline unsigned int *hint_at(pcache_htable_t *ht, unsigned int idx)
{
	return &ht->hint_seg[idx >> PCACHE_SEG_BITS][idx & (PCACHE_SEG_SIZE - 1)];
}

/* under the bucket lock; only a LOWER expiry writes (TTL bumps raise) */
static inline void hint_update(pcache_htable_t *ht, unsigned int idx,
		unsigned int exp)
{
	unsigned int *h = hint_at(ht, idx);

	if (exp && (!*h || exp < *h))
		*h = exp;
}

/* plain increments on the calling process's own cache line */
#define HT_ST(_ht, _f) \
	do { \
		if ((unsigned int)process_no < (_ht)->pstats_n) \
			(_ht)->pstats[process_no]._f++; \
	} while (0)

#define HT_ST_ADD(_ht, _f, _n) \
	do { \
		if ((unsigned int)process_no < (_ht)->pstats_n) \
			(_ht)->pstats[process_no]._f += (_n); \
	} while (0)

/* one 8-byte load of tags[6]+meta; 0x80 at byte i = tags[i] matches.
 * The SWAR borrow can produce a false positive after a true match byte -
 * filtered by the key compare, never a false negative. */
static inline uint64_t tag_matches(const pcache_bucket_t *b,
		unsigned char tag)
{
	/* uint64_t: unsigned long is 4 bytes on ILP32 */
	uint64_t w, x;

	memcpy(&w, b->tags, 8);
	x = w ^ (0x0101010101010101ULL * tag);
	return (x - 0x0101010101010101ULL) & ~x & 0x0000808080808080ULL;
}

/* equality of @n bytes, reading exactly those bytes, so it is as safe as
 * memcmp() inside an optimistic section.  Not memcmp(): with the
 * -minline-all-stringops OpenSIPS builds with, gcc inlines it as
 * "repz cmpsb", which costs about a nanosecond per byte */
static inline int pcache_mem_eq(const void *a, const void *b, unsigned int n)
{
	const unsigned char *p = a, *q = b;
	uint64_t x, y;

	for (; n >= 8; n -= 8, p += 8, q += 8) {
		memcpy(&x, p, 8);
		memcpy(&y, q, 8);
		if (x != y)
			return 0;
	}
	for (; n; n--)
		if (*p++ != *q++)
			return 0;
	return 1;
}

/* meta helpers - writers only, under the bucket lock */
static inline unsigned int bkt_used(const pcache_bucket_t *b)
{
	return b->meta & 0xF;
}

static inline void bkt_set_used(pcache_bucket_t *b, unsigned int used)
{
	b->meta = (b->meta & ~0xF) | used;
}

static inline void bkt_set_owner(pcache_bucket_t *b)
{
	b->meta = (b->meta & 0xF) |
		(unsigned short)(((process_no + 1) & 0xFFF) << 4);
}

static inline void bkt_clear_owner(pcache_bucket_t *b)
{
	b->meta &= 0xF;
}

/* per-process copy-out scratch */
static char *pcache_scratch;

static char *get_scratch(void)
{
	if (!pcache_scratch)
		pcache_scratch = pkg_malloc(PCACHE_CELL_MAX);
	if (!pcache_scratch)
		LM_ERR("no more pkg memory for the copy-out scratch\n");
	return pcache_scratch;
}

/*
 * Scan @b for @key under presumed-stable state: bounded reads only, so it
 * is safe both inside an optimistic section (result trusted only after
 * the version re-check) and under the bucket lock.
 * 0 = hit (scratch filled), -2 = miss.
 */
static int scan_bucket(pcache_bucket_t *b, const str *key, unsigned int hash,
		unsigned char tag, char *dst, unsigned int dstlen,
		unsigned int *vlen_out, unsigned int *exp_out,
		unsigned char *fl_out)
{
	/* full 64-bit match word: a 32-bit one drops slots 4 and 5 on ILP32 */
	uint64_t m;
	unsigned long lo, hi;
	unsigned int bound, vlen, klen, avail;
	pcache_rec_t *r;
	int i;

	pcache_arena_extents(&lo, &hi);

	for (m = tag_matches(b, tag); m; m &= m - 1) {
		i = __builtin_ctzll(m) >> 3;
		r = b->slot[i];
		if (!r)
			continue;

		/* validate before every use: a stale pointer fails one of
		 * these or the caller's version re-check */
		if ((unsigned long)r < lo ||
		        (unsigned long)r + PCACHE_REC_HDR > hi)
			continue;
		bound = pcache_cell_bound(r);
		if (!bound || (unsigned long)r + bound > hi)
			continue;
		if (r->hash != hash)
			continue;
		klen = r->klen;
		if (klen != (unsigned int)key->len ||
		        PCACHE_REC_HDR + klen > bound)
			continue;
		if (!pcache_mem_eq(r->data, key->s, klen))
			continue;

		vlen = r->vlen;                       /* aligned 4-byte load */
		/* subtractive: HDR + klen + vlen could wrap for a torn vlen */
		avail = bound - PCACHE_REC_HDR - klen;
		if (vlen > avail)
			vlen = avail;
		/* report the length even if the buffer is too small */
		*vlen_out = vlen;
		*exp_out = r->expires;
		*fl_out = r->rflags;
		/* probe: metadata only, no copy */
		if (!dst)
			return 0;
		if (vlen > dstlen)
			return PCACHE_E_TOOSMALL;   /* nothing copied */
		memcpy(dst, r->data + klen, vlen);
		return 0;
	}
	return -2;
}

/* overflow lookup - records are stable under the overflow lock */
static int ovf_fetch(pcache_htable_t *ht, const str *key, unsigned int hash,
		char *dst, unsigned int dstlen, unsigned int *vlen_out,
		unsigned int *exp_out, unsigned char *fl_out)
{
	struct povf *n;
	int rc = -2;

	lock_get(&ht->ovf_lock);
	for (n = ht->ovf_tab[hash & (PCACHE_OVF_BUCKETS - 1)]; n; n = n->next) {
		if (n->hash != hash || n->rec->klen != key->len ||
		        !pcache_mem_eq(n->rec->data, key->s, key->len))
			continue;
		*vlen_out = n->rec->vlen;
		*exp_out = n->rec->expires;
		*fl_out = n->rec->rflags;
		/* probe: metadata only, no copy */
		if (!dst) {
			rc = 0;
			break;
		}
		if (*vlen_out > dstlen) {
			rc = PCACHE_E_TOOSMALL;     /* nothing copied */
			break;
		}
		memcpy(dst, n->rec->data + key->len, *vlen_out);
		rc = 0;
		break;
	}
	lock_release(&ht->ovf_lock);
	return rc;
}

/*
 * The single read path behind every fetch and the probe.  @dst NULL with
 * @dstlen 0 is a probe.  @now is a parameter so the selftest can run on a
 * synthetic clock.  Returns 1 for a native counter hit (value in *ll_out).
 */
static int _pcache_ht_fetch_buf(pcache_htable_t *ht, const str *key,
		char *dst, unsigned int dstlen, unsigned int *vlen_out,
		unsigned int now, unsigned int *exp_out, long long *ll_out,
		unsigned char *fl_out)
{
	pcache_bucket_t *b;
	uint64_t route;
	unsigned int hash, idx, v1, v2, vlen = 0, exp = 0, tries;
	unsigned char tag, fl = 0;
	long long ll;
	int rc;

	*vlen_out = 0;
	if (ll_out)
		*ll_out = 0;
	if (exp_out)
		*exp_out = 0;

	if (!ht || !key || (!dst && dstlen))
		return -1;

	hash = pcache_key_hash(key);
	tag = tag_of(hash);

again:
	idx = route_idx(ht, hash, &route);
	b = bucket_at(ht, idx);

	rc = -2;
	for (tries = 0; tries < PCACHE_SEQ_RETRIES; tries++) {
		v1 = __atomic_load_n(&b->version, __ATOMIC_ACQUIRE);
		if (v1 & 1) {
			pcache_pause();
			continue;
		}
		rc = scan_bucket(b, key, hash, tag, dst, dstlen, &vlen, &exp, &fl);
		__atomic_thread_fence(__ATOMIC_ACQUIRE);
		v2 = __atomic_load_n(&b->version, __ATOMIC_RELAXED);
		if (v1 == v2)
			goto settled;
	}

	/* a writer is stalled mid-update: stop spinning, wait on the lock */
	lock_get(&b->lock);
	bkt_set_owner(b);
	rc = scan_bucket(b, key, hash, tag, dst, dstlen, &vlen, &exp, &fl);
	bkt_clear_owner(b);
	lock_release(&b->lock);
	HT_ST(ht, fallbacks);

settled:
	if (tries)
		HT_ST_ADD(ht, retries, tries);
	if (rc == -2) {
		/* a completed split may have re-routed the key */
		if (ht->route != route)
			goto again;
		if (ht->ovf_count)
			rc = ovf_fetch(ht, key, hash, dst, dstlen, &vlen, &exp, &fl);
	}
	if (rc == -2) {
		HT_ST(ht, misses);
		return -2;
	}

	if (exp && exp <= now) {
		HT_ST(ht, misses);
		return -2;                    /* expired reads as absent */
	}
	HT_ST(ht, hits);
	if (exp_out)
		*exp_out = exp;                  /* absolute ticks, 0 = never */
	if (fl_out)
		*fl_out = fl;                    /* record flags, e.g. F_PASSIVE */
	*vlen_out = vlen;

	if (rc == PCACHE_E_TOOSMALL)
		return PCACHE_E_TOOSMALL;

	if ((fl & PCACHE_F_INT) && vlen == 8) {
		/* native counter: hand back the integer for the entry point to
		 * format; a probe copied nothing */
		if (!dst)
			return 1;
		if (!ll_out)
			return -1;
		memcpy(&ll, dst, 8);
		*ll_out = ll;
		return 1;                        /* hit, and it is a counter */
	}
	return 0;
}

/* copies into the per-process scratch, then into a pkg buffer the caller
 * owns; the scratch fits any record, so TOOSMALL cannot happen here */
static int _pcache_ht_fetch(pcache_htable_t *ht, const str *key, str *val,
		unsigned int now, unsigned int *exp_out, unsigned char *fl_out)
{
	unsigned int vlen = 0;
	long long ll = 0;
	char *scratch;
	int rc;

	scratch = get_scratch();
	if (!scratch)
		return -1;

	rc = _pcache_ht_fetch_buf(ht, key, scratch, PCACHE_CELL_MAX, &vlen,
		now, exp_out, &ll, fl_out);
	if (rc < 0)
		return rc == PCACHE_E_TOOSMALL ? -1 : rc;

	if (rc == 1) {                       /* native counter: format on read */
		val->s = pkg_malloc(24);
		if (!val->s) {
			LM_ERR("no more pkg memory\n");
			return -1;
		}
		val->len = snprintf(val->s, 24, "%lld", ll);
		return 0;
	}

	val->s = pkg_malloc(vlen ? vlen : 1);
	if (!val->s) {
		LM_ERR("no more pkg memory for a %u byte value\n", vlen);
		return -1;
	}
	memcpy(val->s, scratch, vlen);
	val->len = vlen;
	return 0;
}

int pcache_ht_fetch(pcache_htable_t *ht, const str *key, str *val)
{
	return _pcache_ht_fetch(ht, key, val, get_ticks(), NULL, NULL);
}

int pcache_ht_fetch_ex(pcache_htable_t *ht, const str *key, str *val,
		unsigned int *expires, unsigned char *rflags)
{
	if (rflags)
		*rflags = 0;
	return _pcache_ht_fetch(ht, key, val, get_ticks(), expires, rflags);
}

int pcache_ht_probe(pcache_htable_t *ht, const str *key, unsigned int *vlen,
		unsigned int *expires, int *is_counter)
{
	unsigned int len = 0, exp = 0;
	int rc;

	if (vlen)
		*vlen = 0;
	if (expires)
		*expires = 0;
	if (is_counter)
		*is_counter = 0;

	rc = _pcache_ht_fetch_buf(ht, key, NULL, 0, &len, get_ticks(),
		&exp, NULL, NULL);
	if (rc < 0)
		return rc;                 /* -2 = absent or expired */
	if (vlen)
		*vlen = len;
	if (expires)
		*expires = exp;
	if (is_counter)
		*is_counter = (rc == 1);
	return 0;
}

int pcache_ht_fetch_buf(pcache_htable_t *ht, const str *key, char *buf,
		unsigned int buflen, unsigned int *vlen, unsigned int *needed)
{
	long long ll = 0;
	int rc;

	if (vlen)
		*vlen = 0;
	if (needed)
		*needed = 0;
	if (!vlen || !buf || buflen < PCACHE_GETBUF_MIN) {
		LM_BUG("get_buf called with buf=%p buflen=%u vlen=%p\n",
			buf, buflen, vlen);
		return -1;
	}

	rc = _pcache_ht_fetch_buf(ht, key, buf, buflen, vlen, get_ticks(),
		NULL, &ll, NULL);

	if (rc == PCACHE_E_TOOSMALL) {
		/* {buf, *vlen} must stay a valid str */
		if (needed)
			*needed = *vlen;
		*vlen = 0;
		return PCACHE_E_TOOSMALL;
	}
	if (rc < 0)
		return rc;
	if (rc == 1)                         /* counter: always fits */
		*vlen = snprintf(buf, buflen, "%lld", ll);
	return 0;
}

/* writer-side slot scan, under the bucket lock - plain and exact */
static int find_slot(pcache_bucket_t *b, const str *key, unsigned int hash,
		unsigned char tag)
{
	pcache_rec_t *r;
	unsigned int used = bkt_used(b), i;

	for (i = 0; i < used; i++) {
		r = b->slot[i];
		if (b->tags[i] == tag && r && r->hash == hash &&
		        r->klen == key->len &&
		        pcache_mem_eq(r->data, key->s, key->len))
			return (int)i;
	}
	return -1;
}

/* overflow search, under the overflow lock */
static struct povf *ovf_find(pcache_htable_t *ht, const str *key,
		unsigned int hash, struct povf ***prev_out)
{
	struct povf **prev = &ht->ovf_tab[hash & (PCACHE_OVF_BUCKETS - 1)], *n;

	for (n = *prev; n; prev = &n->next, n = n->next)
		if (n->hash == hash && n->rec->klen == key->len &&
		        pcache_mem_eq(n->rec->data, key->s, key->len))
			break;
	if (prev_out)
		*prev_out = prev;
	return n;
}

int pcache_ht_store(pcache_htable_t *ht, const str *key, const str *val,
		unsigned int expires)
{
	return pcache_ht_store_ex(ht, key, val, expires, 0);
}

static pcache_rec_t *rec_build(const str *key, const str *val,
		unsigned int expires, unsigned int hash, unsigned char rflags)
{
	pcache_rec_t *r = pcache_cell_alloc(PCACHE_REC_SIZE(key->len, val->len));

	if (r) {
		r->rflags = rflags;
		r->klen = (unsigned short)key->len;
		r->vlen = (unsigned int)val->len;
		r->expires = expires;
		r->hash = hash;
		memcpy(r->data, key->s, key->len);
		memcpy(r->data + key->len, val->s, val->len);
	}
	return r;
}

/* the identical-bytes TTL-bump path keeps the record's existing flags, so
 * re-pulling the owner's bytes does not demote its copy */
int pcache_ht_store_ex(pcache_htable_t *ht, const str *key, const str *val,
		unsigned int expires, unsigned char rflags)
{
	pcache_bucket_t *b;
	pcache_rec_t *nr = NULL, *old = NULL;
	struct povf *node = NULL, *on;
	uint64_t route;
	unsigned int hash, idx, used;
	unsigned char tag;
	int i, inserted = 0, built = 0;

	if (key->len > 0xFFFF ||
	        PCACHE_REC_SIZE(key->len, val->len) > PCACHE_CELL_MAX) {
		PCACHE_REJECT_LOG("key %d + value %d bytes exceed the %d byte record limit\n",
			key->len, val->len, PCACHE_CELL_MAX);
		return -1;
	}

	hash = pcache_key_hash(key);
	tag = tag_of(hash);

again:
	idx = route_idx(ht, hash, &route);
	b = bucket_at(ht, idx);

	/* A new record is built outside the lock, and only when a path will
	 * publish it: the TTL-bump and in-place overwrites need none.  No tag
	 * match in the bucket predicts an insert, so build it now; a wrong
	 * guess either way costs one retry, never a wrong result */
	if (!built && !tag_matches(b, tag)) {
		nr = rec_build(key, val, expires, hash, rflags);
		built = 1;
	}

	lock_get(&b->lock);
	bkt_set_owner(b);

	/* routing may have moved while we waited */
	if (ht->route != route) {
		bkt_clear_owner(b);
		lock_release(&b->lock);
		goto again;
	}

	i = find_slot(b, key, hash, tag);
	if (i >= 0) {
		old = b->slot[i];

		if (old->vlen == (unsigned int)val->len &&
		        pcache_mem_eq(old->data + key->len, val->s, val->len)) {
			/* versionless TTL bump: one aligned store readers cannot
			 * tear */
			__atomic_store_n(&old->expires, expires, __ATOMIC_RELAXED);
			hint_update(ht, idx, expires);
			old = nr;                     /* discard the prebuilt one */
			goto done;
		}

		if (PCACHE_REC_SIZE(key->len, val->len) <= pcache_cell_bound(old)) {
			/* in-place.  Seqlock entry bumps are ACQ_REL, not RELEASE:
			 * on weakly-ordered CPUs a release RMW lets the payload
			 * stores that follow become visible before the version
			 * turns odd.  Exit bumps use ACQ_REL too, for uniformity. */
			__atomic_add_fetch(&b->version, 1, __ATOMIC_ACQ_REL);
			/* reset flags, or an 8-byte string over a counter would
			 * still read as PCACHE_F_INT */
			old->rflags = rflags;
			old->vlen = (unsigned int)val->len;
			memcpy(old->data + key->len, val->s, val->len);
			old->expires = expires;
			__atomic_add_fetch(&b->version, 1, __ATOMIC_ACQ_REL);
			hint_update(ht, idx, expires);
			old = nr;                     /* discard the prebuilt one */
			goto done;
		}

		/* replace the record; the tag stays (same key, same hash) */
		if (!nr)
			goto need_rec;
		__atomic_add_fetch(&b->version, 1, __ATOMIC_ACQ_REL);
		b->slot[i] = nr;
		__atomic_add_fetch(&b->version, 1, __ATOMIC_ACQ_REL);
		hint_update(ht, idx, expires);
		goto done;
	}

	/* not in the bucket - it may sit in overflow */
	if (ht->ovf_count) {
		lock_get(&ht->ovf_lock);
		on = ovf_find(ht, key, hash, NULL);
		if (on && !nr) {
			lock_release(&ht->ovf_lock);
			goto need_rec;
		}
		if (on) {
			old = on->rec;
			on->rec = nr;         /* overflow readers are lock-serialized */
			lock_release(&ht->ovf_lock);
			goto done;
		}
		lock_release(&ht->ovf_lock);
	}

	if (!nr)
		goto need_rec;                /* an insert needs a cell of its own */
	used = bkt_used(b);
	if (used < PCACHE_SLOTS) {
		__atomic_add_fetch(&b->version, 1, __ATOMIC_ACQ_REL);
		b->slot[used] = nr;
		b->tags[used] = tag;
		bkt_set_used(b, used + 1);
		__atomic_add_fetch(&b->version, 1, __ATOMIC_ACQ_REL);
		hint_update(ht, idx, expires);
		inserted = 1;
		goto done;
	}

	/* bucket full -> overflow.  No allocation under the bucket lock: drop
	 * it, allocate the chain node, retry */
	if (!node) {
		bkt_clear_owner(b);
		lock_release(&b->lock);
		node = pcache_cell_alloc(sizeof *node);
		if (!node) {
			pcache_cell_free(nr);
			return -2;                    /* arena full - write dropped */
		}
		goto again;
	}

	lock_get(&ht->ovf_lock);
	node->rec = nr;
	node->hash = hash;
	node->next = ht->ovf_tab[hash & (PCACHE_OVF_BUCKETS - 1)];
	ht->ovf_tab[hash & (PCACHE_OVF_BUCKETS - 1)] = node;
	__atomic_add_fetch(&ht->ovf_count, 1, __ATOMIC_RELAXED);
	lock_release(&ht->ovf_lock);
	node = NULL;
	inserted = 1;

done:
	bkt_clear_owner(b);
	lock_release(&b->lock);

	/* frees strictly after the locks */
	if (old)
		pcache_cell_free(old);
	if (node)
		pcache_cell_free(node);
	HT_ST(ht, stores);
	if (!expires)
		HT_ST(ht, stores_immortal);
	if (inserted)
		HT_ST(ht, created);
	return 0;

need_rec:
	/* a publishing path without a record: build one outside the lock and
	 * retry, unless the arena already refused it */
	if (!built) {
		bkt_clear_owner(b);
		lock_release(&b->lock);
		nr = rec_build(key, val, expires, hash, rflags);
		built = 1;
		goto again;
	}
	bkt_clear_owner(b);
	lock_release(&b->lock);
	if (node)
		pcache_cell_free(node);
	return -2;                            /* arena full - write dropped */
}

int pcache_ht_add(pcache_htable_t *ht, const str *key, long long delta,
		unsigned int expires, long long *new_val)
{
	pcache_bucket_t *b;
	pcache_rec_t *nr, *r, *old = NULL;
	struct povf *node = NULL, *on;
	uint64_t route;
	unsigned int hash, idx, used;
	unsigned char tag;
	long long cur;
	int i, inserted = 0;

	if (key->len > 0xFFFF)
		return -1;

	hash = pcache_key_hash(key);
	tag = tag_of(hash);

	/* pre-built outside any lock; becomes the entry or is freed */
	nr = pcache_cell_alloc(PCACHE_REC_SIZE(key->len, 8));
	if (!nr)
		return -1;
	nr->rflags = PCACHE_F_INT;
	nr->klen = (unsigned short)key->len;
	nr->vlen = 8;
	nr->expires = expires;
	nr->hash = hash;
	memcpy(nr->data, key->s, key->len);
	memcpy(nr->data + key->len, &delta, 8);
	cur = delta;

again:
	idx = route_idx(ht, hash, &route);
	b = bucket_at(ht, idx);

	lock_get(&b->lock);
	bkt_set_owner(b);

	if (ht->route != route) {
		bkt_clear_owner(b);
		lock_release(&b->lock);
		goto again;
	}

	i = find_slot(b, key, hash, tag);
	if (i >= 0) {
		r = b->slot[i];
		if (r->rflags & PCACHE_F_INT) {
			/* the payload may be unaligned, so it changes under the
			 * version */
			memcpy(&cur, r->data + r->klen, 8);
			cur += delta;
			__atomic_add_fetch(&b->version, 1, __ATOMIC_ACQ_REL);
			memcpy(r->data + r->klen, &cur, 8);
			r->expires = expires;
			__atomic_add_fetch(&b->version, 1, __ATOMIC_ACQ_REL);
			hint_update(ht, idx, expires);
			old = nr;
			goto done;
		}
		/* string record: convert on first touch if numeric */
		if (pcache_str2ll(r->data + r->klen, r->vlen, &cur) < 0)
			goto nan;
		cur += delta;
		memcpy(nr->data + key->len, &cur, 8);
		__atomic_add_fetch(&b->version, 1, __ATOMIC_ACQ_REL);
		b->slot[i] = nr;
		__atomic_add_fetch(&b->version, 1, __ATOMIC_ACQ_REL);
		hint_update(ht, idx, expires);
		old = r;
		goto done;
	}

	if (ht->ovf_count) {
		lock_get(&ht->ovf_lock);
		on = ovf_find(ht, key, hash, NULL);
		if (on) {
			r = on->rec;
			if (r->rflags & PCACHE_F_INT) {
				memcpy(&cur, r->data + r->klen, 8);
				cur += delta;
				memcpy(r->data + r->klen, &cur, 8);
				r->expires = expires;
				lock_release(&ht->ovf_lock);
				old = nr;
				goto done;
			}
			if (pcache_str2ll(r->data + r->klen, r->vlen, &cur) < 0) {
				lock_release(&ht->ovf_lock);
				goto nan;
			}
			cur += delta;
			memcpy(nr->data + key->len, &cur, 8);
			on->rec = nr;
			lock_release(&ht->ovf_lock);
			old = r;
			goto done;
		}
		lock_release(&ht->ovf_lock);
	}

	/* absent: nr already carries the delta as the initial value */
	used = bkt_used(b);
	if (used < PCACHE_SLOTS) {
		__atomic_add_fetch(&b->version, 1, __ATOMIC_ACQ_REL);
		b->slot[used] = nr;
		b->tags[used] = tag;
		bkt_set_used(b, used + 1);
		__atomic_add_fetch(&b->version, 1, __ATOMIC_ACQ_REL);
		hint_update(ht, idx, expires);
		inserted = 1;
		goto done;
	}

	if (!node) {
		bkt_clear_owner(b);
		lock_release(&b->lock);
		node = pcache_cell_alloc(sizeof *node);
		if (!node) {
			pcache_cell_free(nr);
			return -1;
		}
		goto again;
	}

	lock_get(&ht->ovf_lock);
	node->rec = nr;
	node->hash = hash;
	node->next = ht->ovf_tab[hash & (PCACHE_OVF_BUCKETS - 1)];
	ht->ovf_tab[hash & (PCACHE_OVF_BUCKETS - 1)] = node;
	__atomic_add_fetch(&ht->ovf_count, 1, __ATOMIC_RELAXED);
	lock_release(&ht->ovf_lock);
	node = NULL;
	inserted = 1;

done:
	bkt_clear_owner(b);
	lock_release(&b->lock);

	if (old)
		pcache_cell_free(old);
	if (node)
		pcache_cell_free(node);
	HT_ST(ht, stores);
	if (!expires)
		HT_ST(ht, stores_immortal);
	if (inserted)
		HT_ST(ht, created);
	if (new_val)
		*new_val = cur;
	return 0;

nan:
	bkt_clear_owner(b);
	lock_release(&b->lock);
	PCACHE_REJECT_LOG("value of <%.*s> is not an integer\n", key->len, key->s);
	pcache_cell_free(nr);
	if (node)
		pcache_cell_free(node);
	return -1;
}

/* versionless TTL bump: one aligned store of expires under the bucket
 * lock, which a lock-free reader sees whole or not at all */
int pcache_ht_touch(pcache_htable_t *ht, const str *key, unsigned int expires)
{
	pcache_bucket_t *b;
	pcache_rec_t *r;
	struct povf *on;
	uint64_t route;
	unsigned int hash, idx;
	unsigned char tag;
	int i, rc = 0;

	hash = pcache_key_hash(key);
	tag = tag_of(hash);

again:
	idx = route_idx(ht, hash, &route);
	b = bucket_at(ht, idx);

	lock_get(&b->lock);
	bkt_set_owner(b);
	if (ht->route != route) {              /* re-routed while waiting */
		bkt_clear_owner(b);
		lock_release(&b->lock);
		goto again;
	}

	i = find_slot(b, key, hash, tag);
	if (i >= 0) {
		r = b->slot[i];
		__atomic_store_n(&r->expires, expires, __ATOMIC_RELAXED);
		hint_update(ht, idx, expires);
		rc = 1;
	}
	bkt_clear_owner(b);
	lock_release(&b->lock);

	if (rc)
		return 1;

	/* a bucket miss may mean a completed split re-routed the key */
	if (ht->route != route)
		goto again;

	/* else it may sit in overflow */
	if (ht->ovf_count) {
		lock_get(&ht->ovf_lock);
		on = ovf_find(ht, key, hash, NULL);
		if (on) {
			on->rec->expires = expires;
			rc = 1;
		}
		lock_release(&ht->ovf_lock);
	}
	return rc;
}

int pcache_ht_remove(pcache_htable_t *ht, const str *key)
{
	pcache_bucket_t *b;
	pcache_rec_t *dead = NULL;
	struct povf *on = NULL, **prev;
	uint64_t route;
	unsigned int hash, idx, used;
	unsigned char tag;
	int i;

	hash = pcache_key_hash(key);
	tag = tag_of(hash);

again:
	idx = route_idx(ht, hash, &route);
	b = bucket_at(ht, idx);

	lock_get(&b->lock);
	bkt_set_owner(b);

	if (ht->route != route) {
		bkt_clear_owner(b);
		lock_release(&b->lock);
		goto again;
	}

	i = find_slot(b, key, hash, tag);
	if (i >= 0) {
		dead = b->slot[i];
		used = bkt_used(b);
		__atomic_add_fetch(&b->version, 1, __ATOMIC_ACQ_REL);
		b->slot[i] = b->slot[used - 1];       /* compact: readers retry */
		b->tags[i] = b->tags[used - 1];
		b->slot[used - 1] = NULL;
		b->tags[used - 1] = 0;
		bkt_set_used(b, used - 1);
		__atomic_add_fetch(&b->version, 1, __ATOMIC_ACQ_REL);
	} else if (ht->ovf_count) {
		lock_get(&ht->ovf_lock);
		on = ovf_find(ht, key, hash, &prev);
		if (on) {
			*prev = on->next;
			__atomic_sub_fetch(&ht->ovf_count, 1, __ATOMIC_RELAXED);
			dead = on->rec;
		}
		lock_release(&ht->ovf_lock);
	}

	bkt_clear_owner(b);
	lock_release(&b->lock);

	if (dead) {
		pcache_cell_free(dead);
		HT_ST(ht, removes);
		HT_ST(ht, destroyed);
	}
	if (on)
		pcache_cell_free(on);
	return dead ? 1 : 0;
}

/*
 * One optimistic snapshot of slot @i into @kbuf/@vbuf (each >=
 * PCACHE_CELL_MAX), with the copy-out clamps and the lock fallback.
 * 1 = a live record was captured, 0 = empty slot.
 */
static int snapshot_slot(pcache_bucket_t *b, unsigned int i,
		char *kbuf, char *vbuf, unsigned int *klen_o, unsigned int *vlen_o,
		unsigned int *exp_o, unsigned char *fl_o,
		unsigned long lo, unsigned long hi)
{
	pcache_rec_t *r;
	unsigned int v1, v2, tries, bound = 0, klen = 0, vlen = 0, exp = 0;
	unsigned char fl = 0;
	int have = 0;

	for (tries = 0; tries < PCACHE_SEQ_RETRIES; tries++) {
		v1 = __atomic_load_n(&b->version, __ATOMIC_ACQUIRE);
		if (v1 & 1) {
			pcache_pause();
			continue;
		}
		r = b->slot[i];
		/* copy-out checks, as in scan_bucket() */
		if (r && ((unsigned long)r < lo ||
		        (unsigned long)r + PCACHE_REC_HDR > hi))
			r = NULL;
		if (r) {
			bound = pcache_cell_bound(r);
			if (!bound || (unsigned long)r + bound > hi)
				r = NULL;
		}
		if (r) {
			klen = r->klen;
			if (PCACHE_REC_HDR + klen > bound)
				klen = bound - PCACHE_REC_HDR;
			vlen = r->vlen;
			if (PCACHE_REC_HDR + klen + vlen > bound)
				vlen = bound - PCACHE_REC_HDR - klen;  /* see scan_bucket */
			memcpy(kbuf, r->data, klen);
			memcpy(vbuf, r->data + klen, vlen);
			exp = r->expires;
			fl = r->rflags;
		}
		__atomic_thread_fence(__ATOMIC_ACQUIRE);
		v2 = __atomic_load_n(&b->version, __ATOMIC_RELAXED);
		if (v1 == v2) {
			have = r != NULL;
			break;
		}
	}
	if (tries == PCACHE_SEQ_RETRIES) {
		/* stalled writer: read this slot under the lock (record stable) */
		lock_get(&b->lock);
		bkt_set_owner(b);
		r = b->slot[i];
		if (r) {
			klen = r->klen;
			vlen = r->vlen;
			exp = r->expires;
			fl = r->rflags;
			memcpy(kbuf, r->data, klen);
			memcpy(vbuf, r->data + klen, vlen);
			have = 1;
		}
		bkt_clear_owner(b);
		lock_release(&b->lock);
	}
	if (!have)
		return 0;
	*klen_o = klen; *vlen_o = vlen; *exp_o = exp; *fl_o = fl;
	return 1;
}

/* format a snapshotted entry (counters as decimal), NUL-terminate and pass
 * it to the callback; returns the callback's rc */
static int emit_entry(pcache_iter_cb cb, void *ctx, char *kbuf,
		unsigned int klen, char *vbuf, unsigned int vlen,
		unsigned int exp, unsigned char fl)
{
	str key, val;
	long long ll;

	if ((fl & PCACHE_F_INT) && vlen == 8) {
		memcpy(&ll, vbuf, 8);
		vlen = snprintf(vbuf, 24, "%lld", ll);
	}
	kbuf[klen] = 0;
	vbuf[vlen] = 0;
	key.s = kbuf; key.len = klen;
	val.s = vbuf; val.len = vlen;
	return cb(&key, &val, exp, ctx);
}

/*
 * Walk the overflow leg from chain *@oidx; @budget > 0 stops after the chain
 * in which that many records were emitted, 0 walks to the end.  On return
 * *@oidx is the chain to resume at (PCACHE_OVF_BUCKETS = done).
 *
 * ovf_lock is dropped around every callback, so the callback may touch the
 * leg.  Chains are walked by index, re-resolved under the lock per entry;
 * if the node at the index changed during the callback it was removed and
 * the index does not advance.
 */
static int iter_overflow_from(pcache_htable_t *ht, pcache_iter_cb cb,
		void *ctx, char *kbuf, char *vbuf, unsigned int *oidx,
		unsigned int budget)
{
	pcache_rec_t *r;
	struct povf *n, *seen;
	unsigned int idx, i, j, klen, vlen, exp, emitted = 0;
	unsigned char fl;
	int rc = 0;

	if (!ht->ovf_count) {
		*oidx = PCACHE_OVF_BUCKETS;
		return 0;
	}
	for (idx = *oidx; idx < PCACHE_OVF_BUCKETS; idx++) {
		i = 0;
		for (;;) {
			lock_get(&ht->ovf_lock);
			n = ht->ovf_tab[idx];
			for (j = 0; n && j < i; j++)
				n = n->next;
			if (!n) {
				lock_release(&ht->ovf_lock);
				break;
			}
			r = n->rec;
			klen = r->klen;
			vlen = r->vlen;
			exp = r->expires;
			fl = r->rflags;
			memcpy(kbuf, r->data, klen);
			memcpy(vbuf, r->data + klen, vlen);
			seen = n;
			lock_release(&ht->ovf_lock);
			rc = emit_entry(cb, ctx, kbuf, klen, vbuf, vlen, exp, fl);
			if (rc < 0)
				break;
			emitted++;
			lock_get(&ht->ovf_lock);
			n = ht->ovf_tab[idx];
			for (j = 0; n && j < i; j++)
				n = n->next;
			lock_release(&ht->ovf_lock);
			if (n == seen)
				i++;
		}
		if (rc < 0)
			break;
		if (budget && emitted >= budget) {
			idx++;
			break;
		}
	}
	*oidx = idx;
	return rc;
}

static int iter_overflow(pcache_htable_t *ht, pcache_iter_cb cb, void *ctx,
		char *kbuf, char *vbuf)
{
	unsigned int oidx = 0;

	return iter_overflow_from(ht, cb, ctx, kbuf, vbuf, &oidx, 0);
}

int pcache_ht_iter(pcache_htable_t *ht, pcache_iter_cb cb, void *ctx)
{
	pcache_bucket_t *b;
	unsigned long lo, hi;
	unsigned int idx, i, klen, vlen, exp;
	unsigned char fl;
	char *kbuf, *vbuf;
	int rc = 0;

	kbuf = pkg_malloc(2 * PCACHE_CELL_MAX);
	if (!kbuf) {
		LM_ERR("no more pkg memory for the walk buffers\n");
		return -1;
	}
	vbuf = kbuf + PCACHE_CELL_MAX;

	pcache_arena_extents(&lo, &hi);

	for (idx = 0; idx < ht->nbuckets; idx++) {
		b = bucket_at(ht, idx);
		for (i = 0; i < PCACHE_SLOTS; i++) {
			if (!snapshot_slot(b, i, kbuf, vbuf, &klen, &vlen,
			        &exp, &fl, lo, hi))
				continue;
			rc = emit_entry(cb, ctx, kbuf, klen, vbuf, vlen, exp, fl);
			if (rc < 0)
				goto out;
		}
	}

	/* overflow leg; the lock is dropped around every callback */
	rc = iter_overflow(ht, cb, ctx, kbuf, vbuf);
out:
	pkg_free(kbuf);
	return rc < 0 ? rc : 0;
}

/* buckets never move and the table only grows, so an ascending cursor
 * stays valid across a concurrent resize */
int pcache_ht_scan(pcache_htable_t *ht, unsigned int *cursor,
		unsigned int max_buckets, pcache_iter_cb cb, void *ctx)
{
	pcache_bucket_t *b;
	unsigned long lo, hi;
	unsigned int idx, end, i, klen, vlen, exp, nb;
	unsigned char fl;
	char *kbuf, *vbuf;
	unsigned int oidx;
	int rc = 0;

	if (!max_buckets)
		max_buckets = PCACHE_SCAN_BUCKETS;

	kbuf = pkg_malloc(2 * PCACHE_CELL_MAX);
	if (!kbuf) {
		LM_ERR("no more pkg memory for the scan buffers\n");
		return -1;
	}
	vbuf = kbuf + PCACHE_CELL_MAX;
	pcache_arena_extents(&lo, &hi);

	nb = ht->nbuckets;
	idx = *cursor;
	if (idx & PCACHE_CURSOR_OVF) {  /* resuming inside the overflow leg */
		oidx = idx & ~PCACHE_CURSOR_OVF;
		goto leg;
	}
	end = (idx > nb || nb - idx < max_buckets) ? nb : idx + max_buckets;

	for (; idx < end; idx++) {
		b = bucket_at(ht, idx);
		for (i = 0; i < PCACHE_SLOTS; i++) {
			if (!snapshot_slot(b, i, kbuf, vbuf, &klen, &vlen,
			        &exp, &fl, lo, hi))
				continue;
			rc = emit_entry(cb, ctx, kbuf, klen, vbuf, vlen, exp, fl);
			if (rc < 0)
				goto out;
		}
	}

	if (idx < nb) {
		*cursor = idx;               /* more buckets remain */
		goto out;
	}
	/* the leg starts on the next call */
	*cursor = ht->ovf_count ? PCACHE_CURSOR_OVF : 0;
	goto out;
leg:
	/* the leg under the same budget, PCACHE_SLOTS records per bucket */
	rc = iter_overflow_from(ht, cb, ctx, kbuf, vbuf, &oidx,
		max_buckets * PCACHE_SLOTS);
	if (rc < 0)
		goto out;                    /* the cursor stands: retry smaller */
	*cursor = oidx < PCACHE_OVF_BUCKETS ? (PCACHE_CURSOR_OVF | oidx) : 0;
out:
	pkg_free(kbuf);
	return rc < 0 ? rc : 0;
}

unsigned int pcache_ht_nbuckets(pcache_htable_t *ht)
{
	return __atomic_load_n(&ht->nbuckets, __ATOMIC_RELAXED);
}

unsigned int pcache_ht_overflow(pcache_htable_t *ht)
{
	return __atomic_load_n(&ht->ovf_count, __ATOMIC_RELAXED);
}

unsigned int pcache_ht_sweep(pcache_htable_t *ht, unsigned int now,
		pcache_expired_cb cb, void *cb_ctx)
{
	pcache_bucket_t *b;
	pcache_rec_t *r, *dead[PCACHE_SLOTS];
	pcache_rec_t *batch_r[64];
	struct povf *n, **prev, *batch_n[64];
	unsigned int idx, i, used, hint, newmin, ndead, freed = 0;
	str dk;
	int bn;

	for (idx = 0; idx < ht->nbuckets; idx++) {
		hint = *hint_at(ht, idx);
		if (!hint || hint > now)
			continue;               /* 16 hints per line, no bucket touch */

		b = bucket_at(ht, idx);
		lock_get(&b->lock);
		bkt_set_owner(b);

		ndead = 0;
		newmin = 0;
		i = 0;
		while (i < (used = bkt_used(b))) {
			r = b->slot[i];
			if (r->expires && r->expires <= now) {
				if (!ndead)
					__atomic_add_fetch(&b->version, 1,
						__ATOMIC_ACQ_REL);
				dead[ndead++] = r;
				b->slot[i] = b->slot[used - 1];
				b->tags[i] = b->tags[used - 1];
				b->slot[used - 1] = NULL;
				b->tags[used - 1] = 0;
				bkt_set_used(b, used - 1);
				continue;           /* re-examine the swapped-in slot */
			}
			if (r->expires && (!newmin || r->expires < newmin))
				newmin = r->expires;
			i++;
		}
		if (ndead)
			__atomic_add_fetch(&b->version, 1, __ATOMIC_ACQ_REL);
		*hint_at(ht, idx) = newmin;

		bkt_clear_owner(b);
		lock_release(&b->lock);

		/* free after the lock, via the global pool: the sweeping
		 * process is not an allocator */
		for (i = 0; i < ndead; i++) {
			if (cb) {
				dk.s = dead[i]->data;
				dk.len = dead[i]->klen;
				cb(&dk, cb_ctx);          /* expiry event, unlocked */
			}
			pcache_cell_free_global(dead[i]);
		}
		freed += ndead;
	}

	if (!ht->ovf_count) {
		HT_ST_ADD(ht, destroyed, freed);
		HT_ST_ADD(ht, expired, freed);
		return freed;
	}

	/* overflow: unhinted, scanned whole - it exists to be small */
	for (idx = 0; idx < PCACHE_OVF_BUCKETS; idx++) {
		do {
			bn = 0;
			lock_get(&ht->ovf_lock);
			prev = &ht->ovf_tab[idx];
			for (n = *prev; n && bn < 64; ) {
				if (n->rec->expires && n->rec->expires <= now) {
					*prev = n->next;
					batch_n[bn] = n;
					batch_r[bn] = n->rec;
					bn++;
					__atomic_sub_fetch(&ht->ovf_count, 1,
						__ATOMIC_RELAXED);
					n = *prev;
				} else {
					prev = &n->next;
					n = n->next;
				}
			}
			lock_release(&ht->ovf_lock);
			for (i = 0; i < (unsigned int)bn; i++) {
				if (cb) {
					dk.s = batch_r[i]->data;
					dk.len = batch_r[i]->klen;
					cb(&dk, cb_ctx);      /* expiry event, unlocked */
				}
				pcache_cell_free_global(batch_r[i]);
				pcache_cell_free_global(batch_n[i]);
			}
			freed += bn;
		} while (bn == 64);
	}

	HT_ST_ADD(ht, destroyed, freed);
	HT_ST_ADD(ht, expired, freed);
	return freed;
}

void pcache_ht_totals(pcache_htable_t *ht, pcache_ht_totals_t *out)
{
	pcache_pstat_t *p;
	unsigned int i;

	memset(out, 0, sizeof *out);
	for (i = 0; i < ht->pstats_n; i++) {
		p = &ht->pstats[i];
		out->hits += p->hits;
		out->misses += p->misses;
		out->stores += p->stores;
		out->removes += p->removes;
		out->created += p->created;
		out->destroyed += p->destroyed;
		out->expired += p->expired;
		out->retries += p->retries;
		out->fallbacks += p->fallbacks;
		out->stores_immortal += p->stores_immortal;
	}
	/* live gauge: always absolute, never relative to a reset */
	out->entries = out->created - out->destroyed;

	/* everything else is a running total - report it since the last reset */
	out->hits      -= ht->base.hits;
	out->misses    -= ht->base.misses;
	out->stores    -= ht->base.stores;
	out->removes   -= ht->base.removes;
	out->created   -= ht->base.created;
	out->destroyed -= ht->base.destroyed;
	out->expired   -= ht->base.expired;
	out->retries   -= ht->base.retries;
	out->fallbacks -= ht->base.fallbacks;
	out->stores_immortal -= ht->base.stores_immortal;
}

void pcache_ht_stats_reset(pcache_htable_t *ht)
{
	pcache_ht_totals_t now;
	unsigned long entries;

	/* fold the current totals into the baseline; the shards are never
	 * rewound, so concurrent increments land in the next interval */
	pcache_ht_totals(ht, &now);
	entries = now.entries;

	ht->base.hits      += now.hits;
	ht->base.misses    += now.misses;
	ht->base.stores    += now.stores;
	ht->base.removes   += now.removes;
	ht->base.created   += now.created;
	ht->base.destroyed += now.destroyed;
	ht->base.expired   += now.expired;
	ht->base.retries   += now.retries;
	ht->base.fallbacks += now.fallbacks;
	ht->base.stores_immortal += now.stores_immortal;

	LM_INFO("statistics reset; %lu entries live\n", entries);
}

/*
 * Linear-hash growth.  There is a single splitter, so splits never race;
 * readers and writers re-check the routing word.  Existing buckets never
 * move.
 */

/* allocate the segment (and hint segment) holding bucket @idx if absent;
 * published with release once built, before any route reaches it */
static int ensure_segment(pcache_htable_t *ht, unsigned int idx)
{
	unsigned int s = idx >> PCACHE_SEG_BITS, i;
	pcache_bucket_t *seg;
	unsigned int *hseg;

	if (ht->seg[s])
		return 0;
	seg = pcache_region_alloc((unsigned long)PCACHE_SEG_SIZE * sizeof *seg);
	if (!seg)
		return -1;
	memset(seg, 0, (unsigned long)PCACHE_SEG_SIZE * sizeof *seg);
	for (i = 0; i < PCACHE_SEG_SIZE; i++)
		lock_init(&seg[i].lock);
	hseg = pcache_region_alloc(PCACHE_SEG_SIZE * sizeof(unsigned int));
	if (!hseg)
		return -1;
	memset(hseg, 0, PCACHE_SEG_SIZE * sizeof(unsigned int));
	ht->hint_seg[s] = hseg;
	__atomic_store_n(&ht->seg[s], seg, __ATOMIC_RELEASE);
	return 1;
}

/*
 * Split bucket `split` into itself and split + 2^level by bit `level` of
 * the stored hash.  Overflow is keyed by hash, not routing, so it is left
 * alone.  1 = split, 0 = at the ceiling, -1 = OOM.
 */
static int pcache_ht_split(pcache_htable_t *ht)
{
	uint64_t r = ht->route, nr;
	unsigned int level = (unsigned int)(r >> 32);
	unsigned int split = (unsigned int)r;
	unsigned int sidx = split, pidx = split + (1U << level);
	pcache_bucket_t *S, *P;
	unsigned int used, pused, i, smin = 0, pmin = 0;
	pcache_rec_t *rec;

	if (pidx >= PCACHE_NSEGS * PCACHE_SEG_SIZE)
		return 0;                          /* at the 2^24 ceiling */
	if (ensure_segment(ht, pidx) < 0)
		return -1;

	S = bucket_at(ht, sidx);
	P = bucket_at(ht, pidx);               /* fresh, zeroed, unreachable */

	lock_get(&S->lock);
	bkt_set_owner(S);
	__atomic_add_fetch(&S->version, 1, __ATOMIC_ACQ_REL);  /* writer in */

	used = bkt_used(S);
	pused = 0;
	i = 0;
	while (i < used) {
		rec = S->slot[i];
		if ((rec->hash >> level) & 1) {            /* -> partner */
			P->slot[pused] = rec;
			P->tags[pused] = S->tags[i];
			pused++;
			S->slot[i] = S->slot[used - 1];
			S->tags[i] = S->tags[used - 1];
			S->slot[used - 1] = NULL;
			S->tags[used - 1] = 0;
			used--;
		} else {
			i++;
		}
	}
	bkt_set_used(S, used);
	bkt_set_used(P, pused);

	/* recompute both expiry hints (moved entries left S) */
	for (i = 0; i < used; i++)
		if (S->slot[i]->expires && (!smin || S->slot[i]->expires < smin))
			smin = S->slot[i]->expires;
	for (i = 0; i < pused; i++)
		if (P->slot[i]->expires && (!pmin || P->slot[i]->expires < pmin))
			pmin = P->slot[i]->expires;
	*hint_at(ht, sidx) = smin;
	*hint_at(ht, pidx) = pmin;

	/* publish the route while S is odd: a reader that later sees S even
	 * and misses a moved key is guaranteed to see the new route on its
	 * re-read */
	if (split + 1 == (1U << level))
		nr = (uint64_t)(level + 1) << 32;     /* level up, split 0 */
	else
		nr = ((uint64_t)level << 32) | (split + 1);
	__atomic_store_n(&ht->route, nr, __ATOMIC_RELEASE);
	ht->nbuckets++;

	__atomic_add_fetch(&S->version, 1, __ATOMIC_ACQ_REL);  /* S stable */
	bkt_clear_owner(S);
	lock_release(&S->lock);
	return 1;
}

/* the entry count is read once: splitting never changes it */
unsigned int pcache_ht_grow(pcache_htable_t *ht, unsigned int target_lf,
		unsigned int budget)
{
	pcache_ht_totals_t t;
	unsigned int did = 0;

	if (!target_lf)
		return 0;
	pcache_ht_totals(ht, &t);
	while (did < budget &&
	       t.entries > (unsigned long)target_lf * ht->nbuckets) {
		if (pcache_ht_split(ht) <= 0)
			break;                         /* ceiling or OOM */
		did++;
	}
	return did;
}

pcache_htable_t *pcache_htable_new(unsigned int size_log2)
{
	pcache_htable_t *ht;
	pcache_bucket_t *seg;
	unsigned int nbuckets, done, n, s, i;

	/* the segment directory is a fixed array */
	if (size_log2 > PCACHE_MAX_SIZE_LOG2) {
		LM_ERR("a table of 2^%u buckets is past the %u-segment "
			"directory's ceiling of 2^%u\n", size_log2,
			PCACHE_NSEGS, PCACHE_MAX_SIZE_LOG2);
		return NULL;
	}
	nbuckets = 1U << size_log2;

	ht = pcache_region_alloc(sizeof *ht);
	if (!ht)
		return NULL;
	memset(ht, 0, sizeof *ht);

	/* always whole segments, so growth can fill a segment up to its
	 * boundary */
	n = (nbuckets + PCACHE_SEG_SIZE - 1) / PCACHE_SEG_SIZE;
	if (n == 0)
		n = 1;
	for (s = 0; s < n; s++) {
		seg = pcache_region_alloc(
			(unsigned long)PCACHE_SEG_SIZE * sizeof *seg);
		if (!seg)
			return NULL;
		memset(seg, 0, (unsigned long)PCACHE_SEG_SIZE * sizeof *seg);
		for (i = 0; i < PCACHE_SEG_SIZE; i++)
			lock_init(&seg[i].lock);
		ht->seg[s] = seg;

		ht->hint_seg[s] = pcache_region_alloc(
			PCACHE_SEG_SIZE * sizeof(unsigned int));
		if (!ht->hint_seg[s])
			return NULL;
		memset(ht->hint_seg[s], 0,
			PCACHE_SEG_SIZE * sizeof(unsigned int));
	}
	(void)done;

	ht->pstats_n = PCACHE_MAX_PROCS;
	ht->pstats = pcache_region_alloc(
		(unsigned long)ht->pstats_n * sizeof *ht->pstats);
	if (!ht->pstats)
		return NULL;
	memset(ht->pstats, 0,
		(unsigned long)ht->pstats_n * sizeof *ht->pstats);

	ht->ovf_tab = pcache_region_alloc(
		PCACHE_OVF_BUCKETS * sizeof *ht->ovf_tab);
	if (!ht->ovf_tab)
		return NULL;
	memset(ht->ovf_tab, 0, PCACHE_OVF_BUCKETS * sizeof *ht->ovf_tab);
	if (!lock_init(&ht->ovf_lock))
		return NULL;

	ht->nbuckets = nbuckets;
	ht->route = (uint64_t)size_log2 << 32;

	LM_DBG("table ready: %u buckets in %u segments\n", nbuckets, s);
	return ht;
}


/* startup selftest (modparam "htable_selftest"), single process */
#define HCHK(cond, ...) \
	do { \
		if (!(cond)) { \
			LM_ERR("htable selftest FAILED: " __VA_ARGS__); \
			return -1; \
		} \
	} while (0)

struct st_walk {
	unsigned char seen[200];
	unsigned int total, bad;
};

static int st_walk_cb(const str *key, const str *val, unsigned int exp,
		void *ctx)
{
	struct st_walk *w = ctx;
	unsigned int i;
	char vb[32];

	w->total++;
	if (key->len != 9 || memcmp(key->s, "spill-", 6) != 0 ||
	        sscanf(key->s + 6, "%u", &i) != 1 || i >= 200) {
		w->bad++;
		return 0;
	}
	w->seen[i]++;
	snprintf(vb, sizeof vb, "payload-%03u", i);
	if (val->len != strlen(vb) || memcmp(val->s, vb, val->len))
		w->bad++;
	return 0;
}

static pcache_rec_t *st_slot_of(pcache_htable_t *ht, const str *key)
{
	uint64_t route;
	unsigned int hash = pcache_key_hash((const str *)key);
	pcache_bucket_t *b = bucket_at(ht, route_idx(ht, hash, &route));
	int i = find_slot(b, key, hash, tag_of(hash));

	return i < 0 ? NULL : b->slot[i];
}

int pcache_htable_selftest(void)
{
	pcache_htable_t *ht;
	pcache_rec_t *r0, *r1;
	pcache_bucket_t *b;
	str k, v, out;
	uint64_t route;
	unsigned int i, ver0, ver1, nb_used;
	char kb[32], vb[512];
	int rc;

	ht = pcache_htable_new(4);              /* 16 buckets: collisions */
	HCHK(ht != NULL, "table creation failed\n");

	/* roundtrip + miss */
	k.s = "key-one"; k.len = 7;
	v.s = "value-one"; v.len = 9;
	HCHK(pcache_ht_store(ht, &k, &v, 0) == 0, "store failed\n");
	rc = pcache_ht_fetch(ht, &k, &out);
	HCHK(rc == 0 && out.len == 9 && !memcmp(out.s, "value-one", 9),
		"roundtrip mismatch (rc %d)\n", rc);
	pkg_free(out.s);
	k.s = "absent"; k.len = 6;
	HCHK(pcache_ht_fetch(ht, &k, &out) == -2, "phantom hit\n");

	/* in-place overwrite: same cell, new bytes */
	k.s = "key-one"; k.len = 7;
	r0 = st_slot_of(ht, &k);
	HCHK(r0 != NULL, "stored key has no slot\n");
	v.s = "VALUE-two"; v.len = 9;
	HCHK(pcache_ht_store(ht, &k, &v, 0) == 0, "overwrite failed\n");
	r1 = st_slot_of(ht, &k);
	HCHK(r1 == r0, "same-size overwrite moved the record\n");
	rc = pcache_ht_fetch(ht, &k, &out);
	HCHK(rc == 0 && !memcmp(out.s, "VALUE-two", 9), "overwrite lost\n");
	pkg_free(out.s);

	/* versionless TTL bump: byte-identical value, version must hold */
	b = bucket_at(ht, route_idx(ht, pcache_key_hash(&k), &route));
	ver0 = b->version;
	HCHK(pcache_ht_store(ht, &k, &v, get_ticks() + 100) == 0,
		"bump store failed\n");
	ver1 = b->version;
	HCHK(ver0 == ver1, "TTL bump bumped the version (%u -> %u)\n",
		ver0, ver1);
	HCHK(st_slot_of(ht, &k)->expires == get_ticks() + 100,
		"TTL bump did not land\n");

	/* replacement: value outgrows the cell class */
	memset(vb, 'R', sizeof vb);
	v.s = vb; v.len = 300;                   /* 16+7+300 -> bigger class */
	HCHK(pcache_ht_store(ht, &k, &v, 0) == 0, "grow store failed\n");
	r1 = st_slot_of(ht, &k);
	HCHK(r1 != r0, "cross-class grow did not replace the record\n");
	rc = pcache_ht_fetch(ht, &k, &out);
	HCHK(rc == 0 && out.len == 300 && out.s[0] == 'R' && out.s[299] == 'R',
		"grown value mismatch\n");
	pkg_free(out.s);

	/* remove + idempotent remove */
	HCHK(pcache_ht_remove(ht, &k) == 1, "remove failed\n");
	HCHK(pcache_ht_fetch(ht, &k, &out) == -2, "removed key still hits\n");
	HCHK(pcache_ht_remove(ht, &k) == 0, "second remove not idempotent\n");

	/* expiry-as-absent, on a synthetic clock (get_ticks() is 0 here) */
	v.s = "temp"; v.len = 4;
	HCHK(pcache_ht_store(ht, &k, &v, 500) == 0, "expired store failed\n");
	HCHK(_pcache_ht_fetch(ht, &k, &out, 1000, NULL, NULL) == -2,
		"expired key still hits\n");
	rc = _pcache_ht_fetch(ht, &k, &out, 400, NULL, NULL);
	HCHK(rc == 0, "live key missed\n");
	pkg_free(out.s);
	pcache_ht_remove(ht, &k);

	/* native counters */
	{
		long long nv = 0;

		k.s = "ctr"; k.len = 3;
		HCHK(pcache_ht_add(ht, &k, 5, 0, &nv) == 0 && nv == 5,
			"counter create: %lld\n", nv);
		HCHK(pcache_ht_add(ht, &k, 37, 0, &nv) == 0 && nv == 42,
			"counter accumulate: %lld\n", nv);
		HCHK(pcache_ht_add(ht, &k, -2, 0, &nv) == 0 && nv == 40,
			"counter subtract: %lld\n", nv);
		r0 = st_slot_of(ht, &k);
		HCHK(r0 && (r0->rflags & PCACHE_F_INT), "counter not native\n");
		rc = pcache_ht_fetch(ht, &k, &out);
		HCHK(rc == 0 && out.len == 2 && !memcmp(out.s, "40", 2),
			"counter fetch not formatted: <%.*s>\n", out.len, out.s);
		pkg_free(out.s);
		HCHK(pcache_ht_remove(ht, &k) == 1, "counter remove\n");

		/* a numeric string converts on the first add */
		k.s = "s2c"; k.len = 3;
		v.s = "100"; v.len = 3;
		HCHK(pcache_ht_store(ht, &k, &v, 0) == 0, "s2c store\n");
		HCHK(pcache_ht_add(ht, &k, 1, 0, &nv) == 0 && nv == 101,
			"s2c add: %lld\n", nv);
		r0 = st_slot_of(ht, &k);
		HCHK(r0 && (r0->rflags & PCACHE_F_INT), "s2c not converted\n");
		HCHK(pcache_ht_remove(ht, &k) == 1, "s2c remove\n");

		/* a non-numeric string refuses */
		k.s = "nan"; k.len = 3;
		v.s = "abc"; v.len = 3;
		HCHK(pcache_ht_store(ht, &k, &v, 0) == 0, "nan store\n");
		/* drives the reject path on purpose - see st_expect_reject */
		st_expect_reject = 1;
		rc = pcache_ht_add(ht, &k, 1, 0, &nv);
		st_expect_reject = 0;
		HCHK(rc == -1, "nan add passed\n");
		HCHK(pcache_ht_remove(ht, &k) == 1, "nan remove\n");
	}

	/* record-size limit */
	k.s = "key-one"; k.len = 7;
	v.s = vb; v.len = PCACHE_CELL_MAX;       /* header pushes it over */
	/* an expected rejection too - see st_expect_reject */
	st_expect_reject = 1;
	rc = pcache_ht_store(ht, &k, &v, 0);
	st_expect_reject = 0;
	HCHK(rc == -1, "oversize store passed\n");

	/* overflow: 200 keys over 16 buckets force chains, then drain */
	for (i = 0; i < 200; i++) {
		k.len = snprintf(kb, sizeof kb, "spill-%03u", i); k.s = kb;
		v.len = snprintf(vb, sizeof vb, "payload-%03u", i); v.s = vb;
		HCHK(pcache_ht_store(ht, &k, &v, 0) == 0, "spill store %u\n", i);
	}
	HCHK(ht->ovf_count > 0, "200 keys over 16 buckets never overflowed\n");
	LM_INFO("htable selftest: %u of 200 keys in overflow\n", ht->ovf_count);
	for (i = 0; i < 200; i++) {
		k.len = snprintf(kb, sizeof kb, "spill-%03u", i); k.s = kb;
		rc = pcache_ht_fetch(ht, &k, &out);
		HCHK(rc == 0, "spill fetch %u missed (rc %d)\n", i, rc);
		v.len = snprintf(vb, sizeof vb, "payload-%03u", i);
		HCHK(out.len == (unsigned int)v.len && !memcmp(out.s, vb, v.len),
			"spill value %u mismatch\n", i);
		pkg_free(out.s);
	}
	/* walker: exactly-once coverage of buckets and overflow */
	{
		struct st_walk w;
		memset(&w, 0, sizeof w);
		HCHK(pcache_ht_iter(ht, st_walk_cb, &w) == 0, "walk failed\n");
		HCHK(w.total == 200 && w.bad == 0,
			"walk saw %u entries, %u bad\n", w.total, w.bad);
		for (i = 0; i < 200; i++)
			HCHK(w.seen[i] == 1, "walk saw key %u %u times\n",
				i, w.seen[i]);
	}

	/* overwrite one overflow resident, verify, then drain everything */
	k.len = snprintf(kb, sizeof kb, "spill-%03u", 199); k.s = kb;
	v.s = "moved"; v.len = 5;
	HCHK(pcache_ht_store(ht, &k, &v, 0) == 0, "ovf overwrite failed\n");
	rc = pcache_ht_fetch(ht, &k, &out);
	HCHK(rc == 0 && out.len == 5 && !memcmp(out.s, "moved", 5),
		"ovf overwrite lost\n");
	pkg_free(out.s);
	for (i = 0; i < 200; i++) {
		k.len = snprintf(kb, sizeof kb, "spill-%03u", i); k.s = kb;
		HCHK(pcache_ht_remove(ht, &k) == 1, "spill remove %u\n", i);
	}
	HCHK(ht->ovf_count == 0, "overflow not drained: %u left\n",
		ht->ovf_count);
	for (i = 0, nb_used = 0; i < ht->nbuckets; i++)
		nb_used += bkt_used(bucket_at(ht, i));
	HCHK(nb_used == 0, "%u slots still used after full drain\n", nb_used);

	/* expiry sweep over buckets and overflow, with a survivor */
	{
		unsigned int freed;

		/* the survivor goes first so it takes a bucket slot */
		k.s = "stay"; k.len = 4;
		v.s = "keep"; v.len = 4;
		HCHK(pcache_ht_store(ht, &k, &v, 0) == 0, "stay store\n");
		for (i = 0; i < 100; i++) {
			k.len = snprintf(kb, sizeof kb, "ex-%03u", i); k.s = kb;
			v.s = "tmp"; v.len = 3;
			HCHK(pcache_ht_store(ht, &k, &v, 10) == 0,
				"sweep store %u\n", i);
		}
		HCHK(ht->ovf_count > 0, "sweep set never overflowed\n");

		freed = pcache_ht_sweep(ht, 5, NULL, NULL);
		HCHK(freed == 0, "sweep before expiry freed %u\n", freed);
		freed = pcache_ht_sweep(ht, 20, NULL, NULL);
		HCHK(freed == 100, "sweep freed %u of 100\n", freed);
		HCHK(ht->ovf_count == 0, "sweep left %u in overflow\n",
			ht->ovf_count);

		k.s = "stay"; k.len = 4;
		rc = pcache_ht_fetch(ht, &k, &out);
		HCHK(rc == 0 && out.len == 4, "never-expiring key swept\n");
		pkg_free(out.s);
		HCHK(pcache_ht_remove(ht, &k) == 1, "stay remove\n");
		for (i = 0, nb_used = 0; i < ht->nbuckets; i++)
			nb_used += bkt_used(bucket_at(ht, i));
		HCHK(nb_used == 0, "%u slots used after the sweep test\n",
			nb_used);
	}

	/* counter sanity after the full drain */
	{
		pcache_ht_totals_t t;

		pcache_ht_totals(ht, &t);
		HCHK(t.hits > 0 && t.misses > 0 && t.stores > 0 && t.removes > 0,
			"dead counters: h=%lu m=%lu s=%lu r=%lu\n",
			t.hits, t.misses, t.stores, t.removes);
		HCHK(t.created == t.destroyed,
			"record leak: created %lu, destroyed %lu\n",
			t.created, t.destroyed);
		HCHK(t.entries == 0, "%lu entries after the drain\n", t.entries);
		HCHK(t.retries == 0 && t.fallbacks == 0,
			"single-process retries %lu, fallbacks %lu\n",
			t.retries, t.fallbacks);
	}

	/* growth: every key must survive the splits */
	{
		pcache_htable_t *g = pcache_htable_new(4);   /* 16 buckets */
		unsigned int nb0, grown, miss = 0;
		HCHK(g != NULL, "growth table creation failed\n");
		for (i = 0; i < 1000; i++) {
			k.len = snprintf(kb, sizeof kb, "grow-%04u", i); k.s = kb;
			v.len = snprintf(vb, sizeof vb, "gv-%04u", i); v.s = vb;
			HCHK(pcache_ht_store(g, &k, &v, 0) == 0, "grow store %u\n", i);
		}
		nb0 = g->nbuckets;
		HCHK(nb0 == 16, "unexpected initial buckets %u\n", nb0);
		grown = pcache_ht_grow(g, 2, 100000);        /* target LF 2 */
		HCHK(g->nbuckets > nb0, "table did not grow (%u)\n", g->nbuckets);
		HCHK(g->nbuckets * 2 >= 1000, "grew short: %u buckets for 1000 "
			"entries at LF 2\n", g->nbuckets);
		/* every key still findable after the splits */
		for (i = 0; i < 1000; i++) {
			k.len = snprintf(kb, sizeof kb, "grow-%04u", i); k.s = kb;
			v.len = snprintf(vb, sizeof vb, "gv-%04u", i);
			if (pcache_ht_fetch(g, &k, &out) != 0) { miss++; continue; }
			if (out.len != (unsigned int)v.len || memcmp(out.s, vb, v.len))
				miss++;
			pkg_free(out.s);
		}
		HCHK(miss == 0, "%u of 1000 keys lost/wrong after growth "
			"(%u->%u buckets, %u splits)\n", miss, nb0, g->nbuckets, grown);
		LM_INFO("htable selftest: growth %u->%u buckets (%u splits), "
			"all 1000 keys intact\n", nb0, g->nbuckets, grown);
	}

	/* every bucket must end on an even (stable) version */
	for (i = 0; i < ht->nbuckets; i++)
		HCHK(!(bucket_at(ht, i)->version & 1),
			"bucket %u left with an odd version\n", i);

	LM_NOTICE("htable selftest: PASS (16 buckets, overflow exercised, "
		"versionless bump verified)\n");
	return 0;
}
