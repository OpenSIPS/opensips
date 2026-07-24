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
 * The table core (DESIGN 3.1/3.2/3.4): 64-byte buckets, 1-byte tags,
 * lock-free optimistic reads under a per-bucket seqlock, writers under the
 * bucket lock.  Rules implemented here and not to be broken:
 *
 *  - readers copy out inside the optimistic section and trust nothing
 *    until the version re-check; every length is clamped and every
 *    pointer extent-checked BEFORE use (3.2 copy-out rules)
 *  - a byte-identical set() that only refreshes the TTL skips the version
 *    bumps and the memcpy - one atomic expires store under the lock
 *    (2.7); readers of the bucket are undisturbed
 *  - no allocation and no free while holding a bucket lock (3.5b):
 *    replacement records are built before lock_get, dead records are
 *    freed after lock_release
 *  - on a miss the routing word is re-read (3.4): a completed split may
 *    have moved the key; writers re-verify routing after lock_get
 *  - full buckets overflow into a small chained side table behind one
 *    lock, gated by ovf_count so the common case costs one cached load;
 *    a key lives in its bucket or in overflow, never both
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

#if defined(__x86_64__) || defined(__i386__)
#define pcache_pause() __builtin_ia32_pause()
#else
#define pcache_pause() do {} while (0)
#endif

struct povf {
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
		unsigned long *route_out)
{
	/* acquire pairs with the release-publish in pcache_ht_split: seeing a
	 * new routing word implies the partner bucket's slots are visible */
	unsigned long r = __atomic_load_n(&ht->route, __ATOMIC_ACQUIRE);
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

/* CP-06: plain increments on the calling process's own cache line */
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
static inline unsigned long tag_matches(const pcache_bucket_t *b,
		unsigned char tag)
{
	unsigned long w, x;

	memcpy(&w, b->tags, 8);
	x = w ^ (0x0101010101010101UL * tag);
	return (x - 0x0101010101010101UL) & ~x & 0x0000808080808080UL;
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

/* per-process copy-out scratch (3.2 rule 3) */
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
		unsigned char tag, char *scratch, unsigned int *vlen_out,
		unsigned int *exp_out, unsigned char *fl_out)
{
	unsigned long m, lo, hi;
	unsigned int bound, vlen, klen;
	pcache_rec_t *r;
	int i;

	pcache_arena_extents(&lo, &hi);

	for (m = tag_matches(b, tag); m; m &= m - 1) {
		i = __builtin_ctzl(m) >> 3;
		r = b->slot[i];
		if (!r)
			continue;

		/* 3.2 copy-out rules: validate before every use.  A stale
		 * pointer fails one of these or the final version re-check;
		 * a mismatch on live data is just not-this-slot */
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
		if (memcmp(r->data, key->s, klen))
			continue;

		vlen = r->vlen;                       /* aligned 4-byte load */
		if (PCACHE_REC_HDR + klen + vlen > bound)
			vlen = bound - PCACHE_REC_HDR - klen;  /* doomed copy, bounded */
		memcpy(scratch, r->data + klen, vlen);
		*vlen_out = vlen;
		*exp_out = r->expires;
		*fl_out = r->rflags;
		return 0;
	}
	return -2;
}

/* overflow lookup - records are stable under the overflow lock */
static int ovf_fetch(pcache_htable_t *ht, const str *key, unsigned int hash,
		char *scratch, unsigned int *vlen_out, unsigned int *exp_out,
		unsigned char *fl_out)
{
	struct povf *n;
	int rc = -2;

	lock_get(&ht->ovf_lock);
	for (n = ht->ovf_tab[hash & (PCACHE_OVF_BUCKETS - 1)]; n; n = n->next) {
		if (n->hash != hash || n->rec->klen != key->len ||
		        memcmp(n->rec->data, key->s, key->len))
			continue;
		*vlen_out = n->rec->vlen;
		*exp_out = n->rec->expires;
		*fl_out = n->rec->rflags;
		memcpy(scratch, n->rec->data + key->len, *vlen_out);
		rc = 0;
		break;
	}
	lock_release(&ht->ovf_lock);
	return rc;
}

/* @now is a parameter (not read inside) so the selftest can run under a
 * synthetic clock - get_ticks() is still 0 during mod_init */
static int _pcache_ht_fetch(pcache_htable_t *ht, const str *key, str *val,
		unsigned int now, unsigned int *exp_out)
{
	pcache_bucket_t *b;
	unsigned long route;
	unsigned int hash, idx, v1, v2, vlen = 0, exp = 0, tries;
	unsigned char tag, fl = 0;
	long long ll;
	char *scratch;
	int rc;

	scratch = get_scratch();
	if (!scratch)
		return -1;

	hash = core_hash(key, NULL, 0);
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
		rc = scan_bucket(b, key, hash, tag, scratch, &vlen, &exp, &fl);
		__atomic_thread_fence(__ATOMIC_ACQUIRE);
		v2 = __atomic_load_n(&b->version, __ATOMIC_RELAXED);
		if (v1 == v2)
			goto settled;
	}

	/* a writer is stalled mid-update: do not keep spinning - sleep on
	 * the lock (3.2 fallback; the lock sleeps under futex) */
	lock_get(&b->lock);
	bkt_set_owner(b);
	rc = scan_bucket(b, key, hash, tag, scratch, &vlen, &exp, &fl);
	bkt_clear_owner(b);
	lock_release(&b->lock);
	HT_ST(ht, fallbacks);

settled:
	if (tries)
		HT_ST_ADD(ht, retries, tries);
	if (rc == -2) {
		/* 3.4: a completed split may have re-routed the key */
		if (ht->route != route)
			goto again;
		if (ht->ovf_count)
			rc = ovf_fetch(ht, key, hash, scratch, &vlen, &exp, &fl);
	}
	if (rc == -2) {
		HT_ST(ht, misses);
		return -2;
	}

	if (exp && exp <= now) {
		HT_ST(ht, misses);
		return -2;                    /* expired-as-absent (3.5) */
	}
	HT_ST(ht, hits);
	if (exp_out)
		*exp_out = exp;                  /* absolute ticks, 0 = never */

	if ((fl & PCACHE_F_INT) && vlen == 8) {
		/* native counter: format on read */
		memcpy(&ll, scratch, 8);
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
	return _pcache_ht_fetch(ht, key, val, get_ticks(), NULL);
}

/* like pcache_ht_fetch, but also returns the record's absolute expiry
 * (0 = never) - the MI perf_get needs the TTL alongside the value */
int pcache_ht_fetch_ex(pcache_htable_t *ht, const str *key, str *val,
		unsigned int *expires)
{
	return _pcache_ht_fetch(ht, key, val, get_ticks(), expires);
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
		        !memcmp(r->data, key->s, key->len))
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
		        !memcmp(n->rec->data, key->s, key->len))
			break;
	if (prev_out)
		*prev_out = prev;
	return n;
}

int pcache_ht_store(pcache_htable_t *ht, const str *key, const str *val,
		unsigned int expires)
{
	pcache_bucket_t *b;
	pcache_rec_t *nr, *old = NULL;
	struct povf *node = NULL, *on;
	unsigned long route;
	unsigned int hash, idx, used;
	unsigned char tag;
	int i, inserted = 0;

	if (key->len > 0xFFFF ||
	        PCACHE_REC_SIZE(key->len, val->len) > PCACHE_CELL_MAX) {
		LM_ERR("key %d + value %d bytes exceed the %d byte record limit\n",
			key->len, val->len, PCACHE_CELL_MAX);
		return -1;
	}

	hash = core_hash(key, NULL, 0);
	tag = tag_of(hash);

	/* build the full replacement record before any lock (3.5b rule 3) */
	nr = pcache_cell_alloc(PCACHE_REC_SIZE(key->len, val->len));
	if (!nr)
		return -1;
	nr->rflags = 0;
	nr->klen = (unsigned short)key->len;
	nr->vlen = (unsigned int)val->len;
	nr->expires = expires;
	nr->hash = hash;
	memcpy(nr->data, key->s, key->len);
	memcpy(nr->data + key->len, val->s, val->len);

again:
	idx = route_idx(ht, hash, &route);
	b = bucket_at(ht, idx);

	lock_get(&b->lock);
	bkt_set_owner(b);

	/* 3.4 writer rule: routing may have moved while we waited */
	if (ht->route != route) {
		bkt_clear_owner(b);
		lock_release(&b->lock);
		goto again;
	}

	i = find_slot(b, key, hash, tag);
	if (i >= 0) {
		old = b->slot[i];

		if (old->vlen == (unsigned int)val->len &&
		        !memcmp(old->data + key->len, val->s, val->len)) {
			/* versionless TTL bump (2.7): the only mutation is one
			 * aligned store readers cannot tear - no version bumps,
			 * no reader disturbance */
			__atomic_store_n(&old->expires, expires, __ATOMIC_RELAXED);
			hint_update(ht, idx, expires);
			old = nr;                     /* discard the prebuilt one */
			goto done;
		}

		if (PCACHE_REC_SIZE(key->len, val->len) <= pcache_cell_bound(old)) {
			/* in-place: the new value fits the cell */
			__atomic_add_fetch(&b->version, 1, __ATOMIC_RELEASE);
			old->vlen = (unsigned int)val->len;
			memcpy(old->data + key->len, val->s, val->len);
			old->expires = expires;
			__atomic_add_fetch(&b->version, 1, __ATOMIC_RELEASE);
			hint_update(ht, idx, expires);
			old = nr;                     /* discard the prebuilt one */
			goto done;
		}

		/* replace the record; the tag stays (same key, same hash) */
		__atomic_add_fetch(&b->version, 1, __ATOMIC_RELEASE);
		b->slot[i] = nr;
		__atomic_add_fetch(&b->version, 1, __ATOMIC_RELEASE);
		hint_update(ht, idx, expires);
		goto done;
	}

	/* not in the bucket - it may sit in overflow (uniqueness: a key is
	 * in its bucket or in overflow, never both) */
	if (ht->ovf_count) {
		lock_get(&ht->ovf_lock);
		on = ovf_find(ht, key, hash, NULL);
		if (on) {
			old = on->rec;
			on->rec = nr;         /* overflow readers are lock-serialized */
			lock_release(&ht->ovf_lock);
			goto done;
		}
		lock_release(&ht->ovf_lock);
	}

	used = bkt_used(b);
	if (used < PCACHE_SLOTS) {
		__atomic_add_fetch(&b->version, 1, __ATOMIC_RELEASE);
		b->slot[used] = nr;
		b->tags[used] = tag;
		bkt_set_used(b, used + 1);
		__atomic_add_fetch(&b->version, 1, __ATOMIC_RELEASE);
		hint_update(ht, idx, expires);
		inserted = 1;
		goto done;
	}

	/* bucket full -> overflow.  The chain node must not be allocated
	 * under the bucket lock, so drop it, allocate, re-take, re-check */
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

	/* frees strictly after the locks (3.5b) */
	if (old)
		pcache_cell_free(old);
	if (node)
		pcache_cell_free(node);
	HT_ST(ht, stores);
	if (inserted)
		HT_ST(ht, created);
	return 0;
}

int pcache_ht_add(pcache_htable_t *ht, const str *key, long long delta,
		unsigned int expires, long long *new_val)
{
	pcache_bucket_t *b;
	pcache_rec_t *nr, *r, *old = NULL;
	struct povf *node = NULL, *on;
	unsigned long route;
	unsigned int hash, idx, used;
	unsigned char tag;
	long long cur;
	int i, inserted = 0;

	if (key->len > 0xFFFF)
		return -1;

	hash = core_hash(key, NULL, 0);
	tag = tag_of(hash);

	/* the counter record is pre-built outside any lock (3.5b); it either
	 * becomes the entry (absent key / string conversion) or is freed */
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
			/* fixed-width accumulate; the payload may be unaligned, so
			 * it changes under the version, never bare */
			memcpy(&cur, r->data + r->klen, 8);
			cur += delta;
			__atomic_add_fetch(&b->version, 1, __ATOMIC_RELEASE);
			memcpy(r->data + r->klen, &cur, 8);
			r->expires = expires;
			__atomic_add_fetch(&b->version, 1, __ATOMIC_RELEASE);
			hint_update(ht, idx, expires);
			old = nr;
			goto done;
		}
		/* string record: convert on first touch if numeric */
		if (pcache_str2ll(r->data + r->klen, r->vlen, &cur) < 0)
			goto nan;
		cur += delta;
		memcpy(nr->data + key->len, &cur, 8);
		__atomic_add_fetch(&b->version, 1, __ATOMIC_RELEASE);
		b->slot[i] = nr;
		__atomic_add_fetch(&b->version, 1, __ATOMIC_RELEASE);
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
		__atomic_add_fetch(&b->version, 1, __ATOMIC_RELEASE);
		b->slot[used] = nr;
		b->tags[used] = tag;
		bkt_set_used(b, used + 1);
		__atomic_add_fetch(&b->version, 1, __ATOMIC_RELEASE);
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
	if (inserted)
		HT_ST(ht, created);
	if (new_val)
		*new_val = cur;
	return 0;

nan:
	bkt_clear_owner(b);
	lock_release(&b->lock);
	LM_ERR("value of <%.*s> is not an integer\n", key->len, key->s);
	pcache_cell_free(nr);
	if (node)
		pcache_cell_free(node);
	return -1;
}

int pcache_ht_remove(pcache_htable_t *ht, const str *key)
{
	pcache_bucket_t *b;
	pcache_rec_t *dead = NULL;
	struct povf *on = NULL, **prev;
	unsigned long route;
	unsigned int hash, idx, used;
	unsigned char tag;
	int i;

	hash = core_hash(key, NULL, 0);
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
		__atomic_add_fetch(&b->version, 1, __ATOMIC_RELEASE);
		b->slot[i] = b->slot[used - 1];       /* compact: readers retry */
		b->tags[i] = b->tags[used - 1];
		b->slot[used - 1] = NULL;
		b->tags[used - 1] = 0;
		bkt_set_used(b, used - 1);
		__atomic_add_fetch(&b->version, 1, __ATOMIC_RELEASE);
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
 * One optimistic seqlock snapshot of slot @i of bucket @b into @kbuf/@vbuf
 * (each >= PCACHE_CELL_MAX), applying the 3.2 copy-out clamps and the
 * stalled-writer lock fallback.  Returns 1 and fills the out-params if a
 * live record was captured, 0 if the slot is empty.  Shared verbatim by the
 * full-table walk (pcache_ht_iter) and the cursored scan (pcache_ht_scan).
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
		/* 3.2 copy-out rules, as in scan_bucket() */
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
				vlen = bound - PCACHE_REC_HDR - klen;
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

/*
 * Format one snapshotted entry (native counters -> decimal), NUL-terminate
 * both buffers and hand it to the callback.  @vbuf must have room for the
 * 24-byte decimal form.  Returns the callback's rc (<0 stops the walk).
 */
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

/* walk the overflow leg under the overflow lock; @kbuf/@vbuf are the caller's
 * snapshot buffers.  Returns the last callback rc (<0 stops). */
static int iter_overflow(pcache_htable_t *ht, pcache_iter_cb cb, void *ctx,
		char *kbuf, char *vbuf)
{
	pcache_rec_t *r;
	struct povf *n;
	unsigned int idx, klen, vlen;
	int rc = 0;

	if (!ht->ovf_count)
		return 0;
	lock_get(&ht->ovf_lock);
	for (idx = 0; idx < PCACHE_OVF_BUCKETS && rc >= 0; idx++) {
		for (n = ht->ovf_tab[idx]; n; n = n->next) {
			r = n->rec;
			klen = r->klen;
			vlen = r->vlen;
			memcpy(kbuf, r->data, klen);
			memcpy(vbuf, r->data + klen, vlen);
			rc = emit_entry(cb, ctx, kbuf, klen, vbuf, vlen,
				r->expires, r->rflags);
			if (rc < 0)
				break;
		}
	}
	lock_release(&ht->ovf_lock);
	return rc;
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

	/* overflow leg - under the lock; the callback must not re-enter */
	rc = iter_overflow(ht, cb, ctx, kbuf, vbuf);
out:
	pkg_free(kbuf);
	return rc < 0 ? rc : 0;
}

/*
 * Cursored, bounded walk for the MI perf_scan (Redis SCAN semantics).  From
 * bucket *@cursor it visits up to @max_buckets buckets, invoking @cb per live
 * entry, then sets *@cursor to the bucket to resume from - or 0 once the walk
 * is complete, the overflow leg being emitted in that final call.  Buckets
 * never move and the table only grows (3.4), so a plain ascending cursor gives
 * the >=-once guarantee and stays valid across a concurrent resize.  The cursor
 * advances a whole bucket at a time, so @cb sees every entry of a visited
 * bucket and is never asked to stop mid-bucket (no intra-bucket duplicates on
 * resume).  Returns 0, or <0 on error / callback stop.
 */
int pcache_ht_scan(pcache_htable_t *ht, unsigned int *cursor,
		unsigned int max_buckets, pcache_iter_cb cb, void *ctx)
{
	pcache_bucket_t *b;
	unsigned long lo, hi;
	unsigned int idx, end, i, klen, vlen, exp, nb;
	unsigned char fl;
	char *kbuf, *vbuf;
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

	/* last bucket reached: drain overflow once, then signal completion */
	rc = iter_overflow(ht, cb, ctx, kbuf, vbuf);
	*cursor = 0;
out:
	pkg_free(kbuf);
	return rc < 0 ? rc : 0;
}

unsigned int pcache_ht_sweep(pcache_htable_t *ht, unsigned int now)
{
	pcache_bucket_t *b;
	pcache_rec_t *r, *dead[PCACHE_SLOTS];
	pcache_rec_t *batch_r[64];
	struct povf *n, **prev, *batch_n[64];
	unsigned int idx, i, used, hint, newmin, ndead, freed = 0;
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
						__ATOMIC_RELEASE);
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
			__atomic_add_fetch(&b->version, 1, __ATOMIC_RELEASE);
		*hint_at(ht, idx) = newmin;

		bkt_clear_owner(b);
		lock_release(&b->lock);

		/* reclamation strictly after the lock (3.5b), through the
		 * global pool - the sweeping process is not an allocator */
		for (i = 0; i < ndead; i++)
			pcache_cell_free_global(dead[i]);
		freed += ndead;
	}

	if (!ht->ovf_count) {
		HT_ST_ADD(ht, destroyed, freed);
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
				pcache_cell_free_global(batch_r[i]);
				pcache_cell_free_global(batch_n[i]);
			}
			freed += bn;
		} while (bn == 64);
	}

	HT_ST_ADD(ht, destroyed, freed);
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
		out->retries += p->retries;
		out->fallbacks += p->fallbacks;
	}
	out->entries = out->created - out->destroyed;
}

/*
 * CP-09: linear-hash growth.  The maintenance timer is the SOLE splitter, so
 * splits never race one another; readers and writers use the routing word
 * plus the 3.4 re-check protocol already wired into fetch/store/remove.
 * Existing buckets never move (growth appends), so no pointer invalidation.
 */

/* allocate the segment (+ its hint segment) containing bucket @idx if absent.
 * Single-splitter, so no alloc race; the seg pointer is published (release)
 * only once fully built, and always before the routing word that makes any
 * bucket in it reachable. */
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
 * Split the current bucket (index = split), redistributing its 6 slots into
 * itself and the new partner (split + 2^level) by bit `level` of each entry's
 * stored hash (no rehash).  Overflow is hash-keyed and bucket-agnostic
 * (ovf_find matches by hash+key regardless of routing), so a split leaves
 * overflow entries findable and does not touch them - they drain as the
 * freed slots absorb new inserts.  Returns 1 on a split, 0 at the ceiling,
 * -1 on OOM.
 */
static int pcache_ht_split(pcache_htable_t *ht)
{
	unsigned long r = ht->route, nr;
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
	__atomic_add_fetch(&S->version, 1, __ATOMIC_RELEASE);  /* writer in */

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

	/* Publish the new routing word WHILE S's version is odd.  The even
	 * bump below is a release that happens-after this store, so any
	 * reader which later observes S even (via acquire) and misses a
	 * moved key is guaranteed to see the new route on its 3.4 re-read
	 * and re-route to the partner - no false-miss window. */
	if (split + 1 == (1U << level))
		nr = (unsigned long)(level + 1) << 32;     /* level up, split 0 */
	else
		nr = ((unsigned long)level << 32) | (split + 1);
	__atomic_store_n(&ht->route, nr, __ATOMIC_RELEASE);
	ht->nbuckets++;

	__atomic_add_fetch(&S->version, 1, __ATOMIC_RELEASE);  /* S stable */
	bkt_clear_owner(S);
	lock_release(&S->lock);
	return 1;
}

/*
 * Split buckets while the load factor exceeds @target_lf, up to @budget
 * splits.  Called only from the maintenance timer (single splitter).  The
 * live-entry count is read once - splitting only redistributes, never
 * changes it - so the loop just watches nbuckets climb.  Returns the number
 * of splits performed.
 */
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
	unsigned int nbuckets = 1U << size_log2, done, n, s, i;

	ht = pcache_region_alloc(sizeof *ht);
	if (!ht)
		return NULL;
	memset(ht, 0, sizeof *ht);

	/* Segments are FIXED at PCACHE_SEG_SIZE buckets (the directory is a
	 * directory of fixed segments, DESIGN 3.4) - always allocate full
	 * segments, even when the initial nbuckets is smaller, so linear-hash
	 * growth can fill a segment up to its boundary without going out of
	 * bounds.  n rounds nbuckets up to whole segments. */
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
	ht->route = (unsigned long)size_log2 << 32;

	LM_DBG("table ready: %u buckets in %u segments\n", nbuckets, s);
	return ht;
}


/*
 * startup selftest (modparam "htable_selftest"): single-process coverage
 * of every path above - roundtrip, in-place vs replacement, the
 * versionless bump (bucket version must NOT move), removal compaction,
 * overflow spill and drain, expiry-as-absent, record-size limits.
 * Multi-process interleavings are CP-16's job.
 */
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
	unsigned long route;
	unsigned int hash = core_hash((str *)key, NULL, 0);
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
	unsigned long route;
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
	b = bucket_at(ht, route_idx(ht, core_hash(&k, NULL, 0), &route));
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

	/* expiry-as-absent, under a synthetic clock (get_ticks() is still 0
	 * in mod_init, so nothing can be "in the past" through the public
	 * wrapper here) */
	v.s = "temp"; v.len = 4;
	HCHK(pcache_ht_store(ht, &k, &v, 500) == 0, "expired store failed\n");
	HCHK(_pcache_ht_fetch(ht, &k, &out, 1000, NULL) == -2,
		"expired key still hits\n");
	rc = _pcache_ht_fetch(ht, &k, &out, 400, NULL);
	HCHK(rc == 0, "live key missed\n");
	pkg_free(out.s);
	pcache_ht_remove(ht, &k);

	/* native counters (CP-04): create, accumulate, format-on-read,
	 * string conversion, NaN refusal */
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
		HCHK(pcache_ht_add(ht, &k, 1, 0, &nv) == -1, "nan add passed\n");
		HCHK(pcache_ht_remove(ht, &k) == 1, "nan remove\n");
	}

	/* record-size limit */
	k.s = "key-one"; k.len = 7;
	v.s = vb; v.len = PCACHE_CELL_MAX;       /* header pushes it over */
	HCHK(pcache_ht_store(ht, &k, &v, 0) == -1, "oversize store passed\n");

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
	/* walker: exactly-once coverage of bucket + overflow legs (single
	 * process, so deterministic), values verified in the callback */
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

	/* expiry sweep (CP-05): hint-routed, bucket + overflow legs, mixed
	 * with never-expiring survivors */
	{
		unsigned int freed;

		/* the never-expiring survivor goes in FIRST so it takes a bucket
		 * slot - stored last it would land in overflow and the count
		 * checks below would misread a correct sweep */
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

		freed = pcache_ht_sweep(ht, 5);
		HCHK(freed == 0, "sweep before expiry freed %u\n", freed);
		freed = pcache_ht_sweep(ht, 20);
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

	/* CP-06 counter sanity: every create matched by a destroy after the
	 * full drain, and a single process never retries against itself */
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

	/* CP-09 growth: fill a small table past its load factor, split it
	 * down, and prove every key survives the relink + re-routing */
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
