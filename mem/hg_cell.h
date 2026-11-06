/*
 * slab allocator with elastic arenas - cell header and size classes
 *
 * Copyright (C) 2026 Yury Kirsanov
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/* included by hg_malloc.h, not on its own */

#ifndef HG_CELL_H
#define HG_CELL_H

#undef HG_ROUNDTO

#if defined(__CPU_sparc64) || defined(__CPU_sparc)
	#define HG_ROUNDTO		sizeof(long long)
#else
	#define HG_ROUNDTO		sizeof(void *)
#endif

#define HG_NCLASSES  21
#define HG_CELL_MAX  65536  /* largest cell; larger go to the large tier */

/* the four-tier huge-page ladder, best first */
enum hg_mem_tier {
	HG_MEM_HUGETLB = 1,   /* mmap MAP_HUGETLB */
	HG_MEM_THP_ADVISE,    /* shmem THP via MADV_HUGEPAGE, huge at fault */
	HG_MEM_THP_COLLAPSE,  /* shmem THP via MADV_COLLAPSE, post-fill */
	HG_MEM_4K,            /* plain pages - always works */
};

const char *hg_mem_tier_str(enum hg_mem_tier tier);

/* cell header before every returned pointer (like FM_FRAG()): the payload is
 * the caller's, but a FREE cell's first pointer is the free-list link */
#ifdef DBG_MALLOC
#define HG_CELL_HDR_DBG (HG_ROUNDTO * 3)  /* file ptr + func ptr + line */
#else
#define HG_CELL_HDR_DBG 0
#endif

#ifdef SHM_EXTRA_STATS
#define HG_CELL_HDR_STATS (HG_ROUNDTO)    /* statistic_index */
#else
#define HG_CELL_HDR_STATS 0
#endif

/* 8, not HG_ROUNDTO (4 on 32-bit ARM): LDREXD/STREXD and 64-bit atomics fault
 * on a 4 mod 8 payload; the padding ends the header, so no field moves */
#define HG_PAYLOAD_ALIGN 8

/* where a guarded cell keeps its requested size: the spare half of the first
 * word (64-bit), the header's alignment pad, else the cell's last 4 bytes */
#if defined(__CPU_sparc64) || defined(__CPU_sparc) || defined(__LP64__) || \
	defined(_LP64) || (defined(__SIZEOF_POINTER__) && __SIZEOF_POINTER__ == 8)
#define HG_REQ_SLOT0 1
#define HG_REQ_PAD   0
#elif defined(DBG_MALLOC) == defined(SHM_EXTRA_STATS)
#define HG_REQ_SLOT0 0
#define HG_REQ_PAD   1
#else
#define HG_REQ_SLOT0 0
#define HG_REQ_PAD   0
#endif
#define HG_REQ_TAIL  (!HG_REQ_SLOT0 && !HG_REQ_PAD)

/* the header as a struct; the _Static_asserts below pin its layout */
struct hg_cell_hdr {
	union {
		struct {
			unsigned char  cls;           /* class id, or HG_LARGE_MARKER */
			unsigned char  state;         /* HG_ST_FRESH / _FREE / _LIVE[_G] */
			unsigned short check;         /* hg_hdr_sum() */
#if HG_REQ_SLOT0
			unsigned int   req;           /* LIVE_G: keyed size (hg_guard_set()) */
#endif
		};
		unsigned int   hw;            /* the three as one word, for the
		                               * atomic LIVE -> FREE */
		unsigned char  _slot0[HG_ROUNDTO];
	};
#ifdef DBG_MALLOC
	const char    *file;
	const char    *func;
	unsigned long  line;
#endif
#ifdef SHM_EXTRA_STATS
	unsigned long  stat_idx;
#endif
#if HG_REQ_PAD
	unsigned int   req;
#endif
};

#define HG_CELL_HDR_RAW  sizeof(struct hg_cell_hdr)
#define HG_CELL_HDR \
	(((HG_CELL_HDR_RAW + HG_PAYLOAD_ALIGN - 1) / HG_PAYLOAD_ALIGN) \
	 * HG_PAYLOAD_ALIGN)

/* meaningful only under SHM_EXTRA_STATS */
#define HG_CELL_STATS_OFF (HG_ROUNDTO + HG_CELL_HDR_DBG)

/* C++ modules include this header too */
#ifdef __cplusplus
#define HG_STATIC_ASSERT static_assert
#else
#define HG_STATIC_ASSERT _Static_assert
#endif

HG_STATIC_ASSERT(HG_CELL_HDR_RAW == HG_ROUNDTO + HG_CELL_HDR_DBG + HG_CELL_HDR_STATS +
	(HG_REQ_PAD ? sizeof(unsigned int) : 0),
	"struct hg_cell_hdr is not the documented header layout");
HG_STATIC_ASSERT((!HG_REQ_SLOT0 || HG_ROUNDTO == 8) &&
	(!HG_REQ_PAD || HG_CELL_HDR == HG_CELL_HDR_RAW),
	"the guarded size must fit in a word the header leaves spare");
HG_STATIC_ASSERT(offsetof(struct hg_cell_hdr, cls) == 0,
	"the class byte must be the first byte of the header");
HG_STATIC_ASSERT(offsetof(struct hg_cell_hdr, state) == 1 &&
	offsetof(struct hg_cell_hdr, check) == 2,
	"the state byte and the checksum must follow the class byte");
HG_STATIC_ASSERT(sizeof(unsigned int) == 4 && HG_ROUNDTO >= 4,
	"class, state and checksum must make up one 32-bit word");
#ifdef DBG_MALLOC
HG_STATIC_ASSERT(offsetof(struct hg_cell_hdr, file) == HG_ROUNDTO &&
	offsetof(struct hg_cell_hdr, func) == HG_ROUNDTO * 2 &&
	offsetof(struct hg_cell_hdr, line) == HG_ROUNDTO * 3,
	"the DBG_MALLOC fields moved");
#endif
#ifdef SHM_EXTRA_STATS
HG_STATIC_ASSERT(offsetof(struct hg_cell_hdr, stat_idx) == HG_CELL_STATS_OFF,
	"the statistic_index field moved");
#endif

#define HG_HDR(p)   ((char *)(p) - HG_CELL_HDR)
/* the header of a payload pointer / of a cell-start pointer */
#define HG_CELL(p)     ((struct hg_cell_hdr *)(void *)HG_HDR(p))
#define HG_CELL_AT(cs) ((struct hg_cell_hdr *)(void *)(cs))
#define HG_CLASS(p) (HG_CELL(p)->cls)

/* cell state, whether a CALLER holds the cell: a free needs LIVE or LIVE_G
 * (guarded), an allocation FRESH or FREE; none is 0x00/0xff, so wipes fail */
#define HG_ST_FRESH  0x3c
#define HG_ST_FREE   0x5a
#define HG_ST_LIVE   0xa5
#define HG_ST_LIVE_G 0x96

static inline int hg_st_live(int st)
{
	return st == HG_ST_LIVE || st == HG_ST_LIVE_G;
}

/* per-run secret mixed into every header checksum, set before the first
 * arena is created (so it is the same in every process) */
extern unsigned long long hg_hdr_secret;

/* not cryptographic (catches overflows, interior pointers, moved headers):
 * base(address, class) ^ key(state), so a state change costs no multiply */
#define HG_ST_KEY(st)  ((unsigned short)((st) * 0x0101u))

static inline unsigned short hg_hdr_base(const void *cs, unsigned int cls)
{
	/* cells are at least 32-aligned, so the class takes the low address
	 * bits; the multiply carries every input bit into the top 16 */
	unsigned long long x = ((unsigned long long)(unsigned long)cs ^
		hg_hdr_secret ^ cls) * 0x9e3779b97f4a7c15ULL;

	return (unsigned short)(x >> 48);
}

static inline unsigned short hg_hdr_sum(const void *cs, unsigned int cls,
                                        unsigned int st)
{
	return hg_hdr_base(cs, cls) ^ HG_ST_KEY(st);
}

/* the header's first word, as the fields struct hg_cell_hdr lays out */
union hg_hdr_w {
	struct {
		unsigned char  cls, state;
		unsigned short check;
	} f;
	unsigned int w;
};

HG_STATIC_ASSERT(sizeof(union hg_hdr_w) == 4,
	"the header word must be exactly class, state and checksum");

static inline unsigned int hg_hdr_make(unsigned int cls, unsigned int st,
                                       unsigned short base)
{
	union hg_hdr_w h;

	h.f.cls = (unsigned char)cls;
	h.f.state = (unsigned char)st;
	h.f.check = (unsigned short)(base ^ HG_ST_KEY(st));
	return h.w;
}

/* one store, so a racing hg_hdr_claim_free() never sees half a header */
static inline void hg_hdr_set_base(void *cs, unsigned int cls, unsigned int st,
                                   unsigned short base)
{
	__atomic_store_n(&HG_CELL_AT(cs)->hw, hg_hdr_make(cls, st, base),
		__ATOMIC_RELAXED);
}

static inline void hg_hdr_set(void *cs, unsigned int cls, unsigned int st)
{
	hg_hdr_set_base(cs, cls, st, hg_hdr_base(cs, cls));
}

/* read the header word once and check it: the state, or -1 if it fails;
 * @w and @base come back for re-stamping without hashing again */
static inline int hg_hdr_read(const void *cs, union hg_hdr_w *w,
                              unsigned short *base)
{
	w->w = __atomic_load_n(&((const struct hg_cell_hdr *)cs)->hw,
		__ATOMIC_RELAXED);
	*base = hg_hdr_base(cs, w->f.cls);
	if (w->f.check != (unsigned short)(*base ^ HG_ST_KEY(w->f.state)))
		return -1;
	return w->f.state;
}

static inline int hg_hdr_state(const void *cs)
{
	union hg_hdr_w w;
	unsigned short base;

	return hg_hdr_read(cs, &w, &base);
}

/* LIVE -> FREE in one CAS: 1 if this free won, 0 if not (then touch nothing);
 * relaxed is enough: only gpool_push(), under hb->lock, shares a FREE cell */
static inline int hg_hdr_claim_free(void *cs, unsigned int live,
                                    unsigned int cls, unsigned short base)
{
	return __atomic_compare_exchange_n(&HG_CELL_AT(cs)->hw, &live,
		hg_hdr_make(cls, HG_ST_FREE, base), 0, __ATOMIC_RELAXED,
		__ATOMIC_RELAXED);
}

/* hg_mem_check tail guard: up to HG_GUARD_LEN bytes past the request, at least
 * one (HG_GUARD_ROOM); the size is kept keyed, so scribbling voids it */
#define HG_GUARD_BYTE 0xcc
#define HG_GUARD_LEN  8
#define HG_GUARD_WORD 0xccccccccccccccccULL
#define HG_GUARD_ROOM (1 + (HG_REQ_TAIL ? sizeof(unsigned int) : 0))

/* @cap payload bytes: where the size is kept, and where the guard ends */
#if HG_REQ_TAIL
#define HG_GUARD_REQ(cs, cap) ((unsigned int *)(void *)((char *)(cs) + \
	HG_CELL_HDR + (cap) - sizeof(unsigned int)))
#else
#define HG_GUARD_REQ(cs, cap) (&HG_CELL_AT(cs)->req)
#endif
#define HG_GUARD_END(cap)     ((cap) - (HG_GUARD_ROOM - 1))

static inline unsigned int hg_guard_key(unsigned short base)
{
	return (unsigned int)base * 0x10001u;
}

/* @size asked for, @size + HG_GUARD_ROOM <= @cap */
static inline void hg_guard_set(void *cs, unsigned short base,
                                unsigned long cap, unsigned long size)
{
	unsigned char *g = (unsigned char *)cs + HG_CELL_HDR + size;
	unsigned long long w = HG_GUARD_WORD;

	*HG_GUARD_REQ(cs, cap) = (unsigned int)size ^ hg_guard_key(base);
	if (HG_GUARD_END(cap) - size >= HG_GUARD_LEN)
		memcpy(g, &w, HG_GUARD_LEN);
	else
		memset(g, HG_GUARD_BYTE, HG_GUARD_END(cap) - size);
}

/* 1 if the guard is intact; @size is the size kept, HG_GUARD_END(@cap) or
 * more when that was overwritten */
static inline int hg_guard_ok(void *cs, unsigned short base,
                              unsigned long cap, unsigned long *size)
{
	const unsigned char *g;
	unsigned long long w;
	unsigned long i;

	*size = *HG_GUARD_REQ(cs, cap) ^ hg_guard_key(base);
	if (*size >= HG_GUARD_END(cap))
		return 0;
	g = (const unsigned char *)cs + HG_CELL_HDR + *size;
	if (HG_GUARD_END(cap) - *size >= HG_GUARD_LEN) {
		memcpy(&w, g, HG_GUARD_LEN);
		return w == HG_GUARD_WORD;
	}
	for (i = 0; i < HG_GUARD_END(cap) - *size; i++)
		if (g[i] != HG_GUARD_BYTE)
			return 0;
	return 1;
}

/* small cells and large frags alike: the tag sits right before the payload */
#ifdef SHM_EXTRA_STATS
#define HG_STATS_IDX(p) (HG_CELL(p)->stat_idx)
#endif

/* class byte of a large-tier fragment (hg_large.c): just past the valid
 * classes, so any other out-of-range byte is still corruption */
#define HG_LARGE_MARKER HG_NCLASSES

#endif /* HG_CELL_H */
