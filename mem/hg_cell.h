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

/* HG_MALLOC cell header: rounding, size classes, the per-cell header and its state; included by hg_malloc.h, not on its own */

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

/*
 * Cell header, hidden before every returned pointer (like FM_FRAG(p) in
 * f_malloc): pointers go to arbitrary callers via shm_malloc()/pkg_malloc(),
 * so the class can NOT live in-band in the payload. DBG_MALLOC and
 * SHM_EXTRA_STATS are independent build flags; each adds its own slice:
 *
 *   offset 0                          : class id (stamped at carve, immutable)
 *   offset HG_ROUNDTO           (DBG) : file
 *   offset HG_ROUNDTO*2         (DBG) : func
 *   offset HG_ROUNDTO*3         (DBG) : line
 *   offset HG_ROUNDTO+HG_CELL_HDR_DBG
 *          (SHM_EXTRA_STATS)          : statistic_index (mem-group index)
 *   a spare word, where one is left   : the size a guarded cell was asked
 *                                       for (hg_mem_check, see HG_REQ_*)
 *   offset HG_CELL_HDR                : payload; while the cell is FREE its
 *                                       first pointer is the free-list link
 *                                       (cell_next() in hg_arena.c)
 */
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

/*
 * Payload alignment: 8 covers uint64_t/double. HG_ROUNDTO does not imply it:
 * it is 4 on 32-bit ARM, and with cells 32-byte aligned a 4-byte header puts
 * every payload at 4 mod 8 - a fault for the LDREXD/STREXD of gen_lock_t
 * and 64-bit atomics. The padding goes at the END of the header, so no
 * field offset moves.
 */
#define HG_PAYLOAD_ALIGN 8

/*
 * Where a guarded cell keeps the size asked for, without growing the header:
 * HG_REQ_SLOT0 in the unused half of the first HG_ROUNDTO bytes (every
 * 64-bit build), HG_REQ_PAD in the payload padding at the header's end (a
 * 32-bit build with both DBG_MALLOC and SHM_EXTRA_STATS, or neither), else
 * HG_REQ_TAIL in the cell's last 4 bytes, after the guard.
 */
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

/*
 * The header as a struct, so sites name a field instead of computing
 * HG_ROUNDTO * n. The _Static_asserts below pin it to the layout above on
 * every ABI and build configuration.
 */
struct hg_cell_hdr {
	/* the first HG_ROUNDTO bytes: class, state and a checksum over both
	 * and the cell's address (hg_hdr_set()) */
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
	const char    *file;                  /* HG_ROUNDTO */
	const char    *func;                  /* HG_ROUNDTO * 2 */
	unsigned long  line;                  /* HG_ROUNDTO * 3 */
#endif
#ifdef SHM_EXTRA_STATS
	unsigned long  stat_idx;              /* HG_ROUNDTO + HG_CELL_HDR_DBG */
#endif
#if HG_REQ_PAD
	unsigned int   req;                   /* LIVE_G: keyed size (hg_guard_set()) */
#endif
};

#define HG_CELL_HDR_RAW  sizeof(struct hg_cell_hdr)
#define HG_CELL_HDR \
	(((HG_CELL_HDR_RAW + HG_PAYLOAD_ALIGN - 1) / HG_PAYLOAD_ALIGN) \
	 * HG_PAYLOAD_ALIGN)

/* offset of the statistic_index field, valid only when SHM_EXTRA_STATS */
#define HG_CELL_STATS_OFF (HG_ROUNDTO + HG_CELL_HDR_DBG)

/* C++ modules include this header too */
#ifdef __cplusplus
#define HG_STATIC_ASSERT static_assert
#else
#define HG_STATIC_ASSERT _Static_assert
#endif

/* the pins: the documented offsets, and the raw size the arithmetic gave */
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

/*
 * Cell state, in the header and covered by its checksum: whether a CALLER
 * holds the cell, not where the allocator keeps it.
 *
 *   carve                 -> FRESH   (hg_arena.c carve_chunk())
 *   FRESH or FREE -> LIVE            an allocation, the only way in
 *   LIVE          -> FREE            a free, by any process - the only way out
 *
 * LIVE_G is LIVE with a tail guard (hg_mem_check, hg_guard_set()): the mark
 * is the cell's own, so the setting may change while cells of both kinds
 * are live. Every rule below for LIVE holds for LIVE_G (hg_st_live()).
 *
 * Moving a cell between private list, shared pool, quarantine (HG_MALLOC_DBG)
 * or exit drain leaves it FREE (or FRESH). A free requires LIVE and an
 * allocation FRESH or FREE, so a double free is always refused and no cell
 * is handed out twice. A small cell's LIVE -> FREE is one CAS of the header
 * word (hg_hdr_claim_free()): of two racing frees exactly one wins; a large
 * fragment's runs under the arena lock. The values differ from 0x00/0xff
 * and each other, so a zeroed or scribbled header is caught even before the
 * checksum.
 */
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

/*
 * 16-bit check over the cell's address, class and state. Not cryptographic:
 * it catches a neighbour's overflow, a pointer into the middle of a cell and
 * a header copied to another address. base(address, class) XOR key(state)
 * costs one multiply per alloc or free (the hottest path): a state change is
 * a constant XOR, and a checked header is re-stamped from the check's base.
 */
#define HG_ST_KEY(st)  ((unsigned short)((st) * 0x0101u))

static inline unsigned short hg_hdr_base(const void *cs, unsigned int cls)
{
	/* cells are at least 32-aligned, so the class lands in bits the
	 * address leaves to the secret; the multiply carries every input bit
	 * into the top 16 */
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

/* the header word of a cell of class @cls in state @st, from its @base */
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

/*
 * Read the header word once (never torn) and check it: the state, or -1 if
 * it fails. @w and @base come back for re-stamping without hashing again.
 */
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

/*
 * LIVE -> FREE in one compare-and-swap, from the @live word and @base that
 * hg_hdr_read() returned: 1 if this free took the cell, 0 if another free
 * got there first - the caller must then touch nothing (no list, no counter).
 *
 * Relaxed is enough, by the protocol rather than by any CPU's ordering:
 *   1. the CAS alone decides the winner; the loser writes nothing;
 *   2. the winner's later writes (free-list link, HG_MALLOC_DBG poison) go
 *      to its private list or quarantine, read only by its own thread;
 *   3. a FREE cell becomes visible to another process or thread only in
 *      gpool_push(), which always runs with hb->lock held;
 *   4. hb->lock (in the shared mapping) orders, by its release/acquire,
 *      this word and the link before the next owner's gpool_pop().
 * Past this point exactly-once needs no CAS: private lists and quarantine
 * have one owning thread each, and the shared pool is under the lock.
 */
static inline int hg_hdr_claim_free(void *cs, unsigned int live,
                                    unsigned int cls, unsigned short base)
{
	return __atomic_compare_exchange_n(&HG_CELL_AT(cs)->hw, &live,
		hg_hdr_make(cls, HG_ST_FREE, base), 0, __ATOMIC_RELAXED,
		__ATOMIC_RELAXED);
}

/*
 * hg_mem_check's tail guard, on a LIVE_G cell: the size asked for is kept
 * (HG_REQ_*), keyed by the header's base so a scribbled one reads as no size
 * at all, and the HG_GUARD_LEN bytes after the request - fewer where the
 * cell ends sooner, never none: the allocation is sized HG_GUARD_ROOM bytes
 * up - are HG_GUARD_BYTE. A write past the request changes them; the free
 * and the realloc see it.
 */
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

/* valid only when SHM_EXTRA_STATS; the same for small cells and large frags,
 * since the tag always sits right before the payload */
#ifdef SHM_EXTRA_STATS
#define HG_STATS_IDX(p) (HG_CELL(p)->stat_idx)
#endif

/* class byte of a large-tier fragment (hg_large.c): the first value past the
 * valid classes [0, HG_NCLASSES), so any other out-of-range byte is still
 * corruption */
#define HG_LARGE_MARKER HG_NCLASSES

#endif /* HG_CELL_H */
