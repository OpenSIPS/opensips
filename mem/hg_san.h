/*
 * slab allocator with elastic arenas - sanitizer hooks
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

/* ASan/Valgrind (-DHG_VALGRIND) hooks, PRIVATE arenas only: the tools keep
 * state per process, and a shared cell changes hands between processes */

#ifndef hg_san_h
#define hg_san_h

#if defined(__SANITIZE_ADDRESS__)
#define HG_SAN_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define HG_SAN_ASAN 1
#endif
#endif

#if defined(__SANITIZE_THREAD__)
#define HG_SAN_TSAN 1
#elif defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define HG_SAN_TSAN 1
#endif
#endif

#if defined(HG_SAN_ASAN)
#include <sanitizer/asan_interface.h>
#define HG_SAN_ON 1
#define HG_SAN_CLOSE(p, n)  ASAN_POISON_MEMORY_REGION((p), (n))
#define HG_SAN_OPEN(p, n)   ASAN_UNPOISON_MEMORY_REGION((p), (n))
#define HG_SAN_FRESH(p, n)  ASAN_UNPOISON_MEMORY_REGION((p), (n))
#elif defined(HG_VALGRIND)
#include <valgrind/memcheck.h>
#define HG_SAN_ON 1
#define HG_SAN_CLOSE(p, n)  ((void)VALGRIND_MAKE_MEM_NOACCESS((p), (n)))
#define HG_SAN_OPEN(p, n)   ((void)VALGRIND_MAKE_MEM_DEFINED((p), (n)))
/* a payload handed out new holds nothing the caller wrote: undefined, so a
 * read of it before a write is reported */
#define HG_SAN_FRESH(p, n)  ((void)VALGRIND_MAKE_MEM_UNDEFINED((p), (n)))
#else
#define HG_SAN_ON 0
#define HG_SAN_CLOSE(p, n)  ((void)0)
#define HG_SAN_OPEN(p, n)   ((void)0)
#define HG_SAN_FRESH(p, n)  ((void)0)
#endif

#ifdef HG_SAN_TSAN  /* TSan cannot see through hb->lock's futex or spin */
void __tsan_acquire(void *addr);
void __tsan_release(void *addr);
#define HG_TSAN_ACQUIRE(a)  __tsan_acquire((void *)(a))
#define HG_TSAN_RELEASE(a)  __tsan_release((void *)(a))
#else
#define HG_TSAN_ACQUIRE(a)  ((void)0)
#define HG_TSAN_RELEASE(a)  ((void)0)
#endif

/* a free cell's free-list link, the only payload bytes the free lists write */
#define HG_SAN_LINK  (sizeof(void *))

#define HG_SAN_PRIVATE(hb)  (HG_SAN_ON && !(hb)->shared)

#define HG_SAN_PAY(cs)      ((char *)(cs) + HG_CELL_HDR)

/* handed out new: @size bytes open, the rest closed */
#define hg_san_give(hb, cs, cap, size) do { \
		if (HG_SAN_PRIVATE(hb)) { \
			HG_SAN_CLOSE(HG_SAN_PAY(cs), (cap)); \
			HG_SAN_FRESH(HG_SAN_PAY(cs), (size)); \
		} \
	} while (0)

/* kept by a realloc in place: @size bytes open and defined, the rest closed */
#define hg_san_keep(hb, cs, cap, size) do { \
		if (HG_SAN_PRIVATE(hb)) { \
			HG_SAN_CLOSE(HG_SAN_PAY(cs), (cap)); \
			HG_SAN_OPEN(HG_SAN_PAY(cs), (size)); \
		} \
	} while (0)

/* a free cell with the allocator, wherever it sits: closed but for the link */
#define hg_san_take(hb, cs, cap) do { \
		if (HG_SAN_PRIVATE(hb)) { \
			HG_SAN_CLOSE(HG_SAN_PAY(cs), (cap)); \
			HG_SAN_OPEN(HG_SAN_PAY(cs), \
				(cap) < HG_SAN_LINK ? (cap) : HG_SAN_LINK); \
		} \
	} while (0)

/* the allocator about to read or write the whole payload */
#define hg_san_open(hb, cs, cap) do { \
		if (HG_SAN_PRIVATE(hb)) \
			HG_SAN_OPEN(HG_SAN_PAY(cs), (cap)); \
	} while (0)

/* in quarantine: closed entirely */
#define hg_san_close(hb, cs, cap) do { \
		if (HG_SAN_PRIVATE(hb)) \
			HG_SAN_CLOSE(HG_SAN_PAY(cs), (cap)); \
	} while (0)

/* @len bytes at @p leaving the cell tiers, back to the buddy: open again,
 * for the buddy and the large tier to write their structures into */
#define hg_san_release(hb, p, len) do { \
		if (HG_SAN_PRIVATE(hb)) \
			HG_SAN_OPEN((p), (len)); \
	} while (0)

#endif /* hg_san_h */
