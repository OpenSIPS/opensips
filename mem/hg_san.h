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

/*
 * Sanitizer hooks. An HG arena is one big mapping, so to ASan or Valgrind
 * every byte is addressable; the hooks below open and close the bytes a
 * caller may touch, and the allocator opens a cell itself before it reads
 * or writes the payload (debug red zone and poison, realloc's copy).
 *
 * PRIVATE arenas only (pkg and a child's own): both tools keep the state per
 * process, so a shared cell closed by the process that freed it would stay
 * closed there after another process allocated it again. Shared memory is
 * covered by HG_MALLOC_DBG's in-band poison (hg_dbg.c).
 *
 * ASan is detected from the compiler; Valgrind's memcheck needs
 * -DHG_VALGRIND and its headers. ThreadSanitizer is told about hb->lock,
 * whose futex or spin implementation it cannot see through. Without a
 * sanitizer every hook compiles to nothing.
 */

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
#elif defined(HG_VALGRIND)
#include <valgrind/memcheck.h>
#define HG_SAN_ON 1
#define HG_SAN_CLOSE(p, n)  ((void)VALGRIND_MAKE_MEM_NOACCESS((p), (n)))
#define HG_SAN_OPEN(p, n)   ((void)VALGRIND_MAKE_MEM_DEFINED((p), (n)))
#else
#define HG_SAN_ON 0
#define HG_SAN_CLOSE(p, n)  ((void)0)
#define HG_SAN_OPEN(p, n)   ((void)0)
#endif

#ifdef HG_SAN_TSAN
void __tsan_acquire(void *addr);
void __tsan_release(void *addr);
#define HG_TSAN_ACQUIRE(a)  __tsan_acquire((void *)(a))
#define HG_TSAN_RELEASE(a)  __tsan_release((void *)(a))
#else
#define HG_TSAN_ACQUIRE(a)  ((void)0)
#define HG_TSAN_RELEASE(a)  ((void)0)
#endif

/* the free-list link at a free cell's payload start, the only payload bytes
 * the free lists write (cell_next()/cell_set_next() in hg_arena.c) */
#define HG_SAN_LINK  (sizeof(void *))

#define HG_SAN_PRIVATE(hb)  (HG_SAN_ON && !(hb)->shared)

/* @cs is a cell start holding @cap payload bytes */
#define HG_SAN_PAY(cs)      ((char *)(cs) + HG_CELL_HDR)

/* handed out: @size bytes open, the rest closed */
#define hg_san_give(hb, cs, cap, size) do { \
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
