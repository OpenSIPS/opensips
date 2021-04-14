/*
 * Copyright (C) 2020 Maksym Sobolyev
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

#if !defined(__FreeBSD__)
#ifndef _BSD_SOURCE
#define _BSD_SOURCE             /* See feature_test_macros(7) */
#endif
#include <endian.h>
#else
#include <sys/endian.h>
#endif

#include <inttypes.h>
#include <assert.h>
#include <string.h>

#define markbetween(x,m,n) \
   ({const typeof(x) cFF = ~(typeof(x))0, c01 = cFF / 255; (((c01*(127+(n))-((x)&c01*127))&~(x)&(((x)&c01*127)+c01*(127-(m))))&c01*128);})

#define nibbleswap(val) ( \
    { \
        const typeof(val) mask = (~(typeof(val))0 / 255) * 0x0f; \
        typeof(val) t =  (val >> 4) & mask; \
        (t | ((val << 4) & (mask << 4))); \
    } \
)


static inline uint64_t cvt_step(uint64_t val, uint64_t msk, int shft)
{
    uint64_t k = val & (msk << shft);
    return (((k << shft) | k) ^ val);
}

#define VECTOR_BITS_MAX 256
#define VECTOR_BYTES(bytelen) (bytelen > (VECTOR_BITS_MAX / 8) ?  (VECTOR_BITS_MAX / 8) : bytelen)

static inline int bcmp_hex128(const char *bin, const char *hex, int hashlen)
{
	const int inelem = VECTOR_BYTES(hashlen) / sizeof(uint64_t);
	uint64_t base;
	uint64_t inws[inelem];
	int i, ib, b;

	assert(hashlen >= sizeof(inws) && (hashlen % sizeof(inws) == 0));
	memset(&base, '0', sizeof(base));
	for (i = 0; i < hashlen; i += sizeof(inws)) {
		uint64_t outw[inelem * 2];
		memcpy(&inws, bin + i, sizeof(inws));
		for (ib = 0; ib < inelem; ib++) {
			uint64_t inw = nibbleswap(htole64(inws[ib]));
			for (b = 0; b < 2; b++) {
				uint64_t addmask, ow;
				ow = cvt_step(inw >> (32 * b) & 0xffffffff, 0x0000ffff, 16);
				ow = cvt_step(ow, 0x00ff000000ff, 8);
				ow = cvt_step(ow, 0x0f000f000f000f, 4);
				addmask = base + (markbetween(ow, 9, 16) >> 7) * ('a' - '0' - 0x0a);
				ow += addmask;
				outw[ib * 2 + b] = le64toh(ow);
			}
		}
		if (bcmp(hex + (i * 2), &outw, sizeof(outw)) != 0)
			return(1);
	}

	return (0);
}

static inline void cvt_hex128(const char *bin, char *hex, int hashlen, int hashhexlen)
{
	const int inelem = VECTOR_BYTES(hashlen) / sizeof(uint64_t);
	uint64_t base;
	uint64_t inws[inelem];
	int i, ib, b;

	assert(hashlen >= sizeof(inws) && (hashlen % sizeof(inws) == 0));
	assert(hashhexlen >= (hashlen * 2));
	memset(&base, '0', sizeof(base));
	for (i = 0; i < hashlen; i += sizeof(inws)) {
		uint64_t outw[inelem * 2];
		memcpy(&inws, bin + i, sizeof(inws));
		for (ib = 0; ib < inelem; ib++) {
			uint64_t inw = nibbleswap(htole64(inws[ib]));
			for (b = 0; b < 2; b++) {
				uint64_t addmask, ow;
				ow = cvt_step(inw >> (32 * b) & 0xffffffff, 0x0000ffff, 16);
				ow = cvt_step(ow, 0x00ff000000ff, 8);
				ow = cvt_step(ow, 0x0f000f000f000f, 4);
				addmask = base + (markbetween(ow, 9, 16) >> 7) * ('a' - '0' - 0x0a);
				ow += addmask;
				outw[ib * 2 + b] = le64toh(ow);
			}
		}
		memcpy(hex + (i * 2), &outw, sizeof(outw));
	}
}
