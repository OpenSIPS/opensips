/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * modules/cachedb_tarantool/msgpuck.h
 * Lightweight, zero-dependency MessagePack encoder and decoder header
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef MSGPUCK_H_INCLUDED
#define MSGPUCK_H_INCLUDED

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

#if defined(__cplusplus)
extern "C" {
#endif

/* MessagePack Format Descriptors */
#define MP_FIXINT_MAX  127
#define MP_FIXMAP      0x80
#define MP_FIXARRAY    0x90
#define MP_FIXSTR      0xa0
#define MP_NIL         0xc0
#define MP_FALSE       0xc2
#define MP_TRUE        0xc3
#define MP_BIN8        0xc4
#define MP_BIN16       0xc5
#define MP_BIN32       0xc6
#define MP_UINT8       0xcc
#define MP_UINT16      0xcd
#define MP_UINT32      0xce
#define MP_UINT64      0xcf
#define MP_INT8        0xd0
#define MP_INT16       0xd1
#define MP_INT32       0xd2
#define MP_INT64       0xd3
#define MP_STR8        0xd9
#define MP_STR16       0xda
#define MP_STR32       0xdb
#define MP_ARRAY16     0xdc
#define MP_ARRAY32     0xdd
#define MP_MAP16       0xde
#define MP_MAP32       0xdf

static inline char *mp_encode_nil(char *data)
{
	*data++ = (char)MP_NIL;
	return data;
}

static inline char *mp_encode_bool(char *data, bool val)
{
	*data++ = val ? (char)MP_TRUE : (char)MP_FALSE;
	return data;
}

static inline char *mp_encode_uint(char *data, uint64_t num)
{
	if (num <= 0x7f) {
		*data++ = (char)num;
	} else if (num <= 0xff) {
		*data++ = (char)MP_UINT8;
		*data++ = (char)num;
	} else if (num <= 0xffff) {
		*data++ = (char)MP_UINT16;
		*data++ = (char)(num >> 8);
		*data++ = (char)num;
	} else if (num <= 0xffffffffULL) {
		*data++ = (char)MP_UINT32;
		*data++ = (char)(num >> 24);
		*data++ = (char)(num >> 16);
		*data++ = (char)(num >> 8);
		*data++ = (char)num;
	} else {
		int i;
		*data++ = (char)MP_UINT64;
		for (i = 7; i >= 0; --i)
			*data++ = (char)(num >> (i * 8));
	}
	return data;
}

static inline char *mp_encode_str(char *data, const char *str, uint32_t len)
{
	if (len <= 31) {
		*data++ = (char)(MP_FIXSTR | len);
	} else if (len <= 0xff) {
		*data++ = (char)MP_STR8;
		*data++ = (char)len;
	} else if (len <= 0xffff) {
		*data++ = (char)MP_STR16;
		*data++ = (char)(len >> 8);
		*data++ = (char)len;
	} else {
		*data++ = (char)MP_STR32;
		*data++ = (char)(len >> 24);
		*data++ = (char)(len >> 16);
		*data++ = (char)(len >> 8);
		*data++ = (char)len;
	}
	if (str && len > 0) {
		memcpy(data, str, (size_t)len);
		data += len;
	}
	return data;
}

static inline char *mp_encode_bin(char *data, const char *bin, uint32_t len)
{
	if (len <= 0xff) {
		*data++ = (char)MP_BIN8;
		*data++ = (char)len;
	} else if (len <= 0xffff) {
		*data++ = (char)MP_BIN16;
		*data++ = (char)(len >> 8);
		*data++ = (char)len;
	} else {
		*data++ = (char)MP_BIN32;
		*data++ = (char)(len >> 24);
		*data++ = (char)(len >> 16);
		*data++ = (char)(len >> 8);
		*data++ = (char)len;
	}
	if (bin && len > 0) {
		memcpy(data, bin, (size_t)len);
		data += len;
	}
	return data;
}

static inline char *mp_encode_array(char *data, uint32_t size)
{
	if (size <= 15) {
		*data++ = (char)(MP_FIXARRAY | size);
	} else if (size <= 0xffff) {
		*data++ = (char)MP_ARRAY16;
		*data++ = (char)(size >> 8);
		*data++ = (char)size;
	} else {
		*data++ = (char)MP_ARRAY32;
		*data++ = (char)(size >> 24);
		*data++ = (char)(size >> 16);
		*data++ = (char)(size >> 8);
		*data++ = (char)size;
	}
	return data;
}

static inline char *mp_encode_map(char *data, uint32_t size)
{
	if (size <= 15) {
		*data++ = (char)(MP_FIXMAP | size);
	} else if (size <= 0xffff) {
		*data++ = (char)MP_MAP16;
		*data++ = (char)(size >> 8);
		*data++ = (char)size;
	} else {
		*data++ = (char)MP_MAP32;
		*data++ = (char)(size >> 24);
		*data++ = (char)(size >> 16);
		*data++ = (char)(size >> 8);
		*data++ = (char)size;
	}
	return data;
}

/* --- MessagePack Decoding Primitives --- */

static inline uint64_t mp_decode_uint(const char **data)
{
	const uint8_t *p = (const uint8_t *)*data;
	uint8_t c = *p++;
	uint64_t val = 0;

	if (c <= 0x7f) {
		val = c;
	} else if (c == MP_UINT8) {
		val = *p++;
	} else if (c == MP_UINT16) {
		val = ((uint64_t)p[0] << 8) | p[1];
		p += 2;
	} else if (c == MP_UINT32) {
		val = ((uint64_t)p[0] << 24) | ((uint64_t)p[1] << 16) | ((uint64_t)p[2] << 8) | p[3];
		p += 4;
	} else if (c == MP_UINT64) {
		int i;
		for (i = 0; i < 8; i++)
			val = (val << 8) | *p++;
	}
	*data = (const char *)p;
	return val;
}

static inline const char *mp_decode_str(const char **data, uint32_t *len)
{
	const uint8_t *p = (const uint8_t *)*data;
	uint8_t c = *p++;
	uint32_t l = 0;
	const char *s = NULL;

	if ((c & 0xe0) == MP_FIXSTR) {
		l = c & 0x1f;
	} else if (c == MP_STR8) {
		l = *p++;
	} else if (c == MP_STR16) {
		l = ((uint32_t)p[0] << 8) | p[1];
		p += 2;
	} else if (c == MP_STR32) {
		l = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
		p += 4;
	}
	s = (const char *)p;
	p += l;
	if (len)
		*len = l;
	*data = (const char *)p;
	return s;
}

static inline uint32_t mp_decode_array(const char **data)
{
	const uint8_t *p = (const uint8_t *)*data;
	uint8_t c = *p++;
	uint32_t size = 0;

	if ((c & 0xf0) == MP_FIXARRAY) {
		size = c & 0x0f;
	} else if (c == MP_ARRAY16) {
		size = ((uint32_t)p[0] << 8) | p[1];
		p += 2;
	} else if (c == MP_ARRAY32) {
		size = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
		p += 4;
	}
	*data = (const char *)p;
	return size;
}

static inline uint32_t mp_decode_map(const char **data)
{
	const uint8_t *p = (const uint8_t *)*data;
	uint8_t c = *p++;
	uint32_t size = 0;

	if ((c & 0xf0) == MP_FIXMAP) {
		size = c & 0x0f;
	} else if (c == MP_MAP16) {
		size = ((uint32_t)p[0] << 8) | p[1];
		p += 2;
	} else if (c == MP_MAP32) {
		size = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
		p += 4;
	}
	*data = (const char *)p;
	return size;
}

static inline void mp_next(const char **data)
{
	const uint8_t *p = (const uint8_t *)*data;
	uint8_t c = *p++;
	uint32_t i, count;

	if (c <= 0x7f || c >= 0xe0) {
		/* positive/negative fixint */
	} else if ((c & 0xe0) == MP_FIXSTR) {
		p += (c & 0x1f);
	} else if ((c & 0xf0) == MP_FIXARRAY) {
		count = c & 0x0f;
		*data = (const char *)p;
		for (i = 0; i < count; i++)
			mp_next(data);
		return;
	} else if ((c & 0xf0) == MP_FIXMAP) {
		count = (c & 0x0f) * 2;
		*data = (const char *)p;
		for (i = 0; i < count; i++)
			mp_next(data);
		return;
	} else {
		switch (c) {
		case MP_NIL:
		case MP_FALSE:
		case MP_TRUE:
			break;
		case MP_UINT8:
		case MP_INT8:
			p += 1;
			break;
		case MP_UINT16:
		case MP_INT16:
			p += 2;
			break;
		case MP_UINT32:
		case MP_INT32:
			p += 4;
			break;
		case MP_UINT64:
		case MP_INT64:
			p += 8;
			break;
		case MP_STR8:
		case MP_BIN8:
			p += 1 + *p;
			break;
		case MP_STR16:
		case MP_BIN16:
			p += 2 + (((uint32_t)p[0] << 8) | p[1]);
			break;
		case MP_STR32:
		case MP_BIN32:
			p += 4 + (((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]);
			break;
		case MP_ARRAY16:
			count = ((uint32_t)p[0] << 8) | p[1];
			p += 2;
			*data = (const char *)p;
			for (i = 0; i < count; i++)
				mp_next(data);
			return;
		case MP_ARRAY32:
			count = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
			p += 4;
			*data = (const char *)p;
			for (i = 0; i < count; i++)
				mp_next(data);
			return;
		case MP_MAP16:
			count = (((uint32_t)p[0] << 8) | p[1]) * 2;
			p += 2;
			*data = (const char *)p;
			for (i = 0; i < count; i++)
				mp_next(data);
			return;
		case MP_MAP32:
			count = (((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]) * 2;
			p += 4;
			*data = (const char *)p;
			for (i = 0; i < count; i++)
				mp_next(data);
			return;
		default:
			break;
		}
	}
	*data = (const char *)p;
}

#if defined(__cplusplus)
}
#endif

#endif /* MSGPUCK_H_INCLUDED */
