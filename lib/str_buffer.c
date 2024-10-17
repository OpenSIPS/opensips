/*
 * str_buffer.c - A str_buffer for building strings without knowing the size.
 *
 * Author: Rick Barenthin (rick@ng-voice.com)
 * Copyright (C) 2024 ng-voice GmbH
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

#include "str_buffer.h"

#include "../mem/mem.h"
#include "../dprint.h"

#include <stdarg.h>

/* generic logging helper for allocation errors in private system memory */
#ifdef SYS_MALLOC
#define PKG_MEM_ERROR LM_ERR("could not allocate private memory from sys pool\n")
#define PKG_MEM_CRITICAL LM_CRIT("could not allocate private memory from sys pool\n")

#ifdef __SUNPRO_C
#define PKG_MEM_ERROR_FMT(...) LM_ERR("could not allocate private memory from sys pool" __VA_ARGS__)
#define PKG_MEM_CRITICAL_FMT(...) LM_CRIT("could not allocate private memory from sys pool" __VA_ARGS__)
#else
#define PKG_MEM_ERROR_FMT(fmt, args...) LM_ERR("could not allocate private memory from sys pool - " fmt , ## args)
#define PKG_MEM_CRITICAL_FMT(fmt, args...) LM_CRIT("could not allocate private memory from sys pool - " fmt , ## args)
#endif

/* generic logging helper for allocation errors in private memory pool */
#else

#define PKG_MEM_ERROR LM_ERR("could not allocate private memory from pkg pool\n")
#define PKG_MEM_CRITICAL LM_CRIT("could not allocate private memory from pkg pool\n")

#ifdef __SUNPRO_C
#define PKG_MEM_ERROR_FMT(...) LM_ERR("could not allocate private memory from pkg pool" __VA_ARGS__)
#define PKG_MEM_CRITICAL_FMT(...) LM_CRIT("could not allocate private memory from pkg pool" __VA_ARGS__)
#else
#define PKG_MEM_ERROR_FMT(fmt, args...) LM_ERR("could not allocate private memory from pkg pool - " fmt , ## args)
#define PKG_MEM_CRITICAL_FMT(fmt, args...) LM_CRIT("could not allocate private memory from pkg pool - " fmt , ## args)
#endif

#endif /* SYS_MALLOC */

/**
 * @brief Resize str_buffer storage if current usage and len will not fit in it.
 *
 * @param buf str_buffer to resize
 * @param len len that needs to fit in str_buffer
 * @return 1 on success else 0
 */
static inline int resizeIfRequired(str_buffer *buf, int len)
{
	if(buf->storage.len + len >= (1 << buf->scaling) * BUFFER_SCALE_PERCENT) {
		char *res = NULL;

		while(buf->storage.len + len
				>= (1 << buf->scaling) * BUFFER_SCALE_PERCENT) {
			++buf->scaling;
		}

		res = pkg_realloc(buf->storage.s, 1 << buf->scaling);
		if(!res) {
			buf->error = 1;
			PKG_MEM_ERROR;
			return 0;
		}

		buf->storage.s = res;
	}

	return 1;
}

/**
 * @brief Calculate the strlen after the replacement in format string.
 *
 * @param fmt  format string
 * @param args argument list
 * @return length of string after the replacement plus 1 because of \0
 */
static inline int lengthAfterReplaced(char *fmt, va_list args)
{
	int len = 0;
	va_list tmpArgs;

	va_copy(tmpArgs, args);
	len = vsnprintf(NULL, 0, fmt, tmpArgs) + 1;
	va_end(tmpArgs);

	return len;
}

/**
 * @brief Append a given format with replaced values to the str_buffer.
 *
 * @param buf  str_buffer where to append
 * @param src  char* format to append
 * @param len  length of the char*
 * @param args replacement for the format
 * @return 1 on success else 0
 */
static inline int str_buffer_append_varg(
		str_buffer *buf, char *src, int len, va_list args)
{
	va_list tmpArgs;
	char *tmp = NULL;
	int replacedLen = 0;

	if(!buf) {
		LM_BUG("Wrong usage passing NULL as the buffer\n");
		return 0;
	}
	if(!src || len == 0) {
		return 1;
	}

	// temp one bigger than original and zero filled, to make sure its zero terminated
	tmp = pkg_malloc(sizeof(char) * len + 1);
	if(!tmp) {
		buf->error = 1;
		PKG_MEM_ERROR;
		return 0;
	}
	memset(tmp, 0, sizeof(char) * len + 1);
	memcpy(tmp, src, len);

	replacedLen = lengthAfterReplaced(tmp, args);
	if(!resizeIfRequired(buf, replacedLen)) {
		pkg_free(tmp);
		return 0;
	}

	va_copy(tmpArgs, args);
	len = vsnprintf(
			buf->storage.s + buf->storage.len, 1 << buf->scaling, tmp, tmpArgs);
	buf->storage.len += len;
	va_end(tmpArgs);

	pkg_free(tmp);

	return 1;
}

str_buffer *new_str_buffer(void)
{
	str_buffer *buf = NULL;
	buf = pkg_malloc(sizeof(str_buffer));
	if(!buf) {
		PKG_MEM_ERROR;
		return NULL;
	}

	buf->storage.s = pkg_malloc(1 << BUFFER_START_BLOCK_SIZE * sizeof(char));
	if(!buf->storage.s) {
		PKG_MEM_ERROR;
		pkg_free(buf);
		return NULL;
	}
	memset(buf->storage.s, 0, 1 << BUFFER_START_BLOCK_SIZE * sizeof(char));

	buf->storage.len = 0;
	buf->scaling = BUFFER_START_BLOCK_SIZE;
	buf->error = 0;

	return buf;
}

void free_str_buffer(str_buffer *buf)
{
	if(!buf) {
		LM_BUG("Wrong usage passing NULL as the buffer\n");
		return;
	}

	if(buf->storage.s) {
		pkg_free(buf->storage.s);
	}

	pkg_free(buf);
}

int str_buffer_has_error(str_buffer *buf)
{
	if(!buf) {
		LM_BUG("Wrong usage passing NULL as the buffer\n");
		return 0;
	}

	return buf->error;
}

int str_buffer_append_str(str_buffer *buf, str *src)
{
	if(!src) {
		return 1;
	}

	return str_buffer_append_char_ptr(buf, src->s, src->len);
}

int str_buffer_append_char_ptr(str_buffer *buf, char *src, int len)
{
	if(!buf) {
		LM_BUG("Wrong usage passing NULL as the buffer\n");
		return 0;
	}
	if(!src || len == 0) {
		return 1;
	}
	if(!resizeIfRequired(buf, len)) {
		return 0;
	}

	memcpy(buf->storage.s + buf->storage.len, src, len);
	buf->storage.len += len;

	return 1;
}

int str_buffer_append_str_fmt(str_buffer *buf, str *src, ...)
{
	int res = 0;
	va_list args;

	if(!src) {
		return 1;
	}

	va_start(args, src);
	res = str_buffer_append_varg(buf, src->s, src->len, args);
	va_end(args);

	return res;
}

int str_buffer_append_char_ptr_fmt(str_buffer *buf, char *src, int len, ...)
{
	int res = 0;
	va_list args;

	va_start(args, len);
	res = str_buffer_append_varg(buf, src, len, args);
	va_end(args);

	return res;
}

int str_buffer_append_int(str_buffer *buf, int val)
{
	return str_buffer_append_char_ptr_fmt(buf, "%d", 2, val);
}

int str_buffer_to_str(str_buffer *buf, str *dest)
{
	if(!dest) {
		LM_BUG("Wrong usage passing NULL as the destination\n");
		return 0;
	}

	return str_buffer_to_char_ptr(buf, &dest->s, &dest->len);
}

int str_buffer_to_char_ptr(str_buffer *buf, char **dest, int *len)
{
	if(!buf) {
		LM_BUG("Wrong usage passing NULL as the buffer\n");
		return 0;
	}
	if(!dest) {
		LM_BUG("Wrong usage passing NULL as the destination\n");
		return 0;
	}

	*dest = pkg_malloc(sizeof(char) * buf->storage.len + 1);
	if(!*dest) {
		PKG_MEM_ERROR;
		return 0;
	}
	memset(*dest, 0, sizeof(char) * buf->storage.len + 1);
	memcpy(*dest, buf->storage.s, buf->storage.len);
	if(len) {
		*len = buf->storage.len;
	}

	return 1;
}
