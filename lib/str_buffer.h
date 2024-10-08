/*
 * str_buffer.h - A str_buffer for building strings without knowing the size.
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


#ifndef STR_BUFFER_H_
#define STR_BUFFER_H_

#include "../str.h"

/** start storage chunk size, exponent for the power of two */
#define BUFFER_START_BLOCK_SIZE 10
/** resize threshold */
#define BUFFER_SCALE_PERCENT 0.9

/**
 * @brief Structure storing the str_buffer data.
 *
 */
typedef struct _str_buffer
{
	str storage;
	int scaling;
	int error;
} str_buffer;

/**
 * @brief Create a new str_buffer.
 *
 * @return NULL or new str_buffer
 */
str_buffer *new_str_buffer(void);
/**
 * @brief Destroy a given str_buffer.
 *
 * @param buf str_buffer to destroy
 */
void free_str_buffer(str_buffer *buf);

/**
 * @brief Test whether there were issues while filling the str_buffer.
 *
 * @param buf str_buffer to test
 * @return 1 if issues exists else 0
 */
int str_buffer_has_error(str_buffer *buf);

/**
 * @brief Append a given str to the str_buffer.
 *
 * @param buf str_buffer where to append
 * @param src str to append
 * @return 1 on success else 0
 */
int str_buffer_append_str(str_buffer *buf, str *src);
/**
 * @brief Append a given char* with len to the str_buffer.
 *
 * @param buf str_buffer where to append
 * @param src char* to append
 * @param len length of the char*
 * @return 1 on success else 0
 */
int str_buffer_append_char_ptr(str_buffer *buf, char *src, int len);
/**
 * @brief Append a give str format with replaced values to the str_buffer.
 *
 * @param buf     str_buffer where to append
 * @param src     str format to append
 * @param VARARGS replacement for the format
 * @return 1 on success else 0
 */
int str_buffer_append_str_fmt(str_buffer *buf, str *src, ...);
/**
 * @brief Append a given char* format with replaced values to the str_buffer.
 *
 * @param buf     str_buffer where to append
 * @param src     char* format to append
 * @param len     length of the char*
 * @param VARARGS replacement for the format
 * @return 1 on success else 0
 */
int str_buffer_append_char_ptr_fmt(str_buffer *buf, char *src, int len, ...);
/**
 * @brief Append a give int to the str_buffer.
 *
 * @param buf str_buffer where to append
 * @param val int to append
 * @return 1 on success else 0
 */
int str_buffer_append_int(str_buffer *buf, int val);

/**
 * @brief Save str_buffer content as str.
 *
 * @param buf  str_buffer to save
 * @param dest str where to save str_buffer content
 * @return 1 on success else 0
 */
int str_buffer_to_str(str_buffer *buf, str *dest);
/**
 * @brief Save str_buffer content as char*.
 *
 * @param buf  str_buffer to save
 * @param dest char* where to save str_buffer content
 * @param len  if not null len will be filled with the char pointer length
 * @return 1 on success else 0
 */
int str_buffer_to_char_ptr(str_buffer *buf, char **dest, int *len);

#endif
