/*
 * Copyright (C) 2025 OpenSIPS Solutions
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

#ifndef _RTPENGINE_BRACKET_H_
#define _RTPENGINE_BRACKET_H_

#include "bencode.h"

#define BRACKET_MAX_DEPTH 8
#define BRACKET_MAX_LEN   4096

/*
 * Create a bencode string from a bracket token, unescaping '--' to '='
 * and '..' to ' ' (matching rtpengine daemon's str_dup_escape behavior).
 * Falls through to zero-copy bencode_string_len() when no escapes present.
 */
bencode_item_t *bracket_string_unescape(bencode_buffer_t *buf,
		const char *s, int len);

/*
 * Parse content inside brackets into a bencode list or dictionary.
 * Input: the content between '[' and ']' (not including the brackets).
 * Determines list vs dict by scanning for '=' at bracket-depth 0.
 * Returns NULL on error (OOM, malformed input, depth/length exceeded).
 */
bencode_item_t *parse_bracket_value(const char *s, int len,
		bencode_buffer_t *buf, int depth);

#endif /* _RTPENGINE_BRACKET_H_ */
