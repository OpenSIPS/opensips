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

#include "../../dprint.h"
#include "rtpengine_bracket.h"

bencode_item_t *bracket_string_unescape(bencode_buffer_t *buf,
		const char *s, int len)
{
	int i, needs = 0;

	/* fast-path: scan for escape sequences before allocating anything */
	for (i = 0; i < len - 1; i++) {
		if ((s[i] == '-' && s[i + 1] == '-') ||
				(s[i] == '.' && s[i + 1] == '.')) {
			needs = 1;
			break;
		}
	}
	if (!needs)
		/* no escapes found - zero-copy, points directly into input */
		return bencode_string_len(buf, s, len);

	/* slow path: unescape into a stack buffer, then copy into bencode.
	 * output is always <= input length since each 2-char escape becomes 1 */
	char tmp[BRACKET_MAX_LEN];
	int j = 0;

	for (i = 0; i < len; i++) {
		if (i < len - 1 && s[i] == '-' && s[i + 1] == '-') {
			tmp[j++] = '=';
			i++;          /* consume both dashes */
		} else if (i < len - 1 && s[i] == '.' && s[i + 1] == '.') {
			tmp[j++] = ' ';
			i++;          /* consume both dots */
		} else {
			tmp[j++] = s[i];
		}
	}
	/* _dup variant copies tmp into the bencode buffer (tmp is stack) */
	return bencode_string_len_dup(buf, tmp, j);
}

/*
 * Two-pass parser for bracket content.
 *
 * Pass 1: determine type — if '=' appears at bracket-depth 0, it's a dict;
 *         otherwise it's a list.  Ignoring '=' inside nested brackets avoids
 *         misdetection on input like "transcode=[PCMA PCMU]".
 *
 * Pass 2: tokenize on spaces (respecting bracket nesting) and build the
 *         bencode structure.  For dicts, each token is "key=value" where
 *         value may be a nested [...] or a plain string.  For lists, each
 *         token is either a nested [...] or a plain string.
 *
 * Pointer conventions:
 *   s   .. end   — the input range (not null-terminated, bounded by len)
 *   p             — current scan position, always in [s, end]
 *   ks, klen      — key start and length (dict mode)
 *   vs, vlen      — value start and length
 *   d             — bracket nesting depth for bracket-matching loops
 */
bencode_item_t *parse_bracket_value(const char *s, int len,
		bencode_buffer_t *buf, int depth)
{
	const char *end, *p, *ks, *vs;
	int is_dict = 0, d, klen, vlen;
	bencode_item_t *container, *item;

	if (depth > BRACKET_MAX_DEPTH || len > BRACKET_MAX_LEN || !buf)
		return NULL;

	end = s + len;

	/* Pass 1: detect dict vs list — scan for '=' at bracket-depth 0 */
	for (d = 0, p = s; p < end; p++) {
		if (*p == '[') d++;
		else if (*p == ']') { if (--d < 0) return NULL; /* stray ']' */ }
		else if (*p == '=' && d == 0) { is_dict = 1; break; }
	}

	container = is_dict ? bencode_dictionary(buf) : bencode_list(buf);
	if (!container)
		return NULL;

	/* Pass 2: tokenize and build */
	p = s;
	while (p < end) {
		while (p < end && *p == ' ') p++;   /* skip inter-token spaces */
		if (p >= end) break;

		if (is_dict) {
			/* --- dict mode: expect "key=value" pairs --- */

			/* extract key: scan until '=' or space */
			ks = p;
			while (p < end && *p != '=' && *p != ' ') p++;
			klen = p - ks;
			if (klen == 0 || p >= end || *p != '=') {
				/* token without '=' in dict context — skip it */
				if (klen > 0)
					LM_WARN("bare token '%.*s' in bracket dictionary "
							"context (missing '='?), skipping\n",
							klen, ks);
				while (p < end && *p != ' ') p++;
				continue;
			}
			p++; /* advance past '=' to start of value */

			/* extract value */
			if (p < end && *p == '[') {
				/* nested bracket value: find matching ']' */
				vs = p + 1;       /* content starts after the '[' */
				for (d = 0; p < end; p++) {
					if (*p == '[') d++;
					else if (*p == ']' && --d == 0) { p++; break; }
				}
				if (d != 0) return NULL;  /* unmatched '[' */
				/* p now points past ']'; inner content is vs..(p-1)
				 * i.e. between the '[' and ']' exclusive */
				item = parse_bracket_value(vs, (p - 1) - vs,
						buf, depth + 1);
			} else {
				/* plain string value: scan to next space */
				vs = p;
				while (p < end && *p != ' ') p++;
				vlen = p - vs;
				if (vlen == 0) continue;  /* "key=" with no value */
				item = bracket_string_unescape(buf, vs, vlen);
			}
			if (!item) return NULL;
			/* add using the key pointer/length captured earlier */
			if (!bencode_dictionary_add_len(container, ks, klen, item))
				return NULL;
		} else {
			/* --- list mode: expect plain tokens or nested [...] --- */

			if (*p == '[') {
				/* nested bracket: find matching ']' */
				vs = p + 1;
				for (d = 0; p < end; p++) {
					if (*p == '[') d++;
					else if (*p == ']' && --d == 0) { p++; break; }
				}
				if (d != 0) return NULL;
				/* recurse on the content between '[' and ']' */
				item = parse_bracket_value(vs, (p - 1) - vs,
						buf, depth + 1);
			} else {
				/* plain token: scan to next space */
				vs = p;
				while (p < end && *p != ' ') p++;
				item = bracket_string_unescape(buf, vs, p - vs);
			}
			if (!item) return NULL;
			if (!bencode_list_add(container, item))
				return NULL;
		}
	}
	return container;
}
