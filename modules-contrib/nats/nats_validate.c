/*
 * Copyright (C) 2026 OpenSIPS Solutions
 * Copyright (C) 2026 Norm Brandinger <n.brandinger@gmail.com>
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * nats_validate.c — input validators for NATS subject/key strings used
 * across event_nats, cachedb_nats, and nats_consumer.
 *
 * Self-contained: depends only on libc.  No LM_* logging here — callers
 * apply context-appropriate logging on rejection.
 */

#include "nats_pool.h"
#include "nats_validate.h"

/*
 * Validate a NATS subject as it would appear in a publish call.
 *
 * Rejects everything that NATS pub/sub semantics or the wire format
 * cannot tolerate from an *outbound* publisher:
 *   - empty / NULL
 *   - embedded NUL byte
 *   - control chars (< 0x20, 0x7f) and whitespace (' ', '\t')
 *   - wildcards '*' and '>' (publish must target a concrete subject)
 *   - leading dot, trailing dot, consecutive dots (empty token)
 *
 * Allows everything else, including punctuation and high-ASCII bytes
 * (NATS itself does not restrict these for publish).  Callers that
 * want a stricter alphabet should layer their own check on top.
 *
 * Returns 0 if valid, -1 if invalid.
 *
 * SECURITY: this MUST re-scan the bytes on every call.  An earlier
 * version cached the last (pointer, length, result) per thread to
 * avoid re-scanning repeated script literals, but OpenSIPS reuses
 * pkg/static str buffers at the same address across invocations: a
 * buffer previously validated OK could be refilled with same-length,
 * attacker-influenced SIP data containing CR/LF (NATS protocol
 * injection onto the line-oriented "PUB <subject>\r\n" wire) and be
 * served the stale "valid" verdict.  The scan is O(len) on short
 * subjects — cheap — so there is no cache.
 */
int nats_validate(const char *s, int len, nats_validate_mode_t mode)
{
	int i;
	int last_was_dot = 0;

	if (!s || len <= 0)
		return -1;

	/* Publish subjects and KV keys must not start or end with a token
	 * separator. */
	if ((mode == NATS_VALIDATE_PUBLISH_SUBJECT ||
			mode == NATS_VALIDATE_KV_KEY) &&
			(s[0] == '.' || s[len - 1] == '.'))
		return -1;

	for (i = 0; i < len; i++) {
		unsigned char c = (unsigned char)s[i];

		/* common: no NUL / control / whitespace in any mode */
		if (c == '\0')             return -1;
		if (c < 0x20 || c == 0x7f) return -1;
		if (c == ' ' || c == '\t') return -1;

		/* wildcards are a subject token only for subscribe filters */
		if ((c == '*' || c == '>') &&
				mode != NATS_VALIDATE_FILTER_SUBJECT)
			return -1;

		/* KV keys: exactly the alphabet nats.c accepts (kv.c validKey),
		 * so an invalid key fails here with a clear message instead of
		 * inside kvStore_* with "Invalid Argument".  This also keeps ':'
		 * out (reserved as the legacy map-key separator). */
		if (mode == NATS_VALIDATE_KV_KEY &&
				!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				  (c >= '0' && c <= '9') || c == '.' || c == '_' ||
				  c == '-' || c == '/' || c == '\\' || c == '='))
			return -1;

		/* stream/consumer names are a single token: no separators */
		if (mode == NATS_VALIDATE_STREAM_NAME &&
				(c == '.' || c == '/' || c == '\\'))
			return -1;

		/* empty tokens (consecutive dots) are illegal in a publish subject */
		if (c == '.') {
			if (mode == NATS_VALIDATE_PUBLISH_SUBJECT ||
					mode == NATS_VALIDATE_KV_KEY) {
				if (last_was_dot) return -1;
				last_was_dot = 1;
			}
		} else {
			last_was_dot = 0;
		}
	}
	return 0;
}

int nats_validate_publish_subject(const char *s, int len)
{
	return nats_validate(s, len, NATS_VALIDATE_PUBLISH_SUBJECT);
}
