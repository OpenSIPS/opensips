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
 */

/*
 * nats_redact.h — URL credential redaction for log lines (split
 * out of nats_pool.h; implementation in nats_redact.c).
 */

#ifndef NATS_REDACT_H
#define NATS_REDACT_H

#include <stddef.h>

/*
 * Redact userinfo (user[:pass]@) from NATS URL strings before logging.
 *
 * Replaces every "user[:pass]@" segment with the literal string
 * "[redacted]" followed by '@'.  The segment is scrubbed whether or not it
 * follows a "scheme://" prefix (a scheme-less "user:pass@host" token still
 * carries credentials).  Handles comma-separated lists of URLs.  URLs
 * without userinfo are copied unchanged.  Always NUL-terminates @out
 * unless out_sz == 0.
 *
 * @param url      Source URL string.  May be NULL.
 * @param out      Destination buffer.  Must be non-NULL if out_sz > 0.
 * @param out_sz   Size of @out in bytes.  If 0, no write is performed.
 *
 * Examples:
 *   nats://user:pass@h:4222         becomes  nats://[redacted]@h:4222
 *   nats://h:4222                   unchanged
 *   nats://h1,nats://u:p@h2         becomes  nats://h1,nats://[redacted]@h2
 *
 * Thread safety: Pure function on caller-provided memory; safe anywhere.
 */
#ifndef NATS_POOL_NO_PROTOTYPES
void nats_redact_url(const char *url, char *out, size_t out_sz);
#endif

/* Suggested stack-buffer size for nats_redact_key() output: namespace
 * token (<= 13 incl. '.') + '~' + 8 hex + '/' + 20-digit length + NUL. */
#define NATS_REDACT_KEY_BUF 48

/*
 * nats_redact_key() -- scrub an AoR-bearing KV row key for logging.
 *
 * usrloc row keys encode the AoR ("usrloc.alice@example.com"), so a raw
 * key in an error log is user-identifying data (PII) even when URL
 * credentials are redacted.  The redacted form keeps enough to correlate
 * repeated failures on the same key without revealing it:
 *
 *   "<ns>.~<fnv1a32>/<len>"   when the leading '.'-terminated token is a
 *                             safe namespace (<= 12 chars of [A-Za-z0-9_-],
 *                             e.g. a configured fts_json_prefix), or
 *   "~<fnv1a32>/<len>"        otherwise (the first token could be an AoR
 *                             fragment -- show nothing literal).
 *
 * NULL key writes "(null)", empty key writes "(empty)".
 *
 * @param key      Source key (NUL-terminated).  May be NULL.
 * @param out      Destination buffer (pkg/stack, caller-owned).  Must be
 *                 non-NULL if out_sz > 0.
 * @param out_sz   Size of @out in bytes.  If 0, no write is performed.
 *                 Output is always NUL-terminated, truncated if needed.
 *
 * Thread safety: Pure function on caller-provided memory; safe anywhere.
 */
#ifndef NATS_POOL_NO_PROTOTYPES
void nats_redact_key(const char *key, char *out, size_t out_sz);
#endif

#endif /* NATS_REDACT_H */
