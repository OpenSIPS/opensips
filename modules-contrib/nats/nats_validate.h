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
 * nats_validate.h — subject/key/name validators (split out of
 * nats_pool.h; implementation in nats_validate.c).
 */

#ifndef NATS_VALIDATE_H
#define NATS_VALIDATE_H

/*
 * Validate a NATS subject for use as an outbound publish target.
 *
 * Rejects empty/NULL, embedded NUL, control/whitespace chars, NATS
 * wildcards ('*' and '>'), and ill-formed dot structure (leading,
 * trailing, or consecutive dots).  Length bound is the caller's job
 * (this function is content-only).
 *
 * @param s   Subject bytes (NOT required to be NUL-terminated).
 * @param len Length of @s in bytes.
 *
 * @return 0 if valid for publish, -1 otherwise.
 *
 * Thread safety: Pure function on caller-provided memory.
 */
#ifndef NATS_POOL_NO_PROTOTYPES
int nats_validate_publish_subject(const char *s, int len);
#endif

/*
 * Unified validator for the NATS subject/key/name strings used across the
 * modules.  All modes reject an empty/NULL string, an embedded NUL, control
 * chars (< 0x20, 0x7f) and whitespace.  Mode-specific rules:
 *
 *   NATS_VALIDATE_PUBLISH_SUBJECT  concrete publish target: no wildcards;
 *                                  no leading/trailing/consecutive dots.
 *   NATS_VALIDATE_FILTER_SUBJECT   subscribe filter: dots AND wildcards
 *                                  ('*','>') allowed.
 *   NATS_VALIDATE_STREAM_NAME      single token: no '.', '*', '>', '/', '\'.
 *   NATS_VALIDATE_KV_KEY           the nats.c key alphabet only: letters,
 *                                  digits and . _ - / \ =; no leading,
 *                                  trailing or consecutive dots.
 *
 * Pure function, content-only (re-scans every call -- see the security note
 * on nats_validate_publish_subject).  Returns 0 if valid, -1 otherwise.
 */
typedef enum {
	NATS_VALIDATE_PUBLISH_SUBJECT = 0,
	NATS_VALIDATE_FILTER_SUBJECT,
	NATS_VALIDATE_STREAM_NAME,
	NATS_VALIDATE_KV_KEY,
} nats_validate_mode_t;

/**
 * Validate @s under the rules of @mode (see the mode table above).
 *
 * @param s    Bytes to validate (NOT required to be NUL-terminated);
 *             NULL is rejected.
 * @param len  Length of @s in bytes; <= 0 is rejected.
 * @param mode One of nats_validate_mode_t.
 *
 * @return 0 if valid for @mode, -1 otherwise.
 *
 * Allocation: none.  Locking: none -- pure function on caller-provided
 * memory (no cache by design; see the security note in nats_validate.c).
 * Context: any process or thread (SIP worker, cnats callback thread,
 * MI handler, mod_init).
 */
#ifndef NATS_POOL_NO_PROTOTYPES
int nats_validate(const char *s, int len, nats_validate_mode_t mode);
#endif

#endif /* NATS_VALIDATE_H */
