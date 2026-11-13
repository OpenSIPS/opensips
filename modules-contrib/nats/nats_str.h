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
 * nats_str.h -- small OpenSIPS-str helpers shared by the NATS modules.
 *
 * Header-only inline helpers (no new symbol in nats.so).  These
 * previously lived as per-module copies (cachedb_nats's str_to_buf /
 * native_str_to_buf, nats_consumer's str_to_cstr); consolidated here so the
 * negative-length guard and the bounds check live in one place.
 *
 * Only the NATS modules include this (they all pull in dprint.h / str.h);
 * modules-contrib/nats's own translation units and standalone unit tests do not.
 */

#ifndef NATS_STR_H
#define NATS_STR_H

#include <string.h>
#include <stdlib.h>

#include "../../str.h"
#include "../../dprint.h"

/**
 * Copy an OpenSIPS str into a caller-provided fixed buffer, NUL-terminating.
 *
 * Guards a negative s->len: it is an int, and the (size_t) cast in the bounds
 * check below would turn a negative value into a huge positive one, silently
 * passing the check and causing a massive memcpy.  A NULL/empty str yields an
 * empty C string.  An embedded NUL is rejected (see the body comment: the
 * result feeds C-string NATS key/subject APIs, which would truncate).
 *
 * @param s        Source str; NULL, NULL s->s or len == 0 yields "".
 * @param buf      Destination buffer, caller-owned (stack/pkg/shm -- the
 *                 caller's choice; nothing is allocated here).
 * @param buf_size Capacity of @buf in bytes, including the NUL; 0 is
 *                 rejected (even "" needs one byte).
 *
 * @return 0 on success (@buf NUL-terminated), -1 on a zero-capacity
 *         buffer, negative length, overflow (s->len >= buf_size) or
 *         embedded NUL; @buf is left untouched on -1.
 *
 * Locking: none.
 * Context: any process or thread; logs via LM_ERR on rejection.
 */
static inline int nats_str_to_buf(const str *s, char *buf, size_t buf_size)
{
	if (buf_size == 0) {
		LM_ERR("zero-capacity buffer\n");
		return -1;
	}
	if (s && s->len < 0) {
		LM_ERR("negative string length (%d)\n", s->len);
		return -1;
	}
	if (!s || !s->s || s->len <= 0) {
		buf[0] = '\0';
		return 0;
	}
	if ((size_t)s->len >= buf_size) {
		LM_ERR("string too long (%d >= %zu)\n", s->len, buf_size);
		return -1;
	}
	/* Reject an embedded NUL: the resulting buffer is handed to C-string
	 * NATS APIs as a KEY / subject / bucket name, which stop at the first
	 * NUL -- a truncated key reads/writes SOMEBODY ELSE'S entry.  Fail
	 * closed (keys never legitimately carry a NUL).  VALUES no longer pass
	 * through here: the set paths ride the length-aware kvStore_Put/
	 * Create/Update, which carry embedded NULs verbatim. */
	if (memchr(s->s, '\0', s->len)) {
		LM_ERR("string contains an embedded NUL (%d bytes) -- refusing "
			"(the NATS C-string KV API would silently truncate it)\n",
			s->len);
		return -1;
	}
	memcpy(buf, s->s, s->len);
	buf[s->len] = '\0';
	return 0;
}

/**
 * Allocate (libc malloc) a NUL-terminated copy of an OpenSIPS str.  Returns
 * NULL on a NULL/empty input or OOM.  The caller frees the result with free().
 * libc malloc (not pkg/shm) so the copy is valid in non-OpenSIPS thread
 * contexts such as the nats_consumer process's borrowed-to-nats.c strings.
 *
 * @param s Source str; NULL, NULL s->s or len <= 0 returns NULL.
 *
 * @return libc-malloc'd NUL-terminated copy owned by the caller, who
 *         frees it with libc free() (NOT pkg_free/shm_free); NULL on
 *         empty input or OOM.  Bytes are copied verbatim: an embedded
 *         NUL survives in memory but truncates any consumer that reads
 *         the result as a C string.
 *
 * Locking: none.
 * Context: any process or thread, including cnats callback threads
 * (the reason for libc malloc over pkg).
 */
static inline char *nats_str_to_cstr(const str *s)
{
	char *out;
	if (!s || s->len <= 0 || !s->s)
		return NULL;
	out = (char *)malloc((size_t)s->len + 1);
	if (!out)
		return NULL;
	memcpy(out, s->s, s->len);
	out[s->len] = '\0';
	return out;
}

#endif /* NATS_STR_H */
