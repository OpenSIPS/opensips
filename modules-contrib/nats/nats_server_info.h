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
 * MI server-info string policy — the one place the connected-URL string
 * surfaced to MI clients is decided (used by nats_pool_get_server_info(),
 * behaviourally locked by test/test_server_info_redact.c).
 */

#ifndef NATS_SERVER_INFO_H
#define NATS_SERVER_INFO_H

#include <stddef.h>
#include <nats/nats.h>

#include "nats_redact.h"

/* Matches natsConnection_GetConnectedUrl(); injectable so the policy is
 * testable without a broker. */
typedef natsStatus (*nats_conn_url_get_f)(natsConnection *nc,
		char *buf, size_t buf_sz);

/**
 * Build the MI-visible server-info string for a connection.
 *
 * Fetches the connected URL via @get_url and redacts any "user[:pass]@"
 * userinfo (nats_redact_url) before it can reach an MI client
 * (mi_nats_status) — the raw URL can carry the broker password.  Any
 * failure — no connection, no getter, non-OK getter status, no output
 * buffer — degrades to the literal "not connected"; the getter's buffer
 * content is never trusted on a non-OK return (GetConnectedUrl may
 * leave it unterminated).
 *
 * @param nc      Connection handle; only passed through to @get_url.
 *                NULL means not connected.
 * @param get_url URL getter (production: the nats_dl
 *                natsConnection_GetConnectedUrl pointer).  NULL is
 *                tolerated and reads as not connected.
 * @param out     Destination buffer, caller-owned (typically the
 *                caller's static); nothing is allocated.
 * @param out_sz  Capacity of @out in bytes; 0 reads as not connected.
 *
 * @return @out (NUL-terminated, redacted, truncated if needed) on
 *         success; the static literal "not connected" otherwise.  The
 *         caller must not write through the returned pointer.
 *
 * Locking: none.
 * Context: any process; no broker I/O beyond the injected getter.
 */
static inline const char *nats_pool_server_info_build(natsConnection *nc,
		nats_conn_url_get_f get_url, char *out, size_t out_sz)
{
	char raw[512];

	if (!nc || !get_url || !out || out_sz == 0)
		return "not connected";

	/* Init defensively: on a non-OK status GetConnectedUrl may leave the
	 * buffer unterminated, and nats_redact_url() would then read
	 * uninitialised stack. */
	raw[0] = '\0';
	if (get_url(nc, raw, sizeof(raw)) != NATS_OK)
		return "not connected";
	raw[sizeof(raw) - 1] = '\0';

	/* Redact any user:pass@ credentials before returning — this value is
	 * surfaced to MI clients (mi_nats_status) and must not leak the
	 * broker password. */
	nats_redact_url(raw, out, out_sz);
	return out;
}

#endif /* NATS_SERVER_INFO_H */
