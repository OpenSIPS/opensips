/*
 * Copyright (C) 2025 OpenSIPS Solutions
 * Copyright (C) 2025 Norm Brandinger <n.brandinger@gmail.com>
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
 * cachedb_url -> NATS server list, for a cachedb_nats configured with
 * cachedb_url only (no nats_url).
 */

#ifndef CACHEDB_NATS_URL_H
#define CACHEDB_NATS_URL_H

#define CDBN_URL_BAD        -1   /* not a usable cachedb_url */
#define CDBN_URL_TLS_DOMAIN -2   /* tls_domain other than "nats" */

/* the tls_mgm client domain the NATS pool takes its TLS settings from */
#define CDBN_TLS_DOMAIN "nats"

/*
 * Build the server list from "nats:group://[user:pass@]h1:p1,h2:p2/[db]
 * [?opts]": "nats://[user:pass@]h1:p1,nats://[user:pass@]h2:p2", with
 * tls:// instead when the options carry tls_domain=nats.  @url need not
 * be NUL-terminated.  Returns the length written to @out (NUL-terminated),
 * or CDBN_URL_BAD / CDBN_URL_TLS_DOMAIN.
 */
int cdbn_url_to_servers(const char *url, int url_len, char *out, int out_size);

#endif
