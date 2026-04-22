/*
 * Copyright (C) 2026 OpenSIPS Foundation
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

#ifndef TLS_SHARED_DATA_H
#define TLS_SHARED_DATA_H

#include <string.h>

#include "../../dprint.h"
#include "../../mem/shm_mem.h"
#include "../../net/tcp_conn_defs.h"

static inline void tls_shared_info_free(struct tcp_connection *c)
{
	struct tcp_tls_info *info;

	if (!c || !c->shared_data)
		return;

	info = c->shared_data;

	if (info->version) {
		shm_free(info->version);
		info->version = 0;
	}
	if (info->cipher_name) {
		shm_free(info->cipher_name);
		info->cipher_name = 0;
	}
	if (info->cipher_desc) {
		shm_free(info->cipher_desc);
		info->cipher_desc = 0;
	}

	info->bits = 0;
	info->peer_verified = 0;

	shm_free(info);
	c->shared_data = 0;
}

static inline int tls_shared_info_store(struct tcp_connection *c,
		const char *version, const char *cipher_name,
		const char *cipher_desc, unsigned int bits,
		unsigned char peer_verified)
{
	struct tcp_tls_info *info;

	if (!c)
		return -1;

	info = c->shared_data;
	if (!info) {
		info = shm_malloc(sizeof(*info));
		if (!info) {
			LM_ERR("failed to allocate shared TLS metadata\n");
			return -1;
		}
		memset(info, 0, sizeof(*info));
		c->shared_data = info;
	} else if (info->version || info->cipher_name || info->cipher_desc) {
		return 0;
	}

	if (version) {
		info->version = shm_strdup(version);
		if (!info->version)
			goto error;
	}

	if (cipher_name) {
		info->cipher_name = shm_strdup(cipher_name);
		if (!info->cipher_name)
			goto error;
	}

	if (cipher_desc) {
		info->cipher_desc = shm_strdup(cipher_desc);
		if (!info->cipher_desc)
			goto error;
	}

	info->bits = bits;
	info->peer_verified = peer_verified;
	return 0;

error:
	tls_shared_info_free(c);
	return -1;
}

#endif /* TLS_SHARED_DATA_H */
