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
 * nats_api.h -- the API of the nats module (nats.so): the connection
 * pool shared by event_nats, cachedb_nats, cachedb_nats_fts and
 * nats_consumer, and the libnats function table.
 *
 * A module binds it in mod_init, the way tls_mgm's API is bound:
 *
 *     struct nats_binds api;
 *     if (load_nats_api(&api) < 0) ...    // needs nats.so loaded
 *
 * and declares the "nats" module as a dependency, so nats.so is
 * initialized first.  The NATS modules use nats_bind_mod.h and
 * nats_bind.h instead, which keep the pool's function names working on
 * top of this API.
 */

#ifndef NATS_API_H
#define NATS_API_H

#include "../../sr_module.h"
#include "nats_api_types.h"

/* Bind the nats module's API.  Returns 0, or -1 when nats.so is not
 * loaded. */
static inline int load_nats_api(struct nats_binds *binds)
{
	load_nats_f load;

	if (!(load = (load_nats_f)find_export("load_nats", 0)))
		return -1;
	return load(binds);
}

#endif /* NATS_API_H */
