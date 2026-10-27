/*
 * Copyright (C) 2026 OpenSIPS Solutions
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

#ifndef _CACHEDB_LOCAL_EVI_H_
#define _CACHEDB_LOCAL_EVI_H_

#include "../../evi/evi_modules.h"
#include "../../evi/evi_params.h"

#define LCACHE_EV_EXPIRED "E_CACHEDB_LOCAL_EXPIRED"

#define LCACHE_EV_PARAM_KEY        "key"
#define LCACHE_EV_PARAM_VALUE      "value"
#define LCACHE_EV_PARAM_COLLECTION "collection"

extern event_id_t ei_lcache_expired_id;

int lcache_event_init(void);
void lcache_raise_expired_event(const str *key, const str *value,
		const str *collection);

#endif /* _CACHEDB_LOCAL_EVI_H_ */
