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

#include "cachedb_local_evi.h"
#include "../../dprint.h"
#include "../../mem/mem.h"

event_id_t ei_lcache_expired_id = EVI_ERROR;

static evi_params_p lcache_expired_params;
static evi_param_p lcache_ev_key;
static evi_param_p lcache_ev_value;
static evi_param_p lcache_ev_collection;

int lcache_event_init(void)
{
	ei_lcache_expired_id = evi_publish_event(
		str_init(LCACHE_EV_EXPIRED));
	if (ei_lcache_expired_id == EVI_ERROR) {
		LM_ERR("cannot register %s event\n", LCACHE_EV_EXPIRED);
		return -1;
	}

	lcache_expired_params = pkg_malloc(sizeof(evi_params_t));
	if (!lcache_expired_params) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}
	memset(lcache_expired_params, 0, sizeof(evi_params_t));

	lcache_ev_key = evi_param_create(lcache_expired_params,
		_str(LCACHE_EV_PARAM_KEY));
	if (!lcache_ev_key)
		goto error;

	lcache_ev_value = evi_param_create(lcache_expired_params,
		_str(LCACHE_EV_PARAM_VALUE));
	if (!lcache_ev_value)
		goto error;

	lcache_ev_collection = evi_param_create(lcache_expired_params,
		_str(LCACHE_EV_PARAM_COLLECTION));
	if (!lcache_ev_collection)
		goto error;

	return 0;

error:
	LM_ERR("cannot create event parameter\n");
	return -1;
}

void lcache_raise_expired_event(const str *key, const str *value,
		const str *collection)
{
	if (ei_lcache_expired_id == EVI_ERROR || !evi_probe_event(ei_lcache_expired_id))
		return;

	if (evi_param_set_str(lcache_ev_key, key) < 0) {
		LM_ERR("cannot set key parameter\n");
		return;
	}

	if (evi_param_set_str(lcache_ev_value, value) < 0) {
		LM_ERR("cannot set value parameter\n");
		return;
	}

	if (evi_param_set_str(lcache_ev_collection, collection) < 0) {
		LM_ERR("cannot set collection parameter\n");
		return;
	}

	if (evi_raise_event(ei_lcache_expired_id, lcache_expired_params) < 0)
		LM_ERR("cannot raise %s event\n", LCACHE_EV_EXPIRED);
}
