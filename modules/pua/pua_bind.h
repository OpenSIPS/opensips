/*
 * pua module - presence user agent module
 *
 * Copyright (C) 2006 Voice Sistem S.R.L.
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


#ifndef PUA_API_H
#define PUA_API_H
#include "send_subscribe.h"
#include "send_publish.h"
#include "pua_callback.h"
#include "hash.h"

typedef struct pua_api {
	send_subscribe_t send_subscribe;
	send_publish_t send_publish;
	register_puacb_t register_puacb;
	query_dialog_t is_dialog;
	get_record_id_t get_record_id;
	add_pua_event_t add_event;
	get_subs_list_t get_subs_list;
} pua_api_t;

typedef int (*bind_pua_t)(pua_api_t* api);

static inline int load_pua_api( pua_api_t *api)
{
	bind_pua_t bind_pua;

	/* import the pua auto-loading function */
	if ( !(bind_pua= (bind_pua_t)find_export("bind_pua",0))) {
		LM_ERR("failed to import bind_pua\n");
		return -1;
	}
	/* let the auto-loading function load all pua stuff */
	if (bind_pua(api) < 0)
	{
		LM_ERR("Can't bind pua\n");
		return -1;
	}
	return 0;
}

#endif
