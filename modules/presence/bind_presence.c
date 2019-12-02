/*
 * presence module - presence server implementation
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
 *
 * History:
 * --------
 *  2007-04-17  initial version (Anca Vamanu)
 */

#include <stdio.h>
#include <stdlib.h>
#include "../../dprint.h"
#include "../../sr_module.h"
#include "presentity.h"
#include "presence.h"
#include "notify.h"
#include "bind_presence.h"

int bind_presence(presence_api_t* api)
{
	if (!api) {
		LM_ERR("Invalid parameter value\n");
		return -1;
	}

	api->add_event = add_event;
	api->contains_event= contains_event;
	api->search_event= search_event;
	api->get_event_list= get_event_list;
	api->update_watchers_status= update_watchers_status;
	api->terminate_watchers= terminate_watchers;
	api->update_presentity = internal_update_presentity;
	api->new_shtable= new_shtable;
	api->destroy_shtable= destroy_shtable;
	api->insert_shtable= insert_shtable;
	api->search_shtable= search_shtable;
	api->delete_shtable= delete_shtable;
	api->update_shtable= update_shtable;
	api->mem_copy_subs= mem_copy_subs;
	api->update_db_subs= update_db_subs;
	api->extract_sdialog_info= extract_sdialog_info;
	api->get_sphere= get_sphere;
	api->contains_presence = contains_presence;
	api->notify_all_on_publish= virtual_notify;
	return 0;
}


