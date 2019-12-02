/*
 * presence module - presence server implementation
 *
 * Copyright (C) 2007 Voice Sistem S.R.L.
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

#ifndef _PRES_BIND_H_
#define _PRES_BIND_H_

#include "event_list.h"
#include "hash.h"
#include "presentity.h"

typedef int (*update_watchers_t)(str pres_uri, pres_ev_t* ev, str* rules_doc);
typedef int (*update_presentity_t)(presentity_t* presentity);
typedef int (*terminate_watchers_t)(str *pres_uri, pres_ev_t* ev);

/* This function may be used to trigger notification (NTOTIFY'es) to all 
 * subscribers/wachers registered for a given presentity. This is basically a
 * virtual PUBLISH (without any SIP request, but with the same behavior).
 * Input data: the presentity SIP URI, the event and the body
 * Returns: 0 upon success, -1 on error
 */
typedef int (*notify_all_on_publish_t)(str *pres_uri, pres_ev_t *ev,
		str *body);


typedef struct presence_api {
	add_event_t add_event;
	contains_event_t contains_event;
	search_event_t search_event;
	get_event_list_t get_event_list;
	update_watchers_t update_watchers_status;
	terminate_watchers_t terminate_watchers;
	update_presentity_t update_presentity;
	/* subs hash table functions */
	new_shtable_t new_shtable;
	destroy_shtable_t destroy_shtable;
	insert_shtable_t insert_shtable;
	search_shtable_t search_shtable;
	delete_shtable_t delete_shtable;
	update_shtable_t update_shtable;
	mem_copy_subs_t  mem_copy_subs;
	update_db_subs_t update_db_subs;
	extract_sdialog_info_t extract_sdialog_info;
	pres_get_sphere_t get_sphere;
	pres_contains_presence_t contains_presence;
	notify_all_on_publish_t notify_all_on_publish;
} presence_api_t;

int bind_presence(presence_api_t* api);

typedef int (*bind_presence_t)(presence_api_t* api);

#endif

