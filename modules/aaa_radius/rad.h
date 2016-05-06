/*
 * Copyright (C) 2009 Irina Stanescu
 * Copyright (C) 2009 Voice System
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
 * History
 * --------
 * 2009-07-20    First version (Irina Stanescu)
 * 2009-08-13 	 Second version (Irina Stanescu) - extract_avp added
 */

#ifndef RAD_H
#define RAD_H

#include "../../aaa/aaa.h"

aaa_conn* rad_init_prot(str* aaa_url);

aaa_message* rad_create_message(aaa_conn* rh, int flag);

int rad_destroy_message(aaa_conn* rh, aaa_message* message);

int rad_send_message(aaa_conn* rh, aaa_message* request, aaa_message** reply);

int rad_find(aaa_conn* rh, aaa_map *map, int flag);

int rad_avp_get(aaa_conn* rh, aaa_message* message, aaa_map* attribute,
					void** value, int* val_lenth, int flag);

int rad_avp_add(aaa_conn* rh, aaa_message* message, aaa_map* name, void* value,
					int val_length, int vendor);

int extract_avp(VALUE_PAIR* vp);

#ifdef RADCLI
uint32_t rc_get_ipaddr (char *host);
#endif
#endif
