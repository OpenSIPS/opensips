/*
 * pua_reginfo module - Presence-User-Agent Handling of reg events
 *
 * Copyright (C) 2011, 2023 Carsten Bock, carsten@ng-voice.com
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

#ifndef _PUA_REGINFO_H
#define _PUA_REGINFO_H

#include "../pua/pua_bind.h"
#include "../usrloc/usrloc.h"
#include "../presence/bind_presence.h"

extern str reginfo_default_domain;
extern str outbound_proxy;
extern str server_address;
extern int publish_reginfo;
extern udomain_t* ul_domain;
extern str ul_identities_key;

extern usrloc_api_t ul;     /*!< Structure containing pointers to usrloc functions*/
extern pua_api_t pua;	    /*!< Structure containing pointers to PUA functions*/
extern presence_api_t pres; /*!< Structure containing pointers to Presence functions*/

extern int reginfo_use_domain;

#endif
