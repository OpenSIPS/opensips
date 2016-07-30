/*
 * pua_urloc module - usrloc pua module
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

#ifndef _PUA_UL_
#define _PUA_UL_
#include "../pua/pua_bind.h"

send_publish_t pua_send_publish;
send_subscribe_t pua_send_subscribe;
void ul_publish(ucontact_t* c, int type, void* param);
int pua_set_publish(struct sip_msg* , char*, char*);

extern str pres_prefix;
extern str presence_server;
extern int pul_status_idx;

#endif
