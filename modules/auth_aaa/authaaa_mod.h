/*
 * Digest Authentication - generic AAA support
 *
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2009 Irina Stanescu
 * Copyright (C) 2009 Voice Systems
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */


#ifndef AUTHAAA_MOD_H
#define AUTHAAA_MOD_H

#include "../auth/api.h"
#include "../../aaa/aaa.h"

extern aaa_map attrs[];
extern aaa_map vals[];
extern aaa_conn *conn;
extern aaa_prot proto;

extern int use_ruri_flag;

extern auth_api_t auth_api;

#endif /* AUTHAAA_MOD_H */
