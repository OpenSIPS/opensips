/*
 * Radius based peering module .h file
 *
 * Copyright (C) 2008 Juha Heinanen
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
 */

#ifndef _PEERING_H_
#define _PEERING_H_

extern aaa_map attrs[];
extern aaa_map vals[];
extern aaa_conn *conn;
extern aaa_prot proto;

extern int verify_destination_service_type;
extern int verify_source_service_type;

#endif /* _PEERING_H_ */
