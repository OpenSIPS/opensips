/*
 * Copyright (C) 2017 OpenSIPS Solutions
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
 * Foundation Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */


#include "../trace_api.h"
#include "trans_trace.h"

int create_trace_message( int id, union sockaddr_union* src,
						union sockaddr_union* dst, int proto, void* dest)
{
	return -1;
}


void add_trace_data( void* message, char* key, str* value)
{
	return;
}

int send_trace_message( void* message, void* destination)
{
	return -1;
}

int trace_message_atonce( int proto, int id, union sockaddr_union* src,
						union sockaddr_union* dst,trans_trace_event event,
						trans_trace_status status, str* data)
{
	return -1;
}
