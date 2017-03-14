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

#ifndef _NET_trans_trace_h
#define _NET_trans_trace_h

typedef enum _trans_trace_status { TRANS_TRACE_SUCCESS, TRANS_TRACE_FAILURE }
	trans_trace_status;

typedef enum _trans_trace_event { TRANS_TRACE_ACCEPTED,
	TRANS_TRACE_CONNECT_START, TRANS_TRACE_CONNECTED,
	TRANS_TRACE_CLOSED, TRANS_TRACE_STATS}
	trans_trace_event;


int create_trace_message( int id, union sockaddr_union* src, union sockaddr_union* dst,
	int proto, void* dest);

void add_trace_data( void* message, char* key, str* value);

int send_trace_message( void* message, void* destination);

int create_send_trace_message( int id, union sockaddr_union* src, union sockaddr_union* dst,
		trans_trace_event event, trans_trace_status status, str* data);

#endif

