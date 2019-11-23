/*
 * Copyright (C) 2001-2003 FhG Fokus
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


#ifndef _SL_FUNCS_H
#define _SL_FUNCS_H

#include "../../str.h"
#include "../../parser/msg_parser.h"

#define SL_RPL_WAIT_TIME  2  /* in sec */

#define SL_TOTAG_SEPARATOR '.'

int sl_startup();
int sl_shutdown();
int sl_send_reply( struct sip_msg *msg, int code, str *reason, str *totag);
int sl_filter_ACK( struct sip_msg *msg, void *foo);
int sl_reply_error( struct sip_msg *msg );
int sl_gen_totag( struct sip_msg *msg, str *totag);


#endif


