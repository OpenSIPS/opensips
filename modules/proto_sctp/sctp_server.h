/*
 * Copyright (C) 2015 OpenSIPS Solutions
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
 *
 * History
 * --------
 *  2007-06-22 sctp_server.h created, using udp_server.h as template -gmarmon
 *  2015-02-19 migrated to the new proto interfaces (bogdan)
 */

/*!
 * \file
 * \brief SCTP protocol support
 */

#ifndef _MOD_SCTP_sctp_server_h
#define _MOD_SCTP_sctp_server_h

#include "../../ip_addr.h"

int proto_sctp_init_listener(struct socket_info* si);

int proto_sctp_send(struct socket_info *source, char *buf, unsigned len,
		union sockaddr_union* to, unsigned int id);

int proto_sctp_read(struct socket_info *si, int* bytes_read);

#endif
