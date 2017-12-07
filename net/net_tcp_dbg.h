/*
 * Copyright (C) 2017 OpenSIPS Solutions
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

#ifndef __NET_TCP_DBG__
#define __NET_TCP_DBG__

#if defined(DBG_TCPCON) && !defined(DBG_STRUCT_HIST)
#	warning "DBG_TCPCON is useless without DBG_STRUCT_HIST"
#	undef DBG_TCPCON
#	include "../lib/dbg/struct_hist.h"
#elif !defined(DBG_TCPCON) && defined(DBG_STRUCT_HIST)
#	undef DBG_STRUCT_HIST
#	include "../lib/dbg/struct_hist.h"
#	define DBG_STRUCT_HIST
#else
#	include "../lib/dbg/struct_hist.h"
#endif

#endif /* __NET_TCP_DBG__ */
