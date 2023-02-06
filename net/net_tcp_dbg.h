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

#ifdef DBG_TCPCON
#include "../lib/dbg/struct_hist.h"
#else

#ifdef shl_init
#undef shl_init
#endif
#define shl_init(...) NULL

#ifdef shl_destroy
#undef shl_destroy
#endif
#define shl_destroy(...)

#ifdef sh_push
#undef sh_push
#endif
#define sh_push(...) NULL

#ifdef sh_unref
#undef sh_unref
#endif
#define sh_unref(...)

#define _sh_log(...) ({0;})

#ifdef sh_log
#undef sh_log
#endif
#define sh_log _sh_log

#ifdef sh_flush
#undef sh_flush
#endif
#define sh_flush(...)
#endif /* DBG_TCPCON */

#endif /* __NET_TCP_DBG__ */
