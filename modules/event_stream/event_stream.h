/*
 * Copyright (C) 2018 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

#ifndef _EV_STREAM_H_
#define _EV_STREAM_H_

/* transport protocols name */
#define TCP_NAME	"tcp"
#define TCP_STR		{ TCP_NAME, sizeof(TCP_NAME) - 1}

/* module flag */
#define STREAM_FLAG		(1 << 23)

#define COLON_C			':'
#define SLASH_C			'/'

#ifdef HAVE_SCHED_YIELD
#include <sched.h>
#else
#include <unistd.h>
/** Fake sched_yield if no unistd.h include is available */
        #define sched_yield()   sleep(0)
#endif /* HAVE_SCHED_YIELD */

#endif
