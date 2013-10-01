/*
 * Copyright (C) 2012 OpenSIPS Solutions
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *
 * history:
 * ---------
 *  2012-05-xx  created (razvancrainea)
 */

#ifndef _EV_XMLRPC_H_
#define _EV_XMLRPC_H_

/* transport protocols name */
#define XMLRPC_NAME		"xmlrpc"
#define XMLRPC_STR		{ XMLRPC_NAME, sizeof(XMLRPC_NAME) - 1}

/* module flag */
#define XMLRPC_FLAG		(1 << 27)

#define COLON_C			':'

#endif

#ifdef HAVE_SCHED_YIELD
#include <sched.h>
#else
#include <unistd.h>
/** Fake sched_yield if no unistd.h include is available */
        #define sched_yield()   sleep(0)
#endif
