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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *
 * history:
 * ---------
 *  2012-12-xx  created (razvancrainea)
 */


#ifndef _EV_ROUTE_H_
#define _EV_ROUTE_H_


/* transport protocol name */
#define SCRIPTROUTE_NAME		"route"
#define SCRIPTROUTE_NAME_STR	{ SCRIPTROUTE_NAME, sizeof(SCRIPTROUTE_NAME)-1}

/* module flag */
#define SCRIPTROUTE_FLAG		(1 << 26)

/* separation char */
#define COLON_C				':'

/* maximum length of the socket */
#define EV_SCRIPTROUTE_MAX_SOCK	256

#endif
