/*
 * Copyright (C) 2011 OpenSIPS Solutions
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
 *  2011-05-xx  created (razvancrainea)
 */


#ifndef _EV_DATAGRAM_H_
#define _EV_DATAGRAM_H_

/* transport protocols name */
#define UDP_NAME	"udp"
#define UDP_STR		{ UDP_NAME, sizeof(UDP_NAME) - 1}
#define UNIX_NAME	"unix"
#define UNIX_STR	{ UNIX_NAME, sizeof(UNIX_NAME) - 1}
/* module flag */
#define DGRAM_UDP_FLAG		(1 << 30)
#define DGRAM_UNIX_FLAG		(1 << 29)


/* default buffer size */
#define DGRAM_BUFFER_SIZE	16384

/* separation char */
#define COLON_C				':'
#define PARAM_SEP			'\n'
#define QUOTE_C				'"'
#define ESC_C				'\\'
#define ATTR_SEP_S			"::"			
#define ATTR_SEP_LEN		(sizeof(ATTR_SEP_S) - 1)

struct dgram_socks {
	int udp_sock;
	int unix_sock;
};

#endif
