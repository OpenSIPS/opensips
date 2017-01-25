/*
 * Copyright (C) 2017 Răzvan Crainea <razvan@opensips.org>
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
 */

#ifndef _CGRATES_H_
#define _CGRATES_H_

#define CGR_DEFAULT_PORT 2014			 /* default port of the CGR Engine */
#define CGR_DEFAULT_MAX_CONNS 10		/* maximum number of conections per process */
#define CGR_DEFAULT_RETRY_TIMEOUT 60	/* default timeout for re-connection */

#define CGR_BUFFER_SIZE 4096			/* buffer read size */

#endif /* _CGRATES_H_ */
