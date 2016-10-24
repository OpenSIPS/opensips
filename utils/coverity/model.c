/*
 * Copyright (C) 2016 Răzvan Crainea <razvan@opensips.org>
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

/* CID 150495 - ./modules/seas/event_dispatcher.c */
int __read_name(int sock, char *dst, int dstlen)
{
	char namelen;

	__coverity_tainted_data_argument__(namelen);

	if (namelen < dstlen || namelen > 0) {
		__coverity_tainted_data_sanitize__(namelen);
		return 1;
	} else {
		return 0;
	}
}
