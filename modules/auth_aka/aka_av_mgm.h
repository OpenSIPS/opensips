/*
 * AKA Authentication - generic Authentication Manager support
 *
 * Copyright (C) 2024 Razvan Crainea
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

#ifndef AKA_AV_MGM_H
#define AKA_AV_MGM_H

#include "../../str.h"
#include "../../lib/list.h"

#define AKA_AV_MGM_PREFIX "load_aka_av_"

struct aka_av_binds {
	/*
	 * realm - the Realm of the authentication vector
	 * impu - Public identity of the user
	 * impi - Private identity of the user
	 * resync - Resync/auts token, or NULL if not a resync request
	 * algmask - Masks of algorithms to request
	 * no - number of AVs for each algorithm
	 * async - indicates whether the request is asynchronous or not
	 */
	int (*fetch)(str *realm, str *impu, str *impi, str *resync, int algmask, int no, int async);
};

struct aka_av_mgm {
	str name;
	struct aka_av_binds binds;
	struct list_head list;
	char buf[0];
};

#endif /* AKA_AV_MGM_H */
