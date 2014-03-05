/**
 * $Id$
 *
 * Copyright (C) 2012 OpenSIPS Solutions
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History
 * -------
 * 2012-09-24  created (liviuchircu)
 *
 */

#ifndef _DS_BL_H_
#define _DS_BL_H_

#include "../../blacklists.h"
#include "dispatch.h"

#define DS_BL_MAX_SETS		32

struct ds_bl {
	unsigned int no_sets;
	unsigned int sets[DS_BL_MAX_SETS];
	struct bl_head *bl;
	struct ds_bl *next;
};

int set_ds_bl(modparam_t type, void *val);

int init_ds_bls(void);

void destroy_ds_bls(void);

int populate_ds_bls(ds_set_t *sets);

#endif /* _DS_BL_H_ */
