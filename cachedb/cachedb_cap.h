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
 *  2011-09-xx  created (vlad-paiu)
 */

#ifndef _CACHEDB_CAP_H
#define _CACHEDB_CAP_H

#include "cachedb.h"
#include"../dprint.h"

#include <stdlib.h>

typedef enum {
	CACHEDB_CAP_GET = 1<<0,
	CACHEDB_CAP_SET = 1<<1,
	CACHEDB_CAP_REMOVE = 1<<2,
	CACHEDB_CAP_ADD = 1<<3,
	CACHEDB_CAP_SUB = 1<<4,
	CACHEDB_CAP_BINARY_VALUE = 1<<5
} cachedb_cap;

#define CACHEDB_CAPABILITY(cdbf,cpv) (((cdbf)->capability & (cpv)) == (cpv))

static inline int check_cachedb_api(cachedb_engine *cde)
{
	if (cde == NULL)
		return -1;

	if (cde->cdb_func.init == 0) {
		LM_ERR("module %.*s does not export init func\n",
				cde->name.len,cde->name.s);
		return -1;
	}

	if (cde->cdb_func.destroy == 0) {
		LM_ERR("module %.*s doesnt export destroy func\n",
				cde->name.len,cde->name.s);
		return -1;
	}
	
	if (cde->cdb_func.get)
		cde->cdb_func.capability |= CACHEDB_CAP_GET;
	if (cde->cdb_func.set)
		cde->cdb_func.capability |= CACHEDB_CAP_SET;
	if (cde->cdb_func.remove)
		cde->cdb_func.capability |= CACHEDB_CAP_REMOVE;
	if (cde->cdb_func.add)
		cde->cdb_func.capability |= CACHEDB_CAP_ADD;
	if (cde->cdb_func.sub)
		cde->cdb_func.capability |= CACHEDB_CAP_SUB;

	return 0;
}

#endif
