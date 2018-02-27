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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
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
	CACHEDB_CAP_BINARY_VALUE = 1<<5,
	CACHEDB_CAP_RAW = 1<<6,

	CACHEDB_CAP_GET_ROWS = 1<<7,
	CACHEDB_CAP_SET_COLS = 1<<8,
	CACHEDB_CAP_UNSET_COLS = 1<<9,
	CACHEDB_CAP_COL_ORIENTED =
		(CACHEDB_CAP_GET_ROWS|CACHEDB_CAP_SET_COLS|CACHEDB_CAP_UNSET_COLS),

	CACHEDB_CAP_TRUNCATE = 1<<10,
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
		LM_ERR("module %.*s doesn't export destroy func\n",
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
	if (cde->cdb_func.raw_query)
		cde->cdb_func.capability |= CACHEDB_CAP_RAW;
	if (cde->cdb_func.get_rows)
		cde->cdb_func.capability |= CACHEDB_CAP_GET_ROWS;

	if (cde->cdb_func.set_cols)
		cde->cdb_func.capability |= CACHEDB_CAP_SET_COLS;
	if (cde->cdb_func.unset_cols)
		cde->cdb_func.capability |= CACHEDB_CAP_UNSET_COLS;
	if (cde->cdb_func.truncate)
		cde->cdb_func.capability |= CACHEDB_CAP_TRUNCATE;

	if (cde->cdb_func.set_cols && cde->cdb_func.unset_cols
	    && cde->cdb_func.truncate)
		cde->cdb_func.capability |= CACHEDB_CAP_COL_ORIENTED;

	return 0;
}

#endif
