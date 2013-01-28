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

#ifndef CACHEDBMONGO_JSON_H
#define CACHEDBMONGO_JSON_H

#include "cachedb_mongodb_dbase.h"

#include <bson.h>
#include <stdint.h>

int json_to_bson(char *json,bson *bb);
int mongo_cursor_to_json(mongo_cursor *m_cursor,
		cdb_raw_entry ***reply,int expected_kv_no,int *reply_no);

#endif /* CACHEDBMONGO_JSON_H */

