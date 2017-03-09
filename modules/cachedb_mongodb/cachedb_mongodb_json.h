/*
 * Copyright (C) 2011-2017 OpenSIPS Project
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
 */

#ifndef CACHEDBMONGO_JSON_H
#define CACHEDBMONGO_JSON_H

#include "cachedb_mongodb_dbase.h"

#include <bson.h>
#include <stdint.h>

int json_to_bson(char *json,bson_t *bb);

void bson_to_json_generic(struct json_object *obj, bson_iter_t *it,
                          bson_type_t type);

#endif /* CACHEDBMONGO_JSON_H */

