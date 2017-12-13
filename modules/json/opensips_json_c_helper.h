/*
 * Copyright (C) 2017 Björn Esser <besser82@fedoraproject.org>
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
 * History:
 * ---------
 *  2017-12-12 first version (besser82)
 */

#ifndef OPENSIPS_JSON_C_HELPER_H
#define OPENSIPS_JSON_C_HELPER_H

/*
 * If those are not defined, we assume to build against json-c v0.9.
 * Starting with v0.11 there is json_c_version.h, which we prefer
 * anyways, so there are no regressions in this case.  Everything
 * conditionalized for v0.10 or later doesn't produce any fallout,
 * when we are asuming v0.9 and building against v0.10.
 */
#ifndef JSON_PKG_MAJOR
#define JSON_PKG_MAJOR	0
#endif
#ifndef JSON_PKG_MINOR
#define JSON_PKG_MINOR	9
#endif
#ifndef JSON_PKG_MICRO
#define JSON_PKG_MICRO	0
#endif

/* json.h automatically includes json_c_version.h, if available. */
#include <json.h>

/*
 * We prefer JSON_C_VERSION_NUM defined in json_c_version.h.  If it is
 * not defined, we construct it the same way from our JSON_PKG_* defines.
 */
#ifndef JSON_C_VERSION_NUM
#define JSON_C_VERSION_NUM (JSON_PKG_MAJOR << 16) | \
			   (JSON_PKG_MINOR << 8)  | \
			    JSON_PKG_MICRO
#endif

/* Macros for checking specific versions. */
#define JSON_C_VERSION_010 (10 << 8)
#define JSON_C_VERSION_013 (13 << 8)

/* json_object_private.h is gone and not needed anymore in json-c v0.13+. */
#if JSON_C_VERSION_NUM < JSON_C_VERSION_013
#include <json_object_private.h>
#endif

/*
 * Newer versions of json-c define this in their headers, so we prefer
 * their definition in that case.
 */
#ifndef JSON_FILE_BUF_SIZE
#define JSON_FILE_BUF_SIZE 4096
#endif

/* Declaration of helper functions. */
void json_object_array_del(struct json_object* obj, int idx);

#endif /* OPENSIPS_JSON_C_HELPER_H */
