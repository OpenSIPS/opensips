/*
 * Copyright (C) 2013 OpenSIPS Solutions
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
 * History:
 * -------
 * 2013-02-28: Created (Liviu)
 */

#ifndef _REST_CB_H_
#define _REST_CB_H_

#include "../../str.h"
#include "../../mem/mem.h"
#include "../../error.h"
#include "../../dprint.h"
#include "../../pvar.h"
#include "../../trim.h"

#define HTTP_HDR_CONTENT_TYPE    "Content-Type"
#define CONTENT_TYPE_HDR_LEN     12
#define MAX_CONTENT_TYPE_LEN     64
#define MAX_HEADER_FIELD_LEN	 1024 /* arbitrary */

size_t write_func(char *ptr, size_t size, size_t nmemb, void *userdata);
size_t header_func(char *ptr, size_t size, size_t nmemb, void *userdata);

#endif /* _REST_CB_H_ */

