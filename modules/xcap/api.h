/*
 * $Id$
 *
 * xcap module - XCAP operations module
 *
 * Copyright (C) 2012 AG Projects
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
 */

#ifndef XCAP_API_H
#define XCAP_API_H

#include "../../str.h"
#include "uri.h"


typedef int (*parse_xcap_uri_t)(const str *uri, xcap_uri_t *xcap_uri);

typedef struct xcap_api {
        int integrated_server;
        str db_url;
        str xcap_table;
        parse_xcap_uri_t parse_xcap_uri;
} xcap_api_t;

int bind_xcap(xcap_api_t* api);

typedef int (*bind_xcap_t)(xcap_api_t* api);

#endif

