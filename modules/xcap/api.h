/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 */

#ifndef XCAP_API_H
#define XCAP_API_H

#include "../../str.h"
#include "doc.h"
#include "uri.h"


typedef str* (*normalize_sip_uri_t)(const str *uri);
typedef int (*parse_xcap_uri_t)(const str *uri, xcap_uri_t *xcap_uri);
typedef int (*get_xcap_doc_t)(str* user, str* domain, int type, str* filename, str* match_etag, str** doc, str** etag);

typedef struct xcap_api {
        int integrated_server;
        str db_url;
        str xcap_table;
        normalize_sip_uri_t normalize_sip_uri;
        parse_xcap_uri_t parse_xcap_uri;
        get_xcap_doc_t get_xcap_doc;
} xcap_api_t;

typedef int (*bind_xcap_t)(xcap_api_t* api);

int bind_xcap(xcap_api_t* api);

#endif

