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

#ifndef XCAP_URI_H
#define XCAP_URI_H

#include "../../config.h"
#include "../../str.h"


typedef struct {
    char buf[MAX_URI_SIZE];
    str uri;
    str root;
    str auid;
    str tree;
    str xui;
    str filename;
    str selector;
} xcap_uri_t;


/* Returns a statically allocated buffer, so the caller is responsible for copying it
 * if necessary */
str* normalize_sip_uri(const str *uri);

int parse_xcap_uri(const str *uri, xcap_uri_t *xcap_uri);

#endif

