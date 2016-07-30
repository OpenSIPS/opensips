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

#ifndef XCAP_DOC_H
#define XCAP_DOC_H

#include "../../str.h"

/* XCAP document types */
#define PRES_RULES         1<<1
#define RESOURCE_LISTS     1<<2
#define RLS_SERVICES       1<<3
#define PIDF_MANIPULATION  1<<4
#define OMA_PRES_RULES     1<<5


int get_xcap_doc(str* user, str* domain, int type, str* filename, str* match_etag, str** doc, str** etag);

#endif

