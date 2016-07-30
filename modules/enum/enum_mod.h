/*
 * Enum module headers
 *
 * Copyright (C) 2002-2003 Juha Heinanen
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
 */


#ifndef ENUM_MOD_H
#define ENUM_MOD_H


#include "../../str.h"


/*
 * Internal module variables
 */
extern str suffix;           /* str version of domain_suffix */
extern str param;            /* str version of tel_uri_params */
extern str service;          /* default (empty) service */

extern str i_suffix;         /* suffix for infrastructure ENUM */
extern str i_branchlabel;    /* the label branching off the infrastructure tree */
extern str i_bl_alg;         /* how to know where to branch off */

extern str isnsuffix;        /* str version of isn_suffix */


#endif /* ENUM_MOD_H */
