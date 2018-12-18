/*
 * Copyright (C) 2018 OpenSIPS Solutions
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

#include "../../str.h"

#include <GeoIP.h>
#include <GeoIPCity.h>

#define RES_BUF_LEN 256

typedef GeoIPRecord* lookup_res_t;

int legacy_parse_cache_type(char *val);

int legacy_open_db(void);
void legacy_close_db(void);
lookup_res_t legacy_lookup_ip(char *ip, int *status);
void legacy_free_lookup_res(lookup_res_t res);
int legacy_get_field(lookup_res_t ip_data, char *field, char buf[256]);

extern int legacy_cache_option;

