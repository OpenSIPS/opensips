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

#include <maxminddb.h>

#define RES_BUF_LEN 256
#define MAX_PATH_DEPTH 4
#define FIELD_PATH_SEP '.'

typedef MMDB_lookup_result_s lookup_res_t;

int geoip2_open_db(void);
void geoip2_close_db(void);
lookup_res_t geoip2_lookup_ip(char *ip, int *status);
int geoip2_get_field(lookup_res_t ip_data, char *field, char buf[256]);
