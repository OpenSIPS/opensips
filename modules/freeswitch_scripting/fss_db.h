/*
 * SQL DB provisioning
 *
 * Copyright (C) 2017 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#ifndef __FSS_DB__
#define __FSS_DB__

#include "../../str.h"

#define TABLE_VERSION 1

extern str db_url;
extern rw_lock_t *db_reload_lk;

int fss_db_init(void);
void fss_db_close(void);
int fss_db_connect(void);
int fss_db_reload(void);
static inline int have_db(void) { return !!db_url.s; };

#endif /* __FSS_DB__ */
