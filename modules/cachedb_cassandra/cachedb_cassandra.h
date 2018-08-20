/*
 * Copyright (C) 2018 OpenSIPS Solutions
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
 */

#ifndef CACHEDBCASSANDRA_H
#define CACHEDBCASSANDRA_H

#define CASS_DEFAULT_CONN_TIMEOUT 5000 /* ms */
#define CASS_DEFAULT_QUERY_TIMEOUT 5000 /* ms */
#define CASS_DEFAULT_EXEC_THRESH  0
#define CASS_DEFAULT_CONSISTENCY_STR "one"
#define CASS_DEFAULT_QUERY_RETRIES 2

extern int cassandra_conn_timeout;
extern int cassandra_query_timeout;
extern int cassandra_exec_threshold;
extern int cassandra_query_retries;

#endif