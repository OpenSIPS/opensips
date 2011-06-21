/* 
 * $Id$ 
 *
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2007-2008 1&1 Internet AG
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
 */

/**
 * \file db/db_con.h
 * \brief Type that represents a database connection
 */

#ifndef DB_CON_H
#define DB_CON_H

#include "../str.h"
#include "db_ps.h"

/**
 * This structure represents a database connection, pointer to this structure
 * are used as a connection handle from modules uses the db API.
 */
typedef struct {
	const str* table;         /**< Default table that should be used        */
	db_ps_t* curr_ps;     /**< Prepared statement to be used for next query */
	struct query_list *ins_list; /**< Insert list to be used for the next insert */
	unsigned long tail; /**< Hook to implementation-specific database state */
	str url;			/**< what is the URL that this connection is bound on */
	int flags;
} db_con_t;

/** Return the table of the connection handle */
#define CON_TABLE(cn)      ((cn)->table)
/** Return the tail of the connection handle */
#define CON_TAIL(cn)       ((cn)->tail)


#endif /* DB_CON_H */
