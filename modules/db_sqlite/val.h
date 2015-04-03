/**
 *
 * Copyright (C) 2015 OpenSIPS Foundation
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
 * History
 * -------
 *  2015-02-18  initial version (Ionut Ionita)
*/
#ifndef VAL_H
#define VAL_H

#include <mysql/mysql.h>
#include "../../db/db_val.h"
#include "../../db/db.h"


/**
 * Does not copy strings
 */
int db_sqlite_str2val(const db_type_t _t, db_val_t* _v, const char* _s,
	const int _l);


/**
 * Used when converting result from a query
 */
int db_sqlite_val2str(const db_con_t* _con, const db_val_t* _v, char* _s,
		int* _len);
int db_sqlite_val2bind(const db_val_t* v, MYSQL_BIND *binds, unsigned int i);

#endif /* VAL_H */
