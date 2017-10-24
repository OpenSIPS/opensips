/*
 * Copyright (C) 2009 Voice Sistem SRL
 * Copyright (C) 2009 Razvan
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
 * History:
 * --------
 *  2009-07-29 initial version (razvan)
 */


#ifndef DB_MOD_H
#define DB_MOD_H

#include "../../db/db_val.h"
#include "../../str.h"
#include "../../db/db_cap.h"

#define CAN_USE 0x0001
#define MAY_USE 0x0002
#define RERECONNECT 0x0010

#define NOT_CAN_USE ~CAN_USE
#define NOT_MAY_USE ~MAY_USE
#define NOT_RERECONNECT ~RERECONNECT


#define CLOSED 0x0020
#define NOT_CLOSED ~CLOSED

#define DB_CAP_FAILOVER (0 | DB_CAP_QUERY | DB_CAP_RAW_QUERY | DB_CAP_INSERT | \
DB_CAP_DELETE | DB_CAP_UPDATE | DB_CAP_REPLACE | DB_CAP_FETCH | \
DB_CAP_LAST_INSERTED_ID  | DB_CAP_INSERT_UPDATE | DB_CAP_ASYNC_RAW_QUERY)

#define DB_CAP_PARALLEL (0 | DB_CAP_QUERY | DB_CAP_RAW_QUERY | DB_CAP_INSERT | \
DB_CAP_DELETE | DB_CAP_UPDATE | DB_CAP_REPLACE | DB_CAP_FETCH | \
DB_CAP_LAST_INSERTED_ID  | DB_CAP_INSERT_UPDATE | DB_CAP_ASYNC_RAW_QUERY)

#define DB_CAP_ROUND (0 | DB_CAP_QUERY | DB_CAP_RAW_QUERY | DB_CAP_INSERT | \
DB_CAP_FETCH | DB_CAP_DELETE | \
DB_CAP_LAST_INSERTED_ID  | DB_CAP_INSERT_UPDATE | DB_CAP_ASYNC_RAW_QUERY)

enum DB_MODE {FAILOVER=0, PARALLEL, ROUND};

#define MEM_PKG           "pkg"
#define MEM_SHM           "share"

#define MEM_ERR(mem_type)  \
		do {	LM_ERR("No more %s memory\n",mem_type);\
				goto error;\
		} while(0)

/*
 * global info
 *
 * info_db
 *      url
 *      func
 *      flags
 *
 * info_set
 *      name
 *      mode
 *
 *      db_list
 *      size
 *
 * info_global
 *
 *      hset_list
 *      size
 */

typedef struct info_db{

    str         db_url;         /* url to real db */
    db_func_t   dbf;            /* db functions and capabilities */
    int         flags;          /* global CAN, MAY flags */
}info_db_t;


typedef struct info_set{

    str         set_name;       /* name of the set; ex: set1, set2...*/
    char        set_mode;       /* mode of the set: PARALLEL, FAILOVER, ... */

    info_db_t*  db_list;
    int         size;
}info_set_t;


typedef struct info_global{

    info_set_t* set_list;
    int         size;
}info_global_t;


int virtual_mod_init(void);
int init_private_handles(void);

#endif /* DB_MOD_H */
