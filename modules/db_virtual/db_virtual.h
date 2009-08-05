/*
 * $Id$
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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
DB_CAP_LAST_INSERTED_ID  | DB_CAP_INSERT_UPDATE)

#define DB_CAP_PARALLEL (0 | DB_CAP_QUERY | DB_CAP_RAW_QUERY | DB_CAP_INSERT | \
DB_CAP_DELETE | DB_CAP_UPDATE | DB_CAP_REPLACE | DB_CAP_FETCH | \
DB_CAP_LAST_INSERTED_ID  | DB_CAP_INSERT_UPDATE)

#define DB_CAP_ROUND (0 | DB_CAP_QUERY | DB_CAP_RAW_QUERY | DB_CAP_INSERT | \
DB_CAP_FETCH | \
DB_CAP_LAST_INSERTED_ID  | DB_CAP_INSERT_UPDATE)

enum DB_MODE {FAILOVER=0, PARALLEL, ROUND};

#define MEM_PKG           "pkg"
#define MEM_SHM           "share"

#define MEM_ERR(mem_type)  \
		do {	LM_ERR("No more %s memory\n",mem_type);\
				goto error;\
		} while(0)

typedef struct db_state{
                    str db_url;
                    db_func_t dbf;
                    int flags;
}db_state_t;

typedef struct db_set{
                    str set_name;
                    char set_mode;

                    db_state_t * db_state_a;
                    int size;
}db_set_t;


typedef struct db_set_array{

                    db_set_t * set_a;
                    int size;
}db_set_array_t;

int virtual_mod_init(void);
int init_private_handles(void);

#endif /* DB_MOD_H */
