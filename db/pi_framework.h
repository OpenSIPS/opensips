/*
 * Copyright (C) 2011 VoIP Embedded Inc.
 *
 * This file is part of Open SIP Server (opensips).
 *
 * opensips is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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
 * History:
 * ---------
 *  2011-09-20  first version (osas)
 */


#ifndef _PI_FRAMEWORK_H
#define _PI_FRAMEWORK_H

#include "db.h"

/**< no validation required */
#define	PI_FLAG_NONE		0
/**< validate as socket: [proto:]host[:port] */
#define	PI_FLAG_P_HOST_PORT	(1<<0)
/**< validate as socket: [proto:]IPv4[:port] */
#define	PI_FLAG_P_IPV4_PORT	(1<<1)
/**< validate as IPv4 */
#define	PI_FLAG_IPV4		(1<<2)
/**< validate as SIP URI */
#define	PI_FLAG_URI		(1<<3)
/**< validate as SIP URI w/ IPv4 host */
#define	PI_FLAG_URI_IPV4HOST	(1<<4)

typedef short int pi_val_flags;

typedef struct pi_db_url_ {
	str id;
	str db_url;
	db_con_t **db_handle;
	db_func_t dbf;
}pi_db_url_t;

typedef struct pi_table_col_ {
	str field;
	db_type_t type;
	pi_val_flags validation;
}pi_table_col_t;

typedef struct pi_db_table_ {
	str id;
	str name;
	str db_url_id;
	pi_db_url_t *db_url;
	pi_table_col_t *cols;
	int cols_size;
}pi_db_table_t;

typedef struct pi_vals_ {
	str *ids;  /* String to display for the given value */
	str *vals; /* pre=populated value for a specific field */
	int vals_size;
}pi_vals_t;

typedef struct pi_cmd_ {
	str name;
	unsigned int type;
	pi_db_table_t *db_table;
	db_op_t *c_ops;
	db_key_t *c_keys;
	db_type_t *c_types;
	pi_vals_t *c_vals; /* array of prepopulated values */
	int c_keys_size;
	db_key_t *q_keys;
	db_type_t *q_types;
	pi_vals_t *q_vals; /* array of prepopulated values */
	str *link_cmd;     /* cmd to be executed for query links */
	int q_keys_size;
	db_key_t *o_keys;
	int o_keys_size;
}pi_cmd_t;

typedef struct pi_mod_ {
	str module;
	pi_cmd_t *cmds;
	int cmds_size;
}pi_mod_t;

typedef struct pi_framework_ {
	pi_db_url_t *pi_db_urls;
	int pi_db_urls_size;
	pi_db_table_t *pi_db_tables;
	int pi_db_tables_size;
	pi_mod_t *pi_modules;
	int pi_modules_size;
}pi_framework_t;

extern pi_framework_t *pi_framework_data;


int pi_init_async_lock(void);
void pi_destroy_async_lock(void);

int pi_init_cmds(pi_framework_t **framework_data, const char* filename);
int pi_framework_init(void);
int pi_framework_init_db(void);
int pi_framework_child_init(void);
void pi_framework_destroy_db(void);
int pi_parse_url(const char* url, int* mod, int* cmd);
int pi_run_cmd(int mod, int cmd, void *connection, void *con_cls,
			str *page, str *buffer);

#endif
