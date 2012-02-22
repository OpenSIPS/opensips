/*
 * Copyright (C) 2011 OpenSIPS Solutions
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *
 * history:
 * ---------
 *  2011-09-xx  created (vlad-paiu)
 */


#ifndef _CACHEDB_H
#define _CACHEDB_H

#include "../str.h"
#include "cachedb_con.h"
#include "cachedb_pool.h"
#include "cachedb_id.h"

struct cachedb_url
{
	str url;
	struct cachedb_url *next;
};

int cachedb_store_url(struct cachedb_url **list,char *val);
void cachedb_free_url(struct cachedb_url *list);

cachedb_con* cachedb_do_init(str *url,void* (*new_connection)(struct cachedb_id *));
void cachedb_do_close(cachedb_con *con, void (*free_connection)(cachedb_pool_con *));

typedef cachedb_con* (cachedb_init_f)(str *url);
typedef void (cachedb_destroy_f)(cachedb_con *con);
typedef int (cachedb_get_f)(cachedb_con *con,str *attr,str *val);
typedef int (cachedb_set_f)(cachedb_con *con,str *attr,str *val,int expires);
typedef int (cachedb_remove_f)(cachedb_con *con,str *attr);
typedef int (cachedb_add_f)(cachedb_con *con,str *attr,int val,int expires,int *new_val);
typedef int (cachedb_sub_f)(cachedb_con *con,str *attr,int val,int expires,int *new_val);

typedef struct cachedb_funcs_t {
	cachedb_init_f		*init;
	cachedb_destroy_f	*destroy;
	cachedb_get_f		*get;
	cachedb_set_f		*set;
	cachedb_remove_f	*remove;
	cachedb_add_f		*add;
	cachedb_sub_f		*sub;
	int capability;
} cachedb_funcs;

typedef struct cachedb_engines {
	str name;					/* name of the engine */
	cachedb_funcs cdb_func;		/* exported functions */
	cachedb_con *default_connection; /* default connection to be used from script */
	cachedb_con_list *connections; /* connection potentially used from script
									  for this particular cachedb engine */
} cachedb_engine;

int register_cachedb(cachedb_engine* cde_entry);

/* functions to be used from script */
int cachedb_store(str* cachedb_engine, str* attr, str* val,int expires);
int cachedb_remove(str* cachedb_engine, str* attr);
int cachedb_fetch(str* cachedb_engine, str* attr, str* val);
int cachedb_add(str* cachedb_engine, str* attr, int val,int expires,int *new_val);
int cachedb_sub(str* cachedb_engine, str* attr, int val,int expires,int *new_val);


int cachedb_bind_mod(str *url,cachedb_funcs *funcs);
int cachedb_put_connection(str *cachedb_name,cachedb_con *con);

void cachedb_end_connections(str *cachedb_name);
#endif
