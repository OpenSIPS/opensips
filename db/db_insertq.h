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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *
 * history:
 * ---------
 *  2011-06-07  created (vlad)
 */

#ifndef _DB_INSERTQ_H
#define _DB_INSERTQ_H

#include "db_ut.h"
#include "db_query.h"
#include "../locking.h"

extern int query_buffer_size; /* number of insert queries that will be
								 held in memory once this number of same
								 type of queries pile up to this number,
								 they will be flushed to DB */
extern int query_flush_time; /* if the query contains inserts older
								that query_flush_time seconds, the timer
								will kick in and flush to DB,
								to maintain "real time" sync with DB */

#define CON_HAS_INSLIST(cn)	((cn)->ins_list)
#define DEF_FLUSH_TIME		10 /* seconds */

typedef struct query_list {
	str url;			/* url for the connection - needed by timer */
	db_func_t dbf;		/* func handlers that will be used by timer */
	db_con_t **conn;	/* connection that will be used by timer */
	str table;			/* table that query is targetting */
	db_key_t *cols;		/* columns for the insert */
	int col_no;			/* number of columns */
	db_val_t **rows;	/* rows queued to be inserted */
	gen_lock_t* lock;	/* lock for adding rows */
	int no_rows;		/* number of rows in queue */
	time_t oldest_query;	/* timestamp of oldest query in queue */
	struct query_list *next;
	struct query_list *prev;
} query_list_t;

extern query_list_t **query_list;
extern gen_lock_t *ql_lock;

int init_ql_support(void);
int ql_row_add(query_list_t *entry,const db_val_t *row,db_val_t ***ins_rows);
int ql_detach_rows_unsafe(query_list_t *entry,db_val_t ***ins_rows);
int con_set_inslist(db_func_t *dbf,db_con_t *con,
							query_list_t **list,db_key_t *cols,int col_no);
void ql_timer_routine(unsigned int ticks,void *param);
int ql_flush_rows(db_func_t *dbf, db_con_t *conn,query_list_t *entry);
void ql_force_process_disconnect(int p_id);

#define CON_RESET_INSLIST(con) \
	do { \
		*((query_list_t **)&con->ins_list) = NULL; \
	} while (0)

#define IS_INSTANT_FLUSH(con)		((con)->flags & CON_INSTANT_FLUSH)

#define CON_FLUSH_UNSAFE(con) \
	do { \
		(con)->flags |= CON_INSTANT_FLUSH; \
	} while (0)

#define CON_FLUSH_SAFE(con) \
	do { \
		lock_get((con)->ins_list->lock); \
		(con)->flags |= CON_INSTANT_FLUSH; \
	} while (0)

#define CON_FLUSH_RESET(con,entry) \
	do { \
		*((int *)&(con)->flags) &= ~CON_INSTANT_FLUSH; \
		lock_release((entry)->lock); \
	} while (0)

void cleanup_rows(db_val_t **rows);
void handle_ql_shutdown(void);

#endif
