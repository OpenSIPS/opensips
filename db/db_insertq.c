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

#include "db_insertq.h"
#include "db_cap.h"
#include "../timer.h"
#include "../pt.h"

int query_buffer_size = 0;
int query_flush_time = 0;
query_list_t **query_list = NULL;
query_list_t **last_query = NULL;
gen_lock_t *ql_lock;

/* inits all the global variables needed for the insert query lists */
int init_query_list(void)
{
	query_list = shm_malloc(sizeof(query_list_t *));
	if (!query_list)
	{
		LM_ERR("no more shm\n");
		return -1;
	}

	last_query = shm_malloc(sizeof(query_list_t *));
	if (!last_query)
	{
		LM_ERR("no more shm\n");
		shm_free(query_list);
		return -1;
	}

	*query_list = NULL;
	*last_query = NULL;

	ql_lock = lock_alloc();
	if (ql_lock == 0) {
		LM_ERR("failed to alloc lock\n");
		goto error0;
	}

	if (lock_init(ql_lock) == 0) {
		LM_ERR("failed to init lock\n");
		goto error1;
	}

	LM_DBG("Initialised query list. Insert queue size = %d\n",query_buffer_size);
	return 0;

error1:
	lock_dealloc(ql_lock);
error0:
	shm_free(query_list);
	return -1;
}

/* Initializes needed structures and registeres timer
 *
 * Important : To be called before forking so all processes
 * inherit same queue */
int init_ql_support(void)
{
	if (query_buffer_size > 1)
	{
		if  (init_query_list() != 0 ||
			register_timer("querydb-flush", ql_timer_routine,NULL,
				query_flush_time>0?query_flush_time:DEF_FLUSH_TIME,
				TIMER_FLAG_DELAY_ON_DELAY) < 0 )
		{
			LM_ERR("failed initializing ins list support\n");
			return -1;
		}
	}

	return 0;
}


void flush_query_list(void)
{
	query_list_t *it;
	static db_ps_t my_ps = NULL;
	int i;

	/* no locks, only attendent is left at this point */
	for (it=*query_list;it;it=it->next)
	{
		if (it->no_rows > 0)
		{
			memset(&it->dbf,0,sizeof(db_func_t));
			if (db_bind_mod(&it->url,&it->dbf) < 0)
			{
				LM_ERR("failed to bind to db at shutdown\n");
				lock_release(it->lock);
				continue;
			}

			it->conn[process_no] = it->dbf.init(&it->url);
			if (it->conn[process_no] == 0)
			{
				LM_ERR("unable to connect to DB at shutdown\n");
				lock_release(it->lock);
				continue;
			}

			it->dbf.use_table(it->conn[process_no],&it->table);

			//Reset prepared statement between query lists/connections
			my_ps = NULL;

			CON_PS_REFERENCE(it->conn[process_no]) = &my_ps;

			/* and let's insert the rows */
			for (i=0;i<it->no_rows;i++)
			{
				if (it->dbf.insert(it->conn[process_no],it->cols,it->rows[i],
							it->col_no) < 0)
					LM_ERR("failed to insert into DB\n");

				shm_free(it->rows[i]);
			}

			/* no longer need this connection */
			if (it->conn[process_no] && it->dbf.close)
				it->dbf.close(it->conn[process_no]);
		}
	}
}

/* free all resources used by insert buffering */
void destroy_query_list(void)
{
	query_list_t *it;

	for (it=*query_list;it;it=it->next)
	{
		lock_destroy(it->lock);
		lock_dealloc(it->lock);
		shm_free(it);
	}

	lock_destroy(ql_lock);
	lock_dealloc(ql_lock);
}

/* to be called only at shutdown *
 * flushes all remaining rows to DB
 * and frees memory */
void handle_ql_shutdown(void)
{
	if (query_buffer_size > 1 && query_list && *query_list)
	{
		flush_query_list();
		destroy_query_list();
	}
}

/* adds a new type of query to the list
 * assumes ql_lock is acquired*/
void ql_add_unsafe(query_list_t *entry)
{
	if (*query_list == NULL)
	{
		*query_list = entry;
		*last_query = entry;
	}
	else
	{
		(*last_query)->next=entry;
		entry->prev = *last_query;
		*last_query = entry;
	}
}

int ql_detach_rows_unsafe(query_list_t *entry,db_val_t ***ins_rows)
{
	static db_val_t **detached_rows = NULL;
	int no_rows;

	if (detached_rows == NULL)
	{
		/* one time allocate buffer to pkg */
		detached_rows = pkg_malloc(query_buffer_size*sizeof(db_val_t *));
		if (detached_rows == NULL)
		{
			LM_ERR("no more pkg mem\n");
			lock_release(entry->lock);
			return -1;
		}
	}

	if (entry->no_rows == 0)
		return 0;

	memcpy(detached_rows,entry->rows,query_buffer_size * sizeof(db_val_t *));
	memset(entry->rows,0,query_buffer_size * sizeof(db_val_t *));

	no_rows = entry->no_rows;
	LM_DBG("detached %d rows\n",no_rows);

	entry->no_rows = 0;
	entry->oldest_query = 0;
	*ins_rows = detached_rows;

	return no_rows;
}

/* safely adds a new row to the insert list
 * also checks if the queue is full and returns all the rows that need to
 * be flushed to DB to the caller
 *
 * returns the number of rows detached
 *
 * Important : it is the caller's job to shm_free the rows
 * after flushing to DB
 * */
int ql_row_add(query_list_t *entry,const db_val_t *row,db_val_t ***ins_rows)
{
	int val_size,i,len,no_rows = 0;
	char *pos;
	db_val_t *shm_row;

	val_size = entry->col_no * sizeof(db_val_t);
	for (i=0;i<entry->col_no;i++)
	{
		if (VAL_TYPE(row+i) == DB_STR && VAL_NULL(row+i) == 0)
		{
			val_size += VAL_STR(row+i).len;
			continue;
		}
		if (VAL_TYPE(row+i) == DB_STRING && VAL_NULL(row+i) == 0)
		{
			val_size += strlen(VAL_STRING(row+i))+1;
			continue;
		}
		if (VAL_TYPE(row+i) == DB_BLOB && VAL_NULL(row+i) == 0)
			val_size += VAL_BLOB(row+i).len;
	}

	shm_row = shm_malloc(val_size);
	if (shm_row == NULL)
	{
		LM_ERR("no more shm\n");
		return -1;
	}

	LM_DBG("adding row to table [%.*s] &  entry %p\n",entry->table.len,entry->table.s,entry);

	/* save row info to shm */
	pos = (char *)(shm_row + entry->col_no);
	memcpy(shm_row,row,entry->col_no * sizeof(db_val_t));
	for (i=0;i<entry->col_no;i++)
	{
		if (VAL_TYPE(row+i) == DB_STR && VAL_NULL(row+i) == 0)
		{
			len = VAL_STR(row+i).len;
			VAL_STR(shm_row+i).len = len;
			VAL_STR(shm_row+i).s = pos;
			memcpy(VAL_STR(shm_row+i).s,VAL_STR(row+i).s,len);
			pos += len;
			continue;
		}
		if (VAL_TYPE(row+i) == DB_STRING && VAL_NULL(row+i) == 0)
		{
			len = strlen(VAL_STRING(row+i)) + 1;
			VAL_STRING(shm_row+i) = pos;
			memcpy((void *)VAL_STRING(shm_row+i),VAL_STRING(row+i),len);
			pos += len;
			continue;
		}
		if (VAL_TYPE(row+i) == DB_BLOB && VAL_NULL(row+i) == 0)
		{
			len = VAL_BLOB(row+i).len;
			VAL_BLOB(shm_row+i).len = len;
			VAL_BLOB(shm_row+i).s = pos;
			memcpy(VAL_BLOB(shm_row+i).s,VAL_BLOB(row+i).s,len);
			pos += len;
		}
	}

	LM_DBG("before locking query entry\n");
	lock_get(entry->lock);

	/* store oldest query for timer to know */
	if (entry->no_rows == 0)
		entry->oldest_query = time(0);

	entry->rows[entry->no_rows++] = shm_row;
	LM_DBG("query for table [%.*s] has %d rows\n",entry->table.len,entry->table.s,entry->no_rows);

	/* is it time to flush to DB ? */
	if (entry->no_rows == query_buffer_size)
	{
		if ((no_rows = ql_detach_rows_unsafe(entry,ins_rows)) < 0)
		{
			LM_ERR("failed to detach rows for insertion\n");
			lock_release(entry->lock);
			return -1;
		}
	}

	lock_release(entry->lock);
	return no_rows;
}

/* initializez a new query entry */
query_list_t *ql_init(db_con_t *con,db_key_t *cols,int col_no)
{
	int key_size,row_q_size,size,i;
	char *pos;
	query_list_t *entry;

	key_size = col_no * sizeof(db_key_t) + col_no * sizeof(str);
	for (i=0;i<col_no;i++)
		key_size += cols[i]->len;

	row_q_size = sizeof(db_val_t *) * query_buffer_size;
	size = sizeof(query_list_t) +
		counted_max_processes * sizeof(db_con_t *) +
		con->table->len + key_size + row_q_size + con->url.len;

	entry = shm_malloc(size);
	if (entry == NULL)
	{
		LM_ERR("no more shm\n");
		return NULL;
	}

	memset(entry,0,size);
	LM_DBG("alloced %p for %d bytes\n",entry,size);

	entry->lock = lock_alloc();
	if (entry->lock == 0)
	{
		LM_ERR("failed to alloc lock\n");
		shm_free(entry);
		return NULL;
	}

	if (lock_init(entry->lock) == 0)
	{
		LM_ERR("failed to init lock\n");
		lock_dealloc(entry->lock);
		shm_free(entry);
		return NULL;
	}

	/* deal with the table name */
	entry->table.s = (char *)entry+sizeof(query_list_t);
	entry->table.len = con->table->len;
	memcpy(entry->table.s,con->table->s,con->table->len);

	/* deal with the columns */
	entry->cols = (db_key_t *)((char *)entry+sizeof(query_list_t)+
								con->table->len);
	entry->col_no = col_no;

	pos = (char *)(entry->cols + col_no) + col_no * sizeof(str);
	for (i=0;i<col_no;i++)
	{
		entry->cols[i] = (str *)((char *)(entry->cols + col_no) +
							i * sizeof(str));
		entry->cols[i]->len = cols[i]->len;
		entry->cols[i]->s = pos;
		memcpy(pos,cols[i]->s,cols[i]->len);
		pos += cols[i]->len;
	}

	/* deal with the rows */
	entry->rows = (db_val_t **)((char *)entry + sizeof(query_list_t) +
					con->table->len + key_size);

	/* save url for later use by timer */
	entry->url.s = (char *)entry + sizeof(query_list_t) +
					con->table->len + key_size + row_q_size;
	entry->url.len = con->url.len;
	memcpy(entry->url.s,con->url.s,con->url.len);

	/* build array of connections per process */
	entry->conn = (db_con_t**)((char *)entry + sizeof(query_list_t) +
					con->table->len + key_size + row_q_size + con->url.len);

	LM_DBG("initialized query list for table [%.*s]\n",entry->table.len,entry->table.s);
	return entry;
}

/* attempts to find a query list described by the given parameters
 * if found, returns the entry
 * else, return NULL
 * assumes ql_lock is acquired
 */
query_list_t *find_query_list_unsafe(const str *table,db_key_t *cols,int col_no)
{
	query_list_t *it,*entry=NULL;
	int i;

	LM_DBG("attempting to find q\n");

	for (it=*query_list;it;it=it->next)
	{
		LM_DBG("iterating through %p\n",it);

		/* match number of columns */
		if (it->col_no != col_no)
		{
			LM_DBG("different col no it = %d , %d\n",it->col_no,col_no);
			continue;
		}

		/* match table name */
		if (it->table.len != table->len ||
				memcmp(it->table.s,table->s,table->len) != 0)
		{
			LM_DBG("different tables - [%.*s] - [%.*s] \n",it->table.len,it->table.s,
						table->len,table->s);
			continue;
		}

		/* match columns */
		for (i=0;i<col_no;i++)
		{
			if (it->cols[i]->len != cols[i]->len ||
					memcmp(it->cols[i]->s,cols[i]->s,cols[i]->len) != 0)
			{
				LM_DBG("failed matching column %d - [%.*s] - [%.*s]\n",i,it->cols[i]->len,
					it->cols[i]->s,cols[i]->len,cols[i]->s);
				goto next_query;
			}
		}

		/* got here, we have found our match */
		entry = it;
		LM_DBG("successful match on %p\n",entry);
		break;

next_query:
		;
	}

	LM_DBG("returning %p\n",entry);
	return entry;
}

/* set's the query_list that will be used for inserts
 * on the provided db connection
 *
 * also takes care of initialisation of this is the first process
 * attempting to execute this type of query */
int con_set_inslist(db_func_t *dbf,db_con_t *con,query_list_t **list,
							db_key_t *cols,int col_no)
{
	query_list_t *entry;

	/* if buffering not enabled, ignore */
	if (query_buffer_size <= 1)
		return 0;

	/* if buffering is enabled, but user is using a module
	 * that does not support multiple inserts,
	 * also ignore */
	if (!DB_CAPABILITY(*dbf,DB_CAP_MULTIPLE_INSERT))
		return 0;

	if (list == NULL)
		return 0;

	/* first time we are being called from this process */
	if (*list == NULL)
	{
		LM_DBG("first inslist call. searching for query list \n");
		lock_get(ql_lock);
		entry = find_query_list_unsafe(con->table,cols,col_no);
		if (entry == NULL)
		{
			LM_DBG("couldn't find entry for this query\n");
			/* first query of this type is done from this process,
			 * it's my job to initialize the query list
			 * and save for later use */
			entry = ql_init(con,cols,col_no);
			if (entry == NULL)
			{
				LM_ERR("failed to initialize ins queue\n");
				lock_release(ql_lock);
				return -1;
			}

			ql_add_unsafe(entry);
			con->ins_list = entry;
			*list = entry;
		}
		else
		{
			LM_DBG("query list already exists - attaching\n");
			/* another process has done a query of this type,
			 * just attach to the con and save for later use */
			con->ins_list = entry;
			*list = entry;
		}

		lock_release(ql_lock);
		return 0;
	}
	else
	{
		/* we've previously found our query list */
		LM_DBG("process already found it's query list\n");
		con->ins_list = *list;
	}

	LM_DBG("successfully returned from con_set_inslist\n");
	return 0;
}

/* clean shm memory used by the rows */
void cleanup_rows(db_val_t **rows)
{
	int i;

	if (rows != NULL)
		for (i=0;i<query_buffer_size;i++)
			if (rows[i] != NULL)
			{
				shm_free(rows[i]);
				rows[i] = NULL;
			}
}

/* handler for timer
 * that flushes old rows to DB */
void ql_timer_routine(unsigned int ticks,void *param)
{
	query_list_t *it;
	time_t now;

	now = time(0);

	for (it=*query_list;it;it=it->next)
	{
		lock_get(it->lock);

		/* are there any old queries in queue ? */
		if (it->oldest_query && (now - it->oldest_query > query_flush_time))
		{
			LM_DBG("insert timer kicking in for query %p [%d]\n",it, it->no_rows);

			if (it->dbf.init == NULL)
			{
				/* first time timer kicked in for this query */
				if (db_bind_mod(&it->url,&it->dbf) < 0)
				{
					LM_ERR("timer failed to bind to db\n");
					lock_release(it->lock);
					continue;
				}
			}

			if (it->conn[process_no] == NULL)
			{
				if (!it->dbf.init) {
					LM_ERR("DB engine does not have init function\n");
					lock_release(it->lock);
					continue;
				}
				it->conn[process_no] = it->dbf.init(&it->url);
				if (it->conn[process_no] == 0)
				{
					LM_ERR("unable to connect to DB\n");
					lock_release(it->lock);
					continue;
				}

				LM_DBG("timer has init conn for query %p\n",it);
			}

			it->dbf.use_table(it->conn[process_no],&it->table);

			/* simulate the finding of the right query list */
			it->conn[process_no]->ins_list = it;
			/* tell the core that this is the insert timer handler */
			CON_FLUSH_UNSAFE(it->conn[process_no]);

			/* no actual new row to provide, flush existing ones */
			if (it->dbf.insert(it->conn[process_no],it->cols,(db_val_t *)-1,
						it->col_no) < 0)
				LM_ERR("failed to insert rows to DB\n");
		}
		else
			lock_release(it->lock);
	}
}

int ql_flush_rows(db_func_t *dbf,db_con_t *conn,query_list_t *entry)
{
	if (query_buffer_size <= 1 || !entry)
		return 0;

	/* simulate the finding of the right query list */
	conn->ins_list = entry;
	/* tell the core that we need to flush right away */
	CON_FLUSH_SAFE(conn);

	/* no actual new row to provide, flush existing ones */
	if (dbf->insert(conn,entry->cols,(db_val_t *)-1,entry->col_no) < 0)
	{
		LM_ERR("failed to flush rows to DB\n");
		return -1;
	}

	return 0;
}

void ql_force_process_disconnect(int p_id)
{
	query_list_t *it;

	if (query_list) {
		for (it=*query_list;it;it=it->next) {
			lock_get(it->lock);

			if (it->conn[p_id]) {
				it->dbf.close(it->conn[p_id]);
				it->conn[p_id]=NULL;
			}

			lock_release(it->lock);
		}
	}
}

