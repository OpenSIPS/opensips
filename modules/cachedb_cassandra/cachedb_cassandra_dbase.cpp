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
 *  2011-12-xx  created (vlad-paiu)
 */

#include "cachedb_cassandra.h"
#include "cachedb_cassandra_dbase.h"
#include "cachedb_cassandra_lib.h"
#include <string.h>

void* cassandra_new_connection(char *_host,int port,str *_keyspace,str* _cf,
	str* _counterf)
{
	string host(_host,strlen(_host));
	string keyspace(_keyspace->s,_keyspace->len);
	string cf(_cf->s,_cf->len);
	string counterf(_counterf->s,_counterf->len);

	CassandraConnection *con = new CassandraConnection(keyspace,cf,counterf);
	if (!con) {
		LM_ERR("failed to init CassandraConnection\n");
		return NULL;
	}

	if (con->cassandra_open(host,port,conn_timeout,send_timeout,
		recv_timeout,rd_consistency_level,wr_consistency_level) < 0) {
		LM_ERR("failed to connect to Cassandra DB\n");
		delete con;
		return NULL;
	}

	return (void *)con;
}

void* cassandra_init_connection(struct cachedb_id *id)
{
	cassandra_con *con;
	str keyspace;
	str column_family;
	str counter_family;
	int db_len;
	char *p;

	if (id == NULL) {
		LM_ERR("null cachedb_id\n");
		return 0;
	}

	if (id->flags & CACHEDB_ID_MULTIPLE_HOSTS) {
		LM_ERR("multiple hosts are not supported for cassandra\n");
		return 0;
	}

	if (id->database == NULL) {
		LM_ERR("no database supplied for cassandra\n");
		return 0;
	}

	db_len = strlen(id->database);

	p=(char *)memchr(id->database,'_',db_len);
	if (!p) {
		LM_ERR("invalid database. Should be 'keyspace_columnfamily_counterfamily'\n");
		return 0;
	}


	keyspace.s=id->database;
	keyspace.len=p-keyspace.s;

	column_family.s=p+1;

	p = (char *)memchr(column_family.s,'_',id->database+db_len-p-1);
	if (!p) {
		LM_ERR("invalid database. Should be 'keyspace_columnfamily_counterfamily'\n");
		return 0;
	}

	column_family.len=p-column_family.s;

	counter_family.s=p+1;
	counter_family.len=id->database+db_len-counter_family.s;

	LM_INFO("Keyspace = [%.*s]. ColumnFamily = [%.*s]. CounterFamily = [%.*s]\n",
		keyspace.len,keyspace.s,column_family.len,column_family.s,
		counter_family.len,counter_family.s);

	con = (cassandra_con *)pkg_malloc(sizeof(cassandra_con));
	if (con == NULL) {
		LM_ERR("no more pkg \n");
		return 0;
	}

	memset(con,0,sizeof(cassandra_con));
	con->id = id;
	con->ref = 1;

	con->cass_con = cassandra_new_connection(id->host,id->port,
		&keyspace,&column_family,&counter_family);

	if (con->cass_con == NULL) {
		LM_ERR("failed to connect to cassandra\n");
		return 0;
	}

	return con;
}

cachedb_con *cassandra_init(str *url)
{
	return cachedb_do_init(url,cassandra_init_connection);
}

void cassandra_free_connection(cachedb_pool_con *con)
{
	cassandra_con * c;
	CassandraConnection *c_con;

	if (!con) return;
	c = (cassandra_con *)con;
	c_con = (CassandraConnection *)c->cass_con;
	c_con->cassandra_close();
	delete c_con;
	pkg_free(c);
}

void cassandra_destroy(cachedb_con *con) {
	cachedb_do_close(con,cassandra_free_connection);
}

int cassandra_get(cachedb_con *connection,str *attr,str *val)
{
	cassandra_con *con;
	CassandraConnection *c_con;
	char* col_val;
	int len;
	string col_name(attr->s,attr->len);

	if (!attr || !val || !connection) {
		LM_ERR("null parameter\n");
		return -1;
	}

	con = (cassandra_con *)connection->data;
	c_con = (CassandraConnection *)con->cass_con;

	col_val=c_con->cassandra_simple_get(col_name);
	if (col_val == NULL) {
		LM_ERR("failed to fetch Cassandra value\n");
		return -1;
	}

	if (col_val == (char *)-1) {
		LM_DBG("no such key - %.*s\n",attr->len,attr->s);
		val->s = NULL;
		val->len = 0;
		return -2;
	}

	len=strlen(col_val);
	val->s = (char *)pkg_malloc(len);
	if (val->s == NULL) {
		LM_ERR("no more pkg\n");
		return -1;
	}

	val->len=len;
	memcpy(val->s,col_val,len);
	return 0;
}

int cassandra_get_counter(cachedb_con *connection,str *attr,int *val)
{
	cassandra_con *con;
	CassandraConnection *c_con;
	int ret;
	string col_name(attr->s,attr->len);

	if (!attr || !val || !connection) {
		LM_ERR("null parameter\n");
		return -1;
	}

	con = (cassandra_con *)connection->data;
	c_con = (CassandraConnection *)con->cass_con;

	ret=c_con->cassandra_simple_get_counter(col_name,val);
	if (ret < 0) {
		LM_ERR("failed to fetch Cassandra value\n");
		return -1;
	}

	return 0;
}

int cassandra_set(cachedb_con *connection,str *attr,str *val,int expires)
{
	cassandra_con *con;
	CassandraConnection *c_con;
	string col_name(attr->s,attr->len);
	string col_val(val->s,val->len);
	int ret;

	if (!attr || !val || !connection) {
		LM_ERR("null parameter\n");
		return -1;
	}

	con = (cassandra_con *)connection->data;
	c_con = (CassandraConnection *)con->cass_con;

	ret = c_con->cassandra_simple_insert(col_name,col_val,expires);
	if (ret<0) {
		LM_ERR("Failed to insert Cassandra key\n");
		return -1;
	}

	LM_DBG("Succesful cassandra insert\n");
	return 0;
}

int cassandra_remove(cachedb_con *connection,str *attr)
{
	cassandra_con *con;
	CassandraConnection *c_con;
	string col_name(attr->s,attr->len);
	int ret;

	if (!attr || !connection) {
		LM_ERR("null parameter\n");
		return -1;
	}

	con = (cassandra_con *)connection->data;
	c_con = (CassandraConnection *)con->cass_con;

	ret = c_con->cassandra_simple_remove(col_name);
	if (ret<0) {
		LM_ERR("Failed to remove Cassandra key\n");
		return -1;
	}

	LM_DBG("Succesful cassandra remove\n");
	return 0;
}

int cassandra_add(cachedb_con *connection,str *attr,int val,int expires,int *new_val)
{
	cassandra_con *con;
	CassandraConnection *c_con;
	string col_name(attr->s,attr->len);
	int ret;

	if (!attr || !connection) {
		LM_ERR("null parameter\n");
		return -1;
	}

	con = (cassandra_con *)connection->data;
	c_con = (CassandraConnection *)con->cass_con;

	/* TODO - so far no support for expiring counters */
	ret = c_con->cassandra_simple_add(col_name,val);
	if (ret<0) {
		LM_ERR("Failed to add Cassandra key\n");
		return -1;
	}

	LM_DBG("Succesful cassandra add\n");

	ret=c_con->cassandra_simple_get_counter(col_name,new_val);
	if (ret < 0) {
		LM_ERR("failed to fetch Cassandra value\n");
		return -1;
	}

	if (ret > 0) {
		LM_DBG("no such key - %.*s\n",attr->len,attr->s);
		return -2;
	}

	return 0;
}

int cassandra_sub(cachedb_con *connection,str *attr,int val,int expires,int *new_val)
{
	cassandra_con *con;
	CassandraConnection *c_con;
	string col_name(attr->s,attr->len);
	int ret;

	if (!attr || !connection) {
		LM_ERR("null parameter\n");
		return -1;
	}

	con = (cassandra_con *)connection->data;
	c_con = (CassandraConnection *)con->cass_con;

	/* TODO - so far no support for expiring counters */
	ret = c_con->cassandra_simple_sub(col_name,val);
	if (ret<0) {
		LM_ERR("Failed to add Cassandra key\n");
		return -1;
	}

	LM_DBG("Succesful cassandra sub\n");

	ret=c_con->cassandra_simple_get_counter(col_name,new_val);
	if (ret < 0) {
		LM_ERR("failed to fetch Cassandra value\n");
		return -1;
	}

	if (ret > 0) {
		LM_DBG("no such key - %.*s\n",attr->len,attr->s);
		return -2;
	}

	return 0;
}
