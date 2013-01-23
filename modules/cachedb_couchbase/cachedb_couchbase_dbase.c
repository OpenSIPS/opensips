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
 *  2013-01-xx  created (vlad-paiu)
 */

#include "../../dprint.h"
#include "cachedb_couchbase_dbase.h"
#include "../../mem/mem.h"
#include "../../ut.h"
#include "../../cachedb/cachedb.h"

#include <string.h>
#include <libcouchbase/couchbase.h>

extern int couch_timeout_usec;

volatile int last_error = 0;
volatile str get_res = {0,0};
volatile int arithmetic_res = 0;

static void couchbase_error_cb(libcouchbase_t instance,
		libcouchbase_error_t error,
		const char *errinfo)
{
	LM_ERR("Error %d occured. Extra info : [%s]\n",error,
		errinfo?errinfo:"");

	last_error = error;
}
static void couchbase_get_cb(libcouchbase_t instance,
				const void *cookie,
				libcouchbase_error_t error,
				const void *key, size_t nkey,
				const void *bytes, size_t nbytes,
				uint32_t flags, uint64_t cas)
{
	if (error != LIBCOUCHBASE_SUCCESS) {
		LM_ERR("Failure to get %.*s\n",(int)nkey,(char*)key);
		last_error = error;
		return;
	}

	get_res.s = pkg_malloc((int)nbytes);
	if (!get_res.s) {
		LM_ERR("No more pkg mem\n");
		last_error = -1;
		return;
	}

	memcpy(get_res.s,bytes,nbytes);
	get_res.len = nbytes;
}

static void couchbase_store_cb(libcouchbase_t instance,
							const void *cookie,
							libcouchbase_storage_t operation,
							libcouchbase_error_t err,
							const void *key, size_t nkey,
							uint64_t cas) 
{
	if (err != LIBCOUCHBASE_SUCCESS) {
		LM_ERR("Failure to store %.*s\n",(int)nkey,(char*)key);
		last_error = err;
	}
}

static void couchbase_remove_cb(libcouchbase_t instance,
							const void *cookie,
							libcouchbase_error_t err,
							const void *key, size_t nkey)
{
	if (err != LIBCOUCHBASE_SUCCESS) {
		LM_ERR("Failure to remove %.*s\n",(int)nkey,(char*)key);
		last_error = err;
	}
}

static void couchbase_arithmetic_cb(libcouchbase_t instance,
									const void *cookie,
									libcouchbase_error_t error,
									const void *key,
									libcouchbase_size_t nkey,
									libcouchbase_uint64_t value,
									libcouchbase_cas_t cas)
{
	if (error != LIBCOUCHBASE_SUCCESS) {
		LM_ERR("Failure to remove %.*s\n",(int)nkey,(char*)key);
		last_error = error;
		return;
	}

	arithmetic_res = value;
}

couchbase_con* couchbase_new_connection(struct cachedb_id* id)
{
	couchbase_con *con;
	libcouchbase_t instance;

	last_error = 0;
	
	if (id == NULL) {
		LM_ERR("null cachedb_id\n");
		return 0;
	}
	
	con = pkg_malloc(sizeof(couchbase_con));
	if (con == NULL) {
		LM_ERR("no more pkg \n");
		return 0;
	}

	memset(con,0,sizeof(couchbase_con));
	con->id = id;
	con->ref = 1;

	/* TODO - support custom ports - couchbase expects host:port in id->host */
	instance=libcouchbase_create(id->host,id->username,
			id->password,id->database,NULL);
	if (instance==NULL) {
		LM_ERR("Failed to create libcouchbase instance\n");
		return 0;
	}
	
	
	(void)libcouchbase_set_error_callback(instance,
			couchbase_error_cb);
	(void)libcouchbase_set_get_callback(instance,
			couchbase_get_cb);
	(void)libcouchbase_set_storage_callback(instance,
			couchbase_store_cb);
	(void)libcouchbase_set_remove_callback(instance,
			couchbase_remove_cb);
	(void)libcouchbase_set_arithmetic_callback(instance,couchbase_arithmetic_cb);
	(void)libcouchbase_set_timeout(instance,couch_timeout_usec);

	if (libcouchbase_connect(instance) != LIBCOUCHBASE_SUCCESS || last_error != 0) {
		LM_ERR("Failed to connect to the Couchbase node\n");
		return 0;
	}

	/* Wait for the connect to complete */
	libcouchbase_wait(instance);

	LM_DBG("Succesfully connected to Couchbase Server\n");
	con->couchcon = instance;
	return con;
}

cachedb_con *couchbase_init(str *url)
{
	return cachedb_do_init(url,(void *)couchbase_new_connection);
}

void couchbase_free_connection(cachedb_pool_con *con)
{
	couchbase_con * c;

	LM_DBG("in couchbase_free_connection\n");

	if (!con) return;
	c = (couchbase_con *)con;
	libcouchbase_destroy(c->couchcon);
	pkg_free(c);
}

void couchbase_destroy(cachedb_con *con) 
{
	cachedb_do_close(con,couchbase_free_connection);
}

/* TODO - handle reconnection ? */

int couchbase_set(cachedb_con *connection,str *attr,
		str *val,int expires)
{
	libcouchbase_t instance;
	libcouchbase_error_t oprc;

	last_error = 0;

	instance = COUCHBASE_CON(connection);
	oprc = libcouchbase_store(instance,
			NULL,
			LIBCOUCHBASE_SET,
			attr->s,
			attr->len,
			val->s,
			val->len,
			0,
			expires,
			0);
	
	if (oprc != LIBCOUCHBASE_SUCCESS) {
		LM_ERR("Failed to send the insert query\n");
		return -1;
	}

	libcouchbase_wait(instance);

	oprc = libcouchbase_get_last_error(instance);
	if (oprc != LIBCOUCHBASE_SUCCESS || last_error != 0) {
		LM_ERR("Failed to store the key\n");
		return -1;
	}

	LM_DBG("Succesfully stored\n");
	return 1;
}

int couchbase_remove(cachedb_con *connection,str *attr)
{
	libcouchbase_t instance;
	libcouchbase_error_t oprc;

	last_error = 0;

	instance = COUCHBASE_CON(connection);
	oprc = libcouchbase_remove(instance,
			NULL,
			attr->s,
			attr->len,
			0);
	
	if (oprc != LIBCOUCHBASE_SUCCESS) {
		LM_ERR("Failed to send the insert query\n");
		return -1;
	}

	libcouchbase_wait(instance);

	oprc = libcouchbase_get_last_error(instance);
	if (oprc != LIBCOUCHBASE_SUCCESS || last_error != 0) {
		LM_ERR("Failed to store the key\n");
		return -1;
	}

	LM_DBG("Succesfully stored\n");
	return 1;
}

int couchbase_get(cachedb_con *connection,str *attr,str *val)
{
	libcouchbase_t instance;
	libcouchbase_error_t oprc;

	last_error = 0;
	instance = COUCHBASE_CON(connection);

	oprc = libcouchbase_mget(instance,
				NULL,
				1,
				(const void*const*)&attr->s,
				(const libcouchbase_size_t *)&attr->len,
				NULL);

	if (oprc != LIBCOUCHBASE_SUCCESS) {
		LM_ERR("Failed to send the insert query\n");
		return -1;
	}

	libcouchbase_wait(instance);

	oprc = libcouchbase_get_last_error(instance);
	if (oprc != LIBCOUCHBASE_SUCCESS || last_error != 0) {
		LM_ERR("Failed to store the key\n");
		return -1;
	}

	*val = get_res;
	return 1;
}

int couchbase_add(cachedb_con *connection,str *attr,int val,int expires,int *new_val)
{
	libcouchbase_t instance;
	libcouchbase_error_t oprc;

	last_error = 0;
	instance = COUCHBASE_CON(connection);

	oprc = libcouchbase_arithmetic(instance,
				NULL,
				attr->s,
				attr->len,
				val,
				expires,
				1,
				val);

	if (oprc != LIBCOUCHBASE_SUCCESS) {
		LM_ERR("Failed to send the insert query\n");
		return -1;
	}

	libcouchbase_wait(instance);

	oprc = libcouchbase_get_last_error(instance);
	if (oprc != LIBCOUCHBASE_SUCCESS || last_error != 0) {
		LM_ERR("Failed to store the key\n");
		return -1;
	}

	if (new_val)
		*new_val = arithmetic_res;

	return 1;
}

int couchbase_sub(cachedb_con *connection,str *attr,int val,int expires,int *new_val)
{
	return couchbase_add(connection,attr,-val,expires,new_val);
}

int couchbase_get_counter(cachedb_con *connection,str *attr,int *val)
{
	return couchbase_add(connection,attr,0,0,val);
}
