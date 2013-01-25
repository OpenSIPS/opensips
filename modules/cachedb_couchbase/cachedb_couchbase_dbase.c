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

static void couchbase_error_cb(lcb_t instance,
		lcb_error_t error,
		const char *errinfo)
{
	LM_ERR("Error %d occured. Extra info : [%s]\n",error,
		errinfo?errinfo:"");

	last_error = error;
}
static void couchbase_get_cb(lcb_t instance,
		const void *cookie, lcb_error_t error,
		const lcb_get_resp_t *item)
{
	if (error != LCB_SUCCESS) {
		LM_ERR("Failure to get %.*s\n",(int)item->v.v0.nkey,(char*)item->v.v0.key);
		last_error = error;
		return;
	}

	get_res.s = pkg_malloc((int)item->v.v0.nbytes);
	if (!get_res.s) {
		LM_ERR("No more pkg mem\n");
		last_error = -1;
		return;
	}

	memcpy(get_res.s,item->v.v0.bytes,item->v.v0.nbytes);
	get_res.len = item->v.v0.nbytes;
}

static void couchbase_store_cb(lcb_t instance, const void *cookie,
							lcb_storage_t operation,
							lcb_error_t err,
							const lcb_store_resp_t *item)
{
	if (err != LCB_SUCCESS) {
		LM_ERR("Failure to store %.*s\n",(int)item->v.v0.nkey,(char*)item->v.v0.key);
		last_error = err;
	}
}

static void couchbase_remove_cb(lcb_t instance,
							const void *cookie,
							lcb_error_t err,
							const lcb_remove_resp_t *item)
{
	if (err != LCB_SUCCESS) {
		LM_ERR("Failure to remove %.*s\n",(int)item->v.v0.nkey,(char*)item->v.v0.key);
		last_error = err;
	}
}

static void couchbase_arithmetic_cb(lcb_t instance,
								const void *cookie,
								lcb_error_t error,
								const lcb_arithmetic_resp_t *item)
{
	if (error != LCB_SUCCESS) {
		LM_ERR("Failure to remove %.*s\n",(int)item->v.v0.nkey,(char*)item->v.v0.key);
		last_error = error;
		return;
	}

	arithmetic_res = item->v.v0.value;
}

couchbase_con* couchbase_new_connection(struct cachedb_id* id)
{
	couchbase_con *con;
	struct lcb_create_st options;
	lcb_t instance;
	lcb_error_t rc;

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
	memset(&options,0,sizeof(struct lcb_create_st));
	options.version = 0;
	options.v.v0.host = id->host;
	options.v.v0.user = id->username;
	options.v.v0.passwd = id->password;
	options.v.v0.bucket = id->database;
	rc=lcb_create(&instance, &options);
	if (rc!=LCB_SUCCESS) {
		LM_ERR("Failed to create libcouchbase instance: 0x%02x, %s\n",
		       rc, lcb_strerror(NULL, rc));
		return 0;
	}


	(void)lcb_set_error_callback(instance,
			couchbase_error_cb);
	(void)lcb_set_get_callback(instance,
			couchbase_get_cb);
	(void)lcb_set_store_callback(instance,
			couchbase_store_cb);
	(void)lcb_set_remove_callback(instance,
			couchbase_remove_cb);
	(void)lcb_set_arithmetic_callback(instance,couchbase_arithmetic_cb);
	(void)lcb_set_timeout(instance,couch_timeout_usec);

	rc=lcb_connect(instance);
	if (rc != LCB_SUCCESS || last_error != 0) {
		LM_ERR("Failed to connect to the Couchbase node: 0x%02x, %s\n",
		       rc, lcb_strerror(instance, rc));
		lcb_destroy(instance);
		return 0;
	}

	/* Wait for the connect to complete */
	lcb_wait(instance);

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
	lcb_destroy(c->couchcon);
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
	lcb_t instance;
	lcb_error_t oprc;
	lcb_store_cmd_t cmd;
	const lcb_store_cmd_t *commands[1];

	last_error = 0;

	instance = COUCHBASE_CON(connection);

	commands[0] = &cmd;
	memset(&cmd, 0, sizeof(cmd));
	cmd.v.v0.operation = LCB_SET;
	cmd.v.v0.key = attr->s;
	cmd.v.v0.nkey = attr->len;
	cmd.v.v0.bytes = val->s;
	cmd.v.v0.nbytes = val->len;
	cmd.v.v0.exptime = expires;
	oprc = lcb_store(instance, NULL, 1, commands);

	if (oprc != LCB_SUCCESS) {
		LM_ERR("Failed to send the insert query\n");
		return -1;
	}

	lcb_wait(instance);

	oprc = lcb_get_last_error(instance);
	if (oprc != LCB_SUCCESS || last_error != 0) {
		LM_ERR("Failed to store the key\n");
		return -1;
	}

	LM_DBG("Succesfully stored\n");
	return 1;
}

int couchbase_remove(cachedb_con *connection,str *attr)
{
	lcb_t instance;
	lcb_error_t oprc;
	lcb_remove_cmd_t cmd;
	const lcb_remove_cmd_t *commands[1];

	last_error = 0;

	instance = COUCHBASE_CON(connection);
	commands[0] = &cmd;
	memset(&cmd, 0, sizeof(cmd));
	cmd.v.v0.key = attr->s;
	cmd.v.v0.nkey = attr->len;
	oprc = lcb_remove(instance, NULL, 1, commands);

	if (oprc != LCB_SUCCESS) {
		LM_ERR("Failed to send the insert query\n");
		return -1;
	}

	lcb_wait(instance);

	oprc = lcb_get_last_error(instance);
	if (oprc != LCB_SUCCESS || last_error != 0) {
		LM_ERR("Failed to store the key\n");
		return -1;
	}

	LM_DBG("Succesfully stored\n");
	return 1;
}

int couchbase_get(cachedb_con *connection,str *attr,str *val)
{
	lcb_t instance;
	lcb_error_t oprc;
	lcb_get_cmd_t cmd;
	const lcb_get_cmd_t *commands[1];

	last_error = 0;
	instance = COUCHBASE_CON(connection);

	commands[0] = &cmd;
	memset(&cmd, 0, sizeof(cmd));
	cmd.v.v0.key = attr->s;
	cmd.v.v0.nkey = attr->len;
	oprc = lcb_get(instance, NULL, 1, commands);

	if (oprc != LCB_SUCCESS) {
		LM_ERR("Failed to send the insert query\n");
		return -1;
	}

	lcb_wait(instance);

	oprc = lcb_get_last_error(instance);
	if (oprc != LCB_SUCCESS || last_error != 0) {
		LM_ERR("Failed to store the key\n");
		return -1;
	}

	*val = get_res;
	return 1;
}

int couchbase_add(cachedb_con *connection,str *attr,int val,int expires,int *new_val)
{
	lcb_t instance;
	lcb_error_t oprc;
	lcb_arithmetic_cmd_t cmd;
	const lcb_arithmetic_cmd_t *commands[1];

	last_error = 0;
	instance = COUCHBASE_CON(connection);

	commands[0] = &cmd;
	memset(&cmd, 0, sizeof(cmd));
	cmd.v.v0.key = attr->s;
	cmd.v.v0.nkey = attr->len;
	cmd.v.v0.delta = val;
	cmd.v.v0.create = 1;
	cmd.v.v0.initial = val;
	cmd.v.v0.exptime = expires;
	oprc = lcb_arithmetic(instance, NULL, 1, commands);

	if (oprc != LCB_SUCCESS) {
		LM_ERR("Failed to send the insert query\n");
		return -1;
	}

	lcb_wait(instance);

	oprc = lcb_get_last_error(instance);
	if (oprc != LCB_SUCCESS || last_error != 0) {
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
