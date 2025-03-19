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
extern int couch_lazy_connect;
extern int couch_exec_threshold;

volatile str get_res = {0,0};
volatile int arithmetic_res = 0;
volatile lcb_STATUS op_error  = LCB_SUCCESS;

static void couchbase_get_cb(lcb_INSTANCE* instance,
		const void *cookie, lcb_STATUS error,
		const lcb_RESPGET *item)
{
	op_error = error;

	const char *key, *value;
	size_t nkey, nvalue;
	lcb_respget_key(item, &key, &nkey);

	if (error != LCB_SUCCESS) {
		if (error != LCB_ERR_DOCUMENT_NOT_FOUND) {
			LM_ERR("Failure to get %.*s - %s\n", (int)nkey, key, lcb_strerror_short(error));
		}

		return;
	}

	lcb_respget_value(item, &value, &nvalue);

	get_res.s = pkg_malloc((int)nvalue);
	if (!get_res.s) {
		LM_ERR("No more pkg mem\n");
		return;
	}

	memcpy(get_res.s, value, nvalue);
	get_res.len = nvalue;
}

static void couchbase_store_cb(lcb_INSTANCE* instance, const void *cookie,
							lcb_STORE_OPERATION operation,
							lcb_STATUS err,
							const lcb_RESPSTORE *item)
{
	op_error = err;

	const char *key;
	size_t nkey;
	lcb_respstore_key(item, &key, &nkey);

	if (err != LCB_SUCCESS) {
		LM_ERR("Failure to store %.*s - %s\n", (int)nkey, key, lcb_strerror_short(err));
	}
}

static void couchbase_remove_cb(lcb_INSTANCE* instance,
							const void *cookie,
							lcb_STATUS err,
							const lcb_RESPREMOVE *item)
{
	op_error = err;

	const char *key;
	size_t nkey;
	lcb_respremove_key(item, &key, &nkey);

	if (err != LCB_SUCCESS) {
		if (err != LCB_ERR_DOCUMENT_NOT_FOUND) {
			LM_ERR("Failure to remove %.*s - %s\n", (int)nkey, key, lcb_strerror_short(err));
		}
	}
}

static void couchbase_arithmetic_cb(lcb_INSTANCE* instance,
								const void *cookie,
								lcb_STATUS error,
								const lcb_RESPCOUNTER *item)
{
	op_error = error;

	const char *key;
	size_t nkey;
	uint64_t value;

	lcb_respcounter_key(item, &key, &nkey);

	if (error != LCB_SUCCESS) {
		LM_ERR("Failure to perform arithmetic %.*s - %s\n", (int)nkey, key, lcb_strerror_short(error));
		return;
	}

	lcb_respcounter_value(item, &value);
	arithmetic_res = value;
}

lcb_STATUS cb_connect(lcb_INSTANCE* instance) {
	lcb_STATUS rc;

	rc = lcb_connect(instance);

	if (rc != LCB_SUCCESS) {
		return rc;
	}

	rc = lcb_wait(instance, LCB_WAIT_DEFAULT);

	if (rc != LCB_SUCCESS) {
		return rc;
	}

	rc = lcb_get_bootstrap_status(instance);

	return rc;
}

lcb_STATUS cb_get(lcb_INSTANCE* instance, const lcb_CMDGET *commands) {
	lcb_STATUS rc;

	rc = lcb_get(instance, NULL, commands);

	if (rc != LCB_SUCCESS) {
		return rc;
	}

	rc = lcb_wait(instance, LCB_WAIT_DEFAULT);

	if (rc != LCB_SUCCESS) {
		return rc;
	}

	return op_error;
}

lcb_STATUS cb_store(lcb_INSTANCE* instance, const lcb_CMDSTORE *commands) {
	lcb_STATUS rc;

	rc = lcb_store(instance, NULL, commands);

	if (rc != LCB_SUCCESS) {
		return rc;
	}

	rc = lcb_wait(instance, LCB_WAIT_DEFAULT);

	if (rc != LCB_SUCCESS) {
		return rc;
	}

	return op_error;
}

lcb_STATUS cb_counter(lcb_INSTANCE* instance, const lcb_CMDCOUNTER *commands) {
	lcb_STATUS rc;

	rc = lcb_counter(instance, NULL, commands);

	if (rc != LCB_SUCCESS) {
		return rc;
	}

	rc = lcb_wait(instance, LCB_WAIT_DEFAULT);

	if (rc != LCB_SUCCESS) {
		return rc;
	}

	return op_error;
}

lcb_STATUS cb_remove(lcb_INSTANCE* instance, const lcb_CMDREMOVE *commands) {
	lcb_STATUS rc;

	rc = lcb_remove(instance, NULL, commands);

	if (rc != LCB_SUCCESS) {
		return rc;
	}

	rc = lcb_wait(instance, LCB_WAIT_DEFAULT);

	if (rc != LCB_SUCCESS) {
		return rc;
	}

	return op_error;
}

#define CBASE_BUF_SIZE	256

couchbase_con* couchbase_connect(struct cachedb_id* id, int is_reconnect)
{
	/* buffer used to temporary store the host, in case we need to build it */
	char tmp_buf[CBASE_BUF_SIZE];
	couchbase_con *con;
	lcb_CREATEOPTS *options = NULL;
	lcb_uint32_t tmo = 0;
	lcb_INSTANCE* instance;
	lcb_STATUS rc;
	int l;

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

	lcb_createopts_create(&options, LCB_TYPE_BUCKET);

	lcb_createopts_credentials(options, id->username, strlen(id->username), id->password, strlen(id->password));

	/* we don't care whether it has CACHEDB_ID_MULTIPLE_HOSTS, because
	 * - if it does, it does not have a port and it should be printed as
	 *   string
	 * - if it does not, simply port the host as string and port if necessary
	 */
	if (!id->port)
		l = snprintf(tmp_buf, CBASE_BUF_SIZE, "couchbase://%s/%s", id->host, id->database);
	else
		l = snprintf(tmp_buf, CBASE_BUF_SIZE, "couchbase://%s:%hu/%s", id->host, id->port,
				id->database);

	if (l >= CBASE_BUF_SIZE) {
		LM_ERR("not enough buffer to print the URL: %.*s\n", CBASE_BUF_SIZE, tmp_buf);
		 lcb_createopts_destroy(options);
		return 0;
	}

	LM_DBG("Connecting URL: %s\n", tmp_buf);
	lcb_createopts_connstr(options, tmp_buf, CBASE_BUF_SIZE);

	rc=lcb_create(&instance, options);
	lcb_createopts_destroy(options);

	if (rc!=LCB_SUCCESS) {
		LM_ERR("Failed to create libcouchbase instance: 0x%02x, %s\n",
		       rc, lcb_strerror_short(rc));
		return 0;
	}

	(void)lcb_install_callback(instance, LCB_CALLBACK_GET, (lcb_RESPCALLBACK)couchbase_get_cb);
	(void)lcb_install_callback(instance, LCB_CALLBACK_STORE, (lcb_RESPCALLBACK)couchbase_store_cb);
	(void)lcb_install_callback(instance, LCB_CALLBACK_REMOVE, (lcb_RESPCALLBACK)couchbase_remove_cb);
	(void)lcb_install_callback(instance, LCB_CALLBACK_COUNTER, (lcb_RESPCALLBACK)couchbase_arithmetic_cb);

	//Set Timeout
	tmo = (lcb_uint32_t)couch_timeout_usec;
	lcb_cntl(instance, LCB_CNTL_SET, LCB_CNTL_OP_TIMEOUT, &tmo);

	if (couch_lazy_connect == 0 || is_reconnect == 1) {
		rc=cb_connect(instance);

		/*Check connection*/
		if (rc != LCB_SUCCESS) {
			/*Consider these connect failurs as fatal*/
			if(rc == LCB_ERR_AUTHENTICATION_FAILURE || rc == LCB_ERR_INVALID_HOST_FORMAT || rc == LCB_ERR_INVALID_CHAR) {
				LM_ERR("Fatal connection error to Couchbase. Host: %s Bucket: %s Error: %s",
					id->host, id->database, lcb_strerror_short(rc));
				lcb_destroy(instance);
				return 0;
			} else {
			/* Non-fatal errors, we may be able to connect later */
				LM_ERR("Non-Fatal connection error to Couchbase. Host: %s Bucket: %s Error: %s",
					id->host, id->database, lcb_strerror_short(rc));
			}
		} else {
			LM_DBG("Successfully connected to Couchbase Server. Host: %s Bucket: %s\n", id->host, id->database);
		}
	}

	con->couchcon = instance;
	return con;
}

couchbase_con* couchbase_new_connection(struct cachedb_id* id)
{
	return couchbase_connect(id, 0);
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

/*Conditionally reconnect based on the error code*/
int couchbase_conditional_reconnect(cachedb_con *con, lcb_STATUS err) {
	cachedb_pool_con *tmp;
	void *newcon;

	if (!con) return -1;

	switch (err) {
		/* Error codes to attempt reconnects on */
		case LCB_ERR_SDK_INTERNAL:
		case LCB_ERR_NO_CONFIGURATION:
		case LCB_ERR_NETWORK:
		case LCB_ERR_TIMEOUT:
		break;
		default:
			/*nothing to do*/
			return 0;
		break;
	}

	tmp = (cachedb_pool_con*)(con->data);
	LM_ERR("Attempting reconnect to Couchbase. Host: %s Bucket: %s On Error: %s",
		tmp->id->host, tmp->id->database, lcb_strerror_short(err));

	newcon = couchbase_connect(tmp->id, 1);

	/*Successful reconnect, get rid of the old handle*/
	if (newcon != NULL) {
		LM_ERR("Successfully reconnected to Couchbase. Host: %s Bucket: %s", tmp->id->host, tmp->id->database);
		tmp->id = NULL;
		couchbase_free_connection(tmp);
		con->data = newcon;
		return 1;
	}

	LM_ERR("Failed to reconnect to Couchbase. Host: %s Bucket: %s", tmp->id->host, tmp->id->database);
	return -2;
}

int couchbase_set(cachedb_con *connection,str *attr,
		str *val,int expires)
{
	lcb_INSTANCE* instance;
	lcb_STATUS oprc;
	lcb_CMDSTORE *commands;
	struct timeval start;

	start_expire_timer(start,couch_exec_threshold);
	instance = COUCHBASE_CON(connection);
	lcb_cmdstore_create(&commands, LCB_STORE_UPSERT);
	lcb_cmdstore_key(commands, attr->s, attr->len);
	lcb_cmdstore_value(commands, val->s, val->len);
	lcb_cmdstore_expiry(commands, expires);
	oprc = cb_store(instance, commands);
	lcb_cmdstore_destroy(commands);

	if (oprc != LCB_SUCCESS) {
		LM_ERR("Set request failed - %s\n", lcb_strerror_short(oprc));
		//Attempt reconnect
		if(couchbase_conditional_reconnect(connection, oprc) != 1) {
			_stop_expire_timer(start,couch_exec_threshold,
				"cachedb_couchbase set",attr->s,attr->len,0,
				cdb_slow_queries, cdb_total_queries);
			return -2;
		}

		//Try again
		instance = COUCHBASE_CON(connection);
		lcb_cmdstore_create(&commands, LCB_STORE_UPSERT);
		lcb_cmdstore_key(commands, attr->s, attr->len);
		lcb_cmdstore_value(commands, val->s, val->len);
		lcb_cmdstore_expiry(commands, expires);
		oprc = cb_store(instance, commands);
		lcb_cmdstore_destroy(commands);

		if (oprc != LCB_SUCCESS) {
			LM_ERR("Set command retry failed - %s\n", lcb_strerror_short(oprc));
			_stop_expire_timer(start,couch_exec_threshold,
				"cachedb_couchbase set",attr->s,attr->len,0,
				cdb_slow_queries, cdb_total_queries);
			return -2;
		}
		LM_ERR("Set command successfully retried\n");
	}
	LM_DBG("Successfully stored\n");
	_stop_expire_timer(start,couch_exec_threshold,
		"cachedb_couchbase set",attr->s,attr->len,0,
		cdb_slow_queries, cdb_total_queries);
	return 1;
}

int couchbase_remove(cachedb_con *connection,str *attr)
{
	lcb_INSTANCE* instance;
	lcb_STATUS oprc;
	lcb_CMDREMOVE *commands;
	struct timeval start;

	start_expire_timer(start,couch_exec_threshold);
	instance = COUCHBASE_CON(connection);
	lcb_cmdremove_create(&commands);
	lcb_cmdremove_key(commands, attr->s, attr->len);
	oprc = cb_remove(instance, commands);
	lcb_cmdremove_destroy(commands);

	if (oprc != LCB_SUCCESS) {
		if (oprc == LCB_ERR_DOCUMENT_NOT_FOUND) {
			_stop_expire_timer(start,couch_exec_threshold,
				"cachedb_couchbase remove",attr->s,attr->len,0,
				cdb_slow_queries, cdb_total_queries);
			return -1;
		}

		LM_ERR("Failed to send the remove query - %s\n", lcb_strerror_short(oprc));
		if (couchbase_conditional_reconnect(connection, oprc) != 1) {
			_stop_expire_timer(start,couch_exec_threshold,
				"cachedb_couchbase remove",attr->s,attr->len,0,
				cdb_slow_queries, cdb_total_queries);
			return -2;
		};

		//Try again
		instance = COUCHBASE_CON(connection);
		lcb_cmdremove_create(&commands);
		lcb_cmdremove_key(commands, attr->s, attr->len);
		oprc = cb_remove(instance, commands);
		lcb_cmdremove_destroy(commands);

		if (oprc != LCB_SUCCESS) {
			if (oprc == LCB_ERR_DOCUMENT_NOT_FOUND) {
				LM_ERR("Remove command successfully retried\n");
				_stop_expire_timer(start,couch_exec_threshold,
					"cachedb_couchbase remove",attr->s,attr->len,0,
					cdb_slow_queries, cdb_total_queries);
				return -1;
			}
			LM_ERR("Remove command retry failed - %s\n", lcb_strerror_short(oprc));
			_stop_expire_timer(start,couch_exec_threshold,
				"cachedb_couchbase remove",attr->s,attr->len,0,
				cdb_slow_queries, cdb_total_queries);
			return -2;
		}
		LM_ERR("Remove command successfully retried\n");
	}

	LM_DBG("Successfully removed\n");
	_stop_expire_timer(start,couch_exec_threshold,
		"cachedb_couchbase remove",attr->s,attr->len,0,
		cdb_slow_queries, cdb_total_queries);
	return 1;
}

int couchbase_get(cachedb_con *connection,str *attr,str *val)
{
	lcb_INSTANCE* instance;
	lcb_STATUS oprc;
	lcb_CMDGET *commands;
	struct timeval start;

	start_expire_timer(start,couch_exec_threshold);
	instance = COUCHBASE_CON(connection);
	lcb_cmdget_create(&commands);
	lcb_cmdget_key(commands, attr->s, attr->len);
	oprc = cb_get(instance, commands);
	lcb_cmdget_destroy(commands);

	if (oprc != LCB_SUCCESS) {
		/* Key not present, record does not exist */
		if (oprc == LCB_ERR_DOCUMENT_NOT_FOUND) {
			_stop_expire_timer(start,couch_exec_threshold,
				"cachedb_couchbase get",attr->s,attr->len,0,
				cdb_slow_queries, cdb_total_queries);
			return -1;
		}

		//Attempt reconnect
		if (couchbase_conditional_reconnect(connection, oprc) != 1) {
			_stop_expire_timer(start,couch_exec_threshold,
				"cachedb_couchbase get",attr->s,attr->len,0,
				cdb_slow_queries, cdb_total_queries);
			return -2;
		}

		//Try again
		instance = COUCHBASE_CON(connection);
		lcb_cmdget_create(&commands);
		lcb_cmdget_key(commands, attr->s, attr->len);
		oprc = cb_get(instance, commands);
		lcb_cmdget_destroy(commands);
		if (oprc != LCB_SUCCESS) {
			if (oprc == LCB_ERR_DOCUMENT_NOT_FOUND) {
				LM_ERR("Get command successfully retried\n");
				_stop_expire_timer(start,couch_exec_threshold,
					"cachedb_couchbase get",attr->s,attr->len,0,
					cdb_slow_queries, cdb_total_queries);
				return -1;
			}
			LM_ERR("Get command retry failed - %s\n", lcb_strerror_short(oprc));
			_stop_expire_timer(start,couch_exec_threshold,
				"cachedb_couchbase get",attr->s,attr->len,0,
				cdb_slow_queries, cdb_total_queries);
			return -2;
		}
		LM_ERR("Get command successfully retried\n");
	}

	//Incase of malloc failure
	if (!get_res.s) {
		_stop_expire_timer(start,couch_exec_threshold,
			"cachedb_couchbase get",attr->s,attr->len,0,
			cdb_slow_queries, cdb_total_queries);
		return -2;
	}

	_stop_expire_timer(start,couch_exec_threshold,
		"cachedb_couchbase get",attr->s,attr->len,0,
		cdb_slow_queries, cdb_total_queries);
	*val = get_res;
	return 1;
}

int couchbase_add(cachedb_con *connection,str *attr,int val,int expires,int *new_val)
{
	lcb_INSTANCE* instance;
	lcb_STATUS oprc;
	lcb_CMDCOUNTER *commands;
	struct timeval start;

	start_expire_timer(start,couch_exec_threshold);
	instance = COUCHBASE_CON(connection);
	lcb_cmdcounter_create(&commands);
	lcb_cmdcounter_key(commands, attr->s, attr->len);
	lcb_cmdcounter_delta(commands, val);
	lcb_cmdcounter_initial(commands, val);
	lcb_cmdcounter_expiry(commands, expires);
	oprc = cb_counter(instance, commands);
	lcb_cmdcounter_destroy(commands);

	if (oprc != LCB_SUCCESS) {
		if (oprc == LCB_ERR_DOCUMENT_NOT_FOUND) {
			return -1;
			_stop_expire_timer(start,couch_exec_threshold,
				"cachedb_couchbase add",attr->s,attr->len,0,
				cdb_slow_queries, cdb_total_queries);
		}

		LM_ERR("Failed to send the arithmetic query - %s\n", lcb_strerror_short(oprc));
		//Attempt reconnect
		if (couchbase_conditional_reconnect(connection, oprc) != 1) {
			_stop_expire_timer(start,couch_exec_threshold,
				"cachedb_couchbase add",attr->s,attr->len,0,
				cdb_slow_queries, cdb_total_queries);
			return -2;
		}

		//Try again
		instance = COUCHBASE_CON(connection);
		lcb_cmdcounter_create(&commands);
		lcb_cmdcounter_key(commands, attr->s, attr->len);
		lcb_cmdcounter_delta(commands, val);
		lcb_cmdcounter_initial(commands, val);
		lcb_cmdcounter_expiry(commands, expires);
		oprc = cb_counter(instance, commands);
		lcb_cmdcounter_destroy(commands);

		if (oprc != LCB_SUCCESS) {
			if (oprc == LCB_ERR_DOCUMENT_NOT_FOUND) {
				LM_ERR("Arithmetic command successfully retried\n");
				_stop_expire_timer(start,couch_exec_threshold,
					"cachedb_couchbase add",attr->s,attr->len,0,
					cdb_slow_queries, cdb_total_queries);
				return -1;
			}
			LM_ERR("Arithmetic command retry failed - %s\n", lcb_strerror_short(oprc));
			_stop_expire_timer(start,couch_exec_threshold,
				"cachedb_couchbase add",attr->s,attr->len,0,
				cdb_slow_queries, cdb_total_queries);
			return -2;
		}
		LM_ERR("Arithmetic command successfully retried\n");
	}

	if (new_val)
		*new_val = arithmetic_res;

	_stop_expire_timer(start,couch_exec_threshold,
		"cachedb_couchbase add",attr->s,attr->len,0,
		cdb_slow_queries, cdb_total_queries);
	return 1;
}

int couchbase_sub(cachedb_con *connection,str *attr,int val,int expires,int *new_val)
{
	return couchbase_add(connection,attr,-val,expires,new_val);
}

int couchbase_get_counter(cachedb_con *connection,str *attr,int *val)
{
	lcb_INSTANCE* instance;
	lcb_STATUS oprc;
	lcb_CMDGET *commands;
	struct timeval start;

	start_expire_timer(start,couch_exec_threshold);
	instance = COUCHBASE_CON(connection);
	lcb_cmdget_create(&commands);
	lcb_cmdget_key(commands, attr->s, attr->len);
	oprc = cb_get(instance, commands);
	lcb_cmdget_destroy(commands);

	if (oprc != LCB_SUCCESS) {
		/* Key not present, record does not exist */
		if (oprc == LCB_ERR_DOCUMENT_NOT_FOUND) {
			_stop_expire_timer(start,couch_exec_threshold,
				"cachedb_couchbase get counter",attr->s,attr->len,0,
				cdb_slow_queries, cdb_total_queries);
			return -1;
		}

		//Attempt reconnect
		if (couchbase_conditional_reconnect(connection, oprc) != 1) {
			_stop_expire_timer(start,couch_exec_threshold,
				"cachedb_couchbase get counter ",attr->s,attr->len,0,
				cdb_slow_queries, cdb_total_queries);
			return -2;
		}

		//Try again
		instance = COUCHBASE_CON(connection);
		lcb_cmdget_create(&commands);
		lcb_cmdget_key(commands, attr->s, attr->len);
		oprc = cb_get(instance, commands);
		lcb_cmdget_destroy(commands);
		if (oprc != LCB_SUCCESS) {
			if (oprc == LCB_ERR_DOCUMENT_NOT_FOUND) {
				LM_ERR("Get counter command successfully retried\n");
				_stop_expire_timer(start,couch_exec_threshold,
					"cachedb_couchbase get counter",attr->s,attr->len,0,
					cdb_slow_queries, cdb_total_queries);
				return -1;
			}
			LM_ERR("Get counter command retry failed - %s\n", lcb_strerror_short(oprc));
			_stop_expire_timer(start,couch_exec_threshold,
				"cachedb_couchbase get counter",attr->s,attr->len,0,
				cdb_slow_queries, cdb_total_queries);
			return -2;
		}
		LM_ERR("Get command successfully retried\n");
	}

	//Incase of malloc failure
	if (!get_res.s) {
		_stop_expire_timer(start,couch_exec_threshold,
			"cachedb_couchbase get counter",attr->s,attr->len,0,
			cdb_slow_queries, cdb_total_queries);
		return -2;
	}

	_stop_expire_timer(start,couch_exec_threshold,
		"cachedb_couchbase get counter",attr->s,attr->len,0,
		cdb_slow_queries, cdb_total_queries);

	if (str2sint((str *)&get_res,val)) {
		LM_ERR("Failued to convert counter [%.*s] to int\n",get_res.len,get_res.s);
		pkg_free(get_res.s);
		get_res.s = NULL;
		return -1;
	}

	pkg_free(get_res.s);
	get_res.s = NULL;
	return 1;
}
