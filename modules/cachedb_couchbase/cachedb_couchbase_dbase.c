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
volatile lcb_error_t op_error  = LCB_SUCCESS;

static void couchbase_get_cb(lcb_t instance,
		const void *cookie, lcb_error_t error,
		const lcb_get_resp_t *item)
{
	op_error = error;

	if (error != LCB_SUCCESS) {
		if (error != LCB_KEY_ENOENT) {
			LM_ERR("Failure to get %.*s - %s\n",(int)item->v.v0.nkey,(char*)item->v.v0.key,lcb_strerror(instance, error));
		}

		return;
	}

	get_res.s = pkg_malloc((int)item->v.v0.nbytes);
	if (!get_res.s) {
		LM_ERR("No more pkg mem\n");
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

	op_error = err;

	if (err != LCB_SUCCESS) {
		LM_ERR("Failure to store %.*s - %s\n",(int)item->v.v0.nkey,(char*)item->v.v0.key,lcb_strerror(instance, err));
	}
}

static void couchbase_remove_cb(lcb_t instance,
							const void *cookie,
							lcb_error_t err,
							const lcb_remove_resp_t *item)
{
	op_error = err;

	if (err != LCB_SUCCESS) {
		if (err != LCB_KEY_ENOENT) {
			LM_ERR("Failure to remove %.*s - %s\n",(int)item->v.v0.nkey,(char*)item->v.v0.key,lcb_strerror(instance, err));
		}
	}
}

static void couchbase_arithmetic_cb(lcb_t instance,
								const void *cookie,
								lcb_error_t error,
								const lcb_arithmetic_resp_t *item)
{
	op_error = error;

	if (error != LCB_SUCCESS) {
		LM_ERR("Failure to perform arithmetic %.*s - %s\n",(int)item->v.v0.nkey,(char*)item->v.v0.key,lcb_strerror(instance, error));
		return;
	}

	arithmetic_res = item->v.v0.value;
}

lcb_error_t cb_connect(lcb_t instance) {
	lcb_error_t rc;

	rc = lcb_connect(instance);

	if (rc != LCB_SUCCESS) {
		return rc;
	}

	rc = lcb_wait(instance);

	if (rc != LCB_SUCCESS) {
		return rc;
	}

	rc = lcb_get_bootstrap_status(instance);

	return rc;
}

lcb_error_t cb_get(lcb_t instance, const void *command_cookie, lcb_size_t num, const lcb_get_cmd_t *const *commands) {
	lcb_error_t rc;

	rc = lcb_get(instance, command_cookie, num, commands);

	if (rc != LCB_SUCCESS) {
		return rc;
	}

	rc = lcb_wait(instance);

	if (rc != LCB_SUCCESS) {
		return rc;
	}

	return op_error;
}

lcb_error_t cb_store(lcb_t instance, const void *command_cookie, lcb_size_t num, const lcb_store_cmd_t *const *commands) {
	lcb_error_t rc;

	rc = lcb_store(instance, command_cookie, num, commands);

	if (rc != LCB_SUCCESS) {
		return rc;
	}

	rc = lcb_wait(instance);

	if (rc != LCB_SUCCESS) {
		return rc;
	}

	return op_error;
}

lcb_error_t cb_arithmetic(lcb_t instance, const void *command_cookie, lcb_size_t num, const lcb_arithmetic_cmd_t *const *commands) {
	lcb_error_t rc;

	rc = lcb_arithmetic(instance, command_cookie, num, commands);

	if (rc != LCB_SUCCESS) {
		return rc;
	}

	rc = lcb_wait(instance);

	if (rc != LCB_SUCCESS) {
		return rc;
	}

	return op_error;
}

lcb_error_t cb_remove(lcb_t instance, const void *command_cookie, lcb_size_t num, const lcb_remove_cmd_t *const *commands) {
	lcb_error_t rc;

	rc = lcb_remove(instance, command_cookie, num, commands);

	if (rc != LCB_SUCCESS) {
		return rc;
	}

	rc = lcb_wait(instance);

	if (rc != LCB_SUCCESS) {
		return rc;
	}

	return op_error;
}

#define CBASE_BUF_SIZE	256

/*
 * fill the options based on the id field
 * the buf and len are used to store the URL/Host in case we need to build it
 */
int couchbase_fill_options(struct cachedb_id *id, struct lcb_create_st *opt,
		char *buf, int len)
{
#if LCB_VERSION <= 0x020300
	char *p;
#endif
	int l;
	memset(opt, 0, sizeof(*opt));

#if LCB_VERSION <= 0x020300
	opt->version = 0;
	opt->v.v0.user = id->username;
	opt->v.v0.passwd = id->password;
	opt->v.v0.bucket = id->database;
	if (id->flags & CACHEDB_ID_MULTIPLE_HOSTS) {
		p = q_memchr(id->host, ',', len);
		if (p) {
			l = p - id->host;
			if (l >= len) {
				LM_ERR("Not enough space for the host [%.*s]%d>=%d\n",
						l, id->host, l, CBASE_BUF_SIZE);
				return -1;
			}
			memcpy(buf, id->host, l);
			buf[l] = 0;
			LM_WARN("Version %s does not support multiple hosts connection! "
					"Connecting only to first host: %s!\n",
					LCB_VERSION_STRING, buf);
			opt->v.v0.host = buf;
		}
	}
	/* when it comes with multiple hosts, the port is already in the id->host
	 * field, so we no longer need to worry to put it in the buffer */
	if (id->port) {
		if (snprintf(buf, len, "%s:%hu", id->host, id->port) >= len) {
			LM_ERR("cannot print %s:%hu in %d buffer\n", id->host, id->port, len);
			return -1;
		}
		opt->v.v0.host = buf;
	} else if (!opt->v.v0.host) {
		opt->v.v0.host = id->host;
	}
	LM_DBG("Connecting HOST: %s BUCKET: %s\n", opt->v.v0.host, opt->v.v0.bucket);
#else
	opt->version = 3;
	opt->v.v3.username = id->username;
	opt->v.v3.passwd = id->password;

	/* we don't care whether it has CACHEDB_ID_MULTIPLE_HOSTS, because
	 * - if it does, it does not have a port and it should be printed as
	 *   string
	 * - if it does not, simply port the host as string and port if necessary
	 */
	if (!id->port)
		l = snprintf(buf, len, "couchbase://%s/%s", id->host, id->database);
	else
		l = snprintf(buf, len, "couchbase://%s:%hu/%s", id->host, id->port,
				id->database);
	if (l >= len) {
		LM_ERR("not enough buffer to print the URL: %.*s\n", len, buf);
		return -1;
	}
	opt->v.v3.connstr = buf;
	LM_DBG("Connecting URL: %s\n", opt->v.v3.connstr);
#endif

	return 0;
}

couchbase_con* couchbase_connect(struct cachedb_id* id, int is_reconnect)
{
	/* buffer used to temporary store the host, in case we need to build it */
	char tmp_buf[CBASE_BUF_SIZE];
	couchbase_con *con;
	struct lcb_create_st options;
	lcb_uint32_t tmo = 0;
	lcb_t instance;
	lcb_error_t rc;

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

	if (couchbase_fill_options(id, &options, tmp_buf, CBASE_BUF_SIZE) < 0) {
		LM_ERR("cannot create connection options!\n");
		return 0;
	}

	rc=lcb_create(&instance, &options);
	if (rc!=LCB_SUCCESS) {
		LM_ERR("Failed to create libcouchbase instance: 0x%02x, %s\n",
		       rc, lcb_strerror(NULL, rc));
		return 0;
	}

	(void)lcb_set_get_callback(instance,
			couchbase_get_cb);
	(void)lcb_set_store_callback(instance,
			couchbase_store_cb);
	(void)lcb_set_remove_callback(instance,
			couchbase_remove_cb);
	(void)lcb_set_arithmetic_callback(instance,couchbase_arithmetic_cb);

	//Set Timeout
	tmo = (lcb_uint32_t)couch_timeout_usec;
	lcb_cntl(instance, LCB_CNTL_SET, LCB_CNTL_OP_TIMEOUT, &tmo);

	if (couch_lazy_connect == 0 || is_reconnect == 1) {
		rc=cb_connect(instance);

		/*Check connection*/
		if (rc != LCB_SUCCESS) {
			/*Consider these connect failurs as fatal*/
			if(rc == LCB_AUTH_ERROR || rc == LCB_INVALID_HOST_FORMAT || rc == LCB_INVALID_CHAR) {
				LM_ERR("Fatal connection error to Couchbase. Host: %s Bucket: %s Error: %s",
					id->host, id->database, lcb_strerror(instance, rc));
				lcb_destroy(instance);
				return 0;
			} else {
			/* Non-fatal errors, we may be able to connect later */
				LM_ERR("Non-Fatal connection error to Couchbase. Host: %s Bucket: %s Error: %s",
					id->host, id->database, lcb_strerror(instance, rc));
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
int couchbase_conditional_reconnect(cachedb_con *con, lcb_error_t err) {
	cachedb_pool_con *tmp;
	void *newcon;

	if (!con) return -1;

	switch (err) {
		/* Error codes to attempt reconnects on */
		case LCB_EINTERNAL:
		case LCB_CLIENT_ETMPFAIL:
		case LCB_EBADHANDLE:
		case LCB_NETWORK_ERROR:
                case LCB_ETIMEDOUT:
		break;
		default:
			/*nothing to do*/
			return 0;
		break;
	}

	tmp = (cachedb_pool_con*)(con->data);
	LM_ERR("Attempting reconnect to Couchbase. Host: %s Bucket: %s On Error: %s",
		tmp->id->host, tmp->id->database, lcb_strerror(COUCHBASE_CON(con), err));

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
	lcb_t instance;
	lcb_error_t oprc;
	lcb_store_cmd_t cmd;
	const lcb_store_cmd_t *commands[1];
	struct timeval start;

	start_expire_timer(start,couch_exec_threshold);
	instance = COUCHBASE_CON(connection);

	commands[0] = &cmd;
	memset(&cmd, 0, sizeof(cmd));
	cmd.v.v0.operation = LCB_SET;
	cmd.v.v0.key = attr->s;
	cmd.v.v0.nkey = attr->len;
	cmd.v.v0.bytes = val->s;
	cmd.v.v0.nbytes = val->len;
	cmd.v.v0.exptime = expires;

	oprc = cb_store(instance, NULL, 1, commands);

	if (oprc != LCB_SUCCESS) {
		LM_ERR("Set request failed - %s\n", lcb_strerror(instance, oprc));
		//Attempt reconnect
		if(couchbase_conditional_reconnect(connection, oprc) != 1) {
			_stop_expire_timer(start,couch_exec_threshold,
				"cachedb_couchbase set",attr->s,attr->len,0,
				cdb_slow_queries, cdb_total_queries);
			return -2;
		}

		//Try again
		instance = COUCHBASE_CON(connection);
		oprc = cb_store(instance, NULL, 1, commands);

		if (oprc != LCB_SUCCESS) {
			LM_ERR("Set command retry failed - %s\n", lcb_strerror(instance, oprc));
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
	lcb_t instance;
	lcb_error_t oprc;
	lcb_remove_cmd_t cmd;
	const lcb_remove_cmd_t *commands[1];
	struct timeval start;

	start_expire_timer(start,couch_exec_threshold);
	instance = COUCHBASE_CON(connection);
	commands[0] = &cmd;
	memset(&cmd, 0, sizeof(cmd));
	cmd.v.v0.key = attr->s;
	cmd.v.v0.nkey = attr->len;
	oprc = cb_remove(instance, NULL, 1, commands);

	if (oprc != LCB_SUCCESS) {
		if (oprc == LCB_KEY_ENOENT) {
			_stop_expire_timer(start,couch_exec_threshold,
				"cachedb_couchbase remove",attr->s,attr->len,0,
				cdb_slow_queries, cdb_total_queries);
			return -1;
		}

		LM_ERR("Failed to send the remove query - %s\n", lcb_strerror(instance, oprc));
		if (couchbase_conditional_reconnect(connection, oprc) != 1) {
			_stop_expire_timer(start,couch_exec_threshold,
				"cachedb_couchbase remove",attr->s,attr->len,0,
				cdb_slow_queries, cdb_total_queries);
			return -2;
		};

		instance = COUCHBASE_CON(connection);
		oprc = cb_remove(instance, NULL, 1, commands);

		if (oprc != LCB_SUCCESS) {
			if (oprc == LCB_KEY_ENOENT) {
				LM_ERR("Remove command successfully retried\n");
				_stop_expire_timer(start,couch_exec_threshold,
					"cachedb_couchbase remove",attr->s,attr->len,0,
					cdb_slow_queries, cdb_total_queries);
				return -1;
			}
			LM_ERR("Remove command retry failed - %s\n", lcb_strerror(instance, oprc));
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
	lcb_t instance;
	lcb_error_t oprc;
	lcb_get_cmd_t cmd;
	const lcb_get_cmd_t *commands[1];
	struct timeval start;

	start_expire_timer(start,couch_exec_threshold);
	instance = COUCHBASE_CON(connection);

	commands[0] = &cmd;
	memset(&cmd, 0, sizeof(cmd));
	cmd.v.v0.key = attr->s;
	cmd.v.v0.nkey = attr->len;
	oprc = cb_get(instance, NULL, 1, commands);

	if (oprc != LCB_SUCCESS) {
		/* Key not present, record does not exist */
		if (oprc == LCB_KEY_ENOENT) {
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

		//Try Again
		instance = COUCHBASE_CON(connection);
		oprc = cb_get(instance, NULL, 1, commands);
		if (oprc != LCB_SUCCESS) {
			if (oprc == LCB_KEY_ENOENT) {
				LM_ERR("Get command successfully retried\n");
				_stop_expire_timer(start,couch_exec_threshold,
					"cachedb_couchbase get",attr->s,attr->len,0,
					cdb_slow_queries, cdb_total_queries);
				return -1;
			}
			LM_ERR("Get command retry failed - %s\n", lcb_strerror(instance, oprc));
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
	lcb_t instance;
	lcb_error_t oprc;
	lcb_arithmetic_cmd_t cmd;
	const lcb_arithmetic_cmd_t *commands[1];
	struct timeval start;

	start_expire_timer(start,couch_exec_threshold);
	instance = COUCHBASE_CON(connection);

	commands[0] = &cmd;
	memset(&cmd, 0, sizeof(cmd));
	cmd.v.v0.key = attr->s;
	cmd.v.v0.nkey = attr->len;
	cmd.v.v0.delta = val;
	cmd.v.v0.create = 1;
	cmd.v.v0.initial = val;
	cmd.v.v0.exptime = expires;
	oprc = cb_arithmetic(instance, NULL, 1, commands);

	if (oprc != LCB_SUCCESS) {
		if (oprc == LCB_KEY_ENOENT) {
			return -1;
			_stop_expire_timer(start,couch_exec_threshold,
				"cachedb_couchbase add",attr->s,attr->len,0,
				cdb_slow_queries, cdb_total_queries);
		}

		LM_ERR("Failed to send the arithmetic query - %s\n", lcb_strerror(instance, oprc));
		//Attempt reconnect
		if (couchbase_conditional_reconnect(connection, oprc) != 1) {
			_stop_expire_timer(start,couch_exec_threshold,
				"cachedb_couchbase add",attr->s,attr->len,0,
				cdb_slow_queries, cdb_total_queries);
			return -2;
		}

		//Try again
		instance = COUCHBASE_CON(connection);
		oprc = cb_arithmetic(instance, NULL, 1, commands);

		if (oprc != LCB_SUCCESS) {
			if (oprc == LCB_KEY_ENOENT) {
				LM_ERR("Arithmetic command successfully retried\n");
				_stop_expire_timer(start,couch_exec_threshold,
					"cachedb_couchbase add",attr->s,attr->len,0,
					cdb_slow_queries, cdb_total_queries);
				return -1;
			}
			LM_ERR("Arithmetic command retry failed - %s\n", lcb_strerror(instance, oprc));
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
	lcb_t instance;
	lcb_error_t oprc;
	lcb_get_cmd_t cmd;
	const lcb_get_cmd_t *commands[1];
	struct timeval start;

	start_expire_timer(start,couch_exec_threshold);
	instance = COUCHBASE_CON(connection);

	commands[0] = &cmd;
	memset(&cmd, 0, sizeof(cmd));
	cmd.v.v0.key = attr->s;
	cmd.v.v0.nkey = attr->len;
	oprc = cb_get(instance, NULL, 1, commands);

	if (oprc != LCB_SUCCESS) {
		/* Key not present, record does not exist */
		if (oprc == LCB_KEY_ENOENT) {
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

		//Try Again
		instance = COUCHBASE_CON(connection);
		oprc = cb_get(instance, NULL, 1, commands);
		if (oprc != LCB_SUCCESS) {
			if (oprc == LCB_KEY_ENOENT) {
				LM_ERR("Get counter command successfully retried\n");
				_stop_expire_timer(start,couch_exec_threshold,
					"cachedb_couchbase get counter",attr->s,attr->len,0,
					cdb_slow_queries, cdb_total_queries);
				return -1;
			}
			LM_ERR("Get counter command retry failed - %s\n", lcb_strerror(instance, oprc));
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
