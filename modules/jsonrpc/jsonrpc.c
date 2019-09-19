/*
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
 */

#include "../../mem/shm_mem.h"
#include "../../net/net_tcp.h"
#include "../../sr_module.h"
#include "../../lib/cJSON.h"
#include "../../lib/list.h"
#include "../../ip_addr.h"
#include "../../mod_fix.h"
#include "../../resolve.h"
#include "../../dprint.h"
#include "../../tsend.h"
#include "../../trim.h"
#include "../../ut.h"
#include "../../pt.h"
#include "jsonrpc.h"
#include <sys/poll.h>
#include <fcntl.h>
#include <unistd.h>

static int mod_init(void);

static int fixup_jsonrpc_dest(void** param);
static int jrpc_request(struct sip_msg *msg, union sockaddr_union *dst,
				str *method, str *params, pv_spec_p spec);
static int jrpc_notify(struct sip_msg *msg, union sockaddr_union *dst,
				str *method, str *params);
static char *jsonrpc_build_cmd(str *method, str *params, int *id);

#define JSONRPC_PRINT(_su) \
	inet_ntoa(_su->sin.sin_addr), ntohs(_su->sin.sin_port)

static int jsonrpc_id_index = 0;
static int jrpc_connect_timeout = JSONRPC_DEFAULT_TIMEOUT;
static int jrpc_write_timeout = JSONRPC_DEFAULT_TIMEOUT;
static int jrpc_read_timeout = JSONRPC_DEFAULT_TIMEOUT;

static param_export_t params[]={
	{ "connect_timeout",	INT_PARAM,	&jrpc_connect_timeout },
	{ "write_timeout",		INT_PARAM,	&jrpc_write_timeout },
	{ "read_timeout",		INT_PARAM,	&jrpc_read_timeout },
	{0,0,0}
};

/* modules dependencies */
static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

/* exported commands */
static cmd_export_t cmds[] = {
	{"jsonrpc_request",			(cmd_function)jrpc_request, {
		{CMD_PARAM_STR, fixup_jsonrpc_dest, 0},
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_VAR,0,0}, {0,0,0}},
		ALL_ROUTES},
	{"jsonrpc_notification",	(cmd_function)jrpc_notify, {
		{CMD_PARAM_STR, fixup_jsonrpc_dest, 0},
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR,0,0}, {0,0,0}},
		ALL_ROUTES},
	{0,0,{{0,0,0}},0}
};

/* module exports */
struct module_exports exports= {
	"jsonrpc",						/* module name */
	MOD_TYPE_DEFAULT,				/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,				/* dlopen flags */
	0,								/* load function */
	&deps,						    /* OpenSIPS module dependencies */
	cmds,							/* exported functions */
	0,								/* exported async functions */
	params,							/* exported parameters */
	0,								/* exported statistics */
	0,								/* exported MI functions */
	0,								/* exported pseudo-variables */
	0,								/* exported transformations */
	0,								/* extra processes */
	0,								/* module pre-initialization function */
	mod_init,						/* module initialization function */
	(response_function) 0,			/* response handling function */
	NULL,							/* destroy function */
	NULL,							/* per-child init function */
	NULL							/* reload confirm function */
};

/**
 * init module function
 */
static int mod_init(void)
{
	LM_NOTICE("initializing JSON-RPC module ...\n");

	if (jrpc_connect_timeout <= 0) {
		LM_ERR("invalid value for connect timeout (%d)! "
				"Please specify a positive value in milliseconds!\n", jrpc_connect_timeout);
		return -1;
	}

	if (jrpc_write_timeout <= 0) {
		LM_ERR("invalid value for write timeout (%d)! "
				"Please specify a positive value in milliseconds!\n", jrpc_write_timeout);
		return -1;
	}

	if (jrpc_read_timeout <= 0) {
		LM_ERR("invalid value for read timeout (%d)! "
				"Please specify a positive value in milliseconds!\n", jrpc_read_timeout);
		return -1;
	}

	jsonrpc_id_index = my_pid() & USHRT_MAX;
	jsonrpc_id_index |= rand() << sizeof(unsigned short);
	return 0;
}

static union sockaddr_union *jsonrpc_get_dst(str *ip_port)
{
	static union sockaddr_union _su;
	struct hostent *hentity;
	char *p, bk;
	str host;
	str port;
	int iport;
	int err;

	if (!ip_port || !ip_port->len) {
		LM_ERR("no IP:port specified!\n");
		return NULL;
	}

	/* search for the port */
	p = memchr(ip_port->s, ':', ip_port->len);
	if (!p) {
		LM_ERR("invalid IP:port %.*s\n", ip_port->len, ip_port->s);
		return NULL;
	}
	host.s = ip_port->s;
	host.len = p - ip_port->s;

	/* remaining should be port */
	port.s = p + 1;
	port.len = ip_port->len - (host.len + 1/* : */);
	trim(&port);

	iport = str2s(port.s, port.len, &err);
	if (iport <= 0 || err != 0 || iport > 65535) {
		LM_ERR("Invalid port specified [%.*s]\n", port.len, port.s);
		return NULL;
	}

	trim(&host);

	/* null terminate host */
	bk = host.s[host.len];
	host.s[host.len] = 0;

	hentity = resolvehost(host.s, 0);
	host.s[host.len] = bk;
	if (!hentity) {
		LM_ERR("cannot resolve host %s\n", host.s);
		return NULL;
	}
	if(hostent2su(&_su, hentity, 0, iport)){
		LM_ERR("failed to resolve %s\n", host.s);
		return NULL;
	}
	
	return &_su;
}


static int fixup_jsonrpc_dest(void** param)
{
	*param = (void*)jsonrpc_get_dst((str*)*param);
	if (!(*param)) {
		LM_ERR("cannot fetch IP:port from param!\n");
		return E_UNSPEC;
	}

	return 0;
}

static int jsonrpc_get_fd(union sockaddr_union *addr)
{
	int fd;
	int flags;

	/* writing the iov on the network */
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		LM_ERR("cannot create socket\n");
		return -1;
	}

	/* mark the socket as non-blocking after connect :) */
	flags = fcntl(fd, F_GETFL);
	if (flags == -1) {
		LM_ERR("fcntl failed: %s\n", strerror(errno));
		goto close;
	}
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
		LM_ERR("fcntl: set non-blocking failed: %s\n", strerror(errno));
		goto close;
	}

	if (tcp_connect_blocking_timeout(fd, &addr->s,
			sockaddru_len(*addr), jrpc_connect_timeout) < 0) {
		LM_ERR("cannot connect to %s[%d:%s]\n",
				inet_ntoa(addr->sin.sin_addr),
				errno, strerror(errno));
		goto close;
	}
	return fd;
close:
	shutdown(fd, SHUT_RDWR);
	close(fd);
	return -1;
}

/**
 * Runs a JSON-RPC command (request or notification)
 * Params:
 *  dst: destination of the command
 *  cmd: comand to send
 *  id: if present, unique ID of the command, otherwise this is a notification
 *  ret: value returned in case of a request
 *
 * Returns:
 *  -2: communication error
 *  -3: reply error
 *   1: success
 */
static int jsonrpc_handle_cmd(union sockaddr_union *dst, char *cmd, int *id,
		pv_value_t *vret)
{
	int r, fd, ret = -2;
	unsigned int cmd_len;
	struct timeval begin;
	struct pollfd pf;
	int tout_left, total;
	cJSON *obj = NULL, *aux;

	char buffer[JSONRPC_DEFAULT_BUFFER_SIZE + 1/* null terminate */];

	/* connect to the destination */
	fd = jsonrpc_get_fd(dst);
	if (fd < 0) {
		LM_ERR("cannot get a connection to %s:%hu\n", JSONRPC_PRINT(dst));
		return -2;
	}

	/* we have a connection - send the command now */
	cmd_len = strlen(cmd);

	if (tsend_stream(fd, cmd, cmd_len, jrpc_write_timeout) < 0) {
		LM_ERR("cannot send stream to %s:%hu\n", JSONRPC_PRINT(dst));
		goto end;
	}
	
	/* notification - no need to wait for a reply */
	if (!id) {
		ret = 1;
		goto end;
	}

	/* read the reply */
	pf.fd = fd;
	pf.events = POLLIN;

	total = 0;
	gettimeofday(&begin, NULL);
	while (1) {
		/* compute how long we are allowed to block */
		tout_left = jrpc_read_timeout - (get_time_diff(&begin) / 1000);
		if (tout_left <= 0) {
			LM_ERR("read timeout reached (%s:%hu)\n", JSONRPC_PRINT(dst));
			goto end;
		}
		r = poll(&pf, 1, tout_left);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			LM_ERR("poll failed: %s [%d\n", strerror(errno), errno);
			goto end;
		}
		if (pf.revents & POLLIN) {
			/* now we can read */
			r = read(fd, buffer + total, JSONRPC_DEFAULT_BUFFER_SIZE - total);
			if (r < 0) {
				if (errno == EINTR)
					continue;
				LM_ERR("cannot read reply from JSON-RPC server %s:%hu\n",
						JSONRPC_PRINT(dst));
				goto end;
			}
			total += r;
			buffer[total] = '\0';
			/* everything read - try to parse it now */
			obj = cJSON_Parse(buffer);
			if (!obj) {
				LM_DBG("could not parse json [%s] - perhapse we did not "
						"receive all of it, retrying!\n", buffer);
				continue;
			}
			/* yey, we have an object */
			break;
		} else if (pf.revents & POLLERR) {
			/* someting happened with the connection */
			LM_ERR("connection error to %s:%hu - %s:%d\n",
					JSONRPC_PRINT(dst), strerror(errno), errno);
			goto end;
		}
	}

	aux = cJSON_GetObjectItem(obj, "error");
	if (aux) {
		/* return the entire error */
		vret->rs.s = cJSON_Print(aux);
		vret->rs.len = strlen(vret->rs.s);
		vret->flags = PV_VAL_STR;
		LM_DBG("Error got from JSON-RPC: %s!\n", buffer);
		ret = -3;
		goto end;
	}

	aux = cJSON_GetObjectItem(obj, "result");
	if (!aux) {
		LM_WARN("Invalid reply from JSON-RPC: %s!\n", buffer);
		pv_get_null(NULL, NULL, vret);
		ret = -3;
		goto end;
	}

	if (aux->type == cJSON_Number)
		pv_get_sintval(NULL, NULL, vret, aux->valueint);
	else {
		vret->rs.s = cJSON_Print(aux);
		vret->rs.len = strlen(vret->rs.s);
		vret->flags = PV_VAL_STR;
	}

	ret = 1;
end:
	shutdown(fd, SHUT_RDWR);
	close(fd);
	return ret;
}

static inline int jsonrpc_unique_id(void)
{
	/*
	 * the format is 'rand | my_pid'
	 * rand is (int) - (unsigned short) long
	 * my_pid is (short) long
	 */
	jsonrpc_id_index += (1 << sizeof(unsigned short));
	/* make sure we always return something positive */
	return jsonrpc_id_index < 0 ? -jsonrpc_id_index : jsonrpc_id_index;
}

/**
 * Function that runs a JSON-RPC notification
 * Returns:
 *  -1: internal error
 *  -2: communication error
 *   1: success
 */
static int jrpc_notify(struct sip_msg *msg, union sockaddr_union *dst,
					str *method, str *params)
{
	int ret;
	char *cmd;
	
	cmd = jsonrpc_build_cmd(method, params, NULL);
	if (!cmd) {
		LM_ERR("cannot build jsonrpc command\n");
		return -1;
	}

	ret = jsonrpc_handle_cmd(dst, cmd, NULL, NULL);
	if (ret < 0)
		LM_ERR("communication error with %s:%hu", JSONRPC_PRINT(dst));
	return ret;
}

/**
 * Function that runs a JSON-RPC request
 * Returns:
 *  -1: internal error
 *  -2: communication error
 *  -3: reply error
 *   1: success
 */
static int jrpc_request(struct sip_msg *msg, union sockaddr_union *dst,
				str *method, str *params, pv_spec_p spec)
{
	int id, ret;
	char *cmd;
	pv_value_t val;

	id = jsonrpc_unique_id();
	cmd = jsonrpc_build_cmd(method, params, &id);
	if (!cmd) {
		LM_ERR("cannot build jsonrpc command \n");
		return -1;
	}

	ret = jsonrpc_handle_cmd(dst, cmd, &id, &val);
	cJSON_PurgeString(cmd);
	if (ret == -2) {
		LM_ERR("communication error with %s:%hu\n", JSONRPC_PRINT(dst));
		return ret;
	}

	if (pv_set_value(msg, spec, 0, &val) < 0) {
		LM_ERR("cannot set returned value!\n");
		ret = -1;
	}
	/* XXX: free the value returned */
	if ((val.flags & PV_VAL_STR) && !(val.flags & PV_VAL_INT))
		cJSON_PurgeString(val.rs.s);

	return ret;
}

static char *jsonrpc_build_cmd(str *method, str *params, int *id)
{
	char *s;
	cJSON *param_obj;
	cJSON *ret_obj;
	char *params_buf;

	/* first thing - try to parse the parameters - need it NULL terminated */
	params_buf = pkg_malloc(params->len + 1);
	if (!params_buf) {
		LM_ERR("cannot allocate memory for params!\n");
		return NULL;
	}
	memcpy(params_buf, params->s, params->len);
	params_buf[params->len] = 0;

	param_obj = cJSON_Parse(params_buf);
	pkg_free(params_buf);
	if (!param_obj) {
		LM_ERR("cannot parse json param: %.*s\n", params->len, params->s);
		return NULL;
	}

	if (param_obj->type != cJSON_Array && param_obj->type != cJSON_Object) {
		LM_ERR("invalid cJSON type %d - must be array or object!\n", param_obj->type);
		cJSON_Delete(param_obj);
		return NULL;
	}
	
	ret_obj = cJSON_CreateObject();
	if (id)
		cJSON_AddNumberToObject(ret_obj, "id", *id);
	else
		cJSON_AddNullToObject(ret_obj, "id");
	cJSON_AddItemToObject(ret_obj, "jsonrpc",
			cJSON_CreateString(JSONRPC_VERSION));
	cJSON_AddItemToObject(ret_obj, "method",
			cJSON_CreateStr(method->s, method->len));
	cJSON_AddItemToObject(ret_obj, "params", param_obj);

	s = cJSON_PrintUnformatted(ret_obj);
	if (!s)
		LM_ERR("cannot print json object!\n");

	cJSON_Delete(ret_obj);
	return s;
}
