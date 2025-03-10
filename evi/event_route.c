/*
 * Copyright (C) 2012 OpenSIPS Solutions
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
 *  2012-12-xx  created (razvancrainea)
 */

#include "evi_modules.h"
#include "../ut.h"
#include "event_route.h"
#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include "../ipc.h"


/* default PVAR names */

#define SR_SOCK_ROUTE(_s) ((struct script_route_ref *)(_s->params))

/* returns 0 if sockets match */
int scriptroute_match(evi_reply_sock *sock1, evi_reply_sock *sock2)
{
	if (!sock1 || !sock2)
		return 0;
	if (!(sock1->flags & EVI_PARAMS) || !(sock2->flags & EVI_PARAMS) ||
		SR_SOCK_ROUTE(sock1) != SR_SOCK_ROUTE(sock2))
		return 0;
	return 1;
}


evi_reply_sock* scriptroute_parse(str socket)
{
	evi_reply_sock *sock = NULL;
	struct script_route_ref *ref;

	if (!socket.len || !socket.s) {
		LM_ERR("no socket specified\n");
		return NULL;
	}

	/* try to "resolve" the name of the route */
	ref = ref_script_route_by_name_str( &socket, sroutes->event, EVENT_RT_NO,
		EVENT_ROUTE, 1 /*in_shm*/);
	if (!ref_script_route_is_valid(ref)) {
		LM_ERR("cannot find route %.*s\n", socket.len, socket.s);
		return NULL;
	}

	sock = shm_malloc(sizeof(evi_reply_sock) + socket.len + 1);
	if (!sock) {
		LM_ERR("no more memory for socket\n");
		return NULL;
	}
	memset(sock, 0, sizeof(evi_reply_sock));

	sock->address.s = (char *)(sock + 1);

	memcpy(sock->address.s, socket.s, socket.len);
	sock->address.len = socket.len;
	sock->address.s[socket.len] = 0;

	sock->params = (void *)ref;
	sock->flags |= EVI_PARAMS;

	LM_DBG("route is <%.*s> idx %d\n", sock->address.len, sock->address.s,
		ref->idx);
	sock->flags |= EVI_ADDRESS;

	sock->flags |= SCRIPTROUTE_FLAG;

	return sock;
}

void scriptroute_free(evi_reply_sock *sock)
{
	/* free the script route reference */
	if (sock && sock->params)
		shm_free(sock->params);
}

str scriptroute_print(evi_reply_sock *sock)
{
	/* return only the route's name */
	return sock->address;
}

/* static parameters list retrieved by the fetch_event_params */
evi_params_t *parameters = NULL;
str *event_name = NULL; // mostly used for debugging

int event_route_param_get(struct sip_msg *msg, pv_param_t *ip,
		pv_value_t *res, void *params, void *extra)
{
	static str event_name_error = str_init("E_ERROR");
	evi_params_t *parameters = (evi_params_t *)params;
	str *event_name = (str *)extra;
	evi_param_t *it;
	pv_value_t tv;
	int index;

	if (!parameters)
	{
		LM_DBG("no parameter specified for this route\n");
		return pv_get_null(msg, ip, res);
	}

	if (!event_name)
	{
		event_name = &event_name_error;
		LM_WARN("invalid event's name, using %.*s\n", event_name->len, event_name->s);
	}

	if(ip->pvn.type==PV_NAME_INTSTR)
	{
		if (ip->pvn.u.isname.type != 0)
		{
			tv.rs =  ip->pvn.u.isname.name.s;
			tv.flags = PV_VAL_STR;
		} else
		{
			tv.ri = ip->pvn.u.isname.name.n;
			tv.flags = PV_VAL_INT|PV_TYPE_INT;
		}
	}
	else
	{
		/* pvar -> it might be another $param variable! */
		if(pv_get_spec_value(msg, (pv_spec_p)(ip->pvn.u.dname), &tv)!=0)
		{
			LM_ERR("cannot get spec value\n");
			return -1;
		}

		if(tv.flags&PV_VAL_NULL || tv.flags&PV_VAL_EMPTY)
		{
			LM_ERR("null or empty name\n");
			return -1;
		}
	}
	it  = parameters->first;

	/* search for the param we want top add, based on index */
	if (tv.flags & PV_VAL_INT) {
		for (index = 1; it && index != tv.ri; it = it->next, index++);
		if (!it) {
			LM_WARN("Parameter %d not found for event %.*s - max %d\n",
					tv.ri, event_name->len, event_name->s, index-1);
			return pv_get_null(msg, ip, res);
		}
	} else {
		/* search by name */
		for (; it; it = it->next) {
			if (it->name.s && it->name.len == tv.rs.len &&
					memcmp(it->name.s, tv.rs.s, it->name.len) == 0)
				break;
		}
		if (!it) {
			LM_WARN("Parameter <%.*s> not found for event <%.*s>\n",
					tv.rs.len, tv.rs.s,
					event_name->len, event_name->s);
			return pv_get_null(msg, ip, res);
		}
	}

	/* parameter found - populate it */
	if (it->flags & EVI_INT_VAL) {
		res->rs.s = sint2str(it->val.n, &res->rs.len);
		res->ri = it->val.n;
		res->flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;
	} else {
		res->rs.s = it->val.s.s;
		res->rs.len = it->val.s.len;
		res->flags = PV_VAL_STR;
	}

	return 0;
}

void route_run(struct script_route route, struct sip_msg* msg,
		evi_params_t *params, str *event)
{
	int old_route_type;

	route_params_push_level(NULL, params, event, event_route_param_get);
	swap_route_type(old_route_type, EVENT_ROUTE);
	run_top_route(route, msg);
	set_route_type(old_route_type);
	route_params_pop_level();
}

int scriptroute_raise(struct sip_msg *msg, str* ev_name,
	evi_reply_sock *sock, evi_params_t *params, evi_async_ctx_t *async_ctx)
{
	route_send_t *buf = NULL;

	if (!sock || !(sock->flags & EVI_PARAMS)) {
		LM_ERR("no socket found\n");
		return -1;
	}

	/* check the socket type */
	if (!(sock->flags & SCRIPTROUTE_FLAG)) {
		LM_ERR("invalid socket type\n");
		return -1;
	}

	if (route_build_buffer(ev_name, sock, params, &buf) < 0) {
		LM_ERR("failed to serialize event route triggering\n");
		return -1;
	}
	/* this below is just to force an update of ther reference, before 
	 * dupping it. If not, we will be stuck with the original reference */
	if (ref_script_route_check_and_update( SR_SOCK_ROUTE(sock) )) {}
	buf->ev_route = dup_ref_script_route_in_shm( SR_SOCK_ROUTE(sock), 1);

	if (route_send(buf) < 0)
		return -1;

	return 0;
}

#define IS_ERR(_err) (errno == _err)

int route_build_buffer(str *event_name, evi_reply_sock *sock,
		evi_params_t *params, route_send_t **msg)
{
	struct {
		route_send_t rt;
		evi_param_t eps[0];
	} *buf;
	evi_param_p param, buf_param;
	int len, params_len=0;
	unsigned int param_no = 0;
	char *s;

	len = sizeof(*buf) + event_name->len;
	if (params) {
		for (param = params->first; param; param = param->next) {
			if (param->flags & EVI_INT_VAL) {
				param_no++;
				params_len += param->name.len;
			} else if (param->flags & EVI_STR_VAL) {
				param_no++;
				params_len += param->name.len + param->val.s.len;
			} else {
				LM_DBG("FIXME: handle param=[%p] name=[%.*s] flags=%X\n",
						param, param->name.len, param->name.s, param->flags);
			}
		}
	}

	len += param_no*sizeof(evi_param_t) + params_len;
	buf = shm_malloc(len);
	if (!buf) {
		LM_ERR("oom\n");
		return -1;
	}
	memset(buf, 0, len);

	/* Stick the event name at the end */
	buf->rt.event.s = (char*)(buf) + len - event_name->len;
	buf->rt.event.len = event_name->len;
	memcpy(buf->rt.event.s, event_name->s, event_name->len);

	if (params && param_no) {
		buf_param = &buf->eps[0];
		buf->rt.params.first = buf_param;
		s = (char*)(&buf->eps[param_no]);
		for (param = params->first; param; param = param->next) {
			if (param->flags & EVI_INT_VAL) {
				buf_param->flags = EVI_INT_VAL;
				memcpy(s, param->name.s, param->name.len);
				buf_param->name.s = s;
				buf_param->name.len = param->name.len;
				s += param->name.len;
				buf_param->val.n = param->val.n;
				buf_param->next = buf_param + 1;
				buf_param++;
			} else if (param->flags & EVI_STR_VAL) {
				buf_param->flags = EVI_STR_VAL;
				memcpy(s, param->name.s, param->name.len);
				buf_param->name.s = s;
				buf_param->name.len = param->name.len;
				s += param->name.len;
				memcpy(s, param->val.s.s, param->val.s.len);
				buf_param->val.s.s = s;
				buf_param->val.s.len = param->val.s.len;
				s += param->val.s.len;
				buf_param->next = buf_param + 1;
				buf_param++;
			} else {
				LM_DBG("FIXME: handle param=[%p] name=[%.*s] flags=%X\n",
						param, param->name.len, param->name.s, param->flags);
			}
		}
		buf_param--;
		buf_param->next = NULL;
		buf->rt.params.last = buf_param;
	}

	*msg = &buf->rt;
	return 0;
}

#if 0
void route_params_push_level(void *params, void *extra, param_getf_t getf);
void route_params_pop_level(void);
int route_params_run(struct sip_msg *msg,  pv_param_t *ip, pv_value_t *res);
#endif

static void route_received(int sender, void *param)
{
	struct sip_msg* req;
	route_send_t *route_s = (route_send_t *)param;

	/* suppress the E_CORE_LOG event for new logs while handling
	 * the event itself */
	suppress_proc_log_event();

	if (!ref_script_route_check_and_update(route_s->ev_route)){
		LM_ERR("event route [%.s] no longer available in script\n",
			route_s->ev_route->name.s);
		goto cleanup;
	}

	req = get_dummy_sip_msg();
	if(req == NULL) {
		LM_ERR("cannot create new dummy sip request\n");
		goto cleanup;
	}

	route_run(sroutes->event[route_s->ev_route->idx], req,
		&route_s->params, &route_s->event);

	release_dummy_sip_msg(req);

	/* remove all added AVP - here we use all the time the default AVP list */
	reset_avps( );

cleanup:
	if (route_s->ev_route)
		shm_free(route_s->ev_route);
	shm_free(route_s);

	reset_proc_log_event();
}


int route_send(route_send_t *route_s)
{
	return ipc_dispatch_rpc( route_received, (void *)route_s);
}
