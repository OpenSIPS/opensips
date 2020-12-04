/*
 * Copyright (C) 2014 VoIP Embedded, Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#include <fcntl.h>
#include <sched.h>
#include <unistd.h>
#include <sched.h>

#include "../../evi/evi_transport.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../ipc.h"
#include "../../ut.h"
#include "route_send.h"
#include "event_route.h"

#define IS_ERR(_err) (errno == _err)

int route_build_buffer(str *event_name, evi_reply_sock *sock,
		evi_params_t *params, route_send_t **msg)
{
	route_send_t *buf;
	evi_param_p param, buf_param;
	int len, params_len=0;
	unsigned int param_no = 0;
	char *s;

	len = sizeof(route_send_t) + event_name->len;
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

	len += sizeof(evi_params_t) + param_no*sizeof(evi_param_t) + params_len;
	buf = shm_malloc(len);
	if (!buf) {
		LM_ERR("oom\n");
		return -1;
	}
	memset(buf, 0, len);

	/* First,is event */
	buf->event.s = (char*)(buf + 1);
	buf->event.len = event_name->len;
	memcpy(buf->event.s, event_name->s, event_name->len);

	if (params) {
		buf_param = (evi_param_p)(buf->event.s + buf->event.len);
		buf->params.first = buf_param;
		s = (char*)(buf_param + param_no);
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
		buf->params.last = buf_param;
	}

	*msg = buf;
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

	req = get_dummy_sip_msg();
	if(req == NULL) {
		LM_ERR("cannot create new dummy sip request\n");
		return;
	}

	route_run(sroutes->event[route_s->ev_route_id].a, req,
		&route_s->params, &route_s->event);

	release_dummy_sip_msg(req);

	/* remove all added AVP - here we use all the time the default AVP list */
	reset_avps( );

	shm_free(route_s);
}


int route_send(route_send_t *route_s)
{
	return ipc_dispatch_rpc( route_received, (void *)route_s);
}



