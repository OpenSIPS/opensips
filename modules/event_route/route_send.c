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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *
 * history:
 * ---------
 *  2014-06-27  created (osas)
 */

#include "../../evi/evi_transport.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../ut.h"
#include "route_send.h"
#include "event_route.h"
#include <fcntl.h>
#include <sched.h>
#include <unistd.h>
#include <sched.h>

#define IS_ERR(_err) (errno == _err)

extern evi_params_t *parameters;
extern str *event_name;

/* used to communicate with the sending process */
static int route_pipe[2];

/* creates communication pipe */
int create_pipe(void)
{
	int rc;

	route_pipe[0] = route_pipe[1] = -1;
	/* create pipe */
	do {
		rc = pipe(route_pipe);
	} while (rc < 0 && IS_ERR(EINTR));

	if (rc < 0) {
		LM_ERR("cannot create status pipe [%d:%s]\n", errno, strerror(errno));
		return -1;
	}
	return 0;
}

void destroy_pipe(void)
{
	if (route_pipe[0] != -1)
		close(route_pipe[0]);
	if (route_pipe[1] != -1)
		close(route_pipe[1]);
}

int route_send(route_send_t *route_s)
{
	int rc, retries = ROUTE_SEND_RETRY;

	do {
		rc = write(route_pipe[1], &route_s, sizeof(route_send_t *));
		if (rc == sizeof(route_send_t *))
			break;
	} while ((rc < 0 && (IS_ERR(EINTR)||IS_ERR(EAGAIN)||IS_ERR(EWOULDBLOCK)))
			|| retries-- > 0);

	if (rc < 0) {
		LM_ERR("unable to send route send struct to worker\n");
		return -1;
	} else if (rc != sizeof(route_send_t *)){
		LM_ERR("Incomplete write [%d/%zu]\n", rc, sizeof(route_send_t *));
		return -1;
	}
	/* give a change to the writer :) */
	sched_yield();
	return 0;
}

static union tmp_route_send_t {
	route_send_t *ptr;
	char buf[sizeof(route_send_t *)];
} recv_buf;

static pid_t event_route_process_pid = -1;

static route_send_t * route_receive(void)
{
	int rc;
	int retries = ROUTE_SEND_RETRY;
	int len = sizeof(route_send_t*);
	int bytes_read = 0;

	if (route_pipe[0] == -1)
		return NULL;

	do {
		rc = read(route_pipe[0], recv_buf.buf + bytes_read, len);
		if (rc > 0) {
			bytes_read += rc;
			len -= rc;
		} else if (rc < 0 && IS_ERR(EINTR)) {
			continue;
		} else if (retries-- <= 0) {
			break;
		}
	} while (len);

	if (rc < 0) {
		LM_ERR("cannot receive send param\n");
		return NULL;
	}
	return recv_buf.ptr;
}

int init_writer(void)
{
	int flags;

	if (event_route_process_pid == getpid())
		return 0;

	if (route_pipe[0] != -1) {
		close(route_pipe[0]);
		route_pipe[0] = -1;
	}

	/* Turn non-blocking mode on for sending*/
	flags = fcntl(route_pipe[1], F_GETFL);
	if (flags == -1) {
		LM_ERR("fcntl failed: %s\n", strerror(errno));
		goto error;
	}
	if (fcntl(route_pipe[1], F_SETFL, flags | O_NONBLOCK) == -1) {
		LM_ERR("fcntl: set non-blocking failed: %s\n", strerror(errno));
		goto error;
	}

	return 0;
error:
	close(route_pipe[1]);
	route_pipe[1] = -1;
	return -1;
}

static void route_init_reader(void)
{
	if (route_pipe[1] != -1) {
		close(route_pipe[1]);
		route_pipe[1] = -1;
	}
	event_route_process_pid = getpid();
}


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
				LM_ERR("FIXME: handle param=[%p]\n", param);
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
				LM_ERR("FIXME: handle param=[%p]\n", param);
			}
		}
		buf_param--;
		buf_param->next = NULL;
		buf->params.last = buf_param;
	}

	*msg = buf;
	return 0;
}


void event_route_handler(int rank)
{
	/* init blocking reader */
	route_init_reader();
	route_send_t *route_s;
	struct sip_msg* req;

	if (init_child(PROC_MODULE) != 0) {
		LM_ERR("cannot init child process\n");
		return;
	}

	/* waiting for commands */
	for (;;) {
		route_s = route_receive();
		if (!route_s) {
			LM_ERR("invalid receive sock info\n");
			goto end;
		}

		req = get_dummy_sip_msg();
		if(req == NULL) {
			LM_ERR("cannot create new dummy sip request\n");
			return;
		}

		event_name = &route_s->event;
		parameters = &route_s->params;
		run_top_route(route_s->a, req);
		release_dummy_sip_msg(req);
end:
		if (route_s)
			shm_free(route_s);
	}
}
