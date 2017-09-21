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
 *  2012-05-xx  created (razvancrainea)
 */

#include "../../evi/evi_transport.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../ut.h"
#include "../../pt.h"
#include "xmlrpc_send.h"
#include "event_xmlrpc.h"
#include <sys/uio.h>
#include <fcntl.h>
#include <unistd.h>

#define IS_ERR(_err) (errno == _err)

unsigned xmlrpc_struct_on = 0;
unsigned xmlrpc_sync_mode = 0;
static char * xmlrpc_body_buf = 0;
static struct iovec xmlrpc_iov[XMLRPC_IOVEC_MAX_SIZE];
static unsigned xmlrpc_iov_len = 0;
static unsigned xmlrpc_first_line_index = 0;
static unsigned xmlrpc_host_index = 0;
static unsigned xmlrpc_ct_len_index = 0;
static unsigned xmlrpc_met_name_index = 0;
static unsigned xmlrpc_ev_name_index = 0;
static unsigned xmlrpc_params_index = 0;
static unsigned xmlrpc_xmlbody_index = 0;
static unsigned nr_procs = 0;

int xmlrpc_init_buffers(void)
{
	xmlrpc_body_buf = pkg_malloc(XMLRPC_DEFAULT_BUFFER_SIZE);
	if (!xmlrpc_body_buf) {
		LM_ERR("cannot allocate header buffer\n");
		return -1;
	}

	return 0;
}

/* used to communicate with the sending process */
static int xmlrpc_pipe[2];
/* used to communicate the status of the send (success or fail) from the sending process back to the requesting ones */
static int (*xmlrpc_status_pipes)[2];
/* more than enought for http first line */

/* creates communication pipe */
int xmlrpc_create_pipe(void)
{
	int rc;

	xmlrpc_pipe[0] = xmlrpc_pipe[1] = -1;
	/* create pipe */
	do {
		rc = pipe(xmlrpc_pipe);
	} while (rc < 0 && IS_ERR(EINTR));

	if (rc < 0) {
		LM_ERR("cannot create status pipe [%d:%s]\n", errno, strerror(errno));
		return -1;
	}

	if (xmlrpc_sync_mode && xmlrpc_create_status_pipes() < 0) {
		LM_ERR("cannot create communication status pipes\n");
		return -1;
	}

	return 0;
}

/* creates status pipes */
int xmlrpc_create_status_pipes(void) {
	int rc, i;

	nr_procs = count_init_children(0) + 2;	/* + 2 timer processes */

	xmlrpc_status_pipes = shm_malloc(nr_procs * sizeof(xmlrpc_pipe));

	if (!xmlrpc_status_pipes) {
		LM_ERR("cannot allocate xmlrpc_status_pipes\n");
		return -1;
	}

	/* create pipes */
	for (i = 0; i < nr_procs; i++) {
		do {
			rc = pipe(xmlrpc_status_pipes[i]);
		} while (rc < 0 && IS_ERR(EINTR));

		if (rc < 0) {
			LM_ERR("cannot create status pipe [%d:%s]\n", errno, strerror(errno));
			return -1;
		}
	}
	return 0;
}

void xmlrpc_destroy_pipe(void)
{
	if (xmlrpc_pipe[0] != -1)
		close(xmlrpc_pipe[0]);
	if (xmlrpc_pipe[1] != -1)
		close(xmlrpc_pipe[1]);

	if (xmlrpc_sync_mode)
		xmlrpc_destroy_status_pipes();
}

void xmlrpc_destroy_status_pipes(void)
{
	int i;

	for(i = 0; i < nr_procs; i++) {
		close(xmlrpc_status_pipes[i][0]);
		close(xmlrpc_status_pipes[i][1]);
	}

	shm_free(xmlrpc_status_pipes);
}

int xmlrpc_send(xmlrpc_send_t* xmlrpcs)
{
	int rc, retries = XMLRPC_SEND_RETRY;
	int send_status;

	xmlrpcs->process_idx = process_no;

	do {
		rc = write(xmlrpc_pipe[1], &xmlrpcs, sizeof(xmlrpc_send_t *));
	} while (rc < 0 && (IS_ERR(EINTR) || retries-- > 0));

	if (rc < 0) {
		LM_ERR("unable to send xmlrpc send struct to worker\n");
		shm_free(xmlrpcs);
		return XMLRPC_SEND_FAIL;
	}
	/* give a change to the writer :) */
	sched_yield();

	if (xmlrpc_sync_mode) {
		retries = XMLRPC_SEND_RETRY;

		do {
			rc = read(xmlrpc_status_pipes[process_no][0], &send_status, sizeof(int));
		} while (rc < 0 && (IS_ERR(EINTR) || retries-- > 0));

		if (rc < 0) {
			LM_ERR("cannot receive send status\n");
			send_status = XMLRPC_SEND_FAIL;
		}

		return send_status;
	} else
		return XMLRPC_SEND_SUCCESS;
}

static xmlrpc_send_t * xmlrpc_receive(void)
{
	static xmlrpc_send_t * recv;
	int rc;
	int retries = XMLRPC_SEND_RETRY;

	if (xmlrpc_pipe[0] == -1)
		return NULL;

	do {
		rc = read(xmlrpc_pipe[0], &recv, sizeof(xmlrpc_send_t*));
	} while (rc < 0 && (IS_ERR(EINTR) || retries-- > 0));

	if (rc < 0) {
		LM_ERR("cannot receive send param\n");
		return NULL;
	}
	return recv;
}

int xmlrpc_init_writer(void)
{
	int flags;

	if (xmlrpc_pipe[0] != -1) {
		close(xmlrpc_pipe[0]);
		xmlrpc_pipe[0] = -1;
	}

	if (xmlrpc_sync_mode)
		close(xmlrpc_status_pipes[process_no][1]);

	/* Turn non-blocking mode on for sending*/
	flags = fcntl(xmlrpc_pipe[1], F_GETFL);
	if (flags == -1) {
		LM_ERR("fcntl failed: %s\n", strerror(errno));
		goto error;
	}
	if (fcntl(xmlrpc_pipe[1], F_SETFL, flags | O_NONBLOCK) == -1) {
		LM_ERR("fcntl: set non-blocking failed: %s\n", strerror(errno));
		goto error;
	}

	return 0;
error:
	close(xmlrpc_pipe[1]);
	xmlrpc_pipe[1] = -1;
	return -1;
}

static void xmlrpc_init_reader(void)
{
	int i, flags;

	if (xmlrpc_pipe[1] != -1) {
		close(xmlrpc_pipe[1]);
		xmlrpc_pipe[1] = -1;
	}

	if (xmlrpc_sync_mode)
		for(i = 0; i < nr_procs; i++) {
			close(xmlrpc_status_pipes[i][0]);

			/* Turn non-blocking mode on for sending*/
			flags = fcntl(xmlrpc_status_pipes[i][1], F_GETFL);
			if (flags == -1) {
				LM_ERR("fcntl failed: %s\n", strerror(errno));
				close(xmlrpc_status_pipes[i][1]);
				return;
			}
			if (fcntl(xmlrpc_status_pipes[i][1], F_SETFL, flags | O_NONBLOCK) == -1) {
				LM_ERR("fcntl: set non-blocking failed: %s\n", strerror(errno));
				close(xmlrpc_status_pipes[i][1]);
				return;
			}
		}
}

/* sends the buffer */
static int xmlrpc_sendmsg(xmlrpc_send_t *sock)
{
	unsigned long i;
	int len = 0;
	int fd, ret = -1;
	int aux;

	xmlrpc_iov[xmlrpc_first_line_index].iov_base = sock->first_line.s;
	xmlrpc_iov[xmlrpc_first_line_index].iov_len = sock->first_line.len;

	xmlrpc_iov[xmlrpc_host_index].iov_base = sock->host.s;
	xmlrpc_iov[xmlrpc_host_index].iov_len = sock->host.len;

	/* event name */
	xmlrpc_iov[xmlrpc_ev_name_index].iov_base = sock->event.s;
	xmlrpc_iov[xmlrpc_ev_name_index].iov_len = sock->event.len;

	/* method name */
	xmlrpc_iov[xmlrpc_met_name_index].iov_base = sock->method.s;
	xmlrpc_iov[xmlrpc_met_name_index].iov_len = sock->method.len;

	/* msg body */
	xmlrpc_iov[xmlrpc_params_index].iov_base = sock->body.s;
	xmlrpc_iov[xmlrpc_params_index].iov_len = sock->body.len;

	/* now compute content length */
	for (i = xmlrpc_xmlbody_index; i < xmlrpc_iov_len; i++)
		len += xmlrpc_iov[i].iov_len;

	xmlrpc_iov[xmlrpc_ct_len_index].iov_base = int2str(len, &aux);
	xmlrpc_iov[xmlrpc_ct_len_index].iov_len = aux;

	/* writing the iov on the network */
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		LM_ERR("cannot create socket\n");
		return -1;
	}

	if (connect(fd, &sock->addr.s, sizeof(struct sockaddr_in)) < 0) {
		LM_ERR("cannot connect to %s[%d:%s]\n",
				inet_ntoa(sock->addr.sin.sin_addr),
				errno, strerror(errno));
		goto close;
	}

	do {
		len = writev(fd, xmlrpc_iov, xmlrpc_iov_len);
	} while ((len < 0 && (IS_ERR(EINTR)||IS_ERR(EAGAIN)||IS_ERR(EWOULDBLOCK))));
	if (len <= 0) {
		LM_ERR("cannot send xmlrpc command %s[%d]\n", strerror(errno), errno);
		goto close;
	}

	ret = 0;
close:
	shutdown(fd, SHUT_RDWR);
	close(fd);
	return ret;
}

static xmlrpc_send_t * xmlrpc_build_send_t(evi_reply_sock *sock,
		char *params, int params_len, str *ev_name)
{
	char * p, *aux;
	struct xmlrpc_sock_param *sock_params=sock->params;
	int len = sizeof(xmlrpc_send_t) + params_len + sock_params->method.len +
		ev_name->len + sock->address.len + 6 /* : port */;

	xmlrpc_send_t *msg = shm_malloc(len);
	if (!msg) {
		LM_ERR("no more shm mem\n");
		return NULL;
	}
	memset(msg, 0, len);

	/* first is body */
	msg->body.s = (char*)(msg + 1);
	memcpy(msg->body.s, params, params_len);
	msg->body.len = params_len;

	/* next is method */
	msg->method.s = msg->body.s + params_len;
	memcpy(msg->method.s, sock_params->method.s, sock_params->method.len);
	msg->method.len = sock_params->method.len;

	/* first line */
	msg->first_line = sock_params->first_line;

	/* event */
	msg->event.s = msg->method.s + msg->method.len;
	memcpy(msg->event.s, ev_name->s, ev_name->len);
	msg->event.len = ev_name->len;

	/* last is host */
	msg->host.s = msg->event.s + msg->event.len;
	memcpy(msg->host.s, sock->address.s, sock->address.len);
	msg->host.len = sock->address.len;

	if (sock->flags & EVI_PARAMS) {
		p = msg->host.s + sock->address.len;
		/* if it has port, add it */
		*p++ = ':';
		aux = int2str(sock->port , &len);
		memcpy(p, aux, len);
		msg->host.len += len + 1;
	}
	/* finally add the socket info */
	memcpy(&msg->addr, &sock->src_addr.udp_addr, sizeof(union sockaddr_union));
	return msg;
}

/* function to build XMLRPC buffer */
int xmlrpc_build_buffer(str *event_name, evi_reply_sock *sock,
		evi_params_t *params, xmlrpc_send_t ** msg)
{
	int len, b_len;
	char *b, *p;
	evi_param_p param;

	b_len = XMLRPC_DEFAULT_BUFFER_SIZE;
	b = xmlrpc_body_buf;

#define COPY_STR(_s, _l) \
	do { \
		if ( (_l) > b_len ) { \
			LM_ERR("buffer too small...\n");\
			return -1; \
		} \
		memcpy( b, (_s), (_l) ); \
		b_len -= (_l); \
		b += (_l); \
	} while (0)


	if (params) {
		for (param = params->first; param; param = param->next) {
			/* '<param>' */
			COPY_STR(START_TAG(XMLRPC_PARAM), LENOF(START_TAG(XMLRPC_PARAM)));

			if (param->name.len && param->name.s) {
				if (xmlrpc_struct_on) {
					COPY_STR(START_TAG(XMLRPC_VALUE),
							LENOF(START_TAG(XMLRPC_VALUE)) - 1);
					COPY_STR(START_TAG(XMLRPC_STRUCT),
							LENOF(START_TAG(XMLRPC_STRUCT)) - 1);
					COPY_STR(START_TAG(XMLRPC_MEMBER),
							LENOF(START_TAG(XMLRPC_MEMBER)));
				}
				LM_DBG("adding parameter %.*s\n",
						param->name.len, param->name.s);
				/* <name> */
				COPY_STR(START_TAG(XMLRPC_ATTR),
						LENOF(START_TAG(XMLRPC_ATTR)) - 1);
				/* parameter name */
				COPY_STR(param->name.s, param->name.len);
				/* </name> */
				COPY_STR(END_TAG(XMLRPC_ATTR),
						LENOF(END_TAG(XMLRPC_ATTR)));
			}

			/* <value> */
			COPY_STR(START_TAG(XMLRPC_VALUE),
					LENOF(START_TAG(XMLRPC_VALUE)) - 1);
			if (param->flags & EVI_INT_VAL) {
				/* <int> */
				COPY_STR(START_TAG(XMLRPC_INT),
						LENOF(START_TAG(XMLRPC_INT)) - 1);
				/* convert int */
				p = int2str(param->val.n, &len);
				if (!p) {
					LM_ERR("cannot convert int parameter\n");
					return -1;
				}
				/* integer parameter */
				COPY_STR(p, len);
				/* </int> */
				COPY_STR(END_TAG(XMLRPC_INT),
						LENOF(END_TAG(XMLRPC_INT)) - 1);
			} else {
				/* <string> */
				COPY_STR(START_TAG(XMLRPC_STRING),
						LENOF(START_TAG(XMLRPC_STRING)) - 1);
				/* string parameter */
				COPY_STR(param->val.s.s, param->val.s.len);
				/* </string> */
				COPY_STR(END_TAG(XMLRPC_STRING),
						LENOF(END_TAG(XMLRPC_STRING)) - 1);
			}
			COPY_STR(END_TAG(XMLRPC_VALUE),
					LENOF(END_TAG(XMLRPC_VALUE)));

			if (param->name.len && param->name.s &&
				xmlrpc_struct_on) {
					COPY_STR(END_TAG(XMLRPC_MEMBER),
							LENOF(END_TAG(XMLRPC_MEMBER)) - 1);
					COPY_STR(END_TAG(XMLRPC_STRUCT),
							LENOF(END_TAG(XMLRPC_STRUCT)) - 1);
					COPY_STR(END_TAG(XMLRPC_VALUE),
							LENOF(END_TAG(XMLRPC_VALUE)));
			}
			COPY_STR(END_TAG(XMLRPC_PARAM),
					LENOF(END_TAG(XMLRPC_PARAM)));
		}
	}

#undef COPY_STR

	len = XMLRPC_DEFAULT_BUFFER_SIZE - b_len;
	*msg = xmlrpc_build_send_t(sock, xmlrpc_body_buf, len, event_name);
	if (!*msg) {
		LM_ERR("cannot build send msg\n");
		return -1;
	}

	return 0;
}

/**
 * Node: if you add any extra headers here, make sure they don't overflow
 * XMLRPC_IOVEC_MAX_SIZE
 */
static void xmlrpc_init_send_buf(void)
{
	/*First Line: POST /... HTTP... */
	xmlrpc_first_line_index = xmlrpc_iov_len++;

	/* host */
	xmlrpc_host_index = xmlrpc_iov_len++;

	xmlrpc_iov[xmlrpc_iov_len].iov_base = XMLRPC_HTTP_HEADER;
	xmlrpc_iov[xmlrpc_iov_len].iov_len = LENOF(XMLRPC_HTTP_HEADER);
	xmlrpc_iov_len++;

	/* content length */
	xmlrpc_ct_len_index = xmlrpc_iov_len++;

	/* delimiter */
	xmlrpc_iov[xmlrpc_iov_len].iov_base = "\r\n\r\n";
	xmlrpc_iov[xmlrpc_iov_len].iov_len = 4;
	xmlrpc_iov_len++;

	/* here goes xml payload */
	/* XML version */
	xmlrpc_iov[xmlrpc_iov_len].iov_base = XMLRPC_BODY_CONST;
	xmlrpc_iov[xmlrpc_iov_len].iov_len = LENOF(XMLRPC_BODY_CONST);
	xmlrpc_xmlbody_index = xmlrpc_iov_len++;

	/* <methodCall> */
	xmlrpc_iov[xmlrpc_iov_len].iov_base = START_TAG(XMLRPC_METHOD_CALL);
	xmlrpc_iov[xmlrpc_iov_len].iov_len = LENOF(START_TAG(XMLRPC_METHOD_CALL));
	xmlrpc_iov_len++;

	/* <methodName> */
	xmlrpc_iov[xmlrpc_iov_len].iov_base = START_TAG(XMLRPC_METHOD_NAME);
	xmlrpc_iov[xmlrpc_iov_len].iov_len = LENOF(START_TAG(XMLRPC_METHOD_NAME))-1;
	xmlrpc_iov_len++;

	/* method name */
	xmlrpc_met_name_index = xmlrpc_iov_len++;

	/* </methodName> */
	xmlrpc_iov[xmlrpc_iov_len].iov_base = END_TAG(XMLRPC_METHOD_NAME);
	xmlrpc_iov[xmlrpc_iov_len].iov_len = LENOF(END_TAG(XMLRPC_METHOD_NAME));
	xmlrpc_iov_len++;

	/* <params> */
	xmlrpc_iov[xmlrpc_iov_len].iov_base = START_TAG(XMLRPC_PARAMS);
	xmlrpc_iov[xmlrpc_iov_len].iov_len = LENOF(START_TAG(XMLRPC_PARAMS));
	xmlrpc_iov_len++;

	/* event name parameter */
	/* <param> */
	xmlrpc_iov[xmlrpc_iov_len].iov_base = START_TAG(XMLRPC_PARAM);
	xmlrpc_iov[xmlrpc_iov_len].iov_len = LENOF(START_TAG(XMLRPC_PARAM));
	xmlrpc_iov_len++;

	/* <value> */
	xmlrpc_iov[xmlrpc_iov_len].iov_base = START_TAG(XMLRPC_VALUE);
	xmlrpc_iov[xmlrpc_iov_len].iov_len = LENOF(START_TAG(XMLRPC_VALUE))-1;
	xmlrpc_iov_len++;

	/* <string> */
	xmlrpc_iov[xmlrpc_iov_len].iov_base = START_TAG(XMLRPC_STRING);
	xmlrpc_iov[xmlrpc_iov_len].iov_len = LENOF(START_TAG(XMLRPC_STRING))-1;
	xmlrpc_iov_len++;

	/* events name */
	xmlrpc_ev_name_index = xmlrpc_iov_len++;

	/* </string> */
	xmlrpc_iov[xmlrpc_iov_len].iov_base = END_TAG(XMLRPC_STRING);
	xmlrpc_iov[xmlrpc_iov_len].iov_len = LENOF(END_TAG(XMLRPC_STRING))-1;
	xmlrpc_iov_len++;

	/* </value> */
	xmlrpc_iov[xmlrpc_iov_len].iov_base = END_TAG(XMLRPC_VALUE);
	xmlrpc_iov[xmlrpc_iov_len].iov_len = LENOF(END_TAG(XMLRPC_VALUE));
	xmlrpc_iov_len++;

	/* </param> */
	xmlrpc_iov[xmlrpc_iov_len].iov_base = END_TAG(XMLRPC_PARAM);
	xmlrpc_iov[xmlrpc_iov_len].iov_len = LENOF(END_TAG(XMLRPC_PARAM));
	xmlrpc_iov_len++;

	/* parameters */
	xmlrpc_params_index = xmlrpc_iov_len++;

	/* </params> */
	xmlrpc_iov[xmlrpc_iov_len].iov_base = END_TAG(XMLRPC_PARAMS);
	xmlrpc_iov[xmlrpc_iov_len].iov_len = LENOF(END_TAG(XMLRPC_PARAMS));
	xmlrpc_iov_len++;

	/* </methodCall> */
	xmlrpc_iov[xmlrpc_iov_len].iov_base = END_TAG(XMLRPC_METHOD_CALL);
	xmlrpc_iov[xmlrpc_iov_len].iov_len = LENOF(END_TAG(XMLRPC_METHOD_CALL))-1;
	xmlrpc_iov_len++;
}



void xmlrpc_process(int rank)
{
	int retries, rc;
	int send_status;

	/* init blocking reader */
	xmlrpc_init_reader();
	xmlrpc_init_send_buf();
	xmlrpc_send_t * xmlrpcs;

	/* waiting for commands */
	for (;;) {
		xmlrpcs = xmlrpc_receive();
		if (!xmlrpcs) {
			LM_ERR("invalid receive sock info\n");
			goto end;
		}

		/* send msg */
		if (xmlrpc_sendmsg(xmlrpcs)) {
			LM_ERR("cannot send message\n");
			send_status = XMLRPC_SEND_FAIL;
		} else
			send_status = XMLRPC_SEND_SUCCESS;

		if (xmlrpc_sync_mode) {
			retries = XMLRPC_SEND_RETRY;

			if (xmlrpcs->process_idx >= 0 && xmlrpcs->process_idx < nr_procs) {
				do {
					rc = write(xmlrpc_status_pipes[xmlrpcs->process_idx][1], &send_status, sizeof(int));
				} while (rc < 0 && (IS_ERR(EINTR) || retries-- > 0));
				if (rc < 0)
					LM_ERR("cannot send status back to requesting process\n");
			}
		}
end:
		if (xmlrpcs)
			shm_free(xmlrpcs);
	}
}
